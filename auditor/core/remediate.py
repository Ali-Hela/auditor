"""Guided remediation engine.

Default audits are read-only. Remediation only runs when ``--fix`` is given.

Three things make a fix safe to offer:

* **Backups.** Files a fix edits are copied aside first.
* **Verification.** After a fix runs, the owning check is re-executed against
  the files as they now are on disk. A fix is only reported as applied if the
  check stops failing. ``sed -i`` on an absent key exits 0 while changing
  nothing, so an exit code alone is not evidence.
* **Risk gating.** Fixes that can lock an operator out of the server (sshd,
  firewall) are only offered with ``--dangerous``, and are never swept up by
  ``--yes`` on its own.
"""

from .model import Status
from .report import Reporter
from .util import backup_file, clear_caches, run


class Remediator:
    def __init__(self, reporter: Reporter, assume_yes: bool = False,
                 allow_risky: bool = False):
        self.reporter = reporter
        self.assume_yes = assume_yes
        self.allow_risky = allow_risky
        self.skip_all = False
        self.quit = False
        self.applied = 0
        self.failed = 0
        self.skipped = 0
        self.blocked = 0
        self.restarts = set()
        self.backups = []

    # -- decision --------------------------------------------------------
    def handle(self, finding, spec=None):
        """Offer, apply and verify the fix for one finding.

        ``spec`` is the CheckSpec that produced the finding; it is re-run to
        confirm the fix worked. Without it, the fix is applied unverified.
        """
        rem = finding.remediation
        if self.quit or not rem or finding.status not in (Status.FAIL, Status.WARN):
            return
        if not rem.automatable:
            if rem.manual:
                self.reporter.note("Manual fix: %s" % rem.manual)
            return
        if rem.risky and not self.allow_risky:
            self.blocked += 1
            self.reporter.note(
                "Fix withheld (%s). Re-run with --dangerous to be offered it, "
                "or apply by hand: %s" % (rem.risk, rem.manual or rem.summary))
            return
        if self.skip_all:
            self.skipped += 1
            return

        if self.assume_yes and not rem.risky:
            choice = "y"
        else:
            question = "Apply fix? %s" % rem.summary
            if rem.risky:
                # A risky fix always asks, even under --yes.
                self.reporter.note("RISK: %s" % rem.risk)
            choice = self.reporter.prompt(question)

        if choice == "q":
            self.quit = True
            return
        if choice == "s":
            self.skip_all = True
            self.skipped += 1
            return
        if choice != "y":
            self.skipped += 1
            return

        self._apply(finding, rem, spec)

    # -- execution -------------------------------------------------------
    def _apply(self, finding, rem, spec):
        for path in rem.backup_files:
            dest = backup_file(path)
            if dest:
                self.backups.append(dest)
                self.reporter.note("Backed up %s -> %s" % (path, dest))

        ok = True
        if rem.func:
            try:
                ok = bool(rem.func())
            except Exception as e:  # pragma: no cover - defensive
                ok = False
                self.reporter.note("Error: %s" % e)
        if ok:
            for cmd in rem.commands:
                rc, out, err = run(cmd, timeout=600)
                if rc != 0:
                    ok = False
                    msg = err or out or ("exit %d" % rc)
                    self.reporter.note("Command failed: %s" % msg)
                    break

        if not ok:
            self.failed += 1
            return

        new_status = self._verify(finding, spec)
        if new_status is None:
            # No way to re-check; the command reported success, so take it at
            # face value but say so.
            self.applied += 1
            self.reporter.note("Applied (not verified).")
        elif new_status in (Status.FAIL, Status.WARN):
            self.failed += 1
            self.reporter.note(
                "Fix ran but the check still reports %s - the change did not "
                "take effect. Apply it by hand: %s"
                % (new_status.value, rem.manual or rem.summary))
            return
        else:
            self.applied += 1
            self.reporter.revise(finding, new_status)
            self.reporter.note("Applied and verified.")

        if rem.restart:
            self.restarts.add(rem.restart)
        if rem.restart_cmd:
            rc, out, err = run(rem.restart_cmd, timeout=120)
            if rc == 0:
                self.reporter.note("Reloaded %s." % (rem.restart or "service"))
                self.restarts.discard(rem.restart)
            else:
                self.reporter.note(
                    "Could not reload %s automatically (%s); restart it "
                    "yourself for the change to take effect."
                    % (rem.restart or "service", err or out or "exit %d" % rc))

    def _verify(self, finding, spec):
        """Re-run the owning check; return the new Status for this finding.

        Returns None when verification is not possible (no spec, or the check
        no longer emits a finding with this id).
        """
        if spec is None:
            return None
        clear_caches()
        try:
            results = list(spec.func())
        except Exception as e:  # pragma: no cover - defensive
            self.reporter.note("Could not re-run check to verify: %s" % e)
            return None
        for result in results:
            if result.check_id == finding.check_id:
                return result.status
        return None

    # -- summary ---------------------------------------------------------
    def summary(self):
        if not (self.applied or self.failed or self.skipped or self.blocked):
            return
        self.reporter.note("")
        self.reporter.note(
            "Remediation: %d applied, %d failed, %d skipped, %d withheld."
            % (self.applied, self.failed, self.skipped, self.blocked))
        if self.applied:
            self.reporter.note(
                "The counts above reflect the server after these fixes.")
        if self.backups:
            self.reporter.note("Backups written: %s" % ", ".join(self.backups))
        if self.restarts:
            self.reporter.note(
                "Restart required: %s" % ", ".join(sorted(self.restarts)))
        if self.blocked:
            self.reporter.note(
                "Withheld fixes can lock you out of the server. Read each one, "
                "confirm you have another way in, then re-run with --dangerous.")
