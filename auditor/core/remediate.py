"""Guided remediation engine.

Default audits are read-only. Remediation only runs when ``--fix`` is given.
Prompts can be skipped wholesale with ``--yes`` (apply all) or interactively
with the ``A`` (skip all remaining) / ``q`` (quit fixing) answers.
"""

from typing import Optional

from .model import Finding, Status
from .report import Reporter
from .util import run


class Remediator:
    def __init__(self, reporter: Reporter, assume_yes: bool = False):
        self.reporter = reporter
        self.assume_yes = assume_yes
        self.skip_all = False
        self.quit = False
        self.applied = 0
        self.failed = 0
        self.skipped = 0
        self.restarts = set()

    def handle(self, finding: Finding):
        rem = finding.remediation
        if self.quit or not rem or finding.status not in (Status.FAIL, Status.WARN):
            return
        if not rem.automatable:
            if rem.manual:
                self.reporter.note("Manual fix: %s" % rem.manual)
            return
        if self.skip_all:
            self.skipped += 1
            return

        if self.assume_yes:
            choice = "y"
        else:
            choice = self.reporter.prompt("Apply fix? %s" % rem.summary)

        if choice == "q":
            self.quit = True
            return
        if choice == "a":
            self.skip_all = True
            self.skipped += 1
            return
        if choice != "y":
            self.skipped += 1
            return

        self._apply(rem)

    def _apply(self, rem):
        ok = True
        if rem.func:
            try:
                ok = bool(rem.func())
            except Exception as e:  # pragma: no cover - defensive
                ok = False
                self.reporter.note("Error: %s" % e)
        for cmd in rem.commands:
            rc, out, err = run(cmd, timeout=120)
            if rc != 0:
                ok = False
                msg = err or out or ("exit %d" % rc)
                self.reporter.note("Command failed: %s" % msg)
        if ok:
            self.applied += 1
            self.reporter.note("Applied.")
            if rem.restart:
                self.restarts.add(rem.restart)
        else:
            self.failed += 1

    def summary(self):
        if not (self.applied or self.failed or self.skipped):
            return
        self.reporter.note("")
        self.reporter.note(
            "Remediation: %d applied, %d failed, %d skipped."
            % (self.applied, self.failed, self.skipped))
        if self.restarts:
            self.reporter.note(
                "Restart required: %s" % ", ".join(sorted(self.restarts)))
