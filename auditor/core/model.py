"""Data model shared across checks, reporting and remediation.

Plain classes (no dataclasses) so the tool runs on the Python 3.6 that ships
as /usr/bin/python3 on AlmaLinux 8 / CloudLinux 8.
"""
import enum


class Status(enum.Enum):
    OK = "OK"        # check passed
    FAIL = "FAIL"    # a real problem that should be fixed
    WARN = "WARN"    # not ideal / needs attention
    INFO = "INFO"    # informational, or a manual step to consider
    SKIP = "SKIP"    # not applicable on this server


class Severity(enum.IntEnum):
    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4


class Remediation(object):
    """How to fix a finding.

    An automatable remediation has ``commands`` (shell) and/or a ``func``.
    A manual-only remediation has just ``manual`` guidance text.

    ``risk`` marks a fix that can cut off access to the server if it is applied
    without preparation (an sshd or firewall change, say). Risky fixes are only
    offered when the operator passes ``--dangerous``, and are never applied by
    ``--yes`` alone.

    ``backup_files`` are copied aside before the fix runs. ``restart_cmd`` is
    run after the fix is verified, so a config change actually takes effect;
    ``restart`` is the human-readable service name shown in the summary.
    """

    def __init__(self, summary, commands=None, func=None, manual=None,
                 restart=None, risk=None, backup_files=None, restart_cmd=None):
        self.summary = summary
        self.commands = commands or []
        self.func = func
        self.manual = manual
        self.restart = restart  # note: service that must be restarted afterwards
        self.risk = risk
        self.backup_files = backup_files or []
        self.restart_cmd = restart_cmd

    @property
    def automatable(self):
        return bool(self.commands or self.func)

    @property
    def risky(self):
        return bool(self.risk)


class Finding(object):
    """One result emitted by a check."""

    def __init__(self, check_id, title, status, detail="",
                 severity=Severity.MEDIUM, remediation=None, reference=""):
        self.check_id = check_id
        self.title = title
        self.status = status
        self.detail = detail
        self.severity = severity
        self.remediation = remediation
        self.reference = reference  # cPanel checklist section / doc reference
        # Filled in by the runner from the owning CheckSpec; checks do not
        # repeat their own category on every Finding they yield.
        self.category = ""
        # Set by the remediator when a fix changed this finding's status.
        self.remediated_from = None

    @property
    def is_problem(self):
        return self.status in (Status.FAIL, Status.WARN)

    def as_dict(self):
        """Serialisable form, used by --json."""
        rem = self.remediation
        return {
            "id": self.check_id,
            "category": self.category,
            "title": self.title,
            "status": self.status.value,
            "remediated_from": (None if self.remediated_from is None
                                else self.remediated_from.value),
            "severity": self.severity.name,
            "detail": self.detail,
            "reference": self.reference,
            "remediation": None if rem is None else {
                "summary": rem.summary,
                "automatable": rem.automatable,
                "risky": rem.risky,
                "risk": rem.risk,
                "manual": rem.manual,
                "restart": rem.restart,
            },
        }
