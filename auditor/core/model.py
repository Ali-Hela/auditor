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
    """

    def __init__(self, summary, commands=None, func=None, manual=None,
                 restart=None):
        self.summary = summary
        self.commands = commands or []
        self.func = func
        self.manual = manual
        self.restart = restart  # note: service that must be restarted afterwards

    @property
    def automatable(self):
        return bool(self.commands or self.func)


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

    @property
    def is_problem(self):
        return self.status in (Status.FAIL, Status.WARN)
