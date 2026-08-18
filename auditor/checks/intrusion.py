"""Section 7 - Intrusion detection and security logs."""

import os

from ..core.model import Finding, Remediation, Severity, Status
from ..core.registry import register
from ..core.util import (is_cpanel, read_file, service_active, truthy, whmapi1,
                         which)

CAT = "Intrusion Detection & Logs"
REF = "cPanel checklist #7: Intrusion detection and security logs"

# Logs worth checking exist and are being written to.
SECURITY_LOGS = ["/var/log/secure", "/var/log/messages"]


@register("IDS-BRUTEFORCE", "Brute-force / intrusion detection", CAT, order=10)
def brute_force():
    fail2ban = service_active("fail2ban")
    lfd = service_active("lfd")
    cphulk = None
    data = whmapi1("cphulk_status") if is_cpanel() else None
    if data:
        cphulk = truthy(data.get("data", {}).get("is_enabled"))

    active = []
    if fail2ban:
        active.append("Fail2Ban")
    if lfd:
        active.append("CSF/lfd")
    if cphulk:
        active.append("cPHulk")

    if active:
        yield Finding("IDS-BRUTEFORCE",
                      "Intrusion detection active: %s" % ", ".join(active),
                      Status.OK, reference=REF)
    else:
        pkg = "dnf" if which("dnf") else "yum"
        yield Finding("IDS-BRUTEFORCE",
                      "No intrusion-detection service detected", Status.FAIL,
                      "Run at least one of Fail2Ban, CSF/lfd, or cPHulk to block "
                      "repeated failed logins.", Severity.HIGH,
                      Remediation(
                          "Install and start Fail2Ban",
                          commands=["%s -y install fail2ban" % pkg,
                                    "systemctl enable --now fail2ban"],
                          manual="Or enable cPHulk in WHM > Security Center > "
                                 "cPHulk Brute Force Protection.",
                          restart="fail2ban"),
                      reference=REF)


@register("IDS-NOTIFY", "Security notifications", CAT, order=20)
def notifications():
    if not is_cpanel():
        yield Finding("IDS-NOTIFY", "Notifications (cPanel only)", Status.SKIP,
                      reference=REF)
        return
    # The WHM "Server Contact Email" lives in /etc/wwwacct.conf (space-separated).
    email = None
    for line in (read_file("/etc/wwwacct.conf") or "").splitlines():
        if line.strip().startswith("CONTACTEMAIL"):
            parts = line.split(None, 1)
            if len(parts) > 1 and parts[1].strip():
                email = parts[1].strip()
    if email:
        yield Finding("IDS-NOTIFY",
                      "Server contact email is set (%s)" % email, Status.OK,
                      reference=REF)
    else:
        yield Finding("IDS-NOTIFY", "No server contact email configured",
                      Status.WARN,
                      "Security alerts (root logins, exploits, lfd) need a "
                      "destination.", Severity.MEDIUM,
                      Remediation("Set the WHM contact email and alerts",
                                  manual="WHM > Server Contacts + Contact Manager; "
                                         "review WHM > Notifications."),
                      reference=REF)


@register("IDS-LOGS", "Security logs are being written", CAT, order=30)
def security_logs():
    """An empty or missing auth log usually means logging broke, or was wiped."""
    missing, empty = [], []
    for path in SECURITY_LOGS:
        if not os.path.isfile(path):
            missing.append(path)
            continue
        try:
            if os.path.getsize(path) == 0:
                empty.append(path)
        except OSError:
            missing.append(path)
    if not missing and not empty:
        yield Finding("IDS-LOGS", "Security logs are present and non-empty",
                      Status.OK, ", ".join(SECURITY_LOGS), reference=REF)
        return
    problems = []
    if missing:
        problems.append("missing: %s" % ", ".join(missing))
    if empty:
        problems.append("empty: %s" % ", ".join(empty))
    yield Finding("IDS-LOGS", "Security logs are missing or empty",
                  Status.WARN, "; ".join(problems)
                  + "\nA freshly rotated log is normal; an unexplained empty "
                    "auth log is not. Confirm rsyslog is running.",
                  Severity.MEDIUM,
                  Remediation("Restore system logging",
                              manual="systemctl status rsyslog; check "
                                     "/etc/rsyslog.conf and logrotate. Ship logs "
                                     "off-box so they survive a compromise."),
                  reference=REF)


@register("IDS-LOGMONITOR", "Log monitoring", CAT, order=40)
def log_monitoring():
    yield Finding("IDS-LOGMONITOR", "Monitor logs for suspicious activity",
                  Status.INFO,
                  "Review /var/log/secure, Apache/Exim logs and lfd reports "
                  "regularly; consider centralized log alerting.", Severity.INFO,
                  Remediation("Set up log monitoring/alerts",
                              manual="Configure lfd alerts in CSF and/or ship "
                                     "logs to a SIEM."),
                  reference=REF)
