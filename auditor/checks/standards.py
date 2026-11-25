"""Our own operational standards that need logic, not just a baseline line.

Root login alerts, hostname / DNS / reverse DNS, the hostname certificate WHM
serves, and basic account hygiene.
"""

import calendar
import os
import re
import socket
import time

from ..core.model import Finding, Remediation, Severity, Status
from ..core.registry import register
from ..core.util import is_cpanel, read_file, run, which
from . import baseline

CAT = "Our Standards"
REF = "Internal standard"

ROOT_BASHRC = "/root/.bashrc"
ALERT_MARKER = "ALERT - Root Shell Access"
PUBLIC_RESOLVER = "1.1.1.1"
FQDN_RE = re.compile(r"^([a-z0-9]([a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,}$")
EMAIL_RE = re.compile(r"[\w.%+-]+@[\w.-]+\.[A-Za-z]{2,}")

ALERT_BLOCK = """
# BEGIN auditor root-login-alert
if [[ $- == *i* ]]; then
    _from=$(echo "${SSH_CLIENT:-local}" | awk '{ print $1 }')
    echo "%(marker)s on $(hostname) at $(date) from $_from" | mail -s "Alert: root access on $(hostname) from $_from" %(email)s
    echo "$(date '+%%F %%T') root login from $_from" >> /var/log/rootlogins
    unset _from
fi
# END auditor root-login-alert
"""


# ----------------------------------------------------------- root alerts

def _install_alert(email):
    try:
        with open(ROOT_BASHRC, "a") as fh:
            fh.write(ALERT_BLOCK % {"marker": ALERT_MARKER, "email": email})
    except OSError:
        return False
    read_file.cache_clear()
    return True


@register("STD-ROOT-ALERT", "Root login email alert", CAT, order=10)
def root_alert():
    text = read_file(ROOT_BASHRC) or ""
    alert = next((l for l in text.splitlines() if ALERT_MARKER in l), None)
    if alert:
        m = EMAIL_RE.search(alert)
        if not which("mail"):
            yield Finding("STD-ROOT-ALERT",
                          "Root login alert is set up but 'mail' is missing",
                          Status.WARN, "Alerts can't be sent without the mail "
                          "command (mailx/s-nail).", Severity.MEDIUM,
                          reference=REF)
        else:
            yield Finding("STD-ROOT-ALERT", "Root logins are emailed to %s"
                          % (m.group(0) if m else "<unknown>"), Status.OK,
                          reference=REF)
        return
    email = baseline.setting("ROOT_ALERT_EMAIL")
    if email and EMAIL_RE.fullmatch(email):
        rem = Remediation("Email root logins to %s" % email,
                          func=lambda: _install_alert(email),
                          backup_files=[ROOT_BASHRC])
    else:
        rem = Remediation("Set up root login alerts",
                          manual="Set ROOT_ALERT_EMAIL in baseline.conf and "
                                 "re-run with --fix.")
    yield Finding("STD-ROOT-ALERT", "Root logins are not emailed", Status.FAIL,
                  "No root login alert in %s, so a root shell from an "
                  "unexpected IP goes unnoticed." % ROOT_BASHRC,
                  Severity.MEDIUM, rem, reference=REF)


# --------------------------------------------------------- hostname & DNS

def fqdn():
    return socket.getfqdn().lower()


def main_ip():
    """The server's public main IP (NAT-aware on cPanel)."""
    ip = (read_file("/var/cpanel/mainip") or "").strip()
    if not ip:
        rc, out, _ = run(["hostname", "-I"])
        ip = out.split()[0] if rc == 0 and out else ""
    for line in (read_file("/var/cpanel/cpnat") or "").splitlines():
        parts = line.split()
        if len(parts) == 2 and parts[0] == ip:
            return parts[1]
    return ip or None


def dns_a(name):
    """A records from a public resolver, so local BIND can't hide a problem."""
    if which("dig"):
        rc, out, _ = run(["dig", "+short", "+time=3", "+tries=1", "A", name,
                          "@" + PUBLIC_RESOLVER])
        if rc == 0:
            return [l for l in out.splitlines() if re.match(r"^[\d.]+$", l)]
    try:
        return socket.gethostbyname_ex(name)[2]
    except OSError:
        return []


def dns_ptr(ip):
    if which("dig"):
        rc, out, _ = run(["dig", "+short", "+time=3", "+tries=1", "-x", ip,
                          "@" + PUBLIC_RESOLVER])
        if rc == 0:
            return out.splitlines()[0].rstrip(".").lower() if out else None
    try:
        return socket.gethostbyaddr(ip)[0].lower()
    except OSError:
        return None


@register("STD-HOSTNAME", "Hostname is a FQDN that resolves here", CAT, order=20)
def hostname():
    name = fqdn()
    manual = "WHM > Networking Setup > Change Hostname"
    if not FQDN_RE.match(name):
        yield Finding("STD-HOSTNAME", "Hostname '%s' is not a FQDN" % name,
                      Status.FAIL, "Use a full name such as server.example.com.",
                      Severity.MEDIUM, Remediation("Set a FQDN hostname",
                                                   manual=manual),
                      reference=REF)
        return
    ip = main_ip()
    if not ip:
        yield Finding("STD-HOSTNAME", "Hostname %s (main IP unknown)" % name,
                      Status.SKIP, reference=REF)
        return
    found = dns_a(name)
    if ip in found:
        yield Finding("STD-HOSTNAME", "%s resolves to this server (%s)"
                      % (name, ip), Status.OK, reference=REF)
    elif not found:
        yield Finding("STD-HOSTNAME", "%s has no public A record" % name,
                      Status.FAIL, "Add an A record pointing to %s." % ip,
                      Severity.MEDIUM, reference=REF)
    else:
        yield Finding("STD-HOSTNAME", "%s resolves elsewhere" % name,
                      Status.FAIL, "It resolves to %s, but this server is %s."
                      % (", ".join(found), ip), Severity.MEDIUM, reference=REF)


@register("STD-PTR", "Reverse DNS matches the hostname", CAT, order=30)
def reverse_dns():
    ip, name = main_ip(), fqdn()
    if not ip:
        yield Finding("STD-PTR", "Reverse DNS (main IP unknown)", Status.SKIP,
                      reference=REF)
        return
    ptr = dns_ptr(ip)
    if ptr == name:
        yield Finding("STD-PTR", "Reverse DNS for %s is %s" % (ip, name),
                      Status.OK, reference=REF)
    else:
        yield Finding("STD-PTR", "Reverse DNS for %s is '%s'" % (ip, ptr or "none"),
                      Status.WARN, "It should be %s; a mismatch hurts mail "
                      "delivery." % name, Severity.MEDIUM,
                      Remediation("Fix the PTR record",
                                  manual="Ask the IP provider to set the PTR "
                                         "for %s to %s." % (ip, name)),
                      reference=REF)


# ---------------------------------------------------- hostname certificate

def served_certificate(host, port=2087):
    """(verify_result, days_left) for the certificate served on ``port``."""
    rc, out, _ = run("timeout 10 openssl s_client -connect 127.0.0.1:%d "
                     "-servername %s -verify_hostname %s </dev/null 2>/dev/null"
                     % (port, host, host), timeout=20)
    m = re.search(r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----",
                  out, re.S)
    if not m:
        return None, None
    verify = re.search(r"Verify return code: (.*)", out)
    rc, end, _ = run("openssl x509 -noout -enddate <<'EOF'\n%s\nEOF" % m.group(0))
    days = None
    if rc == 0 and "=" in end:
        try:
            expiry = calendar.timegm(time.strptime(
                end.split("=", 1)[1].strip(), "%b %d %H:%M:%S %Y %Z"))
            days = int((expiry - time.time()) // 86400)
        except ValueError:
            pass
    return (verify.group(1).strip() if verify else "unknown"), days


@register("STD-HOST-CERT", "Hostname certificate (WHM)", CAT, order=40)
def host_certificate():
    if not is_cpanel():
        yield Finding("STD-HOST-CERT", "Hostname certificate (cPanel only)",
                      Status.SKIP, reference=REF)
        return
    name = fqdn()
    verify, days = served_certificate(name)
    rem = Remediation("Issue a trusted hostname certificate",
                      manual="WHM > SSL/TLS > Manage AutoSSL > run AutoSSL "
                             "for the hostname.")
    if verify is None:
        yield Finding("STD-HOST-CERT", "Could not fetch the WHM certificate",
                      Status.SKIP, "Nothing answered TLS on port 2087.",
                      reference=REF)
    elif not verify.startswith("0"):
        yield Finding("STD-HOST-CERT", "Hostname certificate is not trusted",
                      Status.FAIL, "OpenSSL says: %s (self-signed, or issued "
                      "for another name)." % verify, Severity.HIGH, rem,
                      reference=REF)
    elif days is not None and days < 14:
        yield Finding("STD-HOST-CERT", "Hostname certificate expires in %d days"
                      % days, Status.FAIL, "AutoSSL should have renewed it.",
                      Severity.HIGH, rem, reference=REF)
    elif days is not None and days < 30:
        yield Finding("STD-HOST-CERT", "Hostname certificate expires in %d days"
                      % days, Status.WARN, "", Severity.MEDIUM, rem,
                      reference=REF)
    else:
        yield Finding("STD-HOST-CERT", "Hostname certificate is trusted%s"
                      % ("" if days is None else ", %d days left" % days),
                      Status.OK, reference=REF)


# ------------------------------------------------------- account hygiene

@register("STD-UID0", "Only root has UID 0", CAT, order=50)
def extra_uid0():
    users = [l.split(":")[0] for l in (read_file("/etc/passwd") or "").splitlines()
             if l.count(":") >= 3 and l.split(":")[2] == "0"
             and l.split(":")[0] != "root"]
    if users:
        yield Finding("STD-UID0", "Accounts other than root have UID 0",
                      Status.FAIL, "Full root access through: %s."
                      % ", ".join(users), Severity.CRITICAL, reference=REF)
    else:
        yield Finding("STD-UID0", "Only root has UID 0", Status.OK,
                      reference=REF)


@register("STD-EMPTY-PW", "No accounts with an empty password", CAT, order=60)
def empty_passwords():
    shadow = read_file("/etc/shadow")
    if shadow is None:
        yield Finding("STD-EMPTY-PW", "Empty passwords (/etc/shadow unreadable)",
                      Status.SKIP, reference=REF)
        return
    users = [l.split(":")[0] for l in shadow.splitlines()
             if l.count(":") >= 1 and l.split(":")[1] == ""]
    if users:
        yield Finding("STD-EMPTY-PW", "Accounts with an empty password",
                      Status.FAIL, "Anyone can log in as: %s." % ", ".join(users),
                      Severity.CRITICAL,
                      Remediation("Lock the accounts",
                                  commands=["passwd -l %s" % u for u in users]),
                      reference=REF)
    else:
        yield Finding("STD-EMPTY-PW", "No accounts with an empty password",
                      Status.OK, reference=REF)


SUSPICIOUS_CRON = re.compile(r"base64 -d|eval\(|\$\{IFS\}|"
                             r"(curl|wget)[^|#\n]*\|\s*(ba)?sh")


@register("STD-CRON", "No suspicious cron jobs", CAT, order=70)
def suspicious_cron():
    hits = []
    for top in ["/var/spool/cron", "/etc/crontab", "/etc/cron.d",
                "/etc/cron.hourly", "/etc/cron.daily"]:
        try:
            paths = ([os.path.join(top, n) for n in sorted(os.listdir(top))]
                     if os.path.isdir(top) else [top])
        except OSError:
            continue
        for path in paths:
            text = read_file(path) if os.path.isfile(path) else None
            if text and any(SUSPICIOUS_CRON.search(l) for l in text.splitlines()
                            if not l.strip().startswith("#")):
                hits.append(path)
    if hits:
        yield Finding("STD-CRON", "Suspicious cron jobs", Status.FAIL,
                      "Obfuscated or pipe-to-shell commands in: %s. Review "
                      "them now." % ", ".join(hits), Severity.HIGH,
                      reference=REF)
    else:
        yield Finding("STD-CRON", "No suspicious cron jobs", Status.OK,
                      reference=REF)
