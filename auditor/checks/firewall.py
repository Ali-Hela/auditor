"""Section 2 - Secure the server with firewalls."""

import os

from ..core.model import Finding, Remediation, Severity, Status
from ..core.registry import register
from ..core.util import (listening_ports, parse_kv, read_file, run, service_active,
                         which)

CAT = "Firewall & WAF"
REF = "cPanel checklist #2: Secure the server with firewalls"

# Ports that are normal to expose publicly on a cPanel host.
EXPECTED_PORTS = {
    "20", "21", "22", "25", "26", "53", "80", "110", "143", "443", "465",
    "587", "783", "993", "995", "2077", "2078", "2079", "2080", "2082",
    "2083", "2086", "2087", "2095", "2096", "3306",
}


@register("FW-CSF", "ConfigServer Firewall (CSF)", CAT, order=10)
def csf_installed():
    if which("csf") or os.path.isfile("/etc/csf/csf.conf"):
        yield Finding("FW-CSF", "CSF firewall is installed", Status.OK,
                      reference=REF)
    else:
        yield Finding("FW-CSF", "CSF firewall is not installed", Status.FAIL,
                      "ConfigServer Security & Firewall manages traffic and "
                      "blocks suspicious activity.", Severity.HIGH,
                      Remediation(
                          "Install CSF",
                          commands=["cd /usr/src && rm -fv csf.tgz && "
                                    "wget https://download.configserver.com/csf.tgz "
                                    "&& tar -xzf csf.tgz && cd csf && sh install.sh"],
                          manual="https://configserver.com/cp/csf.html",
                          restart="csf/lfd"),
                      reference=REF)


@register("FW-CSF-TESTING", "CSF not in testing mode", CAT, order=20)
def csf_testing():
    conf = read_file("/etc/csf/csf.conf")
    if conf is None:
        yield Finding("FW-CSF-TESTING", "CSF testing mode (CSF not installed)",
                      Status.SKIP, reference=REF)
        return
    cfg = parse_kv(conf)
    if cfg.get("TESTING") == "0":
        yield Finding("FW-CSF-TESTING", "CSF is in production mode", Status.OK,
                      reference=REF)
    else:
        yield Finding("FW-CSF-TESTING", "CSF is in TESTING mode", Status.FAIL,
                      "TESTING=1 means the firewall flushes its rules every few "
                      "minutes; it is not actually protecting the server.",
                      Severity.HIGH,
                      Remediation(
                          "Disable CSF testing mode and restart",
                          commands=[
                              "sed -ri 's/^TESTING = .*/TESTING = \"0\"/' "
                              "/etc/csf/csf.conf",
                              "csf -r"],
                          restart="csf/lfd",
                          manual="Verify your SSH port is allowed first, then "
                                 "set TESTING=0 and run 'csf -r'."),
                      reference=REF)


@register("FW-LFD", "Login Failure Daemon (lfd)", CAT, order=30)
def lfd():
    if not os.path.isfile("/etc/csf/csf.conf"):
        yield Finding("FW-LFD", "lfd (CSF not installed)", Status.SKIP,
                      reference=REF)
        return
    active = service_active("lfd")
    if active:
        yield Finding("FW-LFD", "Login Failure Daemon (lfd) is running",
                      Status.OK, reference=REF)
    else:
        yield Finding("FW-LFD", "Login Failure Daemon (lfd) is not running",
                      Status.FAIL,
                      "lfd detects repeated login failures and triggers blocks.",
                      Severity.HIGH,
                      Remediation("Start and enable lfd",
                                  commands=["systemctl enable --now lfd"],
                                  restart="lfd"),
                      reference=REF)


@register("FW-MODSEC", "ModSecurity WAF", CAT, order=40)
def modsecurity():
    rc, out, _ = run("httpd -M 2>/dev/null || apachectl -M 2>/dev/null")
    loaded = "security2_module" in out or "security_module" in out
    if loaded:
        yield Finding("FW-MODSEC", "ModSecurity is enabled", Status.OK,
                      reference=REF)
    else:
        yield Finding("FW-MODSEC", "ModSecurity does not appear to be enabled",
                      Status.FAIL,
                      "ModSecurity is a web application firewall for Apache.",
                      Severity.HIGH,
                      Remediation(
                          "Install ModSecurity via EasyApache",
                          manual="WHM > Security Center > ModSecurity "
                                 "Configuration (install ea-apache24-mod_security2)."),
                      reference=REF)


@register("FW-MODSEC-CRS", "OWASP Core Rule Set", CAT, order=50)
def modsec_crs():
    vendors_dir = "/etc/apache2/conf.d/modsec_vendor_configs"
    found = False
    try:
        names = os.listdir(vendors_dir) if os.path.isdir(vendors_dir) else []
    except OSError:
        names = []
    for name in names:
        low = name.lower()
        if "owasp" in low or "crs" in low:
            found = True
            break
    if found:
        yield Finding("FW-MODSEC-CRS", "An OWASP CRS rule set is installed",
                      Status.OK, reference=REF)
    else:
        yield Finding("FW-MODSEC-CRS", "OWASP Core Rule Set not detected",
                      Status.WARN,
                      "A vendor rule set (OWASP CRS) gives ModSecurity its rules.",
                      Severity.MEDIUM,
                      Remediation("Enable an OWASP CRS vendor",
                                  manual="WHM > ModSecurity Vendors > install "
                                         "OWASP ModSecurity Core Rule Set."),
                      reference=REF)


@register("FW-PORTS", "Unexpected open ports", CAT, order=60)
def open_ports():
    ports = listening_ports()
    if not ports:
        yield Finding("FW-PORTS", "Could not enumerate listening ports",
                      Status.SKIP, "ss/netstat unavailable.", reference=REF)
        return
    public = sorted({p for addr, p in ports
                     if addr not in ("127.0.0.1", "::1") and p not in EXPECTED_PORTS},
                    key=int)
    if not public:
        yield Finding("FW-PORTS", "No unexpected public ports are listening",
                      Status.OK, reference=REF)
    else:
        yield Finding("FW-PORTS",
                      "Unexpected public ports listening: %s" % ", ".join(public),
                      Status.WARN,
                      "Review these and close any that are not required.",
                      Severity.MEDIUM,
                      Remediation("Close or firewall unused ports",
                                  manual="Stop the service or restrict the port "
                                         "in CSF (TCP_IN/TCP_OUT)."),
                      reference=REF)
