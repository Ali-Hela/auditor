"""Section 2 - Secure the server with firewalls."""

import os

from ..core.model import Finding, Remediation, Severity, Status
from ..core.registry import register
from ..core.util import (apache_modules, listening_ports, is_public_addr,
                         parse_kv, read_file, service_active, set_config_line,
                         which)

CAT = "Firewall & WAF"
REF = "cPanel checklist #2: Secure the server with firewalls"

CSF_CONF = "/etc/csf/csf.conf"

# Ports that are normal to expose publicly on a cPanel host.
EXPECTED_PORTS = {
    "20", "21", "22", "25", "26", "53", "80", "110", "143", "443", "465",
    "587", "783", "993", "995", "2077", "2078", "2079", "2080", "2082",
    "2083", "2086", "2087", "2091", "2095", "2096",
}

# Ports another check owns. They are not "expected" - listing them in
# EXPECTED_PORTS would contradict the check that flags them - but reporting
# them here too would just say the same thing twice.
OWNED_ELSEWHERE = {"3306"}  # DB-REMOTE


@register("FW-CSF", "ConfigServer Firewall (CSF)", CAT, order=10)
def csf_installed():
    if which("csf") or os.path.isfile(CSF_CONF):
        yield Finding("FW-CSF", "CSF firewall is installed", Status.OK,
                      reference=REF)
    else:
        yield Finding("FW-CSF", "CSF firewall is not installed", Status.FAIL,
                      "ConfigServer Security & Firewall manages traffic and "
                      "blocks suspicious activity.", Severity.HIGH,
                      # Deliberately manual: automating this would mean piping
                      # an unverified remote tarball into a root shell, and a
                      # part-finished install leaves the host with no firewall.
                      Remediation(
                          "Install CSF (manual - installs a firewall, do it "
                          "with console access available)",
                          manual="Follow https://configserver.com/cp/csf.html. "
                                 "Verify the download, add your SSH port to "
                                 "TCP_IN before enabling, and keep a console "
                                 "session open.",
                          restart="csf/lfd"),
                      reference=REF)


@register("FW-CSF-TESTING", "CSF not in testing mode", CAT, order=20)
def csf_testing():
    conf = read_file(CSF_CONF)
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
                          "Disable CSF testing mode and restart the firewall",
                          func=lambda: set_config_line(
                              CSF_CONF, "TESTING", '"0"', spaced=True),
                          commands=["csf -r"],
                          backup_files=[CSF_CONF],
                          restart="csf/lfd",
                          risk="brings a live firewall up - if your SSH port is "
                               "missing from TCP_IN you will be locked out",
                          manual="Verify your SSH port is in TCP_IN first, then "
                                 "set TESTING = \"0\" and run 'csf -r'."),
                      reference=REF)


@register("FW-LFD", "Login Failure Daemon (lfd)", CAT, order=30)
def lfd():
    if not os.path.isfile(CSF_CONF):
        yield Finding("FW-LFD", "lfd (CSF not installed)", Status.SKIP,
                      reference=REF)
        return
    active = service_active("lfd")
    if active is None:
        yield Finding("FW-LFD", "lfd status could not be determined", Status.WARN,
                      "systemctl is unavailable.", Severity.LOW, reference=REF)
    elif active:
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
    mods = apache_modules()
    if mods is None:
        yield Finding("FW-MODSEC", "ModSecurity (Apache not detected)",
                      Status.SKIP,
                      "Could not query loaded Apache modules.", reference=REF)
        return
    if any(m.startswith(("security2_module", "security_module")) for m in mods):
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
    if not os.path.isdir(vendors_dir):
        yield Finding("FW-MODSEC-CRS", "ModSecurity vendors (not applicable)",
                      Status.SKIP,
                      "%s does not exist." % vendors_dir, reference=REF)
        return
    try:
        names = os.listdir(vendors_dir)
    except OSError:
        names = []
    found = [n for n in names if "owasp" in n.lower() or "crs" in n.lower()]
    if found:
        yield Finding("FW-MODSEC-CRS", "An OWASP CRS rule set is installed",
                      Status.OK, ", ".join(sorted(found)), reference=REF)
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
                     if is_public_addr(addr)
                     and p not in EXPECTED_PORTS
                     and p not in OWNED_ELSEWHERE},
                    key=int)
    if not public:
        yield Finding("FW-PORTS", "No unexpected public ports are listening",
                      Status.OK, reference=REF)
    else:
        yield Finding("FW-PORTS",
                      "Unexpected public ports listening: %s" % ", ".join(public),
                      Status.WARN,
                      "Review these and close any that are not required.\n"
                      "Identify each with: ss -tlnp 'sport = :PORT'",
                      Severity.MEDIUM,
                      Remediation("Close or firewall unused ports",
                                  manual="Stop the service, bind it to "
                                         "127.0.0.1, or remove the port from "
                                         "TCP_IN in /etc/csf/csf.conf."),
                      reference=REF)
