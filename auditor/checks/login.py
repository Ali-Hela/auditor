"""Section 1 - Secure your cPanel login."""

from ..core.model import Finding, Remediation, Severity, Status
from ..core.registry import register
from ..core.util import (cpanel_config, is_cpanel, read_file, run, truthy, whmapi1)

CAT = "Login & Access"
REF = "cPanel checklist #1: Secure your cPanel login"


@register("LOGIN-2FA", "Two-Factor Authentication policy", CAT, order=10)
def two_factor():
    if not is_cpanel():
        yield Finding("LOGIN-2FA", "2FA (cPanel only)", Status.SKIP,
                      "Not a cPanel server.", reference=REF)
        return
    data = whmapi1("twofactorauth_policy_status")
    enabled = None
    if data:
        enabled = bool(data.get("data", {}).get("is_enabled"))
    if enabled is None:
        yield Finding("LOGIN-2FA", "2FA policy", Status.WARN,
                      "Could not determine 2FA policy status via whmapi1.",
                      Severity.MEDIUM,
                      Remediation("Enforce 2FA for all users",
                                  manual="WHM > Security Center > Two-Factor "
                                         "Authentication > Manage Policy."),
                      reference=REF)
    elif enabled:
        yield Finding("LOGIN-2FA", "2FA policy is enforced", Status.OK,
                      reference=REF)
    else:
        yield Finding("LOGIN-2FA", "2FA is not enforced for all users",
                      Status.FAIL,
                      "WHM 2FA policy is off; accounts can log in with a "
                      "password alone.", Severity.HIGH,
                      Remediation(
                          "Enable the WHM 2FA enforcement policy",
                          commands=["whmapi1 twofactorauth_enable_policy"],
                          manual="WHM > Security Center > Two-Factor "
                                 "Authentication > Manage Policy."),
                      reference=REF)


@register("LOGIN-ROOT-SSH", "Direct root SSH login", CAT, order=20)
def root_ssh():
    cfg = read_file("/etc/ssh/sshd_config")
    if cfg is None:
        yield Finding("LOGIN-ROOT-SSH", "SSH root login", Status.SKIP,
                      "/etc/ssh/sshd_config not found.", reference=REF)
        return
    value = "yes"  # OpenSSH default if unspecified
    for line in cfg.splitlines():
        s = line.strip()
        if s and not s.startswith("#") and s.lower().startswith("permitrootlogin"):
            value = s.split(None, 1)[1].strip().lower() if len(s.split()) > 1 else "yes"
    if value in ("no", "prohibit-password", "without-password"):
        yield Finding("LOGIN-ROOT-SSH",
                      "Direct root SSH login is restricted (%s)" % value,
                      Status.OK, reference=REF)
    else:
        yield Finding("LOGIN-ROOT-SSH", "Direct root SSH login is permitted",
                      Status.FAIL,
                      "PermitRootLogin is '%s'. Use a sudo-enabled account "
                      "instead." % value, Severity.HIGH,
                      Remediation(
                          "Set PermitRootLogin to prohibit-password and reload sshd",
                          commands=[
                              "sed -ri 's/^[#[:space:]]*PermitRootLogin.*/"
                              "PermitRootLogin prohibit-password/' "
                              "/etc/ssh/sshd_config",
                              "grep -q '^PermitRootLogin' /etc/ssh/sshd_config || "
                              "echo 'PermitRootLogin prohibit-password' >> "
                              "/etc/ssh/sshd_config",
                          ],
                          restart="sshd",
                          manual="Ensure you have a working sudo account FIRST, "
                                 "then set PermitRootLogin prohibit-password."),
                      reference=REF)


@register("LOGIN-CPHULK", "cPHulk brute-force protection", CAT, order=30)
def cphulk():
    if not is_cpanel():
        yield Finding("LOGIN-CPHULK", "cPHulk (cPanel only)", Status.SKIP,
                      "Not a cPanel server.", reference=REF)
        return
    data = whmapi1("cphulk_status")
    enabled = None
    if data:
        enabled = truthy(data.get("data", {}).get("is_enabled"))
    if enabled is None:
        yield Finding("LOGIN-CPHULK", "cPHulk status could not be determined",
                      Status.WARN, "whmapi1 cphulk_status failed (run as root?).",
                      Severity.MEDIUM,
                      Remediation("Verify cPHulk is enabled",
                                  manual="WHM > Security Center > cPHulk "
                                         "Brute Force Protection."),
                      reference=REF)
    elif enabled:
        yield Finding("LOGIN-CPHULK", "cPHulk brute-force protection is enabled",
                      Status.OK, reference=REF)
    else:
        yield Finding("LOGIN-CPHULK", "cPHulk brute-force protection is disabled",
                      Status.FAIL,
                      "cPHulk blocks repeated failed logins to cPanel/WHM/SSH.",
                      Severity.HIGH,
                      Remediation("Enable cPHulk",
                                  commands=["whmapi1 enable_cphulk"],
                                  manual="WHM > Security Center > cPHulk "
                                         "Brute Force Protection."),
                      reference=REF)


@register("LOGIN-PWSTRENGTH", "Password strength policy", CAT, order=40)
def password_strength():
    if not is_cpanel():
        yield Finding("LOGIN-PWSTRENGTH", "Password strength (cPanel only)",
                      Status.SKIP, "Not a cPanel server.", reference=REF)
        return
    cfg = cpanel_config()
    raw = cfg.get("minpwstrength")
    try:
        strength = int(raw) if raw is not None else None
    except ValueError:
        strength = None
    if strength is None:
        yield Finding("LOGIN-PWSTRENGTH", "Password strength policy unknown",
                      Status.WARN, "minpwstrength not set in cpanel.config.",
                      Severity.MEDIUM,
                      Remediation("Set a minimum password strength",
                                  manual="WHM > Security Center > Password "
                                         "Strength Configuration (>= 65)."),
                      reference=REF)
    elif strength >= 65:
        yield Finding("LOGIN-PWSTRENGTH",
                      "Minimum password strength is %d" % strength,
                      Status.OK, reference=REF)
    else:
        yield Finding("LOGIN-PWSTRENGTH",
                      "Minimum password strength is low (%d)" % strength,
                      Status.WARN, "Recommended minimum is 65.", Severity.MEDIUM,
                      Remediation("Raise minimum password strength to 65",
                                  manual="WHM > Security Center > Password "
                                         "Strength Configuration."),
                      reference=REF)


@register("LOGIN-HOSTACCESS", "IP-restricted admin access", CAT, order=50)
def host_access():
    yield Finding("LOGIN-HOSTACCESS", "Restrict admin access by IP", Status.INFO,
                  "Limit WHM/SSH access to trusted IPs and use cPHulk + "
                  "Host Access Control for high-privilege accounts.",
                  Severity.INFO,
                  Remediation("Configure IP allow-lists",
                              manual="WHM > Security Center > Host Access "
                                     "Control; restrict SSH in CSF."),
                  reference=REF)
