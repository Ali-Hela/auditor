"""Section 1 - Secure your cPanel login."""

import os

from ..core.model import Finding, Remediation, Severity, Status
from ..core.registry import register
from ..core.util import (cpanel_config, is_cpanel, parse_kv, read_file,
                         set_config_line, sshd_config, truthy, whmapi1)

CAT = "Login & Access"
REF = "cPanel checklist #1: Secure your cPanel login"

SSHD_CONFIG = "/etc/ssh/sshd_config"
# Reloading rather than restarting keeps existing sessions alive, and the
# config test in front of it means a bad edit can never leave sshd unable to
# start.
SSHD_RELOAD = "sshd -t && systemctl reload sshd"
LOCKOUT_RISK = ("changes how you log in over SSH - confirm you have a working "
                "sudo account or console access first")


@register("LOGIN-2FA", "Two-Factor Authentication policy", CAT, order=10)
def two_factor():
    if not is_cpanel():
        yield Finding("LOGIN-2FA", "2FA (cPanel only)", Status.SKIP,
                      "Not a cPanel server.", reference=REF)
        return
    data = whmapi1("twofactorauth_policy_status")
    enabled = None
    if data:
        # cPanel APIs return booleans as 0/1 integers in some endpoints and
        # "0"/"1" strings in others; bool("0") is True, so coerce properly.
        enabled = truthy(data.get("data", {}).get("is_enabled"))
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
    cfg = sshd_config()
    if cfg is None:
        yield Finding("LOGIN-ROOT-SSH", "SSH root login", Status.SKIP,
                      "sshd configuration could not be read.", reference=REF)
        return
    value = cfg.get("permitrootlogin")
    if value is None:
        # Only reachable on the text-parsing fallback. OpenSSH's own default
        # has been prohibit-password since 7.0, so an absent directive is not
        # evidence of a problem - say so rather than guessing "yes".
        yield Finding("LOGIN-ROOT-SSH",
                      "PermitRootLogin is not set explicitly", Status.WARN,
                      "The compiled-in default (prohibit-password on OpenSSH "
                      "7.0+) applies. Set it explicitly so the policy is "
                      "visible.", Severity.LOW,
                      Remediation(
                          "Set PermitRootLogin prohibit-password explicitly",
                          func=lambda: set_config_line(
                              SSHD_CONFIG, "PermitRootLogin",
                              "prohibit-password", sep=" "),
                          backup_files=[SSHD_CONFIG],
                          restart="sshd", restart_cmd=SSHD_RELOAD,
                          risk=LOCKOUT_RISK,
                          manual="Add 'PermitRootLogin prohibit-password' to "
                                 "%s and reload sshd." % SSHD_CONFIG),
                      reference=REF)
        return
    value = value.strip().lower()
    if value in ("no", "prohibit-password", "without-password", "forced-commands-only"):
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
                          func=lambda: set_config_line(
                              SSHD_CONFIG, "PermitRootLogin",
                              "prohibit-password", sep=" "),
                          backup_files=[SSHD_CONFIG],
                          restart="sshd", restart_cmd=SSHD_RELOAD,
                          risk=LOCKOUT_RISK,
                          manual="Ensure you have a working sudo account FIRST, "
                                 "then set PermitRootLogin prohibit-password."),
                      reference=REF)


@register("LOGIN-SSH-PASSWORD", "SSH password authentication", CAT, order=25)
def ssh_password_auth():
    cfg = sshd_config()
    if cfg is None:
        yield Finding("LOGIN-SSH-PASSWORD", "SSH password authentication",
                      Status.SKIP, "sshd configuration could not be read.",
                      reference=REF)
        return
    value = (cfg.get("passwordauthentication") or "").strip().lower()
    kbd = (cfg.get("kbdinteractiveauthentication")
           or cfg.get("challengeresponseauthentication") or "").strip().lower()
    if value == "no" and kbd != "yes":
        yield Finding("LOGIN-SSH-PASSWORD",
                      "SSH password authentication is disabled (keys only)",
                      Status.OK, reference=REF)
    elif not value:
        yield Finding("LOGIN-SSH-PASSWORD",
                      "SSH password authentication policy is unset",
                      Status.INFO,
                      "Could not read PasswordAuthentication; the OpenSSH "
                      "default is 'yes'.", Severity.LOW, reference=REF)
    else:
        yield Finding("LOGIN-SSH-PASSWORD",
                      "SSH accepts password authentication", Status.WARN,
                      "Password logins are brute-forceable. Move to SSH keys "
                      "and set PasswordAuthentication no once every operator "
                      "has a key installed.", Severity.MEDIUM,
                      Remediation(
                          "Disable SSH password authentication",
                          func=lambda: set_config_line(
                              SSHD_CONFIG, "PasswordAuthentication", "no",
                              sep=" "),
                          backup_files=[SSHD_CONFIG],
                          restart="sshd", restart_cmd=SSHD_RELOAD,
                          risk=LOCKOUT_RISK,
                          manual="Install SSH keys for every operator, verify "
                                 "you can log in with one, then set "
                                 "PasswordAuthentication no."),
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
                                  commands=["whmapi1 set_tweaksetting "
                                            "key=minpwstrength value=65"],
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
                                  commands=["whmapi1 set_tweaksetting "
                                            "key=minpwstrength value=65"],
                                  manual="WHM > Security Center > Password "
                                         "Strength Configuration."),
                      reference=REF)


def _csf_allowed_all(port):
    """True if CSF opens ``port`` to the whole internet via TCP_IN."""
    conf = read_file("/etc/csf/csf.conf")
    if conf is None:
        return None
    tcp_in = parse_kv(conf).get("TCP_IN")
    if tcp_in is None:
        return None
    return port in [p.strip() for p in tcp_in.split(",")]


@register("LOGIN-HOSTACCESS", "IP-restricted admin access", CAT, order=50)
def host_access():
    """Is administrative access (SSH, WHM) limited to known addresses?

    Two mechanisms count: Host Access Control (/etc/hosts.allow), and a CSF
    TCP_IN list that does not open the admin ports to everyone.
    """
    hosts_allow = read_file("/etc/hosts.allow") or ""
    rules = [line.strip() for line in hosts_allow.splitlines()
             if line.strip() and not line.strip().startswith("#")]

    admin_ports = ["22", "2087"]
    wide_open = [p for p in admin_ports if _csf_allowed_all(p) is True]
    csf_known = _csf_allowed_all("22") is not None

    if rules:
        yield Finding("LOGIN-HOSTACCESS",
                      "Host Access Control rules are configured (%d rule(s))"
                      % len(rules), Status.OK,
                      "Verify the rules cover SSH and WHM.", reference=REF)
    elif not csf_known:
        yield Finding("LOGIN-HOSTACCESS",
                      "Administrative access is not IP-restricted", Status.INFO,
                      "No /etc/hosts.allow rules and no CSF config to inspect. "
                      "Limiting SSH and WHM to trusted addresses removes most "
                      "brute-force exposure.", Severity.LOW,
                      Remediation("Configure IP allow-lists",
                                  manual="WHM > Security Center > Host Access "
                                         "Control, or restrict TCP_IN in CSF."),
                      reference=REF)
    elif wide_open:
        yield Finding("LOGIN-HOSTACCESS",
                      "Admin ports are open to every address: %s"
                      % ", ".join(wide_open), Status.WARN,
                      "CSF TCP_IN allows these from anywhere and there are no "
                      "Host Access Control rules. Anyone on the internet can "
                      "reach the login prompt.", Severity.MEDIUM,
                      Remediation("Restrict admin ports to trusted IPs",
                                  manual="Remove %s from TCP_IN in "
                                         "/etc/csf/csf.conf and allow your "
                                         "addresses in /etc/csf/csf.allow, or "
                                         "use WHM > Host Access Control."
                                         % "/".join(wide_open)),
                      reference=REF)
    else:
        yield Finding("LOGIN-HOSTACCESS",
                      "Admin ports are not open to the whole internet in CSF",
                      Status.OK, reference=REF)


@register("LOGIN-ROOT-KEYS", "Root SSH authorized keys", CAT, order=60)
def root_keys():
    path = "/root/.ssh/authorized_keys"
    text = read_file(path)
    if text is None:
        yield Finding("LOGIN-ROOT-KEYS", "No SSH keys authorised for root",
                      Status.INFO,
                      "Root has no authorized_keys file. Key-based access is a "
                      "prerequisite for disabling password logins.",
                      Severity.LOW, reference=REF)
        return
    keys = [l for l in text.splitlines()
            if l.strip() and not l.strip().startswith("#")]
    mode = None
    try:
        mode = os.stat(path).st_mode & 0o777
    except OSError:
        pass
    if mode is not None and mode & 0o077:
        yield Finding("LOGIN-ROOT-KEYS",
                      "root authorized_keys is group/world accessible (%o)" % mode,
                      Status.FAIL,
                      "sshd refuses keys from a loosely-permissioned file, and "
                      "any local user can read or replace it.", Severity.HIGH,
                      Remediation("chmod 600 %s" % path,
                                  commands=["chmod 600 %s" % path],
                                  manual="chmod 600 %s" % path),
                      reference=REF)
    else:
        yield Finding("LOGIN-ROOT-KEYS",
                      "%d SSH key(s) authorised for root" % len(keys),
                      Status.OK, "Review them and remove any you do not "
                      "recognise.", reference=REF)
