"""Section 4 - Secure user accounts and permissions."""

import os

from ..core.model import Finding, Remediation, Severity, Status
from ..core.registry import register
from ..core.util import cpanel_users, is_cpanel, read_file, run, which

CAT = "Accounts & Permissions"
REF = "cPanel checklist #4: Secure user accounts and permissions"

# Shells that do NOT give a real interactive shell.
SAFE_SHELLS = {"/usr/local/cpanel/bin/jailshell", "/usr/local/cpanel/bin/noshell",
               "/sbin/nologin", "/usr/sbin/nologin", "/bin/false"}


@register("ACC-CLOUDLINUX", "CloudLinux", CAT, order=10)
def cloudlinux():
    if read_file("/etc/cloudlinux-release") or which("cldetect"):
        yield Finding("ACC-CLOUDLINUX", "CloudLinux is installed", Status.OK,
                      reference=REF)
    else:
        yield Finding("ACC-CLOUDLINUX", "CloudLinux is not installed",
                      Status.INFO,
                      "CloudLinux adds per-account isolation (CageFS) and "
                      "resource limits. Recommended for shared hosting.",
                      Severity.INFO,
                      Remediation("Consider CloudLinux",
                                  manual="https://www.cloudlinux.com/ "
                                         "(licensed product)."),
                      reference=REF)


@register("ACC-CAGEFS", "CageFS isolation", CAT, order=20)
def cagefs():
    if not which("cagefsctl"):
        yield Finding("ACC-CAGEFS", "CageFS (requires CloudLinux)", Status.SKIP,
                      "cagefsctl not present.", reference=REF)
        return
    rc, out, _ = run(["cagefsctl", "--cagefs-status"])
    enabled = rc == 0 and "enabled" in out.lower()
    if enabled:
        yield Finding("ACC-CAGEFS", "CageFS is enabled", Status.OK, reference=REF)
    else:
        yield Finding("ACC-CAGEFS", "CageFS is not enabled", Status.FAIL,
                      "CageFS isolates each user, preventing cross-account attacks.",
                      Severity.HIGH,
                      Remediation("Enable CageFS for all users",
                                  commands=["cagefsctl --init",
                                            "cagefsctl --enable-all"],
                                  manual="https://docs.cloudlinux.com/cagefs/"),
                      reference=REF)


@register("ACC-SHELL", "Shell access for accounts", CAT, order=30)
def shell_access():
    if not is_cpanel():
        yield Finding("ACC-SHELL", "Shell access (cPanel only)", Status.SKIP,
                      "Not a cPanel server.", reference=REF)
        return
    users = set(cpanel_users())
    if not users:
        yield Finding("ACC-SHELL", "No cPanel accounts found", Status.SKIP,
                      reference=REF)
        return
    passwd = read_file("/etc/passwd") or ""
    shelled = []
    for line in passwd.splitlines():
        parts = line.split(":")
        if len(parts) >= 7 and parts[0] in users:
            shell = parts[6]
            if shell and shell not in SAFE_SHELLS:
                shelled.append("%s (%s)" % (parts[0], shell))
    if not shelled:
        yield Finding("ACC-SHELL",
                      "No non-admin accounts have unrestricted shell access",
                      Status.OK, reference=REF)
    else:
        yield Finding("ACC-SHELL",
                      "%d account(s) have full shell access" % len(shelled),
                      Status.WARN, "\n".join(shelled), Severity.MEDIUM,
                      Remediation("Demote to jailed shell (jailshell)",
                                  manual="WHM > Account Functions > Manage Shell "
                                         "Access; set non-admins to Jailed Shell."),
                      reference=REF)


@register("ACC-FILEPERM", "File permission hardening", CAT, order=40)
def file_perms():
    yield Finding("ACC-FILEPERM", "Restrict file permissions (FileProtect)",
                  Status.INFO,
                  "Run FileProtect and keep secure permissions on user "
                  "directories and config files.", Severity.INFO,
                  Remediation("Apply FileProtect",
                              commands=["/scripts/enablefileprotect"]
                              if os.path.isfile("/scripts/enablefileprotect")
                              else [],
                              manual="WHM > Security Center > Configure Security "
                                     "Policies / run /scripts/enablefileprotect."),
                  reference=REF)
