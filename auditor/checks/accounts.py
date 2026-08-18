"""Section 4 - Secure user accounts and permissions."""

import os

from ..core.model import Finding, Remediation, Severity, Status
from ..core.registry import register
from ..core.util import (cpanel_config, cpanel_users, is_cpanel, mount_options,
                         read_file, run, truthy, which)

CAT = "Accounts & Permissions"
REF = "cPanel checklist #4: Secure user accounts and permissions"

# Shells that do NOT give a real interactive shell.
SAFE_SHELLS = {"/usr/local/cpanel/bin/jailshell", "/usr/local/cpanel/bin/noshell",
               "/sbin/nologin", "/usr/sbin/nologin", "/bin/false",
               "/usr/bin/false"}


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
    if rc != 0:
        yield Finding("ACC-CAGEFS", "CageFS status could not be determined",
                      Status.WARN, "cagefsctl --cagefs-status failed.",
                      Severity.LOW, reference=REF)
        return
    if "enabled" in out.lower() and "disabled" not in out.lower():
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
                      Status.WARN, "\n".join(sorted(shelled)), Severity.MEDIUM,
                      Remediation("Demote to jailed shell (jailshell)",
                                  manual="WHM > Account Functions > Manage Shell "
                                         "Access; set non-admins to Jailed Shell."),
                      reference=REF)


@register("ACC-FILEPROTECT", "FileProtect", CAT, order=40)
def file_protect():
    """cPanel's FileProtect stops one account reading another's document root."""
    if not is_cpanel():
        yield Finding("ACC-FILEPROTECT", "FileProtect (cPanel only)", Status.SKIP,
                      reference=REF)
        return
    cfg = cpanel_config()
    value = cfg.get("file_protect")
    script = "/usr/local/cpanel/scripts/enablefileprotect"
    if value is None:
        yield Finding("ACC-FILEPROTECT", "FileProtect status is unknown",
                      Status.WARN,
                      "file_protect is not set in /var/cpanel/cpanel.config.",
                      Severity.LOW,
                      Remediation("Enable FileProtect",
                                  manual="WHM > Tweak Settings > "
                                         "Security > File Protect."),
                      reference=REF)
    elif truthy(value):
        yield Finding("ACC-FILEPROTECT", "FileProtect is enabled", Status.OK,
                      reference=REF)
    else:
        yield Finding("ACC-FILEPROTECT", "FileProtect is disabled", Status.FAIL,
                      "Without FileProtect, one account's PHP can read another "
                      "account's document root.", Severity.HIGH,
                      Remediation(
                          "Enable FileProtect",
                          commands=(["whmapi1 set_tweaksetting key=file_protect "
                                     "value=1", script]
                                    if os.path.isfile(script)
                                    else ["whmapi1 set_tweaksetting "
                                          "key=file_protect value=1"]),
                          manual="WHM > Tweak Settings > Security > File "
                                 "Protect, then run %s." % script),
                      reference=REF)


@register("ACC-TMP-NOEXEC", "/tmp mount hardening", CAT, order=50)
def tmp_noexec():
    """A world-writable /tmp that permits execution is a standard foothold."""
    opts = mount_options("/tmp")
    if opts is None:
        yield Finding("ACC-TMP-NOEXEC", "/tmp is not a separate filesystem",
                      Status.WARN,
                      "cPanel's securetmp creates a loopback /tmp mounted "
                      "noexec,nosuid so uploaded scripts cannot be executed "
                      "from it.", Severity.MEDIUM,
                      Remediation(
                          "Create a hardened /tmp with securetmp",
                          manual="Run /usr/local/cpanel/scripts/securetmp "
                                 "(it creates /usr/tmpDSK and remounts /tmp "
                                 "noexec,nosuid). Stop services using /tmp "
                                 "first."),
                      reference=REF)
        return
    missing = [o for o in ("noexec", "nosuid") if o not in opts]
    if not missing:
        yield Finding("ACC-TMP-NOEXEC", "/tmp is mounted noexec,nosuid",
                      Status.OK, ",".join(opts), reference=REF)
    else:
        yield Finding("ACC-TMP-NOEXEC",
                      "/tmp is missing mount option(s): %s" % ", ".join(missing),
                      Status.FAIL,
                      "Anyone who can write to /tmp can run binaries from it.\n"
                      "Current: %s" % ",".join(opts), Severity.HIGH,
                      Remediation(
                          "Remount /tmp noexec,nosuid",
                          manual="Add noexec,nosuid,nodev to the /tmp line in "
                                 "/etc/fstab, then 'mount -o remount /tmp'. "
                                 "Check no application needs to execute from "
                                 "/tmp first."),
                      reference=REF)


@register("ACC-COMPILERS", "Compiler access", CAT, order=60)
def compilers():
    """Unprivileged access to a compiler lets an attacker build local exploits."""
    if not is_cpanel():
        yield Finding("ACC-COMPILERS", "Compiler access (cPanel only)",
                      Status.SKIP, reference=REF)
        return
    exposed = []
    for name in ("gcc", "cc", "g++", "c++"):
        path = which(name)
        if not path:
            continue
        try:
            mode = os.stat(path).st_mode & 0o777
        except OSError:
            continue
        # cPanel's 'compilers off' chmods these to 0700 (root-only).
        if mode & 0o055:
            exposed.append("%s (%o)" % (path, mode))
    if not exposed:
        yield Finding("ACC-COMPILERS",
                      "Compilers are restricted to root (or not installed)",
                      Status.OK, reference=REF)
    else:
        yield Finding("ACC-COMPILERS", "Compilers are usable by every account",
                      Status.WARN,
                      "Shared-hosting accounts can compile local privilege "
                      "escalation exploits.\n" + "\n".join(exposed),
                      Severity.MEDIUM,
                      Remediation(
                          "Restrict compilers to root",
                          commands=["/usr/local/cpanel/scripts/compilers off"],
                          manual="WHM > Security Center > Compiler Access > "
                                 "Disable Compilers. Re-enable temporarily if "
                                 "you need to build software."),
                      reference=REF)
