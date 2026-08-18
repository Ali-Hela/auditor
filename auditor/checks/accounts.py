"""Section 4 - Secure user accounts and permissions."""

import os

from ..core.model import Finding, Remediation, Severity, Status
from ..core.registry import register
from ..core.util import (apache_global_indexing, cpanel_config, cpanel_docroots,
                         cpanel_users, is_cpanel, mount_options,
                         parse_options_indexing, read_file, run, truthy, which)

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


INDEXING_DIRECTIVE = "Options -Indexes"
# Only the document root is inspected. Indexing is inherited, so -Indexes there
# covers every subdirectory below it unless one deliberately turns it back on -
# which is where the interesting content (uploads/, backups/) usually lives.
MAX_LISTED = 12


def _docroot_indexing():
    """[(user, docroot, state)] where state is True/False/None per .htaccess."""
    rows = []
    for user, docroot in cpanel_docroots():
        text = read_file(os.path.join(docroot, ".htaccess"))
        rows.append((user, docroot, parse_options_indexing(text)))
    return rows


def _summarise(paths):
    shown = ["  %s (%s)" % (root, user) for user, root in paths[:MAX_LISTED]]
    if len(paths) > MAX_LISTED:
        shown.append("  ... and %d more" % (len(paths) - MAX_LISTED))
    return "\n".join(shown)


def _disable_indexing(docroots):
    """Append 'Options -Indexes' to each document root's .htaccess.

    A .htaccess created here is chowned to match its document root, so the
    account keeps ownership of its own file and can still edit it from cPanel.
    """
    def apply():
        ok = True
        for docroot in docroots:
            path = os.path.join(docroot, ".htaccess")
            existed = os.path.isfile(path)
            try:
                with open(path, "a") as fh:
                    fh.write("\n# Added by auditor: disable directory listing\n"
                             "%s\n" % INDEXING_DIRECTIVE)
                if not existed:
                    st = os.stat(docroot)
                    os.chown(path, st.st_uid, st.st_gid)
                    os.chmod(path, 0o644)
            except OSError:
                ok = False
        return ok
    return apply


@register("ACC-INDEXING", "Directory indexing on account sites", CAT, order=55)
def directory_indexing():
    """Apache lists a directory's contents when it has no index file.

    On shared hosting that exposes uploads, database dumps, .sql/.zip backups
    and anything else a customer left lying around, so the standard is to turn
    it off. cPanel does not disable it by default.
    """
    if not is_cpanel():
        yield Finding("ACC-INDEXING", "Directory indexing (cPanel only)",
                      Status.SKIP, "Not a cPanel server.", reference=REF)
        return
    rows = _docroot_indexing()
    if not rows:
        yield Finding("ACC-INDEXING", "No account document roots found",
                      Status.SKIP,
                      "/var/cpanel/userdata could not be read and no "
                      "/home/*/public_html exists.", reference=REF)
        return

    enabled = [(u, r) for u, r, s in rows if s is True]
    unset = [(u, r) for u, r, s in rows if s is None]
    disabled = [(u, r) for u, r, s in rows if s is False]
    global_state = apache_global_indexing()

    if enabled:
        # An explicit '+Indexes' or bare 'Indexes' overrides whatever the
        # server default is, so this is a listing directory regardless.
        #
        # The fix has to cover the merely-unset roots as well, unless the
        # server default already disables indexing: otherwise fixing only the
        # explicit ones leaves the check reporting WARN, and verification
        # would correctly call the fix ineffective.
        targets = enabled + (unset if global_state is not False else [])
        yield Finding("ACC-INDEXING",
                      "Directory indexing is switched ON for %d site(s)"
                      % len(enabled), Status.FAIL,
                      "These .htaccess files explicitly enable directory "
                      "listing, so anyone can browse the files in any folder "
                      "without an index page:\n%s" % _summarise(enabled),
                      Severity.MEDIUM,
                      Remediation(
                          "Append '%s' to the affected .htaccess files"
                          % INDEXING_DIRECTIVE,
                          func=_disable_indexing([r for _, r in targets]),
                          backup_files=[os.path.join(r, ".htaccess")
                                        for _, r in targets],
                          risk="edits site configuration for %d account(s); a "
                               "site that deliberately serves a browsable "
                               "folder will stop doing so"
                               % len({u for u, _ in targets}),
                          manual="Add '%s' to each .htaccess listed above, or "
                                 "set it once for every account in WHM > "
                                 "Apache Configuration > Include Editor > "
                                 "Pre VirtualHost Include."
                                 % INDEXING_DIRECTIVE),
                      reference=REF)
        return

    if unset and global_state is not False:
        detail = ("No Options directive in these document roots, so the server "
                  "default applies")
        detail += (" - and no <Directory> block disables indexing either.\n"
                   if global_state is None else
                   " - which currently allows indexing.\n")
        detail += _summarise(unset)
        yield Finding("ACC-INDEXING",
                      "Directory indexing is not disabled for %d site(s)"
                      % len(unset), Status.WARN, detail, Severity.MEDIUM,
                      Remediation(
                          "Append '%s' to the affected .htaccess files"
                          % INDEXING_DIRECTIVE,
                          func=_disable_indexing([r for _, r in unset]),
                          backup_files=[os.path.join(r, ".htaccess")
                                        for _, r in unset],
                          risk="edits site configuration for %d account(s); a "
                               "site that deliberately serves a browsable "
                               "folder will stop doing so"
                               % len({u for u, _ in unset}),
                          manual="Better done once for every account: WHM > "
                                 "Apache Configuration > Include Editor > Pre "
                                 "VirtualHost Include, add\n"
                                 "  <Directory \"/home\">\n      %s\n"
                                 "  </Directory>\n"
                                 "then rebuild and restart Apache."
                                 % INDEXING_DIRECTIVE),
                      reference=REF)
        return

    if unset:
        yield Finding("ACC-INDEXING",
                      "Directory indexing is disabled server-wide", Status.OK,
                      "%d document root(s) rely on the global <Directory> "
                      "block; %d disable it in their own .htaccess."
                      % (len(unset), len(disabled)), reference=REF)
        return

    yield Finding("ACC-INDEXING",
                  "Directory indexing is disabled on all %d site(s)"
                  % len(disabled), Status.OK,
                  "Subdirectories can still re-enable it; this check reads the "
                  "document root .htaccess only.", reference=REF)


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
