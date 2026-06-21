"""Section 6 - Secure database and PHP settings."""

from ..core.model import Finding, Remediation, Severity, Status
from ..core.registry import register
from ..core.util import (ea_php_inis, listening_ports, parse_kv, read_file, run,
                         which)

CAT = "Database & PHP"
REF = "cPanel checklist #6: Secure database and PHP settings"

DANGEROUS_FUNCS = ["exec", "passthru", "shell_exec", "system", "proc_open",
                   "popen"]


@register("DB-REMOTE", "MySQL network exposure", CAT, order=10)
def mysql_remote():
    public = [p for addr, p in listening_ports()
              if p == "3306" and addr not in ("127.0.0.1", "::1")]
    if not public:
        yield Finding("DB-REMOTE", "MySQL is not exposed to the network",
                      Status.OK, reference=REF)
    else:
        yield Finding("DB-REMOTE", "MySQL is listening on a public interface",
                      Status.FAIL,
                      "Port 3306 is reachable beyond localhost. Restrict to "
                      "localhost unless remote access is required.", Severity.HIGH,
                      Remediation(
                          "Bind MySQL to localhost",
                          manual="Add 'bind-address=127.0.0.1' to /etc/my.cnf "
                                 "and restart MySQL, or restrict 3306 in CSF."),
                      reference=REF)


@register("DB-SHOWDB", "MySQL SHOW DATABASES exposure", CAT, order=12)
def show_databases():
    # The relevant MySQL option is skip_show_database. Prefer a live query;
    # fall back to scanning my.cnf.
    value = None
    if which("mysql"):
        rc, out, _ = run("mysql -N -B -e \"SHOW VARIABLES LIKE 'skip_show_database'\" "
                         "2>/dev/null")
        if rc == 0 and out:
            parts = out.split()
            if len(parts) >= 2:
                value = parts[1].upper()  # ON / OFF
    if value is None:
        cnf = (read_file("/etc/my.cnf") or "") + (read_file("/etc/my.cnf.d/server.cnf") or "")
        low = cnf.lower()
        if "skip-show-database" in low or "skip_show_database" in low:
            value = "ON"
    if value == "ON":
        yield Finding("DB-SHOWDB", "SHOW DATABASES is restricted to privileged users",
                      Status.OK, reference=REF)
    elif value == "OFF" or value is None:
        yield Finding("DB-SHOWDB",
                      "Any DB user can run SHOW DATABASES", Status.WARN,
                      "skip_show_database is off; users can enumerate all "
                      "databases on the server.", Severity.MEDIUM,
                      Remediation(
                          "Enable skip_show_database",
                          manual="Add 'skip_show_database' under [mysqld] in "
                                 "/etc/my.cnf and restart MySQL."),
                      reference=REF)


@register("DB-PW", "Database user passwords", CAT, order=14)
def db_passwords():
    yield Finding("DB-PW", "Use strong, unique database passwords", Status.INFO,
                  "Ensure every MySQL user has a strong, unique password; avoid "
                  "reusing the cPanel account password.", Severity.INFO,
                  Remediation("Rotate weak DB passwords",
                              manual="cPanel > MySQL Databases / Manage users; "
                                     "set strong unique passwords."),
                  reference=REF)


def _scan_inis(directive, want_present=None, want_absent=None):
    """Return list of (ini, value) for inis whose directive value is risky."""
    bad = []
    for ini in ea_php_inis():
        cfg = parse_kv(read_file(ini))
        # parse_kv lowercases nothing; PHP keys are case-sensitive lowercase
        val = cfg.get(directive)
        if val is None:
            continue
        yield ini, val


@register("PHP-EXPOSE", "expose_php", CAT, order=20)
def expose_php():
    inis = ea_php_inis()
    if not inis:
        yield Finding("PHP-EXPOSE", "expose_php (no PHP found)", Status.SKIP,
                      reference=REF)
        return
    bad = [ini for ini, val in _scan_inis("expose_php") if val.lower() == "on"]
    if not bad:
        yield Finding("PHP-EXPOSE", "expose_php is Off", Status.OK, reference=REF)
    else:
        yield Finding("PHP-EXPOSE", "expose_php is On in %d PHP version(s)"
                      % len(bad), Status.WARN,
                      "Leaks the PHP version in HTTP headers.\n" + "\n".join(bad),
                      Severity.LOW,
                      Remediation(
                          "Set expose_php = Off in all EA-PHP php.ini files",
                          commands=["for f in /opt/cpanel/ea-php*/root/etc/php.ini; "
                                    "do sed -ri 's/^[;[:space:]]*expose_php\\s*=.*/"
                                    "expose_php = Off/' \"$f\"; done"],
                          restart="apache (ea-php-fpm)"),
                      reference=REF)


@register("PHP-URLFOPEN", "allow_url_fopen", CAT, order=30)
def allow_url_fopen():
    inis = ea_php_inis()
    if not inis:
        yield Finding("PHP-URLFOPEN", "allow_url_fopen (no PHP found)",
                      Status.SKIP, reference=REF)
        return
    bad = [ini for ini, val in _scan_inis("allow_url_fopen")
           if val.lower() == "on"]
    if not bad:
        yield Finding("PHP-URLFOPEN", "allow_url_fopen is Off", Status.OK,
                      reference=REF)
    else:
        yield Finding("PHP-URLFOPEN",
                      "allow_url_fopen is On in %d PHP version(s)" % len(bad),
                      Status.WARN,
                      "Allows fetching remote URLs as files; enables some RFI "
                      "attacks. Disable unless an app needs it.\n" + "\n".join(bad),
                      Severity.MEDIUM,
                      Remediation(
                          "Set allow_url_fopen = Off",
                          commands=["for f in /opt/cpanel/ea-php*/root/etc/php.ini; "
                                    "do sed -ri 's/^[;[:space:]]*allow_url_fopen\\s*"
                                    "=.*/allow_url_fopen = Off/' \"$f\"; done"],
                          restart="apache (ea-php-fpm)"),
                      reference=REF)


@register("PHP-DISABLE-FUNC", "Dangerous PHP functions", CAT, order=40)
def disable_functions():
    inis = ea_php_inis()
    if not inis:
        yield Finding("PHP-DISABLE-FUNC", "disable_functions (no PHP found)",
                      Status.SKIP, reference=REF)
        return
    weak = []
    for ini in inis:
        cfg = parse_kv(read_file(ini))
        disabled = cfg.get("disable_functions", "")
        present = {f.strip() for f in disabled.split(",") if f.strip()}
        missing = [f for f in DANGEROUS_FUNCS if f not in present]
        if missing:
            weak.append("%s: missing %s" % (ini, ",".join(missing)))
    if not weak:
        yield Finding("PHP-DISABLE-FUNC",
                      "Dangerous PHP functions are disabled", Status.OK,
                      reference=REF)
    else:
        yield Finding("PHP-DISABLE-FUNC",
                      "Dangerous PHP functions are enabled in %d version(s)"
                      % len(weak), Status.WARN,
                      "Recommend disabling: %s\n%s"
                      % (", ".join(DANGEROUS_FUNCS), "\n".join(weak)),
                      Severity.MEDIUM,
                      Remediation(
                          "Add dangerous functions to disable_functions",
                          manual="WHM > MultiPHP INI Editor > disable_functions; "
                                 "add: %s (verify no app needs them first)."
                                 % ",".join(DANGEROUS_FUNCS)),
                      reference=REF)


# Disabled per user request — open_basedir check is not wanted.
# @register("PHP-OPENBASEDIR", "open_basedir protection", CAT, order=50)
# def open_basedir():
#     if read_file("/var/cpanel/version") is None:
#         # PHP open_basedir tweak is cPanel-managed
#         pass
#     setting = read_file("/var/cpanel/cpanel.config") or ""
#     cfg = parse_kv(setting)
#     val = cfg.get("php_open_basedir_protect") or cfg.get("phpopenbasedirprotect")
#     if val == "1":
#         yield Finding("PHP-OPENBASEDIR", "open_basedir protection is enabled",
#                       Status.OK, reference=REF)
#     else:
#         yield Finding("PHP-OPENBASEDIR", "open_basedir protection is not enabled",
#                       Status.WARN,
#                       "open_basedir confines each account's PHP to its own "
#                       "directory tree.", Severity.MEDIUM,
#                       Remediation(
#                           "Enable PHP open_basedir protection",
#                           commands=["whmapi1 set_tweaksetting "
#                                     "key=php_open_basedir_protect value=1"],
#                           manual="WHM > Security Center > PHP open_basedir Tweak."),
#                       reference=REF)
