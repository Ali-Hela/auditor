"""Section 6 - Secure database and PHP settings."""

from ..core.model import Finding, Remediation, Severity, Status
from ..core.registry import register
from ..core.util import (ea_php_inis, is_public_addr, listening_ports,
                         mysql_available, mysql_variable, php_ini_config,
                         php_version_of_ini, read_file, run, set_config_line,
                         truthy, which)

CAT = "Database & PHP"
REF = "cPanel checklist #6: Secure database and PHP settings"

DANGEROUS_FUNCS = ["exec", "passthru", "shell_exec", "system", "proc_open",
                   "popen"]

# PHP branches past end of life as of 2026. Anything at or below this receives
# no security patches from php.net.
EOL_PHP_VERSIONS = {"5.4", "5.5", "5.6", "7.0", "7.1", "7.2", "7.3", "7.4",
                    "8.0", "8.1"}

PHP_RESTART = "apache (ea-php-fpm)"


@register("DB-REMOTE", "MySQL network exposure", CAT, order=10)
def mysql_remote():
    ports = listening_ports()
    if not ports:
        yield Finding("DB-REMOTE", "MySQL exposure (could not list sockets)",
                      Status.SKIP, "ss/netstat unavailable.", reference=REF)
        return
    bound = [addr for addr, p in ports if p == "3306"]
    if not bound:
        yield Finding("DB-REMOTE", "Nothing is listening on 3306", Status.SKIP,
                      "MySQL is not running, or uses a socket only.",
                      reference=REF)
        return
    public = [addr for addr in bound if is_public_addr(addr)]
    if not public:
        yield Finding("DB-REMOTE", "MySQL is bound to localhost only",
                      Status.OK, ", ".join(sorted(bound)), reference=REF)
    else:
        yield Finding("DB-REMOTE", "MySQL is listening on a public interface",
                      Status.FAIL,
                      "Port 3306 is reachable beyond localhost (%s). Restrict "
                      "to localhost unless remote access is required."
                      % ", ".join(sorted(public)), Severity.HIGH,
                      Remediation(
                          "Bind MySQL to localhost",
                          manual="Add 'bind-address=127.0.0.1' under [mysqld] "
                                 "in /etc/my.cnf and restart MySQL, or remove "
                                 "3306 from TCP_IN in CSF. Check no application "
                                 "connects over the network first."),
                      reference=REF)


@register("DB-SHOWDB", "MySQL SHOW DATABASES exposure", CAT, order=12)
def show_databases():
    if not which("mysql"):
        yield Finding("DB-SHOWDB", "SHOW DATABASES (no MySQL client)",
                      Status.SKIP, reference=REF)
        return
    value = mysql_variable("skip_show_database")
    if value is None:
        # Fall back to the config files; if that fails too we genuinely do not
        # know, and an unknown is not a finding.
        cnf = ((read_file("/etc/my.cnf") or "")
               + (read_file("/etc/my.cnf.d/server.cnf") or "")).lower()
        if "skip-show-database" in cnf or "skip_show_database" in cnf:
            value = "ON"
        else:
            yield Finding("DB-SHOWDB",
                          "SHOW DATABASES policy could not be determined",
                          Status.SKIP,
                          "Could not query MySQL or read my.cnf.", reference=REF)
            return
    if truthy(value):
        yield Finding("DB-SHOWDB",
                      "SHOW DATABASES is restricted to privileged users",
                      Status.OK, reference=REF)
    else:
        yield Finding("DB-SHOWDB",
                      "SHOW DATABASES is available to database users",
                      Status.WARN,
                      "skip_show_database is off. MySQL still hides databases a "
                      "user holds no privileges on, so this is defence in depth "
                      "rather than a direct leak - but enabling it means only "
                      "accounts with the SHOW DATABASES privilege can run the "
                      "statement at all.", Severity.LOW,
                      Remediation(
                          "Enable skip_show_database",
                          manual="Add 'skip_show_database' under [mysqld] in "
                                 "/etc/my.cnf and restart MySQL."),
                      reference=REF)


@register("DB-PW", "Database users without passwords", CAT, order=14)
def db_passwords():
    if not mysql_available():
        yield Finding("DB-PW", "Database passwords (MySQL not reachable)",
                      Status.SKIP,
                      "No mysql client, or it could not connect as root.",
                      reference=REF)
        return
    # authentication_string is the modern column; MySQL 5.6 and earlier used
    # Password. Try the modern one and fall back.
    query = ("SELECT CONCAT(user,'@',host) FROM mysql.user "
             "WHERE authentication_string='' AND plugin IN "
             "('mysql_native_password','')")
    rc, out, _ = run(["mysql", "-N", "-B", "-e", query])
    if rc != 0:
        rc, out, _ = run(["mysql", "-N", "-B", "-e",
                          "SELECT CONCAT(user,'@',host) FROM mysql.user "
                          "WHERE Password=''"])
    if rc != 0:
        yield Finding("DB-PW", "Could not enumerate database users", Status.SKIP,
                      "mysql.user is not readable.", reference=REF)
        return
    empty = [u for u in out.splitlines() if u.strip()]
    if not empty:
        yield Finding("DB-PW", "Every database user has a password", Status.OK,
                      reference=REF)
    else:
        yield Finding("DB-PW",
                      "%d database user(s) have no password" % len(empty),
                      Status.FAIL, "\n".join(empty), Severity.HIGH,
                      Remediation(
                          "Set or remove passwordless database accounts",
                          manual="For each account: ALTER USER 'u'@'h' "
                                 "IDENTIFIED BY '<strong password>'; or DROP "
                                 "USER if unused. Update any application "
                                 "config that uses it."),
                      reference=REF)


def _php_setting(directive):
    """Yield (ini, value) for every php.ini that sets ``directive``."""
    for ini in ea_php_inis():
        val = php_ini_config(ini).get(directive)
        if val is not None:
            yield ini, val


def _php_ini_fix(directive, value):
    """A fix that rewrites a directive across every discovered php.ini."""
    def apply():
        results = [set_config_line(ini, directive, value, spaced=True,
                                   comments=";#")
                   for ini in ea_php_inis()]
        return bool(results) and all(results)
    return apply


@register("PHP-EOL", "End-of-life PHP versions", CAT, order=15)
def php_eol():
    """Unsupported PHP receives no security patches - usually the biggest risk."""
    inis = ea_php_inis()
    if not inis:
        yield Finding("PHP-EOL", "PHP versions (no PHP found)", Status.SKIP,
                      reference=REF)
        return
    eol = []
    for ini in inis:
        version = php_version_of_ini(ini)
        if version and version in EOL_PHP_VERSIONS:
            eol.append(version)
    if not eol:
        yield Finding("PHP-EOL", "No end-of-life PHP versions are installed",
                      Status.OK, reference=REF)
    else:
        eol = sorted(set(eol))
        yield Finding("PHP-EOL",
                      "End-of-life PHP installed: %s" % ", ".join(eol),
                      Status.FAIL,
                      "These branches receive no security patches. Any account "
                      "still assigned to one is running unpatched code.\n"
                      "List assignments with: whmapi1 php_get_vhost_versions",
                      Severity.HIGH,
                      Remediation(
                          "Migrate accounts off EOL PHP, then uninstall it",
                          manual="WHM > MultiPHP Manager: move every vhost to a "
                                 "supported version (8.2+), test the sites, "
                                 "then remove the ea-php%s packages in "
                                 "EasyApache 4."
                                 % eol[0].replace(".", "")),
                      reference=REF)


@register("PHP-EXPOSE", "expose_php", CAT, order=20)
def expose_php():
    if not ea_php_inis():
        yield Finding("PHP-EXPOSE", "expose_php (no PHP found)", Status.SKIP,
                      reference=REF)
        return
    bad = [ini for ini, val in _php_setting("expose_php")
           if truthy(val)]
    if not bad:
        yield Finding("PHP-EXPOSE", "expose_php is Off", Status.OK, reference=REF)
    else:
        yield Finding("PHP-EXPOSE", "expose_php is On in %d PHP version(s)"
                      % len(bad), Status.WARN,
                      "Leaks the PHP version in HTTP headers.\n" + "\n".join(bad),
                      Severity.LOW,
                      Remediation(
                          "Set expose_php = Off in all EA-PHP php.ini files",
                          func=_php_ini_fix("expose_php", "Off"),
                          backup_files=bad,
                          restart=PHP_RESTART,
                          manual="WHM > MultiPHP INI Editor > expose_php = Off."),
                      reference=REF)


@register("PHP-URLFOPEN", "allow_url_fopen", CAT, order=30)
def allow_url_fopen():
    if not ea_php_inis():
        yield Finding("PHP-URLFOPEN", "allow_url_fopen (no PHP found)",
                      Status.SKIP, reference=REF)
        return
    bad = [ini for ini, val in _php_setting("allow_url_fopen") if truthy(val)]
    if not bad:
        yield Finding("PHP-URLFOPEN", "allow_url_fopen is Off", Status.OK,
                      reference=REF)
    else:
        yield Finding("PHP-URLFOPEN",
                      "allow_url_fopen is On in %d PHP version(s)" % len(bad),
                      Status.WARN,
                      "Allows fetching remote URLs as files; enables some RFI "
                      "attacks. Many applications (WordPress included) need it, "
                      "so confirm before disabling.\n" + "\n".join(bad),
                      Severity.MEDIUM,
                      Remediation(
                          "Set allow_url_fopen = Off",
                          func=_php_ini_fix("allow_url_fopen", "Off"),
                          backup_files=bad,
                          restart=PHP_RESTART,
                          risk="breaks applications that fetch remote URLs "
                               "(WordPress updates, many plugins)",
                          manual="WHM > MultiPHP INI Editor > allow_url_fopen = "
                                 "Off. Test the sites afterwards."),
                      reference=REF)


@register("PHP-URLINCLUDE", "allow_url_include", CAT, order=35)
def allow_url_include():
    if not ea_php_inis():
        yield Finding("PHP-URLINCLUDE", "allow_url_include (no PHP found)",
                      Status.SKIP, reference=REF)
        return
    bad = [ini for ini, val in _php_setting("allow_url_include") if truthy(val)]
    if not bad:
        yield Finding("PHP-URLINCLUDE", "allow_url_include is Off", Status.OK,
                      reference=REF)
    else:
        yield Finding("PHP-URLINCLUDE",
                      "allow_url_include is On in %d PHP version(s)" % len(bad),
                      Status.FAIL,
                      "This turns any file-inclusion bug into remote code "
                      "execution. No modern application needs it.\n"
                      + "\n".join(bad), Severity.CRITICAL,
                      Remediation(
                          "Set allow_url_include = Off",
                          func=_php_ini_fix("allow_url_include", "Off"),
                          backup_files=bad,
                          restart=PHP_RESTART,
                          manual="WHM > MultiPHP INI Editor > "
                                 "allow_url_include = Off."),
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
        disabled = php_ini_config(ini).get("disable_functions", "")
        present = {f.strip().lower() for f in disabled.split(",") if f.strip()}
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
                          # Deliberately manual: overwriting disable_functions
                          # would discard entries the operator already set, and
                          # control panels and backup tools legitimately shell
                          # out.
                          manual="WHM > MultiPHP INI Editor > disable_functions; "
                                 "append: %s. Verify no application needs them "
                                 "first - some backup and control-panel plugins "
                                 "do." % ",".join(DANGEROUS_FUNCS)),
                      reference=REF)
