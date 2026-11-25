"""Our own server standard, loaded from ``baseline.conf``.

The built-in checks implement the generic cPanel security checklist. The
baseline holds what is specific to *our* servers - timezone, database engine,
required plugins, settings stricter than the checklist - as one line per
setting, so a new standard is a one-line edit rather than new code.

Each line becomes an ordinary registered check: it gets an ID (``BL-...``),
shows up in ``--list``, works with ``--only`` / ``--json``, and its fix goes
through the same backup / verify / risk-gate engine as every other check.

File format::

    [Section]                         # report category "Baseline: Section"
    type args...                      # mismatch is a FAIL
    warn:type args...                 # mismatch is only a WARN
    type args... | Label              # text shown in the report
    set NAME value                    # a setting read by other checks

Values compare case-insensitively; on/yes/true/1 and off/no/false/0 are equal;
numbers may use <=N >=N <N >N.
"""

import os
import re
import shlex

from ..core.model import Finding, Remediation, Severity, Status
from ..core.registry import REGISTRY, CheckSpec
from ..core.util import (apache_modules, cpanel_config, ea_php_inis, is_cpanel,
                         php_ini_config, read_file, run, set_config_line,
                         sshd_config, sshd_files, which, whmapi1)

DEFAULT_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
    "baseline.conf")
CAT_PREFIX = "Baseline"
REF = "Our baseline (baseline.conf)"

# "set NAME value" lines, readable by any check via setting().
SETTINGS = {}

SSHD_MAIN = "/etc/ssh/sshd_config"
SSHD_RELOAD = "sshd -t && systemctl reload sshd"
# OpenSSH defaults, for when sshd -T is unavailable and only the config files
# can be read: an absent directive means the default applies, not "unset".
SSHD_DEFAULTS = {
    "permitrootlogin": "prohibit-password",
    "permitemptypasswords": "no",
    "passwordauthentication": "yes",
    "pubkeyauthentication": "yes",
    "x11forwarding": "no",
    "maxauthtries": "6",
    "port": "22",
}
SSHD_RISK = ("changes how you log in over SSH - confirm you have a working "
             "sudo account or console access first")
CSF_CONF = "/etc/csf/csf.conf"
PHP_RESTART = ("/usr/local/cpanel/scripts/restartsrv_apache_php_fpm; "
               "/usr/local/cpanel/scripts/restartsrv_httpd")

# Files cPanel regenerates from its own settings: never edit them directly.
MANAGED_FILES = {
    "/etc/pure-ftpd.conf": "WHM > Service Configuration > FTP Server Configuration",
    "/etc/apache2/conf/httpd.conf":
        "WHM > Service Configuration > Apache Configuration > Global Configuration",
    "/etc/exim.conf": "WHM > Service Configuration > Exim Configuration Manager",
}
# whmapi1 read function -> command that turns it on.
WHMAPI_FIXES = {
    "twofactorauth_policy_status": "whmapi1 twofactorauth_enable_policy",
}


def setting(name, default=""):
    return SETTINGS.get(name, default)


# --------------------------------------------------------------- matching

_TRUE = {"1", "on", "yes", "true", "enabled"}
_FALSE = {"0", "off", "no", "false", "disabled"}
_ALIASES = {
    "prohibit-password": "without-password",  # sshd -T prints the old name
    "prod": "productonly",                    # Apache ServerTokens
}
_RANGE = re.compile(r"^(<=|>=|<|>)(\d+)$")


def _canon(value):
    v = str(value).strip().lower()
    if v in _TRUE:
        return "1"
    if v in _FALSE:
        return "0"
    return _ALIASES.get(v, v)


def same(want, got):
    """Does ``got`` satisfy the expected value ``want``?"""
    if got is None:
        return False
    m = _RANGE.match(want.strip())
    if m:
        if not str(got).strip().isdigit():
            return False
        n, g = int(m.group(2)), int(str(got).strip())
        return {"<=": g <= n, ">=": g >= n, "<": g < n, ">": g > n}[m.group(1)]
    return _canon(want) == _canon(got)


def is_range(want):
    return bool(_RANGE.match(want.strip()))


# ----------------------------------------------------------- rule outcome

class Outcome(object):
    """What a rule found. ``ok`` is True, False, or None (could not tell)."""

    def __init__(self, ok, desc, detail="", remediation=None, note=""):
        self.ok = ok
        self.desc = desc
        self.detail = detail
        self.remediation = remediation
        self.note = note


def _mismatch(desc, want, got, remediation=None):
    found = "not set" if got is None else "'%s'" % got
    return Outcome(False, desc, "Expected '%s', found %s." % (want, found),
                   remediation)


def _expect(desc, want, got, remediation=None, note=""):
    if same(want, got):
        return Outcome(True, desc, note=note)
    return _mismatch(desc, want, got, None if is_range(want) else remediation)


# ------------------------------------------------------------- file edits

_COMMENT = ("#", ";")


def _kv_pattern(key):
    return re.compile(r"^(\s*%s(?:\s*=\s*|\s+))(.*)$" % re.escape(key))


def kv_get(text, key):
    """Last uncommented value of ``key`` (``K=V``, ``K = "V"`` or ``K V``)."""
    pattern = _kv_pattern(key)
    value = None
    for raw in (text or "").splitlines():
        if raw.strip().startswith(_COMMENT):
            continue
        m = pattern.match(raw)
        if m:
            v = re.sub(r"\s+[#;].*$", "", m.group(2)).strip()
            if len(v) >= 2 and v[0] == v[-1] and v[0] in "\"'":
                v = v[1:-1]
            value = v
    return value


def kv_set(path, key, value):
    """Set every uncommented ``key`` line, keeping its separator and quotes.

    Appends the setting, in the file's own style, when the key is absent.
    """
    text = read_file(path)
    if text is None:
        return False
    pattern = _kv_pattern(key)
    lines, replaced = text.splitlines(), False
    for i, raw in enumerate(lines):
        if raw.strip().startswith(_COMMENT):
            continue
        m = pattern.match(raw)
        if m:
            old = m.group(2).strip()
            quote = old[0] if old[:1] in ("\"", "'") else ""
            lines[i] = "%s%s%s%s" % (m.group(1), quote, value, quote)
            replaced = True
    if not replaced:
        if re.search(r'^\w+ = "', text, re.M):
            lines.append('%s = "%s"' % (key, value))
        elif re.search(r"^\w+=", text, re.M):
            lines.append("%s=%s" % (key, value))
        else:
            lines.append("%s %s" % (key, value))
    try:
        with open(path, "w") as fh:
            fh.write("\n".join(lines) + "\n")
    except OSError:
        return False
    read_file.cache_clear()
    return True


def _sshd_targets(key):
    """sshd files that set ``key`` outside a Match block, else the main file."""
    pattern = re.compile(r"^\s*%s\s" % re.escape(key), re.I)
    hits = []
    for path in sshd_files():
        for line in (read_file(path) or "").splitlines():
            if line.strip().lower().startswith("match "):
                break
            if pattern.match(line):
                hits.append(path)
                break
    return hits or [SSHD_MAIN]


def _sshd_set(key, value):
    """Set an sshd directive in every file that defines it.

    When nobody defines it yet, the line goes into sshd_config *before* any
    Match block - appending at the end would scope it to the last Match.
    """
    targets = _sshd_targets(key)
    defined = any(re.search(r"^\s*%s\s" % re.escape(key), read_file(p) or "",
                            re.I | re.M) for p in targets)
    if defined:
        return all(set_config_line(p, key, value, sep=" ") for p in targets)
    text = read_file(SSHD_MAIN)
    if text is None:
        return False
    lines = text.splitlines()
    at = next((i for i, l in enumerate(lines)
               if l.strip().lower().startswith("match ")), len(lines))
    lines.insert(at, "%s %s" % (key, value))
    try:
        with open(SSHD_MAIN, "w") as fh:
            fh.write("\n".join(lines) + "\n")
    except OSError:
        return False
    read_file.cache_clear()
    return True


# ------------------------------------------------------------------ rules

def rule_sshd(args):
    key, want = args[0], " ".join(args[1:])
    desc = "SSH %s %s" % (key, want)
    cfg = sshd_config()
    if cfg is None:
        return Outcome(None, desc, "sshd configuration could not be read.")
    targets = _sshd_targets(key)
    rem = Remediation(
        "Set '%s %s' in %s and reload sshd" % (key, want, ", ".join(targets)),
        func=lambda: _sshd_set(key, want), backup_files=targets,
        restart="sshd", restart_cmd=SSHD_RELOAD, risk=SSHD_RISK,
        manual="Set '%s %s' in %s and reload sshd." % (key, want, SSHD_MAIN))
    got = cfg.get(key.lower())
    note = ""
    if got is None and key.lower() in SSHD_DEFAULTS:
        got, note = SSHD_DEFAULTS[key.lower()], "OpenSSH default"
    out = _expect(desc, want, got, rem, note=note)
    if out.ok is False and note:
        out.detail = "Not set, so the OpenSSH default '%s' applies." % got
    return out


def rule_tweak(args):
    key, want = args[0], " ".join(args[1:])
    desc = "WHM tweak setting %s = %s" % (key, want)
    if not is_cpanel():
        return Outcome(None, desc, "Not a cPanel server.")
    got = cpanel_config().get(key)
    if got is None:
        data = whmapi1("get_tweaksetting", key=key)
        if data:
            got = ((data.get("data") or {}).get("tweaksetting") or {}).get("value")
    if got is None:
        return Outcome(None, desc, "Could not read tweak setting '%s'." % key)
    rem = Remediation(
        "Set tweak setting %s to %s" % (key, want),
        commands=["whmapi1 set_tweaksetting key=%s value=%s"
                  % (shlex.quote(key), shlex.quote(want))],
        manual="WHM > Server Configuration > Tweak Settings: %s." % key)
    return _expect(desc, want, got, rem)


def rule_whmapi(args):
    func, field, want = args[0], args[1], " ".join(args[2:])
    desc = "whmapi1 %s: %s = %s" % (func, field, want)
    if not is_cpanel():
        return Outcome(None, desc, "Not a cPanel server.")
    data = whmapi1(func)
    if data is None:
        return Outcome(None, desc, "whmapi1 %s failed." % func)
    node = data.get("data", data)
    for part in field.split("."):
        node = node.get(part) if isinstance(node, dict) else None
    fix = WHMAPI_FIXES.get(func)
    rem = Remediation("Run: %s" % fix, commands=[fix]) if fix else None
    return _expect(desc, want, None if node is None else str(node), rem)


def _systemctl(*argv):
    return run(["systemctl"] + list(argv))[1]


def rule_service(args):
    name, want = args[0], (args[1] if len(args) > 1 else "active")
    desc = "Service %s is %s" % (name, want)
    if want not in ("active", "inactive", "enabled", "disabled"):
        return Outcome(False, desc, "Unknown state '%s' (use active, inactive, "
                                    "enabled or disabled)." % want)
    if not which("systemctl"):
        return Outcome(None, desc, "systemd is not available.")
    load = _systemctl("show", "-p", "LoadState", name).partition("=")[2]
    if not load:
        return Outcome(None, desc, "systemd could not be queried.")
    if load == "not-found":
        if want in ("inactive", "disabled"):
            return Outcome(True, desc, note="not installed")
        return Outcome(False, desc, "%s is not installed." % name)
    query = "is-active" if want in ("active", "inactive") else "is-enabled"
    got = _systemctl(query, name)
    commands = {
        "active": ["systemctl enable --now %s" % shlex.quote(name)],
        "inactive": ["systemctl disable --now %s" % shlex.quote(name)],
        "enabled": ["systemctl enable %s" % shlex.quote(name)],
        "disabled": ["systemctl disable %s" % shlex.quote(name)],
    }[want]
    if name == "cphulkd" and want == "active":
        commands = ["whmapi1 enable_cphulk"]  # cPHulk has its own switch too
    if got == want:
        return Outcome(True, desc)
    return Outcome(False, desc, "%s is %s." % (name, got or "unknown"),
                   Remediation("Make %s %s" % (name, want), commands=commands))


def rule_file_kv(args):
    path, key, want = args[0], args[1], " ".join(args[2:])
    desc = "%s = %s in %s" % (key, want, path)
    text = read_file(path)
    if text is None:
        return Outcome(False, desc, "%s not found." % path)
    if path in MANAGED_FILES:
        rem = Remediation("Set %s to %s" % (key, want),
                          manual="cPanel regenerates this file; change it in "
                                 "%s." % MANAGED_FILES[path])
    else:
        rem = Remediation(
            "Set %s = %s in %s" % (key, want, path),
            func=lambda: kv_set(path, key, want), backup_files=[path],
            restart="csf" if path == CSF_CONF else None,
            restart_cmd="csf -ra" if path == CSF_CONF else None,
            risk="changes the firewall configuration" if path == CSF_CONF else None,
            manual="Set %s to %s in %s." % (key, want, path))
    return _expect(desc, want, kv_get(text, key), rem)


def rule_php_ini(args):
    key, want = args[0], " ".join(args[1:])
    desc = "PHP %s = %s" % (key, want)
    inis = ea_php_inis()
    if not inis:
        return Outcome(None, desc, "No php.ini files found.")
    wrong = [(p, php_ini_config(p).get(key)) for p in inis]
    wrong = [(p, v) for p, v in wrong if not same(want, v)]
    if not wrong:
        return Outcome(True, desc, note="%d php.ini file(s)" % len(inis))
    paths = [p for p, _ in wrong]

    def fix():
        return all(set_config_line(p, key, want, spaced=True, comments=";")
                   for p in paths)
    detail = "Expected '%s' in: %s." % (want, "; ".join(
        "%s (%s)" % (p, "not set" if v is None else v) for p, v in wrong))
    return Outcome(False, desc, detail, Remediation(
        "Set %s = %s in %d php.ini file(s)" % (key, want, len(paths)),
        func=fix, backup_files=paths, restart="PHP-FPM and Apache",
        restart_cmd=PHP_RESTART,
        manual="WHM > Software > MultiPHP INI Editor: set %s." % key))


def current_timezone():
    rc, out, _ = run(["timedatectl", "show", "-p", "Timezone", "--value"])
    if rc == 0 and out:
        return out
    link = os.path.realpath("/etc/localtime")
    return link.split("/zoneinfo/", 1)[1] if "/zoneinfo/" in link else None


def rule_timezone(args):
    want = args[0]
    desc = "Timezone is %s" % want
    got = current_timezone()
    if got == want:
        return Outcome(True, desc)
    return _mismatch(desc, want, got, Remediation(
        "Set the timezone to %s" % want,
        commands=["timedatectl set-timezone %s" % shlex.quote(want)]))


def _pkg_installed(name):
    if which("rpm"):
        return run(["rpm", "-q", name])[0] == 0
    if which("dpkg-query"):
        rc, out, _ = run(["dpkg-query", "-W", "-f=${Status}", name])
        return rc == 0 and "ok installed" in out
    return None


def rule_package(args):
    name, want = args[0], (args[1] if len(args) > 1 else "installed")
    desc = "Package %s is %s" % (name, want)
    installed = _pkg_installed(name)
    if installed is None:
        return Outcome(None, desc, "No rpm or dpkg to query.")
    if installed == (want == "installed"):
        return Outcome(True, desc)
    pm = "dnf" if which("dnf") else "yum"
    action = "install" if want == "installed" else "remove"
    return Outcome(False, desc, "%s is %s." % (
        name, "not installed" if want == "installed" else "installed"),
        Remediation("%s %s" % (action.capitalize(), name),
                    commands=["%s -y %s %s" % (pm, action, shlex.quote(name))],
                    manual="%s -y %s %s (may need epel-release)" % (pm, action, name)))


def rule_apache_module(args):
    name = args[0]
    desc = "Apache module %s is loaded" % name
    mods = apache_modules()
    if mods is None:
        return Outcome(None, desc, "Apache is not installed or not queryable.")
    pattern = re.compile(r"^%s\d*_module$" % re.escape(name))
    if any(pattern.match(m) for m in mods):
        return Outcome(True, desc)
    return Outcome(False, desc, "%s is not loaded." % name, Remediation(
        "Install the Apache module %s" % name,
        manual="WHM > Software > EasyApache 4 > Customize > Apache Modules."))


def _os_release():
    out = {}
    for line in (read_file("/etc/os-release") or "").splitlines():
        k, _, v = line.partition("=")
        out[k.strip()] = v.strip().strip('"')
    return out


def rule_os(args):
    want = args[0]
    desc = "Operating system is %s" % want
    rel = _os_release()
    if not rel:
        return Outcome(None, desc, "/etc/os-release not found.")
    pretty = rel.get("PRETTY_NAME", rel.get("ID", "?"))
    if rel.get("ID", "").lower() == want.lower():
        return Outcome(True, desc, note=pretty)
    return Outcome(False, desc, "Running %s." % pretty)


def rule_db_engine(args):
    want = args[0].lower()
    desc = "Database engine is %s" % want
    rc, out, _ = run(["mysql", "--version"])
    if rc != 0 or not out:
        return Outcome(None, desc, "mysql client not found.")
    got = "mariadb" if "mariadb" in out.lower() else "mysql"
    if got == want:
        return Outcome(True, desc, note=out)
    return Outcome(False, desc, "Found %s (%s)." % (got, out))


def rule_exists(args):
    desc = "%s exists" % args[0]
    if any(os.path.exists(p) for p in args):
        return Outcome(True, desc)
    return Outcome(False, desc, "None of these exist: %s." % ", ".join(args))


def rule_command(args):
    desc = "Command '%s' is available" % args[0]
    if which(args[0]):
        return Outcome(True, desc)
    return Outcome(False, desc, "'%s' is not in PATH." % args[0])


# name -> (handler, minimum number of arguments, ID slug builder)
RULES = {
    "sshd": (rule_sshd, 2, lambda a: "SSHD-" + a[0]),
    "tweak": (rule_tweak, 2, lambda a: "TWEAK-" + a[0]),
    "whmapi": (rule_whmapi, 3, lambda a: "WHM-" + a[1]),
    "service": (rule_service, 1, lambda a: "SVC-" + a[0]),
    "file_kv": (rule_file_kv, 3,
                lambda a: os.path.basename(a[0]).split(".")[0] + "-" + a[1]),
    "php_ini": (rule_php_ini, 2, lambda a: "PHP-" + a[0]),
    "timezone": (rule_timezone, 1, lambda a: "TIMEZONE"),
    "package": (rule_package, 1, lambda a: "PKG-" + a[0]),
    "apache_module": (rule_apache_module, 1, lambda a: "APACHE-" + a[0]),
    "os": (rule_os, 1, lambda a: "OS"),
    "db_engine": (rule_db_engine, 1, lambda a: "DB-ENGINE"),
    "exists": (rule_exists, 1,
               lambda a: "EXISTS-" + os.path.basename(a[0].rstrip("/"))),
    "command": (rule_command, 1, lambda a: "CMD-" + a[0]),
}


# ---------------------------------------------------------------- parsing

class Rule(object):
    def __init__(self, lineno, section, rtype, args, label, warn_only):
        self.lineno = lineno
        self.section = section
        self.rtype = rtype
        self.args = args
        self.label = label
        self.warn_only = warn_only


def parse(text):
    """Return (rules, settings, errors) for baseline file text."""
    rules, settings, errors = [], {}, []
    section = ""
    for lineno, raw in enumerate((text or "").splitlines(), 1):
        line = re.sub(r"(^|\s)#.*$", "", raw).strip()
        if not line:
            continue
        m = re.match(r"^\[(.+)\]$", line)
        if m:
            section = m.group(1).strip()
            continue
        label = ""
        if " | " in line:
            line, _, label = line.partition(" | ")
            line, label = line.strip(), label.strip()
        try:
            parts = shlex.split(line)
        except ValueError as e:
            errors.append("line %d: %s" % (lineno, e))
            continue
        rtype, args = parts[0], parts[1:]
        if rtype == "set":
            if len(args) < 1 or not re.match(r"^[A-Z0-9_]+$", args[0]):
                errors.append("line %d: 'set' needs an UPPER_CASE name" % lineno)
            else:
                settings[args[0]] = " ".join(args[1:])
            continue
        warn_only = rtype.startswith("warn:")
        if warn_only:
            rtype = rtype[len("warn:"):]
        if rtype not in RULES:
            errors.append("line %d: unknown rule type '%s'" % (lineno, rtype))
            continue
        if len(args) < RULES[rtype][1]:
            errors.append("line %d: '%s' needs at least %d argument(s)"
                          % (lineno, rtype, RULES[rtype][1]))
            continue
        rules.append(Rule(lineno, section, rtype, args, label, warn_only))
    return rules, settings, errors


def check_id(rule, taken):
    slug = re.sub(r"[^A-Z0-9]+", "-", RULES[rule.rtype][2](rule.args).upper())
    base = "BL-" + slug.strip("-")
    cid, n = base, 2
    while cid in taken:
        cid, n = "%s-%d" % (base, n), n + 1
    taken.add(cid)
    return cid


def make_check(rule, cid):
    handler = RULES[rule.rtype][0]

    def check():
        out = handler(rule.args)
        title = rule.label or out.desc
        if out.ok:
            if out.note:
                title = "%s (%s)" % (title, out.note)
            yield Finding(cid, title, Status.OK, reference=REF)
        elif out.ok is None:
            yield Finding(cid, title, Status.SKIP, out.detail, reference=REF)
        else:
            yield Finding(cid, title,
                          Status.WARN if rule.warn_only else Status.FAIL,
                          out.detail,
                          Severity.LOW if rule.warn_only else Severity.MEDIUM,
                          out.remediation, reference=REF)
    return check


def load(path=DEFAULT_PATH):
    """Register one check per baseline rule. Returns the number of rules.

    Safe to call more than once: previously loaded baseline checks are
    replaced. A missing file at the default path simply means no baseline.
    """
    REGISTRY[:] = [s for s in REGISTRY if not s.id.startswith("BL-")]
    SETTINGS.clear()
    text = read_file(path)
    if text is None:
        return 0
    rules, settings, errors = parse(text)
    SETTINGS.update(settings)
    taken = set()
    for i, rule in enumerate(rules):
        cat = "%s: %s" % (CAT_PREFIX, rule.section) if rule.section else CAT_PREFIX
        cid = check_id(rule, taken)
        title = rule.label or "%s %s" % (rule.rtype, " ".join(rule.args))
        REGISTRY.append(CheckSpec(cid, title, cat, make_check(rule, cid),
                                  order=i))
    if errors:
        name = os.path.basename(path)

        def config_errors():
            for err in errors:
                yield Finding("BL-CONFIG", "%s %s" % (name, err), Status.WARN,
                              "This line was ignored.", Severity.LOW,
                              reference=REF)
        REGISTRY.append(CheckSpec("BL-CONFIG", "Baseline file errors",
                                  CAT_PREFIX, config_errors, order=-1))
    return len(rules)
