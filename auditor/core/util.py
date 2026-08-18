"""Shell + cPanel environment helpers used by checks.

Everything here degrades gracefully: a helper that cannot determine an answer
returns ``None`` (or an empty collection) rather than guessing, so checks can
report SKIP instead of a false FAIL.

Several helpers are memoised for the duration of a run. Remediation edits
config files underneath us, so ``clear_caches()`` must be called before a
check is re-run to verify a fix.
"""

import datetime
import glob
import json
import os
import re
import shutil
import subprocess
from functools import lru_cache
from typing import Dict, List, Optional, Tuple

# Addresses that mean "not reachable from the network".
LOOPBACK_ADDRS = {"127.0.0.1", "::1", "localhost"}
# Addresses that mean "every interface".
WILDCARD_ADDRS = {"0.0.0.0", "::", "*", ""}


def run(cmd, timeout: int = 30) -> Tuple[int, str, str]:
    """Run a command. Accepts a list (argv) or a string (via bash -c).

    Returns (returncode, stdout, stderr), stripped. Never raises.
    """
    if isinstance(cmd, str):
        argv = ["/bin/bash", "-c", cmd]
    else:
        argv = list(cmd)
    try:
        # capture_output= and text= are 3.7+; spell it out for Python 3.6.
        p = subprocess.run(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                           universal_newlines=True, timeout=timeout)
        out = (p.stdout or "").strip()
        err = (p.stderr or "").strip()
        return p.returncode, out, err
    except subprocess.TimeoutExpired:
        return 124, "", "timed out after %ss" % timeout
    except FileNotFoundError:
        return 127, "", "command not found"
    except Exception as e:  # pragma: no cover - defensive
        return 1, "", str(e)


def which(name: str) -> Optional[str]:
    return shutil.which(name)


@lru_cache(maxsize=256)
def read_file(path: str) -> Optional[str]:
    try:
        with open(path, "r", errors="replace") as fh:
            return fh.read()
    except OSError:
        return None


def parse_kv(text: Optional[str], sep: str = "=",
             comments: str = "#") -> Dict[str, str]:
    """Parse simple key=value config text.

    ``comments`` lists every character that starts a comment line. php.ini uses
    ``;`` and shell-style configs use ``#``; pass both when a format may use
    either. Later assignments win, matching how these parsers behave.
    """
    out: Dict[str, str] = {}
    for raw in (text or "").splitlines():
        line = raw.strip()
        if not line or line[0] in comments or sep not in line:
            continue
        key, _, val = line.partition(sep)
        out[key.strip()] = val.strip().strip('"').strip("'")
    return out


def set_config_line(path: str, key: str, value: str, sep: str = "=",
                    spaced: bool = False, comments: str = "#") -> bool:
    """Set ``key`` to ``value`` in a key=value config file.

    Rewrites *every* existing assignment (including commented-out ones) or
    appends the setting if the key is absent. Rewriting every occurrence
    matters for formats where the first assignment wins (sshd_config) as well
    as those where the last one does (php.ini) - after the rewrite they all
    carry the same value either way. The flip side is that a directive scoped
    inside an sshd ``Match`` block is rewritten too, which is why fixes that
    touch sshd_config also take a backup.

    Returns True on success.

    This exists because ``sed -ri 's/^KEY=.*/KEY=new/'`` exits 0 without
    changing anything when the key is missing, which made failed fixes report
    as applied.
    """
    text = read_file(path)
    if text is None:
        return False
    new_line = "%s%s%s" % (key, " %s " % sep if spaced else sep, value)
    # A whitespace separator has to match runs of tabs or spaces, not one space.
    sep_re = r"\s+" if sep.isspace() else r"\s*%s" % re.escape(sep)
    pattern = re.compile(r"^\s*[%s]?\s*%s%s" % (re.escape(comments),
                                                re.escape(key), sep_re),
                         re.IGNORECASE if sep.isspace() else 0)
    lines = text.splitlines()
    replaced = False
    for i, line in enumerate(lines):
        if pattern.match(line):
            lines[i] = new_line
            replaced = True
    if not replaced:
        lines.append(new_line)
    try:
        with open(path, "w") as fh:
            fh.write("\n".join(lines) + "\n")
    except OSError:
        return False
    read_file.cache_clear()
    return True


def backup_file(path: str) -> Optional[str]:
    """Copy ``path`` beside itself with a timestamped suffix.

    Returns the backup path, or None if the file does not exist or the copy
    failed.
    """
    if not os.path.isfile(path):
        return None
    stamp = datetime.datetime.now().strftime("%Y%m%d%H%M%S")
    dest = "%s.auditor-bak-%s" % (path, stamp)
    try:
        shutil.copy2(path, dest)
        return dest
    except OSError:
        return None


@lru_cache(maxsize=1)
def is_cpanel() -> bool:
    return os.path.isdir("/usr/local/cpanel")


@lru_cache(maxsize=1)
def cpanel_config() -> Dict[str, str]:
    """Parsed /var/cpanel/cpanel.config (WHM Tweak Settings)."""
    return parse_kv(read_file("/var/cpanel/cpanel.config"))


def service_active(name: str) -> Optional[bool]:
    """True/False if systemctl knows the service, None if it cannot be queried."""
    if not which("systemctl"):
        return None
    rc, out, _ = run(["systemctl", "is-active", name])
    if out in ("active", "inactive", "failed", "unknown"):
        return out == "active"
    return None


def truthy(val) -> bool:
    """Coerce assorted cPanel/MySQL boolean spellings to a bool."""
    return str(val).strip().lower() in ("1", "true", "yes", "on", "enabled")


@lru_cache(maxsize=64)
def _whmapi1_cached(func: str, param_items: Tuple[Tuple[str, str], ...]
                    ) -> Optional[dict]:
    argv = ["whmapi1", func, "--output=jsonpretty"]
    for key, val in param_items:
        argv.append("%s=%s" % (key, val))
    rc, out, _ = run(argv, timeout=60)
    if rc != 0 or not out:
        return None
    try:
        parsed = json.loads(out)
    except ValueError:  # json.JSONDecodeError subclasses ValueError
        return None
    result = parsed.get("metadata", {}).get("result")
    if result is not None and not truthy(result):
        return None
    return parsed


def whmapi1(func: str, **params) -> Optional[dict]:
    """Call ``whmapi1 <func>`` and return the parsed JSON, or None on failure.

    Returns None when whmapi1 is missing, cannot be run (e.g. not root),
    fails to parse, or reports ``metadata.result != 1``. Callers should treat
    None as "could not determine" rather than "disabled".

    Results are memoised, so several checks may query the same endpoint
    without paying for repeated subprocess calls.
    """
    if not which("whmapi1"):
        return None
    return _whmapi1_cached(func, tuple(sorted(params.items())))


def normalize_addr(addr: str) -> str:
    """Strip the brackets ss puts around IPv6 literals, and any %scope tail."""
    addr = (addr or "").strip()
    if addr.startswith("[") and addr.endswith("]"):
        addr = addr[1:-1]
    if "%" in addr:
        addr = addr.split("%", 1)[0]
    return addr


def is_loopback(addr: str) -> bool:
    """True if a listening address is only reachable from the machine itself."""
    addr = normalize_addr(addr)
    return addr in LOOPBACK_ADDRS or addr.startswith("127.")


def is_public_addr(addr: str) -> bool:
    """True if a listening address accepts connections from off-box."""
    return not is_loopback(normalize_addr(addr))


def parse_socket_lines(text: str) -> List[Tuple[str, str]]:
    """Parse ``ss -tln`` / ``netstat -tln`` output into [(address, port)].

    Both tools print the local address as the first ``host:port`` token on the
    line; the peer column is always ``*:*`` or ``0.0.0.0:*`` on a listening
    socket, so requiring a numeric port picks the local side unambiguously.
    Addresses are normalised, so IPv6 arrives as ``::1`` rather than ``[::1]``.
    """
    results = []
    for line in (text or "").splitlines():
        if not line.strip() or line.lstrip().startswith(("Proto", "Active",
                                                         "State", "Netid")):
            continue
        for tok in line.split():
            if ":" not in tok:
                continue
            addr, _, port = tok.rpartition(":")
            if not port.isdigit():
                continue
            results.append((normalize_addr(addr), port))
            break
    return results


@lru_cache(maxsize=1)
def listening_ports() -> List[Tuple[str, str]]:
    """Return [(address, port)] of listening TCP sockets, best effort."""
    rc, out, _ = run(["ss", "-tlnH"])
    if rc != 0 or not out:
        rc, out, _ = run(["netstat", "-tln"])
        if rc != 0:
            return []
    return parse_socket_lines(out)


def public_ports() -> List[str]:
    """Sorted, de-duplicated ports reachable from off-box."""
    return sorted({p for addr, p in listening_ports() if is_public_addr(addr)},
                  key=int)


def parse_sshd_output(text: str) -> Dict[str, str]:
    """Parse ``sshd -T`` output (``key value`` per line, keys lowercased)."""
    out: Dict[str, str] = {}
    for line in (text or "").splitlines():
        parts = line.strip().split(None, 1)
        if len(parts) == 2:
            out[parts[0].lower()] = parts[1].strip()
        elif len(parts) == 1 and parts[0]:
            out[parts[0].lower()] = ""
    return out


def sshd_files() -> List[str]:
    """sshd_config plus any files it Includes, in effective order."""
    main = "/etc/ssh/sshd_config"
    paths = [main]
    text = read_file(main) or ""
    for line in text.splitlines():
        s = line.strip()
        if s and not s.startswith("#") and s.lower().startswith("include"):
            parts = s.split(None, 1)
            if len(parts) == 2:
                for pattern in parts[1].split():
                    if not pattern.startswith("/"):
                        pattern = os.path.join("/etc/ssh", pattern)
                    paths.extend(sorted(glob.glob(pattern)))
    return [p for p in paths if os.path.isfile(p)]


@lru_cache(maxsize=1)
def sshd_config() -> Optional[Dict[str, str]]:
    """Effective sshd settings, or None if they cannot be determined.

    Prefers ``sshd -T``, which applies OpenSSH's own defaults and resolves
    ``Include`` directives. Falls back to reading the config files directly,
    but in that case an unset directive is genuinely absent from the result
    rather than being reported with a guessed default.
    """
    sshd = which("sshd") or "/usr/sbin/sshd"
    if os.path.isfile(sshd):
        rc, out, _ = run([sshd, "-T"])
        if rc == 0 and out:
            return parse_sshd_output(out)
    files = sshd_files()
    if not files:
        return None
    merged: Dict[str, str] = {}
    in_match = False
    for path in files:
        for line in (read_file(path) or "").splitlines():
            s = line.strip()
            if not s or s.startswith("#"):
                continue
            # Directives inside a Match block are conditional; ignore them so
            # we never report a Match-scoped value as the global setting.
            if s.lower().startswith("match "):
                in_match = True
                continue
            if in_match:
                continue
            parts = s.split(None, 1)
            if len(parts) == 2:
                merged[parts[0].lower()] = parts[1].strip()
    return merged or None


@lru_cache(maxsize=1)
def apache_modules() -> Optional[List[str]]:
    """Loaded Apache modules, or None if Apache is not installed/queryable."""
    for argv in (["httpd", "-M"], ["apachectl", "-M"],
                 ["/usr/sbin/httpd", "-M"], ["/usr/local/apache/bin/httpd", "-M"]):
        if not (which(argv[0]) or os.path.isfile(argv[0])):
            continue
        rc, out, _ = run(argv)
        if rc == 0 and out:
            return [tok.split()[0] for tok in out.splitlines() if tok.strip()]
    return None


def mysql_available() -> bool:
    """True if a mysql client is present and can reach the server."""
    if not which("mysql"):
        return False
    rc, _, _ = run(["mysql", "-N", "-B", "-e", "SELECT 1"])
    return rc == 0


def mysql_variable(name: str) -> Optional[str]:
    """Value of a MySQL server variable, or None if it cannot be read."""
    if not which("mysql"):
        return None
    rc, out, _ = run(["mysql", "-N", "-B", "-e",
                      "SHOW VARIABLES LIKE '%s'" % name])
    if rc != 0 or not out:
        return None
    parts = out.split()
    return parts[1] if len(parts) >= 2 else None


@lru_cache(maxsize=1)
def ea_php_inis() -> List[str]:
    """All EA-PHP php.ini files plus the CLI default, de-duplicated."""
    paths = sorted(glob.glob("/opt/cpanel/ea-php*/root/etc/php.ini"))
    rc, out, _ = run(["php", "--ini"])
    if rc == 0:
        for line in out.splitlines():
            if "Loaded Configuration File" in line and ":" in line:
                p = line.split(":", 1)[1].strip().strip('"').strip("'")
                if p and p != "(none)":
                    paths.append(p)
    # de-duplicate by real path, preserving order
    seen, unique = set(), []
    for p in paths:
        rp = os.path.realpath(p)
        if rp not in seen and os.path.isfile(rp):
            seen.add(rp)
            unique.append(rp)
    return unique


def php_ini_config(path: str) -> Dict[str, str]:
    """Parse a php.ini. Comments start with ``;`` in this format, not ``#``."""
    return parse_kv(read_file(path), comments=";#")


def php_version_of_ini(path: str) -> Optional[str]:
    """Extract the EA-PHP version from an ini path, e.g. ea-php74 -> '7.4'."""
    m = re.search(r"ea-php(\d)(\d+)", path)
    if m:
        return "%s.%s" % (m.group(1), m.group(2))
    return None


def cpanel_users() -> List[str]:
    """cPanel account usernames from /var/cpanel/users/."""
    try:
        return [n for n in os.listdir("/var/cpanel/users")
                if not n.startswith(".")]
    except OSError:
        return []


def mount_options(target: str) -> Optional[List[str]]:
    """Mount options for ``target``, or None if it is not a separate mount."""
    text = read_file("/proc/mounts")
    if text is None:
        return None
    for line in text.splitlines():
        parts = line.split()
        if len(parts) >= 4 and parts[1] == target:
            return parts[3].split(",")
    return None


def clear_caches():
    """Drop every memoised result.

    Called before a check is re-run to verify a remediation, so the re-run
    observes the config files as they are on disk now.
    """
    for fn in (read_file, is_cpanel, cpanel_config, _whmapi1_cached,
               listening_ports, sshd_config, apache_modules, ea_php_inis):
        fn.cache_clear()
