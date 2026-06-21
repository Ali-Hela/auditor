"""Shell + cPanel environment helpers used by checks."""

import glob
import json
import os
import shutil
import subprocess
from functools import lru_cache
from typing import Dict, List, Optional, Tuple


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


def read_file(path: str) -> Optional[str]:
    try:
        with open(path, "r", errors="replace") as fh:
            return fh.read()
    except OSError:
        return None


def parse_kv(text: Optional[str], sep: str = "=") -> Dict[str, str]:
    """Parse simple key=value config text (ignores blanks and # comments)."""
    out: Dict[str, str] = {}
    for raw in (text or "").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or sep not in line:
            continue
        key, _, val = line.partition(sep)
        out[key.strip()] = val.strip().strip('"').strip("'")
    return out


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


def whmapi1(func: str, **params) -> Optional[dict]:
    """Call ``whmapi1 <func>`` and return the parsed JSON, or None on failure.

    Returns None when whmapi1 is missing, cannot be run (e.g. not root),
    fails to parse, or reports ``metadata.result != 1``. Callers should treat
    None as "could not determine" rather than "disabled".
    """
    if not which("whmapi1"):
        return None
    argv = ["whmapi1", func, "--output=jsonpretty"]
    for key, val in params.items():
        argv.append("%s=%s" % (key, val))
    rc, out, _ = run(argv, timeout=60)
    if rc != 0 or not out:
        return None
    try:
        parsed = json.loads(out)
    except json.JSONDecodeError:
        return None
    result = parsed.get("metadata", {}).get("result")
    if result is not None and not truthy(result):
        return None
    return parsed


def listening_ports() -> List[Tuple[str, str]]:
    """Return [(address, port)] of listening TCP sockets, best effort."""
    rc, out, _ = run(["ss", "-tlnH"])
    if rc != 0 or not out:
        rc, out, _ = run("netstat -tlnH 2>/dev/null || netstat -tln")
        if rc != 0:
            return []
    results = []
    for line in out.splitlines():
        parts = line.split()
        for tok in parts:
            if ":" in tok and tok.rsplit(":", 1)[-1].isdigit():
                addr, port = tok.rsplit(":", 1)
                results.append((addr, port))
                break
    return results


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


def cpanel_users() -> List[str]:
    """cPanel account usernames from /var/cpanel/users/."""
    try:
        return [n for n in os.listdir("/var/cpanel/users")
                if not n.startswith(".")]
    except OSError:
        return []
