#!/usr/bin/env bash
# Launcher for the auditor Python package. Keeps the original drop-in feel:
#   sudo ./auditor.sh            # read-only audit
#   sudo ./auditor.sh --fix      # guided remediation
#
# Picks a suitable Python 3 interpreter (>= 3.6), preferring cPanel's bundled
# one, so it runs on most cPanel installs (AlmaLinux/CloudLinux 8 ship 3.6).
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

pick_python() {
    local candidates=(
        /usr/local/cpanel/3rdparty/bin/python3
        python3.12 python3.11 python3.10 python3.9 python3.8 python3.7 python3.6
        python3
    )
    local py bin
    for py in "${candidates[@]}"; do
        bin="$(command -v "$py" 2>/dev/null)" || continue
        if "$bin" -c 'import sys; raise SystemExit(0 if sys.version_info[:2] >= (3, 6) else 1)' 2>/dev/null; then
            printf '%s\n' "$bin"
            return 0
        fi
    done
    return 1
}

PY="$(pick_python)"
if [ -z "$PY" ]; then
    echo "auditor requires Python 3.6 or newer, but no suitable interpreter was found." >&2
    echo "Install python3 (e.g. 'yum install python3') and try again." >&2
    exit 3
fi

exec env PYTHONPATH="$DIR" "$PY" -m auditor "$@"
