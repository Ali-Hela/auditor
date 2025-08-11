#!/bin/bash
. "$(dirname "$0")/../functions.sh"
# Check for pending security updates

if command -v yum &> /dev/null; then
    updates=$(yum check-update --security -q | grep -E '^[a-zA-Z0-9_.-]+\s+[0-9]')
    if [ -n "$updates" ]; then
        info "Security updates are available! $(echo "$updates" | wc -l) updates found."
    else
        ok "No pending security updates."
    fi
else
    warn "Security Updates: Unsupported package manager."
fi