#!/bin/bash
. "$(dirname "$0")/../functions.sh"

# Parse --prompts flag
parse_prompts_flag "$@"

# Check for pending security updates
if command -v yum &> /dev/null; then
    updates=$(yum check-update --security -q | grep -E '^[a-zA-Z0-9_.-]+\s+[0-9]')
    if [ -n "$updates" ]; then
        warn "Security updates are available! $(echo "$updates" | wc -l) updates found."
        prompt_and_execute "Do you want to install security updates now?" "install_security_updates" "Security updates installation skipped."
    else
        ok "No pending security updates."
    fi
else
    warn "Security Updates: Unsupported package manager."
fi