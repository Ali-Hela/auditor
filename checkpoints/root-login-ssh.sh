#!/bin/bash
. "$(dirname "$0")/../functions.sh"

# Parse --prompts flag
parse_prompts_flag "$@"

# Check if root login is disabled in SSH
if grep -q '^PermitRootLogin no' /etc/ssh/sshd_config; then
    ok "Root login is disabled."
else
    warn "Root login is enabled!"
    prompt_and_execute "Do you want to disable root SSH login now?" "disable_root_ssh" "Root SSH login disable skipped."
fi
