#!/bin/bash
. "$(dirname "$0")/../functions.sh"

# Parse --prompts flag
parse_prompts_flag "$@"

# check if fail2ban is installed and running
if ! command -v fail2ban-client >/dev/null 2>&1; then
    error "fail2ban is not installed."
    prompt_and_execute "Do you want to install Fail2ban now?" "install_fail2ban" "Fail2ban installation skipped."
    exit 1
fi

if ! systemctl is-active --quiet fail2ban; then
    error "fail2ban is not running."
    prompt_and_execute "Do you want to start Fail2ban now?" "start_fail2ban" "Fail2ban start skipped."
    exit 1
fi

ok "fail2ban is installed and running."
