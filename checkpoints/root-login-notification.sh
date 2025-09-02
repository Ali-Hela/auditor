#!/bin/bash
. "$(dirname "$0")/../functions.sh"

# Parse --prompts flag
parse_prompts_flag "$@"

notification_missing=0

if grep -q "ALERT - Root Shell Access" ~/.bashrc; then
    EMAIL=$(grep "ALERT - Root Shell Access" ~/.bashrc | grep -oP 'mail.*"\s+\K\S+')
    ok "Root login notification is set up in .bashrc and is sent to: $EMAIL"
else
    error "Root login email notification is NOT set up in .bashrc"
    notification_missing=1
fi

if grep -q ">> /var/log/rootlogins" ~/.bashrc; then
    LOGFILE=$(grep ">> /var/log/rootlogins" ~/.bashrc | grep -oP '>>\s+\K\S+')
    ok "Root login events are being logged to: $LOGFILE"
else
    error "Root login events are NOT being logged to /var/log/rootlogins in .bashrc"
    notification_missing=1
fi

if [ "$notification_missing" -eq 1 ]; then
    prompt_and_execute "Do you want to set up root login notification now?" "setup_root_login_notification" "Root login notification setup skipped."
fi