#!/bin/bash
. "$(dirname "$0")/../functions.sh"

# Parse --prompts flag
PROMPTS=0
for arg in "$@"; do
    case $arg in
        --prompts)
            PROMPTS=1
            ;;
    esac
done

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

if [ "$notification_missing" -eq 1 ] && [ "$PROMPTS" -eq 1 ]; then
    read -p "Do you want to set up root login notification now? (y/N): " confirm
    case "$confirm" in
        [yY][eE][sS]|[yY])
            setup_root_login_notification
            ;;
        *)
            info "Root login notification setup skipped."
            ;;
    esac
fi