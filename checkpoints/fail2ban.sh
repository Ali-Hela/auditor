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

# check if fail2ban is installed and running
if ! command -v fail2ban-client >/dev/null 2>&1; then
    error "fail2ban is not installed."
    if [ "$PROMPTS" -eq 1 ]; then
        read -p "Do you want to install Fail2ban now? (y/N): " confirm
        case "$confirm" in
            [yY][eE][sS]|[yY])
                install_fail2ban
                ;;
            *)
                info "Fail2ban installation skipped."
                ;;
        esac
    fi
    exit 1
fi

if ! systemctl is-active --quiet fail2ban; then
    error "fail2ban is not running."
    if [ "$PROMPTS" -eq 1 ]; then
        read -p "Do you want to start Fail2ban now? (y/N): " confirm
        case "$confirm" in
            [yY][eE][sS]|[yY])
                systemctl start fail2ban
                if systemctl is-active --quiet fail2ban; then
                    ok "Fail2ban started successfully."
                else
                    error "Failed to start Fail2ban."
                fi
                ;;
            *)
                info "Fail2ban start skipped."
                ;;
        esac
    fi
    exit 1
fi

ok "fail2ban is installed and running."

# Check active jails
active_jails=$(fail2ban-client status 2>/dev/null | grep "Jail list" | cut -d: -f2 | tr ',' '\n' | wc -l)
if [ "$active_jails" -gt 0 ]; then
    ok "Active fail2ban jails: $active_jails"
    fail2ban-client status 2>/dev/null | grep "Jail list" | cut -d: -f2
else
    warn "No active fail2ban jails configured"
fi

# Check banned IPs count
total_banned=0
for jail in $(fail2ban-client status 2>/dev/null | grep "Jail list" | cut -d: -f2 | tr ',' ' '); do
    jail_banned=$(fail2ban-client status "$jail" 2>/dev/null | grep "Currently banned" | awk '{print $4}')
    if [ -n "$jail_banned" ] && [ "$jail_banned" -gt 0 ]; then
        total_banned=$((total_banned + jail_banned))
    fi
done

if [ "$total_banned" -gt 0 ]; then
    info "Currently banned IPs across all jails: $total_banned"
else
    ok "No IPs currently banned (system is clean or no attacks)"
fi

# Check if important services are monitored
important_jails="sshd apache-auth dovecot postfix"
for jail in $important_jails; do
    if fail2ban-client status 2>/dev/null | grep -q "$jail"; then
        ok "Jail '$jail' is active"
    else
        info "Consider enabling fail2ban jail for: $jail"
    fi
done | head -5
