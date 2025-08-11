#!/bin/bash
. "$(dirname "$0")/../functions.sh"

CHECK="✔"
CROSS="✘"

# check if fail2ban is installed and running
if ! command -v fail2ban-client >/dev/null 2>&1; then
    error "fail2ban is not installed."
    exit 1
fi

if ! systemctl is-active --quiet fail2ban; then
    error "fail2ban is not running."
    exit 1
fi

ok "fail2ban is installed and running."
