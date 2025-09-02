#!/bin/bash
. "$(dirname "$0")/../functions.sh"

# Parse --prompts flag
parse_prompts_flag "$@"

# Check if CSF (ConfigServer Security & Firewall) is installed
if [ ! -f /etc/csf/csf.conf ]; then
    error "CSF is not installed."
    prompt_and_execute "Do you want to install CSF now?" "install_csf" "CSF installation skipped."
    exit 1
else
    if grep -q "TESTING = \"1\"" /etc/csf/csf.conf; then
        warn "CSF is installed but in testing mode."
    else
        ok "CSF is installed."
    fi
fi
