#!/bin/bash
. "$(dirname "$0")/../functions.sh"

# Check if CSF (ConfigServer Security & Firewall) is installed
if [ ! -f /etc/csf/csf.conf ]; then
    error "CSF is not installed."
    exit 1
else
    if grep -q "TESTING = \"1\"" /etc/csf/csf.conf; then
        warn "CSF is installed but in testing mode."
    else
        ok "CSF is installed."
    fi
fi
