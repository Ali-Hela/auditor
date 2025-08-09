#!/bin/bash

# Check if CSF (ConfigServer Security & Firewall) is installed
if ! command -v csf >/dev/null 2>&1; then
    echo "CSF is not installed."
    exit 1
fi

echo "CSF is installed."

# Check if CSF is out of testing mode
CSF_CONF="/etc/csf/csf.conf"
if [ ! -f "$CSF_CONF" ]; then
    echo "CSF configuration file not found at $CSF_CONF."
    exit 1
fi

TESTING=$(grep -E '^TESTING\s*=' "$CSF_CONF" | awk -F= '{print $2}' | tr -d ' ')
if [ "$TESTING" = "0" ]; then
    echo "CSF is out of testing mode."
else
    echo "CSF is in testing mode."
fi