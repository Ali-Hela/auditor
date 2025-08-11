#!/bin/bash

# Check if CSF (ConfigServer Security & Firewall) is installed
if [ ! -f /etc/csf/csf.conf ]; then
    echo "✘ CSF is not installed."
    exit 1
else
    if grep -q "TESTING = \"1\"" /etc/csf/csf.conf; then
        echo "▲ CSF is installed but in testing mode."
    else
        echo "✔ CSF is installed."
    fi
fi
