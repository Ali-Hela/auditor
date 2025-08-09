#!/bin/bash

# Check if CSF (ConfigServer Security & Firewall) is installed
if [ ! -f /etc/csf/csf.conf ]; then
    echo "✘ CSF is not installed."
    exit 1
fi

# Check if CSF is out of testing mode
if grep -q "TESTING = \"1\"" /etc/csf/csf.conf; then
    echo "✘ CSF is in testing mode."
else
    echo "✔ CSF is not in testing mode."
fi