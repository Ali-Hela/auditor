#!/bin/bash
. "$(dirname "$0")/../functions.sh"

if grep -q "ALERT - Root Shell Access" ~/.bashrc; then
    EMAIL=$(grep "ALERT - Root Shell Access" ~/.bashrc | grep -oP 'mail.*"\s+\K\S+')
    ok "Root login notification is set up in .bashrc and is sent to: $EMAIL"
else
    error "Root login email notification is NOT set up in .bashrc"
fi

if grep -q ">> /var/log/rootlogins" ~/.bashrc; then
    LOGFILE=$(grep ">> /var/log/rootlogins" ~/.bashrc | grep -oP '>>\s+\K\S+')
    ok "Root login events are being logged to: $LOGFILE"
else
    error "Root login events are NOT being logged to /var/log/rootlogins in .bashrc"
fi