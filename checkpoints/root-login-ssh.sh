#!/bin/bash
# Check if root login is disabled in SSH
if grep -q '^PermitRootLogin no' /etc/ssh/sshd_config; then
    echo "✔ Root login is disabled."
else
    echo "▲ Root login is enabled!"
fi
