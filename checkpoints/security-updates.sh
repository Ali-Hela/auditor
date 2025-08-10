#!/bin/bash
# Check for pending security updates
if command -v apt &> /dev/null; then
    apt list --upgradable 2>/dev/null | grep -i security
elif command -v yum &> /dev/null; then
    yum check-update --security
elif command -v dnf &> /dev/null; then
    dnf updateinfo list security
else
    echo "▲ Security Updates: Unsupported package manager."
fi
