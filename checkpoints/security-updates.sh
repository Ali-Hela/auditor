#!/bin/bash
# Check for pending security updates
if command -v yum &> /dev/null; then
    echo "🛈 Checking for pending security updates..."
    updates=$(yum check-update --security -q | grep -E '^[a-zA-Z0-9_.-]+\s+[0-9]')
    if [ -n "$updates" ]; then
        echo "▲ Security updates are available! $(echo "$updates" | wc -l) updates found."
    else
        echo "✔ No pending security updates."
    fi
else
    echo "▲ Security Updates: Unsupported package manager."
fi