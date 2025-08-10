#!/bin/bash
# Check for pending security updates
echo "🛈 Checking for pending security updates..."
if command -v yum &> /dev/null; then
    yum check-update --security
else
    echo "▲ Security Updates: Unsupported package manager."
fi