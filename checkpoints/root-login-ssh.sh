#!/bin/bash
. "$(dirname "$0")/../functions.sh"
# Check if root login is disabled in SSH
if grep -q '^PermitRootLogin no' /etc/ssh/sshd_config; then
    ok "Root login is disabled."
else
    warn "Root login is enabled!"
fi
