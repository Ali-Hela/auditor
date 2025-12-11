#!/bin/bash
. "$(dirname "$0")/../functions.sh"

# Parse --prompts flag
PROMPTS=0
for arg in "$@"; do
    case $arg in
        --prompts)
            PROMPTS=1
            ;;
    esac
done

# Check if root login is disabled in SSH
if grep -q '^PermitRootLogin no' /etc/ssh/sshd_config; then
    ok "Root SSH login is disabled"
else
    error "Root SSH login is ENABLED - major security risk!"
    if [ "$PROMPTS" -eq 1 ]; then
        read -p "Do you want to disable root SSH login now? (y/N): " confirm
        case "$confirm" in
            [yY][eE][sS]|[yY])
                disable_root_ssh
                ;;
            *)
                info "Root SSH login disable skipped."
                ;;
        esac
    fi
fi

# Check SSH port
ssh_port=$(grep "^Port " /etc/ssh/sshd_config | awk '{print $2}')
if [ -n "$ssh_port" ] && [ "$ssh_port" != "22" ]; then
    ok "SSH is running on non-standard port: $ssh_port"
else
    warn "SSH is on default port 22 - consider changing for security through obscurity"
fi

# Check password authentication
if grep -q "^PasswordAuthentication no" /etc/ssh/sshd_config; then
    ok "SSH password authentication is disabled (key-only)"
elif grep -q "^PasswordAuthentication yes" /etc/ssh/sshd_config; then
    warn "SSH password authentication is enabled - keys are more secure"
fi

# Check for empty passwords allowed
if grep -q "^PermitEmptyPasswords yes" /etc/ssh/sshd_config; then
    error "SSH allows empty passwords - critical security risk!"
else
    ok "Empty passwords are not permitted"
fi

# Check protocol version
if grep -q "^Protocol 2" /etc/ssh/sshd_config; then
    ok "SSH Protocol 2 is enforced"
elif grep -q "^Protocol 1" /etc/ssh/sshd_config; then
    error "SSH Protocol 1 is enabled - use Protocol 2 only!"
fi

# Check MaxAuthTries
max_auth=$(grep "^MaxAuthTries" /etc/ssh/sshd_config | awk '{print $2}')
if [ -n "$max_auth" ]; then
    if [ "$max_auth" -le 4 ]; then
        ok "MaxAuthTries is set to $max_auth (good)"
    else
        warn "MaxAuthTries is $max_auth - consider lowering to 3-4"
    fi
fi

# Check ClientAliveInterval (prevents timeout attacks)
client_alive=$(grep "^ClientAliveInterval" /etc/ssh/sshd_config | awk '{print $2}')
if [ -n "$client_alive" ] && [ "$client_alive" -gt 0 ]; then
    ok "ClientAliveInterval is configured: $client_alive seconds"
fi

# Check for specific user/group restrictions
if grep -q "^AllowUsers\|^AllowGroups" /etc/ssh/sshd_config; then
    ok "SSH access is restricted to specific users/groups"
fi

# Check X11 forwarding (should be disabled for security)
if grep -q "^X11Forwarding no" /etc/ssh/sshd_config; then
    ok "X11 Forwarding is disabled"
elif grep -q "^X11Forwarding yes" /etc/ssh/sshd_config; then
    warn "X11 Forwarding is enabled - disable if not needed"
fi
