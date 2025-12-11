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

# Check if reboot is required
if [ -f /var/run/reboot-required ]; then
    error "System reboot is required"
fi

# Check SELinux status (if applicable)
if command -v getenforce &> /dev/null; then
    selinux_status=$(getenforce 2>/dev/null)
    if [ "$selinux_status" = "Enforcing" ]; then
        ok "SELinux is Enforcing (good security)"
    elif [ "$selinux_status" = "Permissive" ]; then
        warn "SELinux is Permissive - consider Enforcing mode"
    else
        warn "SELinux is Disabled"
    fi
fi

# Check for suspicious cronjobs (base64 encoded or hidden commands)
suspicious_cron=$(grep -rE "base64|eval\(|\$\{IFS\}" /var/spool/cron /etc/cron* 2>/dev/null | grep -v "^#" | wc -l)
if [ "$suspicious_cron" -gt 0 ]; then
    error "Found $suspicious_cron suspicious cron jobs - review immediately"
fi

# Check for world-writable files (critical security risk)
world_writable=$(find /etc /usr/local/cpanel /root -type f -perm -002 2>/dev/null | wc -l)
if [ "$world_writable" -gt 0 ]; then
    error "Found $world_writable world-writable files in critical directories"
fi

# Check for accounts with empty passwords (critical)
empty_pass=$(awk -F: '($2 == "") {print $1}' /etc/shadow 2>/dev/null | wc -l)
if [ "$empty_pass" -gt 0 ]; then
    error "Found $empty_pass accounts with empty passwords"
fi

# Check SSH key permissions (critical security)
if [ -d /root/.ssh ] && [ -f /root/.ssh/authorized_keys ]; then
    ssh_perms=$(stat -c %a /root/.ssh 2>/dev/null)
    key_perms=$(stat -c %a /root/.ssh/authorized_keys 2>/dev/null)
    
    if [ "$ssh_perms" != "700" ]; then
        warn "Root .ssh directory should have 700 permissions (current: $ssh_perms)"
    fi
    
    if [ "$key_perms" != "600" ]; then
        warn "Root authorized_keys should have 600 permissions (current: $key_perms)"
    fi
fi
