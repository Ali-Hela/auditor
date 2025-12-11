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

# Check kernel version and updates
current_kernel=$(uname -r)
info "Current kernel: $current_kernel"

# Check for available kernel updates
if command -v yum &> /dev/null; then
    kernel_updates=$(yum list updates kernel 2>/dev/null | grep -c "^kernel")
    if [ "$kernel_updates" -gt 0 ]; then
        warn "Kernel updates available: $kernel_updates - reboot may be required"
    else
        ok "Kernel is up to date"
    fi
elif command -v apt &> /dev/null; then
    kernel_updates=$(apt list --upgradable 2>/dev/null | grep -c "linux-image")
    if [ "$kernel_updates" -gt 0 ]; then
        warn "Kernel updates available: $kernel_updates - reboot may be required"
    else
        ok "Kernel is up to date"
    fi
fi

# Check uptime and if reboot is required
uptime_days=$(uptime | awk '{print $3}' | sed 's/,//')
info "System uptime: $(uptime -p)"

if [ -f /var/run/reboot-required ]; then
    error "System reboot is required!"
fi

# Check for important security packages
security_packages="aide rkhunter chkrootkit lynis"
for package in $security_packages; do
    if command -v "$package" &> /dev/null; then
        ok "$package is installed"
    else
        info "$package not installed - consider for enhanced security scanning"
    fi
done | head -5

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

# Check for suspicious cronjobs
info "Checking for suspicious cron jobs..."
suspicious_cron=$(grep -r "wget\|curl" /var/spool/cron /etc/cron* 2>/dev/null | grep -v "^#" | wc -l)
if [ "$suspicious_cron" -gt 0 ]; then
    warn "Found $suspicious_cron cron jobs with wget/curl - review for malicious activity"
fi

# Check for world-writable files (security risk)
info "Checking for world-writable files in critical directories..."
world_writable=$(find /etc /usr/local/cpanel /root -type f -perm -002 2>/dev/null | wc -l)
if [ "$world_writable" -gt 0 ]; then
    error "Found $world_writable world-writable files in critical directories!"
else
    ok "No world-writable files found in critical directories"
fi

# Check for SUID/SGID files
info "Checking for SUID/SGID binaries..."
suid_count=$(find /usr /bin /sbin -type f \( -perm -4000 -o -perm -2000 \) 2>/dev/null | wc -l)
info "Found $suid_count SUID/SGID files (review regularly)"

# Check password policies
if [ -f /etc/login.defs ]; then
    pass_max_days=$(grep "^PASS_MAX_DAYS" /etc/login.defs | awk '{print $2}')
    pass_min_days=$(grep "^PASS_MIN_DAYS" /etc/login.defs | awk '{print $2}')
    pass_min_len=$(grep "^PASS_MIN_LEN" /etc/login.defs | awk '{print $2}')
    
    if [ -n "$pass_max_days" ] && [ "$pass_max_days" -le 90 ]; then
        ok "Password max age: $pass_max_days days"
    else
        warn "Password max age should be 90 days or less (current: $pass_max_days)"
    fi
fi

# Check for accounts with empty passwords
empty_pass=$(awk -F: '($2 == "") {print $1}' /etc/shadow 2>/dev/null | wc -l)
if [ "$empty_pass" -gt 0 ]; then
    error "Found $empty_pass accounts with empty passwords!"
else
    ok "No accounts with empty passwords"
fi

# Check SSH key permissions
if [ -d /root/.ssh ]; then
    if [ "$(stat -c %a /root/.ssh)" = "700" ]; then
        ok "Root .ssh directory has correct permissions (700)"
    else
        warn "Root .ssh directory permissions should be 700"
    fi
    
    if [ -f /root/.ssh/authorized_keys ]; then
        if [ "$(stat -c %a /root/.ssh/authorized_keys)" = "600" ]; then
            ok "Root authorized_keys has correct permissions (600)"
        else
            warn "Root authorized_keys permissions should be 600"
        fi
    fi
fi

# Check for failed login attempts
failed_logins=$(grep "Failed password" /var/log/secure 2>/dev/null | tail -20 | wc -l)
if [ "$failed_logins" -gt 10 ]; then
    warn "High number of failed login attempts detected: $failed_logins in recent logs"
fi

# Check system logs for errors
recent_errors=$(journalctl -p err -b 2>/dev/null | wc -l)
if [ "$recent_errors" -gt 0 ]; then
    info "System errors since last boot: $recent_errors (review journalctl -p err)"
fi
