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

# Check if WHM is accessible
if [ -d "/usr/local/cpanel" ]; then
    if systemctl is-active --quiet cpanel || pgrep cpsrvd &> /dev/null; then
        ok "cPanel/WHM services are running"
    else
        error "cPanel/WHM services are NOT running"
    fi
    
    # Check cPanel version
    cpanel_version=$(cat /usr/local/cpanel/version 2>/dev/null)
    if [ -n "$cpanel_version" ]; then
        info "cPanel version: $cpanel_version"
    fi
    
    # Check EasyApache version
    if [ -f /usr/local/apache/version ]; then
        ea_version=$(cat /usr/local/apache/version 2>/dev/null)
        info "EasyApache version: $ea_version"
    fi
    
    # Check if cPanel is up to date
    if [ -f /var/cpanel/cpupdate.conf ]; then
        update_type=$(grep "^CPANEL=" /var/cpanel/cpupdate.conf | cut -d'=' -f2)
        if [ "$update_type" = "release" ]; then
            ok "cPanel is on RELEASE tier (stable)"
        elif [ "$update_type" = "stable" ]; then
            ok "cPanel is on STABLE tier"
        else
            warn "cPanel update tier: $update_type"
        fi
    fi
    
    # Check license status
    if whmapi1 cpanel_license_status 2>/dev/null | grep -q "is_valid: 1"; then
        ok "cPanel license is valid"
    else
        error "cPanel license may be invalid or expired"
    fi
    
    # Check if tweak settings are secure
    # - Shell Fork Bomb Protection
    if whmapi1 get_tweaksetting key=shell_fork_bomb_protection 2>/dev/null | grep -q "value: 1"; then
        ok "Shell fork bomb protection is enabled"
    else
        warn "Shell fork bomb protection should be enabled"
    fi
    
    # - Compiler access
    if whmapi1 get_tweaksetting key=compilers 2>/dev/null | grep -q "value: 0"; then
        ok "Compiler access is restricted"
    else
        warn "Compiler access is not restricted - security risk"
    fi
    
    # Check account count
    account_count=$(whmapi1 listaccts 2>/dev/null | grep -c "user:")
    if [ -n "$account_count" ]; then
        info "Total cPanel accounts: $account_count"
    fi
    
    # Check suspended accounts
    suspended_count=$(whmapi1 listaccts 2>/dev/null | grep -c "suspended: 1")
    if [ "$suspended_count" -gt 0 ]; then
        info "Suspended accounts: $suspended_count"
    fi
    
    # Check for outdated account passwords
    info "Checking for accounts that haven't changed passwords recently..."
    old_password_accounts=$(find /var/cpanel/users -type f -mtime +180 2>/dev/null | wc -l)
    if [ "$old_password_accounts" -gt 0 ]; then
        warn "$old_password_accounts accounts haven't updated configs in 180+ days"
    fi
    
    # Check WHM root password age
    root_pass_age=$(passwd -S root 2>/dev/null | awk '{print $3}')
    if [ -n "$root_pass_age" ]; then
        info "Root password last changed: $root_pass_age"
    fi
    
    # Check for MySQL root access from remote
    if mysql -e "SELECT Host, User FROM mysql.user WHERE User='root'" 2>/dev/null | grep -v "localhost\|127.0.0.1" | grep -q "root"; then
        error "MySQL root user has remote access - security risk!"
    else
        ok "MySQL root access is restricted to localhost"
    fi
    
    # Check ModSecurity status
    if whmapi1 modsec_get_configs 2>/dev/null | grep -q "active: 1"; then
        ok "ModSecurity is active"
    else
        warn "ModSecurity should be enabled for web application firewall"
    fi
    
    # Check Imunify360 or other security software
    if [ -d "/etc/sysconfig/imunify360" ] || command -v imunify360-agent &> /dev/null; then
        ok "Imunify360 is installed"
    else
        info "Imunify360 not detected - consider for enhanced security"
    fi
    
    # Check for demo accounts (security risk)
    if whmapi1 listaccts 2>/dev/null | grep -q "user: demo\|user: test"; then
        warn "Demo or test accounts detected - remove if not needed"
    fi
    
    # Check API tokens
    api_token_count=$(find /var/cpanel/users -name "*.json" 2>/dev/null | wc -l)
    if [ "$api_token_count" -gt 0 ]; then
        info "API tokens in use: $api_token_count (review regularly)"
    fi
    
else
    info "cPanel not detected - skipping WHM-specific checks"
fi
