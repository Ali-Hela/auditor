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
    
    # Check license status
    if whmapi1 cpanel_license_status 2>/dev/null | grep -q "is_valid: 1"; then
        ok "cPanel license is valid"
    else
        error "cPanel license is invalid or expired"
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
    fi
    
    # Check Imunify360
    if [ -d "/etc/sysconfig/imunify360" ] || command -v imunify360-agent &> /dev/null; then
        ok "Imunify360 is installed"
    fi
    
else
    info "cPanel not detected - skipping WHM-specific checks"
fi
