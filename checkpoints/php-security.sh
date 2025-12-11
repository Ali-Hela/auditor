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

# Check PHP version
php_version=$(php -v 2>/dev/null | head -n 1)
if [ -n "$php_version" ]; then
    info "PHP version: $php_version"
    
    # Check if PHP version is EOL (< 7.4)
    if php -v | grep -qE "PHP [567]\.[0-3]"; then
        error "PHP version is outdated and may be End of Life"
    elif php -v | grep -qE "PHP 7\.4"; then
        warn "PHP 7.4 has reached security-only support - consider upgrading to 8.x"
    else
        ok "PHP version appears current"
    fi
else
    warn "PHP is not installed or not in PATH"
    exit 0
fi

# Find php.ini files
php_ini_files=$(find /etc /opt/cpanel /usr/local -name "php.ini" 2>/dev/null | head -10)

if [ -z "$php_ini_files" ]; then
    warn "Could not locate php.ini files"
    exit 0
fi

# Check dangerous PHP functions
for php_ini in $php_ini_files; do
    if [ -f "$php_ini" ]; then
        # Check disable_functions
        if grep -q "^disable_functions" "$php_ini"; then
            disabled=$(grep "^disable_functions" "$php_ini" | head -1)
            if echo "$disabled" | grep -qE "(exec|passthru|shell_exec|system|proc_open|popen)"; then
                ok "Dangerous PHP functions are disabled in $(basename $(dirname $php_ini))"
            else
                warn "Some dangerous PHP functions may not be disabled in $php_ini"
            fi
        else
            warn "disable_functions not set in $php_ini"
        fi
        
        # Check allow_url_fopen
        if grep "^allow_url_fopen" "$php_ini" | grep -q "Off"; then
            ok "allow_url_fopen is Off in $(basename $(dirname $php_ini))"
        else
            warn "allow_url_fopen should be Off in $php_ini"
        fi
        
        # Check allow_url_include
        if grep "^allow_url_include" "$php_ini" | grep -q "Off"; then
            ok "allow_url_include is Off in $(basename $(dirname $php_ini))"
        else
            error "allow_url_include should be Off in $php_ini - critical security risk"
        fi
        
        # Check expose_php
        if grep "^expose_php" "$php_ini" | grep -q "Off"; then
            ok "expose_php is Off in $(basename $(dirname $php_ini))"
        else
            warn "expose_php should be Off in $php_ini"
        fi
        
        # Check display_errors for production
        if grep "^display_errors" "$php_ini" | grep -q "Off"; then
            ok "display_errors is Off in $(basename $(dirname $php_ini))"
        else
            warn "display_errors should be Off in production in $php_ini"
        fi
    fi
done | head -30  # Limit output if many php.ini files

# Check for common PHP shells or malware patterns
info "Scanning for potential PHP malware in /home (sample check)..."
malware_count=$(find /home -name "*.php" -type f -exec grep -l "eval(base64_decode" {} \; 2>/dev/null | wc -l)
if [ "$malware_count" -gt 0 ]; then
    error "Found $malware_count PHP files with suspicious base64 patterns - investigate for malware"
else
    ok "No obvious PHP malware patterns detected in quick scan"
fi
