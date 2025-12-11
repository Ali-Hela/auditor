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

# Find main php.ini file
php_ini=""
if php -i 2>/dev/null | grep -q "Loaded Configuration File"; then
    php_ini=$(php -i 2>/dev/null | grep "Loaded Configuration File" | cut -d'>' -f2 | xargs)
fi

if [ -z "$php_ini" ] || [ ! -f "$php_ini" ]; then
    warn "Could not locate main php.ini file"
    exit 0
fi

# Check dangerous PHP functions
if grep -q "^disable_functions" "$php_ini"; then
    disabled=$(grep "^disable_functions" "$php_ini" | head -1)
    if echo "$disabled" | grep -qE "(exec|passthru|shell_exec|system|proc_open|popen)"; then
        ok "Dangerous PHP functions are disabled"
    else
        warn "Dangerous PHP functions (exec, shell_exec, system, etc.) should be disabled"
    fi
else
    warn "disable_functions not set in php.ini"
fi

# Check allow_url_include (critical security risk)
if grep "^allow_url_include" "$php_ini" | grep -q "Off"; then
    ok "allow_url_include is Off"
else
    error "allow_url_include should be Off - critical security risk"
fi

# Check expose_php
if grep "^expose_php" "$php_ini" | grep -q "Off"; then
    ok "expose_php is Off"
fi

# Check display_errors for production
if grep "^display_errors" "$php_ini" | grep -q "Off"; then
    ok "display_errors is Off (production setting)"
fi

# Quick malware pattern check
malware_count=$(find /home -name "*.php" -type f -exec grep -l "eval(base64_decode\|eval(gzinflate\|preg_replace.*\/e" {} \; 2>/dev/null | wc -l)
if [ "$malware_count" -gt 0 ]; then
    error "Found $malware_count PHP files with suspicious patterns - investigate for malware"
fi
