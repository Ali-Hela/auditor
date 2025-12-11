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

# Check Apache status
if systemctl is-active --quiet httpd || systemctl is-active --quiet apache2; then
    ok "Apache is running"
else
    error "Apache is NOT running"
fi

# Check if Apache version is showing (ServerTokens)
if command -v httpd &> /dev/null; then
    apache_cmd="httpd"
elif command -v apache2 &> /dev/null; then
    apache_cmd="apache2"
else
    warn "Apache command not found"
    exit 0
fi

# Check ServerTokens setting
if grep -r "ServerTokens Prod" /etc/httpd/conf* /etc/apache2/conf* 2>/dev/null | grep -v "^#" | grep -q "ServerTokens"; then
    ok "ServerTokens is set to Prod (secure)"
else
    warn "ServerTokens is not set to Prod - Apache version may be exposed"
fi

# Check ServerSignature setting
if grep -r "ServerSignature Off" /etc/httpd/conf* /etc/apache2/conf* 2>/dev/null | grep -v "^#" | grep -q "ServerSignature"; then
    ok "ServerSignature is Off (secure)"
else
    warn "ServerSignature is not Off - Server information may be exposed"
fi

# Check if mod_security is enabled
if $apache_cmd -M 2>/dev/null | grep -q "security2_module"; then
    ok "ModSecurity is enabled"
else
    warn "ModSecurity is NOT enabled - Consider installing for WAF protection"
fi

# Check if SymLinks are disabled in main config
if grep -r "Options -Indexes" /etc/httpd/conf* /etc/apache2/conf* 2>/dev/null | grep -v "^#" | grep -q "Options"; then
    ok "Directory indexing is disabled"
else
    warn "Directory indexing may be enabled - security risk"
fi

# Check TraceEnable
if grep -r "TraceEnable off" /etc/httpd/conf* /etc/apache2/conf* 2>/dev/null | grep -v "^#" | grep -q "TraceEnable"; then
    ok "TraceEnable is off (secure)"
else
    warn "TraceEnable should be disabled to prevent XST attacks"
fi

# Check Apache error log size
if [ -f /var/log/httpd/error_log ]; then
    error_log_size=$(du -h /var/log/httpd/error_log 2>/dev/null | cut -f1)
    info "Apache error log size: $error_log_size"
elif [ -f /var/log/apache2/error.log ]; then
    error_log_size=$(du -h /var/log/apache2/error.log 2>/dev/null | cut -f1)
    info "Apache error log size: $error_log_size"
fi
