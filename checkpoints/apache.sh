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
fi
