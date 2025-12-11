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

# Check SSL certificates for main hostname
hostname_fqdn=$(hostname -f)

# Check if SSL certificate exists for hostname
if [ -f "/etc/ssl/certs/${hostname_fqdn}.crt" ] || [ -f "/var/cpanel/ssl/installed/certs/${hostname_fqdn}.crt" ]; then
    ok "SSL certificate exists for $hostname_fqdn"
    
    # Find the certificate
    cert_file=""
    if [ -f "/var/cpanel/ssl/installed/certs/${hostname_fqdn}.crt" ]; then
        cert_file="/var/cpanel/ssl/installed/certs/${hostname_fqdn}.crt"
    elif [ -f "/etc/ssl/certs/${hostname_fqdn}.crt" ]; then
        cert_file="/etc/ssl/certs/${hostname_fqdn}.crt"
    fi
    
    # Check expiry date
    if [ -n "$cert_file" ] && [ -f "$cert_file" ]; then
        expiry_date=$(openssl x509 -enddate -noout -in "$cert_file" 2>/dev/null | cut -d= -f2)
        expiry_epoch=$(date -d "$expiry_date" +%s 2>/dev/null)
        current_epoch=$(date +%s)
        days_until_expiry=$(( ($expiry_epoch - $current_epoch) / 86400 ))
        
        if [ "$days_until_expiry" -lt 0 ]; then
            error "SSL certificate for $hostname_fqdn has EXPIRED!"
        elif [ "$days_until_expiry" -lt 30 ]; then
            error "SSL certificate for $hostname_fqdn expires in $days_until_expiry days!"
        elif [ "$days_until_expiry" -lt 60 ]; then
            warn "SSL certificate for $hostname_fqdn expires in $days_until_expiry days"
        else
            ok "SSL certificate for $hostname_fqdn is valid for $days_until_expiry more days"
        fi
    fi
else
    error "No SSL certificate found for $hostname_fqdn"
fi

# Check AutoSSL status
if [ -d "/usr/local/cpanel" ]; then
    if whmapi1 get_autossl_pending_queue 2>/dev/null | grep -q "provider"; then
        autossl_provider=$(whmapi1 get_autossl_providers 2>/dev/null | grep "provider:" | head -1 | awk '{print $2}')
        if [ -n "$autossl_provider" ]; then
            ok "AutoSSL is configured with provider: $autossl_provider"
        else
            ok "AutoSSL is configured"
        fi
    else
        warn "AutoSSL may not be configured - automatic SSL renewal could be affected"
    fi
fi

# Check for self-signed certificates
self_signed_count=$(find /var/cpanel/ssl/installed/certs /etc/ssl/certs -name "*.crt" -type f 2>/dev/null | xargs -I {} sh -c 'openssl x509 -noout -issuer -subject -in {} 2>/dev/null' | grep -c "subject.*issuer.*")
if [ "$self_signed_count" -gt 0 ]; then
    warn "Found certificates that may be self-signed - browsers will show warnings"
else
    ok "No obviously self-signed certificates detected"
fi

# Check SSL/TLS protocols in Apache
if grep -r "SSLProtocol" /etc/httpd/conf* /etc/apache2/conf* 2>/dev/null | grep -v "^#" | grep -q "SSLProtocol"; then
    # Check if TLS 1.2+ is enforced
    if grep -r "SSLProtocol" /etc/httpd/conf* /etc/apache2/conf* 2>/dev/null | grep -v "^#" | grep -E "TLSv1\.[23]"; then
        ok "Modern TLS protocols (1.2+) are configured"
    else
        warn "TLS configuration should disable SSLv3, TLSv1.0, TLSv1.1"
    fi
fi

# Check SSL cipher suites
if grep -r "SSLCipherSuite" /etc/httpd/conf* /etc/apache2/conf* 2>/dev/null | grep -v "^#" | grep -q "SSLCipherSuite"; then
    ok "SSL cipher suite is configured"
else
    warn "Consider configuring strong SSL cipher suites"
fi

# Check for mixed content issues (HTTP + HTTPS)
if [ -f /etc/apache2/sites-enabled/000-default.conf ] || [ -f /etc/httpd/conf/httpd.conf ]; then
    http_vhosts=$(grep -r "VirtualHost.*:80" /etc/httpd/conf* /etc/apache2/sites-* 2>/dev/null | wc -l)
    https_vhosts=$(grep -r "VirtualHost.*:443" /etc/httpd/conf* /etc/apache2/sites-* 2>/dev/null | wc -l)
    info "HTTP VirtualHosts: $http_vhosts, HTTPS VirtualHosts: $https_vhosts"
fi

# Check if HSTS is configured
if grep -r "Strict-Transport-Security" /etc/httpd/conf* /etc/apache2/conf* 2>/dev/null | grep -v "^#" | grep -q "Strict-Transport-Security"; then
    ok "HSTS (HTTP Strict Transport Security) is configured"
else
    warn "HSTS not configured - consider adding for enhanced security"
fi
