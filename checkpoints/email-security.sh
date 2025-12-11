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

# Check if Exim is running
if systemctl is-active --quiet exim || pgrep exim &> /dev/null; then
    ok "Exim mail server is running"
else
    error "Exim mail server is NOT running"
fi

# Check mail queue size
queue_size=$(exim -bpc 2>/dev/null)
if [ -n "$queue_size" ]; then
    if [ "$queue_size" -lt 100 ]; then
        ok "Mail queue size is acceptable: $queue_size messages"
    elif [ "$queue_size" -lt 1000 ]; then
        warn "Mail queue has $queue_size messages - may need attention"
    else
        error "Mail queue has $queue_size messages - investigate for spam/issues"
    fi
else
    warn "Could not check mail queue size"
fi

# Check for frozen emails
frozen_count=$(exim -bp 2>/dev/null | grep -c "*** frozen ***")
if [ "$frozen_count" -gt 0 ]; then
    warn "Found $frozen_count frozen emails in queue"
else
    ok "No frozen emails in queue"
fi

# Check SPF records for server hostname
hostname_fqdn=$(hostname -f)
if host -t TXT "$hostname_fqdn" 2>/dev/null | grep -q "v=spf1"; then
    ok "SPF record exists for $hostname_fqdn"
else
    warn "No SPF record found for $hostname_fqdn - email deliverability may be affected"
fi

# Check DKIM
if [ -d "/var/cpanel/domain_keys" ]; then
    dkim_count=$(find /var/cpanel/domain_keys -name "*.private" 2>/dev/null | wc -l)
    if [ "$dkim_count" -gt 0 ]; then
        ok "DKIM keys found for $dkim_count domains"
    else
        warn "No DKIM keys found - email authentication may be affected"
    fi
fi

# Check DMARC on main domain
if [ -f /etc/localdomains ]; then
    main_domain=$(head -1 /etc/localdomains)
    if host -t TXT "_dmarc.$main_domain" 2>/dev/null | grep -q "v=DMARC1"; then
        ok "DMARC record exists for $main_domain"
    else
        warn "No DMARC record found for $main_domain - recommended for email security"
    fi
fi

# Check for email bombing/spam indicators
recent_sent=$(grep -c "cwd=/home" /var/log/exim_mainlog 2>/dev/null | head -1)
if [ -n "$recent_sent" ]; then
    info "Recent emails sent from user accounts: checking patterns..."
    # Check for accounts sending high volumes
    top_sender=$(grep "cwd=/home" /var/log/exim_mainlog 2>/dev/null | awk '{print $3}' | sort | uniq -c | sort -rn | head -1)
    if [ -n "$top_sender" ]; then
        info "Top sender activity: $top_sender"
    fi
fi

# Check Exim configuration security
if [ -f /etc/exim.conf ]; then
    # Check if relaying is properly restricted
    if grep -q "relay_from_hosts" /etc/exim.conf; then
        ok "Relay restrictions configured in Exim"
    else
        warn "Relay restrictions may not be properly configured"
    fi
    
    # Check if RBL is enabled
    if grep -q "dnsbl" /etc/exim.conf; then
        ok "RBL (spam blacklist) checks are configured"
    else
        warn "Consider enabling RBL checks for spam prevention"
    fi
fi

# Check for boxtrapper
if whmapi1 get_tweaksetting key=boxtrapper 2>/dev/null | grep -q "value: 1"; then
    info "BoxTrapper is available"
fi

# Check mail authentication settings
if [ -f /var/cpanel/cpanel.config ]; then
    if grep -q "emailauth=1" /var/cpanel/cpanel.config; then
        ok "SMTP authentication is required"
    else
        warn "SMTP authentication should be enabled to prevent abuse"
    fi
fi
