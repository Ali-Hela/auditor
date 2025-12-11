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

# Check DKIM if cPanel is present
if [ -d "/var/cpanel/domain_keys" ]; then
    dkim_count=$(find /var/cpanel/domain_keys -name "*.private" 2>/dev/null | wc -l)
    if [ "$dkim_count" -gt 0 ]; then
        ok "DKIM keys configured for $dkim_count domains"
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
    # Check if RBL is enabled
    if grep -q "dnsbl" /etc/exim.conf; then
        ok "RBL (spam blacklist) checks are configured"
    fi
fi
