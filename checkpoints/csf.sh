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

# Check if CSF (ConfigServer Security & Firewall) is installed
if [ ! -f /etc/csf/csf.conf ]; then
    error "CSF is not installed."
    exit 1
fi

# Check if CSF is in testing mode
if grep -q "TESTING = \"1\"" /etc/csf/csf.conf; then
    warn "CSF is installed but in TESTING mode - not blocking threats"
    if [ "$PROMPTS" -eq 1 ]; then
        read -p "Do you want to disable testing mode? (y/N): " confirm
        case "$confirm" in
            [yY][eE][sS]|[yY])
                sed -i 's/TESTING = "1"/TESTING = "0"/' /etc/csf/csf.conf
                csf -r
                ok "CSF testing mode disabled and restarted"
                ;;
            *)
                info "CSF testing mode change skipped."
                ;;
        esac
    fi
else
    ok "CSF is installed and active (not in testing mode)"
fi

# Check if CSF service is running
if systemctl is-active --quiet csf || pgrep lfd &> /dev/null; then
    ok "CSF/LFD services are running"
else
    error "CSF/LFD services are NOT running"
fi

# Check important CSF settings
if [ -f /etc/csf/csf.conf ]; then
    # Check if ICMP is limited
    icmp_limit=$(grep "^ICMP_IN_LIMIT" /etc/csf/csf.conf | cut -d'"' -f2)
    if [ "$icmp_limit" != "0" ]; then
        ok "ICMP rate limiting enabled: $icmp_limit/s"
    else
        warn "ICMP rate limiting disabled - consider enabling"
    fi
    
    # Check if synflood protection is enabled
    synflood=$(grep "^SYNFLOOD " /etc/csf/csf.conf | cut -d'"' -f2)
    if [ "$synflood" = "1" ]; then
        ok "SYN flood protection is enabled"
    else
        warn "SYN flood protection is disabled"
    fi
    
    # Check if port scan detection is enabled
    portflood=$(grep "^PORTFLOOD " /etc/csf/csf.conf | cut -d'"' -f2)
    if [ "$portflood" != "" ] && [ "$portflood" != "0" ]; then
        ok "Port flood protection is configured"
    else
        info "Port flood protection may not be configured"
    fi
    
    # Check common ports
    tcp_in=$(grep "^TCP_IN " /etc/csf/csf.conf | cut -d'"' -f2)
    if echo "$tcp_in" | grep -q "22"; then
        ok "SSH port (22) is allowed in CSF"
    else
        error "SSH port (22) not found in CSF TCP_IN - you may get locked out!"
    fi
    
    # Check if LFD (Login Failure Daemon) is enabled
    lfd=$(grep "^LF_DAEMON " /etc/csf/csf.conf | cut -d'"' -f2)
    if [ "$lfd" = "1" ]; then
        ok "Login Failure Daemon (LFD) is enabled"
    else
        warn "Login Failure Daemon (LFD) should be enabled"
    fi
fi

# Check CSF allow/deny lists
if [ -f /etc/csf/csf.allow ]; then
    allow_count=$(grep -v "^#" /etc/csf/csf.allow | grep -v "^$" | wc -l)
    info "CSF allow list entries: $allow_count"
fi

if [ -f /etc/csf/csf.deny ]; then
    deny_count=$(grep -v "^#" /etc/csf/csf.deny | grep -v "^$" | wc -l)
    info "CSF deny list entries: $deny_count"
fi
