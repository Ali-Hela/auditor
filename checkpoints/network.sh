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

# Check DNS resolution
if ping -c 1 8.8.8.8 &> /dev/null; then
    ok "Internet connectivity is working (ping 8.8.8.8)"
else
    error "No internet connectivity detected"
fi

# Check DNS resolution
if host google.com &> /dev/null; then
    ok "DNS resolution is working"
else
    error "DNS resolution is NOT working"
fi

# Check nameservers
if [ -f /etc/resolv.conf ]; then
    nameserver_count=$(grep -c "^nameserver" /etc/resolv.conf)
    if [ "$nameserver_count" -gt 0 ]; then
        ok "Nameservers configured: $nameserver_count"
        grep "^nameserver" /etc/resolv.conf | while read -r line; do
            info "  $line"
        done
    else
        error "No nameservers configured in /etc/resolv.conf"
    fi
fi

# Check server's own DNS records
hostname_fqdn=$(hostname -f)
server_ip=$(hostname -I | awk '{print $1}')

# Check A record
if host "$hostname_fqdn" &> /dev/null; then
    resolved_ip=$(host "$hostname_fqdn" | grep "has address" | awk '{print $4}' | head -1)
    if [ "$resolved_ip" = "$server_ip" ]; then
        ok "Hostname DNS A record matches server IP: $server_ip"
    else
        warn "Hostname resolves to $resolved_ip but server IP is $server_ip"
    fi
else
    error "Hostname $hostname_fqdn does not resolve in DNS"
fi

# Check reverse DNS (PTR record)
ptr_record=$(host "$server_ip" 2>/dev/null | grep "domain name pointer" | awk '{print $5}' | sed 's/\.$//')
if [ -n "$ptr_record" ]; then
    if [ "$ptr_record" = "$hostname_fqdn" ]; then
        ok "Reverse DNS (PTR) matches hostname: $ptr_record"
    else
        warn "Reverse DNS is $ptr_record but hostname is $hostname_fqdn"
    fi
else
    warn "No reverse DNS (PTR) record found for $server_ip"
fi

# Check if listening on correct ports
expected_ports="22 25 53 80 110 143 443 465 587 993 995 2077 2078 2082 2083 2086 2087"
for port in $expected_ports; do
    if netstat -tuln 2>/dev/null | grep -q ":$port " || ss -tuln 2>/dev/null | grep -q ":$port "; then
        case $port in
            22) service="SSH" ;;
            25) service="SMTP" ;;
            53) service="DNS" ;;
            80) service="HTTP" ;;
            110) service="POP3" ;;
            143) service="IMAP" ;;
            443) service="HTTPS" ;;
            465) service="SMTPS" ;;
            587) service="Submission" ;;
            993) service="IMAPS" ;;
            995) service="POP3S" ;;
            2077) service="WHM/cPanel (SSL)" ;;
            2078) service="Webmail (SSL)" ;;
            2082) service="cPanel" ;;
            2083) service="cPanel (SSL)" ;;
            2086) service="WHM" ;;
            2087) service="WHM (SSL)" ;;
            *) service="Port $port" ;;
        esac
        # Only show critical services or report issues
        if [ "$port" = "22" ] || [ "$port" = "80" ] || [ "$port" = "443" ]; then
            ok "$service listening on port $port"
        fi
    else
        # Warn about missing critical services
        if [ "$port" = "22" ] || [ "$port" = "80" ] || [ "$port" = "443" ]; then
            warn "$service not listening on port $port"
        fi
    fi
done | head -20  # Limit output

# Check firewall rules
if command -v csf &> /dev/null; then
    if csf -l 2>/dev/null | grep -q "DROP"; then
        ok "CSF firewall has active rules"
    fi
elif command -v firewalld &> /dev/null; then
    if systemctl is-active --quiet firewalld; then
        ok "firewalld is active"
    else
        warn "firewalld is installed but not active"
    fi
elif command -v ufw &> /dev/null; then
    if ufw status 2>/dev/null | grep -q "active"; then
        ok "UFW firewall is active"
    else
        warn "UFW is installed but not active"
    fi
else
    warn "No recognized firewall detected (CSF/firewalld/UFW)"
fi

# Check for open ports that shouldn't be (security scan)
suspicious_ports="3306 5432 6379 27017 11211"
for port in $suspicious_ports; do
    if netstat -tuln 2>/dev/null | grep -q ":$port " || ss -tuln 2>/dev/null | grep -q ":$port "; then
        # Check if it's listening on public interface
        if netstat -tuln 2>/dev/null | grep ":$port " | grep -q "0.0.0.0"; then
            case $port in
                3306) service="MySQL" ;;
                5432) service="PostgreSQL" ;;
                6379) service="Redis" ;;
                27017) service="MongoDB" ;;
                11211) service="Memcached" ;;
            esac
            warn "$service (port $port) is listening on public interface - security risk!"
        fi
    fi
done

# Check for DDoS protection
if [ -d "/usr/local/cpanel" ]; then
    if whmapi1 get_tweaksetting key=cphulk 2>/dev/null | grep -q "value: 1"; then
        ok "cPHulk brute force protection is enabled"
    else
        warn "cPHulk should be enabled for brute force protection"
    fi
fi
