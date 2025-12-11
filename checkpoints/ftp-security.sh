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

# Check if FTP service is running
if systemctl is-active --quiet pure-ftpd || pgrep pure-ftpd &> /dev/null; then
    ok "Pure-FTPd is running"
elif systemctl is-active --quiet proftpd || pgrep proftpd &> /dev/null; then
    ok "ProFTPD is running"
elif systemctl is-active --quiet vsftpd || pgrep vsftpd &> /dev/null; then
    ok "vsftpd is running"
else
    warn "No FTP service detected - FTP may be disabled (recommended)"
    exit 0
fi

# Check FTP over TLS/SSL
if [ -f /etc/pure-ftpd/pure-ftpd.conf ]; then
    if grep -q "^TLS" /etc/pure-ftpd/pure-ftpd.conf 2>/dev/null; then
        tls_setting=$(grep "^TLS" /etc/pure-ftpd/pure-ftpd.conf | awk '{print $2}')
        if [ "$tls_setting" = "2" ]; then
            ok "Pure-FTPd requires TLS (forced)"
        elif [ "$tls_setting" = "1" ]; then
            warn "Pure-FTPd allows both TLS and plaintext - consider forcing TLS"
        else
            error "Pure-FTPd TLS is disabled - security risk!"
        fi
    else
        error "TLS not configured in Pure-FTPd"
    fi
fi

# Check if anonymous FTP is disabled
if [ -f /etc/pure-ftpd/pure-ftpd.conf ]; then
    if grep -q "^NoAnonymous.*yes" /etc/pure-ftpd/pure-ftpd.conf; then
        ok "Anonymous FTP is disabled"
    else
        error "Anonymous FTP may be enabled - security risk!"
    fi
elif [ -f /etc/proftpd.conf ]; then
    if grep -q "<Anonymous" /etc/proftpd.conf; then
        error "Anonymous FTP configuration found - verify it's disabled"
    else
        ok "No anonymous FTP configuration in ProFTPD"
    fi
fi

# Check FTP passive ports configuration
if [ -f /etc/pure-ftpd/pure-ftpd.conf ]; then
    if grep -q "^PassivePortRange" /etc/pure-ftpd/pure-ftpd.conf; then
        passive_range=$(grep "^PassivePortRange" /etc/pure-ftpd/pure-ftpd.conf | awk '{print $2}')
        ok "FTP passive port range configured: $passive_range"
    else
        warn "FTP passive port range not explicitly configured"
    fi
fi

# Check if FTP is jailed (users can't access outside their home)
if [ -f /etc/pure-ftpd/pure-ftpd.conf ]; then
    if grep -q "^ChrootEveryone.*yes" /etc/pure-ftpd/pure-ftpd.conf; then
        ok "FTP users are chrooted (jailed to home directory)"
    else
        warn "FTP chroot should be enforced"
    fi
fi
