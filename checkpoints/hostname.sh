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

# is hostname FQDN compatible
if [ -z "$HOSTNAME" ]; then
    error "Hostname is not set: $HOSTNAME"
    if [ "$PROMPTS" -eq 1 ]; then
        info "Hostname configuration requires manual setup. Use 'hostnamectl set-hostname your-fqdn.com'"
    fi
    exit 1
else
    if [[ ! "$HOSTNAME" =~ ^[a-zA-Z0-9]([-a-zA-Z0-9]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([-a-zA-Z0-9]*[a-zA-Z0-9])?)*$ ]]; then
        warn "Hostname is not FQDN compatible: $HOSTNAME"
        if [ "$PROMPTS" -eq 1 ]; then
            info "Hostname should be FQDN format (e.g., server.domain.com). Use 'hostnamectl set-hostname your-fqdn.com'"
        fi
        exit 1
    else
        ok "Hostname is FQDN compatible: $HOSTNAME"
    fi
fi