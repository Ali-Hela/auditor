#!/bin/bash
. "$(dirname "$0")/../functions.sh"

# is hostname FQDN compatible
if [ -z "$HOSTNAME" ]; then
    error "Hostname is not set: $HOSTNAME"
    exit 1
else
    if [[ ! "$HOSTNAME" =~ ^[a-zA-Z0-9]([-a-zA-Z0-9]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([-a-zA-Z0-9]*[a-zA-Z0-9])?)*$ ]]; then
        warn "Hostname is not FQDN compatible: $HOSTNAME"
        exit 1
    else
        ok "Hostname is FQDN compatible: $HOSTNAME"
    fi
fi