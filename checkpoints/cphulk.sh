#!/bin/bash
. "$(dirname "$0")/../functions.sh"

# check if cPHulk service is active
if systemctl is-active --quiet cphulkd; then
    ok "cPHulk service is active"
else
    error "cPHulk service is not active"
fi
