#!/bin/bash
. "$(dirname "$0")/../functions.sh"
CHECK="✔"
CROSS="✘"
# Check if 2FA is enabled in WHM

if whmapi1 twofactorauth_policy_status | grep -q 'is_enabled: 1'; then
    ok "2FA is enabled in WHM"
else
    error "2FA is NOT enabled in WHM"
fi