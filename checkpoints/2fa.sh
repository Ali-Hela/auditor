#!/bin/bash
. "$(dirname "$0")/../functions.sh"

# Parse --prompts flag
parse_prompts_flag "$@"

# Check if 2FA is enabled in WHM
if whmapi1 twofactorauth_policy_status | grep -q 'is_enabled: 1'; then
    ok "2FA is enabled in WHM"
else
    error "2FA is NOT enabled in WHM"
    prompt_and_execute "Do you want to enable 2FA in WHM now?" "enable_2fa_whm" "2FA enablement skipped."
fi