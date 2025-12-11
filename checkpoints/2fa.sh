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

# Check if 2FA is enabled in WHM
if whmapi1 twofactorauth_policy_status | grep -q 'is_enabled: 1'; then
    ok "2FA is enabled in WHM"
else
    error "2FA is NOT enabled in WHM"
    if [ "$PROMPTS" -eq 1 ]; then
        read -p "Do you want to enable 2FA in WHM now? (y/N): " confirm
        case "$confirm" in
            [yY][eE][sS]|[yY])
                enable_2fa_whm
                ;;
            *)
                info "2FA enablement skipped."
                ;;
        esac
    fi
fi