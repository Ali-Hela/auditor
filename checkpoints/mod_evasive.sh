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

if ! apachectl -M | grep -q 'evasive'; then
    error "Apache: mod_evasive is not enabled."
    if [ "$PROMPTS" -eq 1 ]; then
        read -p "Do you want to install mod_evasive now? (y/N): " confirm
        case "$confirm" in
            [yY][eE][sS]|[yY])
                install_mod_evasive
                ;;
            *)
                info "mod_evasive installation skipped."
                ;;
        esac
    fi
    exit 1
else
    ok "Apache: mod_evasive is enabled."
fi
