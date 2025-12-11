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

# check if cPHulk service is active
if systemctl is-active --quiet cphulkd; then
    ok "cPHulk service is active"
else
    error "cPHulk service is not active"
    if [ "$PROMPTS" -eq 1 ]; then
        read -p "Do you want to start cPHulk service now? (y/N): " confirm
        case "$confirm" in
            [yY][eE][sS]|[yY])
                start_cphulk
                ;;
            *)
                info "cPHulk service start skipped."
                ;;
        esac
    fi
fi
