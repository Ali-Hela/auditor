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

# Check if system timezone is Asia/Bahrain
if timedatectl 2>/dev/null | grep -q 'Asia/Bahrain'; then
    ok "System timezone is set to $(timedatectl | grep 'Time zone' | cut -d ':' -f2 | xargs)"
else
    error "System timezone is NOT set to Asia/Bahrain: $(timedatectl | grep 'Time zone' | cut -d ':' -f2 | xargs)"
    if [ "$PROMPTS" -eq 1 ]; then
        read -p "Do you want to set timezone to Asia/Bahrain now? (y/N): " confirm
        case "$confirm" in
            [yY][eE][sS]|[yY])
                set_timezone_bahrain
                ;;
            *)
                info "Timezone change skipped."
                ;;
        esac
    fi
fi