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

# Check for pending security updates
if command -v yum &> /dev/null; then
    updates=$(yum check-update --security -q | grep -E '^[a-zA-Z0-9_.-]+\s+[0-9]')
    if [ -n "$updates" ]; then
        warn "Security updates are available! $(echo "$updates" | wc -l) updates found."
        if [ "$PROMPTS" -eq 1 ]; then
            read -p "Do you want to install security updates now? (y/N): " confirm
            case "$confirm" in
                [yY][eE][sS]|[yY])
                    install_security_updates
                    ;;
                *)
                    info "Security updates installation skipped."
                    ;;
            esac
        fi
    else
        ok "No pending security updates."
    fi
else
    warn "Security Updates: Unsupported package manager."
fi