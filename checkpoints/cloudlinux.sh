#!/bin/bash
. "$(dirname "$0")/../functions.sh"

# Parse --prompts flag
parse_prompts_flag "$@"

# Check if CloudLinux is installed
if [ -f /etc/cloudlinux-release ]; then
    ok "CloudLinux is installed: $(cat /etc/cloudlinux-release)"
else
    error "CloudLinux is not installed, current OS: $(cat /etc/os-release | grep PRETTY_NAME | cut -d= -f2 | tr -d '\"')"
    if [ "$PROMPTS" -eq 1 ]; then
        info "CloudLinux installation requires manual setup and licensing. Please visit: https://cloudlinux.com/"
    fi
    exit 1
fi