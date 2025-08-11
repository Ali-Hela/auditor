#!/bin/bash
. "$(dirname "$0")/../functions.sh"
# Check if CloudLinux is installed
if [ -f /etc/cloudlinux-release ]; then
    ok "CloudLinux is installed: $(cat /etc/cloudlinux-release)"
else
    error "CloudLinux is not installed, current OS: $(cat /etc/os-release | grep PRETTY_NAME | cut -d= -f2 | tr -d '\"')"
    exit 1
fi