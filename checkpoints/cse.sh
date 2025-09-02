#!/bin/bash
. "$(dirname "$0")/../functions.sh"

# Parse --prompts flag
parse_prompts_flag "$@"

# Check if CSE is installed
if [ -f /usr/local/cpanel/whostmgr/docroot/cgi/configserver/cse/cse.conf ]; then
    ok "CSE is installed."
elif [ -f /var/cpanel/apps/cse.conf ]; then
    ok "CSE is installed (legacy location)."
else
    error "CSE is not installed."
    prompt_and_execute "Do you want to install CSE now?" "install_cse" "CSE installation skipped."
    exit 1
fi