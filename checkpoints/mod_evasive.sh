#!/bin/bash
. "$(dirname "$0")/../functions.sh"

# Parse --prompts flag
parse_prompts_flag "$@"

if ! apachectl -M | grep -q 'evasive'; then
    error "Apache: mod_evasive is not enabled."
    prompt_and_execute "Do you want to install mod_evasive now?" "install_mod_evasive" "mod_evasive installation skipped."
    exit 1
else
    ok "Apache: mod_evasive is enabled."
fi
