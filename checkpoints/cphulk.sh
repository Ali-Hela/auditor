#!/bin/bash
. "$(dirname "$0")/../functions.sh"

# Parse --prompts flag
parse_prompts_flag "$@"

# check if cPHulk service is active
if systemctl is-active --quiet cphulkd; then
    ok "cPHulk service is active"
else
    error "cPHulk service is not active"
    prompt_and_execute "Do you want to start cPHulk service now?" "start_cphulk" "cPHulk service start skipped."
fi
