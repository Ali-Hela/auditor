#!/bin/bash
. "$(dirname "$0")/../functions.sh"

if ! apachectl -M | grep -q 'evasive'; then
    error "mod_evasive is not enabled."
    exit 1
fi
ok "mod_evasive is enabled."
    exit 1
fi
echo "$CHECK mod_evasive is enabled."
