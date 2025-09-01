#!/bin/bash
. "$(dirname "$0")/../functions.sh"

if ! apachectl -M | grep -q 'evasive'; then
    error "Apache: mod_evasive is not enabled."
    exit 1
else
    success "Apache: mod_evasive is enabled."
fi
