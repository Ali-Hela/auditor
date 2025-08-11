#!/bin/bash
. "$(dirname "$0")/../functions.sh"
# Check if csf is installed
if [ -f /usr/local/cpanel/whostmgr/docroot/cgi/configserver/cse/cse.conf ]; then
    ok "CSE is installed."
    exit 0
elif [ -f /var/cpanel/apps/cse.conf ]; then
    ok "CSE is installed (legacy location)."
    exit 0
else
    error "CSE is not installed."
    exit 1
fi