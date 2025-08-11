#!/bin/bash
. "$(dirname "$0")/../functions.sh"
# Check if system timezone is Asia/Bahrain

if timedatectl 2>/dev/null | grep -q 'Asia/Bahrain'; then
    ok "System timezone is set to $(timedatectl | grep 'Time zone' | cut -d ':' -f2 | xargs)"
else
    error "System timezone is NOT set to Asia/Bahrain: $(timedatectl | grep 'Time zone' | cut -d ':' -f2 | xargs)"
fi