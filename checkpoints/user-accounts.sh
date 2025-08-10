#!/bin/bash
# List users with sudo privileges
if getent group sudo > /dev/null; then
    sudo_users=$(getent group sudo | cut -d: -f4)
    echo "Users with sudo privileges:"
    if [ -n "$sudo_users" ]; then
        echo "$sudo_users"
    else
        echo "▲ No users in sudo group."
    fi
elif getent group wheel > /dev/null; then
    wheel_users=$(getent group wheel | cut -d: -f4)
    echo "🛈 Users with wheel privileges:"
    if [ -n "$wheel_users" ]; then
        echo "$wheel_users"
    else
        echo "🛈 No users in wheel group."
    fi
else
    echo "▲ No sudo or wheel group found."
fi