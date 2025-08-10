#!/bin/bash
# List users with sudo privileges
if getent group sudo > /dev/null; then
    echo "Users with sudo privileges:"
    getent group sudo | cut -d: -f4
elif getent group wheel > /dev/null; then
    echo "🛈 Users with wheel privileges:"
    getent group wheel | cut -d: -f4
else
    echo "No sudo or wheel group found."
fi