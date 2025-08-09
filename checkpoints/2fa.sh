#!/bin/bash
# Check if 2FA is enabled in WHM

if whmapi1 twofactorauth_status | grep -q 'enabled: 1'; then
    echo "✔ 2FA is enabled in WHM"
else
    echo "✘ 2FA is NOT enabled in WHM"
fi