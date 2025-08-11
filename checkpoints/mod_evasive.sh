#!/bin/bash
# Check mod_evasive Apache module
if ! apachectl -M | grep -q 'evasive'; then
    echo "✖ mod_evasive is not enabled."
    exit 1
fi
echo "✔ mod_evasive is enabled."
