#!/bin/bash
# Check if csf is installed
if [ ! -f /etc/cse/cse.conf ]; then
    echo "✘ CSE is not installed."
    exit 1
fi