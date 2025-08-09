#!/bin/bash
# Check if CloudLinux is installed
if [ -f /etc/cloudlinux-release ]; then
    echo "✔ CloudLinux is installed."
else
    echo "✘ CloudLinux is not installed."
    exit 1
fi