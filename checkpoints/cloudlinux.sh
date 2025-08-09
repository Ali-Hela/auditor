#!/bin/bash
# Check if CloudLinux is installed and active

if [ -f /etc/cloudlinux-release ] && uname -r | grep -qi lve; then
    echo "✔ CloudLinux is installed and activated"
else
    echo "✘ CloudLinux is not installed or not activated"
fi