#!/bin/bash
# Check if CloudLinux is installed
if [ -f /etc/cloudlinux-release ]; then
    echo "✔ CloudLinux is installed: $(cat /etc/cloudlinux-release)"
else
    echo "✘ CloudLinux is not installed, current OS: $(cat /etc/os-release | grep PRETTY_NAME | cut -d= -f2 | tr -d '\"')"
    exit 1
fi