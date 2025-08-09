#!/bin/bash
# Check if CloudLinux is installed
if [ -f /etc/cloudlinux-release ]; then
    echo "✔ CloudLinux is installed."
else
    echo "✘ CloudLinux is not installed."
    exit 1
fi

# Check if the CloudLinux is activated
if [ -f /etc/cl_activation ]; then
    echo "✔ CloudLinux is activated."
else
    echo "✘ CloudLinux is not activated."
    exit 1
fi