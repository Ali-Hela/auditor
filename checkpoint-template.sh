#!/bin/bash
# Check if system timezone is Asia/Bahrain

if timedatectl 2>/dev/null | grep -q 'Asia/Bahrain'; then
    echo "✔ System timezone is set to Asia/Bahrain"
else
    echo "✘ System timezone is NOT set to Asia/Bahrain"
fi