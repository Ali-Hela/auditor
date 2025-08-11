# check if cPHulk service is active
if systemctl is-active --quiet cphulkd; then
    echo "✔ cPHulk service is active"
else
    echo "✖ cPHulk service is not active"
fi
