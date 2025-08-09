# is hostname FQDN compatible
if [ -z "$HOSTNAME" ]; then
    echo "✘ Hostname is not set: $HOSTNAME"
    exit 1
else
    if [[ ! "$HOSTNAME" =~ ^[a-zA-Z0-9]([-a-zA-Z0-9]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([-a-zA-Z0-9]*[a-zA-Z0-9])?)*$ ]]; then
        echo "✘ Hostname is not FQDN compatible: $HOSTNAME"
        exit 1
    else
        echo "✔ Hostname is FQDN compatible: $HOSTNAME"
    fi
fi