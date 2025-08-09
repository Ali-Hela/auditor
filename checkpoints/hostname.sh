# is hostname FQDN compatible
if [ -z "$HOSTNAME" ]; then
    echo "✘ Hostname is not set."
    exit 1
fi