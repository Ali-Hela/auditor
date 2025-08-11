# Check if certbot (Let's Encrypt client) is installed
if ! command -v certbot >/dev/null 2>&1; then
    echo "✖ certbot (Let's Encrypt client) is not installed."
    exit 1
fi

# Check if any Let's Encrypt certificates exist
if [ -d /etc/letsencrypt/live ] && [ "$(ls -A /etc/letsencrypt/live)" ]; then
    echo "✔ Let's Encrypt certificates are present. AutoSSL appears to be enabled."
else
    echo "✖ No Let's Encrypt certificates found. AutoSSL does not appear to be enabled."
fi

# Check AutoSSL status using WHM API
if command -v whmapi1 >/dev/null 2>&1; then
    status=$(whmapi1 get_autossl_metadata | grep -i 'enabled:' | awk '{print $2}')
    if [ "$status" = "1" ]; then
        echo "✔ AutoSSL is enabled (WHM)."
    else
        echo "✖ AutoSSL is not enabled (WHM)."
    fi
else
    echo "✖ whmapi1 command not found. Cannot check AutoSSL status via WHM API."
fi
