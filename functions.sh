ok() {
    echo "✔ $*"
}
error() {
    echo "✘ $*"
}
warn() {
    echo "▲ $*"
}
info() {
    echo "🛈 $*"
}

install_fail2ban() {
    info "Installing Fail2ban..."
    if command -v yum &> /dev/null; then
        yum install -y epel-release
        yum install -y fail2ban
    elif command -v apt &> /dev/null; then
        apt update
        apt install -y fail2ban
    else
        error "Unsupported package manager for Fail2ban installation."
        return 1
    fi
    
    systemctl enable fail2ban
    systemctl start fail2ban
    
    if systemctl is-active --quiet fail2ban; then
        ok "Fail2ban installed and started successfully."
        return 0
    else
        error "Fail2ban installation failed."
        return 1
    fi
}

enable_2fa_whm() {
    info "Enabling 2FA in WHM..."
    whmapi1 twofactorauth_policy_set policy=1
    if whmapi1 twofactorauth_policy_status | grep -q 'is_enabled: 1'; then
        ok "2FA enabled successfully in WHM."
        return 0
    else
        error "Failed to enable 2FA in WHM."
        return 1
    fi
}

install_mod_evasive() {
    info "Installing mod_evasive..."
    if command -v yum &> /dev/null; then
        yum install -y mod_evasive
    elif command -v apt &> /dev/null; then
        apt update
        apt install -y libapache2-mod-evasive
        a2enmod evasive
    else
        error "Unsupported package manager for mod_evasive installation."
        return 1
    fi
    
    systemctl reload httpd || systemctl reload apache2
    
    if apachectl -M | grep -q 'evasive'; then
        ok "mod_evasive installed and enabled successfully."
        return 0
    else
        error "mod_evasive installation failed."
        return 1
    fi
}

disable_root_ssh() {
    info "Disabling root SSH login..."
    cp /etc/ssh/sshd_config /etc/ssh/sshd_config.backup.$(date +%Y%m%d_%H%M%S)
    sed -i 's/^#*PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config
    systemctl reload sshd
    
    if grep -q '^PermitRootLogin no' /etc/ssh/sshd_config; then
        ok "Root SSH login disabled successfully."
        return 0
    else
        error "Failed to disable root SSH login."
        return 1
    fi
}

install_security_updates() {
    info "Installing security updates..."
    if command -v yum &> /dev/null; then
        yum update -y --security
        ok "Security updates installed successfully."
        return 0
    else
        error "Security updates installation not supported on this system."
        return 1
    fi
}

start_cphulk() {
    info "Starting cPHulk service..."
    systemctl enable cphulkd
    systemctl start cphulkd
    
    if systemctl is-active --quiet cphulkd; then
        ok "cPHulk service started successfully."
        return 0
    else
        error "Failed to start cPHulk service."
        return 1
    fi
}

setup_root_login_notification() {
    info "Setting up root login notification..."
    read -p "Enter email address for notifications: " email
    if [ -n "$email" ]; then
        echo 'echo "ALERT - Root Shell Access on:" `date` `who` | mail -s "Alert: Root Access from `who | cut -d\( -f2 | cut -d\) -f1`" '$email >> ~/.bashrc
        echo 'echo "Root login: $(date)" >> /var/log/rootlogins' >> ~/.bashrc
        ok "Root login notification set up for: $email"
        return 0
    else
        error "No email provided for root login notification."
        return 1
    fi
}

set_timezone_bahrain() {
    info "Setting timezone to Asia/Bahrain..."
    timedatectl set-timezone Asia/Bahrain
    
    if timedatectl 2>/dev/null | grep -q 'Asia/Bahrain'; then
        ok "Timezone set to Asia/Bahrain successfully."
        return 0
    else
        error "Failed to set timezone to Asia/Bahrain."
        return 1
    fi
}
