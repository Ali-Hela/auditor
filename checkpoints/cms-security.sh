#!/bin/bash
. "$(dirname "$0")/../functions.sh"

# Parse --prompts flag
PROMPTS=0
for arg in "$@"; do
    case $arg in
        --prompts)
            PROMPTS=1
            ;;
    esac
done

# Check for WordPress installations
info "Scanning for WordPress installations..."
wp_count=$(find /home -name wp-config.php 2>/dev/null | wc -l)

if [ "$wp_count" -eq 0 ]; then
    info "No WordPress installations found"
    exit 0
fi

info "Found $wp_count WordPress installations"

# Check WordPress installations for security issues
find /home -name wp-config.php 2>/dev/null | head -20 | while read wp_config; do
    wp_dir=$(dirname "$wp_config")
    wp_user=$(stat -c %U "$wp_dir" 2>/dev/null)
    
    # Check wp-config.php permissions
    config_perms=$(stat -c %a "$wp_config" 2>/dev/null)
    if [ "$config_perms" = "600" ] || [ "$config_perms" = "640" ]; then
        ok "wp-config.php has secure permissions ($config_perms) for $wp_user"
    else
        warn "wp-config.php has insecure permissions ($config_perms) at $wp_config"
    fi
    
    # Check for security keys
    if grep -q "AUTH_KEY" "$wp_config" && ! grep -q "put your unique phrase here" "$wp_config"; then
        ok "Security keys are configured for $wp_user"
    else
        warn "WordPress security keys not properly configured at $wp_config"
    fi
    
    # Check for database credentials
    if grep -q "DB_PASSWORD" "$wp_config"; then
        db_pass=$(grep "DB_PASSWORD" "$wp_config" | cut -d"'" -f4)
        if [ ${#db_pass} -lt 8 ]; then
            warn "Weak database password detected for WordPress at $wp_dir"
        fi
    fi
    
    # Check for debug mode
    if grep -q "WP_DEBUG.*true" "$wp_config"; then
        warn "WP_DEBUG is enabled at $wp_config - should be disabled in production"
    fi
    
    # Check wp-content/uploads permissions
    if [ -d "$wp_dir/wp-content/uploads" ]; then
        uploads_perms=$(stat -c %a "$wp_dir/wp-content/uploads" 2>/dev/null)
        if [ "$uploads_perms" != "755" ] && [ "$uploads_perms" != "750" ]; then
            warn "Uploads directory has unusual permissions ($uploads_perms) at $wp_dir"
        fi
    fi
    
    # Check for .htaccess in uploads (security)
    if [ ! -f "$wp_dir/wp-content/uploads/.htaccess" ]; then
        warn "No .htaccess protection in uploads directory at $wp_dir"
    fi
    
    # Check for known vulnerable files
    if [ -f "$wp_dir/xmlrpc.php" ]; then
        info "xmlrpc.php exists at $wp_dir - consider blocking if not needed"
    fi
    
    # Check for old WordPress versions (basic check)
    if [ -f "$wp_dir/wp-includes/version.php" ]; then
        wp_version=$(grep "wp_version = " "$wp_dir/wp-includes/version.php" | cut -d"'" -f2)
        if [ -n "$wp_version" ]; then
            info "WordPress $wp_version at $wp_dir (verify it's current)"
        fi
    fi
    
done | head -50  # Limit output if many WP installations

# Check for common malware files
malware_patterns="wp-vcd.php wp-feed.php wp-tmp.php class.plugin-modules.php"
for pattern in $malware_patterns; do
    found=$(find /home -name "$pattern" 2>/dev/null | wc -l)
    if [ "$found" -gt 0 ]; then
        error "Found $found instances of suspicious file: $pattern (possible malware)"
    fi
done

# Check for suspicious admin users in WordPress databases
info "Checking for suspicious WordPress admin accounts..."
if command -v mysql &> /dev/null; then
    wp_admins=$(mysql -e "SELECT table_schema, COUNT(*) FROM information_schema.TABLES WHERE table_name = 'wp_users' GROUP BY table_schema" 2>/dev/null | tail -n +2 | wc -l)
    if [ "$wp_admins" -gt 0 ]; then
        info "Found WordPress databases with user tables - verify admin accounts manually"
    fi
fi

# Check for outdated plugins (file age check)
info "Checking for potentially outdated plugins..."
old_plugins=$(find /home -path "*/wp-content/plugins/*" -name "*.php" -mtime +365 2>/dev/null | wc -l)
if [ "$old_plugins" -gt 0 ]; then
    warn "Found $old_plugins plugin files not modified in over a year - may be outdated"
fi

# Check for other CMS installations
joomla_count=$(find /home -name "configuration.php" -path "*/administrator/components/*" 2>/dev/null | wc -l)
if [ "$joomla_count" -gt 0 ]; then
    info "Found $joomla_count Joomla installations"
fi

drupal_count=$(find /home -name "settings.php" -path "*/sites/default/*" 2>/dev/null | wc -l)
if [ "$drupal_count" -gt 0 ]; then
    info "Found $drupal_count Drupal installations"
fi
