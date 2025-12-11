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

# Check WordPress installations
info "Scanning for WordPress installations..."
wp_count=$(find /home -name wp-config.php 2>/dev/null | wc -l)

if [ "$wp_count" -eq 0 ]; then
    exit 0
fi

info "Found $wp_count WordPress installations"

# Check for critical security issues only
critical_issues=0

find /home -name wp-config.php 2>/dev/null | head -10 | while read wp_config; do
    wp_dir=$(dirname "$wp_config")
    
    # Check wp-config.php permissions (critical)
    config_perms=$(stat -c %a "$wp_config" 2>/dev/null)
    if [ "$config_perms" != "600" ] && [ "$config_perms" != "640" ] && [ "$config_perms" != "400" ]; then
        warn "wp-config.php has insecure permissions ($config_perms) at $wp_config"
    fi
    
    # Check for debug mode in production
    if grep -q "WP_DEBUG.*true" "$wp_config"; then
        warn "WP_DEBUG is enabled at $wp_config - disable in production"
    fi
done

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
