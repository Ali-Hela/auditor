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

# Check if backup is configured in WHM
if [ -d "/usr/local/cpanel" ]; then
    # Check backup configuration
    if [ -f /var/cpanel/backups/config ]; then
        # Check if backups are enabled
        if grep -q "BACKUPENABLE='yes'" /var/cpanel/backups/config 2>/dev/null; then
            ok "cPanel backups are enabled"
        else
            error "cPanel backups are NOT enabled"
        fi
    else
        error "cPanel backup configuration not found - configure in WHM"
    fi
    
    # Check for backup destinations (remote backups)
    if [ -f /var/cpanel/backups/config ]; then
        backup_destinations=$(grep "BACKUP.*DEST" /var/cpanel/backups/config 2>/dev/null | grep -v "^#" | wc -l)
        if [ "$backup_destinations" -gt 0 ]; then
            ok "Remote backup destinations configured: $backup_destinations"
        else
            warn "No remote backup destinations - consider offsite backups"
        fi
    fi
else
    info "Not a cPanel server - skipping cPanel backup checks"
fi
