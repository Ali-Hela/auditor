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
        ok "cPanel backup configuration exists"
        
        # Check if backups are enabled
        if grep -q "BACKUPENABLE='yes'" /var/cpanel/backups/config 2>/dev/null; then
            ok "cPanel backups are enabled"
        else
            error "cPanel backups are NOT enabled"
        fi
        
        # Check backup type
        backup_type=$(grep "BACKUPTYPE" /var/cpanel/backups/config 2>/dev/null | cut -d"'" -f2)
        if [ -n "$backup_type" ]; then
            info "Backup type: $backup_type"
        fi
    else
        warn "cPanel backup configuration not found"
    fi
    
    # Check last backup date
    if [ -d "/backup" ]; then
        last_backup=$(find /backup -type f -name "*.tar.gz" -o -name "backup-*" 2>/dev/null | head -1)
        if [ -n "$last_backup" ]; then
            last_backup_date=$(stat -c %y "$last_backup" 2>/dev/null | cut -d' ' -f1)
            days_since_backup=$(( ($(date +%s) - $(date -d "$last_backup_date" +%s 2>/dev/null || echo 0)) / 86400 ))
            
            if [ "$days_since_backup" -eq 0 ]; then
                ok "Backup found from today"
            elif [ "$days_since_backup" -le 1 ]; then
                ok "Last backup was $days_since_backup day ago"
            elif [ "$days_since_backup" -le 7 ]; then
                warn "Last backup was $days_since_backup days ago"
            else
                error "Last backup was $days_since_backup days ago - backups may not be running"
            fi
        else
            warn "No backup files found in /backup directory"
        fi
    fi
    
    # Check backup disk space
    if [ -d "/backup" ]; then
        backup_usage=$(df -h /backup 2>/dev/null | tail -1 | awk '{print $5}' | sed 's/%//')
        if [ -n "$backup_usage" ]; then
            if [ "$backup_usage" -lt 80 ]; then
                ok "Backup partition usage: ${backup_usage}%"
            elif [ "$backup_usage" -lt 90 ]; then
                warn "Backup partition usage: ${backup_usage}% - monitor space"
            else
                error "Backup partition usage: ${backup_usage}% - low space!"
            fi
        fi
    fi
else
    info "Not a cPanel server - skipping cPanel backup checks"
fi

# Check for backup destinations
if [ -f /var/cpanel/backups/config ]; then
    backup_destinations=$(grep "BACKUP.*DEST" /var/cpanel/backups/config 2>/dev/null | wc -l)
    if [ "$backup_destinations" -gt 0 ]; then
        ok "Remote backup destinations configured: $backup_destinations"
    else
        warn "No remote backup destinations - consider offsite backups"
    fi
fi

# Check if mysqldump/database backups are working
if [ -d "/backup" ]; then
    db_backups=$(find /backup -name "*.sql" -o -name "*mysql*" -type f 2>/dev/null | head -1)
    if [ -n "$db_backups" ]; then
        ok "Database backup files found"
    else
        warn "No database backup files found - verify database backups"
    fi
fi

# Check backup rotation/retention
if [ -d "/backup" ]; then
    old_backups=$(find /backup -type f -mtime +30 2>/dev/null | wc -l)
    if [ "$old_backups" -gt 10 ]; then
        warn "Found $old_backups backup files older than 30 days - verify retention policy"
    else
        info "Backup retention appears reasonable"
    fi
fi
