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

# Check disk usage
disk_usage=$(df -h / | tail -1 | awk '{print $5}' | sed 's/%//')
if [ "$disk_usage" -lt 80 ]; then
    ok "Root partition usage: ${disk_usage}%"
elif [ "$disk_usage" -lt 90 ]; then
    warn "Root partition usage: ${disk_usage}% - monitor closely"
else
    error "Root partition usage: ${disk_usage}% - critical!"
fi

# Check /home partition usage (where user data lives)
if df -h /home &> /dev/null; then
    home_usage=$(df -h /home | tail -1 | awk '{print $5}' | sed 's/%//')
    if [ "$home_usage" -lt 80 ]; then
        ok "/home partition usage: ${home_usage}%"
    elif [ "$home_usage" -lt 90 ]; then
        warn "/home partition usage: ${home_usage}% - monitor closely"
    else
        error "/home partition usage: ${home_usage}% - critical!"
    fi
fi

# Check inode usage
inode_usage=$(df -i / | tail -1 | awk '{print $5}' | sed 's/%//')
if [ "$inode_usage" -lt 80 ]; then
    ok "Inode usage: ${inode_usage}%"
elif [ "$inode_usage" -lt 90 ]; then
    warn "Inode usage: ${inode_usage}% - many small files"
else
    error "Inode usage: ${inode_usage}% - critical!"
fi

# Check memory usage
total_mem=$(free -h | grep Mem | awk '{print $2}')
used_mem=$(free -h | grep Mem | awk '{print $3}')
mem_percent=$(free | grep Mem | awk '{printf "%.0f", $3/$2 * 100}')

if [ "$mem_percent" -lt 80 ]; then
    ok "Memory usage: ${mem_percent}% (${used_mem}/${total_mem})"
elif [ "$mem_percent" -lt 90 ]; then
    warn "Memory usage: ${mem_percent}% (${used_mem}/${total_mem}) - monitor closely"
else
    error "Memory usage: ${mem_percent}% (${used_mem}/${total_mem}) - critical!"
fi

# Check swap usage
if free -h | grep -q Swap; then
    swap_total=$(free -h | grep Swap | awk '{print $2}')
    swap_used=$(free -h | grep Swap | awk '{print $3}')
    swap_percent=$(free | grep Swap | awk '{if ($2 > 0) printf "%.0f", $3/$2 * 100; else print "0"}')
    
    if [ "$swap_percent" -eq 0 ]; then
        ok "Swap usage: 0% (good)"
    elif [ "$swap_percent" -lt 50 ]; then
        info "Swap usage: ${swap_percent}% (${swap_used}/${swap_total})"
    else
        warn "Swap usage: ${swap_percent}% (${swap_used}/${swap_total}) - system may be under memory pressure"
    fi
fi

# Check load average
load_avg=$(uptime | awk -F'load average:' '{print $2}' | awk '{print $1}' | sed 's/,//')
cpu_count=$(nproc)
load_per_cpu=$(echo "$load_avg $cpu_count" | awk '{printf "%.2f", $1/$2}')

if (( $(echo "$load_per_cpu < 0.7" | bc -l) )); then
    ok "Load average: $load_avg (${load_per_cpu} per CPU)"
elif (( $(echo "$load_per_cpu < 1.0" | bc -l) )); then
    warn "Load average: $load_avg (${load_per_cpu} per CPU) - monitor"
else
    error "Load average: $load_avg (${load_per_cpu} per CPU) - high load!"
fi

# Check for large files in /tmp
large_tmp_files=$(find /tmp -type f -size +100M 2>/dev/null | wc -l)
if [ "$large_tmp_files" -gt 0 ]; then
    warn "Found $large_tmp_files large files (>100MB) in /tmp"
else
    ok "No unusually large files in /tmp"
fi

# Check largest directories in /home
info "Top 5 largest user directories:"
du -sh /home/* 2>/dev/null | sort -rh | head -5 | while read size dir; do
    echo "  $size - $(basename $dir)"
done

# Check for suspended accounts
if [ -d "/var/cpanel" ]; then
    suspended_count=$(ls -la /var/cpanel/suspended/ 2>/dev/null | grep -c "^-")
    if [ "$suspended_count" -gt 0 ]; then
        info "Suspended cPanel accounts: $suspended_count"
    fi
fi

# Check database sizes
if command -v mysql &> /dev/null; then
    db_size=$(mysql -e "SELECT ROUND(SUM(data_length + index_length) / 1024 / 1024, 2) AS 'Size (MB)' FROM information_schema.TABLES;" 2>/dev/null | tail -1)
    if [ -n "$db_size" ]; then
        info "Total database size: ${db_size} MB"
    fi
fi
