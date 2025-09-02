#!/bin/bash
. "$(dirname "$0")/../functions.sh"

# Parse --prompts flag
parse_prompts_flag "$@"

# Check if MySQL (not MariaDB) is installed
if mysql --version 2>/dev/null | grep -qi 'mysql' && ! mysql --version 2>/dev/null | grep -qi 'mariadb'; then
    ok "MySQL is installed: $(mysql --version)"
else
    error "MySQL is not installed or MariaDB is present instead: $(mysql --version 2>/dev/null)"
    if [ "$PROMPTS" -eq 1 ]; then
        info "Database system change requires manual intervention. Consider MySQL vs MariaDB requirements."
    fi
fi