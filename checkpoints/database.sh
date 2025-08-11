#!/bin/bash
. "$(dirname "$0")/../functions.sh"
CHECK="✔"
CROSS="✘"
# Check if MySQL (not MariaDB) is installed

if mysql --version 2>/dev/null | grep -qi 'mysql' && ! mysql --version 2>/dev/null | grep -qi 'mariadb'; then
    ok "MySQL is installed: $(mysql --version | awk '{print $5}')"
else
    error "MySQL is not installed or MariaDB is present instead: $(mysql --version 2>/dev/null | awk '{print $5}')"
fi