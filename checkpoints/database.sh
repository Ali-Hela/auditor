#!/bin/bash
# Check if MySQL (not MariaDB) is installed

if mysql --version 2>/dev/null | grep -qi 'mysql' && ! mysql --version 2>/dev/null | grep -qi 'mariadb'; then
    echo "✔ MySQL is installed: $(mysql --version | awk '{print $5}')"
else
    echo "✘ MySQL is not installed or MariaDB is present instead: $(mysql --version 2>/dev/null | awk '{print $5}')"
fi