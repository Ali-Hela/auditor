#!/bin/bash
# Check if MySQL (not MariaDB) is installed

if mysql --version 2>/dev/null | grep -qi 'mysql' && ! mysql --version 2>/dev/null | grep -qi 'mariadb'; then
    echo "✔ MySQL is installed (MariaDB is not present)"
else
    echo "✘ MySQL is not installed or MariaDB is present"
fi