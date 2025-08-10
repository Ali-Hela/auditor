#!/bin/bash

CHECKPOINTS_DIR="$(dirname "$0")/checkpoints"
LOG_FILE="$(dirname "$0")/auditor.log"

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color
BOLD='\033[1m'
RESET_BOLD='\033[22m'

colorize_output() {
    while IFS= read -r line; do
        if [[ "$line" =~ ^✔ ]]; then
            symbol="${line:0:1}"
            message="${line:1}"
            echo -e "${GREEN}${symbol}${BOLD}${message}${RESET_BOLD}${NC}"
        elif [[ "$line" =~ ^✘ ]]; then
            symbol="${line:0:1}"
            message="${line:1}"
            echo -e "${RED}${symbol}${BOLD}${message}${RESET_BOLD}${NC}"
        elif [[ "$line" =~ ^▲ ]]; then
            symbol="${line:0:1}"
            message="${line:1}"
            echo -e "${YELLOW}${symbol}${BOLD}${message}${RESET_BOLD}${NC}"
        elif [[ "$line" =~ ^🛈 ]]; then
            symbol="${line:0:1}"
            message="${line:1}"
            echo -e "${BLUE}${symbol}${BOLD}${message}${RESET_BOLD}${NC}"
        elif [[ "$line" =~ ^[Ee]rror|command\ not\ found ]]; then
            echo -e "${BOLD}${RED}${line}${NC}${RESET_BOLD}"
        else
            echo "$line"
        fi
    done
}

    # Check for cPanel installation
    if [ ! -d "/usr/local/cpanel" ]; then
        echo "This tool was designed for cPanel servers, and will check for configs specific to such servers."
        read -p "cPanel does not appear to be installed. Do you still want to run auditor? (y/N): " confirm
        case "$confirm" in
            [yY][eE][sS]|[yY])
                echo "Continuing without cPanel..."
                ;;
            *)
                echo "Exiting auditor."
                exit 1
                ;;
        esac
    fi

echo "Auditor started at $(date)" > "$LOG_FILE"
echo "Running checkpoints in $CHECKPOINTS_DIR..."

for checkpoint in "$CHECKPOINTS_DIR"/*.sh; do
    [ -x "$checkpoint" ] || chmod +x "$checkpoint"
    # Capture both stdout and stderr, colorize, and log
    result="$("$checkpoint" 2>&1)"
    echo "$result" | colorize_output
    echo "$result" >> "$LOG_FILE"
done

echo "Auditor finished at $(date)" >> "$LOG_FILE"
