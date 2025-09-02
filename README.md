# Auditor
cPanel server security configurations checker

## Features
- Modular security checkpoints for cPanel servers
- Colorized output with clear status indicators
- Automated fix prompts with `--prompts` flag
- Comprehensive logging

## Installation:
```bash
git clone https://github.com/Ali-Hela/auditor.git
cd auditor
```

## Usage:

### Basic security audit:
```bash
sudo ./auditor.sh
```

### Interactive mode with automated fixes:
```bash
sudo ./auditor.sh --prompts
# or
sudo ./auditor.sh -p
```

## Security Checkpoints
The tool checks for:
- Two-Factor Authentication (2FA) in WHM
- CSF (ConfigServer Security & Firewall) installation
- Fail2ban installation and status
- mod_evasive Apache module
- Root SSH login configuration
- Security updates
- cPHulk service status
- CSE (ConfigServer eXploit Scanner)
- CloudLinux installation
- MySQL vs MariaDB presence
- Hostname FQDN compatibility
- System timezone configuration
- Root login notifications
- User account privileges

When using `--prompts`, the tool will offer to automatically fix detected issues where possible.
