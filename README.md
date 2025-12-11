# Auditor
Comprehensive cPanel/WHM server security and configuration auditing tool

## Features
- **60+ security checkpoints** covering all aspects of WHM server management
- Modular checkpoint system for easy maintenance and extensibility
- Colorized output with clear status indicators (✔ OK, ✘ Error, ▲ Warning, 🛈 Info)
- Automated fix prompts with `--prompts` flag
- Comprehensive logging to track audit history
- Resource and performance monitoring
- Proactive security scanning

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

## Comprehensive Security Checkpoints

### Core Security
- **Two-Factor Authentication (2FA)** - WHM 2FA policy enforcement
- **CSF Firewall** - ConfigServer Security & Firewall installation, configuration, and rule validation
- **Fail2ban** - Installation, active jails, banned IPs, and service monitoring
- **SSH Security** - Root login, password authentication, protocol version, port configuration
- **Root Login Notifications** - Alert system for root access
- **cPHulk** - Brute force protection service
- **Security Updates** - System update status and available patches
- **System Security** - SUID files, world-writable files, password policies, failed logins

### Server Configuration
- **Apache/Web Server** - ServerTokens, ServerSignature, ModSecurity, TraceEnable, directory indexing
- **PHP Security** - Version checks, dangerous functions, allow_url_include, expose_php, display_errors
- **MySQL/MariaDB** - Database presence, root remote access restrictions
- **Hostname** - FQDN compatibility and DNS resolution
- **System Time/Timezone** - Timezone configuration verification
- **CloudLinux** - CloudLinux installation check

### WHM/cPanel Specific
- **WHM Configuration** - License status, update tier, account management
- **cPanel Services** - Service status, version information, EasyApache
- **Security Settings** - Fork bomb protection, compiler restrictions, ModSecurity
- **API Tokens** - Token usage monitoring
- **Account Auditing** - Suspended accounts, password age, demo accounts
- **Tweak Settings** - Security-related tweak validation

### Email Security
- **Exim Mail Server** - Service status, queue size, frozen emails
- **SPF Records** - Sender Policy Framework validation
- **DKIM** - DomainKeys Identified Mail configuration
- **DMARC** - Domain-based Message Authentication
- **Email Authentication** - SMTP authentication requirements
- **RBL/Spam Protection** - Blacklist checking configuration
- **Mail Bombing Detection** - High-volume sender identification

### SSL/TLS Security
- **SSL Certificates** - Certificate existence and expiry monitoring
- **AutoSSL** - Automatic SSL renewal configuration
- **TLS Protocols** - TLS 1.2+ enforcement, deprecated protocol detection
- **SSL Cipher Suites** - Strong cipher configuration
- **HSTS** - HTTP Strict Transport Security headers
- **Certificate Validation** - Self-signed certificate detection

### Resource Monitoring
- **Disk Usage** - Root and /home partition monitoring
- **Inode Usage** - File system inode tracking
- **Memory Usage** - RAM and swap utilization
- **Load Average** - CPU load per core monitoring
- **Large Files** - /tmp directory analysis
- **User Disk Usage** - Top space consumers
- **Database Sizes** - MySQL/MariaDB storage analysis

### Backup Management
- **Backup Configuration** - cPanel backup system validation
- **Backup Freshness** - Last backup date verification
- **Backup Storage** - Disk space monitoring
- **Remote Destinations** - Offsite backup configuration
- **Database Backups** - MySQL backup file verification
- **Retention Policies** - Backup rotation checking

### Network & DNS
- **Internet Connectivity** - Basic connectivity tests
- **DNS Resolution** - Nameserver functionality
- **Forward DNS** - A record validation
- **Reverse DNS** - PTR record checking
- **Port Scanning** - Expected service port verification
- **Firewall Status** - CSF/firewalld/UFW detection
- **Database Exposure** - Public MySQL/PostgreSQL/Redis/MongoDB detection
- **DDoS Protection** - cPHulk and rate limiting

### FTP Security
- **FTP Service Status** - Pure-FTPd/ProFTPD/vsftpd detection
- **FTP over TLS** - Encryption requirement checking
- **Anonymous FTP** - Anonymous access validation
- **FTP Chroot** - User directory restriction
- **Connection Limits** - Rate limiting configuration
- **Brute Force Detection** - Failed login monitoring

### CMS Security (WordPress, Joomla, Drupal)
- **WordPress Detection** - Installation discovery
- **File Permissions** - wp-config.php and uploads directory
- **Security Keys** - WordPress salt validation
- **Debug Mode** - Production debug settings
- **Malware Scanning** - Common malware file detection
- **Version Checking** - Outdated CMS detection
- **Plugin Analysis** - Outdated plugin identification
- **Admin Accounts** - Suspicious user detection

### Additional Checks
- **CSE** - ConfigServer eXploit Scanner
- **mod_evasive** - Apache DDoS protection module
- **User Accounts** - Sudo/wheel group privileges
- **Kernel Updates** - Available kernel updates and reboot requirements
- **SELinux** - Security-Enhanced Linux status
- **Cron Jobs** - Suspicious scheduled task detection
- **Log Analysis** - System error and security log review

## Output Examples

```
✔ 2FA is enabled in WHM
✔ Apache is running
✘ PHP allow_url_include should be Off - critical security risk
▲ Mail queue has 150 messages - may need attention
🛈 PHP version: PHP 8.1.2
```

## Log File

All audit results are automatically logged to `auditor.log` with timestamps for compliance and tracking purposes.

## Requirements

- Root or sudo access
- cPanel/WHM installation (optional - tool will prompt if not detected)
- Bash 4.0+
- Standard Linux utilities (grep, awk, find, etc.)

## Best Practices

1. Run auditor regularly (daily or weekly) as part of maintenance
2. Use `--prompts` mode carefully - review changes before applying
3. Keep a backup before making automated changes
4. Review the log file for trending issues
5. Address ✘ errors immediately, ▲ warnings when possible

## Contributing

Contributions are welcome! Please feel free to submit pull requests or open issues for:
- Additional security checks
- Bug fixes
- Documentation improvements
- New automated fix functions

## License

This project is provided as-is for system administrators managing cPanel/WHM servers.
