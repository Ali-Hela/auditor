# Auditor

Comprehensive cPanel/WHM server **security audit** and **guided remediation** tool.

Auditor checks a server against a complete, sectioned security checklist, prints
a colorized report with a security score, and (optionally) walks you through
applying the recommended fixes.

> **v2** is a ground-up rebuild in Python (stdlib only — no `pip install`).
> The first checklist it implements end-to-end is the official
> [cPanel Security Checklist for Sysadmins](https://www.cpanel.net/blog/security/cpanel-security-checklist-for-sysadmins/).

## Highlights

- **Read-only by default.** A plain `./auditor.sh` never changes anything.
- **Opt-in guided fixes** with `--fix` — and prompts you can skip wholesale
  (`--yes`) or one-by-one (answer `A` to skip the rest, `q` to stop fixing).
- **44 checks across 10 categories**, each mapped to a cPanel checklist section.
- **Colorized terminal output** (`✔ ✘ ▲ 🛈`) plus a clean, structured **log file**.
- **Severity-ranked summary** with a security score and a "top items to address" list.
- **Modular** — adding a check is one decorated function; no wiring required.
- **Zero dependencies** — runs on the stock Python 3.6+ found on cPanel hosts.

## Installation

```bash
git clone https://github.com/Ali-Hela/auditor.git
cd auditor
```

## Usage

```bash
# Read-only audit (default)
sudo ./auditor.sh

# Guided remediation: prompt before each fix
sudo ./auditor.sh --fix

# Apply every recommended fix without prompting
sudo ./auditor.sh --fix --yes

# Only show problems on screen (still logged in full)
sudo ./auditor.sh --quiet

# Run a single category or specific checks
sudo ./auditor.sh --category "SSL"
sudo ./auditor.sh --only LOGIN-2FA,FW-CSF

# List every check, or pick a log location
./auditor.sh --list
sudo ./auditor.sh --log /var/log/auditor.log
```

You can also invoke the package directly: `sudo python3 -m auditor [options]`.

### During `--fix`

For each failing check that has an automatable fix you'll be asked:

```
? Apply fix? Enable cPHulk [y]es/[n]o/[A]ll-skip/[q]uit:
```

- `y` apply this fix · `n` skip it · `A` skip all remaining fixes · `q` stop fixing
- Checks that can only be fixed by hand print a `(manual)` step instead of prompting.

## What it checks (cPanel checklist coverage)

| # | Category | Checks |
|---|----------|--------|
| 1 | Login & Access | 2FA policy, root SSH login, cPHulk, password strength, IP restriction |
| 2 | Firewall & WAF | CSF installed, CSF not in testing, lfd running, ModSecurity, OWASP CRS, open ports |
| 3 | SSL / TLS | AutoSSL, Require SSL for services, deprecated TLS, cipher suites |
| 4 | Accounts & Permissions | CloudLinux, CageFS, shell access, FileProtect |
| 5 | Backups & Recovery | Backups enabled, incremental, remote destination, restore testing |
| 6 | Database & PHP | MySQL exposure, SHOW DATABASES, DB passwords, expose_php, allow_url_fopen, dangerous functions, open_basedir |
| 7 | Intrusion Detection & Logs | Brute-force detection, security notifications, log monitoring |
| 8 | Updates & Patching | Auto cPanel updates, version & tier, RPM updates, CMS/plugin updates |
| 9 | DDoS & Network | Imunify360, mod_evasive, edge WAF/CDN |
| 10 | Audits & Best Practices | Security Advisor, periodic audits, training, security advisories |

Run `./auditor.sh --list` for the full per-check breakdown.

## Output example

```
  LOGIN & ACCESS
  ──────────────
  ✘ cPHulk brute-force protection is disabled  [HIGH]
      cPHulk blocks repeated failed logins to cPanel/WHM/SSH.
      → (fix) Enable cPHulk
  ✔ Minimum password strength is 65
  🛈 Restrict admin access by IP
      Limit WHM/SSH access to trusted IPs ...

================================================================
  SUMMARY
================================================================
  ✔ 9 OK   ✘ 7 fail   ▲ 9 warn   🛈 11 info   – 5 skip
  Security score: 36%  (9/25 passing checks)
```

Exit code is `0` when no checks fail and `1` when at least one `✘` remains —
handy for cron/monitoring.

## Architecture

```
auditor.sh                 # launcher -> python3 -m auditor
auditor/
  __main__.py              # CLI
  core/
    model.py               # Status / Severity / Finding / Remediation
    registry.py            # @register decorator + check ordering
    util.py                # shell + cPanel helpers (whmapi1, configs, ports…)
    report.py              # colorized terminal + log file
    remediate.py           # interactive fix engine (skip / skip-all / quit)
  checks/                  # one module per checklist section
    login.py firewall.py ssl.py accounts.py backups.py
    database_php.py intrusion.py updates.py ddos.py audits.py
```

### Adding a check

```python
from ..core.model import Finding, Remediation, Severity, Status
from ..core.registry import register

@register("MY-CHECK", "Short title", "Category Name", order=10)
def my_check():
    if not condition_ok():
        yield Finding("MY-CHECK", "Human-readable problem", Status.FAIL,
                      "Why it matters.", Severity.HIGH,
                      Remediation("What the fix does",
                                  commands=["whmapi1 set_something value=1"],
                                  manual="WHM > ... (fallback instructions)"))
    else:
        yield Finding("MY-CHECK", "All good", Status.OK)
```

Drop the function in a `checks/*.py` module — it registers itself.

## Requirements

- Root / sudo (most checks read privileged config).
- Python 3.6+ (already present on cPanel/CloudLinux hosts).
- Standard Linux utilities (`ss`/`netstat`, `httpd`, `systemctl`, `whmapi1` when on cPanel).

## Best practices

1. Run regularly (cron daily/weekly) and watch the trend in the log.
2. Review `--fix` changes; keep a backup before bulk-applying.
3. Address `✘` (fail) items first, then `▲` (warnings).
4. Re-run after fixing to confirm the score improved.

## License

Provided as-is for system administrators managing cPanel/WHM servers.
