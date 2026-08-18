# Auditor

cPanel/WHM server **security audit** and **guided remediation** tool.

Auditor checks a server against a sectioned security checklist, prints a
colorized report with a security score, and (optionally) walks you through
applying the recommended fixes.

> **v2** is a ground-up rebuild in Python (stdlib only — no `pip install`).
> The checklist it implements end-to-end is the official
> [cPanel Security Checklist for Sysadmins](https://www.cpanel.net/blog/security/cpanel-security-checklist-for-sysadmins/).

## Highlights

- **Read-only by default.** A plain `./auditor.sh` never changes anything.
- **Fixes that prove they worked.** After a fix runs, the owning check is
  re-executed against the files as they now are on disk. A fix is only counted
  as applied if the check stops failing.
- **Backups before edits**, and **risk gating** — fixes that can lock you out
  of the server are withheld unless you pass `--dangerous`, and always prompt.
- **51 checks across 10 categories**, each mapped to a checklist section.
- **Machine-readable output** with `--json`, for cron and monitoring.
- **Colorized terminal output** (`✔ ✘ ▲ 🛈`) plus an appended log file.
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

# Apply every non-risky fix without prompting
sudo ./auditor.sh --fix --yes

# Also offer the fixes that can lock you out (still prompts for each)
sudo ./auditor.sh --fix --dangerous

# Only show problems on screen (still logged in full)
sudo ./auditor.sh --quiet

# Run a single category or specific checks
sudo ./auditor.sh --category "SSL"
sudo ./auditor.sh --only LOGIN-2FA,FW-CSF

# Machine-readable report
sudo ./auditor.sh --json /var/log/auditor.json
sudo ./auditor.sh --json -            # to stdout, silences the normal report

# List every check or category, or pick a log location
./auditor.sh --list
./auditor.sh --list-categories
sudo ./auditor.sh --log /var/log/auditor.log
```

You can also invoke the package directly: `sudo python3 -m auditor [options]`.

Colour follows the terminal, and honours [`NO_COLOR`](https://no-color.org/);
`--color` / `--no-color` override both.

### During `--fix`

For each failing check with an automatable fix you'll be asked:

```
? Apply fix? Enable cPHulk [y]es/[n]o/[s]kip-all/[q]uit:
```

- `y` apply this fix · `n` skip it · `s` skip all remaining · `q` stop fixing
- Checks that can only be fixed by hand print a `(manual)` step instead of prompting.
- Answering EOF (a piped stdin) is treated as `q`, so a non-interactive
  `--fix` never applies anything by accident.

**How a fix is applied.** Files listed by the fix are copied to
`<path>.auditor-bak-<timestamp>` first. The fix runs. Then the check that
produced the finding is re-run with every cached read invalidated, and the
result decides what you're told:

| Re-run result | Reported as |
|---|---|
| Check now passes | `Applied and verified.` — the summary count is updated |
| Check still fails | `Fix ran but the check still reports FAIL` — counted as failed |
| Check can't be re-run | `Applied (not verified).` |

This exists because config edits fail quietly. `sed -ri 's/^UPDATES=.*/UPDATES=daily/'`
exits `0` without changing anything when the key isn't in the file, so exit
status alone is not evidence that a fix worked.

**Risky fixes.** Anything that changes how you reach the server — `sshd`
directives, bringing a firewall out of testing mode — is marked risky. Risky
fixes are withheld entirely unless you pass `--dangerous`, are never swept up
by `--yes`, and print what could go wrong before asking. Where a config change
needs a daemon reload to take effect, Auditor performs it (guarded by
`sshd -t`, so a bad edit can't leave sshd unable to start) rather than
reporting a green check against a daemon still running the old config.

## What it checks

| # | Category | n | Checks |
|---|----------|---|--------|
| 1 | Login & Access | 7 | 2FA policy, root SSH login, SSH password auth, cPHulk, password strength, IP-restricted admin access, root authorized_keys |
| 2 | Firewall & WAF | 6 | CSF installed, CSF not in testing, lfd running, ModSecurity, OWASP CRS, unexpected open ports |
| 3 | SSL / TLS | 4 | AutoSSL, Require SSL for services, deprecated TLS protocols, weak cipher suites |
| 4 | Accounts & Permissions | 6 | CloudLinux, CageFS, shell access, FileProtect, `/tmp` noexec/nosuid, compiler access |
| 5 | Backups & Recovery | 4 | backups enabled, incremental, remote destination, restore testing |
| 6 | Database & PHP | 8 | MySQL exposure, SHOW DATABASES, passwordless DB users, end-of-life PHP, `expose_php`, `allow_url_fopen`, `allow_url_include`, dangerous functions |
| 7 | Intrusion Detection & Logs | 4 | brute-force detection, security notifications, security logs present, log monitoring |
| 8 | Updates & Patching | 4 | auto cPanel updates, version & tier, pending OS packages, CMS/plugin updates |
| 9 | DDoS & Network | 4 | Imunify360, mod_evasive, CSF flood settings, edge WAF/CDN |
| 10 | Audits & Best Practices | 4 | Security Advisor, periodic audits, staff awareness, security advisories |

Run `./auditor.sh --list` for the full per-check breakdown with IDs.

### Statuses

| | Meaning | Counts toward the score |
|---|---|---|
| `✔ OK` | The check passed | yes |
| `✘ FAIL` | A real problem, severity-ranked | yes |
| `▲ WARN` | Not ideal, or a state that needs a human decision | yes |
| `🛈 INFO` | Advice, or context with no pass/fail answer | no |
| `– SKIP` | Not applicable, or the answer could not be determined | no |

A check that cannot determine the answer reports `SKIP`, never `FAIL`. An
absent `httpd`, an unreadable `sshd_config` or a `whmapi1` call that fails
because you aren't root is missing information, not a finding.

## Output example

```
  LOGIN & ACCESS
  ──────────────
  ✘ cPHulk brute-force protection is disabled  [HIGH]
      cPHulk blocks repeated failed logins to cPanel/WHM/SSH.
      → (fix) Enable cPHulk
  ✘ Direct root SSH login is permitted  [HIGH]
      PermitRootLogin is 'yes'. Use a sudo-enabled account instead.
      → (risky fix) Set PermitRootLogin to prohibit-password and reload sshd
  ✔ Minimum password strength is 65

================================================================
  SUMMARY
================================================================
  ✔ 13 OK   ✘ 2 fail   ▲ 12 warn   🛈 12 info   – 12 skip
  Security score: 48%  (13/27 passing checks)
```

Exit codes: `0` clean · `1` at least one `✘` remains · `2` not root ·
`3` bad arguments. After `--fix`, the code reflects the server as it is
*after* verified fixes.

### Cron

```cron
30 4 * * * /opt/auditor/auditor.sh --quiet --json /var/log/auditor.json \
             --log /var/log/auditor.log || mail -s "auditor: findings on $(hostname)" you@example.com < /var/log/auditor.json
```

The log is appended, not truncated, so the trend is visible over time
(`--log-truncate` restores the old behaviour).

## Architecture

```
auditor.sh                 # launcher -> python3 -m auditor
auditor/
  __main__.py              # CLI
  core/
    model.py               # Status / Severity / Finding / Remediation
    registry.py            # @register decorator + check ordering
    util.py                # shell + cPanel helpers (whmapi1, configs, ports…)
    report.py              # colorized terminal, log file, JSON
    remediate.py           # fix engine (backup / apply / verify / risk gate)
  checks/                  # one module per checklist section
    login.py firewall.py ssl.py accounts.py backups.py
    database_php.py intrusion.py updates.py ddos.py audits.py
tests/                     # unittest, no dependencies
```

### Adding a check

```python
from ..core.model import Finding, Remediation, Severity, Status
from ..core.registry import register

@register("MY-CHECK", "Short title", "Category Name", order=10)
def my_check():
    state = look_at_the_server()
    if state is None:
        # Could not determine != broken. Never guess a FAIL.
        yield Finding("MY-CHECK", "My check (not applicable)", Status.SKIP)
    elif state.ok:
        yield Finding("MY-CHECK", "All good", Status.OK)
    else:
        yield Finding("MY-CHECK", "Human-readable problem", Status.FAIL,
                      "Why it matters.", Severity.HIGH,
                      Remediation("What the fix does",
                                  commands=["whmapi1 set_something value=1"],
                                  backup_files=["/etc/something.conf"],
                                  manual="WHM > ... (fallback instructions)"))
```

Drop the function in a `checks/*.py` module — it registers itself. Two rules
the fix engine depends on:

- **Yield your own check ID.** Verification re-runs the check and matches the
  result by ID.
- **Prefer `func=` over a `sed` command** for config edits, using
  `core.util.set_config_line`, which appends the key when it is absent instead
  of silently doing nothing.

### Tests

```bash
python3 -m unittest discover -s tests -v
python3 -m pyflakes auditor tests
```

The parsers (`ss`, `netstat`, `sshd -T`, `php.ini`, `csf.conf`) are tested
against captured real-world output, because a misparse there becomes a false
FAIL on somebody's production server.

## Requirements

- Root / sudo (most checks read privileged config).
- Python 3.6+ (already present on cPanel/CloudLinux hosts).
- Standard Linux utilities (`ss`/`netstat`, `httpd`, `systemctl`, `mysql`,
  `whmapi1` when on cPanel). Anything missing turns its checks into `SKIP`.

## Best practices

1. Run regularly (cron daily/weekly) and watch the trend in the log.
2. Read every `--fix` prompt. Backups land beside the edited file as
   `*.auditor-bak-*`.
3. Address `✘` (fail) items first, then `▲` (warnings).
4. Re-run after fixing to confirm the score improved.

## License

Not yet chosen — all rights reserved by default until a `LICENSE` file is added.
