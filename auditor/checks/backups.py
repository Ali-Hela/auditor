"""Section 5 - Regular backups and disaster recovery."""

import glob
import os

from ..core.model import Finding, Remediation, Severity, Status
from ..core.registry import register
from ..core.util import is_cpanel, parse_kv, read_file, truthy, whmapi1

CAT = "Backups & Recovery"
REF = "cPanel checklist #5: Regular backups and disaster recovery"
BACKUP_CONF = "/var/cpanel/backups/config"


def _backup_cfg():
    """Backup config from the WHM API, falling back to the on-disk file.

    Returns (config_dict, source) where source is 'api', 'file' or None.
    Keys are normalised to lowercase (the API's get_normalized_config does this;
    the on-disk file uses uppercase, so we lower it for a single code path).
    """
    data = whmapi1("backup_config_get")
    if data and data.get("data", {}).get("backup_config"):
        return data["data"]["backup_config"], "api"
    text = read_file(BACKUP_CONF)
    if text:
        return {k.lower(): v for k, v in parse_kv(text).items()}, "file"
    return {}, None


@register("BAK-ENABLED", "Backups enabled", CAT, order=10)
def backups_enabled():
    if not is_cpanel():
        yield Finding("BAK-ENABLED", "Backups (cPanel only)", Status.SKIP,
                      "Not a cPanel server.", reference=REF)
        return
    cfg, source = _backup_cfg()
    if source is None:
        yield Finding("BAK-ENABLED", "Backup status could not be determined",
                      Status.WARN,
                      "whmapi1 backup_config_get failed and the config file "
                      "was unreadable (run as root?).", Severity.MEDIUM,
                      Remediation("Verify backups are enabled",
                                  manual="WHM > Backup > Backup Configuration."),
                      reference=REF)
        return
    if truthy(cfg.get("backupenable")):
        yield Finding("BAK-ENABLED", "cPanel backups are enabled", Status.OK,
                      reference=REF)
    else:
        yield Finding("BAK-ENABLED", "cPanel backups are disabled", Status.FAIL,
                      "backupenable is not set.", Severity.HIGH,
                      Remediation("Enable automated backups",
                                  manual="WHM > Backup > Backup Configuration > "
                                         "Enable Backups."),
                      reference=REF)


@register("BAK-INCREMENTAL", "Incremental backups", CAT, order=20)
def incremental():
    if not is_cpanel():
        yield Finding("BAK-INCREMENTAL", "Incremental backups (cPanel only)",
                      Status.SKIP, reference=REF)
        return
    cfg, source = _backup_cfg()
    if source is None:
        yield Finding("BAK-INCREMENTAL", "Incremental backups (status unknown)",
                      Status.SKIP, reference=REF)
        return
    if cfg.get("backuptype") == "incremental" or truthy(cfg.get("backupinc")):
        yield Finding("BAK-INCREMENTAL", "Incremental backups are enabled",
                      Status.OK, reference=REF)
    else:
        yield Finding("BAK-INCREMENTAL", "Incremental backups are not enabled",
                      Status.INFO,
                      "Incremental backups save space while keeping recent state.",
                      Severity.LOW,
                      Remediation("Enable incremental backups",
                                  manual="WHM > Backup > Backup Configuration > "
                                         "Type: Incremental."),
                      reference=REF)


@register("BAK-REMOTE", "Remote backup destination", CAT, order=30)
def remote_dest():
    if not is_cpanel():
        yield Finding("BAK-REMOTE", "Remote backups (cPanel only)", Status.SKIP,
                      reference=REF)
        return
    active = []
    data = whmapi1("backup_destination_list")
    if data is not None:
        for dest in data.get("data", {}).get("destination_list", []):
            if not truthy(dest.get("disabled")):
                active.append(dest.get("name") or dest.get("type") or "destination")
    else:
        # fall back to on-disk destination files
        for path in glob.glob("/var/cpanel/backups/*.backup_destination"):
            cfg = parse_kv(read_file(path))
            if not truthy(cfg.get("disabled")):
                active.append(cfg.get("name") or os.path.basename(path))
    if active:
        yield Finding("BAK-REMOTE",
                      "Remote backup destination configured: %s"
                      % ", ".join(active), Status.OK, reference=REF)
    else:
        yield Finding("BAK-REMOTE", "No remote backup destination configured",
                      Status.WARN,
                      "Offsite copies survive a full server compromise or loss.",
                      Severity.MEDIUM,
                      Remediation("Add a remote backup destination",
                                  manual="WHM > Backup > Backup Configuration > "
                                         "Additional Destinations."),
                      reference=REF)


@register("BAK-TEST", "Backup restore testing", CAT, order=40)
def test_backups():
    yield Finding("BAK-TEST", "Periodically test backup restores", Status.INFO,
                  "Backups are only useful if they restore. Restore to a test "
                  "environment on a schedule.", Severity.INFO,
                  Remediation("Schedule restore drills",
                              manual="WHM > Backup > Backup Restoration "
                                     "(test in a sandbox)."),
                  reference=REF)
