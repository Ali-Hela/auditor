"""Section 8 - Keep software and plugins updated."""

from ..core.model import Finding, Remediation, Severity, Status
from ..core.registry import register
from ..core.util import (is_cpanel, parse_kv, read_file, run, set_config_line,
                         which)

CAT = "Updates & Patching"
REF = "cPanel checklist #8: Keep software and plugins updated"

CPUPDATE_CONF = "/etc/cpupdate.conf"


def _cpupdate():
    return parse_kv(read_file(CPUPDATE_CONF))


def _set_cpupdate(key, value):
    """Fix helper: cpupdate.conf keys are often absent rather than set."""
    return lambda: set_config_line(CPUPDATE_CONF, key, value)


@register("UPD-CPANEL-AUTO", "Automatic cPanel updates", CAT, order=10)
def cpanel_auto():
    if not is_cpanel():
        yield Finding("UPD-CPANEL-AUTO", "cPanel updates (cPanel only)",
                      Status.SKIP, reference=REF)
        return
    cfg = _cpupdate()
    mode = cfg.get("UPDATES", "").lower()
    if mode in ("daily", "automatic"):
        yield Finding("UPD-CPANEL-AUTO", "cPanel auto-updates are enabled (%s)"
                      % mode, Status.OK, reference=REF)
    elif mode == "manual":
        yield Finding("UPD-CPANEL-AUTO", "cPanel updates are set to manual",
                      Status.WARN,
                      "Security fixes will not apply automatically.",
                      Severity.MEDIUM,
                      Remediation(
                          "Set cPanel updates to automatic (daily)",
                          func=_set_cpupdate("UPDATES", "daily"),
                          backup_files=[CPUPDATE_CONF],
                          manual="WHM > Update Preferences > Automatic."),
                      reference=REF)
    else:
        yield Finding("UPD-CPANEL-AUTO", "cPanel updates are disabled",
                      Status.FAIL,
                      "UPDATES=%s; the server will not receive cPanel patches."
                      % (mode or "unset"), Severity.HIGH,
                      Remediation(
                          "Enable automatic cPanel updates",
                          func=_set_cpupdate("UPDATES", "daily"),
                          backup_files=[CPUPDATE_CONF],
                          manual="WHM > Update Preferences > Automatic."),
                      reference=REF)


@register("UPD-CPANEL-VERSION", "cPanel version & tier", CAT, order=15)
def cpanel_version():
    if not is_cpanel():
        yield Finding("UPD-CPANEL-VERSION", "cPanel version (cPanel only)",
                      Status.SKIP, reference=REF)
        return
    version = (read_file("/usr/local/cpanel/version") or "").strip()
    tier = _cpupdate().get("CPANEL", "").strip()
    detail = "Installed: %s" % (version or "unknown")
    if tier:
        detail += "  ·  Update tier: %s" % tier
    yield Finding("UPD-CPANEL-VERSION", "cPanel version information",
                  Status.INFO, detail, Severity.INFO,
                  # No automated fix: upcp restarts services and can take
                  # tens of minutes, which is not something to trigger from an
                  # audit prompt.
                  Remediation("Keep cPanel current",
                              manual="WHM > cPanel Version Information, or run "
                                     "/usr/local/cpanel/scripts/upcp during a "
                                     "maintenance window."),
                  reference=REF)


@register("UPD-RPM", "System (RPM) updates", CAT, order=20)
def rpm_updates():
    if is_cpanel():
        cfg = _cpupdate()
        if cfg.get("RPMUP", "").lower() in ("daily", "automatic"):
            yield Finding("UPD-RPM", "System RPM auto-updates are enabled",
                          Status.OK, reference=REF)
        else:
            yield Finding("UPD-RPM", "System RPM auto-updates are not enabled",
                          Status.WARN, "RPMUP=%s" % (cfg.get("RPMUP") or "unset"),
                          Severity.MEDIUM,
                          Remediation(
                              "Enable automatic RPM updates",
                              func=_set_cpupdate("RPMUP", "daily"),
                              backup_files=[CPUPDATE_CONF],
                              manual="WHM > Update Preferences > "
                                     "Operating System Package Updates."),
                          reference=REF)
        return
    # Non-cPanel: report what is actually pending.
    mgr = "dnf" if which("dnf") else "yum" if which("yum") else None
    if not mgr:
        yield Finding("UPD-RPM", "Package updates (no dnf/yum)", Status.SKIP,
                      reference=REF)
        return
    rc, out, _ = run([mgr, "-q", "check-update"], timeout=180)
    # check-update exits 100 when updates are available, 0 when none are.
    if rc not in (0, 100):
        yield Finding("UPD-RPM", "Could not check for package updates",
                      Status.WARN, "%s check-update failed." % mgr,
                      Severity.LOW, reference=REF)
        return
    pending = [l for l in out.splitlines()
               if l.strip() and not l.startswith(("Last metadata", "Obsoleting"))]
    if rc == 0 or not pending:
        yield Finding("UPD-RPM", "No pending OS package updates", Status.OK,
                      reference=REF)
    else:
        yield Finding("UPD-RPM", "%d OS package update(s) pending" % len(pending),
                      Status.WARN,
                      "Includes security patches. Apply during a maintenance "
                      "window.", Severity.MEDIUM,
                      Remediation("Apply OS updates",
                                  commands=["%s -y update" % mgr],
                                  risk="upgrades packages and may restart "
                                       "services",
                                  manual="Run '%s -y update' when you can "
                                         "restart services." % mgr),
                      reference=REF)


@register("UPD-CMS", "CMS & plugin updates", CAT, order=30)
def cms_updates():
    if not which("wp-toolkit"):
        yield Finding("UPD-CMS", "WordPress Toolkit is not installed",
                      Status.INFO,
                      "Without it, CMS patching is manual. Patch WordPress/"
                      "Joomla/Drupal core, plugins and themes, and remove "
                      "unused extensions.", Severity.LOW,
                      Remediation("Install WP Toolkit or patch manually",
                                  manual="WHM > cPanel > WordPress Toolkit."),
                      reference=REF)
        return
    rc, out, _ = run(["wp-toolkit", "--list", "-format", "json"], timeout=120)
    if rc != 0:
        yield Finding("UPD-CMS", "WordPress Toolkit is available", Status.OK,
                      "Could not enumerate installations; review it in WHM.",
                      reference=REF)
        return
    outdated = out.lower().count('"update_available": true')
    if outdated:
        yield Finding("UPD-CMS",
                      "%d WordPress installation(s) have updates pending"
                      % outdated, Status.WARN,
                      "Outdated plugins are the most common route into a "
                      "shared host.", Severity.MEDIUM,
                      Remediation("Update WordPress installations",
                                  manual="WHM/cPanel > WordPress Toolkit > "
                                         "Updates; enable automatic updates for "
                                         "core and plugins."),
                      reference=REF)
    else:
        yield Finding("UPD-CMS",
                      "WordPress Toolkit reports no pending updates", Status.OK,
                      reference=REF)
