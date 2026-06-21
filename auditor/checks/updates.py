"""Section 8 - Keep software and plugins updated."""

from ..core.model import Finding, Remediation, Severity, Status
from ..core.registry import register
from ..core.util import is_cpanel, parse_kv, read_file, which

CAT = "Updates & Patching"
REF = "cPanel checklist #8: Keep software and plugins updated"


def _cpupdate():
    return parse_kv(read_file("/etc/cpupdate.conf"))


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
                          commands=["sed -ri 's/^UPDATES=.*/UPDATES=daily/' "
                                    "/etc/cpupdate.conf"],
                          manual="WHM > Update Preferences > Automatic."),
                      reference=REF)
    else:
        yield Finding("UPD-CPANEL-AUTO", "cPanel updates are disabled (never)",
                      Status.FAIL,
                      "UPDATES=%s; the server will not receive cPanel patches."
                      % (mode or "unset"), Severity.HIGH,
                      Remediation(
                          "Enable automatic cPanel updates",
                          commands=["sed -ri 's/^UPDATES=.*/UPDATES=daily/' "
                                    "/etc/cpupdate.conf"],
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
    yield Finding("UPD-CPANEL-VERSION", "Review cPanel version information",
                  Status.INFO, detail, Severity.INFO,
                  Remediation("Keep cPanel current",
                              commands=["/usr/local/cpanel/scripts/upcp --force"],
                              manual="WHM > cPanel Version Information / "
                                     "Upgrade to Latest Version."),
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
                              commands=["sed -ri 's/^RPMUP=.*/RPMUP=daily/' "
                                        "/etc/cpupdate.conf"],
                              manual="WHM > Update Preferences > "
                                     "Operating System Package Updates."),
                          reference=REF)
        return
    # Non-cPanel: count pending updates
    mgr = "dnf" if which("dnf") else "yum" if which("yum") else None
    if not mgr:
        yield Finding("UPD-RPM", "Package updates (no dnf/yum)", Status.SKIP,
                      reference=REF)
        return
    yield Finding("UPD-RPM", "Check for pending OS package updates", Status.INFO,
                  "Run '%s -y update' regularly or enable dnf-automatic." % mgr,
                  Severity.LOW,
                  Remediation("Apply OS updates",
                              commands=["%s -y update" % mgr]),
                  reference=REF)


@register("UPD-CMS", "CMS & plugin updates", CAT, order=30)
def cms_updates():
    wp_toolkit = which("wp-toolkit")
    if wp_toolkit:
        yield Finding("UPD-CMS", "WordPress Toolkit is available", Status.OK,
                      "Use it to keep WordPress core, plugins and themes patched.",
                      reference=REF)
    else:
        yield Finding("UPD-CMS", "Keep CMS applications updated", Status.INFO,
                      "Patch WordPress/Joomla/Drupal core, plugins and themes; "
                      "remove unused plugins/themes.", Severity.INFO,
                      Remediation("Manage CMS updates",
                                  manual="Install WP Toolkit (WHM) or update CMS "
                                         "apps and remove unused extensions."),
                      reference=REF)
