"""Section 9 - DDoS protection and network security."""

from ..core.model import Finding, Remediation, Severity, Status
from ..core.registry import register
from ..core.util import apache_modules, parse_kv, read_file, which

CAT = "DDoS & Network"
REF = "cPanel checklist #9: DDoS protection and network security"


@register("DDOS-IMUNIFY", "Imunify360 / malware protection", CAT, order=10)
def imunify():
    if which("imunify360-agent") or which("imunify-antivirus"):
        yield Finding("DDOS-IMUNIFY", "Imunify protection is installed",
                      Status.OK, reference=REF)
    else:
        yield Finding("DDOS-IMUNIFY", "Imunify360 is not installed", Status.INFO,
                      "Imunify360 adds an advanced WAF, malware scanning and "
                      "proactive defense. Optional, licensed.", Severity.INFO,
                      Remediation("Consider Imunify360",
                                  manual="WHM > cPanel > Imunify360 (licensed)."),
                      reference=REF)


@register("DDOS-MODEVASIVE", "mod_evasive rate limiting", CAT, order=20)
def mod_evasive():
    mods = apache_modules()
    if mods is None:
        yield Finding("DDOS-MODEVASIVE", "mod_evasive (Apache not detected)",
                      Status.SKIP, "Could not query loaded Apache modules.",
                      reference=REF)
        return
    if any("evasive" in m for m in mods):
        yield Finding("DDOS-MODEVASIVE", "mod_evasive is loaded", Status.OK,
                      reference=REF)
    else:
        yield Finding("DDOS-MODEVASIVE", "mod_evasive is not loaded", Status.WARN,
                      "mod_evasive throttles abusive request rates (basic DoS "
                      "mitigation).", Severity.LOW,
                      Remediation("Install mod_evasive",
                                  manual="EasyApache 4 > install "
                                         "ea-apache24-mod_evasive."),
                      reference=REF)


@register("DDOS-CSF-FLOOD", "CSF connection flood protection", CAT, order=25)
def csf_flood():
    """CSF ships SYNFLOOD and CONNLIMIT off by default; both blunt cheap floods."""
    conf = read_file("/etc/csf/csf.conf")
    if conf is None:
        yield Finding("DDOS-CSF-FLOOD", "CSF flood protection (CSF not installed)",
                      Status.SKIP, reference=REF)
        return
    cfg = parse_kv(conf)
    off = []
    if cfg.get("SYNFLOOD", "0") == "0":
        off.append("SYNFLOOD")
    if not cfg.get("CONNLIMIT", "").strip():
        off.append("CONNLIMIT")
    if not cfg.get("PORTFLOOD", "").strip():
        off.append("PORTFLOOD")
    if not off:
        yield Finding("DDOS-CSF-FLOOD", "CSF flood protection is configured",
                      Status.OK, reference=REF)
    else:
        yield Finding("DDOS-CSF-FLOOD",
                      "CSF flood protection is unconfigured: %s" % ", ".join(off),
                      Status.INFO,
                      "These are off by default. SYNFLOOD costs CPU under load "
                      "and CONNLIMIT can affect legitimate bursty clients, so "
                      "tune them rather than switching everything on.",
                      Severity.LOW,
                      Remediation("Tune CSF flood settings",
                                  manual="Set CONNLIMIT (e.g. '80;20,443;20') "
                                         "and PORTFLOOD in /etc/csf/csf.conf, "
                                         "then 'csf -r'. Enable SYNFLOOD only "
                                         "while under attack."),
                      reference=REF)


@register("DDOS-WAF", "Edge WAF / CDN", CAT, order=30)
def edge_waf():
    yield Finding("DDOS-WAF", "Use an edge WAF / CDN", Status.INFO,
                  "Front the server with Cloudflare or a similar WAF/CDN for "
                  "DDoS absorption, rate limiting and reduced origin load.",
                  Severity.INFO,
                  Remediation("Put the site behind a WAF/CDN",
                              manual="Configure Cloudflare (or equivalent) and "
                                     "restrict the origin firewall to its IPs."),
                  reference=REF)
