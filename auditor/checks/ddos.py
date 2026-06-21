"""Section 9 - DDoS protection and network security."""

from ..core.model import Finding, Remediation, Severity, Status
from ..core.registry import register
from ..core.util import run, which

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
    rc, out, _ = run("httpd -M 2>/dev/null || apachectl -M 2>/dev/null")
    if "evasive" in out:
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
