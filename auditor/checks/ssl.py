"""Section 3 - SSL and encryption best practices."""

import glob
import re

from ..core.model import Finding, Remediation, Severity, Status
from ..core.registry import register
from ..core.util import cpanel_config, is_cpanel, read_file, truthy, whmapi1

CAT = "SSL / TLS"
REF = "cPanel checklist #3: SSL and encryption best practices"


@register("SSL-AUTOSSL", "AutoSSL provider", CAT, order=10)
def autossl():
    if not is_cpanel():
        yield Finding("SSL-AUTOSSL", "AutoSSL (cPanel only)", Status.SKIP,
                      "Not a cPanel server.", reference=REF)
        return
    data = whmapi1("get_autossl_providers")
    provider = None
    if data:
        for prov in data.get("data", {}).get("payload", []):
            if truthy(prov.get("enabled")):
                provider = (prov.get("display_name") or prov.get("module_name")
                            or "enabled")
                break
    if data is None:
        yield Finding("SSL-AUTOSSL", "AutoSSL status could not be determined",
                      Status.WARN, "whmapi1 get_autossl_providers failed "
                      "(run as root?).", Severity.LOW,
                      Remediation("Verify AutoSSL is enabled",
                                  manual="WHM > Manage AutoSSL > Providers."),
                      reference=REF)
    elif provider:
        yield Finding("SSL-AUTOSSL", "AutoSSL is enabled (%s)" % provider,
                      Status.OK, reference=REF)
    else:
        yield Finding("SSL-AUTOSSL", "AutoSSL is not enabled", Status.FAIL,
                      "AutoSSL issues and renews free certificates automatically.",
                      Severity.MEDIUM,
                      Remediation(
                          "Select an AutoSSL provider (Let's Encrypt)",
                          commands=["whmapi1 set_autossl_provider "
                                    "provider=cPanel"],
                          manual="WHM > Manage AutoSSL > Providers."),
                      reference=REF)


@register("SSL-REQUIRE", "Require SSL for cPanel services", CAT, order=20)
def require_ssl():
    if not is_cpanel():
        yield Finding("SSL-REQUIRE", "Require SSL (cPanel only)", Status.SKIP,
                      "Not a cPanel server.", reference=REF)
        return
    cfg = cpanel_config()
    val = cfg.get("requiressl")
    if val == "1":
        yield Finding("SSL-REQUIRE", "SSL is required for cPanel services",
                      Status.OK, reference=REF)
    else:
        yield Finding("SSL-REQUIRE", "SSL is not required for cPanel services",
                      Status.FAIL,
                      "Logins to cPanel/WHM/Webmail may occur over plain HTTP.",
                      Severity.HIGH,
                      Remediation(
                          "Require SSL for cPanel services",
                          commands=["whmapi1 set_tweaksetting key=requiressl "
                                    "value=1"],
                          manual="WHM > Tweak Settings > Require SSL.",
                          restart="cpsrvd"),
                      reference=REF)


def _apache_ssl_protocol():
    for path in (["/etc/apache2/conf.d/ssl.conf"]
                 + glob.glob("/etc/apache2/conf.d/*.conf")
                 + ["/etc/apache2/conf/httpd.conf"]):
        text = read_file(path)
        if not text:
            continue
        for line in text.splitlines():
            s = line.strip()
            if s and not s.startswith("#") and s.lower().startswith("sslprotocol"):
                return s
    return None


@register("SSL-TLS-VERSION", "Deprecated TLS protocols", CAT, order=30)
def tls_version():
    line = _apache_ssl_protocol()
    if line is None:
        yield Finding("SSL-TLS-VERSION", "TLS protocol policy not found",
                      Status.WARN,
                      "Could not locate an SSLProtocol directive in Apache config.",
                      Severity.MEDIUM,
                      Remediation("Restrict TLS to 1.2/1.3",
                                  manual="WHM > Apache Configuration > Global "
                                         "Configuration > SSL/TLS Protocols."),
                      reference=REF)
        return
    low = line.lower()
    weak = []
    if re.search(r"(^|[\s+])tlsv1(\b|[^.])", low) and "-tlsv1 " not in low:
        # crude: flag if TLSv1 / TLSv1.1 enabled and not explicitly removed
        if "-tlsv1" not in low:
            weak.append("TLSv1")
    if "tlsv1.1" in low and "-tlsv1.1" not in low:
        weak.append("TLSv1.1")
    if weak:
        yield Finding("SSL-TLS-VERSION",
                      "Deprecated TLS may be enabled: %s" % ", ".join(weak),
                      Status.WARN, "Current: %s" % line, Severity.MEDIUM,
                      Remediation("Allow only TLS 1.2 and 1.3",
                                  manual="WHM > Apache Configuration > Global "
                                         "Configuration: SSLProtocol "
                                         "TLSv1.2 TLSv1.3."),
                      reference=REF)
    else:
        yield Finding("SSL-TLS-VERSION", "TLS protocol policy looks modern",
                      Status.OK, line, reference=REF)


@register("SSL-CIPHERS", "Strong cipher suites", CAT, order=40)
def ciphers():
    yield Finding("SSL-CIPHERS", "Use strong cipher suites", Status.INFO,
                  "Restrict Apache/Nginx to modern ciphers and verify with "
                  "Qualys SSL Labs (https://www.ssllabs.com/ssltest/).",
                  Severity.INFO,
                  Remediation("Harden SSL cipher suite",
                              manual="WHM > Apache Configuration > Global "
                                     "Configuration > SSL Cipher Suite."),
                  reference=REF)
