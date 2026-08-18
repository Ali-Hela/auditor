"""Section 3 - SSL and encryption best practices."""

import glob
import re

from ..core.model import Finding, Remediation, Severity, Status
from ..core.registry import register
from ..core.util import cpanel_config, is_cpanel, read_file, truthy, whmapi1

CAT = "SSL / TLS"
REF = "cPanel checklist #3: SSL and encryption best practices"

# Cipher tokens that are broken or badly weakened. Matched against the
# configured SSLCipherSuite string.
WEAK_CIPHER_TOKENS = ["null", "export", "rc4", "md5", "des-cbc3", "3des",
                      "adh", "aecdh", "seed", "idea", "psk"]


@register("SSL-AUTOSSL", "AutoSSL provider", CAT, order=10)
def autossl():
    if not is_cpanel():
        yield Finding("SSL-AUTOSSL", "AutoSSL (cPanel only)", Status.SKIP,
                      "Not a cPanel server.", reference=REF)
        return
    data = whmapi1("get_autossl_providers")
    if data is None:
        yield Finding("SSL-AUTOSSL", "AutoSSL status could not be determined",
                      Status.WARN, "whmapi1 get_autossl_providers failed "
                      "(run as root?).", Severity.LOW,
                      Remediation("Verify AutoSSL is enabled",
                                  manual="WHM > Manage AutoSSL > Providers."),
                      reference=REF)
        return
    provider = None
    for prov in data.get("data", {}).get("payload", []):
        if truthy(prov.get("enabled")):
            provider = (prov.get("display_name") or prov.get("module_name")
                        or "enabled")
            break
    if provider:
        yield Finding("SSL-AUTOSSL", "AutoSSL is enabled (%s)" % provider,
                      Status.OK, reference=REF)
    else:
        yield Finding("SSL-AUTOSSL", "AutoSSL is not enabled", Status.FAIL,
                      "AutoSSL issues and renews free certificates automatically.",
                      Severity.MEDIUM,
                      Remediation(
                          "Select an AutoSSL provider (Let's Encrypt)",
                          commands=["whmapi1 set_autossl_provider "
                                    "provider=LetsEncrypt"],
                          manual="WHM > Manage AutoSSL > Providers."),
                      reference=REF)


@register("SSL-REQUIRE", "Require SSL for cPanel services", CAT, order=20)
def require_ssl():
    if not is_cpanel():
        yield Finding("SSL-REQUIRE", "Require SSL (cPanel only)", Status.SKIP,
                      "Not a cPanel server.", reference=REF)
        return
    cfg = cpanel_config()
    if truthy(cfg.get("requiressl")):
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


def _apache_directive(name):
    """Last effective value of an Apache directive across the SSL config."""
    found = None
    paths = (["/etc/apache2/conf.d/ssl.conf"]
             + sorted(glob.glob("/etc/apache2/conf.d/*.conf"))
             + ["/etc/apache2/conf/httpd.conf"])
    for path in paths:
        text = read_file(path)
        if not text:
            continue
        for line in text.splitlines():
            s = line.strip()
            if s and not s.startswith("#") and s.lower().startswith(name.lower()):
                found = s
    return found


@register("SSL-TLS-VERSION", "Deprecated TLS protocols", CAT, order=30)
def tls_version():
    line = _apache_directive("SSLProtocol")
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
    # Tokenise so '-TLSv1' (removal) is never confused with 'TLSv1' (enable),
    # and 'TLSv1' never matches inside 'TLSv1.2'.
    tokens = re.findall(r"[+-]?(?:all|SSLv\d|TLSv\d(?:\.\d)?)", line, re.I)
    enabled = set()
    for tok in tokens:
        sign, name = ("-", tok[1:]) if tok[0] == "-" else ("+", tok.lstrip("+"))
        name = name.upper()
        if name == "ALL":
            if sign == "+":
                enabled |= {"SSLV2", "SSLV3", "TLSV1", "TLSV1.1", "TLSV1.2",
                            "TLSV1.3"}
            else:
                enabled.clear()
        elif sign == "+":
            enabled.add(name)
        else:
            enabled.discard(name)
    weak = sorted(enabled & {"SSLV2", "SSLV3", "TLSV1", "TLSV1.1"})
    if weak:
        yield Finding("SSL-TLS-VERSION",
                      "Deprecated TLS/SSL is enabled: %s" % ", ".join(weak),
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
    line = _apache_directive("SSLCipherSuite")
    if line is None:
        yield Finding("SSL-CIPHERS", "Cipher suite policy not found",
                      Status.WARN,
                      "Could not locate an SSLCipherSuite directive in Apache "
                      "config; OpenSSL's defaults apply.", Severity.LOW,
                      Remediation("Set an explicit cipher suite",
                                  manual="WHM > Apache Configuration > Global "
                                         "Configuration > SSL Cipher Suite."),
                      reference=REF)
        return
    value = line.split(None, 1)[1] if len(line.split(None, 1)) > 1 else ""
    low = value.lower()
    weak = []
    for token in WEAK_CIPHER_TOKENS:
        # '!RC4' excludes the cipher; 'RC4' enables it.
        for part in re.split(r"[:\s,]+", low):
            if part.lstrip("+") == token and not part.startswith("!") \
                    and not part.startswith("-"):
                weak.append(token.upper())
                break
    if weak:
        yield Finding("SSL-CIPHERS",
                      "Weak cipher families are permitted: %s" % ", ".join(weak),
                      Status.WARN, "Current: %s" % value, Severity.MEDIUM,
                      Remediation("Harden the SSL cipher suite",
                                  manual="WHM > Apache Configuration > Global "
                                         "Configuration > SSL Cipher Suite; use "
                                         "the Mozilla 'intermediate' list. "
                                         "Confirm with https://ssllabs.com/ssltest/"),
                      reference=REF)
    else:
        yield Finding("SSL-CIPHERS", "No weak cipher families are permitted",
                      Status.OK, value, reference=REF)
