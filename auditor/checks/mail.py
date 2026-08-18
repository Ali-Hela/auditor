"""Mail security - Exim configuration and outbound abuse controls.

Not one of the ten checklist sections, but the largest practical risk on a
shared cPanel host: one compromised account starts sending, the server's IP
lands on a blocklist, and every customer's mail stops working. Most of these
controls exist to cap the blast radius of a compromise rather than prevent it.

Settings come from two places, both plain key=value files:

* ``/var/cpanel/cpanel.config`` - WHM Tweak Settings
* ``/etc/exim.conf.localopts`` - WHM's Exim Configuration Manager

A bare key with no ``=`` in either file means "unset, use the default", so an
absent key is treated as unset rather than as an empty value.
"""

from ..core.model import Finding, Remediation, Severity, Status
from ..core.registry import register
from ..core.util import cpanel_config, exim_localopts, is_cpanel, truthy

CAT = "Mail & Anti-Spam"
REF = "Mail security: cPanel Exim configuration & outbound abuse controls"

# Applying mail hardening can stop mail that currently flows. That is a
# judgement the operator has to make about their own customers, so these fixes
# are risk-gated rather than swept up by --yes.
BREAKS_MAIL = "can stop mail that currently works"


def _skip(check_id, title, reason="Not a cPanel server."):
    return Finding(check_id, title, Status.SKIP, reason, reference=REF)


def _tweak_fix(key, value, risk=None):
    return dict(commands=["whmapi1 set_tweaksetting key=%s value=%s"
                          % (key, value)], risk=risk)


@register("MAIL-SMTP-RESTRICT", "SMTP restrictions", CAT, order=10)
def smtp_restrictions():
    """Stops accounts bypassing Exim to talk straight to a remote port 25.

    Without it, a compromised account (or a script with a hardcoded mail
    library) sends directly, so none of the server's rate limits, logging or
    outbound spam scanning ever sees the message.
    """
    if not is_cpanel():
        yield _skip("MAIL-SMTP-RESTRICT", "SMTP restrictions (cPanel only)")
        return
    value = cpanel_config().get("smtpmailgidonly")
    if value is None:
        yield _skip("MAIL-SMTP-RESTRICT", "SMTP restrictions (setting not found)",
                    "smtpmailgidonly is absent from cpanel.config.")
    elif truthy(value):
        yield Finding("MAIL-SMTP-RESTRICT", "SMTP restrictions are enabled",
                      Status.OK,
                      "Only root, exim and mailman may reach remote SMTP ports.",
                      reference=REF)
    else:
        yield Finding("MAIL-SMTP-RESTRICT", "SMTP restrictions are disabled",
                      Status.FAIL,
                      "Any account can open a connection to a remote mail "
                      "server directly, bypassing Exim entirely. Rate limits, "
                      "outbound spam scanning and per-account logging all stop "
                      "applying, so a compromised account can spam until the "
                      "server's IP is blocklisted.", Severity.HIGH,
                      Remediation(
                          "Enable SMTP restrictions",
                          manual="WHM > Security Center > SMTP Restrictions. "
                                 "Check first whether any customer application "
                                 "sends through an external relay on port 25 - "
                                 "those will need to move to authenticated "
                                 "submission on 587.",
                          **_tweak_fix("smtpmailgidonly", "1",
                                       risk=BREAKS_MAIL + ": applications that "
                                       "send direct to a remote port 25 stop "
                                       "being able to")),
                      reference=REF)


@register("MAIL-RATELIMIT", "Outbound mail rate limit", CAT, order=20)
def rate_limit():
    if not is_cpanel():
        yield _skip("MAIL-RATELIMIT", "Mail rate limit (cPanel only)")
        return
    raw = cpanel_config().get("maxemailsperhour")
    try:
        limit = int(raw) if raw not in (None, "") else 0
    except ValueError:
        limit = 0
    if limit > 0:
        yield Finding("MAIL-RATELIMIT",
                      "Outbound mail is capped at %d messages/hour per domain"
                      % limit, Status.OK, reference=REF)
    else:
        yield Finding("MAIL-RATELIMIT",
                      "Outbound mail per domain is unlimited", Status.WARN,
                      "maxemailsperhour is unset, so a single compromised "
                      "account can send without limit. A cap is what buys you "
                      "the hours between a compromise and a blocklisting.",
                      Severity.MEDIUM,
                      # No automated fix: the right number depends entirely on
                      # what the customers legitimately send, and guessing it
                      # would break somebody's newsletter.
                      Remediation(
                          "Set a maximum emails per hour",
                          manual="WHM > Tweak Settings > Mail > 'Max hourly "
                                 "emails per domain'. Size it from your own "
                                 "traffic - check /var/log/exim_mainlog or WHM "
                                 "> View Mail Statistics for a busy domain's "
                                 "normal hourly peak, then leave headroom."),
                      reference=REF)


@register("MAIL-NOBODY", "Mail from the nobody user", CAT, order=30)
def nobody_mail():
    if not is_cpanel():
        yield _skip("MAIL-NOBODY", "Nobody mail (cPanel only)")
        return
    value = cpanel_config().get("nobodyspam")
    if value is None:
        yield _skip("MAIL-NOBODY", "Nobody mail (setting not found)",
                    "nobodyspam is absent from cpanel.config.")
    elif truthy(value):
        yield Finding("MAIL-NOBODY", "The nobody user cannot send mail",
                      Status.OK, reference=REF)
    else:
        yield Finding("MAIL-NOBODY", "The nobody user is allowed to send mail",
                      Status.WARN,
                      "Mail sent as 'nobody' cannot be attributed to an "
                      "account, so a spamming script is far harder to trace "
                      "and per-account limits do not apply to it.",
                      Severity.MEDIUM,
                      Remediation(
                          "Prevent nobody from sending mail",
                          manual="WHM > Tweak Settings > Mail > 'Prevent "
                                 "nobody from sending mail'. Only safe once "
                                 "PHP runs as the account user (suEXEC/PHP-FPM) "
                                 "rather than as nobody - otherwise every "
                                 "site's mail() calls stop working.",
                          **_tweak_fix("nobodyspam", "1",
                                       risk=BREAKS_MAIL + ": if PHP still runs "
                                       "as nobody, every site's mail() breaks")),
                      reference=REF)


@register("MAIL-OUTBOUND-SPAM", "Outbound spam detection", CAT, order=40)
def outbound_spam():
    """Detection alone changes nothing - the action is what stops the spam."""
    if not is_cpanel():
        yield _skip("MAIL-OUTBOUND-SPAM", "Outbound spam detection (cPanel only)")
        return
    cfg = cpanel_config()
    enabled = cfg.get("email_outbound_spam_detect_enable")
    action = (cfg.get("email_outbound_spam_detect_action") or "").strip().lower()
    if enabled is None:
        yield _skip("MAIL-OUTBOUND-SPAM",
                    "Outbound spam detection (setting not found)",
                    "email_outbound_spam_detect_enable is absent from "
                    "cpanel.config.")
    elif not truthy(enabled):
        yield Finding("MAIL-OUTBOUND-SPAM", "Outbound spam detection is off",
                      Status.FAIL,
                      "Nothing notices when an account starts sending spam. "
                      "Usually the first sign is the IP being blocklisted.",
                      Severity.HIGH,
                      Remediation(
                          "Enable outbound spam detection",
                          manual="WHM > Tweak Settings > Mail > 'Outbound spam "
                                 "detection'.",
                          **_tweak_fix("email_outbound_spam_detect_enable", "1")),
                      reference=REF)
    elif action in ("", "noaction"):
        yield Finding("MAIL-OUTBOUND-SPAM",
                      "Outbound spam is detected but no action is taken",
                      Status.WARN,
                      "Detection is on with action '%s', so the server notices "
                      "the spam and lets it go. Choose an action that holds or "
                      "blocks the sender, and make sure the notification "
                      "reaches somebody who reads it."
                      % (action or "unset"), Severity.MEDIUM,
                      # The choice between holding, blocking and suspending is
                      # a hosting policy decision, not a security default.
                      Remediation(
                          "Choose an action for detected outbound spam",
                          manual="WHM > Tweak Settings > Mail > 'The action "
                                 "taken when a user sends out spam'. Blocking "
                                 "stops the abuse immediately; holding gives "
                                 "you a chance to review first."),
                      reference=REF)
    else:
        threshold = cfg.get("email_outbound_spam_detect_threshold")
        detail = "Action: %s" % action
        if threshold:
            detail += "  ·  threshold: %s" % threshold
        yield Finding("MAIL-OUTBOUND-SPAM",
                      "Outbound spam detection is enabled and acts on hits",
                      Status.OK, detail, reference=REF)


@register("MAIL-SPF-DKIM", "SPF and DKIM for new accounts", CAT, order=50)
def spf_dkim():
    if not is_cpanel():
        yield _skip("MAIL-SPF-DKIM", "SPF/DKIM defaults (cPanel only)")
        return
    cfg = cpanel_config()
    missing = [name for name, key in (("SPF", "create_account_spf"),
                                      ("DKIM", "create_account_dkim"))
               if not truthy(cfg.get(key))]
    if not missing:
        yield Finding("MAIL-SPF-DKIM",
                      "New accounts get SPF and DKIM records automatically",
                      Status.OK, reference=REF)
    else:
        yield Finding("MAIL-SPF-DKIM",
                      "New accounts do not get %s automatically"
                      % " or ".join(missing), Status.WARN,
                      "Without SPF and DKIM, anyone can spoof mail from the "
                      "hosted domains and the domains' own mail is more likely "
                      "to be treated as spam.", Severity.MEDIUM,
                      # Safe to automate: this only affects accounts created
                      # from now on, so no existing mail flow can break.
                      Remediation(
                          "Enable SPF and DKIM for new accounts",
                          commands=["whmapi1 set_tweaksetting "
                                    "key=create_account_spf value=1",
                                    "whmapi1 set_tweaksetting "
                                    "key=create_account_dkim value=1"],
                          manual="WHM > Tweak Settings > Mail. Existing "
                                 "domains are unaffected - fix those with WHM > "
                                 "Email Deliverability."),
                      reference=REF)


@register("MAIL-SECURE-AUTH", "Encrypted SMTP authentication", CAT, order=60)
def secure_auth():
    opts = exim_localopts()
    if not opts:
        yield _skip("MAIL-SECURE-AUTH", "SMTP auth encryption",
                    "/etc/exim.conf.localopts is missing or unreadable.")
        return
    if truthy(opts.get("require_secure_auth")):
        yield Finding("MAIL-SECURE-AUTH",
                      "SMTP authentication requires an encrypted connection",
                      Status.OK, reference=REF)
    else:
        yield Finding("MAIL-SECURE-AUTH",
                      "SMTP authentication is accepted over plaintext",
                      Status.FAIL,
                      "Mail clients can send their username and password "
                      "unencrypted, so anyone on the network path can harvest "
                      "working mailbox credentials - which is exactly how "
                      "accounts get taken over and used to send spam.",
                      Severity.HIGH,
                      Remediation(
                          "Require SSL/TLS for SMTP authentication",
                          manual="WHM > Service Configuration > Exim "
                                 "Configuration Manager > 'Require clients to "
                                 "connect with SSL or issue the STARTTLS "
                                 "command'. Old clients configured for "
                                 "plaintext will need reconfiguring.",
                          risk=BREAKS_MAIL + ": clients configured without "
                               "TLS can no longer authenticate"),
                      reference=REF)


@register("MAIL-TLS", "Mail transport encryption strength", CAT, order=70)
def mail_tls():
    opts = exim_localopts()
    if not opts:
        yield _skip("MAIL-TLS", "Mail TLS settings",
                    "/etc/exim.conf.localopts is missing or unreadable.")
        return
    problems = []
    if truthy(opts.get("allowweakciphers")):
        problems.append("weak ciphers are allowed (allowweakciphers=1)")
    ssl_opts = (opts.get("openssl_options") or "").lower()
    stale = [name for name, token in (("SSLv3", "no_sslv3"),
                                      ("TLSv1.0", "no_tlsv1"),
                                      ("TLSv1.1", "no_tlsv1_1"))
             if token not in ssl_opts]
    if stale:
        problems.append("not disabled: %s" % ", ".join(stale))
    if not problems:
        yield Finding("MAIL-TLS", "Mail TLS settings are modern", Status.OK,
                      opts.get("openssl_options", "").strip(), reference=REF)
    else:
        yield Finding("MAIL-TLS", "Mail accepts obsolete TLS or weak ciphers",
                      Status.WARN, "\n".join(problems), Severity.MEDIUM,
                      Remediation(
                          "Harden Exim's TLS settings",
                          manual="WHM > Service Configuration > Exim "
                                 "Configuration Manager: turn off 'Allow weak "
                                 "SSL/TLS ciphers' and add +no_sslv3 "
                                 "+no_tlsv1 +no_tlsv1_1 to the OpenSSL "
                                 "options."),
                      reference=REF)


# Exim ACLs that blunt the common abuse patterns. All are togglable from WHM's
# Exim Configuration Manager and all default to sensible values on a current
# cPanel, so a finding here usually means somebody turned one off.
ABUSE_ACLS = [
    ("acl_dictionary_attack", "block dictionary attacks against mailboxes"),
    ("acl_ratelimit", "rate limit senders"),
    ("acl_slow_fail_block", "slow down hosts that keep failing"),
    ("senderverify", "verify the sender address"),
    ("acl_requirehelo", "require a HELO/EHLO greeting"),
]


@register("MAIL-ABUSE-ACLS", "Exim abuse-prevention ACLs", CAT, order=80)
def abuse_acls():
    opts = exim_localopts()
    if not opts:
        yield _skip("MAIL-ABUSE-ACLS", "Exim abuse ACLs",
                    "/etc/exim.conf.localopts is missing or unreadable.")
        return
    off = ["%s (%s)" % (key, label) for key, label in ABUSE_ACLS
           if key in opts and not truthy(opts[key])]
    if not off:
        yield Finding("MAIL-ABUSE-ACLS",
                      "Exim's abuse-prevention ACLs are enabled", Status.OK,
                      reference=REF)
    else:
        yield Finding("MAIL-ABUSE-ACLS",
                      "%d Exim abuse-prevention ACL(s) are disabled" % len(off),
                      Status.WARN,
                      "These default to on; something turned them off:\n  "
                      + "\n  ".join(off), Severity.MEDIUM,
                      Remediation(
                          "Re-enable the Exim abuse ACLs",
                          manual="WHM > Service Configuration > Exim "
                                 "Configuration Manager > ACL Options. If one "
                                 "was disabled deliberately to work around a "
                                 "delivery problem, note why."),
                      reference=REF)


@register("MAIL-POPBEFORESMTP", "POP-before-SMTP", CAT, order=90)
def pop_before_smtp():
    if not is_cpanel():
        yield _skip("MAIL-POPBEFORESMTP", "POP-before-SMTP (cPanel only)")
        return
    value = cpanel_config().get("popbeforesmtp")
    if value is None or not truthy(value):
        yield Finding("MAIL-POPBEFORESMTP", "POP-before-SMTP is disabled",
                      Status.OK, reference=REF)
    else:
        yield Finding("MAIL-POPBEFORESMTP", "POP-before-SMTP is enabled",
                      Status.WARN,
                      "Any host that authenticates to POP is then allowed to "
                      "relay mail without authenticating again. On a shared or "
                      "NATed network that grants relay access to everyone "
                      "behind the same address. It is a workaround for mail "
                      "clients that predate SMTP AUTH.", Severity.MEDIUM,
                      Remediation(
                          "Disable POP-before-SMTP",
                          manual="WHM > Tweak Settings > Mail > "
                                 "'Pop-before-SMTP'. Mail clients must use "
                                 "SMTP authentication on port 587 instead.",
                          **_tweak_fix("popbeforesmtp", "0",
                                       risk=BREAKS_MAIL + ": clients relying "
                                       "on it must be reconfigured for SMTP "
                                       "authentication")),
                      reference=REF)
