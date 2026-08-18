"""Tests for the mail checks.

Fixtures are drawn from a real cPanel server's /var/cpanel/cpanel.config and
/etc/exim.conf.localopts, including the quirk that a bare key with no '=' means
"unset, use the default" and so never reaches the parsed dict.
"""

import unittest
from unittest import mock

from auditor.checks import mail
from auditor.core.model import Status

# Trimmed to the mail-relevant keys, values as found on a live server.
LIVE_CPANEL_CONFIG = {
    "smtpmailgidonly": "0",
    "nobodyspam": "1",
    "create_account_spf": "1",
    "create_account_dkim": "1",
    "popbeforesmtp": "0",
    "email_outbound_spam_detect_enable": "1",
    "email_outbound_spam_detect_action": "noaction",
    "email_outbound_spam_detect_threshold": "500",
    # 'maxemailsperhour' appears in the file with no '=' at all, so it is
    # absent here rather than present-and-empty. That means unlimited.
}

LIVE_LOCALOPTS = {
    "require_secure_auth": "1",
    "allowweakciphers": "0",
    "openssl_options": "+no_sslv2 +no_sslv3 +no_tlsv1 +no_tlsv1_1",
    "acl_dictionary_attack": "1",
    "acl_ratelimit": "1",
    "acl_slow_fail_block": "1",
    "senderverify": "1",
    "acl_requirehelo": "1",
}


def only(gen):
    results = list(gen)
    assert len(results) == 1, "expected one finding, got %d" % len(results)
    return results[0]


def with_config(overrides=None, localopts=None, cpanel=True):
    cfg = dict(LIVE_CPANEL_CONFIG)
    if overrides is not None:
        for key, value in overrides.items():
            if value is None:
                cfg.pop(key, None)
            else:
                cfg[key] = value
    opts = dict(LIVE_LOCALOPTS) if localopts is None else localopts
    return (mock.patch.object(mail, "is_cpanel", return_value=cpanel),
            mock.patch.object(mail, "cpanel_config", return_value=cfg),
            mock.patch.object(mail, "exim_localopts", return_value=opts))


class MailCase(unittest.TestCase):
    def check(self, func, overrides=None, localopts=None, cpanel=True):
        patches = with_config(overrides, localopts, cpanel)
        for p in patches:
            p.start()
        try:
            return only(func())
        finally:
            for p in patches:
                p.stop()


class TestSmtpRestrictions(MailCase):
    def test_live_server_is_unrestricted(self):
        f = self.check(mail.smtp_restrictions)
        self.assertEqual(f.status, Status.FAIL)
        self.assertTrue(f.remediation.risky)

    def test_enabled_passes(self):
        self.assertEqual(
            self.check(mail.smtp_restrictions, {"smtpmailgidonly": "1"}).status,
            Status.OK)

    def test_absent_setting_skips(self):
        self.assertEqual(
            self.check(mail.smtp_restrictions, {"smtpmailgidonly": None}).status,
            Status.SKIP)

    def test_non_cpanel_skips(self):
        self.assertEqual(
            self.check(mail.smtp_restrictions, cpanel=False).status, Status.SKIP)


class TestRateLimit(MailCase):
    def test_unset_means_unlimited(self):
        f = self.check(mail.rate_limit)
        self.assertEqual(f.status, Status.WARN)
        self.assertFalse(f.remediation.automatable,
                         "the right cap is site-specific; do not guess one")

    def test_zero_means_unlimited(self):
        self.assertEqual(
            self.check(mail.rate_limit, {"maxemailsperhour": "0"}).status,
            Status.WARN)

    def test_a_cap_passes(self):
        f = self.check(mail.rate_limit, {"maxemailsperhour": "200"})
        self.assertEqual(f.status, Status.OK)
        self.assertIn("200", f.title)

    def test_non_numeric_is_treated_as_unlimited(self):
        self.assertEqual(
            self.check(mail.rate_limit, {"maxemailsperhour": "junk"}).status,
            Status.WARN)


class TestOutboundSpam(MailCase):
    def test_detection_without_action_warns(self):
        # The live server's state: it notices spam and lets it go.
        f = self.check(mail.outbound_spam)
        self.assertEqual(f.status, Status.WARN)
        self.assertIn("noaction", f.detail)

    def test_detection_disabled_fails(self):
        self.assertEqual(
            self.check(mail.outbound_spam,
                       {"email_outbound_spam_detect_enable": "0"}).status,
            Status.FAIL)

    def test_detection_with_action_passes(self):
        f = self.check(mail.outbound_spam,
                       {"email_outbound_spam_detect_action": "block"})
        self.assertEqual(f.status, Status.OK)
        self.assertIn("500", f.detail)

    def test_empty_action_warns(self):
        self.assertEqual(
            self.check(mail.outbound_spam,
                       {"email_outbound_spam_detect_action": ""}).status,
            Status.WARN)


class TestSpfDkim(MailCase):
    def test_both_enabled_passes(self):
        self.assertEqual(self.check(mail.spf_dkim).status, Status.OK)

    def test_missing_dkim_warns(self):
        f = self.check(mail.spf_dkim, {"create_account_dkim": "0"})
        self.assertEqual(f.status, Status.WARN)
        self.assertIn("DKIM", f.title)
        self.assertNotIn("SPF", f.title)

    def test_fix_is_safe_to_automate(self):
        # Only affects accounts created from now on, so nothing in flight
        # can break - this one should not be risk-gated.
        f = self.check(mail.spf_dkim, {"create_account_spf": "0"})
        self.assertTrue(f.remediation.automatable)
        self.assertFalse(f.remediation.risky)


class TestSecureAuth(MailCase):
    def test_required_passes(self):
        self.assertEqual(self.check(mail.secure_auth).status, Status.OK)

    def test_plaintext_auth_fails(self):
        f = self.check(mail.secure_auth,
                       localopts={"require_secure_auth": "0"})
        self.assertEqual(f.status, Status.FAIL)
        self.assertTrue(f.remediation.risky)

    def test_unreadable_localopts_skips(self):
        self.assertEqual(self.check(mail.secure_auth, localopts={}).status,
                         Status.SKIP)


class TestMailTls(MailCase):
    def test_live_settings_pass(self):
        self.assertEqual(self.check(mail.mail_tls).status, Status.OK)

    def test_weak_ciphers_warn(self):
        opts = dict(LIVE_LOCALOPTS, allowweakciphers="1")
        f = self.check(mail.mail_tls, localopts=opts)
        self.assertEqual(f.status, Status.WARN)
        self.assertIn("weak ciphers", f.detail)

    def test_obsolete_protocol_not_disabled_warns(self):
        opts = dict(LIVE_LOCALOPTS, openssl_options="+no_sslv2")
        f = self.check(mail.mail_tls, localopts=opts)
        self.assertEqual(f.status, Status.WARN)
        for name in ("SSLv3", "TLSv1.0", "TLSv1.1"):
            self.assertIn(name, f.detail)


class TestAbuseAcls(MailCase):
    def test_all_enabled_passes(self):
        self.assertEqual(self.check(mail.abuse_acls).status, Status.OK)

    def test_disabled_acls_are_listed(self):
        opts = dict(LIVE_LOCALOPTS, acl_ratelimit="0", senderverify="0")
        f = self.check(mail.abuse_acls, localopts=opts)
        self.assertEqual(f.status, Status.WARN)
        self.assertIn("2 Exim", f.title)
        self.assertIn("acl_ratelimit", f.detail)

    def test_absent_key_is_not_reported_as_disabled(self):
        # A key missing from localopts means "default", which is on. Reporting
        # it as disabled would be a false positive on every older config.
        opts = {k: v for k, v in LIVE_LOCALOPTS.items() if k != "acl_ratelimit"}
        self.assertEqual(self.check(mail.abuse_acls, localopts=opts).status,
                         Status.OK)


class TestPopBeforeSmtp(MailCase):
    def test_disabled_passes(self):
        self.assertEqual(self.check(mail.pop_before_smtp).status, Status.OK)

    def test_enabled_warns(self):
        f = self.check(mail.pop_before_smtp, {"popbeforesmtp": "1"})
        self.assertEqual(f.status, Status.WARN)
        self.assertTrue(f.remediation.risky)

    def test_absent_is_treated_as_disabled(self):
        self.assertEqual(
            self.check(mail.pop_before_smtp, {"popbeforesmtp": None}).status,
            Status.OK)


if __name__ == "__main__":
    unittest.main()
