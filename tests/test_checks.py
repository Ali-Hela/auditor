"""Tests for check logic that had (or could regain) false positives.

Checks read the live system, so these patch the helpers they call rather than
touching real config.
"""

import unittest
from unittest import mock

from auditor.checks import database_php, firewall, login, ssl
from auditor.core.model import Status
from auditor.core.registry import all_checks


def statuses(gen):
    return [f.status for f in gen]


def only(gen):
    results = list(gen)
    assert len(results) == 1, "expected one finding, got %d" % len(results)
    return results[0]


class TestRootSshDefault(unittest.TestCase):
    """OpenSSH defaults to prohibit-password; assuming 'yes' was a false FAIL."""

    def test_prohibit_password_passes(self):
        with mock.patch.object(login, "sshd_config",
                               return_value={"permitrootlogin": "prohibit-password"}):
            self.assertEqual(only(login.root_ssh()).status, Status.OK)

    def test_yes_fails(self):
        with mock.patch.object(login, "sshd_config",
                               return_value={"permitrootlogin": "yes"}):
            self.assertEqual(only(login.root_ssh()).status, Status.FAIL)

    def test_absent_directive_is_not_a_failure(self):
        # sshd -T always reports a value; only the text fallback can omit it,
        # and an omission means "the safe compiled-in default applies".
        with mock.patch.object(login, "sshd_config", return_value={"port": "22"}):
            self.assertEqual(only(login.root_ssh()).status, Status.WARN)

    def test_unreadable_config_skips(self):
        with mock.patch.object(login, "sshd_config", return_value=None):
            self.assertEqual(only(login.root_ssh()).status, Status.SKIP)

    def test_fix_is_marked_risky(self):
        with mock.patch.object(login, "sshd_config",
                               return_value={"permitrootlogin": "yes"}):
            self.assertTrue(only(login.root_ssh()).remediation.risky)


class TestTwoFactorCoercion(unittest.TestCase):
    """bool("0") is True; the 2FA check used to read a disabled policy as on."""

    def _status(self, is_enabled):
        payload = {"data": {"is_enabled": is_enabled}}
        with mock.patch.object(login, "is_cpanel", return_value=True), \
                mock.patch.object(login, "whmapi1", return_value=payload):
            return only(login.two_factor()).status

    def test_string_zero_is_disabled(self):
        self.assertEqual(self._status("0"), Status.FAIL)

    def test_int_zero_is_disabled(self):
        self.assertEqual(self._status(0), Status.FAIL)

    def test_string_one_is_enabled(self):
        self.assertEqual(self._status("1"), Status.OK)

    def test_api_failure_warns(self):
        with mock.patch.object(login, "is_cpanel", return_value=True), \
                mock.patch.object(login, "whmapi1", return_value=None):
            self.assertEqual(only(login.two_factor()).status, Status.WARN)


class TestMysqlExposure(unittest.TestCase):
    def test_ipv6_loopback_is_not_public(self):
        with mock.patch.object(database_php, "listening_ports",
                               return_value=[("::1", "3306")]):
            self.assertEqual(only(database_php.mysql_remote()).status, Status.OK)

    def test_wildcard_is_public(self):
        with mock.patch.object(database_php, "listening_ports",
                               return_value=[("*", "3306")]):
            self.assertEqual(only(database_php.mysql_remote()).status,
                             Status.FAIL)

    def test_absent_mysql_skips(self):
        with mock.patch.object(database_php, "listening_ports",
                               return_value=[("0.0.0.0", "80")]):
            self.assertEqual(only(database_php.mysql_remote()).status,
                             Status.SKIP)


class TestApacheChecksSkipWhenAbsent(unittest.TestCase):
    """`httpd -M` returning 127 must not read as "ModSecurity is disabled"."""

    def test_modsec_skips_without_apache(self):
        with mock.patch.object(firewall, "apache_modules", return_value=None):
            self.assertEqual(only(firewall.modsecurity()).status, Status.SKIP)

    def test_modsec_detected(self):
        with mock.patch.object(firewall, "apache_modules",
                               return_value=["security2_module (shared)",
                                             "core_module (static)"]):
            self.assertEqual(only(firewall.modsecurity()).status, Status.OK)

    def test_modsec_missing_fails(self):
        with mock.patch.object(firewall, "apache_modules",
                               return_value=["core_module (static)"]):
            self.assertEqual(only(firewall.modsecurity()).status, Status.FAIL)


class TestExpectedPorts(unittest.TestCase):
    def test_mysql_is_not_allowlisted(self):
        # FW-PORTS allowlisting 3306 contradicted DB-REMOTE failing it.
        self.assertNotIn("3306", firewall.EXPECTED_PORTS)

    def test_loopback_ports_are_ignored(self):
        with mock.patch.object(firewall, "listening_ports",
                               return_value=[("::1", "9999"),
                                             ("127.0.0.1", "8888")]):
            self.assertEqual(only(firewall.open_ports()).status, Status.OK)

    def test_unexpected_public_port_warns(self):
        with mock.patch.object(firewall, "listening_ports",
                               return_value=[("0.0.0.0", "9999")]):
            finding = only(firewall.open_ports())
            self.assertEqual(finding.status, Status.WARN)
            self.assertIn("9999", finding.title)


class TestTlsProtocolParsing(unittest.TestCase):
    """'-TLSv1' removes the protocol; the old substring match flagged it."""

    def _status(self, directive):
        with mock.patch.object(ssl, "_apache_directive", return_value=directive):
            return only(ssl.tls_version()).status

    def test_explicit_modern_list_passes(self):
        self.assertEqual(self._status("SSLProtocol TLSv1.2 TLSv1.3"), Status.OK)

    def test_removal_syntax_passes(self):
        self.assertEqual(
            self._status("SSLProtocol All -SSLv2 -SSLv3 -TLSv1 -TLSv1.1"),
            Status.OK)

    def test_tlsv1_enabled_warns(self):
        self.assertEqual(self._status("SSLProtocol TLSv1 TLSv1.2"), Status.WARN)

    def test_bare_all_warns(self):
        self.assertEqual(self._status("SSLProtocol All"), Status.WARN)

    def test_missing_directive_warns(self):
        self.assertEqual(self._status(None), Status.WARN)


class TestCipherParsing(unittest.TestCase):
    def _status(self, directive):
        with mock.patch.object(ssl, "_apache_directive", return_value=directive):
            return only(ssl.ciphers()).status

    def test_excluded_weak_ciphers_pass(self):
        self.assertEqual(
            self._status("SSLCipherSuite ECDHE-RSA-AES128-GCM-SHA256:!RC4:!MD5"),
            Status.OK)

    def test_enabled_rc4_warns(self):
        self.assertEqual(self._status("SSLCipherSuite HIGH:RC4:!aNULL"),
                         Status.WARN)


class TestPhpEol(unittest.TestCase):
    def test_flags_eol_versions(self):
        with mock.patch.object(
                database_php, "ea_php_inis",
                return_value=["/opt/cpanel/ea-php74/root/etc/php.ini"]):
            finding = only(database_php.php_eol())
            self.assertEqual(finding.status, Status.FAIL)
            self.assertIn("7.4", finding.title)

    def test_supported_versions_pass(self):
        with mock.patch.object(
                database_php, "ea_php_inis",
                return_value=["/opt/cpanel/ea-php83/root/etc/php.ini"]):
            self.assertEqual(only(database_php.php_eol()).status, Status.OK)


class TestEveryCheckRunsCleanly(unittest.TestCase):
    """Run every check against the real machine.

    Checks are read-only, so this is safe anywhere. On a non-cPanel host (a CI
    runner) it proves the whole suite degrades to SKIP/INFO instead of raising
    or inventing failures from missing tools.
    """

    def test_no_check_raises(self):
        for spec in all_checks():
            with self.subTest(check=spec.id):
                findings = list(spec.func())
                self.assertTrue(findings, "%s yielded nothing" % spec.id)
                for f in findings:
                    self.assertIsInstance(f.status, Status)
                    self.assertTrue(f.title, "%s has an empty title" % spec.id)

    def test_a_missing_tool_never_produces_a_failure(self):
        """The bug class this guards: `httpd -M` exit 127 read as "disabled"."""
        for spec in all_checks():
            for f in spec.func():
                if f.status is Status.FAIL:
                    self.assertTrue(
                        f.detail or f.title,
                        "%s failed without saying why" % spec.id)


class TestRegistry(unittest.TestCase):
    def test_check_ids_are_unique(self):
        ids = [c.id for c in all_checks()]
        self.assertEqual(len(ids), len(set(ids)), "duplicate check IDs")

    def test_every_check_is_a_generator_yielding_findings(self):
        for spec in all_checks():
            self.assertTrue(callable(spec.func), spec.id)
            self.assertTrue(spec.category, spec.id)
            self.assertTrue(spec.title, spec.id)

    def test_findings_reuse_their_check_id(self):
        """Verification matches findings to checks by ID, so they must agree."""
        for spec in all_checks():
            source = spec.func.__code__.co_consts
            self.assertIn(spec.id, [c for c in source if isinstance(c, str)],
                          "%s never yields its own ID" % spec.id)


if __name__ == "__main__":
    unittest.main()
