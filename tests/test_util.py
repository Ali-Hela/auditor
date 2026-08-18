"""Tests for the parsing helpers in auditor.core.util.

Every case here corresponds to a real failure mode: the parsers read output
from ss, netstat, sshd, php.ini and csf.conf, and a misparse turns into a
false FAIL on somebody's production server.
"""

import os
import tempfile
import unittest

from auditor.core.util import (backup_file, is_loopback, is_public_addr,
                               normalize_addr, parse_kv, parse_socket_lines,
                               parse_sshd_output, php_version_of_ini,
                               set_config_line)

# Real `ss -tlnH` output, including the IPv6 and wildcard forms that the
# original address filter mishandled.
SS_OUTPUT = """\
LISTEN 0      45                         0.0.0.0:2087  0.0.0.0:*
LISTEN 0      4096                     127.0.0.1:11234 0.0.0.0:*
LISTEN 0      128                        0.0.0.0:22    0.0.0.0:*
LISTEN 0      70                               *:3306        *:*
LISTEN 0      4096                         [::1]:783     [::]:*
LISTEN 0      511                           [::]:80       [::]:*
LISTEN 0      4096 [fd7a:115c:a1e0::313b:1e06]:51593     [::]:*
"""

# `netstat -tln` prints two header lines before the data.
NETSTAT_OUTPUT = """\
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN
tcp6       0      0 ::1:3306                :::*                    LISTEN
"""


class TestAddressNormalisation(unittest.TestCase):
    def test_brackets_are_stripped(self):
        self.assertEqual(normalize_addr("[::1]"), "::1")
        self.assertEqual(normalize_addr("[fe80::1%eth0]"), "fe80::1")
        self.assertEqual(normalize_addr("127.0.0.1"), "127.0.0.1")

    def test_ipv6_loopback_is_loopback(self):
        # The bug this guards: "[::1]" never matched the literal "::1", so a
        # correctly-bound service was reported as publicly exposed.
        self.assertTrue(is_loopback("[::1]"))
        self.assertTrue(is_loopback("::1"))
        self.assertTrue(is_loopback("127.0.0.1"))
        self.assertTrue(is_loopback("127.0.0.53"))

    def test_wildcards_are_public(self):
        for addr in ("0.0.0.0", "*", "::", "[::]", "203.0.113.7"):
            self.assertTrue(is_public_addr(addr), addr)


class TestSocketParsing(unittest.TestCase):
    def test_parses_ss_output(self):
        pairs = parse_socket_lines(SS_OUTPUT)
        self.assertIn(("0.0.0.0", "2087"), pairs)
        self.assertIn(("127.0.0.1", "11234"), pairs)
        self.assertIn(("*", "3306"), pairs)
        self.assertIn(("::1", "783"), pairs)
        self.assertIn(("fd7a:115c:a1e0::313b:1e06", "51593"), pairs)

    def test_never_captures_the_peer_column(self):
        # The peer column is always "*:*"; a port must be numeric.
        for _, port in parse_socket_lines(SS_OUTPUT):
            self.assertTrue(port.isdigit())

    def test_parses_netstat_output_and_skips_headers(self):
        pairs = parse_socket_lines(NETSTAT_OUTPUT)
        self.assertEqual(sorted(pairs), [("0.0.0.0", "22"), ("::1", "3306")])

    def test_loopback_mysql_is_not_public(self):
        pairs = parse_socket_lines(NETSTAT_OUTPUT)
        public = [a for a, p in pairs if p == "3306" and is_public_addr(a)]
        self.assertEqual(public, [])


class TestParseKV(unittest.TestCase):
    def test_hash_comments(self):
        cfg = parse_kv("# comment\nTESTING = \"0\"\nTCP_IN = \"22,80\"\n")
        self.assertEqual(cfg["TESTING"], "0")
        self.assertEqual(cfg["TCP_IN"], "22,80")

    def test_semicolon_comments_for_php_ini(self):
        # php.ini comments start with ';'. Without comments=';' the commented
        # line becomes a key named ';expose_php'.
        text = "[PHP]\n;expose_php = On\nexpose_php = Off\n"
        self.assertEqual(parse_kv(text, comments=";#"), {"expose_php": "Off"})
        self.assertIn(";expose_php", parse_kv(text))

    def test_last_assignment_wins(self):
        self.assertEqual(parse_kv("a=1\na=2\n")["a"], "2")

    def test_empty_and_none_input(self):
        self.assertEqual(parse_kv(None), {})
        self.assertEqual(parse_kv(""), {})


class TestSshdParsing(unittest.TestCase):
    def test_parses_sshd_dash_t(self):
        cfg = parse_sshd_output(
            "port 22\npermitrootlogin prohibit-password\n"
            "passwordauthentication no\n")
        self.assertEqual(cfg["permitrootlogin"], "prohibit-password")
        self.assertEqual(cfg["passwordauthentication"], "no")

    def test_keys_are_lowercased(self):
        cfg = parse_sshd_output("PermitRootLogin yes\n")
        self.assertEqual(cfg["permitrootlogin"], "yes")


class TestSetConfigLine(unittest.TestCase):
    """The replacement for `sed -i`, which silently no-ops on a missing key."""

    def setUp(self):
        fd, self.path = tempfile.mkstemp()
        os.close(fd)

    def tearDown(self):
        for p in (self.path,):
            if os.path.exists(p):
                os.unlink(p)

    def _write(self, text):
        with open(self.path, "w") as fh:
            fh.write(text)

    def _read(self):
        with open(self.path) as fh:
            return fh.read()

    def test_appends_when_key_is_absent(self):
        # This is the case `sed -ri 's/^UPDATES=.*/UPDATES=daily/'` misses: it
        # exits 0 having changed nothing, so the fix reported success.
        self._write("CPANEL=release\nRPMUP=never\n")
        self.assertTrue(set_config_line(self.path, "UPDATES", "daily"))
        self.assertIn("UPDATES=daily", self._read())

    def test_replaces_existing_key(self):
        self._write("UPDATES=never\nRPMUP=never\n")
        self.assertTrue(set_config_line(self.path, "UPDATES", "daily"))
        self.assertIn("UPDATES=daily", self._read())
        self.assertNotIn("UPDATES=never", self._read())

    def test_replaces_commented_key(self):
        self._write("#UPDATES=never\n")
        self.assertTrue(set_config_line(self.path, "UPDATES", "daily"))
        self.assertEqual(self._read().strip(), "UPDATES=daily")

    def test_spaced_separator_for_csf(self):
        self._write('TESTING = "1"\n')
        self.assertTrue(set_config_line(self.path, "TESTING", '"0"',
                                        spaced=True))
        self.assertIn('TESTING = "0"', self._read())

    def test_whitespace_separator_handles_tabs(self):
        # sshd_config directives may be tab-separated; a literal-space pattern
        # would miss them and append a duplicate that sshd ignores.
        self._write("PermitRootLogin\tyes\n")
        self.assertTrue(set_config_line(self.path, "PermitRootLogin",
                                        "prohibit-password", sep=" "))
        self.assertEqual(self._read().strip(),
                         "PermitRootLogin prohibit-password")

    def test_replaces_every_occurrence(self):
        # sshd honours the FIRST occurrence, php.ini the last; rewriting all of
        # them is correct for both.
        self._write("PermitRootLogin yes\nPort 22\nPermitRootLogin yes\n")
        set_config_line(self.path, "PermitRootLogin", "no", sep=" ")
        self.assertNotIn("PermitRootLogin yes", self._read())
        self.assertEqual(self._read().count("PermitRootLogin no"), 2)

    def test_php_ini_semicolon_comment(self):
        self._write(";expose_php = On\n")
        self.assertTrue(set_config_line(self.path, "expose_php", "Off",
                                        spaced=True, comments=";#"))
        self.assertEqual(self._read().strip(), "expose_php = Off")

    def test_missing_file_returns_false(self):
        self.assertFalse(set_config_line("/nonexistent/path", "K", "v"))


class TestBackupFile(unittest.TestCase):
    def test_creates_a_timestamped_copy(self):
        fd, path = tempfile.mkstemp()
        os.close(fd)
        with open(path, "w") as fh:
            fh.write("original\n")
        dest = backup_file(path)
        try:
            self.assertIsNotNone(dest)
            self.assertTrue(os.path.isfile(dest))
            with open(dest) as fh:
                self.assertEqual(fh.read(), "original\n")
            self.assertIn(".auditor-bak-", dest)
        finally:
            os.unlink(path)
            if dest:
                os.unlink(dest)

    def test_missing_file_returns_none(self):
        self.assertIsNone(backup_file("/nonexistent/path"))


class TestPhpVersionOfIni(unittest.TestCase):
    def test_extracts_version(self):
        self.assertEqual(
            php_version_of_ini("/opt/cpanel/ea-php74/root/etc/php.ini"), "7.4")
        self.assertEqual(
            php_version_of_ini("/opt/cpanel/ea-php83/root/etc/php.ini"), "8.3")

    def test_non_ea_path(self):
        self.assertIsNone(php_version_of_ini("/etc/php.ini"))


if __name__ == "__main__":
    unittest.main()
