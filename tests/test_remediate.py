"""Tests for the remediation engine.

The behaviour that matters: a fix is only counted as applied when re-running
the check proves it worked, risky fixes stay behind --dangerous, and neither
path can be reached by a read-only audit.
"""

import unittest
from unittest import mock

from auditor.core.model import Finding, Remediation, Severity, Status
from auditor.core.registry import CheckSpec
from auditor.core.remediate import Remediator
from auditor.core.report import Reporter


def spec_yielding(*statuses):
    """A CheckSpec whose successive runs yield the given statuses."""
    seq = iter(statuses)

    def func():
        yield Finding("T-1", "test", next(seq))
    return CheckSpec("T-1", "test", "Test", func)


def failing_finding(**rem_kwargs):
    kwargs = {"summary": "do the thing", "commands": ["true"]}
    kwargs.update(rem_kwargs)
    return Finding("T-1", "test", Status.FAIL, "", Severity.HIGH,
                   Remediation(**kwargs))


class RemediatorCase(unittest.TestCase):
    def setUp(self):
        self.reporter = Reporter(log_path=None, use_color=False, silent=True)
        self.notes = []
        self.reporter.note = self.notes.append

    def remediator(self, **kwargs):
        return Remediator(self.reporter, **kwargs)


class TestVerification(RemediatorCase):
    def test_fix_that_works_is_counted_applied(self):
        finding = failing_finding()
        self.reporter.finding(finding)
        rem = self.remediator(assume_yes=True)
        with mock.patch("auditor.core.remediate.run", return_value=(0, "", "")):
            rem.handle(finding, spec_yielding(Status.OK))
        self.assertEqual((rem.applied, rem.failed), (1, 0))
        self.assertIn("Applied and verified.", self.notes)

    def test_fix_that_silently_does_nothing_is_counted_failed(self):
        """`sed -i` on a missing key exits 0 while changing nothing.

        Exit status alone said "applied"; re-running the check says otherwise.
        """
        finding = failing_finding()
        self.reporter.finding(finding)
        rem = self.remediator(assume_yes=True)
        with mock.patch("auditor.core.remediate.run", return_value=(0, "", "")):
            rem.handle(finding, spec_yielding(Status.FAIL))
        self.assertEqual((rem.applied, rem.failed), (0, 1))
        self.assertTrue(any("did not take effect" in n for n in self.notes))

    def test_verified_fix_revises_the_summary_counts(self):
        finding = failing_finding()
        self.reporter.finding(finding)
        self.assertEqual(self.reporter.counts[Status.FAIL], 1)
        rem = self.remediator(assume_yes=True)
        with mock.patch("auditor.core.remediate.run", return_value=(0, "", "")):
            rem.handle(finding, spec_yielding(Status.OK))
        self.assertEqual(self.reporter.counts[Status.FAIL], 0)
        self.assertEqual(self.reporter.counts[Status.OK], 1)
        self.assertEqual(finding.status, Status.OK)
        self.assertEqual(finding.remediated_from, Status.FAIL)

    def test_command_failure_never_reaches_verification(self):
        finding = failing_finding()
        rem = self.remediator(assume_yes=True)
        with mock.patch("auditor.core.remediate.run", return_value=(1, "", "boom")):
            rem.handle(finding, spec_yielding(Status.OK))
        self.assertEqual((rem.applied, rem.failed), (0, 1))

    def test_without_a_spec_the_fix_is_flagged_unverified(self):
        finding = failing_finding()
        rem = self.remediator(assume_yes=True)
        with mock.patch("auditor.core.remediate.run", return_value=(0, "", "")):
            rem.handle(finding, None)
        self.assertEqual(rem.applied, 1)
        self.assertIn("Applied (not verified).", self.notes)


class TestRiskGating(RemediatorCase):
    def test_risky_fix_is_withheld_without_dangerous(self):
        finding = failing_finding(risk="can lock you out")
        rem = self.remediator(assume_yes=True, allow_risky=False)
        with mock.patch("auditor.core.remediate.run") as run:
            rem.handle(finding, spec_yielding(Status.OK))
            run.assert_not_called()
        self.assertEqual(rem.blocked, 1)
        self.assertEqual(rem.applied, 0)

    def test_risky_fix_still_prompts_under_yes(self):
        finding = failing_finding(risk="can lock you out")
        rem = self.remediator(assume_yes=True, allow_risky=True)
        self.reporter.prompt = mock.Mock(return_value="n")
        with mock.patch("auditor.core.remediate.run") as run:
            rem.handle(finding, spec_yielding(Status.OK))
            run.assert_not_called()
        self.reporter.prompt.assert_called_once()
        self.assertEqual(rem.skipped, 1)

    def test_risky_fix_applies_when_confirmed(self):
        finding = failing_finding(risk="can lock you out")
        self.reporter.finding(finding)
        rem = self.remediator(assume_yes=True, allow_risky=True)
        self.reporter.prompt = mock.Mock(return_value="y")
        with mock.patch("auditor.core.remediate.run", return_value=(0, "", "")):
            rem.handle(finding, spec_yielding(Status.OK))
        self.assertEqual(rem.applied, 1)


class TestPromptHandling(RemediatorCase):
    def _run(self, answer):
        finding = failing_finding()
        rem = self.remediator()
        self.reporter.prompt = mock.Mock(return_value=answer)
        with mock.patch("auditor.core.remediate.run", return_value=(0, "", "")):
            rem.handle(finding, spec_yielding(Status.OK))
        return rem

    def test_no_skips(self):
        self.assertEqual(self._run("n").skipped, 1)

    def test_s_skips_everything_after(self):
        rem = self._run("s")
        self.assertTrue(rem.skip_all)
        self.assertEqual(rem.skipped, 1)

    def test_q_stops_fixing(self):
        rem = self._run("q")
        self.assertTrue(rem.quit)
        self.assertEqual(rem.applied, 0)

    def test_eof_is_treated_as_quit(self):
        # Piping input to --fix must not silently apply anything.
        reporter = Reporter(log_path=None, use_color=False, silent=True)
        with mock.patch("builtins.input", side_effect=EOFError):
            self.assertEqual(reporter.prompt("x?"), "q")


class TestScope(RemediatorCase):
    def test_non_problem_findings_are_never_fixed(self):
        for status in (Status.OK, Status.INFO, Status.SKIP):
            finding = Finding("T-1", "t", status, "", Severity.INFO,
                              Remediation("s", commands=["true"]))
            rem = self.remediator(assume_yes=True)
            with mock.patch("auditor.core.remediate.run") as run:
                rem.handle(finding, spec_yielding(Status.OK))
                run.assert_not_called()
            self.assertEqual(rem.applied, 0)

    def test_manual_only_remediation_prints_guidance(self):
        finding = Finding("T-1", "t", Status.FAIL, "", Severity.HIGH,
                          Remediation("s", manual="do it by hand"))
        rem = self.remediator(assume_yes=True)
        with mock.patch("auditor.core.remediate.run") as run:
            rem.handle(finding, spec_yielding(Status.OK))
            run.assert_not_called()
        self.assertIn("Manual fix: do it by hand", self.notes)

    def test_backups_are_taken_before_the_fix(self):
        finding = failing_finding(backup_files=["/etc/example.conf"])
        rem = self.remediator(assume_yes=True)
        with mock.patch("auditor.core.remediate.backup_file",
                        return_value="/etc/example.conf.bak") as backup, \
                mock.patch("auditor.core.remediate.run", return_value=(0, "", "")):
            rem.handle(finding, spec_yielding(Status.OK))
            backup.assert_called_once_with("/etc/example.conf")
        self.assertEqual(rem.backups, ["/etc/example.conf.bak"])


if __name__ == "__main__":
    unittest.main()
