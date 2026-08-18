"""Auditor CLI entry point.

Default run is a read-only audit. Use --fix to opt into guided remediation.
"""

import argparse
import os
import socket
import sys

from . import __version__
from . import checks
from .core.model import Finding, Severity, Status
from .core.registry import all_checks, categories
from .core.remediate import Remediator
from .core.report import Reporter
from .core.util import is_cpanel

EXIT_OK = 0
EXIT_FINDINGS = 1
EXIT_NOT_ROOT = 2
EXIT_USAGE = 3


def build_parser():
    p = argparse.ArgumentParser(
        prog="auditor",
        description="cPanel/WHM server security audit & guided remediation.")
    p.add_argument("--fix", action="store_true",
                   help="interactively apply fixes for failed checks")
    p.add_argument("-y", "--yes", action="store_true",
                   help="with --fix, apply every non-risky fix without prompting")
    p.add_argument("--dangerous", action="store_true",
                   help="with --fix, also offer fixes that can lock you out "
                        "(sshd, firewall); these always prompt")
    p.add_argument("--category", action="append", default=[],
                   metavar="NAME", help="only run checks in this category "
                   "(repeatable, case-insensitive substring)")
    p.add_argument("--only", default="", metavar="IDS",
                   help="comma-separated check IDs to run")
    p.add_argument("--quiet", action="store_true",
                   help="show only problems (FAIL/WARN) on screen")
    p.add_argument("--no-color", dest="color", action="store_false",
                   default=None, help="disable colored output")
    p.add_argument("--color", dest="color", action="store_true",
                   help="force colored output")
    p.add_argument("--log", default=os.path.join(os.getcwd(), "auditor.log"),
                   metavar="PATH", help="log file path (default ./auditor.log)")
    p.add_argument("--no-log", action="store_true", help="do not write a log file")
    p.add_argument("--log-truncate", action="store_true",
                   help="overwrite the log instead of appending to it")
    p.add_argument("--json", metavar="PATH", default=None,
                   help="write a machine-readable report to PATH "
                        "('-' for stdout, which silences the normal report)")
    p.add_argument("--list", action="store_true",
                   help="list all checks and exit")
    p.add_argument("--list-categories", action="store_true",
                   help="list category names usable with --category and exit")
    p.add_argument("-V", "--version", action="version",
                   version="auditor %s" % __version__)
    return p


def select_checks(args):
    """Return (specs, error). ``error`` is a message when a filter is bogus."""
    specs = all_checks()
    if args.only:
        wanted = {s.strip().upper() for s in args.only.split(",") if s.strip()}
        known = {c.id.upper() for c in specs}
        unknown = sorted(wanted - known)
        if unknown:
            return [], ("unknown check ID(s): %s\nRun --list to see every ID."
                        % ", ".join(unknown))
        specs = [c for c in specs if c.id.upper() in wanted]
    if args.category:
        cats = [c.lower() for c in args.category]
        specs = [c for c in specs
                 if any(sub in c.category.lower() for sub in cats)]
        if not specs:
            return [], ("no category matched: %s\nRun --list-categories to see "
                        "the names." % ", ".join(args.category))
    return specs, None


def do_list():
    cur = None
    for c in all_checks():
        if c.category != cur:
            cur = c.category
            print("\n%s" % cur)
        print("  %-18s %s" % (c.id, c.title))


def main(argv=None):
    checks.load_all()
    args = build_parser().parse_args(argv)

    if args.list:
        do_list()
        return EXIT_OK
    if args.list_categories:
        for name in categories():
            print(name)
        return EXIT_OK

    if not args.fix and (args.yes or args.dangerous):
        print("--yes and --dangerous only apply together with --fix.",
              file=sys.stderr)
        return EXIT_USAGE

    # Validate filters before the root check: a bad flag is a usage error, and
    # you should not need sudo to be told about it.
    specs, error = select_checks(args)
    if error:
        print(error, file=sys.stderr)
        return EXIT_USAGE

    if os.geteuid() != 0:
        print("auditor must be run as root (sudo ./auditor.sh). Many checks "
              "read privileged config files.", file=sys.stderr)
        return EXIT_NOT_ROOT

    to_stdout = args.json == "-"
    reporter = Reporter(
        log_path=None if args.no_log else args.log,
        use_color=args.color,
        quiet=args.quiet,
        silent=to_stdout,
        log_append=not args.log_truncate)
    remediator = (Remediator(reporter, assume_yes=args.yes,
                             allow_risky=args.dangerous)
                  if args.fix else None)

    host = socket.gethostname()
    reporter.banner(__version__, host)
    if not is_cpanel():
        reporter.note("cPanel not detected - cPanel-specific checks will be "
                      "skipped.")

    last_cat = None
    for spec in specs:
        if spec.category != last_cat:
            reporter.category(spec.category)
            last_cat = spec.category
        try:
            results = list(spec.func())
        except Exception as e:  # a broken check must not abort the audit
            results = [Finding(spec.id, spec.title, Status.WARN,
                               "Check raised an error: %s" % e, Severity.LOW)]
        for finding in results:
            finding.category = spec.category
            reporter.finding(finding)
            if remediator is not None:
                remediator.handle(finding, spec)

    # Fixes are applied inline as findings stream, and a verified fix revises
    # its finding's status, so the summary and exit code below already describe
    # the server as it is after remediation.
    fails = reporter.summary()
    if remediator is not None:
        remediator.summary()
    reporter.write_log(__version__, host)
    if args.json:
        reporter.write_json(args.json, __version__, host)

    # Exit code: 0 if clean, 1 if any FAIL remains.
    return EXIT_FINDINGS if fails else EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
