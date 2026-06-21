"""Auditor CLI entry point.

Default run is a read-only audit. Use --fix to opt into guided remediation.
"""

import argparse
import os
import socket
import sys

from . import __version__
from . import checks  # noqa: F401  (imports register every check)
from .core.model import Status
from .core.registry import all_checks, categories
from .core.remediate import Remediator
from .core.report import Reporter
from .core.util import is_cpanel


def build_parser():
    p = argparse.ArgumentParser(
        prog="auditor",
        description="cPanel/WHM server security audit & guided remediation.")
    p.add_argument("--fix", action="store_true",
                   help="interactively apply fixes for failed checks")
    p.add_argument("-y", "--yes", action="store_true",
                   help="with --fix, apply every fix without prompting")
    p.add_argument("--category", action="append", default=[],
                   metavar="NAME", help="only run checks in this category "
                   "(repeatable, case-insensitive substring)")
    p.add_argument("--only", default="", metavar="IDS",
                   help="comma-separated check IDs to run")
    p.add_argument("--quiet", action="store_true",
                   help="show only problems (FAIL/WARN) on screen")
    p.add_argument("--no-color", action="store_true",
                   help="disable colored output")
    p.add_argument("--log", default=os.path.join(os.getcwd(), "auditor.log"),
                   metavar="PATH", help="log file path (default ./auditor.log)")
    p.add_argument("--no-log", action="store_true", help="do not write a log file")
    p.add_argument("--list", action="store_true",
                   help="list all checks and exit")
    p.add_argument("-V", "--version", action="version",
                   version="auditor %s" % __version__)
    return p


def select_checks(args):
    specs = all_checks()
    if args.only:
        wanted = {s.strip().upper() for s in args.only.split(",") if s.strip()}
        specs = [c for c in specs if c.id.upper() in wanted]
    if args.category:
        cats = [c.lower() for c in args.category]
        specs = [c for c in specs
                 if any(sub in c.category.lower() for sub in cats)]
    return specs


def do_list():
    cur = None
    for c in all_checks():
        if c.category != cur:
            cur = c.category
            print("\n%s" % cur)
        print("  %-18s %s" % (c.id, c.title))


def main(argv=None):
    args = build_parser().parse_args(argv)

    if args.list:
        do_list()
        return 0

    if os.geteuid() != 0:
        print("auditor must be run as root (sudo ./auditor). Many checks read "
              "privileged config files.", file=sys.stderr)
        return 2

    reporter = Reporter(
        log_path=None if args.no_log else args.log,
        use_color=False if args.no_color else None,
        quiet=args.quiet)
    remediator = Remediator(reporter, assume_yes=args.yes) if args.fix else None

    host = socket.gethostname()
    reporter.banner(__version__, host)
    if not is_cpanel():
        reporter.note("cPanel not detected - cPanel-specific checks will be "
                      "skipped.")

    specs = select_checks(args)
    if not specs:
        reporter.note("No checks matched the given filters.")
        return 0

    last_cat = None
    for spec in specs:
        if spec.category != last_cat:
            reporter.category(spec.category)
            last_cat = spec.category
        try:
            results = list(spec.func())
        except Exception as e:  # a broken check must not abort the audit
            from .core.model import Finding, Severity
            results = [Finding(spec.id, spec.title, Status.WARN,
                               "Check raised an error: %s" % e, Severity.LOW)]
        for finding in results:
            reporter.finding(finding)
            if remediator is not None:
                remediator.handle(finding)

    fails = reporter.summary()
    if remediator is not None:
        remediator.summary()
    reporter.write_log(__version__, host)

    # Exit code: 0 if clean, 1 if any FAIL remains.
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
