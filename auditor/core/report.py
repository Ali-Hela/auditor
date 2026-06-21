"""Terminal + log file reporting."""

import datetime
import sys
from typing import Dict, List, Optional

from .model import Finding, Severity, Status

ANSI = {
    "reset": "\033[0m", "bold": "\033[1m", "dim": "\033[2m",
    "green": "\033[32m", "red": "\033[31m", "yellow": "\033[33m",
    "cyan": "\033[36m", "grey": "\033[90m", "white": "\033[97m",
}

GLYPH = {
    Status.OK: "✔", Status.FAIL: "✘", Status.WARN: "▲",
    Status.INFO: "\U0001f6c8", Status.SKIP: "–",
}
# ASCII fallback for terminals whose encoding cannot represent the glyphs
# (e.g. a server running under the C / POSIX locale).
GLYPH_ASCII = {
    Status.OK: "+", Status.FAIL: "x", Status.WARN: "!",
    Status.INFO: "i", Status.SKIP: "-",
}
COLOR = {
    Status.OK: "green", Status.FAIL: "red", Status.WARN: "yellow",
    Status.INFO: "cyan", Status.SKIP: "grey",
}


def _encoding_supports_glyphs():
    """True if stdout can encode the Unicode glyphs we want to print."""
    enc = getattr(sys.stdout, "encoding", None)
    try:
        "".join(GLYPH.values()).encode(enc or "ascii")
        "─→".encode(enc or "ascii")
        return True
    except (UnicodeEncodeError, LookupError, TypeError):
        return False


class Reporter:
    """Streams findings to the terminal (colorized) and buffers a plain log."""

    def __init__(self, log_path: Optional[str] = None, use_color: Optional[bool] = None,
                 quiet: bool = False):
        self.log_path = log_path
        self.quiet = quiet
        self.use_color = sys.stdout.isatty() if use_color is None else use_color
        self.log_lines: List[str] = []
        self.findings: List[Finding] = []
        self.counts: Dict[Status, int] = {s: 0 for s in Status}
        self._cat: Optional[str] = None
        # Pick glyph set + separators based on what the terminal can encode.
        if _encoding_supports_glyphs():
            self.glyphs = GLYPH
            self.rule = "─"
            self.arrow = "→"
        else:
            self.glyphs = GLYPH_ASCII
            self.rule = "-"
            self.arrow = "->"

    # -- low level -------------------------------------------------------
    def _c(self, text: str, *styles: str) -> str:
        if not self.use_color:
            return text
        prefix = "".join(ANSI[s] for s in styles)
        return prefix + text + ANSI["reset"]

    def _out(self, term: str = "", plain: Optional[str] = None, log: bool = True,
             screen: bool = True):
        if screen:
            print(term)
        if log:
            self.log_lines.append(term if plain is None else plain)

    # -- structure -------------------------------------------------------
    def banner(self, version: str, host: str):
        ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        title = "  AUDITOR v%s  -  cPanel/WHM Security Audit" % version
        bar = "=" * 64
        self._out(self._c(bar, "cyan"), bar)
        self._out(self._c(title, "bold", "white"), title)
        self._out(self._c("  Host: %s    %s" % (host, ts), "dim"),
                  "  Host: %s    %s" % (host, ts))
        self._out(self._c(bar, "cyan"), bar)
        self._out()

    def category(self, name: str):
        # In quiet mode, category headers are logged but not shown on screen.
        scr = not self.quiet
        self._cat = name
        line = "  %s" % name.upper()
        rule = "  " + self.rule * (len(name))
        self._out(screen=scr)
        self._out(self._c(line, "bold", "cyan"), line, screen=scr)
        self._out(self._c(rule, "dim"), rule, screen=scr)

    def finding(self, f: Finding):
        self.findings.append(f)
        self.counts[f.status] += 1
        # In quiet mode only problems (FAIL/WARN) are shown on screen; the rest
        # are still written to the log.
        scr = not (self.quiet and f.status in (Status.OK, Status.INFO, Status.SKIP))
        glyph = self.glyphs[f.status]
        color = COLOR[f.status]
        sev = ""
        if f.status == Status.FAIL:
            sev = "  [%s]" % f.severity.name
        head_plain = "  %s %s%s" % (glyph, f.title, sev)
        head_term = "  %s %s%s" % (
            self._c(glyph, color),
            self._c(f.title, "bold") if f.status == Status.FAIL else f.title,
            self._c(sev, "red", "bold") if sev else "",
        )
        self._out(head_term, head_plain, screen=scr)
        if f.detail:
            for line in f.detail.splitlines():
                d_plain = "      %s" % line
                self._out(self._c(d_plain, "dim"), d_plain, screen=scr)
        if f.remediation and f.status in (Status.FAIL, Status.WARN):
            rem = f.remediation
            tag = "fix" if rem.automatable else "manual"
            r_plain = "      %s (%s) %s" % (self.arrow, tag, rem.summary)
            self._out(self._c(r_plain, "grey"), r_plain, screen=scr)

    def note(self, text: str):
        self._out(self._c("      %s" % text, "grey"), "      %s" % text)

    def prompt(self, question: str) -> str:
        """Interactive y/n/a/q prompt. Returns a single lowercase char."""
        msg = self._c("      ? %s [y]es/[n]o/[A]ll-skip/[q]uit: " % question,
                      "yellow", "bold")
        try:
            ans = input(msg).strip().lower()
        except (EOFError, KeyboardInterrupt):
            return "q"
        return (ans[:1] or "n")

    # -- summary ---------------------------------------------------------
    def summary(self) -> int:
        ok = self.counts[Status.OK]
        fail = self.counts[Status.FAIL]
        warn = self.counts[Status.WARN]
        info = self.counts[Status.INFO]
        skip = self.counts[Status.SKIP]
        scored = ok + fail + warn
        score = int(round(100 * ok / scored)) if scored else 100

        bar = "=" * 64
        self._out()
        self._out(self._c(bar, "cyan"), bar)
        self._out(self._c("  SUMMARY", "bold", "white"), "  SUMMARY")
        self._out(self._c(bar, "cyan"), bar)
        row = "  %s %-9s %s %-9s %s %-9s %s %-7s %s %s" % (
            self._c(self.glyphs[Status.OK], "green"), "%d OK" % ok,
            self._c(self.glyphs[Status.FAIL], "red"), "%d fail" % fail,
            self._c(self.glyphs[Status.WARN], "yellow"), "%d warn" % warn,
            self._c(self.glyphs[Status.INFO], "cyan"), "%d info" % info,
            self._c(self.glyphs[Status.SKIP], "grey"), "%d skip" % skip,
        )
        row_plain = "  %d OK   %d fail   %d warn   %d info   %d skip" % (
            ok, fail, warn, info, skip)
        self._out(row, row_plain)

        score_color = "green" if score >= 90 else "yellow" if score >= 70 else "red"
        sline = "  Security score: %d%%  (%d/%d passing checks)" % (score, ok, scored)
        self._out(self._c(sline, score_color, "bold"), sline)

        if fail or warn:
            self._out()
            self._out(self._c("  Top items to address:", "bold"),
                      "  Top items to address:")
            problems = [f for f in self.findings if f.is_problem]
            problems.sort(key=lambda f: (-f.severity, f.status.value))
            for f in problems[:10]:
                g = self.glyphs[f.status]
                line = "    %s %s" % (g, f.title)
                self._out(self._c(line, COLOR[f.status]), line)
        self._out(self._c(bar, "cyan"), bar)
        return fail

    def write_log(self, version: str, host: str):
        if not self.log_path:
            return
        ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        header = [
            "Auditor v%s security audit log" % version,
            "Host: %s" % host,
            "Generated: %s" % ts,
            "",
        ]
        try:
            with open(self.log_path, "w", encoding="utf-8") as fh:
                fh.write("\n".join(header + self.log_lines) + "\n")
        except OSError as e:
            print("  (could not write log to %s: %s)" % (self.log_path, e))
