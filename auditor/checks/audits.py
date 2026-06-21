"""Section 10 - Security audits and best practices."""

from ..core.model import Finding, Remediation, Severity, Status
from ..core.registry import register
from ..core.util import is_cpanel

CAT = "Audits & Best Practices"
REF = "cPanel checklist #10: Security audits and best practices"


@register("AUD-ADVISOR", "cPanel Security Advisor", CAT, order=10)
def security_advisor():
    if not is_cpanel():
        yield Finding("AUD-ADVISOR", "Security Advisor (cPanel only)",
                      Status.SKIP, reference=REF)
        return
    yield Finding("AUD-ADVISOR", "Run cPanel Security Advisor", Status.INFO,
                  "Security Advisor surfaces vulnerabilities and recommended "
                  "settings inside WHM.", Severity.INFO,
                  Remediation(
                      "Open Security Advisor",
                      manual="WHM > Security Center > Security Advisor."),
                  reference=REF)


@register("AUD-SCHEDULE", "Periodic security audits", CAT, order=20)
def schedule():
    yield Finding("AUD-SCHEDULE", "Perform regular security audits", Status.INFO,
                  "Run this auditor (daily/weekly) and a manual review each "
                  "quarter; track trends in the log.", Severity.INFO,
                  Remediation("Automate periodic audits",
                              manual="Add a cron job for ./auditor and review "
                                     "auditor.log."),
                  reference=REF)


@register("AUD-TRAINING", "Staff & user awareness", CAT, order=30)
def training():
    yield Finding("AUD-TRAINING", "Educate users and staff", Status.INFO,
                  "Train on strong/unique passwords and phishing awareness.",
                  Severity.INFO, reference=REF)


@register("AUD-MAILINGLIST", "cPanel security updates", CAT, order=40)
def mailing_list():
    yield Finding("AUD-MAILINGLIST", "Subscribe to cPanel security alerts",
                  Status.INFO,
                  "Apply cPanel security patches promptly; subscribe to the "
                  "cPanel security mailing list / advisories.", Severity.INFO,
                  Remediation("Subscribe to advisories",
                              manual="https://news.cpanel.com/ "
                                     "(Security category)."),
                  reference=REF)
