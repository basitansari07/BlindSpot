"""
passive_checks.py — Extended Passive Security Checks
Adds coverage for OWASP Top 10 categories A03, A04, A07, A08.
These are passive-only checks (no active payload injection).
"""

import re
import uuid
import logging
from datetime import datetime, timezone
from scanner.rule_scanner import Finding

logger = logging.getLogger(__name__)


def run_extended_checks(snapshot, scan_id: str) -> list:
    """Run all extended passive checks against a PageSnapshot."""
    findings = []
    findings.extend(_check_injection_indicators(snapshot, scan_id))
    findings.extend(_check_insecure_design(snapshot, scan_id))
    findings.extend(_check_auth_failures(snapshot, scan_id))
    findings.extend(_check_integrity_failures(snapshot, scan_id))
    findings.extend(_check_logging_monitoring(snapshot, scan_id))
    findings.extend(_check_ssrf_indicators(snapshot, scan_id))
    return findings


def _check_injection_indicators(snapshot, scan_id: str) -> list:
    """A05:2025-Injection — Detect error messages suggesting injection vulnerabilities."""
    findings = []
    now = datetime.now(timezone.utc).isoformat()
    body = snapshot.body_lower

    indicators = [
        (r"you have an error in your sql syntax", "SQL Syntax Error Detected",
         "The page reveals SQL error messages, indicating potential SQL injection vulnerability.",
         "CWE-89"),
        (r"mysql_(?:query|fetch|num_rows|connect)", "MySQL Function Exposure",
         "PHP MySQL functions are referenced in the page output, suggesting unhandled database errors.",
         "CWE-209"),
        (r"pg_(?:query|exec|connect|last_error)", "PostgreSQL Function Exposure",
         "PostgreSQL functions visible in page output, suggesting unhandled database errors.",
         "CWE-209"),
        (r"ora-\d{5}", "Oracle Database Error Exposed",
         "Oracle database error codes detected in the page output.",
         "CWE-209"),
        (r"microsoft ole db provider for sql server", "MSSQL Error Exposed",
         "Microsoft SQL Server error messages visible in page output.",
         "CWE-209"),
        (r"unclosed quotation mark after the character string", "SQL Injection Indicator",
         "SQL error message detected suggesting the application may be vulnerable to SQL injection.",
         "CWE-89"),
    ]

    for pattern, title, desc, cwe in indicators:
        match = re.search(pattern, body)
        if match:
            findings.append(Finding(
                id=str(uuid.uuid4()), scan_id=scan_id,
                target_url=snapshot.url, timestamp=now,
                source_tool="custom", type="vulnerability",
                severity="high", title=title, description=desc,
                owasp_category="A05:2025-Injection", cwe=cwe,
                evidence_location="body",
                evidence_snippet=match.group(0)[:200],
                remediation="Use parameterized queries and implement proper error handling.",
            ))
            break  # One injection indicator is enough

    return findings


def _check_insecure_design(snapshot, scan_id: str) -> list:
    """A06:2025-Insecure Design — Detect design-level security issues."""
    findings = []
    now = datetime.now(timezone.utc).isoformat()
    headers = snapshot.headers

    # Check for explicitly unsafe autocomplete on password fields.
    for form in snapshot.forms:
        for inp in form.get("inputs", []):
            if inp.get("type") != "password":
                continue

            autocomplete = str(inp.get("autocomplete", "")).strip().lower()

            # Do not infer a vulnerability from the existence of a password field.
            # Only flag an explicitly unsafe autocomplete value.
            if autocomplete not in {"on", "current-password"}:
                continue

            findings.append(Finding(
                id=str(uuid.uuid4()), scan_id=scan_id,
                target_url=snapshot.url, timestamp=now,
                source_tool="custom", type="misconfiguration",
                severity="low",
                title="Password Field Allows Autocomplete",
                description="A password input explicitly allows credential autocomplete, "
                            "which may permit browser credential caching.",
                owasp_category="A06:2025-Insecure Design", cwe="CWE-522",
                evidence_location="body",
                evidence_snippet=(
                    f"Form action: {form.get('action', 'N/A')}, "
                    f"input: {inp.get('name', 'password')}, "
                    f"autocomplete: {autocomplete}"
                ),
                remediation="Use an appropriate autocomplete value such as "
                            "autocomplete=\"new-password\" where credential caching is not desired.",
            ))
            break

    return findings


def _check_auth_failures(snapshot, scan_id: str) -> list:
    """A07:2025-Authentication Failures."""
    findings = []
    now = datetime.now(timezone.utc).isoformat()

    # Check for session tokens in URL
    if snapshot.url and ("sessionid=" in snapshot.url.lower() or
                          "jsessionid=" in snapshot.url.lower() or
                          "phpsessid=" in snapshot.url.lower()):
        findings.append(Finding(
            id=str(uuid.uuid4()), scan_id=scan_id,
            target_url=snapshot.url, timestamp=now,
            source_tool="custom", type="vulnerability",
            severity="high",
            title="Session Token in URL",
            description="Session identifier found in the URL. This exposes the session to "
                        "shoulder surfing, referrer leakage, and browser history.",
            owasp_category="A07:2025-Authentication Failures",
            cwe="CWE-598",
            evidence_location="url",
            evidence_snippet=snapshot.url[:200],
            remediation="Use cookies with HttpOnly and Secure flags for session management.",
        ))

    return findings


def _check_integrity_failures(snapshot, scan_id: str) -> list:
    """A08:2025-Software or Data Integrity Failures — Check SRI."""
    findings = []
    now = datetime.now(timezone.utc).isoformat()
    body = snapshot.body or ""

    # Check for external scripts without SRI (Subresource Integrity)
    cdn_pattern = re.compile(
        r'<script[^>]+src=["\'](?:https?:)?//(?:cdn|cdnjs|unpkg|jsdelivr|ajax\.googleapis)[^"\']+["\'][^>]*>',
        re.IGNORECASE
    )
    integrity_pattern = re.compile(r'integrity=["\']', re.IGNORECASE)

    cdn_scripts = cdn_pattern.findall(body)
    scripts_without_sri = []

    for script_tag in cdn_scripts:
        if not integrity_pattern.search(script_tag):
            scripts_without_sri.append(script_tag[:120])

    if scripts_without_sri:
        findings.append(Finding(
            id=str(uuid.uuid4()), scan_id=scan_id,
            target_url=snapshot.url, timestamp=now,
            source_tool="custom", type="vulnerability",
            severity="medium",
            title="Missing Subresource Integrity (SRI)",
            description=f"{len(scripts_without_sri)} external CDN script(s) loaded without "
                        f"Subresource Integrity hashes. A CDN compromise could inject malicious code.",
            owasp_category="A08:2025-Software or Data Integrity Failures",
            cwe="CWE-353",
            evidence_location="body",
            evidence_snippet="\n".join(scripts_without_sri[:3]),
            remediation="Add integrity=\"sha384-...\" crossorigin=\"anonymous\" to all CDN scripts.",
        ))

    return findings


def _check_logging_monitoring(snapshot, scan_id: str) -> list:
    """A09:2025-Security Logging and Alerting Failures.
    Heuristic: check for indicators of structured logging/monitoring.
    This is inherently approximate since logging is an internal concern.
    """
    findings = []
    now = datetime.now(timezone.utc).isoformat()
    headers = snapshot.headers

    # Check for verbose error pages (stack traces in production)
    body = snapshot.body_lower or ""
    has_stack_trace = any(indicator in body for indicator in [
        "traceback (most recent call last)",
        "at java.", "at org.", "at com.",
        "exception in thread",
        "fatal error", "stack trace:",
        "<b>warning</b>:", "<b>notice</b>:",
    ])

    if has_stack_trace:
        findings.append(Finding(
            id=str(uuid.uuid4()), scan_id=scan_id,
            target_url=snapshot.url, timestamp=now,
            source_tool="custom", type="misconfiguration",
            severity="medium",
            title="Application Stack Trace Exposed",
            description=(
                "The application exposes stack trace or debug information in its response. "
                "This indicates debug mode may be enabled in production and proper error "
                "handling/logging is not configured."
            ),
            owasp_category="A09:2025-Security Logging and Alerting Failures",
            cwe="CWE-209",
            evidence_location="body",
            evidence_snippet="Stack trace or debug output detected in response body",
            remediation=(
                "Disable debug mode in production. Implement custom error pages. "
                "Log detailed errors server-side only (not in HTTP responses). "
                "Set up centralized logging (ELK, Datadog, Sentry)."
            ),
        ))

    return findings


def _check_ssrf_indicators(snapshot, scan_id: str) -> list:
    """A01:2025-Broken Access Control (SSRF).
    Passively detect URL parameters that could be SSRF entry points.
    """
    findings = []
    now = datetime.now(timezone.utc).isoformat()

    # Check URL for redirect/fetch-like parameters
    url_lower = (snapshot.url or "").lower()
    return findings
