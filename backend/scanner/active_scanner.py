"""
active_scanner.py — Active Vulnerability Probes

Non-destructive active probes that verify vulnerabilities by injecting
safe test payloads into discovered parameters.

Probe Types:
  1. Reflected XSS Canary
  2. Error-Based SQL Injection
  3. Time-Based Blind SQL Injection
  4. Local File Inclusion / Path Traversal
  5. CRLF / Header Injection
  6. Open Redirect

All probes use the existing async Fetcher.
Supports GET query parameter injection and POST body form injection.
"""

import re
import uuid

from scanner.rule_scanner import Finding
import time
import asyncio
import logging

from datetime import datetime, timezone
from urllib.parse import urlparse, urlencode, parse_qs, urlunparse

import sys
import os

sys.path.insert(
    0,
    os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
)

from config import (
    ACTIVE_REQUEST_DELAY,
    MAX_ACTIVE_PROBES_PER_TARGET,
    ACTIVE_XSS_CANARY,
    BLIND_SQLI_SLEEP_SECONDS,
    BLIND_SQLI_THRESHOLD,
)

logger = logging.getLogger(__name__)


# ═══════════════════════════════════════════════════════════
# BLIND SQLi PAYLOADS
# ═══════════════════════════════════════════════════════════

BLIND_SQLI_PAYLOADS = [
    ("' OR SLEEP({sleep})-- ", "MySQL SLEEP"),
    ("' OR pg_sleep({sleep})-- ", "PostgreSQL pg_sleep"),
    ("'; WAITFOR DELAY '00:00:0{sleep}'-- ", "MSSQL WAITFOR"),
]


# ═══════════════════════════════════════════════════════════
# SQL ERROR SIGNATURES
# ═══════════════════════════════════════════════════════════

SQL_ERROR_PATTERNS = [
    r"you have an error in your sql syntax",
    r"unclosed quotation mark",
    r"mysql_",
    r"pg_query",
    r"pg_exec",
    r"ora-\d{5}",
    r"microsoft ole db provider",
    r"sqlite3\.operationalerror",
    r"sqlstate\[",
    r"syntax error at or near",
    r"unterminated quoted string",
    r"quoted string not properly terminated",
]


# ═══════════════════════════════════════════════════════════
# LFI / PATH TRAVERSAL INDICATORS
# ═══════════════════════════════════════════════════════════

# IMPORTANT:
# Generic strings such as "localhost" are intentionally NOT used.
# They are too common and produce false positives.

LFI_INDICATORS = [
    r"root:x:0:0:[^<\r\n]*",
    r"\[fonts\]",
    r"\[extensions\]",
    r";\s*for\s+16-bit\s+app",
    r"daemon:x:\d+:\d+:",
    r"nobody:x:\d+:\d+:",
]


LFI_PAYLOADS = [
    "../../../../etc/passwd",
    "..\\..\\..\\..\\windows\\win.ini",
    "....//....//....//....//etc/passwd",
]


# ═══════════════════════════════════════════════════════════
# OPEN REDIRECT PARAMETER NAMES
# ═══════════════════════════════════════════════════════════

OPEN_REDIRECT_PARAM_NAMES = {
    "url",
    "redirect",
    "next",
    "callback",
    "dest",
    "destination",
    "uri",
    "target",
    "return",
    "return_to",
    "returnto",
    "goto",
    "link",
    "redirect_uri",
    "redirect_url",
    "continue",
    "forward",
    "out",
}


# ═══════════════════════════════════════════════════════════
# MAIN ACTIVE SCANNER
# ═══════════════════════════════════════════════════════════

def run_active_probes(fetcher, surface, scan_id, scan_mode="full_active"):
    return asyncio.run(
        _run_active_probes_async(fetcher, surface, scan_id, scan_mode)
    )


async def _run_active_probes_async(
    fetcher: Fetcher,
    surface: AttackSurface,
    scan_id: str,
    scan_mode: str = "full_active",
) -> tuple:
    """
    Run active probes against discovered attack surface.

    Returns:
        (findings, probe_logs)
    """

    findings = []
    probe_logs = []

    if not surface.params:
        logger.info(
            f"[Active {scan_id[:8]}] "
            f"No parameters found — skipping active probes"
        )
        return findings, probe_logs

    logger.info(
        f"[Active {scan_id[:8]}] Running {scan_mode} probes against "
        f"{len(surface.params)} parameters"
    )

    async def _probe_param(param):
        param_findings = []
        param_logs = []

        is_post = param.source == "form_post"

        # ---------------------------------------------------
        # Probe 1: Reflected XSS
        # ---------------------------------------------------

        res_finding, log_item = await _probe_xss(
            fetcher,
            param,
            scan_id,
            use_post=is_post,
        )

        if log_item:
            param_logs.append(log_item)

        if res_finding:
            param_findings.append(res_finding)

        # ---------------------------------------------------
        # Probe 2: Error-Based SQLi
        # ---------------------------------------------------

        res_finding, log_item = await _probe_sqli(
            fetcher,
            param,
            scan_id,
            use_post=is_post,
        )

        if log_item:
            param_logs.append(log_item)

        if res_finding:
            param_findings.append(res_finding)

        # ---------------------------------------------------
        # Full Active Only
        # ---------------------------------------------------

        if scan_mode == "full_active":

            # Probe 3: Time-Based Blind SQLi
            res_finding, log_item = await _probe_blind_sqli(
                fetcher,
                param,
                scan_id,
                use_post=is_post,
            )

            if log_item:
                param_logs.append(log_item)

            if res_finding:
                param_findings.append(res_finding)

            # Probe 4: LFI
            if param.is_file_param:

                res_finding, log_item = await _probe_lfi(
                    fetcher,
                    param,
                    scan_id,
                    use_post=is_post,
                )

                if log_item:
                    param_logs.append(log_item)

                if res_finding:
                    param_findings.append(res_finding)

            # Probe 5: CRLF
            res_finding, log_item = await _probe_crlf(
                fetcher,
                param,
                scan_id,
                use_post=is_post,
            )

            if log_item:
                param_logs.append(log_item)

            if res_finding:
                param_findings.append(res_finding)

            # Probe 6: Open Redirect
            res_finding, log_item = await _probe_open_redirect(
                fetcher,
                param,
                scan_id,
            )

            if log_item:
                param_logs.append(log_item)

            if res_finding:
                param_findings.append(res_finding)

        return param_findings, param_logs

    params_to_probe = surface.params[
        :MAX_ACTIVE_PROBES_PER_TARGET
    ]

    results = await asyncio.gather(
        *[_probe_param(p) for p in params_to_probe],
        return_exceptions=True,
    )

    for item in results:

        if isinstance(item, tuple) and len(item) == 2:

            p_findings, p_logs = item

            findings.extend(p_findings)
            probe_logs.extend(p_logs)

        elif isinstance(item, Exception):

            logger.debug(
                f"[Active {scan_id[:8]}] "
                f"Probe task error: {item}"
            )

    logger.info(
        f"[Active {scan_id[:8]}] Completed probes on "
        f"{len(params_to_probe)} params, "
        f"executed {len(probe_logs)} probes, "
        f"found {len(findings)} active findings"
    )

    return findings, probe_logs


# ═══════════════════════════════════════════════════════════
# PROBE 1 — REFLECTED XSS
# ═══════════════════════════════════════════════════════════

async def _probe_xss(
    fetcher: Fetcher,
    param: ParamTarget,
    scan_id: str,
    use_post: bool = False,
):

    canary = (
        f"{ACTIVE_XSS_CANARY}_"
        f"{uuid.uuid4().hex[:8]}"
        f"'\">"
    )

    probe_url, post_data = _prepare_injection(
        param,
        canary,
        use_post=use_post,
    )

    if not probe_url:
        return None, None

    method_str = "POST" if use_post else "GET"

    finding = None

    log_item = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "param_name": param.param_name,
        "probe_type": f"Reflected XSS Canary ({method_str})",
        "target_url": probe_url,
        "payload": canary,
        "status_code": 0,
        "vulnerable": False,
        "details": (
            "Input sanitized or omitted from HTML body (Safe)"
        ),
    }

    try:

        if use_post:

            result = fetcher.fetch_post(
                probe_url,
                data=post_data,
                timeout=3,
            )

        else:

            result = fetcher.fetch(
                probe_url,
                timeout=3,
            )

        if not result:
            return None, log_item

        log_item["status_code"] = result.status_code

        body = result.body or ""

        if canary in body:

            log_item["vulnerable"] = True

            log_item["details"] = (
                "Unescaped canary string reflected "
                "verbatim in response body"
            )

            evidence_log = (
                "[ACTIVE PROBE EXECUTION LOG]\n"
                f"METHOD & TARGET : "
                f"{method_str} {probe_url}\n"
                f"POST DATA       : "
                f"{post_data if use_post else 'N/A'}\n"
                f"PAYLOAD INJECTED: {canary}\n"
                f"HTTP STATUS     : {result.status_code}\n"
                "VERIFICATION    : "
                "Unescaped canary string reflected "
                "verbatim in HTML response body."
            )

            finding = _make_finding(
                scan_id=scan_id,
                target_url=probe_url,
                title=(
                    f"Reflected XSS — Parameter "
                    f"'{param.param_name}' ({method_str})"
                ),
                description=(
                    f"The parameter '{param.param_name}' "
                    f"({method_str}) reflected the injected "
                    f"canary without HTML encoding. "
                    f"The exact canary appeared in the "
                    f"response body."
                ),
                severity="high",
                owasp="A03:2021-Injection",
                cwe="CWE-79",
                evidence=evidence_log,
                remediation=(
                    "Encode user-controlled data according to "
                    "its output context before rendering. "
                    "Use context-aware output encoding and "
                    "CSP as defense-in-depth."
                ),
            )

    except Exception as e:

        logger.debug(
            f"[XSS Probe] Error on "
            f"{param.param_name}: {e}"
        )

        log_item["details"] = (
            f"Network/Timeout error: {e}"
        )

    return finding, log_item


# ═══════════════════════════════════════════════════════════
# PROBE 2 — ERROR-BASED SQLi
# ═══════════════════════════════════════════════════════════

async def _probe_sqli(
    fetcher: Fetcher,
    param: ParamTarget,
    scan_id: str,
    use_post: bool = False,
):

    payload = f"{param.param_value}'"

    probe_url, post_data = _prepare_injection(
        param,
        payload,
        use_post=use_post,
    )

    if not probe_url:
        return None, None

    method_str = "POST" if use_post else "GET"

    finding = None

    log_item = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "param_name": param.param_name,
        "probe_type": f"Error-Based SQLi ({method_str})",
        "target_url": probe_url,
        "payload": payload,
        "status_code": 0,
        "vulnerable": False,
        "details": (
            "No database error signature detected "
            "in response (Safe)"
        ),
    }

    try:

        if use_post:

            result = fetcher.fetch_post(
                probe_url,
                data=post_data,
                timeout=3,
            )

        else:

            result = fetcher.fetch(
                probe_url,
                timeout=3,
            )

        if not result:
            return None, log_item

        log_item["status_code"] = result.status_code

        body = result.body or ""

        if not body:
            return None, log_item

        body_lower = body.lower()

        for pattern in SQL_ERROR_PATTERNS:

            match = re.search(
                pattern,
                body_lower,
            )

            if not match:
                continue

            log_item["vulnerable"] = True

            matched_signature = match.group(0)[:120]

            log_item["details"] = (
                "Database error matched signature: "
                f"'{matched_signature}'"
            )

            evidence_log = (
                "[ACTIVE PROBE EXECUTION LOG]\n"
                f"METHOD & TARGET : "
                f"{method_str} {probe_url}\n"
                f"POST DATA       : "
                f"{post_data if use_post else 'N/A'}\n"
                f"PAYLOAD INJECTED: {payload}\n"
                f"HTTP STATUS     : {result.status_code}\n"
                f"VERIFICATION    : Database error matched "
                f"signature: '{matched_signature}'"
            )

            finding = _make_finding(
                scan_id=scan_id,
                target_url=probe_url,
                title=(
                    f"SQL Injection — Parameter "
                    f"'{param.param_name}' ({method_str})"
                ),
                description=(
                    f"Appending a single quote to the "
                    f"'{param.param_name}' parameter caused "
                    f"a database error signature to appear "
                    f"in the response."
                ),
                severity="critical",
                owasp="A03:2021-Injection",
                cwe="CWE-89",
                evidence=evidence_log,
                remediation=(
                    "Use parameterized queries or prepared "
                    "statements for database operations. "
                    "Never concatenate user input into SQL."
                ),
            )

            break

    except Exception as e:

        logger.debug(
            f"[SQLi Probe] Error on "
            f"{param.param_name}: {e}"
        )

        log_item["details"] = (
            f"Network/Timeout error: {e}"
        )

    return finding, log_item


# ═══════════════════════════════════════════════════════════
# PROBE 3 — TIME-BASED BLIND SQLi
# ═══════════════════════════════════════════════════════════

async def _probe_blind_sqli(
    fetcher: Fetcher,
    param: ParamTarget,
    scan_id: str,
    use_post: bool = False,
):

    method_str = "POST" if use_post else "GET"

    baseline_url, baseline_post = _prepare_injection(
        param,
        "mapper_baseline_1",
        use_post=use_post,
    )

    if not baseline_url:
        return None, None

    baseline_samples = []

    # Two baselines reduce timing noise.
    for baseline_value in (
        "mapper_baseline_1",
        "mapper_baseline_2",
    ):

        test_url, test_post = _prepare_injection(
            param,
            baseline_value,
            use_post=use_post,
        )

        if not test_url:
            continue

        try:

            started = time.monotonic()

            if use_post:

                fetcher.fetch_post(
                    test_url,
                    data=test_post,
                    timeout=8,
                )

            else:

                fetcher.fetch(
                    test_url,
                    timeout=8,
                )

            baseline_samples.append(
                time.monotonic() - started
            )

        except Exception as e:

            logger.debug(
                f"[Blind SQLi] Baseline error on "
                f"{param.param_name}: {e}"
            )

    if not baseline_samples:

        return None, {
            "timestamp": datetime.now(
                timezone.utc
            ).isoformat(),
            "param_name": param.param_name,
            "probe_type": (
                f"Time-Based Blind SQLi "
                f"({method_str})"
            ),
            "target_url": baseline_url,
            "payload": None,
            "status_code": 0,
            "vulnerable": False,
            "details": (
                "Unable to establish reliable baseline; "
                "timing result is inconclusive"
            ),
        }

    baseline_time = max(baseline_samples)

    last_log = None

    for payload_template, db_label in BLIND_SQLI_PAYLOADS:

        payload = payload_template.format(
            sleep=BLIND_SQLI_SLEEP_SECONDS
        )

        probe_url, post_data = _prepare_injection(
            param,
            payload,
            use_post=use_post,
        )

        if not probe_url:
            continue

        log_item = {
            "timestamp": datetime.now(
                timezone.utc
            ).isoformat(),
            "param_name": param.param_name,
            "probe_type": (
                f"Time-Based Blind SQLi "
                f"({db_label}) ({method_str})"
            ),
            "target_url": probe_url,
            "payload": payload,
            "status_code": 0,
            "vulnerable": False,
            "details": (
                f"Baseline max: {baseline_time:.2f}s — "
                "Testing for delayed response"
            ),
        }

        last_log = log_item

        try:

            started = time.monotonic()

            if use_post:

                result = fetcher.fetch_post(
                    probe_url,
                    data=post_data,
                    timeout=(
                        BLIND_SQLI_SLEEP_SECONDS + 5
                    ),
                )

            else:

                result = fetcher.fetch(
                    probe_url,
                    timeout=(
                        BLIND_SQLI_SLEEP_SECONDS + 5
                    ),
                )

            elapsed = time.monotonic() - started

            if result:
                log_item["status_code"] = (
                    result.status_code
                )

            delay_delta = (
                elapsed - baseline_time
            )

            # Require BOTH an absolute delay and a
            # relative increase over the baseline.
            required_minimum = max(
                baseline_time * 2.0,
                baseline_time + 1.0,
            )

            if (
                delay_delta >= BLIND_SQLI_THRESHOLD
                and elapsed >= required_minimum
            ):

                log_item["vulnerable"] = True

                log_item["details"] = (
                    f"RESPONSE DELAYED {elapsed:.2f}s "
                    f"(baseline max {baseline_time:.2f}s, "
                    f"delta +{delay_delta:.2f}s) — "
                    f"Blind SQLi ({db_label}) CONFIRMED"
                )

                evidence_log = "\n".join([
                    "[ACTIVE PROBE EXECUTION LOG]",
                    (
                        f"Probe Type: Time-Based Blind SQLi "
                        f"({db_label}) ({method_str})"
                    ),
                    f"Target: {probe_url}",
                    (
                        f"POST Data: "
                        f"{post_data if use_post else 'N/A'}"
                    ),
                    f"Payload: {payload}",
                    (
                        "Baseline Samples: "
                        + ", ".join(
                            f"{x:.2f}s"
                            for x in baseline_samples
                        )
                    ),
                    (
                        f"Baseline Max: "
                        f"{baseline_time:.2f}s"
                    ),
                    (
                        f"Probed Response: "
                        f"{elapsed:.2f}s"
                    ),
                    (
                        f"Delta: "
                        f"+{delay_delta:.2f}s"
                    ),
                    (
                        f"Required Delta: "
                        f"{BLIND_SQLI_THRESHOLD:.2f}s"
                    ),
                    (
                        f"Required Minimum Response: "
                        f"{required_minimum:.2f}s"
                    ),
                    (
                        "Verdict: VULNERABLE — "
                        "Significant delayed response confirmed"
                    ),
                ])

                finding = Finding(
                    id=str(uuid.uuid4()),
                    scan_id=scan_id,
                    target_url=probe_url,
                    timestamp=datetime.now(
                        timezone.utc
                    ).isoformat(),
                    source_tool="active_probe",
                    type="vulnerability",
                    severity="critical",
                    title=(
                        f"Time-Based Blind SQL Injection "
                        f"({db_label}) ({method_str})"
                    ),
                    description=(
                        f"Parameter '{param.param_name}' "
                        f"({method_str}) produced a significant "
                        f"server-side response delay using "
                        f"a {db_label} time-delay payload. "
                        f"Observed response: {elapsed:.2f}s; "
                        f"baseline: {baseline_time:.2f}s; "
                        f"delta: +{delay_delta:.2f}s."
                    ),
                    owasp_category=(
                        "A03:2021-Injection"
                    ),
                    cwe="CWE-89",
                    evidence_location="response_time",
                    evidence_snippet=evidence_log,
                    remediation=(
                        "Use parameterized queries / "
                        "prepared statements. "
                        "Never concatenate user input into SQL."
                    ),
                )

                return finding, log_item

            log_item["details"] = (
                f"Response: {elapsed:.2f}s "
                f"(baseline max {baseline_time:.2f}s, "
                f"delta +{delay_delta:.2f}s) — "
                "Below confirmation threshold; Safe"
            )

        except asyncio.TimeoutError:

            # CRITICAL:
            # Timeout is NOT a vulnerability by itself.
            log_item["vulnerable"] = False

            log_item["details"] = (
                f"Request timed out after "
                f"{BLIND_SQLI_SLEEP_SECONDS + 5}s "
                f"(baseline max {baseline_time:.2f}s) — "
                "inconclusive; timeout alone is NOT "
                "treated as Blind SQLi"
            )

            logger.debug(
                f"[Blind SQLi] Timeout on "
                f"{param.param_name} ({db_label}) — "
                "not counted as vulnerability"
            )

            continue

        except Exception as e:

            logger.debug(
                f"[Blind SQLi] Error on "
                f"{param.param_name} "
                f"({db_label}): {e}"
            )

            log_item["details"] = (
                f"Network error: {e}"
            )

    return None, last_log


# ═══════════════════════════════════════════════════════════
# PROBE 4 — LFI / PATH TRAVERSAL
# ═══════════════════════════════════════════════════════════

async def _probe_lfi(
    fetcher: Fetcher,
    param: ParamTarget,
    scan_id: str,
    use_post: bool = False,
):

    method_str = "POST" if use_post else "GET"

    last_log = None

    for payload in LFI_PAYLOADS:

        probe_url, post_data = _prepare_injection(
            param,
            payload,
            use_post=use_post,
        )

        if not probe_url:
            continue

        log_item = {
            "timestamp": datetime.now(
                timezone.utc
            ).isoformat(),
            "param_name": param.param_name,
            "probe_type": (
                f"Path Traversal (LFI) "
                f"({method_str})"
            ),
            "target_url": probe_url,
            "payload": payload,
            "status_code": 0,
            "vulnerable": False,
            "details": (
                "No strong system-file signature "
                "detected in response (Safe)"
            ),
        }

        last_log = log_item

        try:

            if use_post:

                result = fetcher.fetch_post(
                    probe_url,
                    data=post_data,
                    timeout=3,
                )

            else:

                result = fetcher.fetch(
                    probe_url,
                    timeout=3,
                )

            if not result:
                continue

            log_item["status_code"] = (
                result.status_code
            )

            body = result.body or ""

            if not body:
                continue

            body_lower = body.lower()

            for pattern in LFI_INDICATORS:

                match = re.search(
                    pattern,
                    body_lower,
                )

                if not match:
                    continue

                log_item["vulnerable"] = True

                matched_indicator = (
                    match.group(0)[:120]
                )

                log_item["details"] = (
                    "Strong system-file signature "
                    f"matched: '{matched_indicator}'"
                )

                evidence_log = (
                    "[ACTIVE PROBE EXECUTION LOG]\n"
                    f"METHOD & TARGET : "
                    f"{method_str} {probe_url}\n"
                    f"POST DATA       : "
                    f"{post_data if use_post else 'N/A'}\n"
                    f"PAYLOAD INJECTED: {payload}\n"
                    f"HTTP STATUS     : "
                    f"{result.status_code}\n"
                    f"VERIFICATION    : Strong system-file "
                    f"signature matched: "
                    f"'{matched_indicator}'"
                )

                finding = _make_finding(
                    scan_id=scan_id,
                    target_url=probe_url,
                    title=(
                        f"Local File Inclusion / Path Traversal "
                        f"— Parameter '{param.param_name}' "
                        f"({method_str})"
                    ),
                    description=(
                        f"The parameter '{param.param_name}' "
                        f"({method_str}) accepted a path traversal "
                        f"payload and the response contained a "
                        f"strong operating-system file signature."
                    ),
                    severity="critical",
                    owasp=(
                        "A01:2021-Broken Access Control"
                    ),
                    cwe="CWE-22",
                    evidence=evidence_log,
                    remediation=(
                        "Never use user-controlled input directly "
                        "in filesystem paths. Apply strict "
                        "allowlisting and canonicalize paths "
                        "before access."
                    ),
                )

                return finding, log_item

        except Exception as e:

            logger.debug(
                f"[LFI Probe] Error on "
                f"{param.param_name}: {e}"
            )

            log_item["details"] = (
                f"Network/Timeout error: {e}"
            )

    return None, last_log


# ═══════════════════════════════════════════════════════════
# PROBE 5 — CRLF / HEADER INJECTION
# ═══════════════════════════════════════════════════════════

async def _probe_crlf(
    fetcher: Fetcher,
    param: ParamTarget,
    scan_id: str,
    use_post: bool = False,
):

    method_str = "POST" if use_post else "GET"

    marker = "X-Mapper-Injected"

    payload = (
        f"{param.param_value}"
        f"%0d%0a"
        f"{marker}:1"
    )

    probe_url, post_data = _prepare_injection(
        param,
        payload,
        use_post=use_post,
    )

    if not probe_url:
        return None, None

    log_item = {
        "timestamp": datetime.now(
            timezone.utc
        ).isoformat(),
        "param_name": param.param_name,
        "probe_type": (
            f"CRLF / Header Injection "
            f"({method_str})"
        ),
        "target_url": probe_url,
        "payload": payload,
        "status_code": 0,
        "vulnerable": False,
        "details": (
            "Injected header not observed "
            "in response headers (Safe)"
        ),
    }

    try:

        if use_post:

            result = fetcher.fetch_post(
                probe_url,
                data=post_data,
                timeout=3,
            )

        else:

            result = fetcher.fetch(
                probe_url,
                timeout=3,
            )

        if not result:
            return None, log_item

        log_item["status_code"] = (
            result.status_code
        )

        response_headers = (
            result.headers or {}
        )

        # Header-name check is case-insensitive.
        injected_header = any(
            str(header_name).lower()
            == marker.lower()
            for header_name in response_headers
        )

        if injected_header:

            log_item["vulnerable"] = True

            log_item["details"] = (
                f"Injected header '{marker}: 1' "
                "appeared in response headers"
            )

            evidence_log = (
                "[ACTIVE PROBE EXECUTION LOG]\n"
                f"METHOD & TARGET : "
                f"{method_str} {probe_url}\n"
                f"POST DATA       : "
                f"{post_data if use_post else 'N/A'}\n"
                f"PAYLOAD INJECTED: {payload}\n"
                f"HTTP STATUS     : {result.status_code}\n"
                f"VERIFICATION    : Injected header "
                f"'{marker}: 1' appeared in response headers."
            )

            finding = _make_finding(
                scan_id=scan_id,
                target_url=probe_url,
                title=(
                    f"CRLF / Header Injection — "
                    f"Parameter '{param.param_name}' "
                    f"({method_str})"
                ),
                description=(
                    f"The parameter '{param.param_name}' "
                    f"({method_str}) accepted CRLF characters "
                    f"and caused the injected header "
                    f"'{marker}: 1' to appear in the "
                    "HTTP response headers."
                ),
                severity="high",
                owasp="A03:2021-Injection",
                cwe="CWE-113",
                evidence=evidence_log,
                remediation=(
                    "Reject or safely encode CR and LF characters "
                    "before user-controlled data reaches HTTP "
                    "header construction."
                ),
            )

            return finding, log_item

    except Exception as e:

        logger.debug(
            f"[CRLF Probe] Error on "
            f"{param.param_name}: {e}"
        )

        log_item["details"] = (
            f"Network/Timeout error: {e}"
        )

    return None, log_item


# ═══════════════════════════════════════════════════════════
# PROBE 6 — OPEN REDIRECT
# ═══════════════════════════════════════════════════════════

async def _probe_open_redirect(
    fetcher: Fetcher,
    param: ParamTarget,
    scan_id: str,
):

    if (
        param.param_name.lower()
        not in OPEN_REDIRECT_PARAM_NAMES
    ):
        return None, None

    marker_host = "mapper-redirect-check.example"

    payload = (
        f"https://{marker_host}/"
    )

    probe_url = _inject_param(
        param,
        payload,
    )

    if not probe_url:
        return None, None

    log_item = {
        "timestamp": datetime.now(
            timezone.utc
        ).isoformat(),
        "param_name": param.param_name,
        "probe_type": "Open Redirect (GET)",
        "target_url": probe_url,
        "payload": payload,
        "status_code": 0,
        "vulnerable": False,
        "details": (
            "Server did not redirect to "
            "the injected external host (Safe)"
        ),
    }

    try:

        result = fetcher.fetch(
            probe_url,
            timeout=3,
            follow_redirects=False,
        )

        if not result:
            return None, log_item

        log_item["status_code"] = (
            result.status_code
        )

        response_headers = (
            result.headers or {}
        )

        location = ""

        for header_name, header_value in response_headers.items():

            if str(header_name).lower() == "location":

                location = str(
                    header_value or ""
                )

                break

        body_lower = (
            result.body or ""
        ).lower()

        redirected_externally = (
            marker_host.lower()
            in location.lower()
        )

        reflected_client_redirect = (
            marker_host.lower() in body_lower
            and (
                (
                    "meta" in body_lower
                    and "refresh" in body_lower
                )
                or "location.href" in body_lower
                or "window.location" in body_lower
            )
        )

        if (
            redirected_externally
            or reflected_client_redirect
        ):

            log_item["vulnerable"] = True

            if redirected_externally:

                evidence_source = (
                    "HTTP Location header"
                )

            else:

                evidence_source = (
                    "client-side redirect "
                    "script/meta-refresh"
                )

            log_item["details"] = (
                "Server redirected to injected "
                f"external host via {evidence_source}"
            )

            evidence_log = (
                "[ACTIVE PROBE EXECUTION LOG]\n"
                f"METHOD & TARGET : GET {probe_url}\n"
                f"PAYLOAD INJECTED: {payload}\n"
                f"HTTP STATUS     : {result.status_code}\n"
                f"VERIFICATION    : Redirected to "
                f"external host via {evidence_source}."
            )

            finding = _make_finding(
                scan_id=scan_id,
                target_url=probe_url,
                title=(
                    f"Open Redirect — Parameter "
                    f"'{param.param_name}' (GET)"
                ),
                description=(
                    f"The parameter '{param.param_name}' "
                    "accepted an external redirect target. "
                    f"The injected host '{marker_host}' "
                    "was used as the redirect destination."
                ),
                severity="medium",
                owasp=(
                    "A01:2021-Broken Access Control"
                ),
                cwe="CWE-601",
                evidence=evidence_log,
                remediation=(
                    "Validate redirect destinations against "
                    "an allowlist. Prefer relative internal "
                    "paths instead of arbitrary absolute URLs."
                ),
            )

            return finding, log_item

    except Exception as e:

        logger.debug(
            f"[Open Redirect Probe] Error on "
            f"{param.param_name}: {e}"
        )

        log_item["details"] = (
            f"Network/Timeout error: {e}"
        )

    return None, log_item


# ═══════════════════════════════════════════════════════════
# HELPERS
# ═══════════════════════════════════════════════════════════

def _prepare_injection(
    param: ParamTarget,
    payload: str,
    use_post: bool = False,
) -> tuple:
    """
    Returns:
        (probe_url, post_data)

    POST:
        Target URL remains param.url and the parameter is
        injected into the POST form body.

    GET:
        Parameter is replaced in the query string.
    """

    if use_post:

        post_data = {
            param.param_name: payload
        }

        return param.url, post_data

    probe_url = _inject_param(
        param,
        payload,
    )

    return probe_url, None


def _inject_param(
    param: ParamTarget,
    payload: str,
) -> str:
    """
    Build a URL with the payload injected into the
    target query parameter.
    """

    try:

        parsed = urlparse(
            param.url
        )

        query_params = parse_qs(
            parsed.query,
            keep_blank_values=True,
        )

        query_params[
            param.param_name
        ] = [payload]

        new_query = urlencode(
            query_params,
            doseq=True,
        )

        return urlunparse(
            (
                parsed.scheme,
                parsed.netloc,
                parsed.path,
                parsed.params,
                new_query,
                parsed.fragment,
            )
        )

    except Exception as e:

        logger.debug(
            f"[Inject] Failed to build "
            f"probe URL: {e}"
        )

        return ""


def _make_finding(
    scan_id: str,
    target_url: str,
    title: str,
    description: str,
    severity: str,
    owasp: str,
    cwe: str,
    evidence: str,
    remediation: str,
) -> Finding:
    """
    Create a Finding from an active probe result.
    """

    return Finding(
        id=str(uuid.uuid4()),
        scan_id=scan_id,
        target_url=target_url,
        timestamp=datetime.now(
            timezone.utc
        ).isoformat(),
        source_tool="active_probe",
        type="vulnerability",
        severity=severity,
        title=title,
        description=description,
        owasp_category=owasp,
        cwe=cwe,
        evidence_location="parameter",
        evidence_snippet=evidence[:500],
        remediation=remediation,
    )
