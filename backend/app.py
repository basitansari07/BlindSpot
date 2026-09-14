import os
ALLOW_PRIVATE = os.environ.get("ALLOW_PRIVATE_SCAN", "false").lower() == "true"
"""
app.py — Main API Server for the Vulnerability Scanner

BlindSpot Security Scanner
Provides REST endpoints for:
- Authentication
- Scan submission
- Scan status/results
- Risk scoring
- CVE enrichment
- Rule management
- JSON/HTML export
- AI-powered professional PDF security reports

Built on FastAPI + Uvicorn (ASGI), backed by a thread-based scan engine.
"""

import os
import sys
import json
import logging
import threading
import uuid as uuid_mod
import inspect
import asyncio
from datetime import datetime, timezone

# ------------------------------------------------------------
# Ensure backend directory is importable before local imports
# ------------------------------------------------------------

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))


from fastapi import FastAPI, Request, Depends, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import Response

from ai.report_generator import generate_ai_report, generate_pdf

from config import (
    ES_HOST,
    ES_USER,
    ES_PASS,
    ES_VERIFY_CERTS,
    SCAN_RULES_PATH,
    SAFE_VERSIONS_PATH,
    WAPPALYZER_DATA_PATH,
    NUCLEI_TEMPLATES_PATH,
    MAPPER_PORT,
    USERS_PATH,
    ALLOWED_ORIGINS
)

from auth import (
    require_auth,
    handle_login,
    handle_verify,
    handle_logout,
    handle_change_password,
    handle_register
)

from scanner.scan_manager import ScanOrchestrator
from engine.risk_engine import RiskScorer
from enrichment.cve_lookup import CVEEnricher


# ═══════════════════════════════════════════════════════════
#  LOGGING
# ═══════════════════════════════════════════════════════════

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)

logger = logging.getLogger(__name__)


# ═══════════════════════════════════════════════════════════
#  FASTAPI APP
# ═══════════════════════════════════════════════════════════

app = FastAPI(
    title="BlindSpot Vulnerability Scanner API",
    version="1.0.0"
)


app.add_middleware(
    CORSMiddleware,
    allow_origins=(
        ALLOWED_ORIGINS
        if ALLOWED_ORIGINS and "*" not in ALLOWED_ORIGINS
        else ["*"]
    ),
    allow_credentials=True,
    allow_methods=[
        "GET",
        "POST",
        "OPTIONS",
        "DELETE"
    ],
    allow_headers=[
        "Content-Type",
        "Authorization"
    ],
)


# ═══════════════════════════════════════════════════════════
#  SECURITY HEADERS
# ═══════════════════════════════════════════════════════════

@app.middleware("http")
async def add_security_headers(request: Request, call_next):

    response = await call_next(request)

    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"

    response.headers[
        "Cache-Control"
    ] = "no-store, no-cache, must-revalidate, max-age=0"

    return response


# ═══════════════════════════════════════════════════════════
#  ELASTICSEARCH
# ═══════════════════════════════════════════════════════════

es = None

if ES_PASS:

    try:

        from elasticsearch import Elasticsearch

        es = Elasticsearch(
            ES_HOST,
            basic_auth=(ES_USER, ES_PASS),
            verify_certs=ES_VERIFY_CERTS
        )

        if es.ping():

            logger.info(
                "[ES] Connected to Elasticsearch"
            )

        else:

            logger.warning(
                "[ES] Elasticsearch not reachable — "
                "running without ES"
            )

            es = None

    except ImportError:

        logger.warning(
            "[ES] elasticsearch package not installed — "
            "running in memory-only mode"
        )

    except Exception as e:

        logger.warning(
            f"[ES] Elasticsearch unavailable: {e} — "
            "running in memory-only mode"
        )

        es = None

else:

    logger.info(
        "[ES] No ES_PASS configured — "
        "running in memory-only mode"
    )


# ═══════════════════════════════════════════════════════════
#  CORE COMPONENTS
# ═══════════════════════════════════════════════════════════

orchestrator = ScanOrchestrator(
    es_client=es
)

cve_enricher = CVEEnricher()

_rules_lock = threading.Lock()

_rules = []


# ═══════════════════════════════════════════════════════════
#  RULE LOADING
# ═══════════════════════════════════════════════════════════

def load_all_rules():
    """
    Load scan rules from:
    - Curated rules
    - Wappalyzer
    - Nuclei
    """

    all_rules = []


    # --------------------------------------------------------
    # Curated rules
    # --------------------------------------------------------

    if os.path.exists(SCAN_RULES_PATH):

        try:

            with open(
                SCAN_RULES_PATH,
                "r"
            ) as f:

                curated = json.load(f)

            all_rules.extend(curated)

            logger.info(
                f"Loaded {len(curated)} curated scan rules"
            )

        except Exception as e:

            logger.error(
                f"Failed to load scan rules: {e}"
            )


    # --------------------------------------------------------
    # Safe versions
    # --------------------------------------------------------

    safe_versions = {}

    if os.path.exists(SAFE_VERSIONS_PATH):

        try:

            with open(
                SAFE_VERSIONS_PATH,
                "r"
            ) as f:

                safe_versions = json.load(f)

        except Exception:

            pass


    # --------------------------------------------------------
    # Wappalyzer
    # --------------------------------------------------------

    if os.path.exists(WAPPALYZER_DATA_PATH):

        try:

            from importers.wappalyzer_loader import (
                import_wappalyzer_data
            )

            wap_rules = import_wappalyzer_data(
                WAPPALYZER_DATA_PATH,
                safe_versions
            )

            all_rules.extend(wap_rules)

            logger.info(
                f"Imported {len(wap_rules)} Wappalyzer rules"
            )

        except Exception as e:

            logger.warning(
                f"Wappalyzer import failed: {e}"
            )


    # --------------------------------------------------------
    # Nuclei
    # --------------------------------------------------------

    if os.path.exists(NUCLEI_TEMPLATES_PATH):

        try:

            from importers.nuclei_loader import (
                import_nuclei_templates
            )

            nuc_rules = import_nuclei_templates(
                NUCLEI_TEMPLATES_PATH
            )

            all_rules.extend(nuc_rules)

            logger.info(
                f"Imported {len(nuc_rules)} Nuclei rules"
            )

        except Exception as e:

            logger.warning(
                f"Nuclei import failed: {e}"
            )


    return all_rules


def _init_rules():

    global _rules

    with _rules_lock:

        _rules = load_all_rules()

        orchestrator.load_rules(
            _rules
        )

    logger.info(
        f"[Init] Total detection rules loaded: {len(_rules)}"
    )


_init_rules()


# ═══════════════════════════════════════════════════════════
#  HELPERS
# ═══════════════════════════════════════════════════════════

def _is_valid_uuid(val: str) -> bool:

    try:

        uuid_mod.UUID(
            val,
            version=4
        )

        return True

    except (
        ValueError,
        AttributeError
    ):

        return False


def _build_report_data(scan_id: str, job, findings):

    """
    Build the canonical BlindSpot report structure.

    This keeps report generation consistent between:
    - JSON report endpoint
    - AI report
    - PDF generation
    - HTML export
    """

    cve_enricher.enrich_findings(
        findings
    )

    risk = orchestrator.risk_scorer.calculate(
        findings
    )

    return {

        "scan_id": scan_id,

        "target_url": job.target_url,

        "scanned_at": job.started_at,

        "completed_at": job.completed_at,

        "scan_duration_ms": job.scan_duration_ms,

        "technologies": job.technologies,

        "risk_score": risk["score"],

        "risk_grade": risk["grade"],

        "risk_grade_label": risk["grade_label"],

        "summary": risk["summary"],

        "vulnerability_summary": risk["vulnerability_summary"],

        "risk_formula": risk["risk_formula"],

        "severity_breakdown": risk["breakdown"],

        "top_fixes": risk["top_fixes"],

        "owasp_coverage": risk["owasp_coverage"],

        "total_findings": len(findings),

        "findings": findings,

        "active_probes_log": (
            getattr(
                job,
                "active_probes_log",
                []
            )
            or
            job.to_dict().get(
                "active_probes_log",
                []
            )
        )

    }


# ═══════════════════════════════════════════════════════════
#  AI REPORT HELPERS
# ═══════════════════════════════════════════════════════════

def _build_ai_input(report_data):
    """
    Build a compact, professional AI input.

    The scanner can produce hundreds of findings.
    Sending the entire raw report to an AI model is unnecessary
    and can make the generated report noisy.

    The AI receives:
    - Target information
    - Risk information
    - Severity breakdown
    - OWASP coverage
    - Top fixes
    - Finding summaries
    """

    findings = report_data.get(
        "findings",
        []
    )

    finding_summaries = []

    for finding in findings:

        finding_summaries.append({

            "title": finding.get(
                "title",
                finding.get(
                    "name",
                    "Security Finding"
                )
            ),

            "severity": finding.get(
                "severity",
                "unknown"
            ),

            "cvss_score": finding.get(
                "cvss_score",
                finding.get(
                    "cvss",
                    None
                )
            ),

            "owasp_category": finding.get(
                "owasp_category",
                ""
            ),

            "description": finding.get(
                "description",
                ""
            ),

            "evidence": finding.get(
                "evidence",
                ""
            ),

            "remediation": finding.get(
                "remediation",
                finding.get(
                    "mitigation",
                    ""
                )
            ),

            "cve": finding.get(
                "cve",
                finding.get(
                    "cve_id",
                    ""
                )
            )

        })


    return {

        "scan_id": report_data.get(
            "scan_id"
        ),

        "target_url": report_data.get(
            "target_url"
        ),

        "scanned_at": report_data.get(
            "scanned_at"
        ),

        "completed_at": report_data.get(
            "completed_at"
        ),

        "scan_duration_ms": report_data.get(
            "scan_duration_ms"
        ),

        "technologies": report_data.get(
            "technologies",
            []
        ),

        "risk_score": report_data.get(
            "risk_score"
        ),

        "risk_grade": report_data.get(
            "risk_grade"
        ),

        "risk_grade_label": report_data.get(
            "risk_grade_label"
        ),

        "summary": report_data.get(
            "summary"
        ),

        "vulnerability_summary": report_data.get(
            "vulnerability_summary",
            {}
        ),

        "severity_breakdown": report_data.get(
            "severity_breakdown",
            {}
        ),

        "owasp_coverage": report_data.get(
            "owasp_coverage",
            {}
        ),

        "top_fixes": report_data.get(
            "top_fixes",
            []
        ),

        "total_findings": report_data.get(
            "total_findings",
            len(findings)
        ),

        "findings": finding_summaries

    }


async def _call_generator(func, payload):
    """
    Safely call either synchronous or asynchronous
    AI/PDF generator functions.

    Also supports common function signatures so the
    report generator can evolve without breaking app.py.
    """

    try:

        signature = inspect.signature(
            func
        )

        parameters = signature.parameters

        # ----------------------------------------------------
        # Most common API:
        # generate_ai_report(report_data)
        # ----------------------------------------------------

        if len(parameters) == 1:

            result = func(payload)

        else:

            kwargs = {}

            if "report_data" in parameters:
                kwargs["report_data"] = payload

            elif "data" in parameters:
                kwargs["data"] = payload

            elif "scan_data" in parameters:
                kwargs["scan_data"] = payload

            elif "report" in parameters:
                kwargs["report"] = payload

            else:

                # Fallback positional call
                result = func(payload)

                if inspect.isawaitable(result):
                    result = await result

                return result

            result = func(**kwargs)


        if inspect.isawaitable(result):

            result = await result


        return result


    except TypeError as e:

        logger.error(
            f"[AI] Generator signature error: {e}"
        )

        raise


async def _generate_ai_report_content(report_data):

    """
    Generate AI report content using the existing
    ai.report_generator module.
    """

    ai_input = _build_ai_input(
        report_data
    )

    logger.info(
        "[AI] Generating professional security report "
        f"for scan {report_data['scan_id'][:8]}"
    )

    result = await _call_generator(
        generate_ai_report,
        ai_input
    )

    if result is None:

        raise RuntimeError(
            "AI report generator returned no content."
        )

    return result


async def _generate_report_pdf(
    ai_content,
    report_data
):

    """
    Generate PDF using the existing generate_pdf function.

    Supports common generator signatures.
    """

    payload = {

        "report": ai_content,

        "ai_report": ai_content,

        "report_data": report_data

    }


    try:

        signature = inspect.signature(
            generate_pdf
        )

        parameters = signature.parameters


        # ----------------------------------------------------
        # generate_pdf(report_data)
        # ----------------------------------------------------

        if len(parameters) == 1:

            pdf_result = generate_pdf(
                report_data
            )


        # ----------------------------------------------------
        # generate_pdf(report_data, output_path=None)
        # ----------------------------------------------------

        elif "report_data" in parameters:

            pdf_result = generate_pdf(
                report_data=report_data
            )


        # ----------------------------------------------------
        # generate_pdf(report)
        # ----------------------------------------------------

        elif "report" in parameters:

            pdf_result = generate_pdf(
                report=ai_content
            )


        # ----------------------------------------------------
        # generate_pdf(data)
        # ----------------------------------------------------

        elif "data" in parameters:

            pdf_result = generate_pdf(
                data=payload
            )


        else:

            pdf_result = generate_pdf(
                report_data
            )


        if inspect.isawaitable(pdf_result):

            pdf_result = await pdf_result


        return pdf_result


    except TypeError as e:

        logger.error(
            f"[PDF] Generator signature error: {e}"
        )

        raise



def _normalize_pdf_bytes(pdf_result):

    """
    Normalize different possible PDF generator return types
    into raw bytes suitable for FastAPI Response.
    """

    if pdf_result is None:

        raise RuntimeError(
            "PDF generator returned no data."
        )


    # Already bytes
    if isinstance(
        pdf_result,
        bytes
    ):

        return pdf_result


    # bytearray
    if isinstance(
        pdf_result,
        bytearray
    ):

        return bytes(
            pdf_result
        )


    # Memoryview
    if isinstance(
        pdf_result,
        memoryview
    ):

        return pdf_result.tobytes()


    # File-like object
    if hasattr(
        pdf_result,
        "read"
    ):

        content = pdf_result.read()

        if isinstance(
            content,
            bytes
        ):

            return content


    # Path returned by generator
    if isinstance(
        pdf_result,
        str
    ):

        if os.path.exists(
            pdf_result
        ):

            with open(
                pdf_result,
                "rb"
            ) as f:

                return f.read()


    raise RuntimeError(
        "Unsupported PDF generator return type: "
        f"{type(pdf_result).__name__}"
    )


# ═══════════════════════════════════════════════════════════
#  AUTH ENDPOINTS
# ═══════════════════════════════════════════════════════════

@app.post("/api/auth/login")
async def login(request: Request):

    return await handle_login(
        request
    )


@app.post("/api/auth/register")
async def register(request: Request):

    return await handle_register(
        request
    )


@app.get("/api/auth/verify")
async def verify(request: Request):

    return await handle_verify(
        request
    )


@app.post("/api/auth/logout")
async def logout(request: Request):

    return await handle_logout(
        request
    )


@app.post("/api/auth/change-password")
async def change_password(
    request: Request,
    auth_user: str = Depends(require_auth)
):

    return await handle_change_password(
        request,
        auth_user
    )


# ═══════════════════════════════════════════════════════════
#  SCAN SUBMISSION
# ═══════════════════════════════════════════════════════════

@app.post("/api/scan", status_code=202)
async def submit_scan(
    request: Request,
    auth_user: str = Depends(require_auth)
):

    data = await request.json()

    if not data:

        raise HTTPException(
            status_code=400,
            detail="Invalid request"
        )


    target_url = (
        data.get("url") or ""
    ).strip()


    if not target_url:

        raise HTTPException(
            status_code=400,
            detail="URL is required"
        )


    if not target_url.startswith(
        (
            "http://",
            "https://"
        )
    ):

        target_url = (
            "https://" +
            target_url
        )


    import ipaddress
    from urllib.parse import urlparse
    import socket


    parsed = urlparse(
        target_url
    )

    hostname = parsed.hostname


    if not hostname:

        raise HTTPException(
            status_code=400,
            detail="Invalid URL"
        )


    blocked_hosts = {

        "localhost",
        "127.0.0.1",
        "0.0.0.0",
        "::1",
        "metadata.google.internal"

    }


    if not ALLOW_PRIVATE and hostname.lower() in blocked_hosts:

        raise HTTPException(
            status_code=403,
            detail=(
                "Scanning internal/private "
                "addresses is not allowed"
            )
        )


    try:

        resolved = socket.gethostbyname(
            hostname
        )

        ip = ipaddress.ip_address(
            resolved
        )

        if (
            not ALLOW_PRIVATE
            and (
                ip.is_private
                or ip.is_loopback
                or ip.is_reserved
                or ip.is_link_local
            )
        ):

            raise HTTPException(
                status_code=403,
                detail=(
                    "Scanning internal/private "
                    "addresses is not allowed"
                )
            )

    except (
        socket.gaierror,
        ValueError
    ):

        pass


    authorized = data.get(
        "authorized",
        False
    )


    if not authorized:

        raise HTTPException(
            status_code=403,
            detail=(
                "You must confirm authorization "
                "to scan this target"
            )
        )


    custom_headers_raw = data.get("custom_headers", {})
    parsed_cookie_string = ""
    parsed_extra_headers = {}
    if isinstance(custom_headers_raw, dict):
        for key, value in custom_headers_raw.items():
            if key.lower() == "cookie":
                parsed_cookie_string = str(value)
            else:
                parsed_extra_headers[key] = str(value)

    options = {

        "deep_scan": data.get(
            "deep_scan",
            True
        ),

        "check_headers": data.get(
            "check_headers",
            True
        ),

        "check_tls": data.get(
            "check_tls",
            True
        ),

        "scan_mode": data.get(
            "scan_mode",
            "passive"
        ),

        "submitted_by": auth_user,

        "auth_cookies": (
            data.get("auth_cookies", "")
            or parsed_cookie_string
        ),

        "auth_headers": (
            data.get("auth_headers", "")
            or parsed_extra_headers
        ),

        "rate_limit": int(
            data.get(
                "rate_limit",
                0
            )
        )

    }


    valid_modes = {

        "passive",
        "light_active",
        "full_active"

    }


    if (
        options["scan_mode"]
        not in valid_modes
    ):

        options["scan_mode"] = "passive"


    job = orchestrator.submit_scan(
        target_url,
        options
    )


    logger.info(
        f"[Scan] User '{auth_user}' "
        f"submitted scan for {target_url} "
        f"(ID: {job.scan_id[:8]})"
    )


    return {

        "status": "ok",

        "scan_id": job.scan_id,

        "target_url": target_url,

        "message": (
            "Scan submitted successfully"
        )

    }


# ═══════════════════════════════════════════════════════════
#  SCAN STATUS
# ═══════════════════════════════════════════════════════════

@app.get("/api/scan/{scan_id}")
async def get_scan_status(
    scan_id: str,
    auth_user: str = Depends(require_auth)
):

    if not _is_valid_uuid(
        scan_id
    ):

        raise HTTPException(
            status_code=400,
            detail="Invalid scan ID"
        )


    job = orchestrator.get_job(
        scan_id
    )


    if not job:

        raise HTTPException(
            status_code=404,
            detail="Scan not found"
        )


    return {

        "status": "ok",

        "scan": job.to_dict()

    }


# ═══════════════════════════════════════════════════════════
#  SCAN RESULTS
# ═══════════════════════════════════════════════════════════

@app.get("/api/scan/{scan_id}/results")
async def get_scan_results(
    scan_id: str,
    severity: str = "",
    owasp: str = "",
    auth_user: str = Depends(require_auth)
):

    if not _is_valid_uuid(
        scan_id
    ):

        raise HTTPException(
            status_code=400,
            detail="Invalid scan ID"
        )


    job = orchestrator.get_job(
        scan_id
    )


    if not job:

        raise HTTPException(
            status_code=404,
            detail="Scan not found"
        )


    if job.status not in (
        "completed",
        "failed"
    ):

        return {

            "status": "ok",

            "scan_status": job.status,

            "progress": job.progress,

            "message": (
                "Scan is still in progress"
            ),

            "findings": []

        }


    findings = orchestrator.get_findings(
        scan_id
    )


    if severity:

        findings = [
            f
            for f in findings
            if f.get("severity") == severity
        ]


    if owasp:

        findings = [
            f
            for f in findings
            if owasp.lower()
            in f.get(
                "owasp_category",
                ""
            ).lower()
        ]


    return {

        "status": "ok",

        "scan_id": scan_id,

        "target_url": job.target_url,

        "scan_status": job.status,

        "total_findings": len(
            findings
        ),

        "findings": findings

    }


# ═══════════════════════════════════════════════════════════
#  STANDARD JSON REPORT
# ═══════════════════════════════════════════════════════════

@app.get("/api/scan/{scan_id}/report")
async def get_scan_report(
    scan_id: str,
    auth_user: str = Depends(require_auth)
):

    if not _is_valid_uuid(
        scan_id
    ):

        raise HTTPException(
            status_code=400,
            detail="Invalid scan ID"
        )


    job = orchestrator.get_job(
        scan_id
    )


    if not job:

        raise HTTPException(
            status_code=404,
            detail="Scan not found"
        )


    if job.status == "failed":

        return {

            "status": "error",

            "scan_status": "failed",

            "message": (
                f"Scan failed: "
                f"{job.error or 'Unknown error'}"
            ),

            "error": (
                job.error
                or
                "Unknown error"
            )

        }


    if job.status != "completed":

        return {

            "status": "ok",

            "scan_status": job.status,

            "progress": job.progress,

            "message": (
                "Scan not yet completed"
            )

        }


    findings = orchestrator.get_findings(
        scan_id
    )


    report_data = _build_report_data(
        scan_id,
        job,
        findings
    )


    return {

        "status": "ok",

        "report": report_data

    }


# ═══════════════════════════════════════════════════════════
#  AI SECURITY REPORT — PDF
# ═══════════════════════════════════════════════════════════

@app.get("/api/scan/{scan_id}/ai-report")
async def generate_ai_security_report(
    scan_id: str,
    auth_user: str = Depends(require_auth)
):

    """
    Generate a professional AI-powered BlindSpot
    security assessment report as a PDF.

    Flow:

        Scan
          ↓
        Findings
          ↓
        Risk Engine
          ↓
        AI Report Generator
          ↓
        PDF Generator
          ↓
        Browser Download
    """

    # --------------------------------------------------------
    # Validate scan ID
    # --------------------------------------------------------

    if not _is_valid_uuid(
        scan_id
    ):

        raise HTTPException(
            status_code=400,
            detail="Invalid scan ID"
        )


    # --------------------------------------------------------
    # Locate scan
    # --------------------------------------------------------

    job = orchestrator.get_job(
        scan_id
    )


    if not job:

        raise HTTPException(
            status_code=404,
            detail="Scan not found"
        )


    # --------------------------------------------------------
    # Scan must be completed
    # --------------------------------------------------------

    if job.status == "failed":

        raise HTTPException(
            status_code=400,
            detail=(
                f"Scan failed: "
                f"{job.error or 'Unknown error'}"
            )
        )


    if job.status != "completed":

        raise HTTPException(
            status_code=400,
            detail=(
                "Scan is not yet completed. "
                "Wait for the scan to finish."
            )
        )


    # --------------------------------------------------------
    # Collect findings
    # --------------------------------------------------------

    findings = orchestrator.get_findings(
        scan_id
    )


    # --------------------------------------------------------
    # Build canonical report
    # --------------------------------------------------------

    try:

        report_data = _build_report_data(
            scan_id,
            job,
            findings
        )

    except Exception as e:

        logger.exception(
            "[AI] Failed to build report data"
        )

        raise HTTPException(
            status_code=500,
            detail=(
                f"Unable to prepare security report: {e}"
            )
        )


    # --------------------------------------------------------
    # Generate AI content
    # --------------------------------------------------------

    try:

        ai_content = (
            await _generate_ai_report_content(
                report_data
            )
        )

    except Exception as e:

        logger.exception(
            "[AI] AI report generation failed"
        )

        raise HTTPException(
            status_code=500,
            detail=(
                "AI report generation failed. "
                f"{str(e)}"
            )
        )


    # --------------------------------------------------------
    # Generate PDF
    # --------------------------------------------------------

    try:

        pdf_result = (
            await _generate_report_pdf(
                ai_content,
                report_data
            )
        )

        pdf_bytes = _normalize_pdf_bytes(
            pdf_result
        )

    except Exception as e:

        logger.exception(
            "[PDF] PDF generation failed"
        )

        raise HTTPException(
            status_code=500,
            detail=(
                "PDF report generation failed. "
                f"{str(e)}"
            )
        )


    # --------------------------------------------------------
    # Validate PDF
    # --------------------------------------------------------

    if not pdf_bytes:

        raise HTTPException(
            status_code=500,
            detail="Generated PDF is empty."
        )


    if not pdf_bytes.startswith(
        b"%PDF"
    ):

        logger.warning(
            "[PDF] Generator returned data "
            "that does not begin with %PDF"
        )


    filename = (
        f"blindspot-ai-report-"
        f"{scan_id[:8]}.pdf"
    )


    logger.info(
        f"[AI] Professional PDF report generated "
        f"for scan {scan_id[:8]} "
        f"({len(pdf_bytes)} bytes)"
    )


    return Response(

        content=pdf_bytes,

        media_type="application/pdf",

        headers={

            "Content-Disposition": (
                f'attachment; filename="{filename}"'
            ),

            "Content-Length": str(
                len(pdf_bytes)
            ),

            "X-BlindSpot-Report": "AI-PDF"

        }

    )


# ═══════════════════════════════════════════════════════════
#  DELETE SCAN
# ═══════════════════════════════════════════════════════════

@app.delete("/api/scan/{scan_id}")
async def delete_scan(
    scan_id: str,
    auth_user: str = Depends(require_auth)
):

    if not _is_valid_uuid(
        scan_id
    ):

        raise HTTPException(
            status_code=400,
            detail="Invalid scan ID"
        )


    removed = orchestrator.delete_scan(
        scan_id
    )


    if not removed:

        raise HTTPException(
            status_code=404,
            detail="Scan not found"
        )


    logger.info(
        f"[Scan] User '{auth_user}' "
        f"deleted scan {scan_id[:8]}"
    )


    return {

        "status": "ok",

        "message": "Scan deleted"

    }


# ═══════════════════════════════════════════════════════════
#  EXPORT
# ═══════════════════════════════════════════════════════════

@app.get("/api/scan/{scan_id}/export")
async def export_scan_report(
    scan_id: str,
    format: str = "json",
    auth_user: str = Depends(require_auth)
):

    if not _is_valid_uuid(
        scan_id
    ):

        raise HTTPException(
            status_code=400,
            detail="Invalid scan ID"
        )


    job = orchestrator.get_job(
        scan_id
    )


    if not job:

        raise HTTPException(
            status_code=404,
            detail="Scan not found"
        )


    if job.status != "completed":

        raise HTTPException(
            status_code=400,
            detail="Scan not yet completed"
        )


    findings = orchestrator.get_findings(
        scan_id
    )


    report_data = _build_report_data(
        scan_id,
        job,
        findings
    )


    fmt = format.lower()


    # --------------------------------------------------------
    # HTML
    # --------------------------------------------------------

    if fmt == "html":

        try:

            from export.report_builder import (
                generate_html_report
            )

            html = generate_html_report(
                report_data
            )


            return Response(

                content=html,

                media_type="text/html",

                headers={

                    "Content-Disposition": (
                        "attachment; "
                        f"filename=blindspot-report-"
                        f"{scan_id[:8]}.html"
                    )

                }

            )

        except ImportError:

            raise HTTPException(
                status_code=501,
                detail=(
                    "HTML export not available"
                )
            )


    # --------------------------------------------------------
    # JSON
    # --------------------------------------------------------

    return Response(

        content=json.dumps(
            report_data,
            indent=2,
            default=str
        ),

        media_type="application/json",

        headers={

            "Content-Disposition": (
                "attachment; "
                f"filename=blindspot-report-"
                f"{scan_id[:8]}.json"
            )

        }

    )


# ═══════════════════════════════════════════════════════════
#  LIST SCANS
# ═══════════════════════════════════════════════════════════

@app.get("/api/scans")
async def list_scans(
    auth_user: str = Depends(require_auth)
):

    jobs = orchestrator.get_all_jobs()


    jobs.sort(
        key=lambda j: j.get(
            "created_at",
            ""
        ),
        reverse=True
    )


    return {

        "status": "ok",

        "total": len(jobs),

        "scans": jobs

    }


# ═══════════════════════════════════════════════════════════
#  RULES
# ═══════════════════════════════════════════════════════════

@app.get("/api/rules")
async def get_rules(
    auth_user: str = Depends(require_auth)
):

    with _rules_lock:

        rules_snapshot = _rules[:100]

        total = len(_rules)


    return {

        "status": "ok",

        "total": total,

        "rules": rules_snapshot

    }


@app.post("/api/rules/reload")
async def reload_rules(
    auth_user: str = Depends(require_auth)
):

    global _rules


    with _rules_lock:

        _rules = load_all_rules()

        orchestrator.load_rules(
            _rules
        )

        total = len(_rules)


    return {

        "status": "ok",

        "total": total,

        "message": (
            "Rules reloaded successfully"
        )

    }


# ═══════════════════════════════════════════════════════════
#  CVE ENRICHMENT
# ═══════════════════════════════════════════════════════════

@app.get("/api/cve/{cve_id}")
async def lookup_cve(
    cve_id: str,
    auth_user: str = Depends(require_auth)
):

    import re


    if not re.match(
        r'^CVE-\d{4}-\d{4,}$',
        cve_id
    ):

        raise HTTPException(
            status_code=400,
            detail="Invalid CVE ID format"
        )


    data = cve_enricher.enrich(
        cve_id
    )


    if not data:

        raise HTTPException(
            status_code=404,
            detail=(
                f"CVE {cve_id} not found"
            )
        )


    return {

        "status": "ok",

        "cve": data

    }


# ═══════════════════════════════════════════════════════════
#  STATS
# ═══════════════════════════════════════════════════════════

@app.get("/api/stats")
async def get_stats(
    auth_user: str = Depends(require_auth)
):

    jobs = orchestrator.get_all_jobs()


    total_scans = len(
        jobs
    )


    completed = sum(

        1
        for j in jobs
        if j.get("status") == "completed"

    )


    running = sum(

        1
        for j in jobs
        if j.get("status")
        in (
            "queued",
            "fetching",
            "analyzing",
            "active_probing",
            "correlating"
        )

    )


    failed = sum(

        1
        for j in jobs
        if j.get("status") == "failed"

    )


    total_findings = sum(

        j.get(
            "findings_count",
            0
        )
        for j in jobs

    )


    avg_risk = 0


    if completed > 0:

        avg_risk = round(

            sum(

                j.get(
                    "risk_score",
                    0
                )

                for j in jobs

                if j.get(
                    "status"
                ) == "completed"

            )

            /

            completed

        )


    return {

        "status": "ok",

        "total_scans": total_scans,

        "completed_scans": completed,

        "running_scans": running,

        "failed_scans": failed,

        "total_findings": total_findings,

        "average_risk_score": avg_risk

    }


# ═══════════════════════════════════════════════════════════
#  HEALTH CHECK
# ═══════════════════════════════════════════════════════════

@app.get("/api/health")
async def health():

    es_status = "disconnected"


    if es:

        try:

            es_status = (
                "connected"
                if es.ping()
                else "disconnected"
            )

        except Exception:

            es_status = "disconnected"


    with _rules_lock:

        rules_count = len(
            _rules
        )


    return {

        "status": "ok",

        "elasticsearch": es_status,

        "rules_loaded": rules_count

    }


# ═══════════════════════════════════════════════════════════
#  AUTO-CREATE ADMIN USER
# ═══════════════════════════════════════════════════════════

def ensure_admin_user():

    """
    Create a working admin user if the existing hash
    is a placeholder.
    """

    from werkzeug.security import (
        generate_password_hash
    )


    try:

        with open(
            USERS_PATH,
            "r"
        ) as f:

            users = json.load(f)


    except (
        FileNotFoundError,
        json.JSONDecodeError
    ):

        users = []


    admin = None


    for u in users:

        if u["username"] == "admin":

            admin = u

            break


    needs_reset = False


    if not admin:

        needs_reset = True


    elif admin:

        h = admin.get(
            "password_hash",
            ""
        )


        parts = h.split(
            "$"
        )


        if (
            len(parts) != 3
            or
            len(parts[2]) < 64
        ):

            needs_reset = True


        if (
            "8a5f3e2b1c9d4a7f6e5b8c3d2a1f9e8b"
            in h
        ):

            needs_reset = True


    if needs_reset:

        real_hash = generate_password_hash(
            "admin123",
            method="pbkdf2:sha256",
            salt_length=16
        )


        if admin:

            admin["password_hash"] = (
                real_hash
            )


            logger.info(
                "[Init] Reset admin password "
                "to 'admin123' "
                "(placeholder hash detected)"
            )


        else:

            users.append({

                "username": "admin",

                "password_hash": real_hash,

                "role": "admin"

            })


            logger.info(
                "[Init] Created admin user "
                "with password 'admin123'"
            )


        with open(
            USERS_PATH,
            "w"
        ) as f:

            json.dump(
                users,
                f,
                indent=4
            )


ensure_admin_user()


# ═══════════════════════════════════════════════════════════
#  MAIN
# ═══════════════════════════════════════════════════════════

if __name__ == "__main__":

    import uvicorn


    logger.info(
        "=" * 60
    )

    logger.info(
        "  BlindSpot Vulnerability Scanner Backend Starting"
    )

    logger.info(
        f"  Port: {MAPPER_PORT}"
    )


    with _rules_lock:

        logger.info(
            f"  Rules loaded: {len(_rules)}"
        )


    logger.info(
        "  AI Report: enabled"
    )

    logger.info(
        "  PDF Report: enabled"
    )


    logger.info(
        f"  Elasticsearch: "
        f"{'connected' if es else 'memory-only mode'}"
    )


    logger.info(
        "=" * 60
    )


    uvicorn.run(
        app,
        host="0.0.0.0",
        port=MAPPER_PORT
    )
