"""
BlindSpot — Local AI-Style Security Report Generator

No OpenAI/API key required.

Provides:
    generate_ai_report(report_data)
    generate_pdf(report_data, output_path=None)

The generator turns BlindSpot's structured scanner output into:
    - Executive summary
    - Risk overview
    - Severity analysis
    - OWASP coverage
    - Prioritized findings
    - Technical details
    - Remediation guidance

Designed to work with the existing app.py integration.
"""

import os
import re
import json
import math
from datetime import datetime
from collections import Counter, defaultdict

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
    PageBreak,
    KeepTogether,
)
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.pdfbase import pdfmetrics


# ============================================================
# CONFIGURATION
# ============================================================

REPORT_TITLE = "BlindSpot Security Assessment Report"
PRODUCT_NAME = "BLINDSPOT"


OWASP_2025_MAP = {
    "A01:2021": "A01:2025-Broken Access Control",
    "A02:2021": "A04:2025-Cryptographic Failures",
    "A03:2021": "A05:2025-Injection",
    "A04:2021": "A06:2025-Insecure Design",
    "A05:2021": "A02:2025-Security Misconfiguration",
    "A06:2021": "A03:2025-Software Supply Chain Failures",
    "A07:2021": "A07:2025-Authentication Failures",
    "A08:2021": "A08:2025-Software or Data Integrity Failures",
    "A09:2021": "A09:2025-Security Logging and Alerting Failures",
    "A10:2021": "A01:2025-Broken Access Control",
}


def _normalize_owasp_category(category):
    if not category:
        return "Not mapped"

    value = str(category).strip()

    # Remove accidental duplicated OWASP 2025 prefix.
    # Example:
    # A03:2025-A03:2025-Software Supply Chain Failures
    # -> A03:2025-Software Supply Chain Failures
    duplicate_prefix = re.match(
        r"^(A\\d{2}:2025-)(A\\d{2}:2025-)(.+)$",
        value
    )
    if duplicate_prefix:
        value = duplicate_prefix.group(1) + duplicate_prefix.group(3)

    # Already correct OWASP 2025 category.
    if value.startswith("A") and ":2025-" in value:
        return value

    # Convert legacy 2021 category by category number.
    for old_prefix, new_category in OWASP_2025_MAP.items():
        if value.startswith(old_prefix):
            return new_category

    return value

SEVERITY_ORDER = {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 3,
    "info": 4,
    "informational": 4,
}

SEVERITY_LABELS = {
    "critical": "CRITICAL",
    "high": "HIGH",
    "medium": "MEDIUM",
    "low": "LOW",
    "info": "INFORMATIONAL",
    "informational": "INFORMATIONAL",
}

# Report palette
NAVY = colors.HexColor("#0B1220")
DARK = colors.HexColor("#111827")
SLATE = colors.HexColor("#475569")
LIGHT_SLATE = colors.HexColor("#64748B")
BORDER = colors.HexColor("#CBD5E1")
LIGHT_BG = colors.HexColor("#F8FAFC")
WHITE = colors.white
ACCENT = colors.HexColor("#2563EB")


# ============================================================
# OPTIONAL FONT SETUP
# ============================================================

def _register_fonts():
    """
    Try to register common Linux fonts.
    Falls back to Helvetica if unavailable.
    """
    candidates = [
        (
            "Inter",
            "/usr/share/fonts/truetype/inter/Inter-Regular.ttf",
            "/usr/share/fonts/truetype/inter/Inter-Bold.ttf",
        ),
        (
            "DejaVu",
            "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
            "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf",
        ),
    ]

    for family, regular, bold in candidates:
        if os.path.exists(regular) and os.path.exists(bold):
            try:
                pdfmetrics.registerFont(TTFont(family, regular))
                pdfmetrics.registerFont(TTFont(f"{family}-Bold", bold))
                return family, f"{family}-Bold"
            except Exception:
                continue

    return "Helvetica", "Helvetica-Bold"


FONT, FONT_BOLD = _register_fonts()


# ============================================================
# GENERAL HELPERS
# ============================================================

def _safe(value, default=""):
    if value is None:
        return default

    if isinstance(value, (dict, list)):
        return value

    return str(value)


def _clean_text(value):
    """
    Convert scanner values into safe PDF text.
    """
    if value is None:
        return ""

    if isinstance(value, bool):
        return "Yes" if value else "No"

    if isinstance(value, (dict, list)):
        try:
            value = json.dumps(value, ensure_ascii=False)
        except Exception:
            value = str(value)

    value = str(value)

    # ReportLab Paragraph safety
    value = value.replace("&", "&amp;")
    value = value.replace("<", "&lt;")
    value = value.replace(">", "&gt;")

    return value


def _plain_text(value):
    """
    Remove common markup before using text in generated sections.
    """
    if value is None:
        return ""

    value = str(value)

    value = re.sub(r"<[^>]+>", " ", value)
    value = value.replace("&amp;", "&")
    value = value.replace("&lt;", "<")
    value = value.replace("&gt;", ">")

    return " ".join(value.split())


def _severity(value):
    value = _plain_text(value).strip().lower()

    if value == "informational":
        return "info"

    if value in ("critical", "high", "medium", "low", "info"):
        return value

    return "info"


def _severity_rank(value):
    return SEVERITY_ORDER.get(_severity(value), 5)


def _format_number(value):
    try:
        return f"{int(value):,}"
    except Exception:
        return str(value)


def _format_duration(ms):
    try:
        ms = float(ms)

        if ms < 1000:
            return f"{ms:.0f} ms"

        seconds = ms / 1000

        if seconds < 60:
            return f"{seconds:.1f} seconds"

        minutes = int(seconds // 60)
        remaining = int(seconds % 60)

        return f"{minutes}m {remaining}s"

    except Exception:
        return "N/A"


def _risk_level(score):
    try:
        score = float(score)
    except Exception:
        return "Unknown"

    if score >= 90:
        return "Critical"
    if score >= 75:
        return "High"
    if score >= 50:
        return "Moderate"
    if score >= 25:
        return "Low"

    return "Minimal"


def _get_findings(report_data):
    findings = report_data.get("findings", [])

    if not isinstance(findings, list):
        return []

    return findings


def _get_unique_findings(report_data):
    """
    Prefer the risk engine's unique finding summary when available.
    Otherwise derive unique findings from raw findings.
    """
    summary = report_data.get("vulnerability_summary", {})

    if isinstance(summary, dict):
        unique = summary.get("unique_findings")

        if isinstance(unique, list) and unique:
            return unique

    findings = _get_findings(report_data)

    grouped = {}

    for finding in findings:
        if not isinstance(finding, dict):
            continue

        title = (
            finding.get("title")
            or finding.get("name")
            or finding.get("rule_name")
            or finding.get("id")
            or "Unclassified Finding"
        )

        key = str(title).strip().lower()

        if key not in grouped:
            grouped[key] = {
                "title": title,
                "severity": _severity(finding.get("severity")),
                "count": 0,
                "cvss_score": finding.get("cvss_score", finding.get("cvss", 0)),
                "owasp_category": finding.get("owasp_category", ""),
                "one_liner": finding.get("description", ""),
            }

        grouped[key]["count"] += 1

    return list(grouped.values())


def _severity_counts(report_data):
    findings = _get_findings(report_data)

    counts = Counter()

    for finding in findings:
        if isinstance(finding, dict):
            counts[_severity(finding.get("severity"))] += 1

    # If raw findings are absent, use summary counts.
    if not counts:
        summary = report_data.get("vulnerability_summary", {})

        if isinstance(summary, dict):
            narrative = summary.get("narrative", "")

            # Nothing to parse aggressively here.
            # Unique findings remain available for the report.
            if narrative:
                pass

    return counts


def _extract_owasp_counts(report_data):
    coverage = report_data.get("owasp_coverage", {})

    if isinstance(coverage, dict):
        result = {}

        for key, value in coverage.items():
            if isinstance(value, dict):
                count = (
                    value.get("count")
                    or value.get("findings")
                    or value.get("total")
                    or 0
                )
            else:
                count = value

            try:
                result[_normalize_owasp_category(key)] = result.get(_normalize_owasp_category(key), 0) + int(count)
            except Exception:
                result[str(key)] = 0

        if result:
            return result

    findings = _get_findings(report_data)
    counts = Counter()

    for finding in findings:
        if not isinstance(finding, dict):
            continue

        category = (
            finding.get("owasp_category")
            or finding.get("owasp")
            or ""
        )

        category = _plain_text(category).strip()

        if category:
            counts[category] += 1

    return dict(counts)


def _get_top_fixes(report_data):
    fixes = report_data.get("top_fixes", [])

    if isinstance(fixes, list):
        return fixes

    return []


# ============================================================
# LOCAL REPORT INTELLIGENCE
# ============================================================

def _build_executive_summary(report_data):
    score = report_data.get("risk_score", 0)
    grade = report_data.get("risk_grade", "")
    label = report_data.get("risk_grade_label", "")

    findings = _get_findings(report_data)
    counts = _severity_counts(report_data)

    total = report_data.get("total_findings")

    if total is None:
        total = len(findings)

    critical = counts.get("critical", 0)
    high = counts.get("high", 0)
    medium = counts.get("medium", 0)

    # Prefer the scanner's own summary where it is already meaningful.
    scanner_summary = report_data.get("summary")

    if scanner_summary:
        base = _plain_text(scanner_summary)
    else:
        base = (
            f"BlindSpot identified {_format_number(total)} security findings "
            f"across the assessed target."
        )

    details = []

    if critical:
        details.append(
            f"{_format_number(critical)} critical"
        )

    if high:
        details.append(
            f"{_format_number(high)} high"
        )

    if medium:
        details.append(
            f"{_format_number(medium)} medium"
        )

    if details:
        severity_text = ", ".join(details)

        return (
            f"{base} The most significant exposure is concentrated in "
            f"{severity_text}-severity findings. "
            f"The calculated risk score is {score}/100"
            + (f" with an overall grade of {grade}" if grade else "")
            + "."
        )

    return base


def _build_risk_interpretation(report_data):
    score = report_data.get("risk_score", 0)
    grade = report_data.get("risk_grade", "")
    label = report_data.get("risk_grade_label", "")

    level = _risk_level(score)

    if grade:
        grade_text = f"Grade {grade}"
    else:
        grade_text = "the calculated risk rating"

    if label:
        grade_text += f" ({label})"

    if level == "Critical":
        interpretation = (
            "The assessment indicates a critical security posture. "
            "High-impact findings should be reviewed and remediated as a priority."
        )
    elif level == "High":
        interpretation = (
            "The assessment indicates a high level of security exposure. "
            "The identified weaknesses should be addressed promptly."
        )
    elif level == "Moderate":
        interpretation = (
            "The assessment indicates a moderate level of security exposure. "
            "The identified weaknesses should be addressed through planned remediation."
        )
    elif level == "Low":
        interpretation = (
            "The assessment indicates a comparatively low level of security exposure, "
            "although individual findings may still require attention."
        )
    else:
        interpretation = (
            "The assessment indicates a comparatively minimal calculated risk level. "
            "Individual findings should still be reviewed for context."
        )

    return (
        f"BlindSpot calculated a risk score of {score}/100, corresponding to "
        f"{grade_text}. {interpretation}"
    )


def _prioritized_findings(report_data, limit=25):
    unique = _get_unique_findings(report_data)

    def sort_key(item):
        if not isinstance(item, dict):
            return (5, 0, "")

        severity = _severity(item.get("severity"))
        try:
            count = int(item.get("count", 1))
        except Exception:
            count = 1

        return (
            _severity_rank(severity),
            -count,
            str(item.get("title", "")).lower(),
        )

    unique = sorted(unique, key=sort_key)

    return unique[:limit]


def _finding_description(finding):
    if not isinstance(finding, dict):
        return ""

    candidates = [
        finding.get("description"),
        finding.get("details"),
        finding.get("evidence"),
        finding.get("one_liner"),
        finding.get("message"),
    ]

    for value in candidates:
        if value:
            return _plain_text(value)

    return ""


def _finding_remediation(finding):
    if not isinstance(finding, dict):
        return ""

    candidates = [
        finding.get("remediation"),
        finding.get("recommendation"),
        finding.get("fix"),
        finding.get("solution"),
        finding.get("mitigation"),
    ]

    for value in candidates:
        if value:
            return _plain_text(value)

    return (
        "Review the affected component and apply the vendor-recommended "
        "secure configuration or remediation appropriate to the identified issue."
    )


def _build_finding_entry(finding, index):
    if not isinstance(finding, dict):
        finding = {}

    title = (
        finding.get("title")
        or finding.get("name")
        or finding.get("rule_name")
        or "Unclassified Finding"
    )

    severity = _severity(finding.get("severity"))

    count = finding.get("count", 1)

    cvss = (
        finding.get("cvss_score")
        if finding.get("cvss_score") is not None
        else finding.get("cvss")
    )

    if cvss is None:
        cvss = "N/A"

    owasp = _normalize_owasp_category(
        finding.get("owasp_category")
        or finding.get("owasp")
        or "Not mapped"
    )

    cve = (
        finding.get("cve")
        or finding.get("cve_id")
        or finding.get("CVE")
        or ""
    )

    description = _finding_description(finding)
    remediation = _finding_remediation(finding)

    return {
        "index": index,
        "title": _plain_text(title),
        "severity": severity,
        "severity_label": SEVERITY_LABELS.get(
            severity,
            severity.upper()
        ),
        "count": count,
        "cvss": cvss,
        "owasp": _plain_text(owasp),
        "cve": _plain_text(cve),
        "description": description,
        "remediation": remediation,
        "raw": finding,
    }


def _build_ai_report(report_data):
    """
    Generate a deterministic local security-analysis object.

    This is intentionally called "AI-style" rather than pretending that
    a remote LLM was used. The report is derived from actual scanner data.
    """
    findings = _get_findings(report_data)
    unique = _get_unique_findings(report_data)
    counts = _severity_counts(report_data)

    prioritized = [
        _build_finding_entry(item, i + 1)
        for i, item in enumerate(_prioritized_findings(report_data))
    ]

    technologies = report_data.get("technologies") or []

    if not isinstance(technologies, list):
        technologies = [technologies]

    technologies = [
        _plain_text(x) for x in technologies if _plain_text(x)
    ]

    owasp_counts = _extract_owasp_counts(report_data)

    return {
        "title": REPORT_TITLE,
        "product": PRODUCT_NAME,
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "executive_summary": _build_executive_summary(report_data),
        "risk_interpretation": _build_risk_interpretation(report_data),
        "risk": {
            "score": report_data.get("risk_score", 0),
            "grade": report_data.get("risk_grade", "N/A"),
            "label": report_data.get("risk_grade_label", ""),
            "level": _risk_level(report_data.get("risk_score", 0)),
        },
        "severity_counts": dict(counts),
        "total_findings": report_data.get(
            "total_findings",
            len(findings)
        ),
        "unique_findings": len(unique),
        "technologies": technologies,
        "owasp_counts": owasp_counts,
        "top_fixes": _get_top_fixes(report_data),
        "findings": prioritized,
        "scanner_summary": _plain_text(
            report_data.get("summary", "")
        ),
        "narrative": _plain_text(
            report_data.get(
                "vulnerability_summary",
                {}
            ).get("narrative", "")
            if isinstance(
                report_data.get("vulnerability_summary", {}),
                dict
            )
            else ""
        ),
    }


# ============================================================
# PUBLIC AI REPORT FUNCTION
# ============================================================

def generate_ai_report(report_data):
    """
    Generate the local AI-style report.

    Compatible with:
        generate_ai_report(report_data)

    Returns a dictionary suitable for PDF generation or API output.
    """
    if not isinstance(report_data, dict):
        raise TypeError("report_data must be a dictionary")

    # Accept both:
    #   {"report": {...}}
    # and:
    #   {...}
    if isinstance(report_data.get("report"), dict):
        report_data = report_data["report"]

    return _build_ai_report(report_data)


# ============================================================
# PDF STYLES
# ============================================================

def _styles():
    styles = getSampleStyleSheet()

    return {
        "cover_title": ParagraphStyle(
            "BS_CoverTitle",
            parent=styles["Title"],
            fontName=FONT_BOLD,
            fontSize=26,
            leading=31,
            textColor=NAVY,
            alignment=TA_CENTER,
            spaceAfter=8,
        ),

        "cover_subtitle": ParagraphStyle(
            "BS_CoverSubtitle",
            parent=styles["Normal"],
            fontName=FONT,
            fontSize=11,
            leading=16,
            textColor=SLATE,
            alignment=TA_CENTER,
            spaceAfter=5,
        ),

        "section": ParagraphStyle(
            "BS_Section",
            parent=styles["Heading1"],
            fontName=FONT_BOLD,
            fontSize=16,
            leading=20,
            textColor=NAVY,
            spaceBefore=12,
            spaceAfter=8,
        ),

        "subsection": ParagraphStyle(
            "BS_Subsection",
            parent=styles["Heading2"],
            fontName=FONT_BOLD,
            fontSize=11,
            leading=15,
            textColor=DARK,
            spaceBefore=8,
            spaceAfter=5,
        ),

        "body": ParagraphStyle(
            "BS_Body",
            parent=styles["BodyText"],
            fontName=FONT,
            fontSize=9.2,
            leading=14,
            textColor=DARK,
            spaceAfter=6,
        ),

        "small": ParagraphStyle(
            "BS_Small",
            parent=styles["BodyText"],
            fontName=FONT,
            fontSize=7.5,
            leading=10,
            textColor=SLATE,
        ),

        "finding_title": ParagraphStyle(
            "BS_FindingTitle",
            parent=styles["Heading3"],
            fontName=FONT_BOLD,
            fontSize=11,
            leading=14,
            textColor=NAVY,
            spaceAfter=4,
        ),

        "finding_body": ParagraphStyle(
            "BS_FindingBody",
            parent=styles["BodyText"],
            fontName=FONT,
            fontSize=8.3,
            leading=12,
            textColor=DARK,
            spaceAfter=4,
        ),

        "table": ParagraphStyle(
            "BS_Table",
            parent=styles["BodyText"],
            fontName=FONT,
            fontSize=7.5,
            leading=10,
            textColor=DARK,
        ),

        "table_bold": ParagraphStyle(
            "BS_TableBold",
            parent=styles["BodyText"],
            fontName=FONT_BOLD,
            fontSize=7.5,
            leading=10,
            textColor=DARK,
        ),

        "metric": ParagraphStyle(
            "BS_Metric",
            parent=styles["Normal"],
            fontName=FONT_BOLD,
            fontSize=18,
            leading=21,
            textColor=NAVY,
            alignment=TA_CENTER,
        ),

        "metric_label": ParagraphStyle(
            "BS_MetricLabel",
            parent=styles["Normal"],
            fontName=FONT,
            fontSize=7,
            leading=9,
            textColor=SLATE,
            alignment=TA_CENTER,
        ),
    }


# ============================================================
# PDF COMPONENTS
# ============================================================

def _header_footer(canvas, doc):
    canvas.saveState()

    width, height = A4

    # Header
    canvas.setStrokeColor(BORDER)
    canvas.setLineWidth(0.5)
    canvas.line(
        15 * mm,
        height - 13 * mm,
        width - 15 * mm,
        height - 13 * mm,
    )

    canvas.setFont(FONT_BOLD, 7)
    canvas.setFillColor(NAVY)
    canvas.drawString(
        15 * mm,
        height - 10 * mm,
        PRODUCT_NAME
    )

    canvas.setFont(FONT, 7)
    canvas.setFillColor(LIGHT_SLATE)
    canvas.drawRightString(
        width - 15 * mm,
        height - 10 * mm,
        REPORT_TITLE
    )

    # Footer
    canvas.setStrokeColor(BORDER)
    canvas.line(
        15 * mm,
        12 * mm,
        width - 15 * mm,
        12 * mm,
    )

    canvas.setFont(FONT, 7)
    canvas.setFillColor(LIGHT_SLATE)

    canvas.drawString(
        15 * mm,
        7 * mm,
        "Generated by BlindSpot"
    )

    canvas.drawRightString(
        width - 15 * mm,
        7 * mm,
        f"Page {doc.page}"
    )

    canvas.restoreState()


def _metric_card(label, value, width=43 * mm):
    styles = _styles()

    table = Table(
        [
            [
                Paragraph(
                    _clean_text(value),
                    styles["metric"]
                )
            ],
            [
                Paragraph(
                    _clean_text(label),
                    styles["metric_label"]
                )
            ],
        ],
        colWidths=[width],
        rowHeights=[13 * mm, 8 * mm],
    )

    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, -1), LIGHT_BG),
                ("BOX", (0, 0), (-1, -1), 0.7, BORDER),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ("LEFTPADDING", (0, 0), (-1, -1), 5),
                ("RIGHTPADDING", (0, 0), (-1, -1), 5),
                ("TOPPADDING", (0, 0), (-1, -1), 4),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ]
        )
    )

    return table


def _severity_color(severity):
    severity = _severity(severity)

    if severity == "critical":
        return colors.HexColor("#B91C1C")

    if severity == "high":
        return colors.HexColor("#C2410C")

    if severity == "medium":
        return colors.HexColor("#A16207")

    if severity == "low":
        return colors.HexColor("#15803D")

    return colors.HexColor("#475569")


def _severity_badge(severity):
    styles = _styles()

    label = SEVERITY_LABELS.get(
        _severity(severity),
        str(severity).upper()
    )

    table = Table(
        [[
            Paragraph(
                f"<b>{_clean_text(label)}</b>",
                ParagraphStyle(
                    "badge",
                    parent=styles["small"],
                    textColor=WHITE,
                    alignment=TA_CENTER,
                    fontName=FONT_BOLD,
                )
            )
        ]],
        colWidths=[25 * mm],
    )

    table.setStyle(
        TableStyle(
            [
                (
                    "BACKGROUND",
                    (0, 0),
                    (-1, -1),
                    _severity_color(severity),
                ),
                ("BOX", (0, 0), (-1, -1), 0, WHITE),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ("LEFTPADDING", (0, 0), (-1, -1), 3),
                ("RIGHTPADDING", (0, 0), (-1, -1), 3),
                ("TOPPADDING", (0, 0), (-1, -1), 3),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
            ]
        )
    )

    return table


def _metadata_table(report_data):
    styles = _styles()

    rows = [
        [
            Paragraph("<b>Target</b>", styles["table_bold"]),
            Paragraph(
                _clean_text(report_data.get("target_url", "N/A")),
                styles["table"],
            ),
        ],
        [
            Paragraph("<b>Scan ID</b>", styles["table_bold"]),
            Paragraph(
                _clean_text(report_data.get("scan_id", "N/A")),
                styles["table"],
            ),
        ],
        [
            Paragraph("<b>Scanned</b>", styles["table_bold"]),
            Paragraph(
                _clean_text(report_data.get("scanned_at", "N/A")),
                styles["table"],
            ),
        ],
        [
            Paragraph("<b>Completed</b>", styles["table_bold"]),
            Paragraph(
                _clean_text(report_data.get("completed_at", "N/A")),
                styles["table"],
            ),
        ],
        [
            Paragraph("<b>Duration</b>", styles["table_bold"]),
            Paragraph(
                _clean_text(
                    _format_duration(
                        report_data.get("scan_duration_ms")
                    )
                ),
                styles["table"],
            ),
        ],
    ]

    technologies = report_data.get("technologies") or []

    if isinstance(technologies, list):
        tech_text = ", ".join(
            _plain_text(x)
            for x in technologies
            if _plain_text(x)
        )
    else:
        tech_text = _plain_text(technologies)

    rows.append(
        [
            Paragraph("<b>Detected technologies</b>", styles["table_bold"]),
            Paragraph(
                _clean_text(tech_text or "None identified"),
                styles["table"],
            ),
        ]
    )

    table = Table(
        rows,
        colWidths=[42 * mm, 133 * mm],
        repeatRows=0,
    )

    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (0, -1), LIGHT_BG),
                ("GRID", (0, 0), (-1, -1), 0.5, BORDER),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("LEFTPADDING", (0, 0), (-1, -1), 6),
                ("RIGHTPADDING", (0, 0), (-1, -1), 6),
                ("TOPPADDING", (0, 0), (-1, -1), 5),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
            ]
        )
    )

    return table


def _severity_table(counts):
    styles = _styles()

    rows = [
        [
            Paragraph("<b>Severity</b>", styles["table_bold"]),
            Paragraph("<b>Findings</b>", styles["table_bold"]),
        ]
    ]

    for severity in ["critical", "high", "medium", "low", "info"]:
        rows.append(
            [
                Paragraph(
                    _clean_text(
                        SEVERITY_LABELS[severity]
                    ),
                    styles["table"],
                ),
                Paragraph(
                    _format_number(counts.get(severity, 0)),
                    styles["table"],
                ),
            ]
        )

    table = Table(
        rows,
        colWidths=[55 * mm, 35 * mm],
        repeatRows=1,
    )

    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), NAVY),
                ("TEXTCOLOR", (0, 0), (-1, 0), WHITE),
                ("GRID", (0, 0), (-1, -1), 0.5, BORDER),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ("LEFTPADDING", (0, 0), (-1, -1), 6),
                ("RIGHTPADDING", (0, 0), (-1, -1), 6),
                ("TOPPADDING", (0, 0), (-1, -1), 5),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
            ]
        )
    )

    return table


def _owasp_table(owasp_counts):
    styles = _styles()

    if not owasp_counts:
        return Paragraph(
            "No OWASP category mappings were available in the scan data.",
            styles["body"],
        )

    rows = [
        [
            Paragraph("<b>OWASP Category</b>", styles["table_bold"]),
            Paragraph("<b>Findings</b>", styles["table_bold"]),
        ]
    ]

    ordered = sorted(
        owasp_counts.items(),
        key=lambda x: (-x[1], x[0])
    )

    for category, count in ordered:
        rows.append(
            [
                Paragraph(
                    _clean_text(category),
                    styles["table"],
                ),
                Paragraph(
                    _format_number(count),
                    styles["table"],
                ),
            ]
        )

    table = Table(
        rows,
        colWidths=[130 * mm, 35 * mm],
        repeatRows=1,
    )

    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), NAVY),
                ("TEXTCOLOR", (0, 0), (-1, 0), WHITE),
                ("GRID", (0, 0), (-1, -1), 0.5, BORDER),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ("LEFTPADDING", (0, 0), (-1, -1), 6),
                ("RIGHTPADDING", (0, 0), (-1, -1), 6),
                ("TOPPADDING", (0, 0), (-1, -1), 5),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
            ]
        )
    )

    return table


def _finding_block(finding):
    styles = _styles()

    title = finding["title"]
    severity = finding["severity"]
    cvss = finding["cvss"]
    owasp = finding["owasp"]
    cve = finding["cve"]
    count = finding["count"]

    header_data = [
        [
            Paragraph(
                _clean_text(title),
                styles["finding_title"]
            ),
            _severity_badge(severity),
        ]
    ]

    header = Table(
        header_data,
        colWidths=[132 * mm, 32 * mm],
    )

    header.setStyle(
        TableStyle(
            [
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("LEFTPADDING", (0, 0), (-1, -1), 0),
                ("RIGHTPADDING", (0, 0), (-1, -1), 0),
                ("TOPPADDING", (0, 0), (-1, -1), 0),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
            ]
        )
    )

    metadata = [
        [
            Paragraph(
                f"<b>CVSS:</b> {_clean_text(cvss)}",
                styles["finding_body"],
            ),
            Paragraph(
                f"<b>OWASP:</b> {_clean_text(owasp)}",
                styles["finding_body"],
            ),
            Paragraph(
                f"<b>Occurrences:</b> {_clean_text(count)}",
                styles["finding_body"],
            ),
        ]
    ]

    if cve:
        metadata.append(
            [
                Paragraph(
                    f"<b>CVE:</b> {_clean_text(cve)}",
                    styles["finding_body"],
                ),
                "",
                "",
            ]
        )

    meta_table = Table(
        metadata,
        colWidths=[38 * mm, 88 * mm, 38 * mm],
    )

    meta_table.setStyle(
        TableStyle(
            [
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("LEFTPADDING", (0, 0), (-1, -1), 0),
                ("RIGHTPADDING", (0, 0), (-1, -1), 4),
                ("TOPPADDING", (0, 0), (-1, -1), 0),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 0),
            ]
        )
    )

    elements = [
        header,
        meta_table,
    ]

    if finding["description"]:
        elements.extend(
            [
                Paragraph(
                    "<b>Assessment</b>",
                    styles["finding_body"],
                ),
                Paragraph(
                    _clean_text(finding["description"]),
                    styles["finding_body"],
                ),
            ]
        )

    elements.extend(
        [
            Paragraph(
                "<b>Recommended remediation</b>",
                styles["finding_body"],
            ),
            Paragraph(
                _clean_text(finding["remediation"]),
                styles["finding_body"],
            ),
            Spacer(1, 3),
        ]
    )

    outer = Table(
        [[elements]],
        colWidths=[170 * mm],
    )

    outer.setStyle(
        TableStyle(
            [
                ("BOX", (0, 0), (-1, -1), 0.6, BORDER),
                ("BACKGROUND", (0, 0), (-1, -1), WHITE),
                ("LEFTPADDING", (0, 0), (-1, -1), 8),
                ("RIGHTPADDING", (0, 0), (-1, -1), 8),
                ("TOPPADDING", (0, 0), (-1, -1), 7),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
            ]
        )
    )

    return outer


# ============================================================
# PDF GENERATION
# ============================================================

def generate_pdf(report_data, output_path=None):
    """
    Generate a professional PDF security assessment.

    Compatible with:
        generate_pdf(report_data)

    or:
        generate_pdf(report_data, "/path/to/report.pdf")

    Returns:
        Absolute path to generated PDF.
    """
    if not isinstance(report_data, dict):
        raise TypeError("report_data must be a dictionary")

    # Support:
    # {"report": {...}}
    if isinstance(report_data.get("report"), dict):
        source_report = report_data["report"]
    else:
        source_report = report_data

    analysis = generate_ai_report(source_report)

    scan_id = (
        source_report.get("scan_id")
        or "unknown"
    )

    if output_path is None:
        output_path = os.path.join(
            "/tmp",
            f"blindspot-report-{str(scan_id)[:8]}.pdf"
        )

    output_path = os.path.abspath(output_path)

    os.makedirs(
        os.path.dirname(output_path),
        exist_ok=True
    )

    styles = _styles()

    doc = SimpleDocTemplate(
        output_path,
        pagesize=A4,
        rightMargin=20 * mm,
        leftMargin=20 * mm,
        topMargin=19 * mm,
        bottomMargin=18 * mm,
        title=REPORT_TITLE,
        author="BlindSpot",
        subject="Security Assessment Report",
    )

    story = []

    # ========================================================
    # COVER
    # ========================================================

    story.append(Spacer(1, 35 * mm))

    story.append(
        Paragraph(
            PRODUCT_NAME,
            ParagraphStyle(
                "brand",
                parent=styles["cover_subtitle"],
                fontName=FONT_BOLD,
                fontSize=12,
                textColor=ACCENT,
                spaceAfter=10,
            )
        )
    )

    story.append(
        Paragraph(
            REPORT_TITLE,
            styles["cover_title"]
        )
    )

    story.append(
        Paragraph(
            "External Web Application Security Assessment",
            styles["cover_subtitle"]
        )
    )

    story.append(Spacer(1, 15 * mm))

    target = source_report.get(
        "target_url",
        "Target not specified"
    )

    cover_table = Table(
        [
            [
                Paragraph(
                    "<b>ASSESSED TARGET</b>",
                    styles["small"]
                )
            ],
            [
                Paragraph(
                    _clean_text(target),
                    ParagraphStyle(
                        "target",
                        parent=styles["body"],
                        fontName=FONT_BOLD,
                        fontSize=11,
                        alignment=TA_CENTER,
                        textColor=NAVY,
                    )
                )
            ],
        ],
        colWidths=[140 * mm],
    )

    cover_table.setStyle(
        TableStyle(
            [
                ("BOX", (0, 0), (-1, -1), 0.8, BORDER),
                ("BACKGROUND", (0, 0), (-1, 0), LIGHT_BG),
                ("ALIGN", (0, 0), (-1, -1), "CENTER"),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ("LEFTPADDING", (0, 0), (-1, -1), 10),
                ("RIGHTPADDING", (0, 0), (-1, -1), 10),
                ("TOPPADDING", (0, 0), (-1, -1), 7),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
            ]
        )
    )

    story.append(cover_table)
    story.append(Spacer(1, 12 * mm))

    story.append(
        Paragraph(
            "CONFIDENTIAL SECURITY ASSESSMENT",
            ParagraphStyle(
                "confidential",
                parent=styles["small"],
                fontName=FONT_BOLD,
                alignment=TA_CENTER,
                textColor=SLATE,
            )
        )
    )

    story.append(PageBreak())

    # ========================================================
    # 1. ASSESSMENT OVERVIEW
    # ========================================================

    story.append(
        Paragraph(
            "1. Assessment Overview",
            styles["section"]
        )
    )

    story.append(_metadata_table(source_report))
    story.append(Spacer(1, 7 * mm))

    story.append(
        Paragraph(
            "Executive Summary",
            styles["subsection"]
        )
    )

    story.append(
        Paragraph(
            _clean_text(
                analysis["executive_summary"]
            ),
            styles["body"]
        )
    )

    # ========================================================
    # RISK CARDS
    # ========================================================

    score = analysis["risk"]["score"]
    grade = analysis["risk"]["grade"]
    total = analysis["total_findings"]

    cards = Table(
        [[
            _metric_card("RISK SCORE", f"{score}/100"),
            _metric_card("RISK GRADE", grade or "N/A"),
            _metric_card(
                "TOTAL FINDINGS",
                _format_number(total)
            ),
        ]],
        colWidths=[
            54 * mm,
            54 * mm,
            54 * mm,
        ],
    )

    cards.setStyle(
        TableStyle(
            [
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("LEFTPADDING", (0, 0), (-1, -1), 2),
                ("RIGHTPADDING", (0, 0), (-1, -1), 2),
                ("TOPPADDING", (0, 0), (-1, -1), 2),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
            ]
        )
    )

    story.append(cards)
    story.append(Spacer(1, 7 * mm))

    story.append(
        Paragraph(
            _clean_text(
                analysis["risk_interpretation"]
            ),
            styles["body"]
        )
    )

    # ========================================================
    # 2. SEVERITY ANALYSIS
    # ========================================================

    story.append(
        Paragraph(
            "2. Severity Analysis",
            styles["section"]
        )
    )

    counts = analysis["severity_counts"]

    severity_total = sum(counts.values())

    if severity_total == 0:
        severity_total = total

    story.append(
        Paragraph(
            "The following distribution summarizes the findings returned by "
            "the scanner according to severity.",
            styles["body"]
        )
    )

    story.append(_severity_table(counts))
    story.append(Spacer(1, 6 * mm))

    # Severity narrative
    critical = counts.get("critical", 0)
    high = counts.get("high", 0)
    medium = counts.get("medium", 0)

    severity_narrative = []

    if critical:
        severity_narrative.append(
            f"{_format_number(critical)} critical finding(s)"
        )

    if high:
        severity_narrative.append(
            f"{_format_number(high)} high-severity finding(s)"
        )

    if medium:
        severity_narrative.append(
            f"{_format_number(medium)} medium-severity finding(s)"
        )

    if severity_narrative:
        story.append(
            Paragraph(
                _clean_text(
                    "Priority exposure is concentrated in "
                    + ", ".join(severity_narrative)
                    + ". These findings should receive the greatest "
                      "attention during security review."
                ),
                styles["body"]
            )
        )

    # ========================================================
    # 3. OWASP COVERAGE
    # ========================================================

    story.append(
        Paragraph(
            "3. OWASP Coverage",
            styles["section"]
        )
    )

    story.append(
        Paragraph(
            "The assessment findings are mapped to OWASP categories where "
            "the scanner provided a corresponding classification.",
            styles["body"]
        )
    )

    story.append(
        _owasp_table(
            analysis["owasp_counts"]
        )
    )

    # ========================================================
    # 4. PRIORITIZED FINDINGS
    # ========================================================

    story.append(PageBreak())

    story.append(
        Paragraph(
            "4. Prioritized Security Findings",
            styles["section"]
        )
    )

    story.append(
        Paragraph(
            "Findings are ordered by severity and then by occurrence count. "
            "The sections below provide the security significance and "
            "recommended remediation for the highest-priority findings.",
            styles["body"]
        )
    )

    findings = analysis["findings"]

    if not findings:
        story.append(
            Paragraph(
                "No detailed findings were available for this assessment.",
                styles["body"]
            )
        )
    else:
        for finding in findings:
            story.append(
                KeepTogether(
                    [
                        _finding_block(finding),
                        Spacer(1, 5 * mm),
                    ]
                )
            )

    # ========================================================
    # 5. REMEDIATION PRIORITIES
    # ========================================================

    story.append(PageBreak())

    story.append(
        Paragraph(
            "5. Remediation Priorities",
            styles["section"]
        )
    )

    story.append(
        Paragraph(
            "The following priorities are derived from the scanner's "
            "severity and remediation data.",
            styles["body"]
        )
    )

    top_fixes = analysis["top_fixes"]

    if top_fixes:
        for index, fix in enumerate(top_fixes[:10], 1):
            if isinstance(fix, dict):
                title = (
                    fix.get("title")
                    or fix.get("name")
                    or fix.get("finding")
                    or "Recommended Action"
                )

                text = (
                    fix.get("remediation")
                    or fix.get("recommendation")
                    or fix.get("fix")
                    or fix.get("description")
                    or ""
                )

                content = (
                    f"<b>{index}. {_clean_text(title)}</b>"
                    + (
                        f"<br/>{_clean_text(text)}"
                        if text
                        else ""
                    )
                )
            else:
                content = (
                    f"<b>{index}.</b> "
                    f"{_clean_text(fix)}"
                )

            story.append(
                Paragraph(
                    content,
                    styles["body"]
                )
            )
    else:
        # Derive remediation priorities from prioritized findings.
        priority_findings = findings[:10]

        if priority_findings:
            for index, finding in enumerate(
                priority_findings,
                1
            ):
                story.append(
                    Paragraph(
                        (
                            f"<b>{index}. "
                            f"{_clean_text(finding['title'])}</b><br/>"
                            f"{_clean_text(finding['remediation'])}"
                        ),
                        styles["body"]
                    )
                )
        else:
            story.append(
                Paragraph(
                    "No remediation priorities were provided in the scan data.",
                    styles["body"]
                )
            )

    # ========================================================
    # 6. METHODOLOGY / SCOPE
    # ========================================================

    story.append(
        Paragraph(
            "6. Assessment Scope & Methodology",
            styles["section"]
        )
    )

    # Keep methodology concise and human-readable. Do not dump the raw
    # active-probe log because scanner backends may record generic entries
    # such as "Active probe", which adds noise without helping the reader.
    story.append(
        Paragraph(
            "BlindSpot evaluates the target using configured security rules, "
            "web security checks, technology identification, CVE enrichment, "
            "OWASP classification and, where enabled, active security probes.",
            styles["body"]
        )
    )

    scan_mode = source_report.get("scan_mode", "")
    if scan_mode:
        readable_mode = _plain_text(scan_mode).replace("_", " ").title()
        story.append(
            Paragraph(
                f"<b>Assessment mode:</b> {_clean_text(readable_mode)}",
                styles["body"]
            )
        )

    active_probes = source_report.get("active_probes_log", [])
    if isinstance(active_probes, list) and active_probes:
        # Count recorded probe activity, but suppress repetitive/generic
        # entries from the final report.
        meaningful_names = []
        generic_names = {
            "", "active probe", "probe", "unknown probe",
            "active", "security probe"
        }

        for probe in active_probes:
            if isinstance(probe, dict):
                name = (
                    probe.get("name")
                    or probe.get("probe")
                    or probe.get("type")
                    or ""
                )
            else:
                name = probe

            name = _plain_text(name).strip()
            if name and name.lower() not in generic_names:
                if name not in meaningful_names:
                    meaningful_names.append(name)

        probe_count = len(active_probes)

        probe_text = (
            f"<b>Active security checks:</b> "
            f"{_format_number(probe_count)} recorded probe check(s)."
        )

        if meaningful_names:
            probe_text += (
                " Recorded checks included: "
                + ", ".join(_clean_text(x) for x in meaningful_names[:8])
                + "."
            )

        story.append(
            Paragraph(
                probe_text,
                styles["body"]
            )
        )

    # ========================================================
    # FINAL
    # ========================================================

    story.append(Spacer(1, 8 * mm))

    story.append(
        Table(
            [[
                Paragraph(
                    "<b>BlindSpot Security Assessment</b><br/>"
                    "This report reflects the findings and metadata "
                    "available from the completed BlindSpot scan.",
                    styles["body"]
                )
            ]],
            colWidths=[170 * mm],
            style=TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, -1), LIGHT_BG),
                    ("BOX", (0, 0), (-1, -1), 0.6, BORDER),
                    ("LEFTPADDING", (0, 0), (-1, -1), 9),
                    ("RIGHTPADDING", (0, 0), (-1, -1), 9),
                    ("TOPPADDING", (0, 0), (-1, -1), 8),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
                ]
            )
        )
    )

    doc.build(
        story,
        onFirstPage=_header_footer,
        onLaterPages=_header_footer,
    )

    return output_path


# ============================================================
# OPTIONAL CLI TEST
# ============================================================

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        description="Generate a BlindSpot security assessment PDF."
    )

    parser.add_argument(
        "input",
        help="Path to BlindSpot report JSON"
    )

    parser.add_argument(
        "-o",
        "--output",
        default=None,
        help="Output PDF path"
    )

    args = parser.parse_args()

    with open(
        args.input,
        "r",
        encoding="utf-8"
    ) as f:
        report = json.load(f)

    generated = generate_pdf(
        report,
        args.output
    )

    print(f"PDF generated: {generated}")
