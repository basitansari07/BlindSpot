"""
nuclei_importer.py — Nuclei Template Importer
Parses selected Nuclei YAML templates into the unified rule schema.
Extracts: id, info.severity, info.classification.cve-id,
requests[].matchers[] — and converts into rules the custom matcher can evaluate.
"""

import os
import re
import logging

import yaml

logger = logging.getLogger(__name__)

# Map Nuclei severity to our severity levels
SEVERITY_MAP = {
    "critical": "critical",
    "high": "high",
    "medium": "medium",
    "low": "low",
    "info": "info",
    "unknown": "info",
}

# Nuclei matcher type → our match_type
# NUCLEI_GROUPING_PATCH_V1
# Nuclei HTTP matchers belonging to one request must be evaluated
# as a group instead of being converted into independent findings.

NUCLEI_GROUPING_PATCH_V1 = True

MATCHER_TYPE_MAP = {
    "word": "string",
    "regex": "regex",
    "status": "status_code",
    "binary": "string",
    "dsl": "dsl",
}

# Tags we want to import (broadened subset for better coverage)
IMPORT_TAGS = {
    "cve", "tech", "misconfig", "exposure", "config",
    "default-login", "xss", "sqli", "lfi", "rfi",
    "ssrf", "redirect", "disclosure", "token",
    "unauth", "takeover", "panel", "iot",
    "wordpress", "joomla", "drupal", "apache", "nginx",
    "jenkins", "docker", "kubernetes", "cloud",
    "aws", "azure", "gcp", "git", "backup",
    "debug", "api", "graphql", "swagger",
    "phpmyadmin", "adminer", "login", "rce",
    "deserialization", "ssti", "xxe", "cors",
    "crlf", "header-injection", "open-redirect",
}



def _build_nuclei_matcher_group(
    template_id,
    template_info,
    request_index,
    request,
):
    """
    Preserve one Nuclei HTTP request as one logical matcher group.

    A Nuclei template can contain multiple matchers with an AND/OR
    condition. These matchers must NOT become independent vulnerability
    rules.
    """
    matchers = request.get("matchers", []) or []
    condition = request.get("matchers-condition", "or").lower()

    paths = request.get("path", []) or []
    if isinstance(paths, str):
        paths = [paths]

    normalized = []

    for matcher_index, matcher in enumerate(matchers):
        matcher_type = matcher.get("type", "word")
        part = matcher.get("part", "body").lower()

        item = {
            "index": matcher_index,
            "type": matcher_type,
            "part": part,
            "condition": matcher.get("condition", "or").lower(),
            "words": matcher.get("words", []) or [],
            "regex": matcher.get("regex", []) or [],
            "status": matcher.get("status", []) or [],
            "dsl": matcher.get("dsl", []) or [],
        }

        normalized.append(item)

    return {
        "template_id": template_id,
        "request_index": request_index,
        "method": request.get("method", "GET").upper(),
        "paths": paths,
        "matchers_condition": condition,
        "matchers": normalized,
        "name": template_info.get("name", template_id),
    }


def import_nuclei_templates(templates_dir: str, max_templates: int = 500) -> list:
    """
    Import curated Nuclei YAML templates into unified rule schema.

    Args:
        templates_dir: Path to nuclei-templates directory
        max_templates: Maximum number of templates to import

    Returns:
        List of unified rule schema dicts
    """
    rules = []

    if not os.path.isdir(templates_dir):
        logger.warning(f"[NucleiImporter] Templates dir not found: {templates_dir}")
        return rules

    # Walk the templates directory
    yaml_files = []
    for root, dirs, files in os.walk(templates_dir):
        for f in files:
            if f.endswith((".yaml", ".yml")):
                yaml_files.append(os.path.join(root, f))

    logger.info(f"[NucleiImporter] Found {len(yaml_files)} YAML templates")

    imported = 0
    for filepath in yaml_files:
        if imported >= max_templates:
            break

        try:
            template_rules = _parse_template(filepath)
            if template_rules:
                rules.extend(template_rules)
                imported += 1
        except Exception as e:
            logger.debug(f"[NucleiImporter] Skipping {filepath}: {e}")

    logger.info(f"[NucleiImporter] Imported {len(rules)} rules from {imported} templates")
    return rules


def _should_import(info: dict) -> bool:
    """Check if a template should be imported based on its tags."""
    tags = info.get("tags", "")
    if isinstance(tags, str):
        tag_set = set(t.strip().lower() for t in tags.split(","))
    elif isinstance(tags, list):
        tag_set = set(t.lower() for t in tags)
    else:
        return False

    return bool(tag_set & IMPORT_TAGS)


def _parse_template(filepath: str) -> list:
    """Parse a single Nuclei YAML template into safe unified rules."""

    with open(filepath, "r", errors="replace") as f:
        try:
            template = yaml.safe_load(f)
        except yaml.YAMLError:
            return []

    if not template or not isinstance(template, dict):
        return []

    template_id = template.get("id", "")
    info = template.get("info", {})

    if not template_id or not info:
        return []

    if not _should_import(info):
        return []

    severity = SEVERITY_MAP.get(
        str(info.get("severity", "info")).lower(),
        "info"
    )

    classification = info.get("classification", {}) or {}

    cve_id = ""
    cwe_id = ""

    cve_ids = classification.get("cve-id", [])
    if isinstance(cve_ids, list) and cve_ids:
        cve_id = cve_ids[0]
    elif isinstance(cve_ids, str):
        cve_id = cve_ids

    cwe_ids = classification.get("cwe-id", [])
    if isinstance(cwe_ids, list) and cwe_ids:
        cwe_id = cwe_ids[0]
    elif isinstance(cwe_ids, str):
        cwe_id = cwe_ids

    owasp = _infer_owasp_category(info)

    description = info.get(
        "description",
        f"Nuclei template: {info.get('name', template_id)}"
    )

    remediation = info.get("remediation", "")

    references = info.get("reference", [])
    if isinstance(references, str):
        references = [references]

    rules = []

    http_reqs = template.get(
        "http",
        template.get("requests", [])
    )

    if not isinstance(http_reqs, list):
        return []

    for req_index, req in enumerate(http_reqs):

        if not isinstance(req, dict):
            continue

        matchers = req.get("matchers", [])
        if not isinstance(matchers, list) or not matchers:
            continue

        matchers_condition = str(
            req.get("matchers-condition", "or")
        ).lower()

        # NUCLEI_GROUPING_PATCH_V2
        #
        # Preserve the complete Nuclei HTTP request as ONE logical rule.
        # Matchers belonging to the same request must be evaluated
        # together according to matchers-condition (AND/OR).
        #
        # We also preserve the request path and HTTP method so that
        # endpoint-specific CVEs cannot match against the homepage.

        matcher_group = _build_nuclei_matcher_group(
            template_id=template_id,
            template_info=info,
            request_index=req_index,
            request=req,
        )

        if not matcher_group["matchers"]:
            continue

        # Keep the first meaningful matcher as the compatibility
        # representation for the existing Finding/report schema.
        first_matcher = matcher_group["matchers"][0]

        rule_id = (
            f"nuclei-{template_id}-"
            f"{req_index}"
        )

        rules.append({
            "id": rule_id,
            "enabled": True,

            "type": (
                "vulnerability"
                if cve_id
                else "misconfiguration"
            ),

            # Compatibility fields used by the existing scanner.
            "target_location": _map_part_to_location(
                first_matcher.get("part", "body")
            ),
            "match_type": "nuclei_group",
            "pattern": info.get("name", template_id),

            "severity": severity,
            "title": info.get("name", template_id),
            "description": description,

            "cve": cve_id,
            "cwe": cwe_id,
            "owasp_category": owasp,

            "remediation": remediation,
            "references": references,

            "source": "nuclei",
            "nuclei_template_id": template_id,

            # Complete Nuclei request semantics.
            "nuclei_request_index": req_index,
            "nuclei_method": matcher_group["method"],
            "nuclei_paths": matcher_group["paths"],
            "nuclei_matchers_condition": matcher_group[
                "matchers_condition"
            ],
            "nuclei_matchers": matcher_group["matchers"],
        })

    return rules

def _map_part_to_location(part: str) -> str:
    """Map Nuclei 'part' field to our target_location."""
    mapping = {
        "body": "body",
        "header": "header",
        "response": "body",
        "all": "all",
        "status": "status_code",
        "interactsh_protocol": "body",
    }
    return mapping.get(part, "body")


def _convert_dsl_to_pattern(dsl_expr: str) -> dict:
    """
    Convert simple Nuclei DSL expressions into regex/string patterns.
    Handles common patterns like:
      - contains(body, "string")
      - status_code == 200
      - contains(all_headers, "string")
    Returns None for unsupported/complex DSL.
    """
    if not isinstance(dsl_expr, str):
        return None

    # Match: contains(body, "string") or contains(all_headers, "string")
    m = re.match(r'contains\(\s*(body|all_headers|header|response)\s*,\s*["\'](.+?)["\']\s*\)', dsl_expr)
    if m:
        part_name = m.group(1)
        search_str = m.group(2)
        part_map = {"body": "body", "all_headers": "header", "header": "header", "response": "body"}
        return {
            "match_type": "string",
            "pattern": search_str,
            "part": part_map.get(part_name, "body"),
        }

    # Match: status_code == 200
    m = re.match(r'status_code\s*==\s*(\d+)', dsl_expr)
    if m:
        return {
            "match_type": "status_code",
            "pattern": m.group(1),
            "part": "status",
        }

    # Match: contains(body, "a") && contains(body, "b")
    parts = re.findall(r'contains\(\s*(?:body|response)\s*,\s*["\'](.+?)["\']\s*\)', dsl_expr)
    if len(parts) >= 2 and "&&" in dsl_expr:
        escaped = [re.escape(p) for p in parts]
        combo_pattern = "(?=.*" + ")(?=.*".join(escaped) + ")"
        return {
            "match_type": "regex",
            "pattern": combo_pattern,
            "part": "body",
        }

    # Unsupported DSL — skip
    return None


def _infer_owasp_category(info: dict) -> str:
    """Infer OWASP Top 10 category from Nuclei template tags."""
    tags = info.get("tags", "")
    if isinstance(tags, str):
        tags = tags.lower()
    elif isinstance(tags, list):
        tags = ",".join(tags).lower()
    else:
        tags = ""

    if any(x in tags for x in ["sqli", "sql-injection"]):
        return "A03:2021-Injection"
    if any(x in tags for x in ["xss", "cross-site"]):
        return "A03:2021-Injection"
    if any(x in tags for x in ["ssrf"]):
        return "A10:2021-Server-Side Request Forgery"
    if any(x in tags for x in ["misconfig", "config", "default-login"]):
        return "A05:2021-Security Misconfiguration"
    if any(x in tags for x in ["exposure", "disclosure"]):
        return "A01:2021-Broken Access Control"
    if any(x in tags for x in ["cve", "tech"]):
        return "A06:2021-Vulnerable Components"
    if any(x in tags for x in ["unauth", "auth", "login"]):
        return "A07:2021-Identification and Authentication Failures"
    if any(x in tags for x in ["lfi", "rfi", "traversal"]):
        return "A01:2021-Broken Access Control"
    if any(x in tags for x in ["redirect", "open-redirect"]):
        return "A01:2021-Broken Access Control"
    if any(x in tags for x in ["takeover"]):
        return "A05:2021-Security Misconfiguration"

    return ""
