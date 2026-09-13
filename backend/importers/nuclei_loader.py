"""
nuclei_importer.py — Nuclei Template Importer

Parses selected Nuclei YAML templates into the unified BlindSpot
rule schema.

Safety behavior:
- One Nuclei HTTP request remains one logical matcher group.
- Endpoint-specific paths are preserved.
- HTTP methods are preserved.
- Unsafe Nuclei templates are marked as active-only.
- Templates requiring interactsh/OAST callbacks are marked
  as active-only.
- Raw request definitions are preserved for future request-aware
  active scanning.
- Unsupported matcher semantics are NOT guessed or converted
  into false passive evidence.
"""

import os
import re
import logging

import yaml


logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Severity mapping
# ---------------------------------------------------------------------------

SEVERITY_MAP = {
    "critical": "critical",
    "high": "high",
    "medium": "medium",
    "low": "low",
    "info": "info",
    "unknown": "info",
}


# ---------------------------------------------------------------------------
# Nuclei matcher type mapping
# ---------------------------------------------------------------------------

MATCHER_TYPE_MAP = {
    "word": "string",
    "regex": "regex",
    "status": "status_code",
    "binary": "string",
    "dsl": "dsl",
}


# ---------------------------------------------------------------------------
# Import filter
# ---------------------------------------------------------------------------

IMPORT_TAGS = {
    "cve",
    "tech",
    "misconfig",
    "exposure",
    "config",
    "default-login",
    "xss",
    "sqli",
    "lfi",
    "rfi",
    "ssrf",
    "redirect",
    "disclosure",
    "token",
    "unauth",
    "takeover",
    "panel",
    "iot",
    "wordpress",
    "joomla",
    "drupal",
    "apache",
    "nginx",
    "jenkins",
    "docker",
    "kubernetes",
    "cloud",
    "aws",
    "azure",
    "gcp",
    "git",
    "backup",
    "debug",
    "api",
    "graphql",
    "swagger",
    "phpmyadmin",
    "adminer",
    "login",
    "rce",
    "deserialization",
    "ssti",
    "xxe",
    "cors",
    "crlf",
    "header-injection",
    "open-redirect",
}


# ---------------------------------------------------------------------------
# Nuclei matcher-group builder
# ---------------------------------------------------------------------------

def _build_nuclei_matcher_group(
    template_id,
    template_info,
    request_index,
    request,
):
    """
    Preserve one complete Nuclei HTTP request as one logical group.

    Important:
    Nuclei templates can contain active/exploit-style requests and
    OAST/interactsh callbacks. These must not accidentally become
    passive findings from an unrelated PageSnapshot.

    We therefore preserve:
        - method
        - paths
        - raw requests
        - unsafe flag
        - host-redirects
        - matcher semantics
        - interactsh requirement
    """

    if not isinstance(request, dict):
        return {
            "template_id": template_id,
            "request_index": request_index,
            "method": "GET",
            "paths": [],
            "matchers_condition": "or",
            "matchers": [],
            "name": template_info.get("name", template_id),
            "unsafe": False,
            "host_redirects": False,
            "raw_requests": [],
            "requires_interactsh": False,
        }

    matchers = request.get("matchers", []) or []

    if not isinstance(matchers, list):
        matchers = []

    condition = str(
        request.get(
            "matchers-condition",
            "or",
        )
    ).lower().strip()

    if condition not in ("and", "or"):
        condition = "or"

    paths = request.get("path", []) or []

    if isinstance(paths, str):
        paths = [paths]

    if not isinstance(paths, list):
        paths = []

    paths = [
        str(path).strip()
        for path in paths
        if str(path).strip()
    ]

    # Some Nuclei templates use raw HTTP requests instead of path/method.
    raw_requests = request.get("raw", []) or []

    if isinstance(raw_requests, str):
        raw_requests = [raw_requests]

    if not isinstance(raw_requests, list):
        raw_requests = []

    raw_requests = [
        str(raw)
        for raw in raw_requests
        if str(raw).strip()
    ]

    method = str(
        request.get(
            "method",
            "GET",
        )
    ).upper().strip()

    if not method:
        method = "GET"

    unsafe = bool(
        request.get(
            "unsafe",
            False,
        )
    )

    host_redirects = bool(
        request.get(
            "host-redirects",
            False,
        )
    )

    normalized = []

    for matcher_index, matcher in enumerate(matchers):

        if not isinstance(matcher, dict):
            continue

        matcher_type = str(
            matcher.get(
                "type",
                "word",
            )
        ).lower().strip()

        part = str(
            matcher.get(
                "part",
                "body",
            )
        ).lower().strip()

        matcher_condition = str(
            matcher.get(
                "condition",
                "or",
            )
        ).lower().strip()

        if matcher_condition not in ("and", "or"):
            matcher_condition = "or"

        words = matcher.get(
            "words",
            [],
        ) or []

        regex_values = matcher.get(
            "regex",
            [],
        ) or []

        status = matcher.get(
            "status",
            [],
        ) or []

        dsl = matcher.get(
            "dsl",
            [],
        ) or []

        if isinstance(words, str):
            words = [words]

        if isinstance(regex_values, str):
            regex_values = [regex_values]

        if isinstance(status, (str, int)):
            status = [status]

        if isinstance(dsl, str):
            dsl = [dsl]

        if not isinstance(words, list):
            words = []

        if not isinstance(regex_values, list):
            regex_values = []

        if not isinstance(status, list):
            status = []

        if not isinstance(dsl, list):
            dsl = []

        item = {
            "index": matcher_index,
            "type": matcher_type,
            "part": part,
            "condition": matcher_condition,
            "words": words,
            "regex": regex_values,
            "status": status,
            "dsl": dsl,
        }

        normalized.append(item)

    # ---------------------------------------------------------------
    # Detect OAST / interactsh requirements.
    # ---------------------------------------------------------------

    requires_interactsh = False

    for matcher in normalized:

        matcher_part = str(
            matcher.get(
                "part",
                "",
            )
        ).lower()

        if (
            matcher_part == "interactsh_protocol"
            or matcher_part.startswith("interactsh_")
        ):
            requires_interactsh = True
            break

        for expression in matcher.get("dsl", []) or []:

            expression_text = str(
                expression
            ).lower()

            if (
                "interactsh" in expression_text
                or "interactsh_protocol" in expression_text
            ):
                requires_interactsh = True
                break

        if requires_interactsh:
            break

    # Raw requests containing interactsh URLs are also OAST-dependent.
    if not requires_interactsh:

        for raw_request in raw_requests:

            if "interactsh" in raw_request.lower():
                requires_interactsh = True
                break

    return {
        "template_id": template_id,
        "request_index": request_index,
        "method": method,
        "paths": paths,
        "matchers_condition": condition,
        "matchers": normalized,
        "name": template_info.get(
            "name",
            template_id,
        ),

        # Request semantics.
        "unsafe": unsafe,
        "host_redirects": host_redirects,
        "raw_requests": raw_requests,

        # Evidence requirements.
        "requires_interactsh": requires_interactsh,
    }


# ---------------------------------------------------------------------------
# Import all templates
# ---------------------------------------------------------------------------

def import_nuclei_templates(
    templates_dir: str,
    max_templates: int = 500,
) -> list:
    """
    Import selected Nuclei YAML templates into the unified rule schema.

    Args:
        templates_dir:
            Path to the Nuclei templates directory.

        max_templates:
            Maximum number of templates to import.

    Returns:
        List of unified BlindSpot rule dictionaries.
    """

    rules = []

    if not os.path.isdir(templates_dir):

        logger.warning(
            "[NucleiImporter] Templates dir not found: %s",
            templates_dir,
        )

        return rules

    # ---------------------------------------------------------------
    # Find YAML templates.
    # ---------------------------------------------------------------

    yaml_files = []

    for root, dirs, files in os.walk(templates_dir):

        for filename in files:

            if filename.endswith(
                (
                    ".yaml",
                    ".yml",
                )
            ):

                yaml_files.append(
                    os.path.join(
                        root,
                        filename,
                    )
                )

    logger.info(
        "[NucleiImporter] Found %d YAML templates",
        len(yaml_files),
    )

    imported = 0

    for filepath in yaml_files:

        if imported >= max_templates:
            break

        try:

            template_rules = _parse_template(
                filepath
            )

            if template_rules:

                rules.extend(
                    template_rules
                )

                imported += 1

        except Exception as exc:

            logger.debug(
                "[NucleiImporter] Skipping %s: %s",
                filepath,
                exc,
            )

    logger.info(
        "[NucleiImporter] Imported %d rules from %d templates",
        len(rules),
        imported,
    )

    return rules


# ---------------------------------------------------------------------------
# Template import filtering
# ---------------------------------------------------------------------------

def _should_import(info: dict) -> bool:
    """
    Check whether a Nuclei template should be imported.

    A template is imported when at least one of its tags belongs
    to IMPORT_TAGS.
    """

    if not isinstance(info, dict):
        return False

    tags = info.get(
        "tags",
        "",
    )

    if isinstance(tags, str):

        tag_set = {
            tag.strip().lower()
            for tag in tags.split(",")
            if tag.strip()
        }

    elif isinstance(tags, list):

        tag_set = {
            str(tag).strip().lower()
            for tag in tags
            if str(tag).strip()
        }

    else:

        return False

    return bool(
        tag_set & IMPORT_TAGS
    )


# ---------------------------------------------------------------------------
# Parse one template
# ---------------------------------------------------------------------------

def _parse_template(
    filepath: str,
) -> list:
    """
    Parse one Nuclei YAML template into BlindSpot rules.
    """

    try:

        with open(
            filepath,
            "r",
            errors="replace",
        ) as file:

            try:
                template = yaml.safe_load(file)

            except yaml.YAMLError:

                return []

    except OSError as exc:

        logger.debug(
            "[NucleiImporter] Cannot read %s: %s",
            filepath,
            exc,
        )

        return []

    if not template or not isinstance(
        template,
        dict,
    ):
        return []

    template_id = str(
        template.get(
            "id",
            "",
        )
    ).strip()

    info = template.get(
        "info",
        {},
    )

    if not template_id or not isinstance(
        info,
        dict,
    ):
        return []

    if not _should_import(info):
        return []

    # ---------------------------------------------------------------
    # Severity.
    # ---------------------------------------------------------------

    severity = SEVERITY_MAP.get(
        str(
            info.get(
                "severity",
                "info",
            )
        ).lower(),
        "info",
    )

    # ---------------------------------------------------------------
    # Classification.
    # ---------------------------------------------------------------

    classification = (
        info.get(
            "classification",
            {},
        )
        or {}
    )

    if not isinstance(
        classification,
        dict,
    ):
        classification = {}

    cve_id = ""
    cwe_id = ""

    cve_ids = classification.get(
        "cve-id",
        [],
    )

    if isinstance(
        cve_ids,
        list,
    ) and cve_ids:

        cve_id = str(
            cve_ids[0]
        )

    elif isinstance(
        cve_ids,
        str,
    ):

        cve_id = cve_ids

    cwe_ids = classification.get(
        "cwe-id",
        [],
    )

    if isinstance(
        cwe_ids,
        list,
    ) and cwe_ids:

        cwe_id = str(
            cwe_ids[0]
        )

    elif isinstance(
        cwe_ids,
        str,
    ):

        cwe_id = cwe_ids

    # ---------------------------------------------------------------
    # Metadata.
    # ---------------------------------------------------------------

    owasp = _infer_owasp_category(
        info
    )

    template_name = str(
        info.get(
            "name",
            template_id,
        )
    )

    description = info.get(
        "description",
        f"Nuclei template: {template_name}",
    )

    if not isinstance(
        description,
        str,
    ):
        description = str(
            description
        )

    remediation = info.get(
        "remediation",
        "",
    )

    if not isinstance(
        remediation,
        str,
    ):
        remediation = str(
            remediation
        )

    references = info.get(
        "reference",
        [],
    )

    if isinstance(
        references,
        str,
    ):

        references = [
            references
        ]

    elif not isinstance(
        references,
        list,
    ):

        references = []

    references = [
        str(reference)
        for reference in references
        if str(reference).strip()
    ]

    # ---------------------------------------------------------------
    # HTTP requests.
    # ---------------------------------------------------------------

    http_reqs = template.get(
        "http",
        template.get(
            "requests",
            [],
        ),
    )

    if not isinstance(
        http_reqs,
        list,
    ):
        return []

    rules = []

    for req_index, request in enumerate(
        http_reqs
    ):

        if not isinstance(
            request,
            dict,
        ):
            continue

        matchers = request.get(
            "matchers",
            [],
        )

        if not isinstance(
            matchers,
            list,
        ) or not matchers:

            continue

        matcher_group = (
            _build_nuclei_matcher_group(
                template_id=template_id,
                template_info=info,
                request_index=req_index,
                request=request,
            )
        )

        if not matcher_group[
            "matchers"
        ]:

            continue

        # -----------------------------------------------------------
        # First matcher remains compatibility metadata.
        # -----------------------------------------------------------

        first_matcher = (
            matcher_group[
                "matchers"
            ][0]
        )

        rule_id = (
            f"nuclei-{template_id}-"
            f"{req_index}"
        )

        # -----------------------------------------------------------
        # IMPORTANT:
        #
        # Active/OAST templates are still imported so future
        # request-aware active scanning can use them.
        #
        # But they are explicitly marked active-only.
        # -----------------------------------------------------------

        active_only = bool(
            matcher_group[
                "unsafe"
            ]
            or matcher_group[
                "requires_interactsh"
            ]
            or matcher_group[
                "raw_requests"
            ]
        )

        rules.append({

            "id": rule_id,

            "enabled": True,

            "type": (
                "vulnerability"
                if cve_id
                else "misconfiguration"
            ),

            # Compatibility fields.
            "target_location": (
                _map_part_to_location(
                    first_matcher.get(
                        "part",
                        "body",
                    )
                )
            ),

            "match_type": "nuclei_group",

            "pattern": template_name,

            "severity": severity,

            "title": template_name,

            "description": description,

            "cve": cve_id,

            "cwe": cwe_id,

            "owasp_category": owasp,

            "remediation": remediation,

            "references": references,

            "source": "nuclei",

            "nuclei_template_id": template_id,

            # -------------------------------------------------------
            # Complete Nuclei request semantics.
            # -------------------------------------------------------

            "nuclei_request_index": req_index,

            "nuclei_method": matcher_group[
                "method"
            ],

            "nuclei_paths": matcher_group[
                "paths"
            ],

            "nuclei_matchers_condition": matcher_group[
                "matchers_condition"
            ],

            "nuclei_matchers": matcher_group[
                "matchers"
            ],

            # -------------------------------------------------------
            # Safety / execution metadata.
            # -------------------------------------------------------

            "nuclei_unsafe": matcher_group[
                "unsafe"
            ],

            "nuclei_host_redirects": matcher_group[
                "host_redirects"
            ],

            "nuclei_raw_requests": matcher_group[
                "raw_requests"
            ],

            "nuclei_requires_interactsh": matcher_group[
                "requires_interactsh"
            ],

            "nuclei_active_only": active_only,
        })

    return rules


# ---------------------------------------------------------------------------
# Compatibility helper
# ---------------------------------------------------------------------------

def _map_part_to_location(
    part: str,
) -> str:
    """
    Map Nuclei matcher 'part' to BlindSpot target_location.
    """

    part = str(
        part or "body"
    ).lower().strip()

    mapping = {

        "body": "body",

        "header": "header",

        "headers": "header",

        "response": "body",

        "all": "all",

        "status": "status_code",

        "status_code": "status_code",

        # interactsh is NOT actually body evidence.
        # It is retained as metadata and handled by the
        # active-only safety gate.
        "interactsh_protocol": "body",
    }

    return mapping.get(
        part,
        "body",
    )


# ---------------------------------------------------------------------------
# Simple DSL conversion
# ---------------------------------------------------------------------------

def _convert_dsl_to_pattern(
    dsl_expr: str,
) -> dict:
    """
    Convert only simple, safely-supported Nuclei DSL expressions.

    Unsupported/complex DSL is intentionally rejected instead of
    being guessed.
    """

    if not isinstance(
        dsl_expr,
        str,
    ):
        return None

    dsl_expr = dsl_expr.strip()

    if not dsl_expr:
        return None

    # ---------------------------------------------------------------
    # OAST/interactsh expressions must never be converted into
    # passive response evidence.
    # ---------------------------------------------------------------

    if (
        "interactsh" in dsl_expr.lower()
        or "interactsh_protocol" in dsl_expr.lower()
    ):
        return None

    # ---------------------------------------------------------------
    # contains(body, "string")
    # contains(all_headers, "string")
    # contains(header, "string")
    # contains(response, "string")
    # ---------------------------------------------------------------

    match = re.fullmatch(
        r'contains\(\s*'
        r'(body|all_headers|header|response)'
        r'\s*,\s*'
        r'["\'](.+?)["\']'
        r'\s*\)',
        dsl_expr,
        re.IGNORECASE,
    )

    if match:

        part_name = match.group(
            1
        ).lower()

        search_string = match.group(
            2
        )

        part_map = {
            "body": "body",
            "all_headers": "header",
            "header": "header",
            "response": "body",
        }

        return {
            "match_type": "string",
            "pattern": search_string,
            "part": part_map.get(
                part_name,
                "body",
            ),
        }

    # ---------------------------------------------------------------
    # status_code == 200
    # ---------------------------------------------------------------

    match = re.fullmatch(
        r"status_code\s*==\s*(\d+)",
        dsl_expr,
        re.IGNORECASE,
    )

    if match:

        return {
            "match_type": "status_code",
            "pattern": match.group(1),
            "part": "status",
        }

    # ---------------------------------------------------------------
    # contains(body, "a") && contains(body, "b")
    #
    # Keep this only for a simple literal AND expression.
    # ---------------------------------------------------------------

    if "&&" in dsl_expr:

        parts = re.findall(
            r'contains\(\s*'
            r'(?:body|response)'
            r'\s*,\s*'
            r'["\'](.+?)["\']'
            r'\s*\)',
            dsl_expr,
            re.IGNORECASE,
        )

        if len(parts) >= 2:

            escaped = [
                re.escape(part)
                for part in parts
            ]

            combo_pattern = (
                "(?=.*"
                + ")(?=.*".join(
                    escaped
                )
                + ")"
            )

            return {
                "match_type": "regex",
                "pattern": combo_pattern,
                "part": "body",
            }

    # ---------------------------------------------------------------
    # Unsupported DSL.
    # ---------------------------------------------------------------

    return None


# ---------------------------------------------------------------------------
# OWASP mapping
# ---------------------------------------------------------------------------

def _infer_owasp_category(
    info: dict,
) -> str:
    """
    Infer an OWASP Top 10 category from Nuclei tags.
    """

    if not isinstance(
        info,
        dict,
    ):
        return ""

    tags = info.get(
        "tags",
        "",
    )

    if isinstance(
        tags,
        str,
    ):

        tags_text = tags.lower()

    elif isinstance(
        tags,
        list,
    ):

        tags_text = ",".join(
            str(tag)
            for tag in tags
        ).lower()

    else:

        tags_text = ""

    if any(
        value in tags_text
        for value in (
            "sqli",
            "sql-injection",
        )
    ):

        return "A05:2025-Injection"

    if any(
        value in tags_text
        for value in (
            "xss",
            "cross-site",
        )
    ):

        return "A05:2025-Injection"

    if "ssrf" in tags_text:

        return (
            "A01:2025-"
            "Server-Side Request Forgery"
        )

    if any(
        value in tags_text
        for value in (
            "misconfig",
            "config",
            "default-login",
        )
    ):

        return "A02:2025-Security Misconfiguration"

    if any(
        value in tags_text
        for value in (
            "exposure",
            "disclosure",
        )
    ):

        return (
            "A01:2025-"
            "Broken Access Control"
        )

    if any(
        value in tags_text
        for value in (
            "cve",
            "tech",
        )
    ):

        return "A03:2025-Software Supply Chain Failures"

    if any(
        value in tags_text
        for value in (
            "unauth",
            "auth",
            "login",
        )
    ):

        return (
            "A07:2025-"
            "Identification and Authentication Failures"
        )

    if any(
        value in tags_text
        for value in (
            "lfi",
            "rfi",
            "traversal",
        )
    ):

        return (
            "A01:2025-"
            "Broken Access Control"
        )

    if any(
        value in tags_text
        for value in (
            "redirect",
            "open-redirect",
        )
    ):

        return (
            "A01:2025-"
            "Broken Access Control"
        )

    if "takeover" in tags_text:

        return (
            "A02:2025-"
            "A02:2025-Security Misconfiguration"
        )

    return ""
