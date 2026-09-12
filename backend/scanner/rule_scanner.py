"""
matcher.py — Pattern Matching Engine

Consumes the unified rule schema and matches rules against a PageSnapshot.

Supports:
- regex
- string
- version_range
- status_code
- absent
- Nuclei grouped matchers

Includes:
- compiled regex caching
- regex execution timeout
- target-content caching
- diagnostic timing
- protection against pathological regex rules
- passive safety gates for active/OAST Nuclei templates
"""

import re
import regex
import uuid
import time
import logging

from datetime import datetime, timezone
from dataclasses import dataclass, field, asdict
from typing import Optional
from urllib.parse import urlparse

from packaging.version import Version, InvalidVersion

from scanner.response_normalizer import PageSnapshot


logger = logging.getLogger(__name__)


# Maximum amount of content supplied to regex matching.
MAX_REGEX_CONTENT = 1_000_000

# Maximum execution time for one regex operation.
REGEX_TIMEOUT = 0.20


@dataclass
class Finding:
    """A single vulnerability or fingerprint finding."""

    id: str = ""
    scan_id: str = ""
    target_url: str = ""
    timestamp: str = ""

    # Finding details
    source_tool: str = "custom"
    type: str = "vulnerability"
    severity: str = "info"
    title: str = ""
    description: str = ""
    rule_id: str = ""

    # Classification
    cve: str = ""
    cwe: str = ""
    owasp_category: str = ""

    # Evidence
    evidence_location: str = ""
    evidence_pattern: str = ""
    evidence_snippet: str = ""
    detected_version: str = ""
    detected_technology: str = ""

    # CVSS Scoring
    cvss_score: float = 0.0
    cvss_severity: str = ""

    # Remediation
    remediation: str = ""
    mitigation_strategy: str = ""
    reference_urls: list = field(default_factory=list)

    # Correlation
    correlated: bool = False
    correlation_sources: list = field(default_factory=list)

    def to_dict(self):
        return asdict(self)


def _map_nuclei_part_for_scanner(part: str) -> str:
    """
    Map a Nuclei matcher 'part' to a PageSnapshot target.

    interactsh/OAST parts are intentionally NOT mapped to body.
    They require active execution and are rejected by the passive
    Nuclei safety gate.
    """

    part = str(part or "body").lower().strip()

    mapping = {
        "body": "body",
        "header": "header",
        "headers": "header",
        "all": "all",
        "response": "body",
        "raw": "all",
        "server": "server",
        "cookie": "cookie",
        "meta": "meta",
        "comment": "comment",
        "status": "status_code",
        "status_code": "status_code",
    }

    return mapping.get(part, "body")


def _convert_dsl_to_pattern_for_group(expr: str):
    """
    Convert only simple Nuclei DSL expressions into the matcher
    representation understood by _evaluate_nuclei_simple_matcher().

    Complex request-aware, OAST, body_N, header_N and other
    multi-response expressions are intentionally rejected.
    """

    expr = str(expr or "").strip()

    if not expr:
        return None

    # ---------------------------------------------------------------
    # Never turn OAST/interactsh expressions into passive evidence.
    # ---------------------------------------------------------------

    expr_lower = expr.lower()

    if (
        "interactsh" in expr_lower
        or "interactsh_protocol" in expr_lower
    ):
        return None

    # ---------------------------------------------------------------
    # Nuclei numbered response references such as body_1,
    # body_2, header_1 etc. cannot be represented by one
    # PageSnapshot.
    # ---------------------------------------------------------------

    if re.search(
        r"\b(?:body|header|all_headers|response|status_code)_\d+\b",
        expr,
        re.IGNORECASE,
    ):
        return None

    # ---------------------------------------------------------------
    # Common status-code expressions.
    # ---------------------------------------------------------------

    status_match = re.fullmatch(
        r"status_code\s*([=!]=?)\s*(\d+)",
        expr,
        re.IGNORECASE,
    )

    if status_match:

        operator = status_match.group(1)
        code = status_match.group(2)

        if operator in ("==", "="):

            return {
                "match_type": "string",
                "pattern": code,
                "part": "status_code",
            }

        return None

    # ---------------------------------------------------------------
    # Common body/header contains expressions.
    # ---------------------------------------------------------------

    contains_match = re.fullmatch(
        r'(?:contains|contains_all|contains_any)'
        r'\(\s*(body|header|all)\s*,\s*"([^"]+)"\s*\)',
        expr,
        re.IGNORECASE,
    )

    if contains_match:

        part = contains_match.group(1).lower()
        value = contains_match.group(2)

        return {
            "match_type": "string",
            "pattern": value,
            "part": _map_nuclei_part_for_scanner(part),
        }

    # Also support single-quoted simple strings.
    contains_match = re.fullmatch(
        r"(?:contains|contains_all|contains_any)"
        r"\(\s*(body|header|all)\s*,\s*'([^']+)'\s*\)",
        expr,
        re.IGNORECASE,
    )

    if contains_match:

        part = contains_match.group(1).lower()
        value = contains_match.group(2)

        return {
            "match_type": "string",
            "pattern": value,
            "part": _map_nuclei_part_for_scanner(part),
        }

    # ---------------------------------------------------------------
    # Common direct body/header equality expressions.
    # ---------------------------------------------------------------

    simple_match = re.fullmatch(
        r'(body|header)\s*([=!]=?)\s*"([^"]+)"',
        expr,
        re.IGNORECASE,
    )

    if simple_match:

        part = simple_match.group(1).lower()
        operator = simple_match.group(2)
        value = simple_match.group(3)

        if operator in ("==", "="):

            return {
                "match_type": "string",
                "pattern": value,
                "part": _map_nuclei_part_for_scanner(part),
            }

    return None


class Matcher:
    """
    Matches unified rules against a PageSnapshot.
    """

    def __init__(self, rules: list = None):

        self.rules = rules or []

        # Compiled regex cache.
        self._compiled_patterns = {}

        # Cache of target content for the current snapshot.
        self._target_cache = {}

    def load_rules(self, rules: list):
        """Load or replace the rule set."""

        self.rules = rules
        self._compiled_patterns = {}

        for rule in rules:

            pattern = rule.get(
                "pattern",
                ""
            )

            match_type = rule.get(
                "match_type"
            )

            if not pattern:
                continue

            if match_type not in (
                "regex",
                "version_range",
            ):
                continue

            try:

                self._compiled_patterns[
                    rule["id"]
                ] = regex.compile(
                    pattern,
                    regex.IGNORECASE | regex.DOTALL,
                )

            except (
                regex.error,
                re.error,
            ) as e:

                logger.warning(
                    "Invalid regex in rule "
                    "%s: %s",
                    rule.get("id"),
                    e,
                )

    def match_snapshot(
        self,
        snapshot: PageSnapshot,
        scan_id: str,
    ) -> list:
        """
        Run all rules against a PageSnapshot.

        Active/OAST Nuclei templates are excluded from passive
        matching and therefore cannot contribute to findings,
        risk scoring or reports from this snapshot.
        """

        findings = []

        now = datetime.now(
            timezone.utc
        ).isoformat()

        # Cache target content once for this snapshot.
        self._target_cache = {}

        total_rules = len(
            self.rules
        )

        evaluated = 0

        logger.info(
            "[RULE ENGINE] Starting evaluation of %d rules",
            total_rules,
        )

        overall_start = time.monotonic()

        for rule in self.rules:

            if not rule.get(
                "enabled",
                True,
            ):
                continue

            evaluated += 1

            rule_id = rule.get(
                "id",
                "",
            )

            try:

                rule_start = time.monotonic()

                matches = self._evaluate_rule(
                    rule,
                    snapshot,
                )

                elapsed = (
                    time.monotonic()
                    - rule_start
                )

                if elapsed > 0.5:

                    logger.warning(
                        "[RULE SLOW] %s took %.2fs pattern=%r",
                        rule_id,
                        elapsed,
                        rule.get(
                            "pattern",
                            "",
                        )[:100],
                    )

                for match_info in matches:

                    finding = Finding(
                        id=str(
                            uuid.uuid4()
                        ),
                        scan_id=scan_id,
                        target_url=snapshot.url,
                        timestamp=now,

                        source_tool="custom",

                        type=rule.get(
                            "type",
                            "vulnerability",
                        ),

                        severity=rule.get(
                            "severity",
                            "info",
                        ),

                        title=rule.get(
                            "title",
                            rule_id,
                        ),

                        description=rule.get(
                            "description",
                            "",
                        ),

                        rule_id=rule_id,

                        cve=rule.get(
                            "cve",
                            "",
                        ),

                        cwe=rule.get(
                            "cwe",
                            "",
                        ),

                        owasp_category=rule.get(
                            "owasp_category",
                            "",
                        ),

                        evidence_location=match_info.get(
                            "location",
                            "",
                        ),

                        evidence_pattern=rule.get(
                            "pattern",
                            "",
                        ),

                        evidence_snippet=match_info.get(
                            "snippet",
                            "",
                        )[:500],

                        detected_version=match_info.get(
                            "version",
                            "",
                        ),

                        detected_technology=match_info.get(
                            "technology",
                            "",
                        ),

                        remediation=rule.get(
                            "remediation",
                            "",
                        ),

                        reference_urls=rule.get(
                            "references",
                            [],
                        ),
                    )

                    findings.append(
                        finding
                    )

            except Exception as e:

                logger.error(
                    "Error evaluating rule %s: %s",
                    rule_id,
                    e,
                )

            # Progress diagnostics.
            if evaluated % 100 == 0:

                elapsed_total = (
                    time.monotonic()
                    - overall_start
                )

                logger.info(
                    "[RULE PROGRESS] %d/%d rules evaluated "
                    "(%.1fs elapsed, %d findings)",
                    evaluated,
                    total_rules,
                    elapsed_total,
                    len(findings),
                )

        total_elapsed = (
            time.monotonic()
            - overall_start
        )

        logger.info(
            "[RULE ENGINE] Finished: %d rules, "
            "%d findings, %.2fs total",
            evaluated,
            len(findings),
            total_elapsed,
        )

        self._target_cache = {}

        return findings

    def _nuclei_passive_safety_gate(
        self,
        rule: dict,
    ) -> bool:
        """
        Decide whether a Nuclei rule is safe to evaluate against
        the current passive PageSnapshot.

        Returns:
            True  -> safe for passive evaluation
            False -> requires active/request-aware execution
        """

        # -----------------------------------------------------------
        # Only Nuclei grouped rules need this gate.
        # -----------------------------------------------------------

        if rule.get(
            "match_type"
        ) != "nuclei_group":

            return True

        # -----------------------------------------------------------
        # Explicit importer metadata.
        # -----------------------------------------------------------

        if rule.get(
            "nuclei_active_only",
            False,
        ):

            logger.debug(
                "[NUCLEI PASSIVE SKIP] "
                "%s marked active-only",
                rule.get("id"),
            )

            return False

        if rule.get(
            "nuclei_requires_interactsh",
            False,
        ):

            logger.debug(
                "[NUCLEI PASSIVE SKIP] "
                "%s requires interactsh/OAST",
                rule.get("id"),
            )

            return False

        if rule.get(
            "nuclei_unsafe",
            False,
        ):

            logger.debug(
                "[NUCLEI PASSIVE SKIP] "
                "%s marked unsafe",
                rule.get("id"),
            )

            return False

        # -----------------------------------------------------------
        # Raw request safety.
        #
        # A raw request sequence cannot be faithfully represented
        # by the initial PageSnapshot.
        # -----------------------------------------------------------

        raw_requests = rule.get(
            "nuclei_raw_requests",
            [],
        ) or []

        if isinstance(
            raw_requests,
            str,
        ):

            raw_requests = [
                raw_requests
            ]

        if raw_requests:

            # Any interactsh/OAST token makes this active-only.
            for raw_request in raw_requests:

                raw_text = str(
                    raw_request
                ).lower()

                if (
                    "interactsh" in raw_text
                    or "{{interactsh-url}}" in raw_text
                    or "{{interactsh-domain}}" in raw_text
                ):

                    logger.debug(
                        "[NUCLEI PASSIVE SKIP] "
                        "%s raw request uses OAST",
                        rule.get("id"),
                    )

                    return False

            # Multiple raw requests represent a request sequence.
            if len(raw_requests) > 1:

                logger.debug(
                    "[NUCLEI PASSIVE SKIP] "
                    "%s contains %d raw requests",
                    rule.get("id"),
                    len(raw_requests),
                )

                return False

        # -----------------------------------------------------------
        # Host redirects are request execution semantics.
        # Don't treat them as passive response evidence.
        # -----------------------------------------------------------

        if rule.get(
            "nuclei_host_redirects",
            False,
        ):

            logger.debug(
                "[NUCLEI PASSIVE SKIP] "
                "%s uses host-redirects",
                rule.get("id"),
            )

            return False

        # -----------------------------------------------------------
        # Matcher-level safety checks.
        # -----------------------------------------------------------

        matchers = rule.get(
            "nuclei_matchers",
            [],
        ) or []

        for matcher in matchers:

            if not isinstance(
                matcher,
                dict,
            ):
                continue

            part = str(
                matcher.get(
                    "part",
                    "",
                )
            ).lower()

            # interactsh matcher parts cannot be inferred from
            # body/header/status.
            if (
                part == "interactsh_protocol"
                or part.startswith(
                    "interactsh_"
                )
            ):

                logger.debug(
                    "[NUCLEI PASSIVE SKIP] "
                    "%s uses %s matcher",
                    rule.get("id"),
                    part,
                )

                return False

            # -------------------------------------------------------
            # Numbered response references require Nuclei's
            # request/response context.
            # -------------------------------------------------------

            for dsl_expr in (
                matcher.get(
                    "dsl",
                    [],
                ) or []
            ):

                expr = str(
                    dsl_expr
                ).lower()

                if (
                    "interactsh" in expr
                    or re.search(
                        r"\b(?:body|header|all_headers|response)_\d+\b",
                        expr,
                    )
                ):

                    logger.debug(
                        "[NUCLEI PASSIVE SKIP] "
                        "%s uses unsupported request-aware DSL",
                        rule.get("id"),
                    )

                    return False

        # -----------------------------------------------------------
        # Passive evidence gate.
        #
        # A Nuclei rule that only checks HTTP status (for example
        # 200) is not sufficient evidence for a vulnerability.
        # -----------------------------------------------------------

        if rule.get("type", "vulnerability") in (
            "vulnerability",
            "detection",
        ):

            meaningful_matcher = False

            for matcher in matchers:

                matcher_type = str(
                    matcher.get("type", "")
                ).lower()

                if matcher_type in (
                    "word",
                    "regex",
                    "binary",
                ):

                    values = (
                        matcher.get("words")
                        or matcher.get("regex")
                        or []
                    )

                    if isinstance(values, str):
                        values = [values]

                    if values:
                        meaningful_matcher = True
                        break

                elif matcher_type == "dsl":

                    dsl_values = matcher.get(
                        "dsl",
                        [],
                    ) or []

                    if isinstance(dsl_values, str):
                        dsl_values = [dsl_values]

                    for expr in dsl_values:
                        converted = (
                            _convert_dsl_to_pattern_for_group(expr)
                        )

                        if (
                            converted
                            and converted.get("part") != "status_code"
                            and converted.get("pattern")
                        ):
                            meaningful_matcher = True
                            break

                    if meaningful_matcher:
                        break

            if not meaningful_matcher:
                logger.debug(
                    "[NUCLEI PASSIVE SKIP] %s has no meaningful response evidence",
                    rule.get("id"),
                )
                return False

        return True

    def _evaluate_nuclei_group(
        self,
        rule: dict,
        snapshot: PageSnapshot,
    ) -> list:
        """
        Evaluate one complete Nuclei HTTP request.

        Only Nuclei requests that can be faithfully evaluated from
        the current PageSnapshot are allowed.

        Active/OAST/multi-request templates are rejected here.
        """

        # -----------------------------------------------------------
        # SAFETY GATE
        # -----------------------------------------------------------

        if not self._nuclei_passive_safety_gate(
            rule
        ):
            return []

        # -----------------------------------------------------------
        # Endpoint matching.
        # -----------------------------------------------------------

        paths = rule.get(
            "nuclei_paths",
            [],
        ) or []

        if paths:

            snapshot_url = str(
                getattr(
                    snapshot,
                    "url",
                    "",
                )
                or ""
            ).rstrip("/")

            path_matches = False

            for path in paths:

                path = str(
                    path or ""
                ).strip()

                # Root/BaseURL request.
                if path in (
                    "{{BaseURL}}",
                    "{{BaseURL}}/",
                    "/",
                ):

                    path_matches = True
                    break

                # Don't guess template variables.
                if "{{" in path:

                    continue

                if path.startswith("/"):

                    try:

                        parsed = urlparse(
                            snapshot_url
                        )

                        expected = (
                            f"{parsed.scheme}://"
                            f"{parsed.netloc}"
                            f"{path.rstrip('/')}"
                        )

                        if snapshot_url == expected:

                            path_matches = True
                            break

                    except Exception:
                        pass

                elif path == snapshot_url:

                    path_matches = True
                    break

            if not path_matches:
                return []

        # -----------------------------------------------------------
        # Matcher group.
        # -----------------------------------------------------------

        matchers = rule.get(
            "nuclei_matchers",
            [],
        ) or []

        if not matchers:
            return []

        group_condition = str(
            rule.get(
                "nuclei_matchers_condition",
                "or",
            )
        ).lower()

        if group_condition not in (
            "and",
            "or",
        ):

            group_condition = "or"

        matched_results = []
        matcher_results = []

        for matcher in matchers:

            if not isinstance(
                matcher,
                dict,
            ):
                matcher_results.append(
                    False
                )
                continue

            matcher_type = str(
                matcher.get(
                    "type",
                    "word",
                )
            ).lower()

            part = str(
                matcher.get(
                    "part",
                    "body",
                )
            ).lower()

            # -------------------------------------------------------
            # Status matcher.
            # -------------------------------------------------------

            if matcher_type == "status":

                expected_codes = matcher.get(
                    "status",
                    [],
                ) or []

                if not isinstance(
                    expected_codes,
                    list,
                ):

                    expected_codes = [
                        expected_codes
                    ]

                matched = any(
                    str(
                        snapshot.status_code
                    )
                    == str(code)
                    for code in expected_codes
                )

                matcher_results.append(
                    matched
                )

                if matched:

                    matched_results.append({
                        "location": "status_code",
                        "snippet": (
                            f"Status code: "
                            f"{snapshot.status_code}"
                        ),
                    })

                continue

            # -------------------------------------------------------
            # DSL matcher.
            # -------------------------------------------------------

            if matcher_type == "dsl":

                dsl_values = matcher.get(
                    "dsl",
                    [],
                ) or []

                if isinstance(
                    dsl_values,
                    str,
                ):
                    dsl_values = [
                        dsl_values
                    ]

                local_results = []

                for expr in dsl_values:

                    converted = (
                        _convert_dsl_to_pattern_for_group(
                            expr
                        )
                    )

                    if not converted:
                        continue

                    # Status-only DSL is never meaningful vulnerability
                    # evidence. It is handled separately by status matchers.
                    if converted.get("part") == "status_code":
                        continue

                    evidence = (
                        self._evaluate_nuclei_simple_matcher(
                            converted,
                            snapshot,
                        )
                    )

                    if evidence:
                        local_results.append(
                            evidence
                        )

                matched = bool(
                    local_results
                )

                matcher_results.append(
                    matched
                )

                if matched:
                    matched_results.extend(
                        local_results
                    )

                continue

            # -------------------------------------------------------
            # Word / regex / binary matchers.
            # -------------------------------------------------------

            words = matcher.get(
                "words",
                [],
            ) or []

            if (
                not words
                and matcher_type == "regex"
            ):

                words = matcher.get(
                    "regex",
                    [],
                ) or []

            if isinstance(
                words,
                str,
            ):

                words = [
                    words
                ]

            if (
                not isinstance(
                    words,
                    list,
                )
                or not words
            ):

                matcher_results.append(
                    False
                )

                continue

            target = (
                _map_nuclei_part_for_scanner(
                    part
                )
            )

            targets = self._get_target_content(
                target,
                snapshot,
            )

            content_values = [
                content
                for _, content in targets
                if content
            ]

            if not content_values:

                matcher_results.append(
                    False
                )

                continue

            matcher_condition = str(
                matcher.get(
                    "condition",
                    "or",
                )
            ).lower()

            if matcher_condition not in (
                "and",
                "or",
            ):

                matcher_condition = "or"

            individual_results = []

            for word in words:

                word = str(
                    word
                )

                matched_one = False
                evidence = None

                for content in content_values:

                    if matcher_type in (
                        "word",
                        "binary",
                    ):

                        result = self._match_string(
                            word,
                            content,
                        )

                    elif matcher_type == "regex":

                        fake_rule = {
                            "id": (
                                f"{rule.get('id')}:"
                                f"{matcher.get('index', 0)}"
                            )
                        }

                        result = self._match_regex(
                            fake_rule,
                            word,
                            content,
                        )

                    else:

                        result = None

                    if result:

                        matched_one = True
                        evidence = result
                        break

                individual_results.append(
                    matched_one
                )

                if (
                    matched_one
                    and evidence
                ):

                    matched_results.append({
                        "location": part,
                        "snippet": evidence.get(
                            "snippet",
                            "",
                        )[:200],
                    })

            if matcher_condition == "and":

                matcher_matched = all(
                    individual_results
                )

            else:

                matcher_matched = any(
                    individual_results
                )

            matcher_results.append(
                matcher_matched
            )

        # -----------------------------------------------------------
        # Group condition.
        # -----------------------------------------------------------

        # Status-code match alone is never sufficient evidence for a
        # vulnerability/detection Nuclei rule.
        meaningful_results = []

        for matcher, matched in zip(
            matchers,
            matcher_results,
        ):

            if not isinstance(
                matcher,
                dict,
            ):
                continue

            matcher_type = str(
                matcher.get(
                    "type",
                    "word",
                )
            ).lower()

            # Status matchers are supporting evidence only.
            if matcher_type == "status":
                continue

            meaningful_results.append(
                matched
            )

        if not meaningful_results:
            return []

        if group_condition == "and":

            group_matched = all(
                matcher_results
            ) and all(
                meaningful_results
            )

        else:

            # At least one meaningful matcher must actually match.
            group_matched = any(
                meaningful_results
            )

        if not group_matched:
            return []

        # -----------------------------------------------------------
        # FINAL VULNERABILITY EVIDENCE REQUIREMENT
        #
        # HTTP status alone is never proof of a vulnerability.
        # For vulnerability/detection rules, at least one actual
        # response-content matcher must have produced evidence.
        # -----------------------------------------------------------

        rule_type = str(
            rule.get(
                "type",
                "vulnerability",
            )
        ).lower()

        if rule_type in (
            "vulnerability",
            "detection",
        ):

            if not matched_results:
                logger.debug(
                    "[NUCLEI EVIDENCE REJECT] %s matched without "
                    "actual response evidence",
                    rule.get("id"),
                )
                return []

            # Reject a finding if every matched result is only a
            # status-code observation.
            non_status_evidence = [
                item
                for item in matched_results
                if str(
                    item.get(
                        "location",
                        "",
                    )
                ).lower()
                not in (
                    "status",
                    "status_code",
                )
            ]

            if not non_status_evidence:
                logger.debug(
                    "[NUCLEI EVIDENCE REJECT] %s matched only "
                    "HTTP status evidence",
                    rule.get("id"),
                )
                return []

        # -----------------------------------------------------------
        # Evidence.
        # -----------------------------------------------------------

        evidence = (
            next(
                (
                    item
                    for item in matched_results
                    if str(
                        item.get(
                            "location",
                            "",
                        )
                    ).lower()
                    not in (
                        "status",
                        "status_code",
                    )
                ),
                matched_results[0],
            )
            if matched_results
            else {
                "location": "nuclei",
                "snippet": "",
            }
        )

        return [{
            "location": evidence.get(
                "location",
                "nuclei",
            ),
            "snippet": evidence.get(
                "snippet",
                "",
            )[:500],
            "matched": True,
        }]

    def _evaluate_nuclei_simple_matcher(
        self,
        matcher: dict,
        snapshot: PageSnapshot,
    ) -> Optional[dict]:
        """Evaluate a converted simple Nuclei matcher and return actual evidence."""

        match_type = matcher.get(
            "match_type",
            "string",
        )

        pattern = str(
            matcher.get(
                "pattern",
                "",
            )
        )

        if not pattern:
            return None

        target = matcher.get(
            "part",
            "body",
        )

        targets = self._get_target_content(
            target,
            snapshot,
        )

        for location_name, content in targets:

            if not content:
                continue

            if match_type == "string":

                result = self._match_string(
                    pattern,
                    content,
                )

            elif match_type == "regex":

                fake_rule = {
                    "id": (
                        "nuclei-dsl:"
                        + pattern[:40]
                    )
                }

                result = self._match_regex(
                    fake_rule,
                    pattern,
                    content,
                )

            else:
                result = None

            if result:
                return {
                    "location": location_name,
                    "snippet": result.get(
                        "snippet",
                        "",
                    )[:200],
                    "matched": True,
                }

        return None

    def _evaluate_rule(
        self,
        rule: dict,
        snapshot: PageSnapshot,
    ) -> list:
        """
        Evaluate one rule against the snapshot.
        """

        # Nuclei HTTP requests use grouped matcher semantics.
        if rule.get(
            "match_type"
        ) == "nuclei_group":

            return self._evaluate_nuclei_group(
                rule,
                snapshot,
            )

        target = rule.get(
            "target_location",
            "body",
        )

        match_type = rule.get(
            "match_type",
            "string",
        )

        pattern = rule.get(
            "pattern",
            "",
        )

        if not pattern:
            return []

        targets = self._get_target_content(
            target,
            snapshot,
        )

        matches = []

        for location_name, content in targets:

            if not content:
                continue

            if match_type == "string":

                result = self._match_string(
                    pattern,
                    content,
                )

            elif match_type == "regex":

                result = self._match_regex(
                    rule,
                    pattern,
                    content,
                )

            elif match_type == "version_range":

                result = self._match_version(
                    rule,
                    pattern,
                    content,
                )

            elif match_type == "status_code":

                result = self._match_status(
                    pattern,
                    snapshot.status_code,
                )

            elif match_type == "absent":

                result = self._match_absent(
                    pattern,
                    content,
                )

            else:

                continue

            if result:

                result["location"] = (
                    location_name
                )

                matches.append(
                    result
                )

        return matches

    def _get_target_content(
        self,
        target: str,
        snapshot: PageSnapshot,
    ) -> list:
        """
        Return target content.

        Results are cached per target so the same body/header/script
        data is not rebuilt 1000+ times.
        """

        if target in self._target_cache:

            return self._target_cache[
                target
            ]

        if target == "body":

            results = [
                (
                    "body",
                    snapshot.body_lower,
                )
            ]

        elif target == "header":

            header_str = "\n".join(
                f"{k}: {v}"
                for k, v in snapshot.headers.items()
            )

            results = [
                (
                    "header",
                    header_str.lower(),
                )
            ]

        elif target == "header_key":

            results = [
                (
                    f"header:{k}",
                    v.lower(),
                )
                for k, v in snapshot.headers.items()
            ]

        elif target == "script":

            results = [
                (
                    "script_src",
                    " ".join(
                        snapshot.scripts
                    ).lower(),
                )
            ]

            for i, js in enumerate(
                snapshot.inline_scripts
            ):

                results.append(
                    (
                        f"inline_script_{i}",
                        js.lower(),
                    )
                )

        elif target == "cookie":

            cookie_str = "\n".join(
                f"{k}: {v}"
                for k, v in snapshot.cookies.items()
            )

            results = [
                (
                    "cookie",
                    cookie_str.lower(),
                )
            ]

        elif target == "meta":

            meta_str = "\n".join(
                f"{k}: {v}"
                for k, v in snapshot.meta_tags.items()
            )

            results = [
                (
                    "meta",
                    meta_str.lower(),
                )
            ]

        elif target == "comment":

            results = [
                (
                    "comment",
                    " ".join(
                        snapshot.comments
                    ).lower(),
                )
            ]

        elif target == "server":

            results = [
                (
                    "server",
                    snapshot.server.lower(),
                )
            ]

        elif target == "all":

            results = [
                (
                    "body",
                    snapshot.body_lower,
                )
            ]

            header_str = "\n".join(
                f"{k}: {v}"
                for k, v in snapshot.headers.items()
            )

            results.append(
                (
                    "header",
                    header_str.lower(),
                )
            )

            results.append(
                (
                    "script_src",
                    " ".join(
                        snapshot.scripts
                    ).lower(),
                )
            )

            for i, js in enumerate(
                snapshot.inline_scripts
            ):

                results.append(
                    (
                        f"inline_script_{i}",
                        js.lower(),
                    )
                )

        else:

            results = [
                (
                    "body",
                    snapshot.body_lower,
                )
            ]

        self._target_cache[
            target
        ] = results

        return results

    def _match_string(
        self,
        pattern: str,
        content: str,
    ) -> Optional[dict]:
        """Simple case-insensitive substring match."""

        pattern_lower = pattern.lower()

        idx = content.find(
            pattern_lower
        )

        if idx >= 0:

            start = max(
                0,
                idx - 50,
            )

            end = min(
                len(content),
                idx + len(pattern_lower) + 50,
            )

            return {
                "snippet": content[
                    start:end
                ],
                "matched": True,
            }

        return None

    def _match_literal_lookaheads(
        self,
        pattern: str,
        content: str,
    ) -> Optional[dict]:
        """
        Fast path for Nuclei-generated literal lookahead patterns.

        Example:
            (?=.*foo)(?=.*bar)

        This is equivalent to checking that both literal strings
        exist in the content, avoiding expensive regex backtracking.
        """

        if not pattern.startswith(
            "(?=.*"
        ):

            return None

        try:

            parts = re.findall(
                r"\(\?=\.\*(.*?)\)",
                pattern,
            )

            if len(parts) < 2:

                return None

            for part in parts:

                if part.lower() not in content:

                    return {
                        "matched": False
                    }

            return {
                "snippet": " | ".join(
                    parts
                )[:200],
                "matched": True,
            }

        except Exception:

            return None

    def _match_regex(
        self,
        rule: dict,
        pattern: str,
        content: str,
    ) -> Optional[dict]:
        """
        Regex match protected by a hard timeout.
        """

        fast_result = (
            self._match_literal_lookaheads(
                pattern,
                content,
            )
        )

        if fast_result is not None:

            if fast_result.get(
                "matched"
            ):

                return fast_result

            return None

        compiled = self._compiled_patterns.get(
            rule["id"]
        )

        if not compiled:

            try:

                compiled = regex.compile(
                    pattern,
                    regex.IGNORECASE
                    | regex.DOTALL,
                )

                self._compiled_patterns[
                    rule["id"]
                ] = compiled

            except (
                regex.error,
                re.error,
            ) as e:

                logger.warning(
                    "[REGEX INVALID] %s: %s",
                    rule.get("id"),
                    e,
                )

                return None

        safe_content = content[
            :MAX_REGEX_CONTENT
        ]

        try:

            match = compiled.search(
                safe_content,
                timeout=REGEX_TIMEOUT,
            )

        except TimeoutError:

            logger.warning(
                "[REGEX TIMEOUT] rule=%s "
                "pattern=%r",
                rule.get("id"),
                pattern[:120],
            )

            return None

        except regex.error as e:

            logger.warning(
                "[REGEX ERROR] rule=%s: %s",
                rule.get("id"),
                e,
            )

            return None

        if not match:

            return None

        result = {
            "snippet": match.group(
                0
            )[:200],
            "matched": True,
        }

        if (
            match.lastindex
            and match.lastindex >= 1
        ):

            try:

                result["version"] = (
                    match.group(1)
                )

            except IndexError:

                result["version"] = ""

            result["technology"] = (
                rule.get(
                    "technology",
                    "",
                )
            )

        return result

    def _match_version(
        self,
        rule: dict,
        pattern: str,
        content: str,
    ) -> Optional[dict]:
        """
        Version-aware matching with regex timeout.
        """

        compiled = self._compiled_patterns.get(
            rule["id"]
        )

        if not compiled:

            try:

                compiled = regex.compile(
                    pattern,
                    regex.IGNORECASE,
                )

                self._compiled_patterns[
                    rule["id"]
                ] = compiled

            except (
                regex.error,
                re.error,
            ) as e:

                logger.warning(
                    "[VERSION REGEX INVALID] %s: %s",
                    rule.get("id"),
                    e,
                )

                return None

        safe_content = content[
            :MAX_REGEX_CONTENT
        ]

        try:

            match = compiled.search(
                safe_content,
                timeout=REGEX_TIMEOUT,
            )

        except TimeoutError:

            logger.warning(
                "[VERSION REGEX TIMEOUT] "
                "rule=%s pattern=%r",
                rule.get("id"),
                pattern[:120],
            )

            return None

        except regex.error as e:

            logger.warning(
                "[VERSION REGEX ERROR] "
                "rule=%s: %s",
                rule.get("id"),
                e,
            )

            return None

        if not match:

            return None

        detected_version = ""

        if (
            match.lastindex
            and match.lastindex >= 1
        ):

            try:

                detected_version = (
                    match.group(1)
                )

            except IndexError:

                detected_version = ""

        else:

            detected_version = (
                match.group(0)
            )

        if not detected_version:

            return None

        min_safe = rule.get(
            "min_safe_version",
            "",
        )

        if min_safe:

            try:

                if (
                    Version(
                        detected_version
                    )
                    < Version(
                        min_safe
                    )
                ):

                    return {
                        "snippet": match.group(
                            0
                        )[:200],

                        "version": (
                            detected_version
                        ),

                        "technology": rule.get(
                            "technology",
                            "",
                        ),

                        "matched": True,
                    }

            except InvalidVersion:

                return {
                    "snippet": match.group(
                        0
                    )[:200],

                    "version": (
                        detected_version
                    ),

                    "technology": rule.get(
                        "technology",
                        "",
                    ),

                    "matched": True,
                }

        if rule.get(
            "type"
        ) == "fingerprint":

            return {
                "snippet": match.group(
                    0
                )[:200],

                "version": (
                    detected_version
                ),

                "technology": rule.get(
                    "technology",
                    "",
                ),

                "matched": True,
            }

        return None

    def _match_status(
        self,
        pattern: str,
        status_code: int,
    ) -> Optional[dict]:
        """Match against HTTP status code."""

        try:

            expected = int(
                pattern
            )

            if status_code == expected:

                return {
                    "snippet": (
                        f"Status code: "
                        f"{status_code}"
                    ),
                    "matched": True,
                }

        except ValueError:

            pass

        return None

    def _match_absent(
        self,
        pattern: str,
        content: str,
    ) -> Optional[dict]:
        """Match when a pattern is ABSENT."""

        if (
            pattern.lower()
            not in content.lower()
        ):

            return {
                "snippet": (
                    f"Missing: {pattern}"
                ),
                "matched": True,
            }

        return None
