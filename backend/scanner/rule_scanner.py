"""
matcher.py — Pattern Matching Engine

Consumes the unified rule schema and matches rules against a PageSnapshot.

Supports:
- regex
- string
- version_range
- status_code
- absent

Includes:
- compiled regex caching
- regex execution timeout
- target-content caching
- diagnostic timing
- protection against pathological regex rules
"""

import re
import regex
import uuid
import time
import logging

from datetime import datetime, timezone
from dataclasses import dataclass, field, asdict
from typing import Optional

from packaging.version import Version, InvalidVersion

from scanner.response_normalizer import PageSnapshot


logger = logging.getLogger(__name__)


# Maximum amount of content supplied to regex matching.
# This prevents very large pages/scripts from causing excessive
# regex processing time.
MAX_REGEX_CONTENT = 1_000_000

# Maximum execution time for one regex operation.
# regex.TimeoutError is handled safely below.
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
    Convert common Nuclei DSL expressions into the simple matcher
    representation understood by _evaluate_nuclei_simple_matcher().
    """

    expr = str(expr or "").strip()

    if not expr:
        return None

    # Common status-code expressions.
    status_match = re.fullmatch(
        r"status_code\s*([=!]=?)\s*(\d+)",
        expr,
        re.IGNORECASE
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

    # Common body/header contains expressions.
    contains_match = re.fullmatch(
        r'(?:contains|contains_all|contains_any)'
        r'\(\s*(body|header|all)\s*,\s*"([^"]+)"\s*\)',
        expr,
        re.IGNORECASE
    )

    if contains_match:
        part = contains_match.group(1).lower()
        value = contains_match.group(2)

        return {
            "match_type": "string",
            "pattern": value,
            "part": _map_nuclei_part_for_scanner(part),
        }

    # Common direct body/header equality-style expressions.
    simple_match = re.fullmatch(
        r'(body|header)\s*([=!]=?)\s*"([^"]+)"',
        expr,
        re.IGNORECASE
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
            pattern = rule.get("pattern", "")
            match_type = rule.get("match_type")

            if not pattern:
                continue

            if match_type not in ("regex", "version_range"):
                continue

            try:
                self._compiled_patterns[rule["id"]] = regex.compile(
                    pattern,
                    regex.IGNORECASE | regex.DOTALL
                )

            except (regex.error, re.error) as e:
                logger.warning(
                    f"Invalid regex in rule "
                    f"{rule.get('id')}: {e}"
                )

    def match_snapshot(
        self,
        snapshot: PageSnapshot,
        scan_id: str
    ) -> list:
        """
        Run all rules against a PageSnapshot.

        Regex rules are protected by a hard execution timeout so
        one pathological pattern cannot stall the complete scan.
        """

        findings = []
        now = datetime.now(timezone.utc).isoformat()

        # Cache target content once for this snapshot.
        self._target_cache = {}

        total_rules = len(self.rules)
        evaluated = 0

        logger.info(
            "[RULE ENGINE] Starting evaluation of %d rules",
            total_rules
        )

        overall_start = time.monotonic()

        for rule in self.rules:

            if not rule.get("enabled", True):
                continue

            evaluated += 1

            rule_id = rule.get("id", "")

            try:
                rule_start = time.monotonic()

                matches = self._evaluate_rule(
                    rule,
                    snapshot
                )

                elapsed = time.monotonic() - rule_start

                if elapsed > 0.5:
                    logger.warning(
                        "[RULE SLOW] %s took %.2fs pattern=%r",
                        rule_id,
                        elapsed,
                        rule.get("pattern", "")[:100]
                    )

                for match_info in matches:

                    finding = Finding(
                        id=str(uuid.uuid4()),
                        scan_id=scan_id,
                        target_url=snapshot.url,
                        timestamp=now,
                        source_tool="custom",
                        type=rule.get(
                            "type",
                            "vulnerability"
                        ),
                        severity=rule.get(
                            "severity",
                            "info"
                        ),
                        title=rule.get(
                            "title",
                            rule_id
                        ),
                        description=rule.get(
                            "description",
                            ""
                        ),
                        rule_id=rule_id,
                        cve=rule.get(
                            "cve",
                            ""
                        ),
                        cwe=rule.get(
                            "cwe",
                            ""
                        ),
                        owasp_category=rule.get(
                            "owasp_category",
                            ""
                        ),
                        evidence_location=match_info.get(
                            "location",
                            ""
                        ),
                        evidence_pattern=rule.get(
                            "pattern",
                            ""
                        ),
                        evidence_snippet=match_info.get(
                            "snippet",
                            ""
                        )[:500],
                        detected_version=match_info.get(
                            "version",
                            ""
                        ),
                        detected_technology=match_info.get(
                            "technology",
                            ""
                        ),
                        remediation=rule.get(
                            "remediation",
                            ""
                        ),
                        reference_urls=rule.get(
                            "references",
                            []
                        ),
                    )

                    findings.append(finding)

            except Exception as e:
                logger.error(
                    "Error evaluating rule %s: %s",
                    rule_id,
                    e
                )

            # Progress diagnostics.
            if evaluated % 100 == 0:
                elapsed_total = (
                    time.monotonic() - overall_start
                )

                logger.info(
                    "[RULE PROGRESS] %d/%d rules evaluated "
                    "(%.1fs elapsed, %d findings)",
                    evaluated,
                    total_rules,
                    elapsed_total,
                    len(findings)
                )

        total_elapsed = (
            time.monotonic() - overall_start
        )

        logger.info(
            "[RULE ENGINE] Finished: %d rules, "
            "%d findings, %.2fs total",
            evaluated,
            len(findings),
            total_elapsed
        )

        self._target_cache = {}

        return findings

    def _evaluate_nuclei_group(
        self,
        rule: dict,
        snapshot: PageSnapshot
    ) -> list:
        """
        Evaluate one complete Nuclei HTTP request.

        Nuclei matchers are evaluated as a logical group rather than
        producing independent findings for each matcher.
        """

        paths = rule.get("nuclei_paths", []) or []

        # Endpoint-specific Nuclei rules must not be evaluated against
        # an unrelated snapshot URL.
        if paths:
            snapshot_url = str(
                getattr(snapshot, "url", "") or ""
            ).rstrip("/")

            path_matches = False

            for path in paths:
                path = str(path or "").strip()

                # BaseURL/root requests can be evaluated against the
                # current snapshot.
                if path in (
                    "{{BaseURL}}",
                    "{{BaseURL}}/",
                    "/",
                ):
                    path_matches = True
                    break

                # Resolve only simple absolute/static paths.
                if "{{" in path:
                    continue

                if path.startswith("/"):
                    try:
                        from urllib.parse import urlparse

                        parsed = urlparse(snapshot_url)
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

        matchers = rule.get("nuclei_matchers", []) or []

        if not matchers:
            return []

        group_condition = str(
            rule.get(
                "nuclei_matchers_condition",
                "or"
            )
        ).lower()

        matched_results = []
        matcher_results = []

        for matcher in matchers:
            matcher_type = str(
                matcher.get("type", "word")
            ).lower()

            part = str(
                matcher.get("part", "body")
            ).lower()

            # DSL status checks can be evaluated against the snapshot.
            if matcher_type == "status":
                expected_codes = matcher.get("status", []) or []

                if not isinstance(expected_codes, list):
                    expected_codes = [expected_codes]

                matched = any(
                    str(snapshot.status_code) == str(code)
                    for code in expected_codes
                )

                matcher_results.append(matched)

                if matched:
                    matched_results.append({
                        "location": "status_code",
                        "snippet": (
                            f"Status code: "
                            f"{snapshot.status_code}"
                        ),
                    })

                continue

            # DSL expressions.
            if matcher_type == "dsl":
                dsl_values = matcher.get("dsl", []) or []

                if isinstance(dsl_values, str):
                    dsl_values = [dsl_values]

                local_results = []

                for expr in dsl_values:
                    converted = _convert_dsl_to_pattern_for_group(
                        expr
                    )

                    if not converted:
                        continue

                    local_results.append(
                        self._evaluate_nuclei_simple_matcher(
                            converted,
                            snapshot
                        )
                    )

                matched = (
                    any(local_results)
                    if local_results
                    else False
                )

                matcher_results.append(matched)

                if matched:
                    matched_results.append({
                        "location": part,
                        "snippet": str(
                            dsl_values[0]
                        )[:200],
                    })

                continue

            # Word / regex / binary matchers.
            words = matcher.get("words", []) or []

            if not words:
                words = matcher.get("regex", []) or []

            if isinstance(words, str):
                words = [words]

            if not isinstance(words, list) or not words:
                matcher_results.append(False)
                continue

            target = _map_nuclei_part_for_scanner(part)
            targets = self._get_target_content(
                target,
                snapshot
            )

            content_values = [
                content
                for _, content in targets
                if content
            ]

            if not content_values:
                matcher_results.append(False)
                continue

            matcher_condition = str(
                matcher.get("condition", "or")
            ).lower()

            individual_results = []

            for word in words:
                word = str(word)

                matched_one = False
                evidence = None

                for content in content_values:
                    if matcher_type in ("word", "binary"):
                        result = self._match_string(
                            word,
                            content
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
                            content
                        )
                    else:
                        result = None

                    if result:
                        matched_one = True
                        evidence = result
                        break

                individual_results.append(matched_one)

                if matched_one and evidence:
                    matched_results.append({
                        "location": part,
                        "snippet": evidence.get(
                            "snippet",
                            ""
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

            matcher_results.append(matcher_matched)

        if group_condition == "and":
            group_matched = (
                bool(matcher_results)
                and all(matcher_results)
            )
        else:
            group_matched = any(matcher_results)

        if not group_matched:
            return []

        evidence = (
            matched_results[0]
            if matched_results
            else {
                "location": "nuclei",
                "snippet": rule.get(
                    "pattern",
                    ""
                ),
            }
        )

        return [{
            "location": evidence.get(
                "location",
                "nuclei"
            ),
            "snippet": evidence.get(
                "snippet",
                ""
            )[:500],
            "matched": True,
        }]


    def _evaluate_nuclei_simple_matcher(
        self,
        matcher: dict,
        snapshot: PageSnapshot
    ) -> bool:
        """Evaluate a converted simple Nuclei matcher."""

        match_type = matcher.get(
            "match_type",
            "string"
        )

        pattern = str(
            matcher.get("pattern", "")
        )

        if not pattern:
            return False

        target = matcher.get(
            "part",
            "body"
        )

        targets = self._get_target_content(
            target,
            snapshot
        )

        for _, content in targets:
            if not content:
                continue

            if match_type == "string":
                if self._match_string(
                    pattern,
                    content
                ):
                    return True

            elif match_type == "regex":
                fake_rule = {
                    "id": (
                        "nuclei-dsl:"
                        + pattern[:40]
                    )
                }

                if self._match_regex(
                    fake_rule,
                    pattern,
                    content
                ):
                    return True

        return False


    def _evaluate_rule(
        self,
        rule: dict,
        snapshot: PageSnapshot
    ) -> list:
        """
        Evaluate one rule against the snapshot.
        """

        # Nuclei HTTP requests use grouped matcher semantics.
        if rule.get("match_type") == "nuclei_group":
            return self._evaluate_nuclei_group(
                rule,
                snapshot
            )

        target = rule.get(
            "target_location",
            "body"
        )

        match_type = rule.get(
            "match_type",
            "string"
        )

        pattern = rule.get(
            "pattern",
            ""
        )

        if not pattern:
            return []

        targets = self._get_target_content(
            target,
            snapshot
        )

        matches = []

        for location_name, content in targets:

            if not content:
                continue

            if match_type == "string":

                result = self._match_string(
                    pattern,
                    content
                )

            elif match_type == "regex":

                result = self._match_regex(
                    rule,
                    pattern,
                    content
                )

            elif match_type == "version_range":

                result = self._match_version(
                    rule,
                    pattern,
                    content
                )

            elif match_type == "status_code":

                result = self._match_status(
                    pattern,
                    snapshot.status_code
                )

            elif match_type == "absent":

                result = self._match_absent(
                    pattern,
                    content
                )

            else:
                continue

            if result:

                result["location"] = location_name

                matches.append(result)

        return matches

    def _get_target_content(
        self,
        target: str,
        snapshot: PageSnapshot
    ) -> list:
        """
        Return target content.

        Results are cached per target so the same body/header/script
        data is not rebuilt 1000+ times.
        """

        if target in self._target_cache:
            return self._target_cache[target]

        if target == "body":

            results = [
                ("body", snapshot.body_lower)
            ]

        elif target == "header":

            header_str = "\n".join(
                f"{k}: {v}"
                for k, v in snapshot.headers.items()
            )

            results = [
                ("header", header_str.lower())
            ]

        elif target == "header_key":

            results = [
                (
                    f"header:{k}",
                    v.lower()
                )
                for k, v in snapshot.headers.items()
            ]

        elif target == "script":

            results = [
                (
                    "script_src",
                    " ".join(
                        snapshot.scripts
                    ).lower()
                )
            ]

            for i, js in enumerate(
                snapshot.inline_scripts
            ):
                results.append(
                    (
                        f"inline_script_{i}",
                        js.lower()
                    )
                )

        elif target == "cookie":

            cookie_str = "\n".join(
                f"{k}: {v}"
                for k, v in snapshot.cookies.items()
            )

            results = [
                ("cookie", cookie_str.lower())
            ]

        elif target == "meta":

            meta_str = "\n".join(
                f"{k}: {v}"
                for k, v in snapshot.meta_tags.items()
            )

            results = [
                ("meta", meta_str.lower())
            ]

        elif target == "comment":

            results = [
                (
                    "comment",
                    " ".join(
                        snapshot.comments
                    ).lower()
                )
            ]

        elif target == "server":

            results = [
                (
                    "server",
                    snapshot.server.lower()
                )
            ]

        elif target == "all":

            results = [
                (
                    "body",
                    snapshot.body_lower
                )
            ]

            header_str = "\n".join(
                f"{k}: {v}"
                for k, v in snapshot.headers.items()
            )

            results.append(
                (
                    "header",
                    header_str.lower()
                )
            )

            results.append(
                (
                    "script_src",
                    " ".join(
                        snapshot.scripts
                    ).lower()
                )
            )

            for i, js in enumerate(
                snapshot.inline_scripts
            ):
                results.append(
                    (
                        f"inline_script_{i}",
                        js.lower()
                    )
                )

        else:

            results = [
                (
                    "body",
                    snapshot.body_lower
                )
            ]

        self._target_cache[target] = results

        return results

    def _match_string(
        self,
        pattern: str,
        content: str
    ) -> Optional[dict]:
        """Simple case-insensitive substring match."""

        pattern_lower = pattern.lower()

        idx = content.find(
            pattern_lower
        )

        if idx >= 0:

            start = max(
                0,
                idx - 50
            )

            end = min(
                len(content),
                idx + len(pattern_lower) + 50
            )

            return {
                "snippet": content[start:end],
                "matched": True
            }

        return None

    def _match_literal_lookaheads(
        self,
        pattern: str,
        content: str
    ) -> Optional[dict]:
        """
        Fast path for Nuclei-generated literal lookahead patterns.

        Example:
            (?=.*foo)(?=.*bar)

        This is equivalent to checking that both literal strings
        exist in the content, avoiding expensive regex backtracking.
        """
        if not pattern.startswith("(?=.*"):
            return None

        try:
            parts = re.findall(r"\(\?=\.\*(.*?)\)", pattern)

            if len(parts) < 2:
                return None

            for part in parts:
                if part.lower() not in content:
                    return {
                        "matched": False
                    }

            return {
                "snippet": " | ".join(parts)[:200],
                "matched": True
            }

        except Exception:
            return None


    def _match_regex(
        self,
        rule: dict,
        pattern: str,
        content: str
    ) -> Optional[dict]:
        """
        Regex match protected by a hard timeout.
        """

        # Fast path for Nuclei-generated literal lookahead combinations.
        fast_result = self._match_literal_lookaheads(
            pattern,
            content
        )

        if fast_result is not None:
            if fast_result.get("matched"):
                return fast_result
            return None

        compiled = self._compiled_patterns.get(
            rule["id"]
        )

        if not compiled:

            try:

                compiled = regex.compile(
                    pattern,
                    regex.IGNORECASE | regex.DOTALL
                )

                self._compiled_patterns[
                    rule["id"]
                ] = compiled

            except (regex.error, re.error) as e:

                logger.warning(
                    "[REGEX INVALID] %s: %s",
                    rule.get("id"),
                    e
                )

                return None

        # Limit input size.
        safe_content = content[
            :MAX_REGEX_CONTENT
        ]

        try:

            match = compiled.search(
                safe_content,
                timeout=REGEX_TIMEOUT
            )

        except TimeoutError:

            logger.warning(
                "[REGEX TIMEOUT] rule=%s "
                "pattern=%r",
                rule.get("id"),
                pattern[:120]
            )

            return None

        except regex.error as e:

            logger.warning(
                "[REGEX ERROR] rule=%s: %s",
                rule.get("id"),
                e
            )

            return None

        if not match:
            return None

        result = {
            "snippet": match.group(0)[:200],
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

            result["technology"] = rule.get(
                "technology",
                ""
            )

        return result

    def _match_version(
        self,
        rule: dict,
        pattern: str,
        content: str
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
                    regex.IGNORECASE
                )

                self._compiled_patterns[
                    rule["id"]
                ] = compiled

            except (regex.error, re.error) as e:

                logger.warning(
                    "[VERSION REGEX INVALID] %s: %s",
                    rule.get("id"),
                    e
                )

                return None

        safe_content = content[
            :MAX_REGEX_CONTENT
        ]

        try:

            match = compiled.search(
                safe_content,
                timeout=REGEX_TIMEOUT
            )

        except TimeoutError:

            logger.warning(
                "[VERSION REGEX TIMEOUT] "
                "rule=%s pattern=%r",
                rule.get("id"),
                pattern[:120]
            )

            return None

        except regex.error as e:

            logger.warning(
                "[VERSION REGEX ERROR] "
                "rule=%s: %s",
                rule.get("id"),
                e
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

            detected_version = match.group(0)

        if not detected_version:
            return None

        min_safe = rule.get(
            "min_safe_version",
            ""
        )

        if min_safe:

            try:

                if (
                    Version(detected_version)
                    < Version(min_safe)
                ):

                    return {
                        "snippet": match.group(0)[:200],
                        "version": detected_version,
                        "technology": rule.get(
                            "technology",
                            ""
                        ),
                        "matched": True,
                    }

            except InvalidVersion:

                return {
                    "snippet": match.group(0)[:200],
                    "version": detected_version,
                    "technology": rule.get(
                        "technology",
                        ""
                    ),
                    "matched": True,
                }

        if rule.get("type") == "fingerprint":

            return {
                "snippet": match.group(0)[:200],
                "version": detected_version,
                "technology": rule.get(
                    "technology",
                    ""
                ),
                "matched": True,
            }

        return None

    def _match_status(
        self,
        pattern: str,
        status_code: int
    ) -> Optional[dict]:
        """Match against HTTP status code."""

        try:

            expected = int(pattern)

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
        content: str
    ) -> Optional[dict]:
        """Match when a pattern is ABSENT."""

        if pattern.lower() not in content.lower():

            return {
                "snippet": (
                    f"Missing: {pattern}"
                ),
                "matched": True,
            }

        return None
