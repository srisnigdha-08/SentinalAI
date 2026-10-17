"""
SentinelAI Modular Threat Detection - E4 Layer 7 HTTP / WAF Payload Inspection Detector Prototype
Phase 9E Prototype Implementation Milestone: Deep Application-Layer Inspection

Inspects raw HTTP request lines, headers, query parameters, and request bodies for
SQL Injection (SQLi), Cross-Site Scripting (XSS), Directory Traversal, and Command Injection.
Strictly zero reliance on ground-truth label columns.
"""

from __future__ import annotations
import re
import urllib.parse
import html
import logging
from typing import Any, Dict, List, Optional, Tuple

from modular.base import BaseDetector
from modular.contracts import (
    DetectorResult,
    DetectorStatus,
    PolicyDecision,
    SeverityLevel,
    MitigationAction,
    EvidenceRecord,
    SimulatedMitigation,
    create_degraded_result,
    validate_finite_score
)

log = logging.getLogger("sentinel.modular.layer7_waf")

# Compiled High-Precision Attack Signatures
SQLI_PATTERNS = [
    (re.compile(r"(\%27)|(\')|(\-\-)|(\%23)|(#)", re.IGNORECASE), "SQL_META_CHARACTERS"),
    (re.compile(r"\b(union\s+all\s+select|union\s+select|select\s+.*\s+from)\b", re.IGNORECASE), "SQL_UNION_SELECT"),
    (re.compile(r"\b(or|and)\s+['\"0-9a-z]+\s*=\s*['\"0-9a-z]+", re.IGNORECASE), "SQL_BOOLEAN_TAUTOLOGY"),
    (re.compile(r"\b(drop\s+table|insert\s+into|delete\s+from|update\s+.*\s+set)\b", re.IGNORECASE), "SQL_DML_INJECTION"),
    (re.compile(r"\b(waitfor\s+delay|pg_sleep|benchmark\s*\()\b", re.IGNORECASE), "SQL_TIME_DELAY"),
    (re.compile(r"\b(information_schema|sys\.tables|sysobjects)\b", re.IGNORECASE), "SQL_METADATA_PROBE"),
]

XSS_PATTERNS = [
    (re.compile(r"<\s*script[^>]*>.*(<\s*/\s*script\s*>)?", re.IGNORECASE | re.DOTALL), "XSS_SCRIPT_TAG"),
    (re.compile(r"\b(javascript|vbscript)\s*:\s*", re.IGNORECASE), "XSS_JAVASCRIPT_URI"),
    (re.compile(r"on(load|error|click|mouseover|focus|blur|submit)\s*=", re.IGNORECASE), "XSS_EVENT_HANDLER"),
    (re.compile(r"\b(alert|eval|prompt|confirm)\s*\(", re.IGNORECASE), "XSS_DOM_EXEC"),
    (re.compile(r"document\.(cookie|location|write)", re.IGNORECASE), "XSS_DOCUMENT_ACCESS"),
]

TRAVERSAL_PATTERNS = [
    (re.compile(r"(\.\./|\.\.\\|\%2e\%2e\%2f|\%2e\%2e\/|\.\.%2f)", re.IGNORECASE), "PATH_TRAVERSAL_DOT_DOT"),
    (re.compile(r"(/etc/passwd|/etc/shadow|/proc/version|c:\\boot\.ini|windows\\system32)", re.IGNORECASE), "SYSTEM_FILE_ACCESS"),
]

RCE_PATTERNS = [
    (re.compile(r"(;\s*(cat|ls|whoami|id|uname|nc|curl|wget)\b)|(\|\|\s*(cat|id|whoami)\b)", re.IGNORECASE), "COMMAND_INJECTION_SHELL"),
    (re.compile(r"(powershell(\.exe)?\s+(-enc|-e|downloadstring))|(cmd\.exe\s+/c)", re.IGNORECASE), "WINDOWS_SHELL_INJECTION"),
    (re.compile(r"(/bin/sh|/bin/bash)\s+-i", re.IGNORECASE), "REVERSE_SHELL_PAYLOAD"),
]


class Layer7WAFDetector(BaseDetector):
    """
    E4 Layer 7 HTTP / WAF Deep Payload Inspection Detector.
    
    Evaluates HTTP request payloads, URLs, headers, and query strings.
    Extracts, decodes, and evaluates OWASP injection vectors.
    """

    def __init__(
        self,
        detector_id: str = "layer7_waf",
        version: str = "1.0.0"
    ):
        super().__init__(detector_id=detector_id, version=version)

    def health_check(self) -> DetectorStatus:
        """Verifies signature engine readiness."""
        return DetectorStatus.HEALTHY

    def _normalize_and_decode(self, text: str) -> str:
        """Applies multi-pass URL and HTML entity decoding to counter obfuscation."""
        # Bound payload length to 64 KB to protect against ReDoS on malicious inputs
        decoded = text[:65536] if len(text) > 65536 else text
        for _ in range(3):
            prev = decoded
            decoded = urllib.parse.unquote_plus(decoded)
            decoded = html.unescape(decoded)
            if decoded == prev:
                break
        return decoded

    def _extract_inspectable_strings(self, telemetry: Dict[str, Any]) -> List[Tuple[str, str]]:
        """
        Extracts inspectable payload strings from telemetry.
        Returns list of (location_tag, raw_string).
        """
        items: List[Tuple[str, str]] = []
        for k, v in telemetry.items():
            if not isinstance(v, str):
                continue
            key_clean = k.strip().lower()
            if any(target in key_clean for target in ("uri", "url", "path", "query", "header", "body", "payload", "request")):
                items.append((k, v))
        return items

    def _inspect(self, telemetry: Dict[str, Any], correlation_id: str) -> DetectorResult:
        inspectable = self._extract_inspectable_strings(telemetry)

        # If telemetry is purely network-layer (no HTTP payloads or strings present)
        if not inspectable:
            # Check destination port
            dst_port = telemetry.get("dst_port") or telemetry.get("Destination Port")
            if dst_port in (80, 443, 8080, 8443):
                # HTTP port but transport summary only: deep inspection incomplete
                return create_degraded_result(
                    detector_id=self.detector_id,
                    status=DetectorStatus.INCOMPLETE,
                    reason="Flow targeted HTTP port but telemetry lacks Layer 7 payload buffers",
                    correlation_id=correlation_id
                )
            else:
                # Non-HTTP protocol
                return DetectorResult(
                    detector_id=self.detector_id,
                    version=self.version,
                    correlation_id=correlation_id,
                    status=DetectorStatus.UNSUPPORTED,
                    decision=PolicyDecision.MONITOR,
                    confidence=0.0,
                    severity=SeverityLevel.INFORMATIONAL,
                    evidence=EvidenceRecord(
                        trigger_rule="NON_HTTP_PROTOCOL",
                        summary="Telemetry does not contain HTTP payload buffers or web ports",
                        extracted_features={"status": "UNSUPPORTED"}
                    ),
                    mitigation_recommendation=SimulatedMitigation(action=MitigationAction.NONE, simulated=True)
                )

        violations: List[Dict[str, Any]] = []

        for field_name, raw_content in inspectable:
            decoded = self._normalize_and_decode(raw_content)

            # 1. SQL Injection Scan
            for pat, rule_id in SQLI_PATTERNS:
                m = pat.search(decoded)
                if m:
                    violations.append({
                        "category": "SQL_INJECTION",
                        "rule": rule_id,
                        "field": field_name,
                        "match": m.group(0)[:64]
                    })

            # 2. XSS Scan
            for pat, rule_id in XSS_PATTERNS:
                m = pat.search(decoded)
                if m:
                    violations.append({
                        "category": "CROSS_SITE_SCRIPTING",
                        "rule": rule_id,
                        "field": field_name,
                        "match": m.group(0)[:64]
                    })

            # 3. Path Traversal Scan
            for pat, rule_id in TRAVERSAL_PATTERNS:
                m = pat.search(decoded)
                if m:
                    violations.append({
                        "category": "PATH_TRAVERSAL",
                        "rule": rule_id,
                        "field": field_name,
                        "match": m.group(0)[:64]
                    })

            # 4. Command Injection Scan
            for pat, rule_id in RCE_PATTERNS:
                m = pat.search(decoded)
                if m:
                    violations.append({
                        "category": "COMMAND_INJECTION",
                        "rule": rule_id,
                        "field": field_name,
                        "match": m.group(0)[:64]
                    })

        if not violations:
            # Clean HTTP payload
            return DetectorResult(
                detector_id=self.detector_id,
                version=self.version,
                correlation_id=correlation_id,
                status=DetectorStatus.HEALTHY,
                decision=PolicyDecision.ALLOW,
                confidence=0.05,
                severity=SeverityLevel.INFORMATIONAL,
                evidence=EvidenceRecord(
                    trigger_rule="L7_PAYLOAD_BENIGN",
                    summary=f"Inspected {len(inspectable)} HTTP fields; no malicious injection signatures detected",
                    extracted_features={"inspected_fields": [k for k, _ in inspectable]}
                ),
                mitigation_recommendation=SimulatedMitigation(action=MitigationAction.NONE, simulated=True)
            )

        # Malicious signature matched
        primary_violation = violations[0]
        cat = primary_violation["category"]
        rule = primary_violation["rule"]
        matched_sample = primary_violation["match"]

        confidence = 0.95 if len(violations) >= 2 or cat in ("SQL_INJECTION", "COMMAND_INJECTION") else 0.85
        confidence = validate_finite_score(confidence)

        return DetectorResult(
            detector_id=self.detector_id,
            version=self.version,
            correlation_id=correlation_id,
            status=DetectorStatus.HEALTHY,
            decision=PolicyDecision.SIMULATED_BLOCK,
            confidence=confidence,
            severity=SeverityLevel.CRITICAL if cat in ("SQL_INJECTION", "COMMAND_INJECTION") else SeverityLevel.HIGH,
            evidence=EvidenceRecord(
                trigger_rule=f"L7_INJECTION_{cat}_{rule}",
                summary=f"Layer 7 exploit detected ({cat}) in field '{primary_violation['field']}': match '{matched_sample}'",
                extracted_features={
                    "total_violations": len(violations),
                    "violations": violations[:5],
                    "matched_category": cat
                }
            ),
            mitigation_recommendation=SimulatedMitigation(
                action=MitigationAction.SIMULATED_BLOCK,
                simulated=True,
                watermark=f"[SIMULATED BLOCK - L7 {cat}]"
            )
        )
