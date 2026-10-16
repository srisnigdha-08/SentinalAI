"""
SentinelAI Telemetry Sanitizer & Ground-Truth Isolation Guard
Phase 9C.2 Remediation Milestone: DEF-02 Fix

This module strictly sanitizes incoming telemetry to ensure that no dataset ground-truth
labels (such as 'Label', 'Attack', 'target', 'y', 'ground_truth', 'target_label', etc.)
can leak into detector inference, feature extraction, or policy decision paths.

Key Architectural Guarantees:
1. Case-Insensitive Matching: Keys are normalized (k.strip().lower()) before evaluation.
2. Alias & Composite Pattern Matching: Matches exact stems, prefix patterns, and suffix patterns.
3. Operational Feature Protection: Known legitimate flow metrics and metadata keys are explicitly
   whitelisted to prevent accidental over-stripping.
4. Deep Immutability: Deeply clones data structures; never mutates caller input objects.
5. Recursive Collection Handling: Traverses nested dicts, lists, tuples, and sets.

NOTE ON RESIDUAL LIMITATIONS:
A field denylist provides defense-in-depth against dataset label leakage from academic
corpora (CICIDS2017, CSE-CIC-IDS2018), but cannot guarantee 100% blinding across arbitrary,
untyped user dictionaries. For production deployment, strict allowlist schema validation
(e.g., Pydantic models with extra="forbid") must be enforced at API ingestion boundaries.
"""

from __future__ import annotations
import copy
import logging
from typing import Any, Dict, List, Set, Union

log = logging.getLogger("sentinel.modular.sanitizer")

# Canonical lowercase stems of forbidden ground-truth labels and evaluation metadata
FORBIDDEN_GROUND_TRUTH_STEMS: Set[str] = {
    "label",
    "attack",
    "target",
    "y",
    "y_true",
    "y_pred",
    "ground_truth",
    "groundtruth",
    "class_name",
    "classname",
    "category",
    "attack_type",
    "attacktype",
    "is_attack",
    "is_anomaly_gt",
    "target_label",
    "targetlabel",
    "actual_class",
    "actualclass",
    "true_class",
    "trueclass",
    "binary_label",
    "binarylabel",
    "multiclass_label",
    "eval_label",
    "dataset_label",
}

# Alias for backwards-compatibility
FORBIDDEN_GROUND_TRUTH_KEYS = FORBIDDEN_GROUND_TRUTH_STEMS

# Protected operational network metadata and flow feature keys
# These keys must NEVER be stripped even if they contain partial substrings of stems
LEGITIMATE_OPERATIONAL_KEYS: Set[str] = {
    "sourceip",
    "destinationip",
    "sourceport",
    "destinationport",
    "source_ip",
    "destination_ip",
    "source_port",
    "destination_port",
    "protocol",
    "timestamp",
    "session_id",
    "sessionid",
    "flow_duration",
    "total_fwd_packets",
    "total_bwd_packets",
    "total_len_fwd_packets",
    "total_len_bwd_packets",
    "fwd_packet_len_max",
    "fwd_packet_len_min",
    "fwd_packet_len_mean",
    "fwd_packet_len_std",
    "bwd_packet_len_max",
    "bwd_packet_len_min",
    "bwd_packet_len_mean",
    "bwd_packet_len_std",
    "flow_bytes_per_sec",
    "flow_packets_per_sec",
    "flow_iat_mean",
    "flow_iat_std",
    "flow_iat_max",
    "flow_iat_min",
    "fwd_iat_total",
    "fwd_iat_mean",
    "fwd_iat_std",
    "fwd_iat_max",
    "fwd_iat_min",
    "bwd_iat_total",
    "bwd_iat_mean",
    "bwd_iat_std",
    "bwd_iat_max",
    "bwd_iat_min",
    "fin_flag_count",
    "syn_flag_count",
    "rst_flag_count",
    "psh_flag_count",
    "ack_flag_count",
    "urg_flag_count",
    "fwd_psh_flags",
    "bwd_psh_flags",
    "fwd_urg_flags",
    "bwd_urg_flags",
    "fwd_header_len",
    "bwd_header_len",
    "fwd_avg_bytes_per_bulk",
    "bwd_avg_bytes_per_bulk",
    "flow_rate",
    "packet_count",
    "byte_count",
}


def is_ground_truth_key(key: Any) -> bool:
    """
    Evaluates whether a key corresponds to a ground-truth label or evaluation annotation.
    Case-normalized, whitespace-stripped, and handles composite compound names.
    """
    if not isinstance(key, str):
        key_str = str(key)
    else:
        key_str = key

    k_clean = key_str.strip().lower()

    # 1. Protected operational key override
    if k_clean in LEGITIMATE_OPERATIONAL_KEYS:
        return False

    # 2. Exact match against canonical stems
    if k_clean in FORBIDDEN_GROUND_TRUTH_STEMS:
        return True

    # 3. Compound suffix / prefix pattern matching
    # Examples: target_label, raw_attack_type, eval_ground_truth, attack_name
    if (
        k_clean.endswith("_label")
        or k_clean.endswith("_attack")
        or k_clean.endswith("_class")
        or k_clean.startswith("label_")
        or k_clean.startswith("attack_")
        or k_clean.startswith("ground_truth_")
        or "ground_truth" in k_clean
        or "target_label" in k_clean
    ):
        return True

    return False


def detect_ground_truth_keys(data: Any, prefix: str = "") -> List[str]:
    """
    Recursively scans nested dictionaries, lists, tuples, and sets for forbidden ground-truth keys.
    Returns path representations of any discovered violations.
    """
    found: List[str] = []
    if isinstance(data, dict):
        for k, v in data.items():
            current_path = f"{prefix}.{k}" if prefix else str(k)
            if is_ground_truth_key(k):
                found.append(current_path)
            found.extend(detect_ground_truth_keys(v, current_path))
    elif isinstance(data, (list, tuple, set)):
        for idx, item in enumerate(data):
            current_path = f"{prefix}[{idx}]"
            found.extend(detect_ground_truth_keys(item, current_path))
    return found


def sanitize_telemetry(raw_event: Dict[str, Any], raise_on_ground_truth: bool = False) -> Dict[str, Any]:
    """
    Sanitizes raw event telemetry before dispatching to detectors or the orchestrator.
    - Deep-copies the event to prevent side-channel mutation or shared reference leaks.
    - Strips all detected ground-truth keys using case-insensitive and compound matching.
    - If raise_on_ground_truth is True and violations exist, raises a ValueError.
    """
    if not isinstance(raw_event, dict):
        raise TypeError(f"Telemetry must be a dict, got {type(raw_event).__name__}")

    violations = detect_ground_truth_keys(raw_event)
    if violations:
        msg = f"Security Violation: Ground-truth keys detected in inference telemetry: {violations}"
        if raise_on_ground_truth:
            log.error(msg)
            raise ValueError(msg)
        else:
            log.warning(f"{msg}. Stripping keys immediately to preserve inference blind integrity.")

    clean_event: Dict[str, Any] = {}
    for k, v in raw_event.items():
        if is_ground_truth_key(k):
            continue

        if isinstance(v, dict):
            clean_event[k] = sanitize_telemetry(v, raise_on_ground_truth=False)
        elif isinstance(v, list):
            clean_event[k] = [
                sanitize_telemetry(item, raise_on_ground_truth=False) if isinstance(item, dict) else copy.deepcopy(item)
                for item in v
            ]
        elif isinstance(v, tuple):
            clean_event[k] = tuple(
                sanitize_telemetry(item, raise_on_ground_truth=False) if isinstance(item, dict) else copy.deepcopy(item)
                for item in v
            )
        elif isinstance(v, set):
            clean_event[k] = {
                copy.deepcopy(item) for item in v if not (isinstance(item, dict) or is_ground_truth_key(item))
            }
        else:
            clean_event[k] = copy.deepcopy(v)

    return clean_event


def assert_isolated_from_ground_truth(event: Dict[str, Any]) -> None:
    """
    Assertion helper used in pre-inference hooks and unit tests.
    Raises ValueError immediately if ANY ground-truth key is present.
    """
    violations = detect_ground_truth_keys(event)
    if violations:
        raise ValueError(
            f"Ground-Truth Isolation Failed: Found {len(violations)} forbidden key(s): {violations}. "
            f"Inference algorithms must operate strictly blind to dataset labels."
        )
