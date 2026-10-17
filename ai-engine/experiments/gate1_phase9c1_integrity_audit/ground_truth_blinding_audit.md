# SentinelAI GATE-1 Phase 9C.1: Telemetry Ground-Truth Blinding Audit

**Auditor**: Senior Security Architect & Independent Security-Systems Reviewer  
**Date**: 2026-10-17  
**Execution Context**: Detailed Code & Vulnerability Audit of `ai-engine/modular/sanitizer.py`  

---

## 1. Blinding Architecture & Implementation

[`ai-engine/modular/sanitizer.py`](file:///c:/Users/srisn/Desktop/Projects/sentinelai-complete/ai-engine/modular/sanitizer.py) provides input blinding to prevent evaluation models and detectors from cheating via dataset labels.

### Denylist Keys Audited
```python
FORBIDDEN_GROUND_TRUTH_KEYS = {
    "label", "Label", "LABEL",
    "attack", "Attack", "ATTACK",
    "target", "Target", "TARGET",
    "y", "Y", "y_true",
    "ground_truth", "GroundTruth", "GROUND_TRUTH",
    "class_name", "ClassName",
    "category", "Category",
    "attack_type", "AttackType",
    "is_attack", "is_anomaly_gt",
}
```

### Recursive Sanitization ([`sanitizer.py`](file:///c:/Users/srisn/Desktop/Projects/sentinelai-complete/ai-engine/modular/sanitizer.py#L45-L75))
- Recursively traverses nested dictionaries and arrays.
- Strips any key present in `FORBIDDEN_GROUND_TRUTH_KEYS`.
- Constructs a fresh clean dictionary to avoid mutating input references.
- Verified in `BaseDetector.evaluate()`: Every detector automatically sanitizes incoming telemetry before calling `_inspect()`.

---

## 2. Discovered Vulnerability: Case-Variant and Suffix Bypass

The auditor tested the blinding mechanism against non-standard casing and composite key variations:

### Empirical Test Execution
```python
tainted = {'lAbEl': 'DDoS', 'ATTACK_TYPE': 'SYN_FLOOD', 'target_label': 1}
violations = detect_ground_truth_keys(tainted)
clean = sanitize_telemetry(tainted)
```

### Test Output
```
Mixed-case violations detected: []
Clean keys: ['lAbEl', 'ATTACK_TYPE', 'target_label']
```

### Vulnerability Analysis
1. **Case-Sensitivity Defect**: `FORBIDDEN_GROUND_TRUTH_KEYS` performs strict string membership checking (`k in FORBIDDEN_GROUND_TRUTH_KEYS`). It lacks case-normalization (`k.lower() in {...}`). An adversarial or malformed dataset containing `lAbEl` or `ATTACK_TYPE` completely bypasses detection and sanitization!
2. **Compound Suffixes**: Variations such as `target_label`, `true_class`, `binary_label`, or `eval_category` are not matched.
3. **Denylist vs. Allowlist Limitation**: A denylist is fundamentally vulnerable to vocabulary expansion. While it successfully strips canonical CICIDS / CSE-CIC-IDS2018 columns (`Label`, `y`), it cannot provide mathematical guarantees of label isolation across unknown third-party corpora.

- **Severity**: **MEDIUM**.
- **Status**: **CONFIRMED**.
- **Required Fix**:
  1. Update `detect_ground_truth_keys` and `sanitize_telemetry` to normalize keys (`k.strip().lower()`) against a lowercase normalized forbidden set.
  2. Implement a strict **feature allowlist** (e.g. standard 53-feature flow vector schema, or typed telemetry models with `extra = "forbid"`) to reject all unapproved fields before inference.

---

## 3. Operational Feature Collision Audit

The auditor audited all 53 network flow feature names (`FEATURE_NAMES` in `ai-engine/utils/features.py`):
- Features audited include `flow_duration`, `total_fwd_packets`, `fwd_packet_len_mean`, `fin_flag_count`, `syn_flag_count`, etc.
- **Zero collisions found**: No legitimate flow features share names with any forbidden ground-truth keys. The sanitizer does not accidentally strip legitimate network metrics.
- **Classification**: **CONFIRMED**.
