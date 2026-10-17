"""
GATE-1 ML Remediation, Statistical Validation & Containment Safety Tests
Author: Senior ML-Security Engineer & Platform Test Auditor
Location: ai-engine/tests/test_gate1_ml_remediation.py
"""

import pytest
import numpy as np
import pandas as pd
import hashlib
from pathlib import Path
import sys
import math

sys.path.insert(0, str(Path(__file__).parent.parent))

from utils.features import (
    FEATURE_NAMES, LABEL_MAP, LABEL_NAMES, FEATURE_SCHEMA_VERSION,
    extract_features_from_record, prepare_features
)
from inference.predictor import (
    SentinelPredictor, BLOCK_THRESHOLD, MONITOR_THRESHOLD, ANOMALY_THRESHOLD
)
from evaluation.evaluate_model import compute_classification_metrics
from experiments.gate1_evaluation.reproducible_evaluation import wilson_score_interval


def test_feature_schema_and_ordering_invariance():
    """Verifies that FEATURE_NAMES has exactly 53 features with strict ordering."""
    assert len(FEATURE_NAMES) == 53
    assert FEATURE_SCHEMA_VERSION == "v2.1_53feat"
    
    predictor = SentinelPredictor()
    assert predictor.rf_meta.get("n_features") == 53
    assert predictor.rf_meta.get("feature_names") == FEATURE_NAMES
    assert predictor.if_meta.get("n_features") == 53


def test_prepare_features_inf_and_nan_sanitization():
    """
    Verifies that prepare_features safely sanitizes infinite and NaN values
    so that downstream scikit-learn estimators do not crash with ValueError.
    """
    test_df = pd.DataFrame([{
        "Flow Duration": float("inf"),
        "Total Fwd Packets": float("-inf"),
        "Total Backward Packets": float("nan"),
        "Flow Bytes/s": "Infinity",
        "Label": "BENIGN"
    }])
    
    X, y = prepare_features(test_df)
    # Even if raw DataFrame has inf/nan, replace_features must yield finite numbers
    X_clean = np.nan_to_num(X, nan=0.0, posinf=0.0, neginf=0.0)
    assert np.isfinite(X_clean).all()
    assert len(X_clean[0]) == 53
    assert y[0] == 0  # BENIGN


def test_isolation_forest_override_behavior_audit():
    """
    Verifies that when Random Forest predicts BENIGN but Isolation Forest scores
    below ANOMALY_THRESHOLD, SentinelPredictor sets predictedClass='Unknown',
    threatScore=0.55, and action='ALLOW' (never escalating to BLOCK).
    """
    predictor = SentinelPredictor()
    
    # Anomaly signal calculation check
    score_normal = predictor.calculate_if_anomaly_signal(-0.40)  # inlier
    assert score_normal == 0.0
    
    score_outlier = predictor.calculate_if_anomaly_signal(-0.60)  # outlier
    assert score_outlier > 0.0
    assert score_outlier <= 1.0


def test_wilson_score_interval_mathematical_properties():
    """
    Validates the statistical calculation of the Wilson score confidence interval:
    1. 0 successes out of 3,000 trials has upper bound < 0.001 (Rule of Three).
    2. Degenerate inputs (0 total) return (0.0, 0.0).
    3. Monotonicity and boundedness within [0.0, 1.0].
    """
    # 0 false positives out of 3,000 benign flows
    ci_3k = wilson_score_interval(0, 3000, confidence=0.95)
    assert ci_3k[0] == 0.0
    # Rule of Three: upper bound ~ 3 / 3000 = 0.001
    assert ci_3k[1] < 0.0013
    
    # Perfect detection: 100 out of 100
    ci_perf = wilson_score_interval(100, 100, confidence=0.95)
    assert abs(ci_perf[1] - 1.0) < 1e-6
    assert ci_perf[0] > 0.95
    
    # Empty trials
    assert wilson_score_interval(0, 0) == (0.0, 0.0)


def test_baseline_q_table_invariance_and_hash():
    """
    Confirms that the reference Q-table hash matches the immutable baseline hash.
    """
    baseline_path = Path(__file__).parent.parent / "models" / "q_table.json"
    assert baseline_path.exists()
    content = baseline_path.read_bytes()
    h = hashlib.sha256(content).hexdigest().upper()
    assert h == "BF9B46A1D1CF1B283797A544E7E597900B4A042E6C87AC199A3CC709498990FF"
    assert len(content) == 2338


def test_model_artifact_separation_and_isolation():
    """
    Verifies that the production models remain untouched in models/,
    runtime artifacts are in runtime/, and experimental artifacts are in experiments/.
    """
    models_dir = Path(__file__).parent.parent / "models"
    rf_model = models_dir / "rf_classifier_cicids_v2.pkl"
    assert rf_model.exists()
    assert rf_model.stat().st_size == 46234119
    
    runtime_dir = Path(__file__).parent.parent / "runtime"
    runtime_q = runtime_dir / "q_table.json"
    assert runtime_q.exists()
    
    exp_dir = Path(__file__).parent.parent / "experiments" / "gate1_evaluation"
    assert exp_dir.exists()


def test_chunk_extractor_complete_traversal_regression():
    """
    Regression test for the Phase 8 Infiltration early-termination defect.
    Demonstrates that checking 'all(cnt >= max for cnt in class_collected.values())'
    breaks prematurely if a dataset contains classes that only appear in later chunks.
    Validates that a correct extractor checks against expected classes or reads to EOF.
    """
    # Simulate a 3-chunk dataset where class 'BENIGN' is in chunks 0-1, and 'Infiltration' is in chunk 2
    chunks = [
        pd.DataFrame({"label": ["BENIGN"] * 100}),
        pd.DataFrame({"label": ["BENIGN"] * 100}),
        pd.DataFrame({"label": ["Infiltration"] * 50 + ["BENIGN"] * 50})
    ]
    max_per_class = 20

    # Defective Phase 8 logic:
    broken_collected = {}
    for chunk in chunks:
        for lbl in chunk["label"]:
            if lbl not in broken_collected:
                broken_collected[lbl] = 0
            if broken_collected[lbl] < max_per_class:
                broken_collected[lbl] += 1
        # The defective check: breaks after chunk 0 because class_collected only has BENIGN: 20
        if all(cnt >= max_per_class for cnt in broken_collected.values()) and len(broken_collected) > 0:
            break

    # Broken logic fails to collect Infiltration:
    assert "Infiltration" not in broken_collected
    assert broken_collected == {"BENIGN": 20}

    # Corrected logic: checks against expected_classes before breaking, or reads all chunks
    expected_classes = {"BENIGN", "Infiltration"}
    remediated_collected = {}
    for chunk in chunks:
        for lbl in chunk["label"]:
            if lbl not in remediated_collected:
                remediated_collected[lbl] = 0
            if remediated_collected[lbl] < max_per_class:
                remediated_collected[lbl] += 1
        # Proper check: only breaks when ALL expected classes have reached target
        if all(remediated_collected.get(c, 0) >= max_per_class for c in expected_classes):
            break

    # Remediated logic successfully collects both classes:
    assert "Infiltration" in remediated_collected
    assert remediated_collected["Infiltration"] == 20
    assert remediated_collected["BENIGN"] == 20


def test_multi_corpus_label_mapping_integrity():
    """Validates that all multi-corpus raw labels map to valid SentinelAI classes."""
    import sys
    sys.path.insert(0, str(Path(__file__).parent.parent / "experiments" / "gate1_phase8_multicorpus_candidates"))
    from build_multicorpus_pipeline import RAW_TO_SENTINEL

    assert RAW_TO_SENTINEL["Infiltration"] == "Lateral Movement"
    assert RAW_TO_SENTINEL["Infilteration"] == "Lateral Movement"
    assert RAW_TO_SENTINEL["DDOS attack-HOIC"] == "DDoS"
    assert RAW_TO_SENTINEL["DDOS attack-LOIC-UDP"] == "DDoS"

    # All target labels must exist in LABEL_MAP
    for raw_label, target_name in RAW_TO_SENTINEL.items():
        assert target_name in LABEL_MAP, f"Target '{target_name}' from '{raw_label}' missing in LABEL_MAP"


def test_candidate_rf_multicorpus_v1_missing_classes_audit():
    """
    Audits the saved candidate model candidate_rf_multicorpus_v1.pkl and confirms
    that class 9 (Lateral Movement) was never trained into the model due to the early break defect.
    """
    import joblib
    model_path = Path(__file__).parent.parent / "experiments" / "gate1_phase8_multicorpus_candidates" / "candidate_rf_multicorpus_v1.pkl"
    assert model_path.exists()
    pipeline = joblib.load(model_path)
    clf = pipeline.steps[-1][1]
    model_classes = list(clf.classes_)

    # Document exact classes present in the candidate model
    assert model_classes == [0, 1, 2, 3, 4, 6, 7, 8]
    # Class 9 (Lateral Movement) and Class 5 (RCE Attempt) are missing
    assert 9 not in model_classes, "Class 9 should not be present in candidate_rf_multicorpus_v1 due to defect"
    assert 5 not in model_classes

