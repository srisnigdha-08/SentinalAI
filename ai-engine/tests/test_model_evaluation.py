"""
Test suite for Phase 7 AI Model Evaluation, Drift Monitoring & Metadata Integrity
"""

import pytest
import numpy as np
import pandas as pd
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).parent.parent))
from evaluation.evaluate_model import ModelEvaluator, compute_file_sha256
from utils.features import FEATURE_NAMES, FEATURE_SCHEMA_VERSION


@pytest.fixture
def evaluator():
    return ModelEvaluator()


def test_model_metadata_verification(evaluator):
    meta = evaluator.verify_model_metadata()
    assert meta["integrityPassed"] is True
    assert meta["expectedFeatureCount"] == 53
    assert meta["featureSchemaVersion"] == FEATURE_SCHEMA_VERSION
    assert meta["rfClassifier"]["exists"] is True
    assert meta["rfClassifier"]["sha256"].startswith("CA0EFB1F")
    assert meta["isolationForest"]["exists"] is True
    assert meta["isolationForest"]["sha256"].startswith("17BD08FF")
    assert meta["thresholds"]["block"] == 0.92
    assert meta["thresholds"]["monitor"] == 0.85  # validated alert line (docs/IMPROVEMENTS_REPORT.md)
    assert meta["thresholds"]["anomaly"] == -0.55


def test_missing_artifact_handling(tmp_path):
    # Test that ModelEvaluator safely handles a directory with missing models
    empty_evaluator = ModelEvaluator(model_dir=str(tmp_path))
    meta = empty_evaluator.verify_model_metadata()
    assert meta["integrityPassed"] is False
    assert meta["rfClassifier"]["exists"] is False
    assert meta["rfClassifier"]["sha256"] == ""
    assert meta["isolationForest"]["exists"] is False


def test_schema_mismatch_detection():
    # If a feature vector does not match 53 features, predictor rejects it
    from inference.predictor import SentinelPredictor
    predictor = SentinelPredictor()
    malformed_record = {"flow_duration": 1000.0}  # Missing 52 features
    # extract_features_from_record populates defaults or extracts safely
    # but an array with wrong dimensions must be rejected
    with pytest.raises(Exception):
        # Pass a 2D array of wrong shape directly to predict_proba
        predictor.rf.predict(np.zeros((1, 20)))


def test_data_drift_detection(evaluator):
    # Create two identical distributions -> no drift
    np.random.seed(42)
    base_dist = np.random.normal(loc=10.0, scale=2.0, size=(100, 53))
    curr_dist_identical = np.random.normal(loc=10.0, scale=2.0, size=(100, 53))

    report = evaluator.check_drift(base_dist, curr_dist_identical, alpha=0.01)
    assert report["overallDataDrift"] is False
    assert report["checkedFeatures"] == 53

    # Create a severely drifted distribution across all 53 features
    drifted_dist = np.random.normal(loc=100.0, scale=20.0, size=(100, 53))
    report_drifted = evaluator.check_drift(base_dist, drifted_dist, alpha=0.01)
    assert report_drifted["overallDataDrift"] is True
    assert report_drifted["driftedFeatureCount"] > 10


def test_data_drift_dimension_mismatch(evaluator):
    base_dist = np.zeros((10, 53))
    mismatched_dist = np.zeros((10, 30))
    report = evaluator.check_drift(base_dist, mismatched_dist)
    assert "error" in report
    assert "dimension mismatch" in report["error"]


def test_inference_latency_and_throughput_measurement(evaluator):
    results = evaluator.evaluate_synthetic_held_out(rows=20)
    assert results["status"] == "EVALUATED"
    assert results["sampleCount"] == 20
    assert "metrics" in results
    assert "performance" in results
    assert results["performance"]["latencyMeanMs"] > 0
    assert results["performance"]["throughputPerSec"] > 0
    assert "falsePositiveRate" in results["metrics"]
    assert "falseNegativeRate" in results["metrics"]


def test_compute_classification_metrics_hand_calculated():
    from evaluation.evaluate_model import compute_classification_metrics
    # 5 samples:
    # y_true: 2 BENIGN (negatives), 3 Attacks (1 Port Scan, 2 DDoS)
    # y_pred: 1 BENIGN, 2 Port Scan, 1 DDoS, 1 BENIGN
    # -> TN: 1 (BENIGN -> BENIGN)
    # -> FP: 1 (BENIGN -> Port Scan)
    # -> FN: 1 (DDoS -> BENIGN)
    # -> TP: 2 (Port Scan -> Port Scan, DDoS -> DDoS)
    y_true = ["BENIGN", "BENIGN", "Port Scan", "DDoS", "DDoS"]
    y_pred = ["BENIGN", "Port Scan", "Port Scan", "DDoS", "BENIGN"]

    metrics = compute_classification_metrics(y_true, y_pred)
    assert metrics["sampleCount"] == 5
    cm = metrics["confusionMatrixBinary"]
    assert cm["trueNegative"] == 1
    assert cm["falsePositive"] == 1
    assert cm["falseNegative"] == 1
    assert cm["truePositive"] == 2

    # FPR = FP / (FP + TN) = 1 / (1 + 1) = 0.50
    assert metrics["falsePositiveRate"] == 0.50
    # FNR = FN / (FN + TP) = 1 / (1 + 2) = 0.3333
    assert abs(metrics["falseNegativeRate"] - 0.3333) < 0.001
    # Binary precision = TP / (TP + FP) = 2 / (2 + 1) = 0.6667
    assert abs(metrics["binaryPrecision"] - 0.6667) < 0.001
    # Binary recall = TP / (TP + FN) = 2 / (2 + 1) = 0.6667
    assert abs(metrics["binaryRecall"] - 0.6667) < 0.001
    # Binary F1 = 0.6667
    assert abs(metrics["binaryF1"] - 0.6667) < 0.001


def test_compute_classification_metrics_zero_detections():
    from evaluation.evaluate_model import compute_classification_metrics
    # Attacks in ground truth, but all predicted as BENIGN (100% false negative rate)
    y_true = ["Port Scan", "DDoS", "SSH Brute Force", "BENIGN"]
    y_pred = ["BENIGN", "BENIGN", "BENIGN", "BENIGN"]

    metrics = compute_classification_metrics(y_true, y_pred)
    cm = metrics["confusionMatrixBinary"]
    assert cm["trueNegative"] == 1
    assert cm["falsePositive"] == 0
    assert cm["falseNegative"] == 3
    assert cm["truePositive"] == 0
    assert metrics["falsePositiveRate"] == 0.0
    assert metrics["falseNegativeRate"] == 1.0  # 100% FNR
    assert metrics["binaryPrecision"] == 0.0
    assert metrics["binaryRecall"] == 0.0
    assert metrics["binaryF1"] == 0.0


def test_compute_classification_metrics_perfect_detection():
    from evaluation.evaluate_model import compute_classification_metrics
    y_true = ["BENIGN", "BENIGN", "Port Scan", "DDoS"]
    y_pred = ["BENIGN", "BENIGN", "Port Scan", "DDoS"]

    metrics = compute_classification_metrics(y_true, y_pred)
    cm = metrics["confusionMatrixBinary"]
    assert cm["trueNegative"] == 2
    assert cm["falsePositive"] == 0
    assert cm["falseNegative"] == 0
    assert cm["truePositive"] == 2
    assert metrics["falsePositiveRate"] == 0.0
    assert metrics["falseNegativeRate"] == 0.0
    assert metrics["binaryPrecision"] == 1.0
    assert metrics["binaryRecall"] == 1.0
    assert metrics["binaryF1"] == 1.0
    assert metrics["f1Macro"] == 1.0


def test_compute_classification_metrics_single_class_benign():
    from evaluation.evaluate_model import compute_classification_metrics
    # Only BENIGN samples present in ground truth and predictions
    y_true = ["BENIGN", "BENIGN", "BENIGN"]
    y_pred = ["BENIGN", "BENIGN", "BENIGN"]

    metrics = compute_classification_metrics(y_true, y_pred)
    cm = metrics["confusionMatrixBinary"]
    assert cm["trueNegative"] == 3
    assert cm["falsePositive"] == 0
    assert cm["falseNegative"] == 0
    assert cm["truePositive"] == 0
    # Zero positives -> FNR should safely return 0.0 without ZeroDivisionError
    assert metrics["falsePositiveRate"] == 0.0
    assert metrics["falseNegativeRate"] == 0.0
    assert metrics["binaryPrecision"] == 0.0
    assert metrics["binaryRecall"] == 0.0


def test_compute_classification_metrics_single_class_attack():
    from evaluation.evaluate_model import compute_classification_metrics
    # Only attack samples present
    y_true = ["DDoS", "DDoS", "DDoS"]
    y_pred = ["DDoS", "DDoS", "DDoS"]

    metrics = compute_classification_metrics(y_true, y_pred)
    cm = metrics["confusionMatrixBinary"]
    assert cm["trueNegative"] == 0
    assert cm["falsePositive"] == 0
    assert cm["falseNegative"] == 0
    assert cm["truePositive"] == 3
    # Zero negatives -> FPR should safely return 0.0 without ZeroDivisionError
    assert metrics["falsePositiveRate"] == 0.0
    assert metrics["falseNegativeRate"] == 0.0
    assert metrics["binaryPrecision"] == 1.0
    assert metrics["binaryRecall"] == 1.0


def test_compute_classification_metrics_empty_inputs():
    from evaluation.evaluate_model import compute_classification_metrics
    metrics = compute_classification_metrics([], [])
    assert metrics["sampleCount"] == 0
    assert metrics["f1Macro"] == 0.0
    assert metrics["falsePositiveRate"] == 0.0
    assert metrics["falseNegativeRate"] == 0.0


def test_compute_classification_metrics_length_mismatch():
    from evaluation.evaluate_model import compute_classification_metrics
    with pytest.raises(ValueError):
        compute_classification_metrics(["BENIGN"], ["BENIGN", "DDoS"])


def test_evaluate_dataset_empty(evaluator):
    res = evaluator.evaluate_dataset(pd.DataFrame())
    assert res["status"] == "EVALUATED_EMPTY"
    assert res["sampleCount"] == 0
    assert res["metrics"]["sampleCount"] == 0


def test_evaluate_cicids_held_out(evaluator):
    res = evaluator.evaluate_cicids_held_out(max_samples_per_file=50)
    assert res["status"] == "EVALUATED"
    assert res["sampleCount"] > 0
    # Confirms that on real PCAP flows the model detects attacks (non-zero recall)
    assert res["metrics"]["binaryRecall"] > 0.80
    assert res["metrics"]["confusionMatrixBinary"]["truePositive"] > 0

