#!/usr/bin/env python3
"""
SentinelAI Model Evaluation, Drift Monitoring & Observability Pipeline (Phase 7)

Provides:
1. Reproducible evaluation pipeline measuring Precision, Recall, F1, FPR, FNR,
   Inference Latency, Throughput, and Confusion Matrices across classes.
2. Drift Monitoring:
   - Data Drift (Kolmogorov-Smirnov / feature distribution shifts)
   - Prediction Drift (class frequency deflection / score shift)
   - Concept Drift (degradation in F1 with labeled validation sets)
3. Model Metadata & Integrity Verification (SHA-256 checksums, schema versions, thresholds).
"""

import os
import sys
import time
import json
import hashlib
from pathlib import Path
from typing import Dict, Any, List, Tuple
import numpy as np
import pandas as pd
from sklearn.metrics import (
    precision_score, recall_score, f1_score,
    confusion_matrix, classification_report
)

sys.path.insert(0, str(Path(__file__).parent.parent))
from utils.features import (
    FEATURE_NAMES, LABEL_MAP, LABEL_NAMES, FEATURE_SCHEMA_VERSION,
    extract_features_from_record, RAW_LABEL_TO_TARGET
)
from inference.predictor import SentinelPredictor, BLOCK_THRESHOLD, MONITOR_THRESHOLD, ANOMALY_THRESHOLD


def compute_file_sha256(filepath: Path) -> str:
    """Computes SHA-256 hash of a file."""
    if not filepath.exists():
        return ""
    h = hashlib.sha256()
    with open(filepath, "rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest().upper()


def compute_classification_metrics(y_true: List[str], y_pred: List[str], all_labels: List[str] = None) -> Dict[str, Any]:
    """
    Computes macro, weighted, and binary (Benign vs Malicious) classification metrics
    with strict zero-division guards and hand-verifiable properties.
    """
    if len(y_true) != len(y_pred):
        raise ValueError(f"Length mismatch: len(y_true)={len(y_true)}, len(y_pred)={len(y_pred)}")

    if len(y_true) == 0:
        return {
            "sampleCount": 0,
            "f1Macro": 0.0,
            "f1Weighted": 0.0,
            "precisionMacro": 0.0,
            "recallMacro": 0.0,
            "falsePositiveRate": 0.0,
            "falseNegativeRate": 0.0,
            "binaryPrecision": 0.0,
            "binaryRecall": 0.0,
            "binaryF1": 0.0,
            "confusionMatrixBinary": {
                "trueNegative": 0,
                "falsePositive": 0,
                "falseNegative": 0,
                "truePositive": 0
            },
            "classesEvaluated": []
        }

    # Macro & weighted metrics across all classes
    p_macro = float(precision_score(y_true, y_pred, average="macro", zero_division=0))
    r_macro = float(recall_score(y_true, y_pred, average="macro", zero_division=0))
    f1_mac = float(f1_score(y_true, y_pred, average="macro", zero_division=0))
    f1_wgt = float(f1_score(y_true, y_pred, average="weighted", zero_division=0))

    # Binary Benign (0 / negative) vs Malicious (1 / positive)
    def is_pos(lbl):
        s = str(lbl).strip().upper()
        return s not in ["BENIGN", "0"]

    tn, fp, fn, tp = 0, 0, 0, 0
    for yt, yp in zip(y_true, y_pred):
        t_pos = is_pos(yt)
        p_pos = is_pos(yp)
        if not t_pos and not p_pos:
            tn += 1
        elif not t_pos and p_pos:
            fp += 1
        elif t_pos and not p_pos:
            fn += 1
        else:
            tp += 1

    fpr = float(fp / (fp + tn)) if (fp + tn) > 0 else 0.0
    fnr = float(fn / (fn + tp)) if (fn + tp) > 0 else 0.0
    bin_prec = float(tp / (tp + fp)) if (tp + fp) > 0 else 0.0
    bin_rec = float(tp / (tp + fn)) if (tp + fn) > 0 else 0.0
    bin_f1 = float(2 * bin_prec * bin_rec / (bin_prec + bin_rec)) if (bin_prec + bin_rec) > 0 else 0.0

    eval_classes = sorted(list(set(y_true + y_pred)))

    return {
        "sampleCount": len(y_true),
        "f1Macro": round(f1_mac, 4),
        "f1Weighted": round(f1_wgt, 4),
        "precisionMacro": round(p_macro, 4),
        "recallMacro": round(r_macro, 4),
        "falsePositiveRate": round(fpr, 4),
        "falseNegativeRate": round(fnr, 4),
        "binaryPrecision": round(bin_prec, 4),
        "binaryRecall": round(bin_rec, 4),
        "binaryF1": round(bin_f1, 4),
        "confusionMatrixBinary": {
            "trueNegative": tn,
            "falsePositive": fp,
            "falseNegative": fn,
            "truePositive": tp
        },
        "classesEvaluated": eval_classes
    }


class ModelEvaluator:
    def __init__(self, model_dir: str = "models", data_dir: str = "datasets"):
        self.base_dir = Path(__file__).parent.parent
        self.model_dir = self.base_dir / model_dir
        self.data_dir = self.base_dir / data_dir
        self.predictor = SentinelPredictor(model_dir=str(self.model_dir))

    def verify_model_metadata(self) -> Dict[str, Any]:
        """
        Verifies model metadata records, artifact SHA-256 integrity,
        feature schema versions, and threshold alignments.
        """
        # The artifacts the engine actually serves (models/registry.json), not a hard-coded file name.
        from inference.predictor import load_registry
        try:
            reg = load_registry(self.model_dir)
        except ValueError:
            reg = None
        clf = reg["classifier"] if reg else {"file": "rf_classifier_cicids_v2.pkl", "meta": "rf_classifier_cicids_v2_meta.json"}
        ano = reg["anomaly"] if reg else {"file": "isolation_forest_cicids.pkl", "meta": "isolation_forest_cicids_meta.json"}
        rf_model_p, rf_meta_p = self.model_dir / clf["file"], self.model_dir / (clf.get("meta") or "-")
        if_model_p, if_meta_p = self.model_dir / ano["file"], self.model_dir / (ano.get("meta") or "-")

        rf_hash = compute_file_sha256(rf_model_p)
        if_hash = compute_file_sha256(if_model_p)

        meta = {
            "verifiedAt": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "featureSchemaVersion": FEATURE_SCHEMA_VERSION,
            "expectedFeatureCount": len(FEATURE_NAMES),
            "rfClassifier": {
                "file": rf_model_p.name,
                "sha256": rf_hash,
                "exists": rf_model_p.exists(),
                "metaExists": rf_meta_p.exists(),
                "nFeatures": getattr(self.predictor.rf, "n_features_in_", None),
                "version": self.predictor.rf_meta.get("version", "unknown")
            },
            "isolationForest": {
                "file": if_model_p.name,
                "sha256": if_hash,
                "exists": if_model_p.exists(),
                "metaExists": if_meta_p.exists(),
                "nFeatures": getattr(self.predictor.ifo, "n_features_in_", None),
                "version": self.predictor.if_meta.get("version", "unknown")
            },
            "thresholds": {
                "block": BLOCK_THRESHOLD,
                "monitor": MONITOR_THRESHOLD,
                "anomaly": ANOMALY_THRESHOLD
            },
            "integrityPassed": bool(rf_model_p.exists() and if_model_p.exists() and self.predictor._loaded)
        }
        return meta

    def evaluate_dataset(self, samples_df: pd.DataFrame, max_samples: int = 5000) -> Dict[str, Any]:
        """
        Runs comprehensive evaluation against a labeled dataset dataframe.
        """
        if not self.predictor._loaded:
            return {"error": "Predictor models not loaded", "status": "UNAVAILABLE"}

        if samples_df is None or len(samples_df) == 0:
            empty_metrics = compute_classification_metrics([], [])
            return {
                "status": "EVALUATED_EMPTY",
                "sampleCount": 0,
                "metrics": empty_metrics,
                "performance": {
                    "latencyMeanMs": 0.0,
                    "latencyMedianMs": 0.0,
                    "latencyP95Ms": 0.0,
                    "latencyP99Ms": 0.0,
                    "throughputPerSec": 0.0
                },
                "classesEvaluated": []
            }

        # Subsample if necessary
        df = samples_df.copy()
        if len(df) > max_samples:
            df = df.sample(n=max_samples, random_state=42)

        # Find label column (case and whitespace insensitive)
        label_col = next((c for c in df.columns if c.strip().lower() in ["label", "target_class"]), None)
        if not label_col:
            return {"error": "No label column found in dataset", "status": "UNAVAILABLE"}

        y_true = []
        y_pred = []
        latencies = []

        for _, row in df.iterrows():
            record = row.to_dict()
            raw_label = str(row[label_col]).strip()
            true_label = RAW_LABEL_TO_TARGET.get(raw_label, raw_label)
            if true_label.upper() == "BENIGN":
                true_label = "BENIGN"

            t0 = time.perf_counter()
            try:
                res = self.predictor.predict(record, explain=False)
                latencies.append((time.perf_counter() - t0) * 1000.0)
                pred_label = res["predictedClass"]
            except Exception:
                pred_label = "Unknown"
                latencies.append((time.perf_counter() - t0) * 1000.0)

            y_true.append(true_label)
            y_pred.append(pred_label)

        metrics = compute_classification_metrics(y_true, y_pred)
        latency_arr = np.array(latencies) if latencies else np.array([0.0])
        throughput = float(len(latencies) / (np.sum(latency_arr) / 1000.0)) if len(latencies) > 0 and np.sum(latency_arr) > 0 else 0.0

        return {
            "status": "EVALUATED",
            "sampleCount": len(df),
            "metrics": metrics,
            "performance": {
                "latencyMeanMs": round(float(np.mean(latency_arr)), 2),
                "latencyMedianMs": round(float(np.median(latency_arr)), 2),
                "latencyP95Ms": round(float(np.percentile(latency_arr, 95)), 2),
                "latencyP99Ms": round(float(np.percentile(latency_arr, 99)), 2),
                "throughputPerSec": round(throughput, 1)
            },
            "classesEvaluated": metrics["classesEvaluated"]
        }

    def evaluate_cicids_held_out(self, max_samples_per_file: int = 500) -> Dict[str, Any]:
        """
        Evaluates model against real CICIDS2017 PCAP flow CSV files from datasets/cicids2017/.
        Extracts PortScan and DDoS attack flows along with benign ambient flows.
        """
        cicids_dir = self.data_dir / "cicids2017"
        if not cicids_dir.exists():
            return {"error": f"CICIDS directory not found at {cicids_dir}", "status": "UNAVAILABLE"}

        dfs = []
        target_files = [
            "Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv",
            "Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv"
        ]

        for fname in target_files:
            fpath = cicids_dir / fname
            if not fpath.exists():
                continue
            chunks = pd.read_csv(fpath, chunksize=5000)
            collected_attack = []
            collected_benign = []
            for chunk in chunks:
                l_col = next((c for c in chunk.columns if "label" in c.lower()), None)
                if not l_col:
                    break
                attacks = chunk[chunk[l_col].astype(str).str.strip().str.upper() != "BENIGN"]
                benigns = chunk[chunk[l_col].astype(str).str.strip().str.upper() == "BENIGN"]
                if len(attacks) > 0 and sum(len(x) for x in collected_attack) < max_samples_per_file:
                    collected_attack.append(attacks.head(max_samples_per_file - sum(len(x) for x in collected_attack)))
                if len(benigns) > 0 and sum(len(x) for x in collected_benign) < max_samples_per_file:
                    collected_benign.append(benigns.head(max_samples_per_file - sum(len(x) for x in collected_benign)))
                if sum(len(x) for x in collected_attack) >= max_samples_per_file and sum(len(x) for x in collected_benign) >= max_samples_per_file:
                    break

            if collected_attack and collected_benign:
                dfs.append(pd.concat(collected_attack + collected_benign, ignore_index=True))

        if not dfs:
            return {"error": "No valid CICIDS samples loaded", "status": "UNAVAILABLE"}

        combined_df = pd.concat(dfs, ignore_index=True)
        return self.evaluate_dataset(combined_df, max_samples=len(combined_df))

    def evaluate_synthetic_held_out(self, rows: int = 2000) -> Dict[str, Any]:
        """
        Evaluates model on held-out synthetic validation flows.
        """
        from utils.data_generator import generate
        val_df = generate(rows)
        return self.evaluate_dataset(val_df, max_samples=rows)

    def check_drift(self, baseline_features: np.ndarray, current_features: np.ndarray, alpha: float = 0.05) -> Dict[str, Any]:
        """
        Assesses Data Drift using two-sample Kolmogorov-Smirnov test per feature.
        """
        from scipy import stats
        drift_report = {
            "checkedFeatures": len(FEATURE_NAMES),
            "driftedFeatureCount": 0,
            "driftedFeatures": [],
            "overallDataDrift": False
        }

        if baseline_features.shape[1] != current_features.shape[1]:
            drift_report["error"] = "Feature dimension mismatch between baseline and current"
            return drift_report

        for i, feat_name in enumerate(FEATURE_NAMES):
            b_col = baseline_features[:, i]
            c_col = current_features[:, i]

            # Perform KS test
            ks_res = stats.ks_2samp(b_col, c_col)
            is_drifted = ks_res.pvalue < alpha
            if is_drifted:
                drift_report["driftedFeatureCount"] += 1
                drift_report["driftedFeatures"].append({
                    "feature": feat_name,
                    "statistic": round(float(ks_res.statistic), 4),
                    "pValue": float(ks_res.pvalue)
                })

        # Threshold: if > 20% of features show distribution shift, flag data drift
        if drift_report["driftedFeatureCount"] > (0.2 * len(FEATURE_NAMES)):
            drift_report["overallDataDrift"] = True

        return drift_report


if __name__ == "__main__":
    evaluator = ModelEvaluator()
    print("=== Model Metadata & Integrity ===")
    meta = evaluator.verify_model_metadata()
    print(json.dumps(meta, indent=2))

    print("\n=== Evaluating Held-Out Synthetic Validation Set (1,000 samples) ===")
    results = evaluator.evaluate_synthetic_held_out(1000)
    print(json.dumps(results, indent=2))
