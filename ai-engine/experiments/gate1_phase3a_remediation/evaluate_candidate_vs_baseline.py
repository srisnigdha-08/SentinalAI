#!/usr/bin/env python3
"""
SentinelAI — GATE-1 Phase 3A: Empirical Policy Comparison
Location: ai-engine/experiments/gate1_phase3a_remediation/evaluate_candidate_vs_baseline.py

Directly compares the baseline policy against the candidate decoupled policy
using identical input flows, identical model checkpoints, and identical label criteria.

Outputs:
ai-engine/experiments/gate1_phase3a_remediation/baseline_vs_candidate_metrics.json
"""

import sys
import os
import json
import time
import math
from pathlib import Path
import numpy as np
import pandas as pd
import joblib

CURRENT_DIR = Path(__file__).resolve().parent
AI_ENGINE_DIR = CURRENT_DIR.parent.parent

if str(AI_ENGINE_DIR) not in sys.path:
    sys.path.insert(0, str(AI_ENGINE_DIR))
if str(CURRENT_DIR) not in sys.path:
    sys.path.insert(0, str(CURRENT_DIR))

from utils.features import FEATURE_NAMES, LABEL_NAMES, RAW_LABEL_TO_TARGET, extract_features_from_record
from inference.predictor import SentinelPredictor, BLOCK_THRESHOLD, MONITOR_THRESHOLD, ANOMALY_THRESHOLD
from candidate_policy import CandidateSentinelPolicy


def wilson_score_interval(successes, total, confidence=0.95):
    """Calculates Wilson score 95% confidence interval for a binomial proportion."""
    if total == 0:
        return (0.0, 0.0)
    z = 1.95996 if confidence == 0.95 else 1.64485
    p = float(successes) / float(total)
    denominator = 1.0 + (z**2) / total
    centre = p + (z**2) / (2.0 * total)
    std = math.sqrt((p * (1.0 - p) + (z**2) / (4.0 * total)) / total)
    lower = max(0.0, (centre - z * std) / denominator)
    upper = min(1.0, (centre + z * std) / denominator)
    return (round(lower, 5), round(upper, 5))


def evaluate_both_policies(df, label_name, is_benign_only=False):
    """
    Evaluates both baseline predictor and candidate policy on identical flow stream.
    Features and model outputs are computed once and evaluated by both policies.
    """
    predictor = SentinelPredictor()
    cand_policy = CandidateSentinelPolicy()

    t0 = time.perf_counter()

    # Ground truth labels
    l_col = next((c for c in df.columns if "label" in c.lower()), "Label")
    y_true_raw = df[l_col].astype(str).str.strip().tolist()
    y_is_attack = np.array([RAW_LABEL_TO_TARGET.get(x, x).upper() != "BENIGN" for x in y_true_raw], dtype=bool)

    # 1. Feature extraction for all records
    records = df.to_dict(orient="records")
    X_list = [extract_features_from_record(r) for r in records]
    X = np.vstack(X_list)

    # 2. Vectorized Model Inference
    probas = predictor.rf.predict_proba(X)
    classes = predictor.rf.predict(X)
    max_ps = np.max(probas, axis=1)

    X_scaled = predictor.ifo.named_steps["scaler"].transform(X)
    if_scores = predictor.ifo.named_steps["if"].score_samples(X_scaled)

    # Collectors for Baseline
    b_actions = []
    b_scores = []
    b_classes = []

    # Collectors for Candidate
    c_actions = []
    c_scores = []
    c_classes = []
    c_status = []
    c_telemetry_alerts = []
    c_block_eligible = []

    for i in range(len(records)):
        cls_idx = int(classes[i])
        raw_cname = LABEL_NAMES.get(cls_idx, "BENIGN")
        max_p = float(max_ps[i])
        if_score = float(if_scores[i])
        is_anomaly = bool(if_score < ANOMALY_THRESHOLD)
        if_sig = predictor.calculate_if_anomaly_signal(if_score)

        # Baseline evaluation logic
        b_rf_s = max_p if raw_cname != "BENIGN" else (1.0 - max_p)
        b_score = round(0.7 * b_rf_s + 0.3 * if_sig, 4)
        b_cname = raw_cname
        if raw_cname == "BENIGN" and is_anomaly:
            b_cname = "Unknown"
            b_score = max(b_score, 0.55)
        b_action = "BLOCK" if b_score >= BLOCK_THRESHOLD else "MONITOR" if b_score >= MONITOR_THRESHOLD else "ALLOW"

        b_actions.append(b_action)
        b_scores.append(b_score)
        b_classes.append(b_cname)

        # Candidate evaluation logic
        c_res = cand_policy.evaluate_signals(
            cname=raw_cname,
            confidence=max_p,
            is_anomaly=is_anomaly,
            anomaly_signal=if_sig,
            anomaly_score=if_score,
        )
        c_actions.append(c_res["action"])
        c_scores.append(c_res["threatScore"])
        c_classes.append(c_res["predictedClass"])
        c_status.append(c_res["status"])
        c_telemetry_alerts.append(c_res["threatScore"] >= 0.50 or c_res["predictedClass"] == "Unknown")
        c_block_eligible.append(c_res["action"] == "BLOCK")

    duration = time.perf_counter() - t0
    total_pos = int(np.sum(y_is_attack))
    total_neg = int(np.sum(~y_is_attack))

    def calc_policy_metrics(act_list, blk_list, raw_cls_list):
        act_arr = np.array(act_list)
        
        # Policy Containment Action (MONITOR or BLOCK)
        action_pos = (act_arr == "MONITOR") | (act_arr == "BLOCK")
        pol_tp = int(np.sum(action_pos & y_is_attack))
        pol_fp = int(np.sum(action_pos & ~y_is_attack))
        pol_tn = int(np.sum(~action_pos & ~y_is_attack))
        pol_fn = int(np.sum(~action_pos & y_is_attack))

        pol_rec = pol_tp / total_pos if total_pos > 0 else 0.0
        pol_fpr = pol_fp / total_neg if total_neg > 0 else 0.0

        # Autonomous Block Action (BLOCK only)
        blk_arr = np.array(blk_list)
        blk_tp = int(np.sum(blk_arr & y_is_attack))
        blk_fp = int(np.sum(blk_arr & ~y_is_attack))
        blk_tn = int(np.sum(~blk_arr & ~y_is_attack))
        blk_fn = int(np.sum(~blk_arr & y_is_attack))

        blk_rec = blk_tp / total_pos if total_pos > 0 else 0.0
        blk_fpr = blk_fp / total_neg if total_neg > 0 else 0.0

        # Raw Supervised Classifier Detection (predicted != BENIGN)
        det_pos = np.array([p != "BENIGN" for p in raw_cls_list])
        det_tp = int(np.sum(det_pos & y_is_attack))
        det_fp = int(np.sum(det_pos & ~y_is_attack))
        det_rec = det_tp / total_pos if total_pos > 0 else 0.0
        det_fpr = det_fp / total_neg if total_neg > 0 else 0.0

        return {
            "policy_containment_action": {
                "confusion": {"TN": pol_tn, "FP": pol_fp, "FN": pol_fn, "TP": pol_tp},
                "recall": round(pol_rec, 5),
                "recall_ci_95": list(wilson_score_interval(pol_tp, total_pos)),
                "fpr": round(pol_fpr, 5),
                "fpr_ci_95": list(wilson_score_interval(pol_fp, total_neg)),
                "actions": pd.Series(act_list).value_counts().to_dict(),
            },
            "autonomous_block_action": {
                "confusion": {"TN": blk_tn, "FP": blk_fp, "FN": blk_fn, "TP": blk_tp},
                "recall": round(blk_rec, 5),
                "recall_ci_95": list(wilson_score_interval(blk_tp, total_pos)),
                "fpr": round(blk_fpr, 5),
                "fpr_ci_95": list(wilson_score_interval(blk_fp, total_neg)),
            },
            "supervised_detection_classifier": {
                "recall": round(det_rec, 5),
                "recall_ci_95": list(wilson_score_interval(det_tp, total_pos)),
                "fpr": round(det_fpr, 5),
                "fpr_ci_95": list(wilson_score_interval(det_fp, total_neg)),
            }
        }

    raw_rf_preds = [LABEL_NAMES.get(int(c), "BENIGN") for c in classes]
    baseline_metrics = calc_policy_metrics(b_actions, [a == "BLOCK" for a in b_actions], raw_rf_preds)
    candidate_metrics = calc_policy_metrics(c_actions, c_block_eligible, raw_rf_preds)
    
    candidate_metrics["telemetry_alert_rate"] = {
        "alert_count": int(np.sum(c_telemetry_alerts)),
        "alert_rate_overall": round(float(np.mean(c_telemetry_alerts)), 5),
        "alert_rate_on_attacks": round(float(np.sum(np.array(c_telemetry_alerts) & y_is_attack) / total_pos), 5) if total_pos > 0 else 0.0,
        "alert_rate_on_benign": round(float(np.sum(np.array(c_telemetry_alerts) & ~y_is_attack) / total_neg), 5) if total_neg > 0 else 0.0,
    }

    return {
        "dataset": label_name,
        "sampleCount": len(df),
        "negativeCount": total_neg,
        "positiveCount": total_pos,
        "durationSec": round(duration, 2),
        "baseline_policy": baseline_metrics,
        "candidate_policy": candidate_metrics,
        "delta": {
            "policy_recall_gain": round(candidate_metrics["policy_containment_action"]["recall"] - baseline_metrics["policy_containment_action"]["recall"], 5),
            "policy_fpr_delta": round(candidate_metrics["policy_containment_action"]["fpr"] - baseline_metrics["policy_containment_action"]["fpr"], 5),
            "block_recall_gain": round(candidate_metrics["autonomous_block_action"]["recall"] - baseline_metrics["autonomous_block_action"]["recall"], 5),
        }
    }


def main():
    print("=" * 70)
    print("  SentinelAI GATE-1 Phase 3A: Empirical Policy Comparison")
    print("=" * 70)

    data_dir = AI_ENGINE_DIR / "datasets" / "cicids2017"
    results = {
        "metadata": {
            "eval_timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "evaluation_module": "evaluate_candidate_vs_baseline.py",
            "active_rf_model": "rf_classifier_cicids_v2.pkl",
            "active_if_model": "isolation_forest_cicids.pkl",
            "note_on_monday": "Monday dataset is NOT an untouched holdout (15,000 flows sampled during training). Used as internal benign validation benchmark."
        },
        "datasets": {}
    }

    # 1. Monday Pure Benign Capture (10,000 samples)
    monday_csv = data_dir / "Monday-WorkingHours.pcap_ISCX.csv"
    if monday_csv.exists():
        print("\n[1/3] Loading 10,000 benign samples from Monday capture...")
        chunks = pd.read_csv(monday_csv, chunksize=20000)
        b_samples = []
        for chunk in chunks:
            chunk.columns = chunk.columns.str.strip()
            l_col = next((c for c in chunk.columns if "label" in c.lower()), "Label")
            b = chunk[chunk[l_col].astype(str).str.strip().str.upper() == "BENIGN"]
            b_samples.append(b)
            if sum(len(x) for x in b_samples) >= 10000:
                break
        df_mon = pd.concat(b_samples, ignore_index=True).head(10000)
        print(f"Loaded {len(df_mon):,} samples. Evaluating policies...")
        res_mon = evaluate_both_policies(df_mon, "Monday_Benign_Validation", is_benign_only=True)
        results["datasets"]["monday_benign_validation"] = res_mon
        print(f"  Baseline Policy Action FPR:  {res_mon['baseline_policy']['policy_containment_action']['fpr']*100:.2f}%")
        print(f"  Candidate Policy Action FPR: {res_mon['candidate_policy']['policy_containment_action']['fpr']*100:.2f}% (FPR Delta: {res_mon['delta']['policy_fpr_delta']*100:.2f}%)")

    # 2. Friday DDoS Capture (1,000 DDoS + 1,000 Benign)
    ddos_csv = data_dir / "Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv"
    if ddos_csv.exists():
        print("\n[2/3] Loading 1,000 DDoS + 1,000 Benign samples from Friday DDoS capture (offset=30,000)...")
        chunks = pd.read_csv(ddos_csv, chunksize=20000)
        b_list, a_list = [], []
        b_skipped = 0
        offset = 30000
        for chunk in chunks:
            chunk.columns = chunk.columns.str.strip()
            l_col = next((c for c in chunk.columns if "label" in c.lower()), "Label")
            b = chunk[chunk[l_col].astype(str).str.strip().str.upper() == "BENIGN"]
            a = chunk[chunk[l_col].astype(str).str.strip() == "DDoS"]
            if b_skipped < offset:
                s = min(len(b), offset - b_skipped)
                b = b.iloc[s:]
                b_skipped += s
            if len(b) > 0 and sum(len(x) for x in b_list) < 1000:
                b_list.append(b.head(1000 - sum(len(x) for x in b_list)))
            if len(a) > 0 and sum(len(x) for x in a_list) < 1000:
                a_list.append(a.head(1000 - sum(len(x) for x in a_list)))
            if sum(len(x) for x in b_list) >= 1000 and sum(len(x) for x in a_list) >= 1000:
                break
        df_ddos = pd.concat(b_list + a_list, ignore_index=True)
        print(f"Loaded {len(df_ddos):,} samples (1000 Benign, 1000 DDoS). Evaluating policies...")
        res_ddos = evaluate_both_policies(df_ddos, "Friday_DDoS_Capture")
        results["datasets"]["friday_ddos"] = res_ddos
        print(f"  Baseline Policy Recall:  {res_ddos['baseline_policy']['policy_containment_action']['recall']*100:.2f}% (TP={res_ddos['baseline_policy']['policy_containment_action']['confusion']['TP']})")
        print(f"  Candidate Policy Recall: {res_ddos['candidate_policy']['policy_containment_action']['recall']*100:.2f}% (TP={res_ddos['candidate_policy']['policy_containment_action']['confusion']['TP']}) -> Gain: +{res_ddos['delta']['policy_recall_gain']*100:.2f}%")
        print(f"  Candidate Block Recall:  {res_ddos['candidate_policy']['autonomous_block_action']['recall']*100:.2f}% (TP={res_ddos['candidate_policy']['autonomous_block_action']['confusion']['TP']})")

    # 3. Friday PortScan Capture (1,000 PortScan + 1,000 Benign)
    ps_csv = data_dir / "Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv"
    if ps_csv.exists():
        print("\n[3/3] Loading 1,000 PortScan + 1,000 Benign samples from Friday PortScan capture (offset=30,000)...")
        chunks = pd.read_csv(ps_csv, chunksize=20000)
        b_list, a_list = [], []
        b_skipped = 0
        offset = 30000
        for chunk in chunks:
            chunk.columns = chunk.columns.str.strip()
            l_col = next((c for c in chunk.columns if "label" in c.lower()), "Label")
            b = chunk[chunk[l_col].astype(str).str.strip().str.upper() == "BENIGN"]
            a = chunk[chunk[l_col].astype(str).str.strip() == "PortScan"]
            if b_skipped < offset:
                s = min(len(b), offset - b_skipped)
                b = b.iloc[s:]
                b_skipped += s
            if len(b) > 0 and sum(len(x) for x in b_list) < 1000:
                b_list.append(b.head(1000 - sum(len(x) for x in b_list)))
            if len(a) > 0 and sum(len(x) for x in a_list) < 1000:
                a_list.append(a.head(1000 - sum(len(x) for x in a_list)))
            if sum(len(x) for x in b_list) >= 1000 and sum(len(x) for x in a_list) >= 1000:
                break
        df_ps = pd.concat(b_list + a_list, ignore_index=True)
        print(f"Loaded {len(df_ps):,} samples (1000 Benign, 1000 PortScan). Evaluating policies...")
        res_ps = evaluate_both_policies(df_ps, "Friday_PortScan_Capture")
        results["datasets"]["friday_portscan"] = res_ps
        print(f"  Baseline Policy Recall:  {res_ps['baseline_policy']['policy_containment_action']['recall']*100:.2f}% (TP={res_ps['baseline_policy']['policy_containment_action']['confusion']['TP']})")
        print(f"  Candidate Policy Recall: {res_ps['candidate_policy']['policy_containment_action']['recall']*100:.2f}% (TP={res_ps['candidate_policy']['policy_containment_action']['confusion']['TP']}) -> Gain: +{res_ps['delta']['policy_recall_gain']*100:.2f}%")
        print(f"  Candidate Block Recall:  {res_ps['candidate_policy']['autonomous_block_action']['recall']*100:.2f}% (TP={res_ps['candidate_policy']['autonomous_block_action']['confusion']['TP']})")

    out_file = CURRENT_DIR / "baseline_vs_candidate_metrics.json"
    with open(out_file, "w") as f:
        json.dump(results, f, indent=2)
    print(f"\n[SUCCESS] Baseline vs Candidate comparative metrics saved to:\n  {out_file}")


if __name__ == "__main__":
    main()
