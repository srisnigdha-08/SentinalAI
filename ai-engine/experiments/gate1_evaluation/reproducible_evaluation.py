#!/usr/bin/env python3
"""
GATE-1 Rigorous Evaluation & Statistical Validation Pipeline
Author: Machine Learning & MLOps Engineer
Location: ai-engine/experiments/gate1_evaluation/reproducible_evaluation.py

Evaluates:
1. Raw Random Forest Classifier (rf_classifier_cicids_v2.pkl)
2. Production SentinelPredictor (with Isolation Forest override)
3. Evaluates against:
   - Monday Pure Benign Capture (10,000 samples - zero training overlap)
   - Friday DDoS Capture (1,000 attacks + 1,000 ambient benign)
   - Friday PortScan Capture (1,000 attacks + 1,000 ambient benign)
4. Computes exact Wilson Score 95% Confidence Intervals for FPR and Recall.
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

base_dir = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(base_dir))

from utils.features import FEATURE_NAMES, LABEL_MAP, LABEL_NAMES, RAW_LABEL_TO_TARGET, extract_features_from_record
from inference.predictor import SentinelPredictor, ANOMALY_THRESHOLD, BLOCK_THRESHOLD, MONITOR_THRESHOLD
from evaluation.evaluate_model import compute_classification_metrics

def wilson_score_interval(successes, total, confidence=0.95):
    """
    Calculates the Wilson score confidence interval for a binomial proportion.
    """
    if total == 0:
        return (0.0, 0.0)
    # z for 95% confidence is ~1.95996
    z = 1.95996 if confidence == 0.95 else 1.64485
    p = float(successes) / float(total)
    denominator = 1.0 + (z**2) / total
    centre_adjusted_probability = p + (z**2) / (2.0 * total)
    adjusted_standard_deviation = math.sqrt((p * (1.0 - p) + (z**2) / (4.0 * total)) / total)
    
    lower_bound = (centre_adjusted_probability - z * adjusted_standard_deviation) / denominator
    upper_bound = (centre_adjusted_probability + z * adjusted_standard_deviation) / denominator
    return (max(0.0, lower_bound), min(1.0, upper_bound))

def evaluate_stream(predictor, df, label_name, is_benign_only=False):
    """
    Evaluates both raw RF and composite SentinelPredictor on a dataframe.
    """
    raw_rf_preds = []
    comp_preds = []
    actions = []
    threat_scores = []
    is_anomalies = []
    if_scores = []
    
    t0 = time.time()
    for _, row in df.iterrows():
        rec = row.to_dict()
        res = predictor.predict(rec)
        
        comp_preds.append(res["predictedClass"])
        actions.append(res["action"])
        threat_scores.append(res["threatScore"])
        is_anomalies.append(res["isAnomaly"])
        if_scores.append(res["anomalyScore"])
        
        # Raw RF prediction without composite override
        X = extract_features_from_record(rec).reshape(1, -1)
        raw_cls = int(predictor.rf.predict(X)[0])
        raw_rf_preds.append(LABEL_NAMES.get(raw_cls, "Unknown"))
        
    duration = time.time() - t0
    
    # Ground truth
    l_col = next((c for c in df.columns if "label" in c.lower()), "Label")
    y_true_raw = df[l_col].astype(str).str.strip().tolist()
    y_true = ["BENIGN" if RAW_LABEL_TO_TARGET.get(x, x).upper() == "BENIGN" else RAW_LABEL_TO_TARGET.get(x, x) for x in y_true_raw]
    
    # Raw RF binary metrics (treat any non-BENIGN as Positive)
    rf_tn, rf_fp, rf_fn, rf_tp = 0, 0, 0, 0
    for yt, yp in zip(y_true, raw_rf_preds):
        t_pos = (yt != "BENIGN")
        p_pos = (yp != "BENIGN")
        if not t_pos and not p_pos: rf_tn += 1
        elif not t_pos and p_pos: rf_fp += 1
        elif t_pos and not p_pos: rf_fn += 1
        else: rf_tp += 1
        
    # Composite binary metrics (treat any non-BENIGN, including Unknown, as Positive)
    comp_tn, comp_fp, comp_fn, comp_tp = 0, 0, 0, 0
    for yt, yp in zip(y_true, comp_preds):
        t_pos = (yt != "BENIGN")
        p_pos = (yp != "BENIGN")
        if not t_pos and not p_pos: comp_tn += 1
        elif not t_pos and p_pos: comp_fp += 1
        elif t_pos and not p_pos: comp_fn += 1
        else: comp_tp += 1
        
    # Policy-Action binary metrics (treat action == BLOCK or MONITOR as Positive)
    pol_tn, pol_fp, pol_fn, pol_tp = 0, 0, 0, 0
    for yt, act in zip(y_true, actions):
        t_pos = (yt != "BENIGN")
        p_pos = (act in ["BLOCK", "MONITOR"])
        if not t_pos and not p_pos: pol_tn += 1
        elif not t_pos and p_pos: pol_fp += 1
        elif t_pos and not p_pos: pol_fn += 1
        else: pol_tp += 1

    total_neg = rf_tn + rf_fp
    total_pos = rf_tp + rf_fn
    
    rf_fpr = rf_fp / total_neg if total_neg > 0 else 0.0
    rf_fpr_ci = wilson_score_interval(rf_fp, total_neg)
    rf_rec = rf_tp / total_pos if total_pos > 0 else 0.0
    rf_rec_ci = wilson_score_interval(rf_tp, total_pos)
    
    comp_fpr = comp_fp / total_neg if total_neg > 0 else 0.0
    comp_fpr_ci = wilson_score_interval(comp_fp, total_neg)
    comp_rec = comp_tp / total_pos if total_pos > 0 else 0.0
    comp_rec_ci = wilson_score_interval(comp_tp, total_pos)
    
    pol_fpr = pol_fp / total_neg if total_neg > 0 else 0.0
    pol_fpr_ci = wilson_score_interval(pol_fp, total_neg)
    pol_rec = pol_tp / total_pos if total_pos > 0 else 0.0
    pol_rec_ci = wilson_score_interval(pol_tp, total_pos)
    
    return {
        "dataset": label_name,
        "sampleCount": len(df),
        "negativeCount": total_neg,
        "positiveCount": total_pos,
        "durationSec": round(duration, 2),
        "raw_rf": {
            "confusion": {"TN": rf_tn, "FP": rf_fp, "FN": rf_fn, "TP": rf_tp},
            "fpr": round(rf_fpr, 5),
            "fpr_ci_95": [round(rf_fpr_ci[0], 5), round(rf_fpr_ci[1], 5)],
            "recall": round(rf_rec, 5),
            "recall_ci_95": [round(rf_rec_ci[0], 5), round(rf_rec_ci[1], 5)],
            "predictions": pd.Series(raw_rf_preds).value_counts().to_dict()
        },
        "composite_predictor": {
            "confusion": {"TN": comp_tn, "FP": comp_fp, "FN": comp_fn, "TP": comp_tp},
            "fpr": round(comp_fpr, 5),
            "fpr_ci_95": [round(comp_fpr_ci[0], 5), round(comp_fpr_ci[1], 5)],
            "recall": round(comp_rec, 5),
            "recall_ci_95": [round(comp_rec_ci[0], 5), round(comp_rec_ci[1], 5)],
            "anomalies_flagged": int(np.sum(is_anomalies)),
            "predictions": pd.Series(comp_preds).value_counts().to_dict()
        },
        "policy_action": {
            "confusion": {"TN": pol_tn, "FP": pol_fp, "FN": pol_fn, "TP": pol_tp},
            "fpr": round(pol_fpr, 5),
            "fpr_ci_95": [round(pol_fpr_ci[0], 5), round(pol_fpr_ci[1], 5)],
            "recall": round(pol_rec, 5),
            "recall_ci_95": [round(pol_rec_ci[0], 5), round(pol_rec_ci[1], 5)],
            "actions": pd.Series(actions).value_counts().to_dict()
        }
    }

def main():
    print("=" * 70)
    print("  SentinelAI GATE-1 Rigorous Statistical Evaluation Pipeline")
    print("=" * 70)
    
    predictor = SentinelPredictor()
    data_dir = base_dir / "datasets" / "cicids2017"
    results = {}
    
    # 1. Monday Pure Benign Capture (10,000 samples)
    monday_csv = data_dir / "Monday-WorkingHours.pcap_ISCX.csv"
    if monday_csv.exists():
        print("\n[1/3] Loading 10,000 independent benign samples from Monday capture...")
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
        print(f"Loaded {len(df_mon):,} samples. Running evaluation...")
        res_mon = evaluate_stream(predictor, df_mon, "Monday_Pure_Benign", is_benign_only=True)
        results["monday_pure_benign"] = res_mon
        print(f"  Raw RF FPR: {res_mon['raw_rf']['fpr']*100:.2f}% (95% CI: [{res_mon['raw_rf']['fpr_ci_95'][0]*100:.2f}%, {res_mon['raw_rf']['fpr_ci_95'][1]*100:.2f}%])")
        print(f"  Composite Predictor FPR: {res_mon['composite_predictor']['fpr']*100:.2f}% (95% CI: [{res_mon['composite_predictor']['fpr_ci_95'][0]*100:.2f}%, {res_mon['composite_predictor']['fpr_ci_95'][1]*100:.2f}%])")
        print(f"  Policy Action (BLOCK/MONITOR) FPR: {res_mon['policy_action']['fpr']*100:.2f}% (95% CI: [{res_mon['policy_action']['fpr_ci_95'][0]*100:.2f}%, {res_mon['policy_action']['fpr_ci_95'][1]*100:.2f}%])")

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
        print(f"Loaded {len(df_ddos):,} samples (1000 Benign, 1000 DDoS). Running evaluation...")
        res_ddos = evaluate_stream(predictor, df_ddos, "Friday_DDoS_Capture")
        results["friday_ddos"] = res_ddos
        print(f"  Raw RF Recall: {res_ddos['raw_rf']['recall']*100:.2f}% | Raw RF FPR: {res_ddos['raw_rf']['fpr']*100:.2f}%")
        print(f"  Composite Predictor Recall: {res_ddos['composite_predictor']['recall']*100:.2f}% | Composite Predictor FPR: {res_ddos['composite_predictor']['fpr']*100:.2f}%")
        print(f"  Policy Action Recall: {res_ddos['policy_action']['recall']*100:.2f}% | Policy Action FPR: {res_ddos['policy_action']['fpr']*100:.2f}%")

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
        print(f"Loaded {len(df_ps):,} samples (1000 Benign, 1000 PortScan). Running evaluation...")
        res_ps = evaluate_stream(predictor, df_ps, "Friday_PortScan_Capture")
        results["friday_portscan"] = res_ps
        print(f"  Raw RF Recall: {res_ps['raw_rf']['recall']*100:.2f}% | Raw RF FPR: {res_ps['raw_rf']['fpr']*100:.2f}%")
        print(f"  Composite Predictor Recall: {res_ps['composite_predictor']['recall']*100:.2f}% | Composite Predictor FPR: {res_ps['composite_predictor']['fpr']*100:.2f}%")
        print(f"  Policy Action Recall: {res_ps['policy_action']['recall']*100:.2f}% | Policy Action FPR: {res_ps['policy_action']['fpr']*100:.2f}%")

    out_json = base_dir / "experiments" / "gate1_evaluation" / "evaluation_results.json"
    with open(out_json, "w") as f:
        json.dump(results, f, indent=2)
    print(f"\nAll results saved to: {out_json}")

if __name__ == "__main__":
    main()
