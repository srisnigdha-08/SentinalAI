#!/usr/bin/env python3
"""
SentinelAI Phase 10: Trace and Diagnose Failing Categories
Location: ai-engine/experiments/gate1_phase10_detector_recovery/trace_failing_categories.py
"""

import sys
import os
import json
import hashlib
from pathlib import Path
import numpy as np
import pandas as pd
import joblib
from collections import Counter

REPO_ROOT = Path(__file__).resolve().parent.parent.parent.parent
AI_ENGINE_DIR = REPO_ROOT / "ai-engine"
PHASE8_DIR = AI_ENGINE_DIR / "experiments" / "gate1_phase8_multicorpus_candidates"
HOLDOUT_DIR = Path("D:/sentinelai_datasets/cse_cic_ids2018/holdout_sets")
CSE2018_DIR = Path("D:/sentinelai_datasets/cse_cic_ids2018")

sys.path.insert(0, str(AI_ENGINE_DIR))
from utils.features import FEATURE_NAMES, LABEL_NAMES, LABEL_MAP

sys.stdout.reconfigure(encoding='utf-8')

timing_features = [
    "flow_duration", "flow_iat_mean", "flow_iat_std", "flow_iat_max", "flow_iat_min",
    "fwd_iat_total", "fwd_iat_mean", "fwd_iat_std", "fwd_iat_max", "fwd_iat_min",
    "bwd_iat_total", "bwd_iat_mean", "bwd_iat_std", "bwd_iat_max", "bwd_iat_min"
]
window_features = ["init_win_bytes_forward", "init_win_bytes_backward"]
rate_features = ["flow_bytes_per_sec", "flow_packets_per_sec"]
length_features = ["total_len_fwd_packets", "total_len_bwd_packets"]

def transform_to_schema_f(df: pd.DataFrame):
    df_c = df.copy()
    feats = [f for f in FEATURE_NAMES if f not in window_features]
    for tf in timing_features + rate_features + length_features:
        if tf in feats and tf in df_c.columns:
            df_c[tf] = np.log1p(np.maximum(df_c[tf].values, 0.0))
    fwd_pkts = np.maximum(df_c["total_fwd_packets"].values, 1.0)
    bwd_pkts = np.maximum(df_c["total_bwd_packets"].values, 1.0)
    df_c["fwd_header_len"] = df_c["fwd_header_len"].values / fwd_pkts
    df_c["bwd_header_len"] = df_c["bwd_header_len"].values / bwd_pkts
    return df_c[feats].values.astype(np.float32), feats

def main():
    print("=" * 80)
    print("PHASE 10: FORENSIC ROOT-CAUSE TRACING OF FAILING DETECTION CATEGORIES")
    print("=" * 80)

    # 1. Inspect Candidate Model Metadata
    cand_path = PHASE8_DIR / "candidate_rf_multicorpus_v1.pkl"
    cand_model = joblib.load(cand_path)
    rf = cand_model.named_steps["rf"]
    print(f"\n[1] Candidate Model: {cand_path.name}")
    print(f"  Trained Classes: {rf.classes_}")
    print(f"  Class Names: {[LABEL_NAMES.get(c, str(c)) for c in rf.classes_]}")
    print(f"  Missing Target Classes: {[c for c in LABEL_MAP.values() if c not in rf.classes_]}")

    # 2. Inspect Phase 8 Training Partitions
    train_p = PHASE8_DIR / "partition_train_multicorpus.parquet"
    df_train = pd.read_parquet(train_p)
    print(f"\n[2] Phase 8 Training Partition: {train_p.name} ({len(df_train)} rows)")
    print(f"  Raw Labels in Training:\n{df_train['ground_truth_raw'].value_counts().to_dict()}")
    print(f"  Mapped Labels in Training:\n{df_train['ground_truth_label'].value_counts().to_dict()}")

    # 3. Trace Each Failing Category
    failing_slices = [
        ("holdout_ddos.parquet", "DDoS HOIC & LOIC-UDP", "DDoS"),
        ("holdout_infiltration.parquet", "Infiltration", "Lateral Movement"),
        ("holdout_bruteforce_ssh_ftp.parquet", "SSH Brute Force", "SSH Brute Force"),
        ("holdout_botnet.parquet", "Botnet Ares", "Malware Beacon"),
        ("holdout_web_attacks.parquet", "Web Attacks", ["Credential Stuffing", "XSS Attempt", "SQL Injection"])
    ]

    diagnostics = {}

    for fn, desc, target_lbl in failing_slices:
        print(f"\n[3] Tracing: {desc} ({fn})")
        df_h = pd.read_parquet(HOLDOUT_DIR / fn)
        if isinstance(target_lbl, list):
            df_att = df_h[df_h["ground_truth_label"].isin(target_lbl)].copy()
        else:
            df_att = df_h[df_h["ground_truth_label"] == target_lbl].copy()
        
        n_att = len(df_att)
        if n_att == 0:
            print("  No matching attack rows found!")
            continue

        X, _ = transform_to_schema_f(df_att)
        probas = cand_model.predict_proba(X)
        preds = cand_model.predict(X)
        max_p = np.max(probas, axis=1)

        det_mask = (preds != 0) & (max_p >= 0.70)
        tp = int(np.sum(det_mask))
        fn_cnt = int(np.sum(~det_mask))
        recall = tp / n_att

        pred_dist = Counter([LABEL_NAMES.get(int(p), str(p)) for p in preds])
        missed_pred_dist = Counter([LABEL_NAMES.get(int(p), str(p)) for p in preds[~det_mask]])

        print(f"  Total Flows: {n_att}, Detected: {tp}, Missed: {fn_cnt}, Recall: {recall*100:.2f}%")
        print(f"  Overall Predicted Class Distribution: {dict(pred_dist)}")
        print(f"  Missed Flows Predicted Class Distribution: {dict(missed_pred_dist)}")
        print(f"  Mean P(BENIGN) across all flows: {np.mean(probas[:, 0]):.4f}")
        print(f"  Mean P(BENIGN) for missed flows: {np.mean(probas[~det_mask, 0]):.4f}")
        if np.sum(det_mask) > 0:
            print(f"  Mean Max P for detected flows: {np.mean(max_p[det_mask]):.4f}")
        print(f"  Mean Max P for missed flows: {np.mean(max_p[~det_mask]):.4f}")

        diagnostics[desc] = {
            "total": n_att,
            "tp": tp,
            "fn": fn_cnt,
            "recall": round(recall, 4),
            "predicted_distribution": dict(pred_dist),
            "missed_predicted_distribution": dict(missed_pred_dist),
            "mean_p_benign_missed": round(float(np.mean(probas[~det_mask, 0])), 4),
            "mean_max_p_missed": round(float(np.mean(max_p[~det_mask])), 4)
        }

    out_file = Path(__file__).parent / "diagnostic_trace_summary.json"
    with open(out_file, "w", encoding="utf-8") as f:
        json.dump(diagnostics, f, indent=2)
    print(f"\nSaved diagnostic trace summary to: {out_file}")

if __name__ == "__main__":
    main()
