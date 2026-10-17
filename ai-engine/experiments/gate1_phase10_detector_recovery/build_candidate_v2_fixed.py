"""
SentinelAI GATE-1: Fixed Data Pipeline and Candidate V2 Model Training
Location: ai-engine/experiments/gate1_phase10_detector_recovery/build_candidate_v2_fixed.py

Fixes:
1. Premature loop exit bug: collection iterates through all chunks until all target quotas are satisfied or EOF.
2. Ingestion of omitted Wednesday-21-02-2018 (DDOS attack-HOIC and LOIC-UDP).
3. Ingestion of Thursday-01-03-2018 Infilteration (Class 9 Lateral Movement) with balanced benign pairing.
4. Preserves 100% zero leakage against sealed holdouts.
5. Saves candidate model strictly to isolated artifact location: candidate_rf_multicorpus_v2_fixed.pkl
"""

import sys
import os
import json
import math
import time
import hashlib
from pathlib import Path
import numpy as np
import pandas as pd
import joblib

from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.pipeline import Pipeline

REPO_ROOT = Path(__file__).resolve().parent.parent.parent.parent
AI_ENGINE_DIR = REPO_ROOT / "ai-engine"
PHASE8_DIR = AI_ENGINE_DIR / "experiments" / "gate1_phase8_multicorpus_candidates"
PHASE10_DIR = Path(__file__).resolve().parent
HOLDOUT_DIR = Path("D:/sentinelai_datasets/cse_cic_ids2018/holdout_sets")
CSE2018_DIR = Path("D:/sentinelai_datasets/cse_cic_ids2018")
CIC2017_DIR = AI_ENGINE_DIR / "datasets" / "cicids2017"

sys.path.insert(0, str(AI_ENGINE_DIR))
sys.path.insert(0, str(PHASE8_DIR))

from utils.features import FEATURE_NAMES, LABEL_NAMES, LABEL_MAP
from build_multicorpus_pipeline import (
    FEATURE_MAPPING_2018, FEATURE_MAPPING_2017, RAW_TO_SENTINEL,
    standardize_df
)

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


def index_holdout_hashes():
    holdout_files = sorted(list(HOLDOUT_DIR.glob("*.parquet")))
    holdout_hashes = set()
    for hf in holdout_files:
        df_h = pd.read_parquet(hf)
        for _, r in df_h[FEATURE_NAMES].iterrows():
            r_str = ",".join(f"{float(r[k]):.4f}" for k in sorted(FEATURE_NAMES))
            holdout_hashes.add(hashlib.md5(r_str.encode("utf-8")).hexdigest())
    return holdout_hashes


def extract_chunks_robust(csv_path, mapping, corpus_name, target_classes_dict, holdout_hashes, chunksize=25000):
    """
    Robust chunk extractor: traverses all chunks until target quotas are satisfied or file is exhausted.
    """
    csv_path = Path(csv_path)
    print(f"  Streaming: {csv_path.name} ({corpus_name})...")
    class_collected = {k: 0 for k in target_classes_dict}
    rows = []
    chunk_idx = 0

    for chunk in pd.read_csv(csv_path, chunksize=chunksize, encoding='utf-8', encoding_errors='ignore', low_memory=False):
        chunk_idx += 1
        std_chunk = standardize_df(chunk, mapping, corpus_name)

        for _, row in std_chunk.iterrows():
            lbl = row["ground_truth_label"]
            if lbl not in class_collected:
                continue
            if class_collected[lbl] >= target_classes_dict[lbl]:
                continue

            # Strict holdout exclusion
            r_str = ",".join(f"{float(row[k]):.4f}" for k in sorted(FEATURE_NAMES))
            r_hash = hashlib.md5(r_str.encode("utf-8")).hexdigest()
            if r_hash in holdout_hashes:
                continue

            class_collected[lbl] += 1
            rows.append(row)

        if all(class_collected[k] >= target_classes_dict[k] for k in target_classes_dict):
            print(f"    Reached all quotas after chunk {chunk_idx}: {class_collected}")
            break

    print(f"    Finished {csv_path.name}: collected {class_collected} (Total rows: {len(rows)})")
    return pd.DataFrame(rows) if rows else pd.DataFrame()


def main():
    print("=" * 80)
    print("SENTINELAI GATE-1: BUILDING CANDIDATE V2 FIXED MODEL")
    print("=" * 80)

    # 1. Index Holdout Hashes
    print("\n[STEP 1] Indexing Sealed Holdout Row Hashes...")
    holdout_hashes = index_holdout_hashes()
    print(f"  Indexed {len(holdout_hashes)} unique row hashes across sealed holdouts.")

    # 2. Extract Multi-Corpus Partitions with Pipeline Fixes
    print("\n[STEP 2] Extracting Multi-Corpus Training Partitions with Robust Traversal...")
    dfs = []

    # 2.1 2017 Sources
    f2017_specs = [
        ("Monday-WorkingHours.pcap_ISCX.csv", {"BENIGN": 20000}),
        ("Tuesday-WorkingHours.pcap_ISCX.csv", {"SSH Brute Force": 8000, "Credential Stuffing": 8000}),
        ("Wednesday-workingHours.pcap_ISCX.csv", {"DDoS": 12000}),
        ("Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv", {"XSS Attempt": 600, "SQL Injection": 60, "Credential Stuffing": 1500}),
        ("Friday-WorkingHours-Morning.pcap_ISCX.csv", {"Malware Beacon": 3000}),
        ("Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv", {"Port Scan": 15000, "BENIGN": 5000}),
        ("Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv", {"DDoS": 15000, "BENIGN": 5000}),
    ]
    for fn, quotas in f2017_specs:
        p = CIC2017_DIR / fn
        if p.exists():
            df_part = extract_chunks_robust(p, FEATURE_MAPPING_2017, "CICIDS2017", quotas, holdout_hashes)
            if not df_part.empty:
                dfs.append(df_part)

    # 2.2 2018 Sources (Fixed Ingestion & Complete Traversal)
    f2018_specs = [
        # Wednesday 14-02: SSH & FTP
        ("Wednesday-14-02-2018_TrafficForML_CICFlowMeter.csv", {"SSH Brute Force": 10000, "Credential Stuffing": 10000, "BENIGN": 15000}),
        # Thursday 15-02: DoS
        ("Thursday-15-02-2018_TrafficForML_CICFlowMeter.csv", {"DDoS": 10000, "BENIGN": 15000}),
        # Wednesday 21-02: HOIC & LOIC-UDP (Omitted File FIX)
        ("Wednesday-21-02-2018_TrafficForML_CICFlowMeter.csv", {"DDoS": 15000, "BENIGN": 15000}),
        # Thursday 01-03: Infiltration (Early-Exit FIX)
        ("Thursday-01-03-2018_TrafficForML_CICFlowMeter.csv", {"Lateral Movement": 4000, "BENIGN": 15000}),
        # Friday 02-03: Bot
        ("Friday-02-03-2018_TrafficForML_CICFlowMeter.csv", {"Malware Beacon": 10000, "BENIGN": 15000}),
        # Friday 23-02: Web Attacks & Benign
        ("Friday-23-02-2018_TrafficForML_CICFlowMeter.csv", {"Credential Stuffing": 300, "XSS Attempt": 150, "SQL Injection": 50, "BENIGN": 15000}),
    ]
    for fn, quotas in f2018_specs:
        p = CSE2018_DIR / fn
        if p.exists():
            df_part = extract_chunks_robust(p, FEATURE_MAPPING_2018, "CSE-CIC-IDS2018", quotas, holdout_hashes)
            if not df_part.empty:
                dfs.append(df_part)

    train_all = pd.concat(dfs, ignore_index=True)
    print(f"\nFinal Assembled V2 Training Partition: {len(train_all)} rows across {train_all['ground_truth_label'].nunique()} classes")
    print(f"Class Breakdown:\n{train_all['ground_truth_label'].value_counts()}")

    # 3. Verify Strict Leakage Invariants
    print("\n[STEP 3] Verifying Strict Holdout Exclusion (Zero Overlap)...")
    overlap_count = 0
    for _, r in train_all[FEATURE_NAMES].iterrows():
        r_str = ",".join(f"{float(r[k]):.4f}" for k in sorted(FEATURE_NAMES))
        if hashlib.md5(r_str.encode("utf-8")).hexdigest() in holdout_hashes:
            overlap_count += 1
    print(f"Overlap check result: {overlap_count} overlapping rows.")
    assert overlap_count == 0, "FATAL LEAKAGE: Training set overlaps with sealed holdout!"
    print("CONFIRMED: ZERO LEAKAGE between V2 training partition and sealed holdout.")

    # Save V2 training partition parquet in experiments dir
    v2_train_parquet = PHASE10_DIR / "partition_train_multicorpus_v2.parquet"
    train_all.to_parquet(v2_train_parquet, index=False)
    print(f"Saved partition to: {v2_train_parquet.name}")

    # 4. Train Candidate V2 Model
    print("\n[STEP 4] Training Candidate V2 Model (candidate_rf_multicorpus_v2_fixed.pkl)...")
    X_tr, feats = transform_to_schema_f(train_all)
    y_tr = train_all["target_class"].values.astype(int)

    v2_pipe = Pipeline([
        ("scaler", StandardScaler()),
        ("rf", RandomForestClassifier(
            n_estimators=100, max_depth=12, min_samples_leaf=20, min_samples_split=20, random_state=42, n_jobs=-1
        ))
    ])
    t0 = time.perf_counter()
    v2_pipe.fit(X_tr, y_tr)
    fit_time = time.perf_counter() - t0
    print(f"Model fit completed in {fit_time:.2f}s")
    rf = v2_pipe.named_steps["rf"]
    print(f"Trained Classes: {rf.classes_}")
    print(f"Class Names: {[LABEL_NAMES.get(c, str(c)) for c in rf.classes_]}")
    assert 9 in rf.classes_, "FAILED: Class 9 (Lateral Movement) is missing from trained model!"
    assert 4 in rf.classes_, "FAILED: Class 4 (DDoS) is missing from trained model!"

    # Save to isolated disposable candidate location ONLY
    v2_cand_path = PHASE10_DIR / "candidate_rf_multicorpus_v2_fixed.pkl"
    joblib.dump(v2_pipe, v2_cand_path)
    v2_hash = hashlib.sha256(open(v2_cand_path, "rb").read()).hexdigest().upper()
    print(f"Saved Candidate V2 to: {v2_cand_path.name}")
    print(f"Candidate V2 SHA-256: {v2_hash}")

    # 5. Evaluate Candidate V2 on Sealed Holdout Sets
    print("\n[STEP 5] Evaluating Candidate V2 Model on Sealed Holdouts...")
    
    # 5.1 Large-Scale Benign FPR
    df_benign = pd.read_parquet(HOLDOUT_DIR / "holdout_benign_30k.parquet")
    X_b, _ = transform_to_schema_f(df_benign)
    probas_b = v2_pipe.predict_proba(X_b)
    preds_b = v2_pipe.predict(X_b)
    max_p_b = np.max(probas_b, axis=1)
    fp_mask = (preds_b != 0) & (max_p_b >= 0.70)
    fp_cnt = int(np.sum(fp_mask))
    fpr = fp_cnt / len(df_benign)
    print(f"\n--- Benign 30k Holdout ---")
    print(f"Total: {len(df_benign)}, False Positives: {fp_cnt}, FPR: {fpr*100:.4f}% (Target: <= 0.10%)")
    if fp_cnt > 0:
        from collections import Counter
        fp_classes = Counter([LABEL_NAMES.get(int(c), str(c)) for c in preds_b[fp_mask]])
        print(f"FP Breakdown by Predicted Class: {dict(fp_classes)}")

    # 5.2 Attacks
    attack_slices = [
        ("holdout_ddos.parquet", "DDoS HOIC & LOIC-UDP", "DDoS", 0.80),
        ("holdout_infiltration.parquet", "Infiltration", "Lateral Movement", 0.70),
        ("holdout_bruteforce_ssh_ftp.parquet", "SSH Brute Force", "SSH Brute Force", 0.80),
        ("holdout_botnet.parquet", "Botnet Ares", "Malware Beacon", 0.75),
        ("holdout_web_attacks.parquet", "Web Attacks", ["Credential Stuffing", "XSS Attempt", "SQL Injection"], 0.80)
    ]

    metrics = {
        "benign_fpr": {
            "total": len(df_benign),
            "fp": fp_cnt,
            "fpr": round(fpr, 6),
            "status": "PASS" if fpr <= 0.001 else "FAIL"
        },
        "attacks": {}
    }

    for fn, desc, target_lbl, target_recall in attack_slices:
        df_h = pd.read_parquet(HOLDOUT_DIR / fn)
        if isinstance(target_lbl, list):
            df_att = df_h[df_h["ground_truth_label"].isin(target_lbl)].copy()
        else:
            df_att = df_h[df_h["ground_truth_label"] == target_lbl].copy()

        n_att = len(df_att)
        X_att, _ = transform_to_schema_f(df_att)
        probas_att = v2_pipe.predict_proba(X_att)
        preds_att = v2_pipe.predict(X_att)
        max_p_att = np.max(probas_att, axis=1)

        det_mask = (preds_att != 0) & (max_p_att >= 0.70)
        tp = int(np.sum(det_mask))
        recall = tp / max(1, n_att)

        print(f"\n--- {desc} ({fn}) ---")
        print(f"Total: {n_att}, Detected: {tp}, Recall: {recall*100:.2f}% (Target: {target_recall*100:.1f}%)")
        print(f"Status: {'PASS' if recall >= target_recall else 'FAIL'}")

        metrics["attacks"][desc] = {
            "total": n_att,
            "tp": tp,
            "recall": round(recall, 4),
            "target": target_recall,
            "status": "PASS" if recall >= target_recall else "FAIL"
        }

    # Save metrics JSON
    metrics_path = PHASE10_DIR / "candidate_v2_evaluation_metrics.json"
    with open(metrics_path, "w", encoding="utf-8") as f:
        json.dump(metrics, f, indent=2)
    print(f"\nSaved metrics to: {metrics_path.name}")

if __name__ == "__main__":
    main()
