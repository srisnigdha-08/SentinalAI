#!/usr/bin/env python3
"""
SentinelAI Phase 10: Isolated Disposable Training and Offline Modular Harness Evaluation
Location: ai-engine/experiments/gate1_phase10_detector_recovery/run_phase10_experiment.py
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
    standardize_df, compute_wilson
)
from modular.volumetric_flood import VolumetricFloodDetector
from modular.auth_abuse import AuthAbuseDetector
from modular.layer7_waf import Layer7WAFDetector
from modular.orchestrator import ModularOrchestrator
from modular.contracts import DetectorStatus, PolicyDecision

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


def extract_with_bugfix(csv_path, mapping, corpus_name, target_classes_dict, holdout_hashes, max_per_class=10000):
    """
    Fixed extractor: does NOT break prematurely when only one class reaches max.
    Only breaks when all classes specified in target_classes_dict have reached their quota.
    """
    print(f"  Streaming: {csv_path.name} ({corpus_name})...")
    class_collected = {k: 0 for k in target_classes_dict}
    rows = []
    
    for chunk in pd.read_csv(csv_path, chunksize=25000, encoding='utf-8', encoding_errors='ignore', low_memory=False):
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
            print(f"    Reached quota for all targets: {class_collected}")
            break
            
    print(f"    Finished extraction: {class_collected} (Total rows: {len(rows)})")
    return pd.DataFrame(rows) if rows else pd.DataFrame()


def main():
    print("=" * 80)
    print("SENTINELAI PHASE 10: DISPOSABLE TRAINING & EMPIRICAL RECOVERY EVALUATION")
    print("=" * 80)

    # 1. Index Holdout Hashes
    print("\n[STEP 1] Indexing Sealed Holdout Row Hashes...")
    holdout_hashes = index_holdout_hashes()
    print(f"  Indexed {len(holdout_hashes)} unique row hashes across sealed holdouts.")

    # 2. Extract Data with Ingestion Bugfixes
    print("\n[STEP 2] Extracting Training Partitions with Ingestion Fixes...")
    dfs = []
    
    # 2.1 CSE-2018 Wednesday 14-02: FTP & SSH Brute Force
    p14 = CSE2018_DIR / "Wednesday-14-02-2018_TrafficForML_CICFlowMeter.csv"
    if p14.exists():
        df14 = extract_with_bugfix(p14, FEATURE_MAPPING_2018, "CSE-2018", 
                                   {"Credential Stuffing": 8000, "SSH Brute Force": 8000, "BENIGN": 15000}, 
                                   holdout_hashes)
        if not df14.empty: dfs.append(df14)

    # 2.2 CSE-2018 Thursday 15-02: DoS GoldenEye & Slowloris
    p15 = CSE2018_DIR / "Thursday-15-02-2018_TrafficForML_CICFlowMeter.csv"
    if p15.exists():
        df15 = extract_with_bugfix(p15, FEATURE_MAPPING_2018, "CSE-2018",
                                   {"DDoS": 8000, "BENIGN": 10000},
                                   holdout_hashes)
        if not df15.empty: dfs.append(df15)

    # 2.3 CSE-2018 Wednesday 21-02: FIX 1 - Include HOIC & LOIC-UDP DDoS
    p21 = CSE2018_DIR / "Wednesday-21-02-2018_TrafficForML_CICFlowMeter.csv"
    if p21.exists():
        df21 = extract_with_bugfix(p21, FEATURE_MAPPING_2018, "CSE-2018",
                                   {"DDoS": 12000, "BENIGN": 5000},
                                   holdout_hashes)
        if not df21.empty: dfs.append(df21)

    # 2.4 CSE-2018 Thursday 01-03: FIX 2 - Infiltration without early-break bug
    p01 = CSE2018_DIR / "Thursday-01-03-2018_TrafficForML_CICFlowMeter.csv"
    if p01.exists():
        df01 = extract_with_bugfix(p01, FEATURE_MAPPING_2018, "CSE-2018",
                                   {"Lateral Movement": 8000, "BENIGN": 5000},
                                   holdout_hashes)
        if not df01.empty: dfs.append(df01)

    # 2.5 CSE-2018 Friday 02-03: Bot
    p02 = CSE2018_DIR / "Friday-02-03-2018_TrafficForML_CICFlowMeter.csv"
    if p02.exists():
        df02 = extract_with_bugfix(p02, FEATURE_MAPPING_2018, "CSE-2018",
                                   {"Malware Beacon": 8000, "BENIGN": 5000},
                                   holdout_hashes)
        if not df02.empty: dfs.append(df02)

    # 2.6 CICIDS2017 Friday PortScan & Friday DDoS
    p_ps = CIC2017_DIR / "Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv"
    if p_ps.exists():
        df_ps = extract_with_bugfix(p_ps, FEATURE_MAPPING_2017, "CIC2017",
                                   {"Port Scan": 10000, "BENIGN": 5000},
                                   holdout_hashes)
        if not df_ps.empty: dfs.append(df_ps)

    # 2.7 CICIDS2017 Web Attacks & SQLi
    p_web = CIC2017_DIR / "Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv"
    if p_web.exists():
        df_web = extract_with_bugfix(p_web, FEATURE_MAPPING_2017, "CIC2017",
                                    {"XSS Attempt": 500, "SQL Injection": 50, "Credential Stuffing": 1000},
                                    holdout_hashes)
        if not df_web.empty: dfs.append(df_web)

    train_df = pd.concat(dfs, ignore_index=True)
    print(f"\nFinal Assembled Disposable Training Partition: {len(train_df)} rows")
    print(f"Class Breakdown:\n{train_df['ground_truth_label'].value_counts()}")

    # Verify zero holdout overlap
    overlap_count = 0
    for _, r in train_df[FEATURE_NAMES].iterrows():
        r_str = ",".join(f"{float(r[k]):.4f}" for k in sorted(FEATURE_NAMES))
        if hashlib.md5(r_str.encode("utf-8")).hexdigest() in holdout_hashes:
            overlap_count += 1
    print(f"\nHoldout Overlap Check: {overlap_count} overlapping rows. (Invariance: MUST BE 0)")
    assert overlap_count == 0, "FATAL: Overlap detected with sealed holdout!"

    # 3. Train Disposable Candidate Model
    print("\n[STEP 3] Training Disposable Candidate Model (disposable_rf_phase10_v1.pkl)...")
    X_tr, feats = transform_to_schema_f(train_df)
    y_tr = train_df["target_class"].values.astype(int)

    disposable_pipe = Pipeline([
        ("scaler", StandardScaler()),
        ("rf", RandomForestClassifier(
            n_estimators=100, max_depth=12, min_samples_leaf=20, min_samples_split=20, random_state=42, n_jobs=-1
        ))
    ])
    t0 = time.perf_counter()
    disposable_pipe.fit(X_tr, y_tr)
    fit_time = time.perf_counter() - t0
    print(f"  Model fit completed in {fit_time:.2f}s")
    print(f"  Trained Classes: {disposable_pipe.named_steps['rf'].classes_}")
    print(f"  Class Names: {[LABEL_NAMES.get(c, str(c)) for c in disposable_pipe.named_steps['rf'].classes_]}")

    # Save to isolated disposable directory ONLY (never to models/ or phase 8)
    disp_path = PHASE10_DIR / "disposable_rf_phase10_v1.pkl"
    joblib.dump(disposable_pipe, disp_path)
    disp_hash = hashlib.sha256(open(disp_path, "rb").read()).hexdigest().upper()
    print(f"  Saved disposable model to: {disp_path.name} (SHA-256: {disp_hash[:16]}...)")

    # 4. Evaluate on Sealed Holdout Sets
    print("\n[STEP 4] Evaluating Disposable Model on Sealed Holdout Sets...")
    slices_to_eval = [
        ("holdout_benign_30k.parquet", "Large-Scale Benign (N=30,000)", None),
        ("holdout_bruteforce_ssh_ftp.parquet", "SSH & FTP Brute Force", ["SSH-Bruteforce", "FTP-BruteForce"]),
        ("holdout_botnet.parquet", "Botnet (Malware Beacon)", ["Bot"]),
        ("holdout_ddos.parquet", "DDoS / DoS (HOIC & LOIC-UDP)", ["DDOS attack-HOIC", "DDOS attack-LOIC-UDP"]),
        ("holdout_infiltration.parquet", "Infiltration", ["Infilteration"]),
        ("holdout_web_attacks.parquet", "Web Attacks (Transport ML)", ["Brute Force -Web", "Brute Force -XSS", "SQL Injection"])
    ]

    eval_results = {}

    for fn, desc, attack_subtypes in slices_to_eval:
        print(f"\n--- Evaluating {desc} ({fn}) ---")
        df_h = pd.read_parquet(HOLDOUT_DIR / fn)
        X_h, _ = transform_to_schema_f(df_h)
        probas_h = disposable_pipe.predict_proba(X_h)
        preds_h = disposable_pipe.predict(X_h)
        max_ps_h = np.max(probas_h, axis=1)

        is_att = df_h["is_attack"].values.astype(bool) if "is_attack" in df_h.columns else np.zeros(len(df_h), dtype=bool)
        n_total = len(df_h)

        if fn == "holdout_benign_30k.parquet":
            # Benign FPR evaluation
            fp_alert = 0
            fp_block = 0
            for i in range(n_total):
                c_idx = int(preds_h[i])
                cname = LABEL_NAMES.get(c_idx, "BENIGN")
                pval = float(max_ps_h[i])
                if cname != "BENIGN" and pval >= 0.70:
                    fp_alert += 1
                if cname != "BENIGN" and pval >= 0.85:
                    fp_block += 1
            fpr_alert = fp_alert / n_total
            w_l, w_u = compute_wilson(fp_alert, n_total)
            print(f"  Benign Flows: {n_total}, Alert FPs: {fp_alert} (FPR: {fpr_alert*100:.4f}%, Wilson 95%: [{w_l*100:.4f}%, {w_u*100:.4f}%])")
            eval_results["benign_fpr"] = {
                "sample_size": n_total,
                "fp_count": fp_alert,
                "fpr": round(fpr_alert, 6),
                "wilson_ci": [round(w_l, 6), round(w_u, 6)],
                "pass_gate1": (fpr_alert < 0.0010 and w_u < 0.0010)
            }
        else:
            # Attack recall evaluation
            n_attacks = int(np.sum(is_att))
            tp = 0
            fn_cnt = 0
            sub_results = {}

            gt_raw = df_h["ground_truth_raw"].values if "ground_truth_raw" in df_h.columns else df_h["ground_truth_label"].values

            for i in range(n_total):
                if not is_att[i]:
                    continue
                raw_lbl = str(gt_raw[i])
                c_idx = int(preds_h[i])
                cname = LABEL_NAMES.get(c_idx, "BENIGN")
                pval = float(max_ps_h[i])
                is_detected = (cname != "BENIGN" and pval >= 0.70)

                if raw_lbl not in sub_results:
                    sub_results[raw_lbl] = {"total": 0, "detected": 0}
                sub_results[raw_lbl]["total"] += 1
                if is_detected:
                    sub_results[raw_lbl]["detected"] += 1
                    tp += 1
                else:
                    fn_cnt += 1

            rec = tp / max(n_attacks, 1)
            w_l, w_u = compute_wilson(tp, n_attacks)
            print(f"  Total Attacks: {n_attacks}, TP: {tp}, FN: {fn_cnt}, Recall: {rec*100:.2f}% (Wilson 95%: [{w_l*100:.2f}%, {w_u*100:.2f}%])")
            for sub_k, sub_v in sub_results.items():
                s_rec = sub_v["detected"] / max(sub_v["total"], 1)
                print(f"    - {sub_k}: {sub_v['detected']}/{sub_v['total']} ({s_rec*100:.2f}%)")

            eval_results[fn] = {
                "description": desc,
                "total_attacks": n_attacks,
                "tp": tp, "fn": fn_cnt,
                "recall": round(rec, 4),
                "wilson_ci": [round(w_l, 6), round(w_u, 6)],
                "subtypes": sub_results
            }

    # 5. Offline Modular Harness Demonstration
    print("\n[STEP 5] Testing Offline Modular Multi-Tier Orchestrator Harness...")
    orchestrator = ModularOrchestrator(
        detector_timeout_seconds=0.1,
        max_threads=4,
        max_pending_tasks=16
    )
    orchestrator.register_detector(VolumetricFloodDetector())
    orchestrator.register_detector(AuthAbuseDetector())
    orchestrator.register_detector(Layer7WAFDetector())

    harness_results = {
        "ssh_surge_test": None,
        "hoic_surge_test": None,
        "waf_exploit_test": None
    }

    # 5.1 Test Auth Abuse Detector under rapid SSH attempts
    print("  Testing AuthAbuseDetector with 10 sequential SSH connections from an attacker IP...")
    attacker_ip = "192.168.10.50"
    victim_ip = "192.168.10.10"
    decisions = []
    for sec in range(10):
        flow = {
            "source_ip": attacker_ip, "destination_ip": victim_ip, "destination_port": 22, "protocol": 6,
            "packets": 2, "bytes": 120, "flow_duration": 0.0001, "timestamp": 1000.0 + sec
        }
        res = orchestrator.evaluate_shadow(flow, force_shadow=True)
        decisions.append(res.overall_decision.value if res else "NONE")
    harness_results["ssh_surge_test"] = {
        "final_decision": decisions[-1],
        "decision_sequence": decisions
    }
    print(f"    Sequence: {decisions[:3]} ... {decisions[-3:]} -> Final Decision: {decisions[-1]}")

    # 5.2 Test Layer 7 WAF Detector with SQLi payload
    print("  Testing Layer7WAFDetector with SQL Injection payload...")
    sqli_flow = {
        "source_ip": "203.0.113.45", "destination_ip": "192.168.10.80", "destination_port": 80, "protocol": 6,
        "http_uri": "/api/user?id=1%20UNION%20SELECT%20null%2Cusername%2Cpassword%20FROM%20users--",
        "http_headers": "Host: internal.corp\r\nUser-Agent: sqlmap/1.4"
    }
    waf_res = orchestrator.evaluate_shadow(sqli_flow, force_shadow=True)
    if waf_res:
        det_res = waf_res.detector_results.get("layer7_waf")
        harness_results["waf_exploit_test"] = {
            "overall_decision": waf_res.overall_decision.value,
            "waf_decision": det_res.decision.value if det_res else "NONE",
            "waf_confidence": det_res.confidence if det_res else 0.0,
            "simulated_block": waf_res.simulated_block
        }
        print(f"    WAF Overall Decision: {waf_res.overall_decision.value}, Simulated Block: {waf_res.simulated_block}")
    else:
        print("    WAF evaluate_shadow returned None")

    # 5.3 Test Volumetric Flood Detector with high-rate packet flood
    print("  Testing VolumetricFloodDetector with high-rate flood (12,000 pps)...")
    vol_flow = {
        "source_ip": "198.51.100.99", "destination_ip": "192.168.10.80", "destination_port": 80, "protocol": 6,
        "packets": 12000, "bytes": 8_000_000, "flow_duration": 1.0,
        "flow_packets_per_sec": 12000.0, "flow_bytes_per_sec": 8_000_000.0, "timestamp": 2000.0
    }
    vol_res = orchestrator.evaluate_shadow(vol_flow, force_shadow=True)
    if vol_res:
        vol_det = vol_res.detector_results.get("volumetric_flood")
        harness_results["hoic_surge_test"] = {
            "overall_decision": vol_res.overall_decision.value,
            "vol_decision": vol_det.decision.value if vol_det else "NONE",
            "vol_confidence": vol_det.confidence if vol_det else 0.0,
            "simulated_block": vol_res.simulated_block
        }
        print(f"    Volumetric Decision: {vol_res.overall_decision.value}, Simulated Block: {vol_res.simulated_block}")
    else:
        print("    Volumetric evaluate_shadow returned None")

    orchestrator.shutdown()

    # Save complete evaluation output
    full_output = {
        "disposable_model_hash": disp_hash,
        "disposable_eval_results": eval_results,
        "modular_offline_harness": harness_results
    }
    out_json = PHASE10_DIR / "phase10_recovery_metrics.json"
    with open(out_json, "w", encoding="utf-8") as f:
        json.dump(full_output, f, indent=2)
    print(f"\nPhase 10 Evaluation Output successfully saved to: {out_json}")


if __name__ == "__main__":
    main()
