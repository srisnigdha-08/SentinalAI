#!/usr/bin/env python3
"""
SentinelAI — GATE-1 Phase 3B Reconciliation: Threshold Decision Matrix Generator
Location: ai-engine/experiments/gate1_phase3b_reconciliation/generate_threshold_decision_matrix.py

Computes per-attack confusion matrices, ALLOW/MONITOR/simulated BLOCK counts,
and FPR/Recall trade-offs across confidence qualification thresholds:
tau in [0.60, 0.70, 0.75, 0.80, 0.85, 0.90, 0.92].

Outputs:
ai-engine/experiments/gate1_phase3b_reconciliation/threshold_decision_matrix.csv
"""

import sys
import os
import csv
from pathlib import Path
import numpy as np
import pandas as pd

CURRENT_DIR = Path(__file__).resolve().parent
AI_ENGINE_DIR = CURRENT_DIR.parent.parent
PHASE3A_DIR = CURRENT_DIR.parent / "gate1_phase3a_remediation"
PHASE3B_DIR = CURRENT_DIR.parent / "gate1_phase3b_sensitivity"

sys.path.insert(0, str(AI_ENGINE_DIR))
sys.path.insert(0, str(PHASE3A_DIR))
sys.path.insert(0, str(PHASE3B_DIR))

from candidate_policy import CandidateSentinelPolicy, calculate_if_anomaly_signal, ANOMALY_THRESHOLD, BLOCK_THRESHOLD
from utils.features import LABEL_NAMES
from evaluate_multi_attack_sensitivity import load_slice, normalize_label

def main():
    data_dir = AI_ENGINE_DIR / "datasets" / "cicids2017"
    
    # Pre-load datasets
    print("Loading datasets for threshold decision matrix generation...")
    datasets = {}
    
    # 1. PortScan
    f_ps = data_dir / "Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv"
    if f_ps.exists():
        datasets["PortScan"] = load_slice(f_ps, "PortScan", offset=30000, max_attack=1000, max_benign=1000)

    # 2. DDoS
    f_ddos = data_dir / "Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv"
    if f_ddos.exists():
        datasets["DDoS"] = load_slice(f_ddos, "DDoS", offset=30000, max_attack=1000, max_benign=1000)

    # 3. SSH Brute Force
    f_tue = data_dir / "Tuesday-WorkingHours.pcap_ISCX.csv"
    if f_tue.exists():
        datasets["SSH_BruteForce"] = load_slice(f_tue, "SSH-Patator", offset=0, max_attack=1000, max_benign=1000)

    # 4. Web Attacks
    f_web = data_dir / "Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv"
    if f_web.exists():
        datasets["Web_Attacks"] = load_slice(f_web, lambda l: "web attack" in str(l).lower(), offset=0, max_attack=1000, max_benign=1000, encoding="cp1252")

    # 5. Infiltration
    f_inf = data_dir / "Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv"
    if f_inf.exists():
        datasets["Infiltration"] = load_slice(f_inf, "Infiltration", offset=0, max_attack=1000, max_benign=1000)

    # 6. Botnet
    f_bot = data_dir / "Friday-WorkingHours-Morning.pcap_ISCX.csv"
    if f_bot.exists():
        datasets["Botnet"] = load_slice(f_bot, "Bot", offset=0, max_attack=1000, max_benign=1000)

    # 7. DoS Hulk
    f_wed = data_dir / "Wednesday-workingHours.pcap_ISCX.csv"
    if f_wed.exists():
        datasets["DoS_Hulk"] = load_slice(f_wed, "DoS Hulk", offset=30000, max_attack=1000, max_benign=1000)

    # 8. Monday Pure Benign
    f_mon = data_dir / "Monday-WorkingHours.pcap_ISCX.csv"
    if f_mon.exists():
        datasets["Monday_Benign"] = load_slice(f_mon, "NON_EXISTENT", offset=0, max_attack=0, max_benign=10000)

    from inference.predictor import SentinelPredictor
    from utils.features import extract_features_from_record
    predictor = SentinelPredictor()

    cached_inference = {}
    print("Performing feature extraction and model inference once across all datasets...")
    for dname, df in datasets.items():
        l_col = next((c for c in df.columns if "label" in c.lower()), "Label")
        y_is_attack = np.array([normalize_label(x).upper() != "BENIGN" for x in df[l_col]], dtype=bool)
        
        recs = df.to_dict(orient="records")
        X = np.vstack([extract_features_from_record(r) for r in recs])
        probas = predictor.rf.predict_proba(X)
        classes = predictor.rf.predict(X)
        max_ps = np.max(probas, axis=1)
        X_scaled = predictor.ifo.named_steps["scaler"].transform(X)
        if_scores = predictor.ifo.named_steps["if"].score_samples(X_scaled)
        
        cached_inference[dname] = {
            "y_is_attack": y_is_attack,
            "classes": classes,
            "max_ps": max_ps,
            "if_scores": if_scores,
            "total_pos": int(np.sum(y_is_attack)),
            "total_neg": int(np.sum(~y_is_attack)),
        }

    thresholds = [0.60, 0.70, 0.75, 0.80, 0.85, 0.90, 0.92]
    rows = []

    print("Sweeping thresholds and generating decision matrix...")
    for tau in thresholds:
        pol = CandidateSentinelPolicy(
            block_threshold=0.92,
            monitor_threshold=min(tau, 0.70),
            experimental_confidence_threshold=tau
        )
        
        for dname, cache in cached_inference.items():
            y_is_attack = cache["y_is_attack"]
            classes = cache["classes"]
            max_ps = cache["max_ps"]
            if_scores = cache["if_scores"]
            n_pos = cache["total_pos"]
            n_neg = cache["total_neg"]
            
            actions = []
            for i in range(len(y_is_attack)):
                raw_c = LABEL_NAMES.get(int(classes[i]), "BENIGN")
                p = float(max_ps[i])
                s_if = float(if_scores[i])
                sig = calculate_if_anomaly_signal(s_if)
                is_ano = bool(s_if < ANOMALY_THRESHOLD)
                
                res = pol.evaluate_signals(raw_c, p, is_ano, sig, s_if)
                actions.append(res["action"])
                
            act_arr = np.array(actions)
            
            # Policy Containment Action (MONITOR or BLOCK)
            c_pos = (act_arr == "MONITOR") | (act_arr == "BLOCK")
            tp = int(np.sum(c_pos & y_is_attack))
            fp = int(np.sum(c_pos & ~y_is_attack))
            tn = int(np.sum(~c_pos & ~y_is_attack))
            fn = int(np.sum(~c_pos & y_is_attack))
            
            rec = tp / n_pos if n_pos > 0 else 0.0
            fpr = fp / n_neg if n_neg > 0 else 0.0
            
            # Simulated Block Decision
            b_pos = (act_arr == "BLOCK")
            b_tp = int(np.sum(b_pos & y_is_attack))
            b_fp = int(np.sum(b_pos & ~y_is_attack))
            b_tn = int(np.sum(~b_pos & ~y_is_attack))
            b_fn = int(np.sum(~b_pos & y_is_attack))
            
            b_rec = b_tp / n_pos if n_pos > 0 else 0.0
            b_fpr = b_fp / n_neg if n_neg > 0 else 0.0
            
            allowed_attacks = fn
            allowed_benign = tn
            
            rows.append({
                "threshold_tau": tau,
                "category": dname,
                "total_flows": len(y_is_attack),
                "attack_flows": n_pos,
                "benign_flows": n_neg,
                "TN": tn,
                "FP": fp,
                "FN": fn,
                "TP": tp,
                "policy_recall": round(rec, 5),
                "policy_fpr": round(fpr, 5),
                "sim_block_TN": b_tn,
                "sim_block_FP": b_fp,
                "sim_block_FN": b_fn,
                "sim_block_TP": b_tp,
                "sim_block_recall": round(b_rec, 5),
                "sim_block_fpr": round(b_fpr, 5),
                "allowed_attacks": allowed_attacks,
                "allowed_benign": allowed_benign,
                "allow_count": int(np.sum(act_arr == "ALLOW")),
                "monitor_count": int(np.sum(act_arr == "MONITOR")),
                "block_count": int(np.sum(act_arr == "BLOCK")),
            })

    out_csv = CURRENT_DIR / "threshold_decision_matrix.csv"
    df_out = pd.DataFrame(rows)
    df_out.to_csv(out_csv, index=False)
    print(f"\n[SUCCESS] Threshold decision matrix written to:\n  {out_csv}")
    print(f"Total rows generated: {len(df_out)}")

if __name__ == "__main__":
    main()
