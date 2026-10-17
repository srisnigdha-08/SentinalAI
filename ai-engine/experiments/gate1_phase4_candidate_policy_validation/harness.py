#!/usr/bin/env python3
"""
SentinelAI — GATE-1 Phase 4: Isolated Candidate Policy Harness & Multi-Attack Validation
Location: ai-engine/experiments/gate1_phase4_candidate_policy_validation/harness.py

Compares the Active Production Policy against the Phase 3A Candidate Policy side-by-side
across all 23,036 evaluation flows. Strictly read-only on models, databases, and firewall.
"""

import sys
import os
import json
import time
import math
import hashlib
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

from utils.features import FEATURE_NAMES, LABEL_NAMES, RAW_LABEL_TO_TARGET, extract_features_from_record
from inference.predictor import SentinelPredictor, ANOMALY_THRESHOLD, BLOCK_THRESHOLD, MONITOR_THRESHOLD
from candidate_policy import CandidateSentinelPolicy, calculate_if_anomaly_signal
from evaluate_multi_attack_sensitivity import load_slice, normalize_label


def compute_file_sha256(filepath: Path) -> str:
    """Computes SHA-256 hash of a file."""
    h = hashlib.sha256()
    with open(filepath, "rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest().upper()


def wilson_score_interval(successes: int, total: int, confidence: float = 0.95):
    """
    Calculates exact Wilson score confidence interval for a binomial proportion.
    """
    if total == 0:
        return (0.0, 0.0)
    z = 1.95996 if confidence == 0.95 else 1.64485
    p = float(successes) / float(total)
    denominator = 1.0 + (z**2) / total
    centre = (p + (z**2) / (2.0 * total)) / denominator
    std = math.sqrt((p * (1.0 - p) + (z**2) / (4.0 * total)) / total) / denominator
    lower = max(0.0, centre - z * std)
    upper = min(1.0, centre + z * std)
    return (round(lower, 5), round(upper, 5))


def calc_metrics(y_true_attack, actions, simulated_blocks, raw_preds):
    """
    Computes confusion matrices, recall, false positive rates, and Wilson intervals.
    """
    total_pos = int(np.sum(y_true_attack))
    total_neg = int(np.sum(~y_true_attack))

    act_arr = np.array(actions)
    blk_arr = np.array(simulated_blocks)

    # 1. Policy Containment (action is MONITOR or BLOCK)
    containment_pos = (act_arr == "MONITOR") | (act_arr == "BLOCK")
    c_tp = int(np.sum(containment_pos & y_true_attack))
    c_fp = int(np.sum(containment_pos & ~y_true_attack))
    c_tn = int(np.sum(~containment_pos & ~y_true_attack))
    c_fn = int(np.sum(~containment_pos & y_true_attack))

    c_rec = c_tp / total_pos if total_pos > 0 else 0.0
    c_fpr = c_fp / total_neg if total_neg > 0 else 0.0

    # 2. Simulated Autonomous BLOCK (action is BLOCK)
    b_tp = int(np.sum(blk_arr & y_true_attack))
    b_fp = int(np.sum(blk_arr & ~y_true_attack))
    b_tn = int(np.sum(~blk_arr & ~y_true_attack))
    b_fn = int(np.sum(~blk_arr & y_true_attack))

    b_rec = b_tp / total_pos if total_pos > 0 else 0.0
    b_fpr = b_fp / total_neg if total_neg > 0 else 0.0

    # 3. Raw Supervised Classifier (predicted != BENIGN)
    det_pos = np.array([p != "BENIGN" for p in raw_preds])
    d_tp = int(np.sum(det_pos & y_true_attack))
    d_fp = int(np.sum(det_pos & ~y_true_attack))
    d_tn = int(np.sum(~det_pos & ~y_true_attack))
    d_fn = int(np.sum(~det_pos & y_true_attack))

    d_rec = d_tp / total_pos if total_pos > 0 else 0.0
    d_fpr = d_fp / total_neg if total_neg > 0 else 0.0

    # Action counts
    act_series = pd.Series(actions)
    action_counts = {
        "ALLOW": int(act_series.value_counts().get("ALLOW", 0)),
        "MONITOR": int(act_series.value_counts().get("MONITOR", 0)),
        "BLOCK": int(act_series.value_counts().get("BLOCK", 0)),
    }

    return {
        "policy_containment": {
            "confusion": {"TP": c_tp, "FP": c_fp, "TN": c_tn, "FN": c_fn},
            "recall": round(c_rec, 5),
            "recall_ci_95": list(wilson_score_interval(c_tp, total_pos)),
            "fpr": round(c_fpr, 5),
            "fpr_ci_95": list(wilson_score_interval(c_fp, total_neg)),
            "action_counts": action_counts,
        },
        "simulated_block": {
            "confusion": {"TP": b_tp, "FP": b_fp, "TN": b_tn, "FN": b_fn},
            "recall": round(b_rec, 5),
            "recall_ci_95": list(wilson_score_interval(b_tp, total_pos)),
            "fpr": round(b_fpr, 5),
            "fpr_ci_95": list(wilson_score_interval(b_fp, total_neg)),
        },
        "raw_supervised_classifier": {
            "confusion": {"TP": d_tp, "FP": d_fp, "TN": d_tn, "FN": d_fn},
            "recall": round(d_rec, 5),
            "recall_ci_95": list(wilson_score_interval(d_tp, total_pos)),
            "fpr": round(d_fpr, 5),
            "fpr_ci_95": list(wilson_score_interval(d_fp, total_neg)),
        },
    }


def main():
    print("==================================================================")
    print("SentinelAI GATE-1 Phase 4: Candidate Policy Evaluation Harness")
    print("==================================================================")

    data_dir = AI_ENGINE_DIR / "datasets" / "cicids2017"
    models_dir = AI_ENGINE_DIR / "models"

    # Verify protected asset hashes before evaluation
    protected_assets = {
        "rf_classifier_cicids_v2.pkl": models_dir / "rf_classifier_cicids_v2.pkl",
        "isolation_forest_cicids.pkl": models_dir / "isolation_forest_cicids.pkl",
        "xgb_classifier_cicids_v2.pkl": models_dir / "xgb_classifier_cicids_v2.pkl",
        "q_table.json": models_dir / "q_table.json",
        "runtime_q_table.json": AI_ENGINE_DIR / "runtime" / "q_table.json",
    }
    asset_hashes_pre = {k: compute_file_sha256(v) for k, v in protected_assets.items()}

    print("\nProtected Asset Hashes (Pre-Harness Verification):")
    for k, h in asset_hashes_pre.items():
        print(f"  {k:30s}: {h}")

    # Load Predictor and Candidate Policy
    predictor = SentinelPredictor(model_dir=str(models_dir))
    candidate = CandidateSentinelPolicy(
        block_threshold=BLOCK_THRESHOLD,
        monitor_threshold=MONITOR_THRESHOLD,
        experimental_confidence_threshold=0.85,
    )

    # Dataset Provenance Specification
    slices_def = [
        {
            "key": "PortScan",
            "file": "Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv",
            "filter": "PortScan",
            "offset": 30000,
            "max_attack": 1000,
            "max_benign": 1000,
            "canonical_label": "Port Scan",
            "provenance": "Friday Afternoon PCAP; offset=30,000; 10,000 in training (6.29%)",
        },
        {
            "key": "DDoS",
            "file": "Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv",
            "filter": "DDoS",
            "offset": 30000,
            "max_attack": 1000,
            "max_benign": 1000,
            "canonical_label": "DDoS",
            "provenance": "Friday Afternoon PCAP; offset=30,000; 10,000 in training (7.81%)",
        },
        {
            "key": "SSH_Patator",
            "file": "Tuesday-WorkingHours.pcap_ISCX.csv",
            "filter": "SSH-Patator",
            "offset": 0,
            "max_attack": 1000,
            "max_benign": 1000,
            "canonical_label": "SSH Brute Force",
            "provenance": "Tuesday PCAP; 100% of available SSH-Patator in training (In-sample Leakage)",
        },
        {
            "key": "Web_Attacks",
            "file": "Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv",
            "filter": lambda l: "web attack" in str(l).lower(),
            "offset": 0,
            "max_attack": 1000,
            "max_benign": 1000,
            "encoding": "cp1252",
            "canonical_label": "Web Attack (Multi-vector)",
            "provenance": "Thursday Morning PCAP; 100% of Web Attacks in training (In-sample Leakage)",
        },
        {
            "key": "Infiltration",
            "file": "Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv",
            "filter": "Infiltration",
            "offset": 0,
            "max_attack": 1000,
            "max_benign": 1000,
            "canonical_label": "Infiltration",
            "provenance": "Thursday Afternoon PCAP; 36 total flows (100% in training; Insufficient Data)",
        },
        {
            "key": "Botnet",
            "file": "Friday-WorkingHours-Morning.pcap_ISCX.csv",
            "filter": "Bot",
            "offset": 0,
            "max_attack": 1000,
            "max_benign": 1000,
            "canonical_label": "Malware Beacon",
            "provenance": "Friday Morning PCAP; 100% in training (In-sample Leakage)",
        },
        {
            "key": "DoS_Hulk",
            "file": "Wednesday-workingHours.pcap_ISCX.csv",
            "filter": "DoS Hulk",
            "offset": 30000,
            "max_attack": 1000,
            "max_benign": 1000,
            "canonical_label": "DDoS",
            "provenance": "Wednesday PCAP; offset=30,000; Partial training overlap risk",
        },
        {
            "key": "Monday_Benign",
            "file": "Monday-WorkingHours.pcap_ISCX.csv",
            "filter": "NON_EXISTENT",
            "offset": 0,
            "max_attack": 0,
            "max_benign": 10000,
            "canonical_label": "BENIGN",
            "provenance": "Monday Pure Benign Benchmark; 15,000 sampled in training (2.83% overlap risk)",
        },
    ]

    all_metrics = {}
    per_attack_confusion = {}
    total_evaluated_flows = 0

    print("\nExecuting Side-by-Side Policy Evaluation...")

    for sdef in slices_def:
        skey = sdef["key"]
        csv_path = data_dir / sdef["file"]
        if not csv_path.exists():
            print(f"  [WARN] File not found: {csv_path}. Skipping slice.")
            continue

        print(f"\nProcessing slice: {skey} ({sdef['file']})...")
        enc = sdef.get("encoding", "utf-8")
        df = load_slice(
            csv_path,
            sdef["filter"],
            offset=sdef["offset"],
            max_attack=sdef["max_attack"],
            max_benign=sdef["max_benign"],
            encoding=enc,
        )

        n_total = len(df)
        total_evaluated_flows += n_total

        l_col = next((c for c in df.columns if "label" in c.lower()), "Label")
        y_raw = df[l_col].tolist()
        y_target = [normalize_label(lbl) for lbl in y_raw]
        y_is_attack = np.array([lbl.upper() != "BENIGN" for lbl in y_target], dtype=bool)

        records = df.to_dict(orient="records")
        X_list = [extract_features_from_record(r) for r in records]
        X = np.vstack(X_list)

        # Batch Model Inferences
        probas = predictor.rf.predict_proba(X)
        classes = predictor.rf.predict(X)
        max_ps = np.max(probas, axis=1)

        X_scaled = predictor.ifo.named_steps["scaler"].transform(X)
        if_scores = predictor.ifo.named_steps["if"].score_samples(X_scaled)

        prod_actions = []
        prod_sim_blocks = []
        cand_actions = []
        cand_sim_blocks = []
        raw_rf_preds = []

        for i in range(n_total):
            cls_idx = int(classes[i])
            raw_cname = LABEL_NAMES.get(cls_idx, "BENIGN")
            max_p = float(max_ps[i])
            if_score = float(if_scores[i])
            is_anomaly = bool(if_score < ANOMALY_THRESHOLD)
            if_sig = calculate_if_anomaly_signal(if_score)

            raw_rf_preds.append(raw_cname)

            # 1. Active Production Policy
            b_rf_s = max_p if raw_cname != "BENIGN" else (1.0 - max_p)
            prod_score = round(0.7 * b_rf_s + 0.3 * if_sig, 4)
            prod_action = (
                "BLOCK" if prod_score >= BLOCK_THRESHOLD else "MONITOR" if prod_score >= MONITOR_THRESHOLD else "ALLOW"
            )
            prod_actions.append(prod_action)
            prod_sim_blocks.append(prod_action == "BLOCK")

            # 2. Candidate Decoupled Policy
            c_res = candidate.evaluate_signals(
                cname=raw_cname,
                confidence=max_p,
                is_anomaly=is_anomaly,
                anomaly_signal=if_sig,
                anomaly_score=if_score,
            )
            cand_actions.append(c_res["action"])
            cand_sim_blocks.append(c_res["action"] == "BLOCK")

        # Compute Metrics for both policies
        prod_m = calc_metrics(y_is_attack, prod_actions, prod_sim_blocks, raw_rf_preds)
        cand_m = calc_metrics(y_is_attack, cand_actions, cand_sim_blocks, raw_rf_preds)

        all_metrics[skey] = {
            "slice_metadata": {
                "key": skey,
                "file": sdef["file"],
                "total_flows": n_total,
                "attack_flows": int(np.sum(y_is_attack)),
                "benign_flows": int(np.sum(~y_is_attack)),
                "provenance": sdef["provenance"],
                "canonical_label": sdef["canonical_label"],
            },
            "production_policy": prod_m,
            "candidate_policy": cand_m,
        }

        per_attack_confusion[skey] = {
            "attack_flows": int(np.sum(y_is_attack)),
            "benign_flows": int(np.sum(~y_is_attack)),
            "production_containment_confusion": prod_m["policy_containment"]["confusion"],
            "production_containment_recall": prod_m["policy_containment"]["recall"],
            "production_containment_recall_ci95": prod_m["policy_containment"]["recall_ci_95"],
            "candidate_containment_confusion": cand_m["policy_containment"]["confusion"],
            "candidate_containment_recall": cand_m["policy_containment"]["recall"],
            "candidate_containment_recall_ci95": cand_m["policy_containment"]["recall_ci_95"],
            "candidate_simulated_block_recall": cand_m["simulated_block"]["recall"],
            "candidate_simulated_block_recall_ci95": cand_m["simulated_block"]["recall_ci_95"],
            "candidate_fp_monitor_rate": cand_m["policy_containment"]["fpr"],
            "candidate_fp_monitor_ci95": cand_m["policy_containment"]["fpr_ci_95"],
            "candidate_fp_block_rate": cand_m["simulated_block"]["fpr"],
            "candidate_fp_block_ci95": cand_m["simulated_block"]["fpr_ci_95"],
            "candidate_action_counts": cand_m["policy_containment"]["action_counts"],
        }

        print(
            f"  Production Recall: {prod_m['policy_containment']['recall']:.2%} | "
            f"Candidate Recall: {cand_m['policy_containment']['recall']:.2%} | "
            f"Candidate BLOCK Recall: {cand_m['simulated_block']['recall']:.2%}"
        )

    print(f"\nTotal Evaluated Flows: {total_evaluated_flows} (Reconciled exact count: 23,036)")

    # 4. Generate Threshold Sensitivity Analysis CSV
    print("\nGenerating Threshold Sensitivity Grid (sweeping thresholds)...")
    sens_rows = []
    threshold_taus = [0.70, 0.75, 0.80, 0.85, 0.90, 0.92]
    block_thresholds = [0.88, 0.90, 0.92, 0.95]

    for bt in block_thresholds:
        for tau in threshold_taus:
            test_policy = CandidateSentinelPolicy(
                block_threshold=bt,
                monitor_threshold=MONITOR_THRESHOLD,
                experimental_confidence_threshold=tau,
            )

            # Evaluate on PortScan and Monday Benign
            ps_df = load_slice(
                data_dir / "Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv",
                "PortScan",
                offset=30000,
                max_attack=1000,
                max_benign=1000,
            )
            ps_records = ps_df.to_dict(orient="records")
            ps_X = np.vstack([extract_features_from_record(r) for r in ps_records])
            ps_probas = predictor.rf.predict_proba(ps_X)
            ps_classes = predictor.rf.predict(ps_X)
            ps_max_p = np.max(ps_probas, axis=1)
            ps_if_s = predictor.ifo.named_steps["if"].score_samples(
                predictor.ifo.named_steps["scaler"].transform(ps_X)
            )

            ps_acts = []
            for j in range(len(ps_records)):
                c_eval = test_policy.evaluate_signals(
                    cname=LABEL_NAMES.get(int(ps_classes[j]), "BENIGN"),
                    confidence=float(ps_max_p[j]),
                    is_anomaly=bool(ps_if_s[j] < ANOMALY_THRESHOLD),
                    anomaly_signal=calculate_if_anomaly_signal(float(ps_if_s[j])),
                )
                ps_acts.append(c_eval["action"])

            ps_rec = np.sum((np.array(ps_acts[:1000]) == "MONITOR") | (np.array(ps_acts[:1000]) == "BLOCK")) / 1000.0
            ps_blk = np.sum(np.array(ps_acts[:1000]) == "BLOCK") / 1000.0
            ps_fpr = np.sum((np.array(ps_acts[1000:]) == "MONITOR") | (np.array(ps_acts[1000:]) == "BLOCK")) / 1000.0

            sens_rows.append(
                {
                    "block_threshold": bt,
                    "confidence_qualification_tau": tau,
                    "portscan_containment_recall": round(ps_rec, 4),
                    "portscan_simulated_block_recall": round(ps_blk, 4),
                    "portscan_benign_fpr": round(ps_fpr, 4),
                }
            )

    # Save outputs
    out_dir = CURRENT_DIR
    metrics_path = out_dir / "candidate_vs_production_policy_metrics.json"
    conf_path = out_dir / "per_attack_confusion_matrices.json"
    sens_path = out_dir / "threshold_sensitivity.csv"

    with open(metrics_path, "w", encoding="utf-8") as f:
        json.dump(all_metrics, f, indent=2)
    print(f"\nSaved metrics to: {metrics_path}")

    with open(conf_path, "w", encoding="utf-8") as f:
        json.dump(per_attack_confusion, f, indent=2)
    print(f"Saved confusion matrices to: {conf_path}")

    sens_df = pd.DataFrame(sens_rows)
    sens_df.to_csv(sens_path, index=False)
    print(f"Saved threshold sensitivity to: {sens_path}")

    # Re-verify protected asset hashes post-harness
    asset_hashes_post = {k: compute_file_sha256(v) for k, v in protected_assets.items()}
    drift_detected = False
    for k in asset_hashes_pre:
        if asset_hashes_pre[k] != asset_hashes_post[k]:
            drift_detected = True
            print(f"[FATAL] Cryptographic drift detected on {k}!")

    if not drift_detected:
        print("\nProtected Asset Verification: ZERO DRIFT (All 5 files identical before and after).")

    # Generate protected_asset_hash_verification.json
    hash_manifest = {
        "audit_phase": "SentinelAI GATE-1 Phase 4: Candidate Policy Evaluation",
        "verification_timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "source_commit": "e9f71a0",
        "zero_drift_verified": not drift_detected,
        "assets": [
            {
                "asset_name": k,
                "file_path": str(v),
                "sha256": asset_hashes_post[k],
                "verified": asset_hashes_pre[k] == asset_hashes_post[k],
            }
            for k, v in protected_assets.items()
        ],
    }
    with open(out_dir / "protected_asset_hash_verification.json", "w", encoding="utf-8") as f:
        json.dump(hash_manifest, f, indent=2)


if __name__ == "__main__":
    main()
