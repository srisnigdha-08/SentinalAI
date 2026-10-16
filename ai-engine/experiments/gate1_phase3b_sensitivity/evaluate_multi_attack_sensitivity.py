#!/usr/bin/env python3
"""
SentinelAI — GATE-1 Phase 3B: Multi-Attack Sensitivity and Threshold Analysis
Location: ai-engine/experiments/gate1_phase3b_sensitivity/evaluate_multi_attack_sensitivity.py

Evaluates the candidate policy across all available CICIDS2017 attack categories:
- PortScan (Friday Afternoon)
- DDoS (Friday Afternoon)
- SSH Brute Force / SSH-Patator (Tuesday)
- Web Attacks (Thursday Morning)
- Infiltration (Thursday Afternoon - 36 flows, flagged INSUFFICIENT)
- Botnet / Malware Beacon (Friday Morning)
- DoS Hulk (Wednesday)
- Pure Benign Benchmark (Monday - 10,000 flows)

Produces:
- ai-engine/experiments/gate1_phase3b_sensitivity/multi_attack_metrics.json
- ai-engine/experiments/gate1_phase3b_sensitivity/threshold_sensitivity.csv
"""

import sys
import os
import json
import time
import math
from pathlib import Path
import numpy as np
import pandas as pd

CURRENT_DIR = Path(__file__).resolve().parent
PHASE3A_DIR = CURRENT_DIR.parent / "gate1_phase3a_remediation"
AI_ENGINE_DIR = CURRENT_DIR.parent.parent

if str(AI_ENGINE_DIR) not in sys.path:
    sys.path.insert(0, str(AI_ENGINE_DIR))
if str(PHASE3A_DIR) not in sys.path:
    sys.path.insert(0, str(PHASE3A_DIR))

from utils.features import FEATURE_NAMES, LABEL_NAMES, RAW_LABEL_TO_TARGET, extract_features_from_record
from inference.predictor import SentinelPredictor, ANOMALY_THRESHOLD, BLOCK_THRESHOLD, MONITOR_THRESHOLD
from candidate_policy import CandidateSentinelPolicy, calculate_if_anomaly_signal


def wilson_score_interval(successes: int, total: int, confidence: float = 0.95):
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


def normalize_label(raw_label: str) -> str:
    """Safely normalizes raw CSV label strings with potential encoding artifacts."""
    s = str(raw_label).strip()
    s_clean = s.encode("ascii", errors="ignore").decode("ascii").strip()
    if "web attack" in s.lower() or "web attack" in s_clean.lower():
        if "brute" in s.lower(): return "Credential Stuffing"
        if "xss" in s.lower(): return "XSS Attempt"
        if "sql" in s.lower(): return "SQL Injection"
        return "Credential Stuffing"
    return RAW_LABEL_TO_TARGET.get(s, RAW_LABEL_TO_TARGET.get(s_clean, s))


def evaluate_dataset_stream(predictor, policy, df, dataset_name, sufficiency="SUFFICIENT", provenance_note=""):
    """
    Evaluates raw RF, baseline policy, and candidate policy on a dataframe stream.
    """
    t0 = time.perf_counter()
    l_col = next((c for c in df.columns if "label" in c.lower()), "Label")
    y_raw = df[l_col].tolist()
    y_target = [normalize_label(lbl) for lbl in y_raw]
    y_is_attack = np.array([lbl.upper() != "BENIGN" for lbl in y_target], dtype=bool)

    records = df.to_dict(orient="records")
    X_list = [extract_features_from_record(r) for r in records]
    X = np.vstack(X_list)

    # Fast Vectorized Inference
    probas = predictor.rf.predict_proba(X)
    classes = predictor.rf.predict(X)
    max_ps = np.max(probas, axis=1)

    X_scaled = predictor.ifo.named_steps["scaler"].transform(X)
    if_scores = predictor.ifo.named_steps["if"].score_samples(X_scaled)

    # Candidate collectors
    c_actions = []
    c_scores = []
    c_classes = []
    c_telemetry = []
    c_simulated_blocks = []

    # Baseline collectors
    b_actions = []

    for i in range(len(records)):
        cls_idx = int(classes[i])
        raw_cname = LABEL_NAMES.get(cls_idx, "BENIGN")
        max_p = float(max_ps[i])
        if_score = float(if_scores[i])
        is_anomaly = bool(if_score < ANOMALY_THRESHOLD)
        if_sig = predictor.calculate_if_anomaly_signal(if_score)

        # Baseline calculation
        b_rf_s = max_p if raw_cname != "BENIGN" else (1.0 - max_p)
        b_score = round(0.7 * b_rf_s + 0.3 * if_sig, 4)
        if raw_cname == "BENIGN" and is_anomaly:
            b_score = max(b_score, 0.55)
        b_act = "BLOCK" if b_score >= BLOCK_THRESHOLD else "MONITOR" if b_score >= MONITOR_THRESHOLD else "ALLOW"
        b_actions.append(b_act)

        # Candidate evaluation
        res = policy.evaluate_signals(
            cname=raw_cname,
            confidence=max_p,
            is_anomaly=is_anomaly,
            anomaly_signal=if_sig,
            anomaly_score=if_score,
        )
        c_actions.append(res["action"])
        c_scores.append(res["threatScore"])
        c_classes.append(res["predictedClass"])
        c_telemetry.append(res["threatScore"] >= 0.50 or res["predictedClass"] == "Unknown")
        c_simulated_blocks.append(res["action"] == "BLOCK")

    duration = time.perf_counter() - t0
    total_pos = int(np.sum(y_is_attack))
    total_neg = int(np.sum(~y_is_attack))

    # Helper for metrics
    def get_metrics_for_actions(act_list, blk_list):
        act_arr = np.array(act_list)
        # Containment (MONITOR or BLOCK)
        c_pos = (act_arr == "MONITOR") | (act_arr == "BLOCK")
        tp = int(np.sum(c_pos & y_is_attack))
        fp = int(np.sum(c_pos & ~y_is_attack))
        tn = int(np.sum(~c_pos & ~y_is_attack))
        fn = int(np.sum(~c_pos & y_is_attack))
        rec = tp / total_pos if total_pos > 0 else 0.0
        fpr = fp / total_neg if total_neg > 0 else 0.0

        # Simulated Block Only
        b_pos = np.array(blk_list)
        b_tp = int(np.sum(b_pos & y_is_attack))
        b_fp = int(np.sum(b_pos & ~y_is_attack))
        b_tn = int(np.sum(~b_pos & ~y_is_attack))
        b_fn = int(np.sum(~b_pos & y_is_attack))
        b_rec = b_tp / total_pos if total_pos > 0 else 0.0
        b_fpr = b_fp / total_neg if total_neg > 0 else 0.0

        return {
            "containment_action": {
                "confusion": {"TN": tn, "FP": fp, "FN": fn, "TP": tp},
                "recall": round(rec, 5),
                "recall_ci_95": list(wilson_score_interval(tp, total_pos)),
                "fpr": round(fpr, 5),
                "fpr_ci_95": list(wilson_score_interval(fp, total_neg)),
                "actions": pd.Series(act_list).value_counts().to_dict(),
            },
            "simulated_block_decision": {
                "confusion": {"TN": b_tn, "FP": b_fp, "FN": b_fn, "TP": b_tp},
                "recall": round(b_rec, 5),
                "recall_ci_95": list(wilson_score_interval(b_tp, total_pos)),
                "fpr": round(b_fpr, 5),
                "fpr_ci_95": list(wilson_score_interval(b_fp, total_neg)),
            }
        }

    # Raw RF metrics
    raw_preds = [LABEL_NAMES.get(int(c), "BENIGN") for c in classes]
    rf_pos = np.array([p != "BENIGN" for p in raw_preds])
    rf_tp = int(np.sum(rf_pos & y_is_attack))
    rf_fp = int(np.sum(rf_pos & ~y_is_attack))
    rf_tn = int(np.sum(~rf_pos & ~y_is_attack))
    rf_fn = int(np.sum(~rf_pos & y_is_attack))
    raw_rf_metrics = {
        "confusion": {"TN": rf_tn, "FP": rf_fp, "FN": rf_fn, "TP": rf_tp},
        "recall": round(rf_tp / total_pos, 5) if total_pos > 0 else 0.0,
        "recall_ci_95": list(wilson_score_interval(rf_tp, total_pos)),
        "fpr": round(rf_fp / total_neg, 5) if total_neg > 0 else 0.0,
        "fpr_ci_95": list(wilson_score_interval(rf_fp, total_neg)),
    }

    base_metrics = get_metrics_for_actions(b_actions, [a == "BLOCK" for a in b_actions])
    cand_metrics = get_metrics_for_actions(c_actions, c_simulated_blocks)

    return {
        "dataset_name": dataset_name,
        "data_sufficiency": sufficiency,
        "provenance_note": provenance_note,
        "sampleCount": len(df),
        "positiveCount": total_pos,
        "negativeCount": total_neg,
        "durationSec": round(duration, 2),
        "raw_supervised_classifier": raw_rf_metrics,
        "baseline_policy": base_metrics,
        "candidate_policy": cand_metrics,
        "telemetry_alert_rate": {
            "alert_count": int(np.sum(c_telemetry)),
            "alert_rate_on_attacks": round(float(np.sum(np.array(c_telemetry) & y_is_attack) / total_pos), 5) if total_pos > 0 else 0.0,
            "alert_rate_on_benign": round(float(np.sum(np.array(c_telemetry) & ~y_is_attack) / total_neg), 5) if total_neg > 0 else 0.0,
        },
        "attack_false_negatives_count": cand_metrics["containment_action"]["confusion"]["FN"],
        "error_counts": {
            "exceptions": 0,
            "missing_predictions": 0,
            "degraded_fallbacks": 0
        },
        "_cache_raw": {
            "y_is_attack": y_is_attack.tolist(),
            "classes": [int(c) for c in classes],
            "max_ps": [float(p) for p in max_ps],
            "if_scores": [float(s) for s in if_scores],
        }
    }


def run_threshold_sensitivity_sweep(evaluated_datasets, thresholds=[0.60, 0.70, 0.75, 0.80, 0.85, 0.90, 0.92]):
    """
    Sweeps confidence qualification thresholds while keeping decision formulas fixed.
    Generates threshold_sensitivity.csv.
    """
    rows = []

    for tau in thresholds:
        # Create policy instance with experimental threshold = tau
        pol = CandidateSentinelPolicy(
            block_threshold=0.92,
            monitor_threshold=min(tau, 0.70), # qualification boundary
            experimental_confidence_threshold=tau
        )

        for dname, data in evaluated_datasets.items():
            cache = data["_cache_raw"]
            y_is_attack = np.array(cache["y_is_attack"], dtype=bool)
            total_pos = int(np.sum(y_is_attack))
            total_neg = int(np.sum(~y_is_attack))

            actions = []
            for i in range(len(y_is_attack)):
                cls_idx = cache["classes"][i]
                raw_cname = LABEL_NAMES.get(cls_idx, "BENIGN")
                max_p = cache["max_ps"][i]
                if_score = cache["if_scores"][i]
                is_anomaly = bool(if_score < ANOMALY_THRESHOLD)
                if_sig = calculate_if_anomaly_signal(if_score)

                res = pol.evaluate_signals(
                    cname=raw_cname,
                    confidence=max_p,
                    is_anomaly=is_anomaly,
                    anomaly_signal=if_sig,
                    anomaly_score=if_score
                )
                actions.append(res["action"])

            act_arr = np.array(actions)
            c_pos = (act_arr == "MONITOR") | (act_arr == "BLOCK")
            tp = int(np.sum(c_pos & y_is_attack))
            fp = int(np.sum(c_pos & ~y_is_attack))
            rec = tp / total_pos if total_pos > 0 else 0.0
            fpr = fp / total_neg if total_neg > 0 else 0.0

            b_pos = (act_arr == "BLOCK")
            b_tp = int(np.sum(b_pos & y_is_attack))
            b_fp = int(np.sum(b_pos & ~y_is_attack))
            b_rec = b_tp / total_pos if total_pos > 0 else 0.0
            b_fpr = b_fp / total_neg if total_neg > 0 else 0.0

            allowed_prop = np.mean(act_arr == "ALLOW")

            rows.append({
                "threshold_tau": tau,
                "dataset": dname,
                "total_flows": len(y_is_attack),
                "attack_flows": total_pos,
                "benign_flows": total_neg,
                "policy_containment_recall": round(rec, 5),
                "policy_containment_fpr": round(fpr, 5),
                "simulated_block_recall": round(b_rec, 5),
                "simulated_block_fpr": round(b_fpr, 5),
                "proportion_allowed": round(allowed_prop, 5),
                "allow_count": int(np.sum(act_arr == "ALLOW")),
                "monitor_count": int(np.sum(act_arr == "MONITOR")),
                "block_count": int(np.sum(act_arr == "BLOCK")),
            })

    df_sweep = pd.DataFrame(rows)
    return df_sweep


def load_slice(csv_path, attack_name_filter, offset=0, max_attack=1000, max_benign=1000, encoding=None):
    """Memory-efficient chunked reader for extracting exact evaluation slices."""
    chunks = pd.read_csv(csv_path, chunksize=20000, encoding=encoding)
    b_list, a_list = [], []
    b_skipped, a_skipped = 0, 0

    for chunk in chunks:
        chunk.columns = chunk.columns.str.strip()
        l_col = next((c for c in chunk.columns if "label" in c.lower()), "Label")
        chunk["norm_label"] = chunk[l_col].astype(str).str.strip()

        b = chunk[chunk["norm_label"].str.upper() == "BENIGN"]
        if callable(attack_name_filter):
            a = chunk[chunk["norm_label"].apply(attack_name_filter)]
        else:
            a = chunk[chunk["norm_label"] == attack_name_filter]

        if b_skipped < offset:
            s = min(len(b), offset - b_skipped)
            b = b.iloc[s:]
            b_skipped += s
        if a_skipped < offset:
            s = min(len(a), offset - a_skipped)
            a = a.iloc[s:]
            a_skipped += s

        if len(b) > 0 and sum(len(x) for x in b_list) < max_benign:
            need = max_benign - sum(len(x) for x in b_list)
            b_list.append(b.head(need))
        if len(a) > 0 and sum(len(x) for x in a_list) < max_attack:
            need = max_attack - sum(len(x) for x in a_list)
            a_list.append(a.head(need))

        if sum(len(x) for x in b_list) >= max_benign and sum(len(x) for x in a_list) >= max_attack:
            break

    df_b = pd.concat(b_list, ignore_index=True) if b_list else pd.DataFrame()
    df_a = pd.concat(a_list, ignore_index=True) if a_list else pd.DataFrame()
    return pd.concat([df_b, df_a], ignore_index=True)


def main():
    print("=" * 70)
    print("  SentinelAI GATE-1 Phase 3B: Multi-Attack Sensitivity Pipeline")
    print("=" * 70)

    data_dir = AI_ENGINE_DIR / "datasets" / "cicids2017"
    predictor = SentinelPredictor()
    policy = CandidateSentinelPolicy()

    dataset_results = {}

    # 1. PortScan (Friday Afternoon)
    f_ps = data_dir / "Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv"
    if f_ps.exists():
        print("\n[1/8] Loading PortScan slice (offset=30,000)...")
        df_ps = load_slice(f_ps, "PortScan", offset=30000, max_attack=1000, max_benign=1000)
        res_ps = evaluate_dataset_stream(
            predictor, policy, df_ps, "Friday_PortScan",
            sufficiency="SUFFICIENT",
            provenance_note="10,000 PortScan sampled during training; offset=30,000 used to minimize direct sample collision."
        )
        dataset_results["portscan"] = res_ps
        print(f"  PortScan Recall: {res_ps['candidate_policy']['containment_action']['recall']*100:.2f}% | Simulated Block Recall: {res_ps['candidate_policy']['simulated_block_decision']['recall']*100:.2f}%")

    # 2. DDoS (Friday Afternoon)
    f_ddos = data_dir / "Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv"
    if f_ddos.exists():
        print("\n[2/8] Loading DDoS slice (offset=30,000)...")
        df_ddos = load_slice(f_ddos, "DDoS", offset=30000, max_attack=1000, max_benign=1000)
        res_ddos = evaluate_dataset_stream(
            predictor, policy, df_ddos, "Friday_DDoS",
            sufficiency="SUFFICIENT",
            provenance_note="10,000 DDoS sampled during training; offset=30,000 used to minimize direct sample collision."
        )
        dataset_results["ddos"] = res_ddos
        print(f"  DDoS Recall: {res_ddos['candidate_policy']['containment_action']['recall']*100:.2f}% | Simulated Block Recall: {res_ddos['candidate_policy']['simulated_block_decision']['recall']*100:.2f}%")

    # 3. SSH Brute Force (Tuesday WorkingHours: SSH-Patator)
    f_tue = data_dir / "Tuesday-WorkingHours.pcap_ISCX.csv"
    if f_tue.exists():
        print("\n[3/8] Loading SSH Brute Force slice (Tuesday SSH-Patator, offset=0)...")
        df_ssh = load_slice(f_tue, "SSH-Patator", offset=0, max_attack=1000, max_benign=1000)
        res_ssh = evaluate_dataset_stream(
            predictor, policy, df_ssh, "Tuesday_SSH_BruteForce",
            sufficiency="SUFFICIENT",
            provenance_note="In-sample resubstitution: all 5,897 SSH-Patator flows were ingested by train.py."
        )
        dataset_results["ssh_bruteforce"] = res_ssh
        print(f"  SSH Brute Force Recall: {res_ssh['candidate_policy']['containment_action']['recall']*100:.2f}% | Simulated Block Recall: {res_ssh['candidate_policy']['simulated_block_decision']['recall']*100:.2f}%")

    # 4. Web Attacks (Thursday Morning)
    f_web = data_dir / "Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv"
    if f_web.exists():
        print("\n[4/8] Loading Web Attacks slice (Thursday Morning, max 1000 attacks)...")
        def is_web_attack(lbl):
            s = str(lbl).lower()
            return "web attack" in s
        df_web = load_slice(f_web, is_web_attack, offset=0, max_attack=1000, max_benign=1000, encoding="cp1252")
        res_web = evaluate_dataset_stream(
            predictor, policy, df_web, "Thursday_WebAttacks",
            sufficiency="SUFFICIENT",
            provenance_note="In-sample resubstitution: all 2,180 Web Attack flows were ingested by train.py."
        )
        dataset_results["web_attacks"] = res_web
        print(f"  Web Attacks Recall: {res_web['candidate_policy']['containment_action']['recall']*100:.2f}% | Simulated Block Recall: {res_web['candidate_policy']['simulated_block_decision']['recall']*100:.2f}%")

    # 5. Infiltration (Thursday Afternoon - 36 flows)
    f_inf = data_dir / "Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv"
    if f_inf.exists():
        print("\n[5/8] Loading Infiltration slice (Thursday Afternoon, 36 attacks)...")
        df_inf = load_slice(f_inf, "Infiltration", offset=0, max_attack=1000, max_benign=1000)
        res_inf = evaluate_dataset_stream(
            predictor, policy, df_inf, "Thursday_Infiltration",
            sufficiency="INSUFFICIENT (N=36)",
            provenance_note="CRITICAL WARNING: Only 36 Infiltration flows exist in entire capture. Highly insufficient sample size."
        )
        dataset_results["infiltration"] = res_inf
        print(f"  Infiltration Recall: {res_inf['candidate_policy']['containment_action']['recall']*100:.2f}% (N={res_inf['positiveCount']}) [STATUS: INSUFFICIENT DATA]")

    # 6. Botnet / Malware Beacon (Friday Morning)
    f_bot = data_dir / "Friday-WorkingHours-Morning.pcap_ISCX.csv"
    if f_bot.exists():
        print("\n[6/8] Loading Botnet slice (Friday Morning Bot, max 1000 attacks)...")
        df_bot = load_slice(f_bot, "Bot", offset=0, max_attack=1000, max_benign=1000)
        res_bot = evaluate_dataset_stream(
            predictor, policy, df_bot, "Friday_Botnet",
            sufficiency="SUFFICIENT",
            provenance_note="In-sample resubstitution: all 1,966 Bot flows were ingested by train.py."
        )
        dataset_results["botnet"] = res_bot
        print(f"  Botnet Recall: {res_bot['candidate_policy']['containment_action']['recall']*100:.2f}% | Simulated Block Recall: {res_bot['candidate_policy']['simulated_block_decision']['recall']*100:.2f}%")

    # 7. DoS Hulk (Wednesday)
    f_wed = data_dir / "Wednesday-workingHours.pcap_ISCX.csv"
    if f_wed.exists():
        print("\n[7/8] Loading DoS Hulk slice (Wednesday, offset=30,000)...")
        df_hulk = load_slice(f_wed, "DoS Hulk", offset=30000, max_attack=1000, max_benign=1000)
        res_hulk = evaluate_dataset_stream(
            predictor, policy, df_hulk, "Wednesday_DoSHulk",
            sufficiency="SUFFICIENT",
            provenance_note="10,000 DDoS/DoS flows sampled during training; offset=30,000 used."
        )
        dataset_results["dos_hulk"] = res_hulk
        print(f"  DoS Hulk Recall: {res_hulk['candidate_policy']['containment_action']['recall']*100:.2f}% | Simulated Block Recall: {res_hulk['candidate_policy']['simulated_block_decision']['recall']*100:.2f}%")

    # 8. Monday Pure Benign Benchmark (10,000 flows)
    f_mon = data_dir / "Monday-WorkingHours.pcap_ISCX.csv"
    if f_mon.exists():
        print("\n[8/8] Loading Monday Pure Benign Benchmark (10,000 flows)...")
        df_mon = load_slice(f_mon, "NON_EXISTENT_LABEL", offset=0, max_attack=0, max_benign=10000)
        res_mon = evaluate_dataset_stream(
            predictor, policy, df_mon, "Monday_Benign_Validation",
            sufficiency="SUFFICIENT",
            provenance_note="Internal validation benchmark: 15,000 flows sampled by train.py; not an independent blind test."
        )
        dataset_results["monday_benign"] = res_mon
        print(f"  Monday Benign FPR: {res_mon['candidate_policy']['containment_action']['fpr']*100:.2f}% (95% CI: [{res_mon['candidate_policy']['containment_action']['fpr_ci_95'][0]*100:.2f}%, {res_mon['candidate_policy']['containment_action']['fpr_ci_95'][1]*100:.2f}%])")

    # Save JSON metrics (excluding raw cache)
    cleaned_results = {
        "metadata": {
            "evaluation_module": "evaluate_multi_attack_sensitivity.py",
            "active_rf_model": "rf_classifier_cicids_v2.pkl",
            "active_if_model": "isolation_forest_cicids.pkl",
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "notice": "All block metrics represent simulated policy decisions. Actual Windows Firewall enforcement remains permanently disabled."
        },
        "datasets": {}
    }
    for k, v in dataset_results.items():
        v_clean = {k2: v2 for k2, v2 in v.items() if k2 != "_cache_raw"}
        cleaned_results["datasets"][k] = v_clean

    out_json = CURRENT_DIR / "multi_attack_metrics.json"
    with open(out_json, "w") as f:
        json.dump(cleaned_results, f, indent=2)
    print(f"\n[OUTPUT] Multi-attack metrics written to:\n  {out_json}")

    # Threshold Sensitivity Sweep
    print("\n" + "=" * 70)
    print("  Running Threshold Sensitivity Sweep (tau in [0.60, 0.70, 0.75, 0.80, 0.85, 0.90, 0.92])...")
    print("=" * 70)
    sweep_df = run_threshold_sensitivity_sweep(dataset_results)
    out_csv = CURRENT_DIR / "threshold_sensitivity.csv"
    sweep_df.to_csv(out_csv, index=False)
    print(f"[OUTPUT] Threshold sensitivity CSV written to:\n  {out_csv}")
    print("\nThreshold Sweep Summary (Averaged across attack datasets):")
    for tau, grp in sweep_df.groupby("threshold_tau"):
        atk_sub = grp[grp["dataset"] != "monday_benign"]
        mean_rec = atk_sub["policy_containment_recall"].mean()
        mean_blk = atk_sub["simulated_block_recall"].mean()
        mon_fpr = grp[grp["dataset"] == "monday_benign"]["policy_containment_fpr"].values[0] if len(grp[grp["dataset"] == "monday_benign"]) > 0 else 0.0
        print(f"  tau={tau:.2f} | Mean Attack Recall: {mean_rec*100:.2f}% | Mean Block Recall: {mean_blk*100:.2f}% | Monday Benign FPR: {mon_fpr*100:.2f}%")


if __name__ == "__main__":
    main()
