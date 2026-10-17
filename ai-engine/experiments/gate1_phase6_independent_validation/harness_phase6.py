#!/usr/bin/env python3
"""
SentinelAI — GATE-1 Phase 6: Controlled Architecture Comparison Harness
Location: ai-engine/experiments/gate1_phase6_independent_validation/harness_phase6.py

Compares:
A. Existing Production Flow Policy (Coupled RF + IF)
B. Phase 4 Candidate Flow Policy (Decoupled RF + IF)
C. Layer 7 WAF Pre-Filter Alone
D. Combined Layer 7 WAF + Candidate Flow Policy

Evaluates on:
1. 300-Record Comprehensive HTTP Benchmark (Benign, Attacks, Malformed, Non-HTTP)
2. 23,036 CICIDS2017 Flow Corpus across 8 PCAP slices (testing L7 fallback & L4 flow recall)
"""

import sys
import os
import re
import json
import time
import math
import urllib.parse
import unicodedata
from pathlib import Path
import numpy as np
import pandas as pd

CURRENT_DIR = Path(__file__).resolve().parent
AI_ENGINE_DIR = CURRENT_DIR.parent.parent
PHASE3A_DIR = CURRENT_DIR.parent / "gate1_phase3a_remediation"
PHASE3B_DIR = CURRENT_DIR.parent / "gate1_phase3b_sensitivity"
PHASE4_DIR = CURRENT_DIR.parent / "gate1_phase4_candidate_policy_validation"
PHASE5_DIR = CURRENT_DIR.parent / "gate1_phase5_independent_validation"

sys.path.insert(0, str(AI_ENGINE_DIR))
sys.path.insert(0, str(PHASE3A_DIR))
sys.path.insert(0, str(PHASE3B_DIR))
sys.path.insert(0, str(PHASE4_DIR))
sys.path.insert(0, str(PHASE5_DIR))

from utils.features import FEATURE_NAMES, LABEL_NAMES, RAW_LABEL_TO_TARGET, extract_features_from_record
from inference.predictor import SentinelPredictor, ANOMALY_THRESHOLD, BLOCK_THRESHOLD, MONITOR_THRESHOLD
from candidate_policy import CandidateSentinelPolicy
from evaluate_multi_attack_sensitivity import load_slice, normalize_label
from layer7_prototype import Layer7PreFilter, generate_http_evaluation_benchmark, evaluate_record_across_configs, wilson_score_interval


def run_phase6_comparison():
    print("================================================================================")
    print("SentinelAI GATE-1 Phase 6: Controlled Policy Architecture Comparison")
    print("================================================================================")

    models_dir = AI_ENGINE_DIR / "models"
    data_dir = AI_ENGINE_DIR / "datasets" / "cicids2017"

    predictor = SentinelPredictor(model_dir=str(models_dir))
    cand_policy = CandidateSentinelPolicy(
        block_threshold=BLOCK_THRESHOLD,
        monitor_threshold=MONITOR_THRESHOLD,
        experimental_confidence_threshold=0.85
    )
    l7_waf = Layer7PreFilter(block_threshold=0.85, monitor_threshold=0.70)

    # -------------------------------------------------------------------------
    # PART 1: EVALUATE 300-RECORD HTTP BENCHMARK
    # -------------------------------------------------------------------------
    print("\n[PART 1/2] Benchmarking 300-Record Comprehensive HTTP Benchmark...")
    http_records = generate_http_evaluation_benchmark()

    results_http = {
        "config_a_prod": {"tp": 0, "fp": 0, "tn": 0, "fn": 0, "block_tp": 0, "block_fp": 0},
        "config_b_cand_flow": {"tp": 0, "fp": 0, "tn": 0, "fn": 0, "block_tp": 0, "block_fp": 0},
        "config_c_l7_alone": {"tp": 0, "fp": 0, "tn": 0, "fn": 0, "block_tp": 0, "block_fp": 0},
        "config_d_combined": {"tp": 0, "fp": 0, "tn": 0, "fn": 0, "block_tp": 0, "block_fp": 0},
    }

    per_category_http = {}
    latencies_l7 = []

    for r in http_records:
        cat = r["category"]
        is_att = r["is_attack"]
        rec = r["l4_record"]
        l7_d = r["l7_data"]

        t0 = time.perf_counter()
        eval_out = evaluate_record_across_configs(predictor, cand_policy, l7_waf, rec, l7_data=l7_d)
        lat_ms = (time.perf_counter() - t0) * 1000.0
        latencies_l7.append(lat_ms)

        if cat not in per_category_http:
            per_category_http[cat] = {
                "total": 0,
                "is_attack": is_att,
                "config_a_detected": 0,
                "config_b_detected": 0,
                "config_c_detected": 0,
                "config_d_detected": 0,
                "config_d_blocked": 0,
            }
        per_category_http[cat]["total"] += 1

        for ckey, cdata in eval_out.items():
            act = cdata["action"]
            is_pos = (act in ("MONITOR", "BLOCK"))
            is_blk = cdata["sim_block"]

            if is_att:
                if is_pos: results_http[ckey]["tp"] += 1
                else: results_http[ckey]["fn"] += 1
                if is_blk: results_http[ckey]["block_tp"] += 1
            else:
                if is_pos: results_http[ckey]["fp"] += 1
                else: results_http[ckey]["tn"] += 1
                if is_blk: results_http[ckey]["block_fp"] += 1

        if eval_out["config_a_prod"]["action"] in ("MONITOR", "BLOCK"): per_category_http[cat]["config_a_detected"] += 1
        if eval_out["config_b_cand_flow"]["action"] in ("MONITOR", "BLOCK"): per_category_http[cat]["config_b_detected"] += 1
        if eval_out["config_c_l7_alone"]["action"] in ("MONITOR", "BLOCK"): per_category_http[cat]["config_c_detected"] += 1
        if eval_out["config_d_combined"]["action"] in ("MONITOR", "BLOCK"): per_category_http[cat]["config_d_detected"] += 1
        if eval_out["config_d_combined"]["sim_block"]: per_category_http[cat]["config_d_blocked"] += 1

    print("HTTP benchmark evaluation finished.")
    print(f"Mean inspection latency: {np.mean(latencies_l7):.3f} ms (p99: {np.percentile(latencies_l7, 99):.3f} ms)")

    # -------------------------------------------------------------------------
    # PART 2: EVALUATE 23,036 CICIDS2017 FLOW CORPUS (L7 FALLBACK & L4 RECALL)
    # -------------------------------------------------------------------------
    print("\n[PART 2/2] Benchmarking 23,036 CICIDS2017 Flow Corpus across 8 PCAP Slices...")

    slices_def = [
        {"key": "PortScan", "file": "Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv", "filter": "PortScan", "offset": 30000, "max_attack": 1000, "max_benign": 1000},
        {"key": "DDoS", "file": "Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv", "filter": "DDoS", "offset": 30000, "max_attack": 1000, "max_benign": 1000},
        {"key": "SSH_Patator", "file": "Tuesday-WorkingHours.pcap_ISCX.csv", "filter": "SSH-Patator", "offset": 0, "max_attack": 1000, "max_benign": 1000},
        {"key": "Web_Attacks", "file": "Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv", "filter": lambda l: "web attack" in str(l).lower(), "offset": 0, "max_attack": 1000, "max_benign": 1000, "encoding": "cp1252"},
        {"key": "Infiltration", "file": "Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv", "filter": "Infiltration", "offset": 0, "max_attack": 1000, "max_benign": 1000},
        {"key": "Botnet", "file": "Friday-WorkingHours-Morning.pcap_ISCX.csv", "filter": "Bot", "offset": 0, "max_attack": 1000, "max_benign": 1000},
        {"key": "DoS_Hulk", "file": "Wednesday-workingHours.pcap_ISCX.csv", "filter": "DoS Hulk", "offset": 30000, "max_attack": 1000, "max_benign": 1000},
        {"key": "Monday_Benign", "file": "Monday-WorkingHours.pcap_ISCX.csv", "filter": "NON_EXISTENT", "offset": 0, "max_attack": 0, "max_benign": 10000},
    ]

    corpus_results = {}
    total_corpus_flows = 0

    for sdef in slices_def:
        skey = sdef["key"]
        csv_path = data_dir / sdef["file"]
        if not csv_path.exists():
            print(f"  [WARN] File not found: {csv_path}. Skipping.")
            continue

        print(f"  Evaluating slice: {skey}...")
        enc = sdef.get("encoding", "utf-8")
        df = load_slice(
            csv_path,
            sdef["filter"],
            offset=sdef["offset"],
            max_attack=sdef["max_attack"],
            max_benign=sdef["max_benign"],
            encoding=enc
        )

        n_total = len(df)
        total_corpus_flows += n_total

        l_col = next((c for c in df.columns if "label" in c.lower()), "Label")
        y_raw = df[l_col].tolist()
        y_target = [normalize_label(lbl) for lbl in y_raw]
        y_is_attack = np.array([lbl.upper() != "BENIGN" for lbl in y_target], dtype=bool)

        records = df.to_dict(orient="records")
        X_list = [extract_features_from_record(r) for r in records]
        X = np.vstack(X_list)

        probas = predictor.rf.predict_proba(X)
        classes = predictor.rf.predict(X)
        max_ps = np.max(probas, axis=1)

        X_scaled = predictor.ifo.named_steps["scaler"].transform(X)
        if_scores = predictor.ifo.named_steps["if"].score_samples(X_scaled)

        slice_counts = {
            "config_a_prod": {"tp": 0, "fp": 0, "tn": 0, "fn": 0, "block_tp": 0, "block_fp": 0},
            "config_b_cand_flow": {"tp": 0, "fp": 0, "tn": 0, "fn": 0, "block_tp": 0, "block_fp": 0},
            "config_c_l7_alone": {"tp": 0, "fp": 0, "tn": 0, "fn": 0, "block_tp": 0, "block_fp": 0},
            "config_d_combined": {"tp": 0, "fp": 0, "tn": 0, "fn": 0, "block_tp": 0, "block_fp": 0},
        }

        for i in range(n_total):
            is_att = bool(y_is_attack[i])
            rec = records[i]
            cls_idx = int(classes[i])
            raw_cname = LABEL_NAMES.get(cls_idx, "BENIGN")
            max_p = float(max_ps[i])
            if_score = float(if_scores[i])
            is_anomaly = bool(if_score < ANOMALY_THRESHOLD)
            if_sig = predictor.calculate_if_anomaly_signal(if_score)

            # Config A
            rf_s = max_p if raw_cname != "BENIGN" else (1.0 - max_p)
            prod_s = round(0.7 * rf_s + 0.3 * if_sig, 4)
            prod_act = "BLOCK" if prod_s >= BLOCK_THRESHOLD else "MONITOR" if prod_s >= MONITOR_THRESHOLD else "ALLOW"
            prod_blk = (prod_act == "BLOCK")

            # Config B
            cand_dec = cand_policy.evaluate_signals(
                cname=raw_cname,
                confidence=max_p,
                is_anomaly=is_anomaly,
                anomaly_signal=if_sig,
                anomaly_score=if_score
            )
            cand_act = cand_dec["action"]
            cand_blk = (cand_act == "BLOCK")

            # Config C (L7 alone: since pure L4 flow has no HTTP body, L7 is UNAVAILABLE -> ALLOW)
            l7_act = "ALLOW"
            l7_blk = False

            # Config D (Combined: L7 is unavailable, so falls back seamlessly to Candidate Flow Policy)
            comb_act = cand_act
            comb_blk = cand_blk

            configs = {
                "config_a_prod": (prod_act in ("MONITOR", "BLOCK"), prod_blk),
                "config_b_cand_flow": (cand_act in ("MONITOR", "BLOCK"), cand_blk),
                "config_c_l7_alone": (l7_act in ("MONITOR", "BLOCK"), l7_blk),
                "config_d_combined": (comb_act in ("MONITOR", "BLOCK"), comb_blk),
            }

            for ckey, (is_pos, is_b) in configs.items():
                if is_att:
                    if is_pos: slice_counts[ckey]["tp"] += 1
                    else: slice_counts[ckey]["fn"] += 1
                    if is_b: slice_counts[ckey]["block_tp"] += 1
                else:
                    if is_pos: slice_counts[ckey]["fp"] += 1
                    else: slice_counts[ckey]["tn"] += 1
                    if is_b: slice_counts[ckey]["block_fp"] += 1

        corpus_results[skey] = {
            "total_flows": n_total,
            "attack_flows": int(np.sum(y_is_attack)),
            "benign_flows": int(np.sum(~y_is_attack)),
            "configs": slice_counts
        }

    print(f"Corpus evaluation completed across all {total_corpus_flows} flows.")

    # -------------------------------------------------------------------------
    # PART 3: FORMAT & WRITE OUTPUT DELIVERABLES
    # -------------------------------------------------------------------------
    out_metrics = {
        "metadata": {
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "benchmark_scope": "GATE-1 Phase 6 Controlled Policy Architecture Comparison",
            "evaluated_corpora": {
                "http_synthetic_benchmark": {"total_records": len(http_records)},
                "cicids2017_flow_corpus": {"total_flows": total_corpus_flows}
            },
            "configurations": {
                "config_a_prod": "Existing Production Policy (Coupled RF + IF)",
                "config_b_cand_flow": "Phase 4 Candidate Flow Policy (Decoupled RF + IF)",
                "config_c_l7_alone": "Layer 7 WAF Pre-Filter Alone",
                "config_d_combined": "Combined Layer 7 Pre-Filter + Candidate Flow Policy"
            },
            "latency_profiling_ms": {
                "mean_ms": round(float(np.mean(latencies_l7)), 3),
                "p50_ms": round(float(np.percentile(latencies_l7, 50)), 3),
                "p95_ms": round(float(np.percentile(latencies_l7, 95)), 3),
                "p99_ms": round(float(np.percentile(latencies_l7, 99)), 3),
            }
        },
        "http_benchmark_metrics": {},
        "cicids2017_corpus_metrics": {}
    }

    # Format HTTP benchmark metrics
    for ckey, counts in results_http.items():
        tot_att = counts["tp"] + counts["fn"]
        tot_ben = counts["fp"] + counts["tn"]
        rec = counts["tp"] / tot_att if tot_att > 0 else 0.0
        fpr = counts["fp"] / tot_ben if tot_ben > 0 else 0.0
        blk_rec = counts["block_tp"] / tot_att if tot_att > 0 else 0.0
        blk_fpr = counts["block_fp"] / tot_ben if tot_ben > 0 else 0.0

        out_metrics["http_benchmark_metrics"][ckey] = {
            "containment_recall": round(rec, 5),
            "containment_recall_ci_95": list(wilson_score_interval(counts["tp"], tot_att)),
            "simulated_block_recall": round(blk_rec, 5),
            "simulated_block_recall_ci_95": list(wilson_score_interval(counts["block_tp"], tot_att)),
            "false_positive_rate": round(fpr, 5),
            "false_positive_rate_ci_95": list(wilson_score_interval(counts["fp"], tot_ben)),
            "simulated_block_fpr": round(blk_fpr, 5),
            "simulated_block_fpr_ci_95": list(wilson_score_interval(counts["block_fp"], tot_ben)),
            "confusion": counts
        }

    # Format CICIDS2017 corpus metrics
    for skey, sdata in corpus_results.items():
        out_metrics["cicids2017_corpus_metrics"][skey] = {
            "total_flows": sdata["total_flows"],
            "attack_flows": sdata["attack_flows"],
            "benign_flows": sdata["benign_flows"],
            "configs": {}
        }
        tot_att = sdata["attack_flows"]
        tot_ben = sdata["benign_flows"]

        for ckey, counts in sdata["configs"].items():
            rec = counts["tp"] / tot_att if tot_att > 0 else 0.0
            fpr = counts["fp"] / tot_ben if tot_ben > 0 else 0.0
            blk_rec = counts["block_tp"] / tot_att if tot_att > 0 else 0.0
            blk_fpr = counts["block_fp"] / tot_ben if tot_ben > 0 else 0.0

            out_metrics["cicids2017_corpus_metrics"][skey]["configs"][ckey] = {
                "containment_recall": round(rec, 5),
                "containment_recall_ci_95": list(wilson_score_interval(counts["tp"], tot_att)),
                "simulated_block_recall": round(blk_rec, 5),
                "simulated_block_recall_ci_95": list(wilson_score_interval(counts["block_tp"], tot_att)),
                "false_positive_rate": round(fpr, 5),
                "false_positive_rate_ci_95": list(wilson_score_interval(counts["fp"], tot_ben)),
                "simulated_block_fpr": round(blk_fpr, 5),
                "simulated_block_fpr_ci_95": list(wilson_score_interval(counts["block_fp"], tot_ben)),
                "confusion": counts
            }

    # Write policy_comparison_metrics.json
    out_metrics_file = CURRENT_DIR / "policy_comparison_metrics.json"
    with open(out_metrics_file, "w") as f:
        json.dump(out_metrics, f, indent=2)
    print(f"\n[OUTPUT] Saved Phase 6 policy comparison metrics to:\n  {out_metrics_file}")

    # Write per_attack_confusion_matrices.json
    per_attack_out = {
        "metadata": {
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "notice": "All block counts represent simulated policy decisions. Zero Windows Firewall rules were created."
        },
        "http_attack_categories": per_category_http,
        "flow_corpus_slices": {skey: sdata["configs"] for skey, sdata in corpus_results.items()}
    }

    out_cm_file = CURRENT_DIR / "per_attack_confusion_matrices.json"
    with open(out_cm_file, "w") as f:
        json.dump(per_attack_out, f, indent=2)
    print(f"[OUTPUT] Saved Phase 6 per-attack confusion matrices to:\n  {out_cm_file}")


if __name__ == "__main__":
    run_phase6_comparison()
