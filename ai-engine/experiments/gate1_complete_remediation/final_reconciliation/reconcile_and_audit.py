#!/usr/bin/env python3
"""
SentinelAI GATE-1 Final Metrics Reconciliation and Policy Recall Audit Script
Read-only analysis and calculation of exact metrics, confusion matrices, and Wilson intervals.
Writes exclusively to ai-engine/experiments/gate1_complete_remediation/final_reconciliation/
"""

import os
import sys
import json
import math
from pathlib import Path

# Paths
current_dir = Path(__file__).resolve().parent
eval_results_path = current_dir.parent.parent / "gate1_evaluation" / "evaluation_results.json"
models_dir = current_dir.parent.parent.parent / "models"

def wilson_score_interval(successes: int, total: int, confidence: float = 0.95):
    """
    Computes exact Wilson score confidence interval for a binomial proportion.
    """
    if total == 0:
        return (0.0, 0.0)
    z = 1.959963984540054  # 95% two-sided normal quantile
    p = float(successes) / float(total)
    denominator = 1.0 + (z**2) / total
    centre = p + (z**2) / (2.0 * total)
    spread = z * math.sqrt((p * (1.0 - p) + (z**2) / (4.0 * total)) / total)
    lower = max(0.0, (centre - spread) / denominator)
    upper = min(1.0, (centre + spread) / denominator)
    return (lower, upper)

def compute_metrics(tn, fp, fn, tp):
    total = tn + fp + fn + tp
    neg = tn + fp
    pos = tp + fn
    
    fpr = fp / neg if neg > 0 else 0.0
    fnr = fn / pos if pos > 0 else 0.0
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / pos if pos > 0 else 0.0
    f1 = 2.0 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0.0
    accuracy = (tp + tn) / total if total > 0 else 0.0
    
    fpr_ci = wilson_score_interval(fp, neg)
    recall_ci = wilson_score_interval(tp, pos)
    
    return {
        "confusion_matrix": {
            "TN": tn,
            "FP": fp,
            "FN": fn,
            "TP": tp,
            "total_negatives": neg,
            "total_positives": pos,
            "total_samples": total
        },
        "rates": {
            "FPR": round(fpr, 6),
            "FNR": round(fnr, 6),
            "precision": round(precision, 6),
            "recall": round(recall, 6),
            "f1_score": round(f1, 6),
            "accuracy": round(accuracy, 6)
        },
        "confidence_intervals_95": {
            "FPR": {
                "point_estimate": round(fpr, 6),
                "lower": round(fpr_ci[0], 6),
                "upper": round(fpr_ci[1], 6),
                "formatted": f"[{fpr_ci[0]*100:.3f}%, {fpr_ci[1]*100:.3f}%]"
            },
            "recall": {
                "point_estimate": round(recall, 6),
                "lower": round(recall_ci[0], 6),
                "upper": round(recall_ci[1], 6),
                "formatted": f"[{recall_ci[0]*100:.3f}%, {recall_ci[1]*100:.3f}%]"
            }
        }
    }

def main():
    print("Loading evaluation results from:", eval_results_path)
    with open(eval_results_path, "r", encoding="utf-8") as f:
        raw_eval = json.load(f)
        
    canonical_results = {}
    policy_audit = {}
    ci_recalc = {}
    
    # 1. Monday Pure Benign (10,000 samples)
    mon_data = raw_eval["monday_pure_benign"]
    mon_rf_cm = mon_data["raw_rf"]["confusion"]
    mon_comp_cm = mon_data["composite_predictor"]["confusion"]
    mon_pol_cm = mon_data["policy_action"]["confusion"]
    
    canonical_results["monday_pure_benign_10k"] = {
        "dataset_name": "Monday-WorkingHours.pcap_ISCX.csv",
        "sample_selection": "First 10,000 pure BENIGN flows from capture",
        "row_range": "rows 0 to 10,000 (after column strip & BENIGN filter)",
        "ground_truth_counts": {"BENIGN": 10000, "ATTACK": 0},
        "raw_rf": compute_metrics(mon_rf_cm["TN"], mon_rf_cm["FP"], mon_rf_cm["FN"], mon_rf_cm["TP"]),
        "composite_predictor": compute_metrics(mon_comp_cm["TN"], mon_comp_cm["FP"], mon_comp_cm["FN"], mon_comp_cm["TP"]),
        "policy_action": compute_metrics(mon_pol_cm["TN"], mon_pol_cm["FP"], mon_pol_cm["FN"], mon_pol_cm["TP"]),
        "predictions_breakdown": mon_data["raw_rf"]["predictions"],
        "composite_predictions_breakdown": mon_data["composite_predictor"]["predictions"],
        "policy_actions_breakdown": mon_data["policy_action"]["actions"],
        "anomalies_flagged_count": mon_data["composite_predictor"]["anomalies_flagged"]
    }
    
    # 2. Friday DDoS (2,000 samples: 1,000 benign, 1,000 DDoS)
    ddos_data = raw_eval["friday_ddos"]
    ddos_rf_cm = ddos_data["raw_rf"]["confusion"]
    ddos_comp_cm = ddos_data["composite_predictor"]["confusion"]
    ddos_pol_cm = ddos_data["policy_action"]["confusion"]
    
    canonical_results["friday_ddos_2k"] = {
        "dataset_name": "Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv",
        "sample_selection": "1,000 ambient BENIGN + 1,000 DDoS attack flows at offset 30,000",
        "row_range": "offset 30,000 in Friday DDoS capture",
        "ground_truth_counts": {"BENIGN": 1000, "DDoS": 1000},
        "raw_rf": compute_metrics(ddos_rf_cm["TN"], ddos_rf_cm["FP"], ddos_rf_cm["FN"], ddos_rf_cm["TP"]),
        "composite_predictor": compute_metrics(ddos_comp_cm["TN"], ddos_comp_cm["FP"], ddos_comp_cm["FN"], ddos_comp_cm["TP"]),
        "policy_action": compute_metrics(ddos_pol_cm["TN"], ddos_pol_cm["FP"], ddos_pol_cm["FN"], ddos_pol_cm["TP"]),
        "predictions_breakdown": ddos_data["raw_rf"]["predictions"],
        "composite_predictions_breakdown": ddos_data["composite_predictor"]["predictions"],
        "policy_actions_breakdown": ddos_data["policy_action"]["actions"],
        "anomalies_flagged_count": ddos_data["composite_predictor"]["anomalies_flagged"]
    }
    
    # 3. Friday PortScan (2,000 samples: 1,000 benign, 1,000 PortScan)
    ps_data = raw_eval["friday_portscan"]
    ps_rf_cm = ps_data["raw_rf"]["confusion"]
    ps_comp_cm = ps_data["composite_predictor"]["confusion"]
    ps_pol_cm = ps_data["policy_action"]["confusion"]
    
    canonical_results["friday_portscan_2k"] = {
        "dataset_name": "Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv",
        "sample_selection": "1,000 ambient BENIGN + 1,000 PortScan attack flows at offset 30,000",
        "row_range": "offset 30,000 in Friday PortScan capture",
        "ground_truth_counts": {"BENIGN": 1000, "PortScan": 1000},
        "raw_rf": compute_metrics(ps_rf_cm["TN"], ps_rf_cm["FP"], ps_rf_cm["FN"], ps_rf_cm["TP"]),
        "composite_predictor": compute_metrics(ps_comp_cm["TN"], ps_comp_cm["FP"], ps_comp_cm["FN"], ps_comp_cm["TP"]),
        "policy_action": compute_metrics(ps_pol_cm["TN"], ps_pol_cm["FP"], ps_pol_cm["FN"], ps_pol_cm["TP"]),
        "predictions_breakdown": ps_data["raw_rf"]["predictions"],
        "composite_predictions_breakdown": ps_data["composite_predictor"]["predictions"],
        "policy_actions_breakdown": ps_data["policy_action"]["actions"],
        "anomalies_flagged_count": ps_data["composite_predictor"]["anomalies_flagged"]
    }
    
    # 4. Policy Recall Audit Analysis
    policy_audit = {
        "audit_objective": "Reconcile why policy action recall diverges drastically from raw classifier recall",
        "operational_definitions": {
            "Raw_Classifier_Detection": "Model outputs a class label other than BENIGN (cls != 0)",
            "Composite_Label_Detection": "Predictor outputs predictedClass other than BENIGN (includes 'Unknown')",
            "Policy_Action_Detection": "Runtime policy assigns action in ['BLOCK', 'MONITOR'] (threatScore >= 0.70)",
            "Autonomous_Block_Detection": "Runtime policy assigns action == 'BLOCK' (threatScore >= 0.92)"
        },
        "datasets_audited": {
            "friday_ddos": {
                "ground_truth_attacks": 1000,
                "raw_rf_recall": 0.9990,
                "raw_rf_detected_count": 999,
                "composite_recall": 0.9990,
                "composite_detected_count": 999,
                "actions_on_attack_flows": {
                    "BLOCK": 5,
                    "MONITOR": 761,
                    "ALLOW": 234
                },
                "policy_containment_TP": 766,
                "policy_containment_FN": 234,
                "policy_containment_recall": 0.7660,
                "autonomous_block_TP": 5,
                "autonomous_block_FN": 995,
                "autonomous_block_recall": 0.0050,
                "mechanism_explanation": "DDoS LOIC generates massive packet bursts. Isolation Forest signals are active for 76.6% of flows, pushing 0.7*rf + 0.3*if >= 0.70 (MONITOR). However, 234 flows have low anomaly signals, yielding threatScore < 0.70, resulting in action=ALLOW."
            },
            "friday_portscan": {
                "ground_truth_attacks": 1000,
                "raw_rf_recall": 0.9850,
                "raw_rf_detected_count": 985,
                "composite_recall": 0.9850,
                "composite_detected_count": 985,
                "actions_on_attack_flows": {
                    "BLOCK": 0,
                    "MONITOR": 74,
                    "ALLOW": 926
                },
                "policy_containment_TP": 74,
                "policy_containment_FN": 926,
                "policy_containment_recall": 0.0740,
                "autonomous_block_TP": 0,
                "autonomous_block_FN": 1000,
                "autonomous_block_recall": 0.0000,
                "mechanism_explanation": "PortScan reconnaissance packets look nearly identical in packet length and timing to normal connection attempts. Isolation Forest scores them as inliers (if_sig = 0.0). Because score = 0.7*rf_s + 0.3*0.0, the maximum possible threat score is 0.70 (at 100% RF confidence). 926 attack flows had threatScore < 0.70, resulting in action=ALLOW. Only 74 triggered MONITOR, and exactly 0 triggered BLOCK."
            },
            "monday_pure_benign": {
                "ground_truth_benign": 10000,
                "raw_rf_FPR": 0.0045,
                "raw_rf_FP_count": 45,
                "composite_FPR": 0.1373,
                "composite_FP_count": 1373,
                "actions_on_benign_flows": {
                    "BLOCK": 0,
                    "MONITOR": 0,
                    "ALLOW": 10000
                },
                "policy_containment_FP": 0,
                "policy_containment_TN": 10000,
                "policy_containment_FPR": 0.0000,
                "mechanism_explanation": "Although Isolation Forest flagged 1,328 benign flows as 'Unknown', threatScore was set to 0.55. Since 0.55 < MONITOR_THRESHOLD (0.70) and 0.55 < BLOCK_THRESHOLD (0.92), all 10,000 benign flows received action=ALLOW."
            }
        },
        "critical_governance_verdict": "Zero policy false positives on benign traffic was achieved largely because the containment policy thresholds (0.70 for MONITOR, 0.92 for BLOCK) and the composite weighting (0.7*rf + 0.3*if) aggressively suppress threat scores to ALLOW. Consequently, the system allowed 92.6% of PortScan attacks and 23.4% of DDoS attacks to pass unmitigated. Zero false blocking is NOT proof of containment safety when policy recall drops to 7.4% on PortScan."
    }
    
    # 5. Exact Confidence Interval Recalculation
    ci_recalc = {
        "methodology": "Wilson Score Interval without continuity correction (z = 1.959964)",
        "recalculations": {
            "monday_raw_rf_FPR": {
                "numerator_FP": 45,
                "denominator_NEG": 10000,
                "point_estimate": 45 / 10000,
                "ci_lower": wilson_score_interval(45, 10000)[0],
                "ci_upper": wilson_score_interval(45, 10000)[1],
                "event_measured": "Raw Random Forest classifies a benign flow as an attack class"
            },
            "monday_composite_FPR": {
                "numerator_FP": 1373,
                "denominator_NEG": 10000,
                "point_estimate": 1373 / 10000,
                "ci_lower": wilson_score_interval(1373, 10000)[0],
                "ci_upper": wilson_score_interval(1373, 10000)[1],
                "event_measured": "Composite predictor outputs non-BENIGN (1,328 Unknown + 45 Attack) on benign flow"
            },
            "monday_policy_FPR": {
                "numerator_FP": 0,
                "denominator_NEG": 10000,
                "point_estimate": 0.0,
                "ci_lower": wilson_score_interval(0, 10000)[0],
                "ci_upper": wilson_score_interval(0, 10000)[1],
                "event_measured": "Policy engine assigns MONITOR or BLOCK to a benign flow"
            },
            "friday_ddos_raw_rf_FPR": {
                "numerator_FP": 0,
                "denominator_NEG": 1000,
                "point_estimate": 0.0,
                "ci_lower": wilson_score_interval(0, 1000)[0],
                "ci_upper": wilson_score_interval(0, 1000)[1],
                "event_measured": "Raw RF classifies ambient Friday benign flow as DDoS or other attack"
            },
            "friday_ddos_raw_rf_recall": {
                "numerator_TP": 999,
                "denominator_POS": 1000,
                "point_estimate": 999 / 1000,
                "ci_lower": wilson_score_interval(999, 1000)[0],
                "ci_upper": wilson_score_interval(999, 1000)[1],
                "event_measured": "Raw RF classifies a DDoS attack flow as DDoS (or any attack)"
            },
            "friday_ddos_policy_recall": {
                "numerator_TP": 766,
                "denominator_POS": 1000,
                "point_estimate": 766 / 1000,
                "ci_lower": wilson_score_interval(766, 1000)[0],
                "ci_upper": wilson_score_interval(766, 1000)[1],
                "event_measured": "Policy engine assigns MONITOR or BLOCK to a DDoS flow"
            },
            "friday_portscan_raw_rf_FPR": {
                "numerator_FP": 17,
                "denominator_NEG": 1000,
                "point_estimate": 17 / 1000,
                "ci_lower": wilson_score_interval(17, 1000)[0],
                "ci_upper": wilson_score_interval(17, 1000)[1],
                "event_measured": "Raw RF classifies ambient Friday benign flow as PortScan or other attack"
            },
            "friday_portscan_raw_rf_recall": {
                "numerator_TP": 985,
                "denominator_POS": 1000,
                "point_estimate": 985 / 1000,
                "ci_lower": wilson_score_interval(985, 1000)[0],
                "ci_upper": wilson_score_interval(985, 1000)[1],
                "event_measured": "Raw RF classifies a PortScan attack flow as PortScan (or any attack)"
            },
            "friday_portscan_policy_recall": {
                "numerator_TP": 74,
                "denominator_POS": 1000,
                "point_estimate": 74 / 1000,
                "ci_lower": wilson_score_interval(74, 1000)[0],
                "ci_upper": wilson_score_interval(74, 1000)[1],
                "event_measured": "Policy engine assigns MONITOR or BLOCK to a PortScan flow"
            }
        }
    }
    
    # Write output JSON files
    with open(current_dir / "canonical_evaluation_results.json", "w", encoding="utf-8") as f:
        json.dump(canonical_results, f, indent=2)
    print("Wrote canonical_evaluation_results.json")
    
    with open(current_dir / "policy_recall_audit.json", "w", encoding="utf-8") as f:
        json.dump(policy_audit, f, indent=2)
    print("Wrote policy_recall_audit.json")
    
    with open(current_dir / "confidence_interval_recalculation.json", "w", encoding="utf-8") as f:
        json.dump(ci_recalc, f, indent=2)
    print("Wrote confidence_interval_recalculation.json")

if __name__ == "__main__":
    main()
