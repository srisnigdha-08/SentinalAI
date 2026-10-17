"""
SentinelAI Phase 13: Feature Leakage Audit (time_of_day_* & Temporal/Identifier Leakage)
Location: ai-engine/experiments/gate1_phase13_shift_and_leakage/audit_feature_leakage.py
"""

import sys
import os
import json
import numpy as np
import pandas as pd
from pathlib import Path
from sklearn.metrics import roc_auc_score, recall_score, confusion_matrix
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.pipeline import Pipeline
import joblib

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from utils.features import FEATURE_NAMES, LABEL_NAMES

def run_leakage_audit():
    out_dir = Path(__file__).resolve().parent
    out_dir.mkdir(parents=True, exist_ok=True)
    
    train_path = Path("ai-engine/experiments/gate1_phase10_detector_recovery/partition_train_multicorpus_v2.parquet")
    val_path = Path("ai-engine/experiments/gate1_phase12_evidence_repair/validation_split.parquet")
    cand_v2_path = Path("ai-engine/experiments/gate1_phase10_detector_recovery/candidate_rf_multicorpus_v2_fixed.pkl")
    
    print(f"Loading training data: {train_path}...")
    df_train = pd.read_parquet(train_path)
    print(f"Loading validation data: {val_path}...")
    df_val = pd.read_parquet(val_path)
    
    # 1. Feature importances in Candidate V2
    window_features = ["init_win_bytes_forward", "init_win_bytes_backward"]
    schema_f_feats = [f for f in FEATURE_NAMES if f not in window_features]
    
    cand_v2 = joblib.load(cand_v2_path)
    rf_v2 = cand_v2.named_steps["rf"] if hasattr(cand_v2, "named_steps") else cand_v2
    importances = rf_v2.feature_importances_
    
    ranked_importances = sorted(
        [{"feature": schema_f_feats[i], "index": i, "importance": float(imp)} for i, imp in enumerate(importances)],
        key=lambda x: x["importance"],
        reverse=True
    )
    for rank, item in enumerate(ranked_importances, 1):
        item["rank"] = rank
        
    v2_time_rankings = {
        item["feature"]: item for item in ranked_importances if "time_of_day" in item["feature"] or item["feature"] == "payload_entropy"
    }
    
    print("\n--- Candidate V2 Top Feature Importances ---")
    for r in ranked_importances[:10]:
        print(f"Rank {r['rank']:2d}: {r['feature']:25s} = {r['importance']*100:.2f}%")
    print("--- Time features ---")
    for f, item in v2_time_rankings.items():
        print(f"Rank {item['rank']:2d}: {item['feature']:25s} = {item['importance']*100:.2f}%")
        
    # 2. Compute ROC-AUC of time_of_day_sin / time_of_day_cos
    print("\nComputing per-class and binary ROC-AUC of time_of_day_* features...")
    y_binary = (df_train["target_class"] > 0).astype(int)
    
    # Combined time vector magnitude / L2 or logistic regression AUC
    sin_vals = df_train["time_of_day_sin"].values
    cos_vals = df_train["time_of_day_cos"].values
    
    # Individual AUCs
    auc_sin_binary = float(roc_auc_score(y_binary, sin_vals))
    auc_cos_binary = float(roc_auc_score(y_binary, cos_vals))
    
    # If feature is anti-correlated, directional AUC is max(auc, 1-auc)
    auc_sin_binary_dir = max(auc_sin_binary, 1.0 - auc_sin_binary)
    auc_cos_binary_dir = max(auc_cos_binary, 1.0 - auc_cos_binary)
    
    # 2D time projection (hour of day)
    # Recover hour: hour = (atan2(sin, cos) / 2pi) * 24 mod 24
    hours = (np.arctan2(sin_vals, cos_vals) / (2 * np.pi) * 24.0) % 24.0
    
    per_class_auc = {}
    classes_present = sorted(df_train["target_class"].unique())
    for c in classes_present:
        if c == 0:
            continue
        c_int = int(c)
        c_name = LABEL_NAMES.get(c_int, f"Class_{c_int}")
        y_c = (df_train["target_class"] == c).astype(int)
        
        auc_sin = float(roc_auc_score(y_c, sin_vals))
        auc_cos = float(roc_auc_score(y_c, cos_vals))
        auc_sin_dir = max(auc_sin, 1.0 - auc_sin)
        auc_cos_dir = max(auc_cos, 1.0 - auc_cos)
        
        # Attack hour distribution
        attack_hours = hours[df_train["target_class"] == c]
        benign_hours = hours[df_train["target_class"] == 0]
        
        per_class_auc[c_name] = {
            "target_class": c_int,
            "auc_sin": round(auc_sin, 4),
            "auc_cos": round(auc_cos, 4),
            "auc_sin_directional": round(auc_sin_dir, 4),
            "auc_cos_directional": round(auc_cos_dir, 4),
            "attack_hour_mean": round(float(np.mean(attack_hours)), 2),
            "attack_hour_std": round(float(np.std(attack_hours)), 2),
            "benign_hour_mean": round(float(np.mean(benign_hours)), 2),
            "benign_hour_std": round(float(np.std(benign_hours)), 2),
        }
        print(f"Class {c_int} ({c_name:20s}): sin AUC={auc_sin_dir:.4f}, cos AUC={auc_cos_dir:.4f}, Mean Hour: Attack={np.mean(attack_hours):.1f}h vs Benign={np.mean(benign_hours):.1f}h")

    # 3. Feature Ablation: Train with vs without time_of_day features
    print("\n--- Running Feature Ablation on Training Data ---")
    timing_features = [
        "flow_duration", "flow_iat_mean", "flow_iat_std", "flow_iat_max", "flow_iat_min",
        "fwd_iat_total", "fwd_iat_mean", "fwd_iat_std", "fwd_iat_max", "fwd_iat_min",
        "bwd_iat_total", "bwd_iat_mean", "bwd_iat_std", "bwd_iat_max", "bwd_iat_min"
    ]
    rate_features = ["flow_bytes_per_sec", "flow_packets_per_sec"]
    length_features = ["total_len_fwd_packets", "total_len_bwd_packets"]

    def prepare_x(df, feature_list):
        df_c = df.copy()
        for tf in timing_features + rate_features + length_features:
            if tf in feature_list and tf in df_c.columns:
                df_c[tf] = np.log1p(np.maximum(df_c[tf].values, 0.0))
        fwd_pkts = np.maximum(df_c["total_fwd_packets"].values, 1.0)
        bwd_pkts = np.maximum(df_c["total_bwd_packets"].values, 1.0)
        df_c["fwd_header_len"] = df_c["fwd_header_len"].values / fwd_pkts
        df_c["bwd_header_len"] = df_c["bwd_header_len"].values / bwd_pkts
        X = df_c[feature_list].values.astype(np.float32)
        X = np.nan_to_num(X, nan=0.0, posinf=1e9, neginf=-1e9)
        return X

    # Features without time_of_day
    clean_49_feats = [f for f in schema_f_feats if f not in ("time_of_day_sin", "time_of_day_cos")]
    print(f"Schema F features: {len(schema_f_feats)}, Clean features (without time): {len(clean_49_feats)}")

    # Downsample train set for fast ablation comparison (50k rows: stratified)
    print("Preparing stratified 60k ablation subset from train split...")
    sub_train = df_train.groupby("target_class", group_keys=False).apply(
        lambda g: g.sample(min(len(g), 10000), random_state=42)
    ).reset_index(drop=True)
    
    y_sub_train = sub_train["target_class"].values.astype(int)
    y_val = df_val["target_class"].values.astype(int)
    
    # Train Model A (With time features, 51 feats)
    X_train_51 = prepare_x(sub_train, schema_f_feats)
    X_val_51 = prepare_x(df_val, schema_f_feats)
    
    print("Training Model A (WITH time_of_day_*)...")
    clf_51 = Pipeline([
        ("scaler", StandardScaler()),
        ("rf", RandomForestClassifier(n_estimators=100, max_depth=16, random_state=42, n_jobs=-1))
    ])
    clf_51.fit(X_train_51, y_sub_train)
    
    # Train Model B (WITHOUT time_of_day_*, 49 feats)
    X_train_49 = prepare_x(sub_train, clean_49_feats)
    X_val_49 = prepare_x(df_val, clean_49_feats)
    
    print("Training Model B (WITHOUT time_of_day_*)...")
    clf_49 = Pipeline([
        ("scaler", StandardScaler()),
        ("rf", RandomForestClassifier(n_estimators=100, max_depth=16, random_state=42, n_jobs=-1))
    ])
    clf_49.fit(X_train_49, y_sub_train)
    
    # Evaluate both on validation split (threshold P >= 0.70)
    def eval_model(pipeline, X_val, y_val, feats):
        probs = pipeline.predict_proba(X_val)
        classes_ = list(pipeline.named_steps["rf"].classes_)
        class_to_idx = {c: i for i, c in enumerate(classes_)}
        
        results = {}
        # Per class recall at P >= 0.70
        for c in sorted(list(set(y_val))):
            c_int = int(c)
            mask_c = (y_val == c_int)
            total_c = int(np.sum(mask_c))
            c_name = LABEL_NAMES.get(c_int, f"Class_{c_int}")
            if c_int == 0:
                # Benign FPR at P >= 0.70 for any attack class
                attack_indices = [idx for cls_val, idx in class_to_idx.items() if cls_val != 0]
                if attack_indices:
                    max_attack_prob = np.max(probs[mask_c][:, attack_indices], axis=1)
                    fp = int(np.sum(max_attack_prob >= 0.70))
                    fpr = float(fp / total_c)
                else:
                    fp = 0
                    fpr = 0.0
                results["BENIGN"] = {"count": total_c, "false_positives": fp, "fpr": round(fpr, 6)}
            else:
                if c_int in class_to_idx:
                    col_idx = class_to_idx[c_int]
                    preds_c = (probs[mask_c, col_idx] >= 0.70)
                    tp = int(np.sum(preds_c))
                    rec = float(tp / total_c) if total_c > 0 else 0.0
                else:
                    tp = 0
                    rec = 0.0
                results[c_name] = {"target_class": c_int, "count": total_c, "true_positives": tp, "recall": round(rec, 4)}
        return results

    res_with_time = eval_model(clf_51, X_val_51, y_val, schema_f_feats)
    res_without_time = eval_model(clf_49, X_val_49, y_val, clean_49_feats)
    
    print("\n--- Ablation Comparison on Validation Split (P >= 0.70) ---")
    print(f"{'Class':22s} | {'With Time Recall':17s} | {'Without Time Recall':19s} | {'Delta':8s}")
    print("-" * 75)
    ablation_summary = {}
    for k in sorted(res_with_time.keys()):
        if k == "BENIGN":
            fpr_with = res_with_time[k]["fpr"] * 100
            fpr_without = res_without_time[k]["fpr"] * 100
            delta = fpr_without - fpr_with
            print(f"{'BENIGN (FPR)':22s} | {fpr_with:15.3f}% | {fpr_without:17.3f}% | {delta:+7.3f}%")
            ablation_summary[k] = {"with_time_fpr": fpr_with, "without_time_fpr": fpr_without, "delta_fpr": delta}
        else:
            rec_with = res_with_time[k]["recall"] * 100
            rec_without = res_without_time[k]["recall"] * 100
            delta = rec_without - rec_with
            print(f"{k:22s} | {rec_with:15.2f}% | {rec_without:17.2f}% | {delta:+7.2f}%")
            ablation_summary[k] = {"with_time_recall": rec_with, "without_time_recall": rec_without, "delta_recall": delta}
            
    # Check predictor.py train/serve skew
    predictor_skew_findings = {
        "wall_clock_fallback": "predictor.py extract_features_from_record() calls compute_time_of_day(None) -> datetime.now() if timestamp missing",
        "leakage_mechanism": "Lab datasets had attack campaigns scheduled during fixed daytime hours; random forest splits on time_of_day to memorize capture schedule rather than flow behavior",
        "skew_impact": "At inference time, benign traffic during attack hours triggers false alarms, while attack traffic outside lab hours escapes detection",
        "remediation_decision": "Candidate V3 MUST drop time_of_day_sin and time_of_day_cos from the feature schema completely to ensure invariant network flow classification"
    }

    report = {
        "feature_importances_candidate_v2": ranked_importances,
        "time_of_day_rankings_v2": v2_time_rankings,
        "auc_time_of_day_binary": {
            "sin_auc": round(auc_sin_binary, 4),
            "cos_auc": round(auc_cos_binary, 4),
            "sin_directional_auc": round(auc_sin_binary_dir, 4),
            "cos_directional_auc": round(auc_cos_binary_dir, 4),
        },
        "per_class_auc_time_of_day": per_class_auc,
        "ablation_results": ablation_summary,
        "predictor_skew_findings": predictor_skew_findings
    }
    
    out_file = out_dir / "feature_leakage_audit.json"
    with open(out_file, "w") as f:
        json.dump(report, f, indent=2)
    print(f"\nAudit complete. Results written to {out_file}")

if __name__ == "__main__":
    run_leakage_audit()
