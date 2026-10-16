#!/usr/bin/env python3
"""
GATE-1 Evaluation Reproduction and Model Comparison Pipeline
Evaluates baseline models (rf_v2, rf_v1, xgb_v2, stacking) on held-out CICIDS2017 splits.
"""
import sys
import os
import json
import time
from pathlib import Path
import numpy as np
import pandas as pd
import joblib

# Ensure ai-engine is in path
base_dir = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(base_dir))

from utils.features import FEATURE_NAMES, LABEL_MAP, LABEL_NAMES, RAW_LABEL_TO_TARGET, prepare_features
from evaluation.evaluate_model import compute_classification_metrics

def evaluate_model_on_data(pipe, X, y, label_name):
    y_pred = pipe.predict(X)
    proba = pipe.predict_proba(X) if hasattr(pipe, "predict_proba") else None
    
    # Binary metrics: Negative (0) = BENIGN, Positive (>0) = Attack
    y_true_str = [LABEL_NAMES.get(i, "BENIGN") for i in y]
    y_pred_str = [LABEL_NAMES.get(i, "BENIGN") for i in y_pred]
    
    metrics = compute_classification_metrics(y_true_str, y_pred_str)
    
    # Specific attack-vs-benign slice metrics
    # Target class label index
    target_idx = LABEL_MAP.get(label_name, 4)
    
    # Benign slice (actual = 0)
    benign_mask = (y == 0)
    attack_mask = (y == target_idx)
    
    # False positives on benign: benign samples predicted as attack (or specifically as target_idx)
    benign_preds = y_pred[benign_mask]
    fp_any_attack = np.sum(benign_preds != 0)
    fp_target = np.sum(benign_preds == target_idx)
    total_benign = np.sum(benign_mask)
    fpr = float(fp_any_attack / total_benign) if total_benign > 0 else 0.0
    fpr_target = float(fp_target / total_benign) if total_benign > 0 else 0.0
    
    # Recall on target attack
    attack_preds = y_pred[attack_mask]
    tp_target = np.sum(attack_preds == target_idx)
    tp_any_attack = np.sum(attack_preds != 0)
    total_attack = np.sum(attack_mask)
    recall_target = float(tp_target / total_attack) if total_attack > 0 else 0.0
    recall_any = float(tp_any_attack / total_attack) if total_attack > 0 else 0.0
    
    return {
        "total_samples": len(y),
        "benign_samples": int(total_benign),
        "attack_samples": int(total_attack),
        "fpr_any_attack": round(fpr, 4),
        "fpr_target": round(fpr_target, 4),
        "recall_target": round(recall_target, 4),
        "recall_any_attack": round(recall_any, 4),
        "confusion_binary": metrics["confusionMatrixBinary"],
        "macro_metrics": metrics
    }

def load_cicids_slice(csv_path, label_col, attack_raw_name, offset=60000, n_per_class=1000):
    print(f"Loading {csv_path.name} with offset {offset} and n={n_per_class} per class...")
    # Read chunked
    chunks = pd.read_csv(csv_path, chunksize=10000)
    collected_benign = []
    collected_attack = []
    
    benign_skipped = 0
    attack_skipped = 0
    
    for chunk in chunks:
        chunk.columns = chunk.columns.str.strip()
        l_col = next((c for c in chunk.columns if "label" in c.lower()), "Label")
        
        benigns = chunk[chunk[l_col].astype(str).str.strip().str.upper() == "BENIGN"]
        attacks = chunk[chunk[l_col].astype(str).str.strip() == attack_raw_name]
        
        # Skip offset for benign
        if benign_skipped < offset:
            skip_now = min(len(benigns), offset - benign_skipped)
            benigns = benigns.iloc[skip_now:]
            benign_skipped += skip_now
            
        if len(benigns) > 0 and sum(len(x) for x in collected_benign) < n_per_class:
            need = n_per_class - sum(len(x) for x in collected_benign)
            collected_benign.append(benigns.head(need))
            
        # Skip offset for attacks
        if attack_skipped < offset:
            skip_now = min(len(attacks), offset - attack_skipped)
            attacks = attacks.iloc[skip_now:]
            attack_skipped += skip_now
            
        if len(attacks) > 0 and sum(len(x) for x in collected_attack) < n_per_class:
            need = n_per_class - sum(len(x) for x in collected_attack)
            collected_attack.append(attacks.head(need))
            
        if sum(len(x) for x in collected_benign) >= n_per_class and sum(len(x) for x in collected_attack) >= n_per_class:
            break
            
    df_benign = pd.concat(collected_benign, ignore_index=True) if collected_benign else pd.DataFrame()
    df_attack = pd.concat(collected_attack, ignore_index=True) if collected_attack else pd.DataFrame()
    
    df_combined = pd.concat([df_benign, df_attack], ignore_index=True)
    X, y = prepare_features(df_combined)
    return X, y, len(df_benign), len(df_attack)

def main():
    models_dir = base_dir / "models"
    data_dir = base_dir / "datasets" / "cicids2017"
    
    models = {
        "rf_v2": models_dir / "rf_classifier_cicids_v2.pkl",
        "rf_v1": models_dir / "rf_classifier_cicids.pkl",
        "xgb_v2": models_dir / "xgb_classifier_cicids_v2.pkl",
        "stacking": models_dir / "stacking_classifier_cicids.pkl"
    }
    
    loaded_pipes = {}
    for mname, mpath in models.items():
        if mpath.exists():
            loaded_pipes[mname] = joblib.load(mpath)
            print(f"Loaded {mname} from {mpath.name}")
            
    # Test 1: PortScan (offset 60000, 100 per class vs 1000 per class)
    ps_file = data_dir / "Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv"
    ddos_file = data_dir / "Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv"
    
    print("\n" + "="*60)
    print("Evaluating 200 samples (100 Benign, 100 Attack) at offset 60,000")
    print("="*60)
    
    if ps_file.exists():
        X_ps_200, y_ps_200, n_b, n_a = load_cicids_slice(ps_file, "Label", "PortScan", offset=60000, n_per_class=100)
        for mname, pipe in loaded_pipes.items():
            res = evaluate_model_on_data(pipe, X_ps_200, y_ps_200, "Port Scan")
            print(f"[{mname}] PortScan (200 samples): Recall={res['recall_target']*100:.1f}%, FPR={res['fpr_any_attack']*100:.1f}%, CM={res['confusion_binary']}")
            
    if ddos_file.exists():
        X_ddos_200, y_ddos_200, n_b, n_a = load_cicids_slice(ddos_file, "Label", "DDoS", offset=60000, n_per_class=100)
        for mname, pipe in loaded_pipes.items():
            res = evaluate_model_on_data(pipe, X_ddos_200, y_ddos_200, "DDoS")
            print(f"[{mname}] DDoS (200 samples): Recall={res['recall_target']*100:.1f}%, FPR={res['fpr_any_attack']*100:.1f}%, CM={res['confusion_binary']}")
            
    print("\n" + "="*60)
    print("Evaluating 2,000 samples (1,000 Benign, 1,000 Attack) at offset 60,000")
    print("="*60)
    
    if ps_file.exists():
        X_ps_2k, y_ps_2k, n_b, n_a = load_cicids_slice(ps_file, "Label", "PortScan", offset=60000, n_per_class=1000)
        for mname, pipe in loaded_pipes.items():
            res = evaluate_model_on_data(pipe, X_ps_2k, y_ps_2k, "Port Scan")
            print(f"[{mname}] PortScan (2,000 samples): Recall={res['recall_target']*100:.1f}%, FPR={res['fpr_any_attack']*100:.1f}%, CM={res['confusion_binary']}")
            
    if ddos_file.exists():
        X_ddos_2k, y_ddos_2k, n_b, n_a = load_cicids_slice(ddos_file, "Label", "DDoS", offset=60000, n_per_class=1000)
        for mname, pipe in loaded_pipes.items():
            res = evaluate_model_on_data(pipe, X_ddos_2k, y_ddos_2k, "DDoS")
            print(f"[{mname}] DDoS (2,000 samples): Recall={res['recall_target']*100:.1f}%, FPR={res['fpr_any_attack']*100:.1f}%, CM={res['confusion_binary']}")

if __name__ == "__main__":
    main()
