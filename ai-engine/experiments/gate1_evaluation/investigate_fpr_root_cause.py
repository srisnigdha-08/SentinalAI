#!/usr/bin/env python3
"""
Deep Root Cause Analysis for DDoS False Positive Rate in SentinelAI
Compares raw RF predictions vs Isolation Forest anomaly overrides vs SentinelPredictor combined scores.
"""
import sys
import os
from pathlib import Path
import numpy as np
import pandas as pd
import joblib

base_dir = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(base_dir))

from utils.features import FEATURE_NAMES, LABEL_MAP, LABEL_NAMES, RAW_LABEL_TO_TARGET, extract_features_from_record
from inference.predictor import SentinelPredictor, ANOMALY_THRESHOLD

def main():
    predictor = SentinelPredictor()
    ddos_csv = base_dir / "datasets" / "cicids2017" / "Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv"
    ps_csv = base_dir / "datasets" / "cicids2017" / "Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv"
    monday_csv = base_dir / "datasets" / "cicids2017" / "Monday-WorkingHours.pcap_ISCX.csv"
    
    print("=== Loaded Models in SentinelPredictor ===")
    print(f"Classifier: {predictor.clf.__class__.__name__} ({predictor.model_type})")
    print(f"Isolation Forest: {predictor.ifo.__class__.__name__}")
    print(f"ANOMALY_THRESHOLD: {ANOMALY_THRESHOLD}")
    
    def analyze_benign_flows(csv_path, name, offset=60000, n_samples=500):
        print(f"\n--- Analyzing {n_samples} Benign Flows from {name} (offset={offset}) ---")
        chunks = pd.read_csv(csv_path, chunksize=10000)
        benigns = []
        skipped = 0
        for chunk in chunks:
            chunk.columns = chunk.columns.str.strip()
            l_col = next((c for c in chunk.columns if "label" in c.lower()), "Label")
            b = chunk[chunk[l_col].astype(str).str.strip().str.upper() == "BENIGN"]
            if skipped < offset:
                s = min(len(b), offset - skipped)
                b = b.iloc[s:]
                skipped += s
            if len(b) > 0:
                benigns.append(b.head(n_samples - sum(len(x) for x in benigns)))
            if sum(len(x) for x in benigns) >= n_samples:
                break
                
        df_b = pd.concat(benigns, ignore_index=True)
        print(f"Collected {len(df_b)} benign samples.")
        
        # Analyze predictions
        rf_classes = []
        rf_confidences = []
        if_scores = []
        is_anomalies = []
        final_classes = []
        threat_scores = []
        actions = []
        
        for _, row in df_b.iterrows():
            rec = row.to_dict()
            res = predictor.predict(rec)
            
            # Extract raw RF prediction
            X = extract_features_from_record(rec).reshape(1, -1)
            raw_rf_cls = int(predictor.rf.predict(X)[0])
            raw_rf_p = float(max(predictor.rf.predict_proba(X)[0]))
            
            rf_classes.append(LABEL_NAMES.get(raw_rf_cls, "Unknown"))
            rf_confidences.append(raw_rf_p)
            if_scores.append(res["anomalyScore"])
            is_anomalies.append(res["isAnomaly"])
            final_classes.append(res["predictedClass"])
            threat_scores.append(res["threatScore"])
            actions.append(res["action"])
            
        rf_classes = np.array(rf_classes)
        final_classes = np.array(final_classes)
        is_anomalies = np.array(is_anomalies)
        threat_scores = np.array(threat_scores)
        actions = np.array(actions)
        
        rf_benign_count = np.sum(rf_classes == "BENIGN")
        rf_fp_count = np.sum(rf_classes != "BENIGN")
        final_benign_count = np.sum(final_classes == "BENIGN")
        final_fp_count = np.sum(final_classes != "BENIGN")
        unknown_count = np.sum(final_classes == "Unknown")
        anomaly_count = np.sum(is_anomalies)
        
        print(f"Raw RF Classifier:")
        print(f"  Predicted BENIGN: {rf_benign_count}/{len(df_b)} ({rf_benign_count/len(df_b)*100:.1f}%)")
        print(f"  Predicted Attack (Raw RF FP): {rf_fp_count}/{len(df_b)} ({rf_fp_count/len(df_b)*100:.1f}%)")
        if rf_fp_count > 0:
            unique_fps, fp_counts = np.unique(rf_classes[rf_classes != "BENIGN"], return_counts=True)
            for u, c in zip(unique_fps, fp_counts):
                print(f"    Raw RF FP Breakdown: {u}: {c}")
                
        print(f"Isolation Forest Anomaly Overrides:")
        print(f"  Flagged as Anomaly (isAnomaly=True): {anomaly_count}/{len(df_b)} ({anomaly_count/len(df_b)*100:.1f}%)")
        print(f"  Final Class Overridden to 'Unknown': {unknown_count}/{len(df_b)} ({unknown_count/len(df_b)*100:.1f}%)")
        print(f"Final SentinelPredictor Result:")
        print(f"  Final BENIGN: {final_benign_count}/{len(df_b)} ({final_benign_count/len(df_b)*100:.1f}%)")
        print(f"  Final Non-BENIGN (Total Evaluated FP): {final_fp_count}/{len(df_b)} ({final_fp_count/len(df_b)*100:.1f}%)")
        print(f"  Actions: ALLOW={np.sum(actions=='ALLOW')}, MONITOR={np.sum(actions=='MONITOR')}, BLOCK={np.sum(actions=='BLOCK')}")
        print(f"  Mean Threat Score on Benign: {np.mean(threat_scores):.4f}")

    if ddos_csv.exists():
        analyze_benign_flows(ddos_csv, "Friday DDoS (ambient benign)", offset=60000, n_samples=500)
    if ps_csv.exists():
        analyze_benign_flows(ps_csv, "Friday PortScan (ambient benign)", offset=60000, n_samples=500)
    if monday_csv.exists():
        analyze_benign_flows(monday_csv, "Monday (pure benign)", offset=60000, n_samples=500)

if __name__ == "__main__":
    main()
