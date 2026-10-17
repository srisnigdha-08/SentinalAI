#!/usr/bin/env python3
"""
SentinelAI GATE-1 Phase 8: Multi-Corpus Retraining and Evaluation Pipeline
Location: ai-engine/experiments/gate1_phase8_multicorpus_candidates/build_multicorpus_pipeline.py

Executes:
1. Leakage-Resistant Multi-Corpus Partitioning (CICIDS2017 + CSE-CIC-IDS2018)
2. Controlled Feature Ablation Experiments (A - F)
3. Regularization Setting Comparison (max_depth, min_samples_leaf)
4. Multi-Corpus Candidate Model Training & Sealed Holdout Evaluation
5. Defense Tier Evaluation (Transport, L7 WAF, Combined Policy)
6. Complete Evidence Artifact and Manifest Generation
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

# Paths
EXPERIMENT_DIR = Path(__file__).resolve().parent
REPO_ROOT = EXPERIMENT_DIR.parent.parent.parent
AI_ENGINE_DIR = REPO_ROOT / "ai-engine"
HOLDOUT_DIR = Path("D:/sentinelai_datasets/cse_cic_ids2018/holdout_sets")
CSE2018_DIR = Path("D:/sentinelai_datasets/cse_cic_ids2018")
CIC2017_DIR = AI_ENGINE_DIR / "datasets" / "cicids2017"

sys.path.insert(0, str(AI_ENGINE_DIR))
sys.path.insert(0, str(REPO_ROOT / "ai-engine" / "experiments" / "gate1_phase3a_remediation"))
sys.path.insert(0, str(REPO_ROOT / "ai-engine" / "experiments" / "gate1_phase5_independent_validation"))

from utils.features import FEATURE_NAMES, LABEL_NAMES, LABEL_MAP
from candidate_policy import CandidateSentinelPolicy
from layer7_prototype import Layer7PreFilter

sys.stdout.reconfigure(encoding='utf-8')

# -----------------------------------------------------------------------------
# 1. Feature Mappings & Unified Label Mapping
# -----------------------------------------------------------------------------
FEATURE_MAPPING_2018 = [
    ("flow_duration", "Flow Duration"),
    ("total_fwd_packets", "Tot Fwd Pkts"),
    ("total_bwd_packets", "Tot Bwd Pkts"),
    ("total_len_fwd_packets", "TotLen Fwd Pkts"),
    ("total_len_bwd_packets", "TotLen Bwd Pkts"),
    ("fwd_packet_len_max", "Fwd Pkt Len Max"),
    ("fwd_packet_len_min", "Fwd Pkt Len Min"),
    ("fwd_packet_len_mean", "Fwd Pkt Len Mean"),
    ("fwd_packet_len_std", "Fwd Pkt Len Std"),
    ("bwd_packet_len_max", "Bwd Pkt Len Max"),
    ("bwd_packet_len_min", "Bwd Pkt Len Min"),
    ("bwd_packet_len_mean", "Bwd Pkt Len Mean"),
    ("bwd_packet_len_std", "Bwd Pkt Len Std"),
    ("flow_bytes_per_sec", "Flow Byts/s"),
    ("flow_packets_per_sec", "Flow Pkts/s"),
    ("flow_iat_mean", "Flow IAT Mean"),
    ("flow_iat_std", "Flow IAT Std"),
    ("flow_iat_max", "Flow IAT Max"),
    ("flow_iat_min", "Flow IAT Min"),
    ("fwd_iat_total", "Fwd IAT Tot"),
    ("fwd_iat_mean", "Fwd IAT Mean"),
    ("fwd_iat_std", "Fwd IAT Std"),
    ("fwd_iat_max", "Fwd IAT Max"),
    ("fwd_iat_min", "Fwd IAT Min"),
    ("bwd_iat_total", "Bwd IAT Tot"),
    ("bwd_iat_mean", "Bwd IAT Mean"),
    ("bwd_iat_std", "Bwd IAT Std"),
    ("bwd_iat_max", "Bwd IAT Max"),
    ("bwd_iat_min", "Bwd IAT Min"),
    ("fwd_psh_flags", "Fwd PSH Flags"),
    ("bwd_psh_flags", "Bwd PSH Flags"),
    ("fwd_urg_flags", "Fwd URG Flags"),
    ("bwd_urg_flags", "Bwd URG Flags"),
    ("fin_flag_count", "FIN Flag Cnt"),
    ("syn_flag_count", "SYN Flag Cnt"),
    ("rst_flag_count", "RST Flag Cnt"),
    ("psh_flag_count", "PSH Flag Cnt"),
    ("ack_flag_count", "ACK Flag Cnt"),
    ("urg_flag_count", "URG Flag Cnt"),
    ("fwd_header_len", "Fwd Header Len"),
    ("bwd_header_len", "Bwd Header Len"),
    ("fwd_avg_bytes_per_bulk", "Fwd Byts/b Avg"),
    ("bwd_avg_bytes_per_bulk", "Bwd Byts/b Avg"),
    ("init_win_bytes_forward", "Init Fwd Win Byts"),
    ("init_win_bytes_backward", "Init Bwd Win Byts"),
    ("active_mean", "Active Mean"),
    ("active_std", "Active Std"),
    ("idle_mean", "Idle Mean"),
    ("idle_std", "Idle Std"),
    ("down_up_ratio", "Down/Up Ratio"),
]

FEATURE_MAPPING_2017 = [
    ("flow_duration", "Flow Duration"),
    ("total_fwd_packets", "Total Fwd Packets"),
    ("total_bwd_packets", "Total Backward Packets"),
    ("total_len_fwd_packets", "Total Length of Fwd Packets"),
    ("total_len_bwd_packets", "Total Length of Bwd Packets"),
    ("fwd_packet_len_max", "Fwd Packet Length Max"),
    ("fwd_packet_len_min", "Fwd Packet Length Min"),
    ("fwd_packet_len_mean", "Fwd Packet Length Mean"),
    ("fwd_packet_len_std", "Fwd Packet Length Std"),
    ("bwd_packet_len_max", "Bwd Packet Length Max"),
    ("bwd_packet_len_min", "Bwd Packet Length Min"),
    ("bwd_packet_len_mean", "Bwd Packet Length Mean"),
    ("bwd_packet_len_std", "Bwd Packet Length Std"),
    ("flow_bytes_per_sec", "Flow Bytes/s"),
    ("flow_packets_per_sec", "Flow Packets/s"),
    ("flow_iat_mean", "Flow IAT Mean"),
    ("flow_iat_std", "Flow IAT Std"),
    ("flow_iat_max", "Flow IAT Max"),
    ("flow_iat_min", "Flow IAT Min"),
    ("fwd_iat_total", "Fwd IAT Total"),
    ("fwd_iat_mean", "Fwd IAT Mean"),
    ("fwd_iat_std", "Fwd IAT Std"),
    ("fwd_iat_max", "Fwd IAT Max"),
    ("fwd_iat_min", "Fwd IAT Min"),
    ("bwd_iat_total", "Bwd IAT Total"),
    ("bwd_iat_mean", "Bwd IAT Mean"),
    ("bwd_iat_std", "Bwd IAT Std"),
    ("bwd_iat_max", "Bwd IAT Max"),
    ("bwd_iat_min", "Bwd IAT Min"),
    ("fwd_psh_flags", "Fwd PSH Flags"),
    ("bwd_psh_flags", "Bwd PSH Flags"),
    ("fwd_urg_flags", "Fwd URG Flags"),
    ("bwd_urg_flags", "Bwd URG Flags"),
    ("fin_flag_count", "FIN Flag Count"),
    ("syn_flag_count", "SYN Flag Count"),
    ("rst_flag_count", "RST Flag Count"),
    ("psh_flag_count", "PSH Flag Count"),
    ("ack_flag_count", "ACK Flag Count"),
    ("urg_flag_count", "URG Flag Count"),
    ("fwd_header_len", "Fwd Header Length"),
    ("bwd_header_len", "Bwd Header Length"),
    ("fwd_avg_bytes_per_bulk", "Fwd Avg Bytes/Bulk"),
    ("bwd_avg_bytes_per_bulk", "Bwd Avg Bytes/Bulk"),
    ("init_win_bytes_forward", "Init_Win_bytes_forward"),
    ("init_win_bytes_backward", "Init_Win_bytes_backward"),
    ("active_mean", "Active Mean"),
    ("active_std", "Active Std"),
    ("idle_mean", "Idle Mean"),
    ("idle_std", "Idle Std"),
    ("down_up_ratio", "Down/Up Ratio"),
]

RAW_TO_SENTINEL = {
    "BENIGN": "BENIGN", "Benign": "BENIGN",
    "SSH-Patator": "SSH Brute Force", "SSH-Bruteforce": "SSH Brute Force",
    "FTP-Patator": "Credential Stuffing", "FTP-BruteForce": "Credential Stuffing",
    "Web Attack \ufffd Brute Force": "Credential Stuffing", "Brute Force -Web": "Credential Stuffing",
    "Web Attack \ufffd XSS": "XSS Attempt", "Brute Force -XSS": "XSS Attempt",
    "Web Attack \ufffd Sql Injection": "SQL Injection", "SQL Injection": "SQL Injection",
    "PortScan": "Port Scan",
    "DDoS": "DDoS", "DDOS attack-HOIC": "DDoS", "DDOS attack-LOIC-UDP": "DDoS",
    "DoS Hulk": "DDoS", "DoS GoldenEye": "DDoS", "DoS slowloris": "DDoS", "DoS Slowhttptest": "DDoS",
    "DoS attacks-GoldenEye": "DDoS", "DoS attacks-Slowloris": "DDoS",
    "Bot": "Malware Beacon",
    "Infiltration": "Lateral Movement", "Infilteration": "Lateral Movement",
    "Heartbleed": "RCE Attempt"
}

def compute_wilson(successes: int, total: int, confidence: float = 0.95) -> tuple:
    if total <= 0:
        return (0.0, 0.0)
    z = 1.959963984540054
    p = float(successes) / float(total)
    denominator = 1.0 + (z**2) / total
    centre = (p + (z**2) / (2.0 * total)) / denominator
    factor = z * math.sqrt((p * (1.0 - p) + (z**2) / (4.0 * total)) / total) / denominator
    return (max(0.0, centre - factor), min(1.0, centre + factor))

def compute_row_hash(row_dict: dict) -> str:
    feats = [f"{float(row_dict.get(k, 0.0)):.4f}" for k in sorted(FEATURE_NAMES)]
    return hashlib.md5(",".join(feats).encode("utf-8")).hexdigest()

# -----------------------------------------------------------------------------
# 2. Extract Dataframe in Standard 53-Feature Format
# -----------------------------------------------------------------------------
def standardize_df(raw_df: pd.DataFrame, mapping: list, corpus_name: str) -> pd.DataFrame:
    raw_df.columns = raw_df.columns.str.strip()
    # Filter repeated header lines if present
    if "Label" in raw_df.columns:
        raw_df = raw_df[raw_df["Label"] != "Label"].copy()
    elif "label" in raw_df.columns:
        raw_df = raw_df[raw_df["label"] != "label"].copy()

    # Time of Day sin / cos
    ts_col = "Timestamp" if "Timestamp" in raw_df.columns else "timestamp"
    if ts_col in raw_df.columns:
        dt = pd.to_datetime(raw_df[ts_col], errors="coerce")
        hours = dt.dt.hour.fillna(12.0) + dt.dt.minute.fillna(0.0) / 60.0 + dt.dt.second.fillna(0.0) / 3600.0
        time_sin = np.sin(2.0 * np.pi * hours / 24.0).astype(np.float32)
        time_cos = np.cos(2.0 * np.pi * hours / 24.0).astype(np.float32)
    else:
        time_sin = np.zeros(len(raw_df), dtype=np.float32)
        time_cos = np.zeros(len(raw_df), dtype=np.float32)

    # Payload Entropy
    fwd_len_col = "TotLen Fwd Pkts" if "TotLen Fwd Pkts" in raw_df.columns else ("Total Length of Fwd Packets" if "Total Length of Fwd Packets" in raw_df.columns else None)
    bwd_len_col = "TotLen Bwd Pkts" if "TotLen Bwd Pkts" in raw_df.columns else ("Total Length of Bwd Packets" if "Total Length of Bwd Packets" in raw_df.columns else None)
    
    tot_fwd = pd.to_numeric(raw_df[fwd_len_col], errors="coerce").fillna(0.0).values.astype(np.float64) if fwd_len_col else np.zeros(len(raw_df))
    tot_bwd = pd.to_numeric(raw_df[bwd_len_col], errors="coerce").fillna(0.0).values.astype(np.float64) if bwd_len_col else np.zeros(len(raw_df))
    tot = tot_fwd + tot_bwd
    p_f = np.where(tot > 0, tot_fwd / np.maximum(tot, 1e-9), 0.0)
    p_b = np.where(tot > 0, tot_bwd / np.maximum(tot, 1e-9), 0.0)
    ent_f = np.where(p_f > 0, -p_f * np.log2(np.maximum(p_f, 1e-12)), 0.0)
    ent_b = np.where(p_b > 0, -p_b * np.log2(np.maximum(p_b, 1e-12)), 0.0)
    payload_entropy = (ent_f + ent_b).astype(np.float32)

    out = {}
    for feat_name, raw_name in mapping:
        if raw_name in raw_df.columns:
            s = pd.to_numeric(raw_df[raw_name], errors="coerce").fillna(0.0).replace([np.inf, -np.inf], 0.0)
            out[feat_name] = s.values.astype(np.float32)
        else:
            out[feat_name] = np.zeros(len(raw_df), dtype=np.float32)

    out["payload_entropy"] = payload_entropy
    out["time_of_day_sin"] = time_sin.values if hasattr(time_sin, "values") else time_sin
    out["time_of_day_cos"] = time_cos.values if hasattr(time_cos, "values") else time_cos

    # Optional port features for ablation C
    dst_col = "Dst Port" if "Dst Port" in raw_df.columns else ("Destination Port" if "Destination Port" in raw_df.columns else None)
    if dst_col:
        out["raw_dst_port"] = pd.to_numeric(raw_df[dst_col], errors="coerce").fillna(0.0).values.astype(np.float32)
    else:
        out["raw_dst_port"] = np.zeros(len(raw_df), dtype=np.float32)

    df_out = pd.DataFrame(out)
    
    # Label extraction
    lbl_col = "Label" if "Label" in raw_df.columns else "label"
    raw_lbls = raw_df[lbl_col].astype(str).values
    mapped_lbls = [RAW_TO_SENTINEL.get(lbl, "BENIGN" if "benign" in lbl.lower() else "UNKNOWN") for lbl in raw_lbls]
    df_out["ground_truth_raw"] = raw_lbls
    df_out["ground_truth_label"] = mapped_lbls
    df_out["target_class"] = [LABEL_MAP.get(lbl, 0) for lbl in mapped_lbls]
    df_out["is_attack"] = [lbl != "BENIGN" for lbl in mapped_lbls]
    df_out["corpus"] = corpus_name
    return df_out

print("Pipeline module loaded successfully.")
