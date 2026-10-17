#!/usr/bin/env python3
"""
SentinelAI GATE-1 Phase 7: CSE-CIC-IDS2018 Preprocessing & Holdout Extraction Pipeline
Converts raw 80-column CSE-CIC-IDS2018 CSVs into standardized 53-feature holdout sets.

Target Schema: v2.1_53feat
Output Location: D:/sentinelai_datasets/cse_cic_ids2018/
"""

import sys
import os
import math
import time
from pathlib import Path
import numpy as np
import pandas as pd

CURRENT_DIR = Path(__file__).resolve().parent
AI_ENGINE_DIR = CURRENT_DIR.parent.parent
sys.path.insert(0, str(AI_ENGINE_DIR))

from utils.features import FEATURE_NAMES, LABEL_MAP, EXPECTED_FEATURE_COUNT

RAW_DATA_DIR = Path("D:/sentinelai_datasets/cse_cic_ids2018")
OUTPUT_DIR = RAW_DATA_DIR / "holdout_sets"
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

# 80-to-53 deterministic feature mapping
FEATURE_MAPPING = [
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

RAW_TO_SENTINEL_LABEL = {
    "Benign": "BENIGN",
    "Infilteration": "Lateral Movement",
    "Brute Force -Web": "Credential Stuffing",
    "Brute Force -XSS": "XSS Attempt",
    "SQL Injection": "SQL Injection",
    "SSH-Bruteforce": "SSH Brute Force",
    "FTP-BruteForce": "Credential Stuffing",
    "Bot": "Malware Beacon",
    "DDOS attack-LOIC-HTTP": "DDoS",
    "DDOS attack-HOIC": "DDoS",
    "DDOS attack-LOIC-UDP": "DDoS",
    "DoS attacks-Hulk": "DDoS",
    "DoS attacks-GoldenEye": "DDoS",
    "DoS attacks-Slowloris": "DDoS",
    "DoS attacks-SlowHTTPTest": "DDoS"
}

def transform_raw_df_to_sentinel_features(df: pd.DataFrame) -> pd.DataFrame:
    """
    Transforms raw 80-column CSE-CIC-IDS2018 dataframe into 53-feature SentinelAI schema.
    """
    # 1. Filter out repetitive header rows if present
    df = df[df["Label"] != "Label"].copy()

    # 2. Time of day sine/cosine from Timestamp (dd/MM/yyyy HH:mm:ss)
    dt = pd.to_datetime(df["Timestamp"], format="%d/%m/%Y %H:%M:%S", errors="coerce")
    if dt.isna().any():
        dt = dt.fillna(pd.to_datetime(df["Timestamp"], errors="coerce"))
    
    hours = dt.dt.hour.fillna(12.0) + dt.dt.minute.fillna(0.0) / 60.0 + dt.dt.second.fillna(0.0) / 3600.0
    time_sin = np.sin(2.0 * np.pi * hours / 24.0).astype(np.float32)
    time_cos = np.cos(2.0 * np.pi * hours / 24.0).astype(np.float32)

    # 3. Payload entropy
    tot_len_fwd = pd.to_numeric(df["TotLen Fwd Pkts"], errors="coerce").fillna(0.0).values.astype(np.float64)
    tot_len_bwd = pd.to_numeric(df["TotLen Bwd Pkts"], errors="coerce").fillna(0.0).values.astype(np.float64)
    total_len = tot_len_fwd + tot_len_bwd

    p_f = np.where(total_len > 0, tot_len_fwd / np.maximum(total_len, 1e-9), 0.0)
    p_b = np.where(total_len > 0, tot_len_bwd / np.maximum(total_len, 1e-9), 0.0)
    ent_f = np.where(p_f > 0, -p_f * np.log2(np.maximum(p_f, 1e-12)), 0.0)
    ent_b = np.where(p_b > 0, -p_b * np.log2(np.maximum(p_b, 1e-12)), 0.0)
    payload_entropy = (ent_f + ent_b).astype(np.float32)

    # 4. Map the direct 49 features
    out_dict = {}
    for feat_name, raw_col in FEATURE_MAPPING:
        if raw_col in df.columns:
            s = pd.to_numeric(df[raw_col], errors="coerce").fillna(0.0)
            s = s.replace([np.inf, -np.inf], 0.0)
            out_dict[feat_name] = s.values.astype(np.float32)
        else:
            out_dict[feat_name] = np.zeros(len(df), dtype=np.float32)

    out_dict["payload_entropy"] = payload_entropy
    out_dict["time_of_day_sin"] = time_sin.values
    out_dict["time_of_day_cos"] = time_cos.values

    # Construct final dataframe in exact schema order
    feat_df = pd.DataFrame(out_dict, columns=FEATURE_NAMES)
    
    # Target label and is_attack indicator
    raw_labels = df["Label"].astype(str).values
    mapped_labels = [RAW_TO_SENTINEL_LABEL.get(lbl, "BENIGN" if "benign" in lbl.lower() else "UNKNOWN") for lbl in raw_labels]
    feat_df["ground_truth_raw"] = raw_labels
    feat_df["ground_truth_label"] = mapped_labels
    feat_df["is_attack"] = [lbl != "BENIGN" for lbl in mapped_labels]
    
    return feat_df


def extract_holdout_slices():
    print("================================================================================")
    print("SentinelAI GATE-1 Phase 7: CSE-CIC-IDS2018 Holdout Extraction Pipeline")
    print(f"Source Directory: {RAW_DATA_DIR}")
    print(f"Target Directory: {OUTPUT_DIR}")
    print("================================================================================")

    np.random.seed(42)

    # -------------------------------------------------------------------------
    # SLICE 1: INFILTRATION HOLDOUT (Thursday-01-03-2018)
    # -------------------------------------------------------------------------
    fn_infil = RAW_DATA_DIR / "Thursday-01-03-2018_TrafficForML_CICFlowMeter.csv"
    if fn_infil.exists():
        print(f"\n[1/6] Processing Infiltration from {fn_infil.name}...")
        df_infil = pd.read_csv(fn_infil, low_memory=False)
        df_infil = df_infil[df_infil["Label"] != "Label"]

        df_infil_attacks = df_infil[df_infil["Label"] == "Infilteration"]
        df_infil_benign = df_infil[df_infil["Label"] == "Benign"]

        print(f"  Available: {len(df_infil_attacks)} Infiltration, {len(df_infil_benign)} Benign")
        sampled_att = df_infil_attacks.sample(n=min(2000, len(df_infil_attacks)), random_state=42)
        sampled_ben = df_infil_benign.sample(n=min(1000, len(df_infil_benign)), random_state=42)
        combined = pd.concat([sampled_att, sampled_ben], ignore_index=True)

        feat_df = transform_raw_df_to_sentinel_features(combined)
        out_path = OUTPUT_DIR / "holdout_infiltration.parquet"
        feat_df.to_parquet(out_path, index=False)
        print(f"  [SAVED] {out_path} ({len(feat_df)} rows: {sum(feat_df['is_attack'])} attack, {sum(~feat_df['is_attack'])} benign)")

    # -------------------------------------------------------------------------
    # SLICE 2: WEB ATTACKS HOLDOUT (Friday-23-02-2018)
    # -------------------------------------------------------------------------
    fn_web = RAW_DATA_DIR / "Friday-23-02-2018_TrafficForML_CICFlowMeter.csv"
    if fn_web.exists():
        print(f"\n[2/6] Processing Web Attacks from {fn_web.name}...")
        df_web = pd.read_csv(fn_web, low_memory=False)
        df_web = df_web[df_web["Label"] != "Label"]

        web_labels = ["Brute Force -Web", "Brute Force -XSS", "SQL Injection"]
        df_web_attacks = df_web[df_web["Label"].isin(web_labels)]
        df_web_benign = df_web[df_web["Label"] == "Benign"]

        print(f"  Available: {len(df_web_attacks)} Web Attacks, {len(df_web_benign)} Benign")
        sampled_ben = df_web_benign.sample(n=min(1000, len(df_web_benign)), random_state=42)
        combined = pd.concat([df_web_attacks, sampled_ben], ignore_index=True)

        feat_df = transform_raw_df_to_sentinel_features(combined)
        out_path = OUTPUT_DIR / "holdout_web_attacks.parquet"
        feat_df.to_parquet(out_path, index=False)
        print(f"  [SAVED] {out_path} ({len(feat_df)} rows: {sum(feat_df['is_attack'])} attack, {sum(~feat_df['is_attack'])} benign)")

    # -------------------------------------------------------------------------
    # SLICE 3: BRUTE FORCE (SSH & FTP) HOLDOUT (Wednesday-14-02-2018)
    # -------------------------------------------------------------------------
    fn_brute = RAW_DATA_DIR / "Wednesday-14-02-2018_TrafficForML_CICFlowMeter.csv"
    if fn_brute.exists():
        print(f"\n[3/6] Processing SSH/FTP Brute Force from {fn_brute.name}...")
        df_brute = pd.read_csv(fn_brute, low_memory=False)
        df_brute = df_brute[df_brute["Label"] != "Label"]

        df_ssh = df_brute[df_brute["Label"] == "SSH-Bruteforce"]
        df_ftp = df_brute[df_brute["Label"] == "FTP-BruteForce"]
        df_benign = df_brute[df_brute["Label"] == "Benign"]

        print(f"  Available: {len(df_ssh)} SSH, {len(df_ftp)} FTP, {len(df_benign)} Benign")
        sampled_ssh = df_ssh.sample(n=min(1000, len(df_ssh)), random_state=42)
        sampled_ftp = df_ftp.sample(n=min(1000, len(df_ftp)), random_state=42)
        sampled_ben = df_benign.sample(n=min(1000, len(df_benign)), random_state=42)
        combined = pd.concat([sampled_ssh, sampled_ftp, sampled_ben], ignore_index=True)

        feat_df = transform_raw_df_to_sentinel_features(combined)
        out_path = OUTPUT_DIR / "holdout_bruteforce_ssh_ftp.parquet"
        feat_df.to_parquet(out_path, index=False)
        print(f"  [SAVED] {out_path} ({len(feat_df)} rows: {sum(feat_df['is_attack'])} attack, {sum(~feat_df['is_attack'])} benign)")

    # -------------------------------------------------------------------------
    # SLICE 4: BOTNET HOLDOUT (Friday-02-03-2018)
    # -------------------------------------------------------------------------
    fn_bot = RAW_DATA_DIR / "Friday-02-03-2018_TrafficForML_CICFlowMeter.csv"
    if fn_bot.exists() and fn_bot.stat().st_size > 100 * 1024 * 1024:
        print(f"\n[4/6] Processing Botnet from {fn_bot.name}...")
        df_bot = pd.read_csv(fn_bot, low_memory=False)
        df_bot = df_bot[df_bot["Label"] != "Label"]

        df_bot_attacks = df_bot[df_bot["Label"] == "Bot"]
        df_bot_benign = df_bot[df_bot["Label"] == "Benign"]

        print(f"  Available: {len(df_bot_attacks)} Bot, {len(df_bot_benign)} Benign")
        sampled_att = df_bot_attacks.sample(n=min(2000, len(df_bot_attacks)), random_state=42)
        sampled_ben = df_bot_benign.sample(n=min(1000, len(df_bot_benign)), random_state=42)
        combined = pd.concat([sampled_att, sampled_ben], ignore_index=True)

        feat_df = transform_raw_df_to_sentinel_features(combined)
        out_path = OUTPUT_DIR / "holdout_botnet.parquet"
        feat_df.to_parquet(out_path, index=False)
        print(f"  [SAVED] {out_path} ({len(feat_df)} rows: {sum(feat_df['is_attack'])} attack, {sum(~feat_df['is_attack'])} benign)")

    # -------------------------------------------------------------------------
    # SLICE 5: DDOS / DOS HOLDOUT (Wednesday-21-02-2018 or Thursday-15-02-2018)
    # -------------------------------------------------------------------------
    fn_ddos = RAW_DATA_DIR / "Wednesday-21-02-2018_TrafficForML_CICFlowMeter.csv"
    if fn_ddos.exists() and fn_ddos.stat().st_size > 100 * 1024 * 1024:
        print(f"\n[5/6] Processing DDoS from {fn_ddos.name}...")
        df_ddos = pd.read_csv(fn_ddos, low_memory=False)
        df_ddos = df_ddos[df_ddos["Label"] != "Label"]

        ddos_labels = [l for l in df_ddos["Label"].unique() if "ddos" in l.lower() or "dos" in l.lower()]
        df_ddos_attacks = df_ddos[df_ddos["Label"].isin(ddos_labels)]
        df_ddos_benign = df_ddos[df_ddos["Label"] == "Benign"]

        print(f"  Available: {len(df_ddos_attacks)} DDoS ({ddos_labels}), {len(df_ddos_benign)} Benign")
        sampled_att = df_ddos_attacks.sample(n=min(2000, len(df_ddos_attacks)), random_state=42)
        sampled_ben = df_ddos_benign.sample(n=min(1000, len(df_ddos_benign)), random_state=42)
        combined = pd.concat([sampled_att, sampled_ben], ignore_index=True)

        feat_df = transform_raw_df_to_sentinel_features(combined)
        out_path = OUTPUT_DIR / "holdout_ddos.parquet"
        feat_df.to_parquet(out_path, index=False)
        print(f"  [SAVED] {out_path} ({len(feat_df)} rows: {sum(feat_df['is_attack'])} attack, {sum(~feat_df['is_attack'])} benign)")

    # -------------------------------------------------------------------------
    # SLICE 6: 30,000 PURE BENIGN HOLDOUT (Thursday-01-03 & Friday-23-02)
    # -------------------------------------------------------------------------
    print("\n[6/6] Assembling 30,000 Pure Benign Holdout Corpus for Wilson Score FPR bound...")
    benign_chunks = []
    
    if fn_infil.exists():
        df_i_b = pd.read_csv(fn_infil, low_memory=False)
        df_i_b = df_i_b[df_i_b["Label"] == "Benign"]
        benign_chunks.append(df_i_b.sample(n=15000, random_state=42))
        del df_i_b

    if fn_web.exists():
        df_w_b = pd.read_csv(fn_web, low_memory=False)
        df_w_b = df_w_b[df_w_b["Label"] == "Benign"]
        benign_chunks.append(df_w_b.sample(n=15000, random_state=42))
        del df_w_b

    if len(benign_chunks) == 2:
        df_benign_30k = pd.concat(benign_chunks, ignore_index=True)
        feat_df_benign_30k = transform_raw_df_to_sentinel_features(df_benign_30k)
        out_path = OUTPUT_DIR / "holdout_benign_30k.parquet"
        feat_df_benign_30k.to_parquet(out_path, index=False)
        print(f"  [SAVED] {out_path} ({len(feat_df_benign_30k)} pure benign rows)")

    print("\nHoldout extraction pipeline completed successfully.")

if __name__ == "__main__":
    extract_holdout_slices()
