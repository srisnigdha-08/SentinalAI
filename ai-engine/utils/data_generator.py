#!/usr/bin/env python3
"""Synthetic CICIDS2017-style dataset generator for SentinelAI training."""
import numpy as np
import pandas as pd
import argparse
import datetime
from pathlib import Path

PROFILES = {
    "BENIGN":             {"w":0.50,"bps":(5000,8000),   "pps":(200,300),   "syn":(0,1), "dur":(50000,80000)},
    "SSH Brute Force":    {"w":0.08,"bps":(200000,50000),"pps":(5000,1000), "syn":(1,3), "dur":(500,800)},
    "SQL Injection":      {"w":0.06,"bps":(15000,5000),  "pps":(500,200),   "syn":(1,2), "dur":(2000,1000)},
    "Port Scan":          {"w":0.08,"bps":(500000,100000),"pps":(80000,20000),"syn":(1,2),"dur":(5,20)},
    "DDoS":               {"w":0.05,"bps":(2000000,500000),"pps":(50000,10000),"syn":(1,2),"dur":(100000,30000)},
    "RCE Attempt":        {"w":0.03,"bps":(20000,8000),  "pps":(600,200),   "syn":(1,2), "dur":(3000,1500)},
    "XSS Attempt":        {"w":0.04,"bps":(12000,4000),  "pps":(400,150),   "syn":(1,2), "dur":(1500,800)},
    "Malware Beacon":     {"w":0.03,"bps":(1000,300),    "pps":(40,10),     "syn":(1,2), "dur":(200,50)},
    "Credential Stuffing":{"w":0.03,"bps":(8000,3000), "pps":(300,100),   "syn":(1,2), "dur":(800,400)},
    "Lateral Movement":   {"w":0.05,"bps":(3000,1000),   "pps":(800,200),   "syn":(1,2), "dur":(150,50)},
    "Data Exfiltration":  {"w":0.05,"bps":(1500000,300000),"pps":(120,30),  "syn":(1,2), "dur":(300000,50000)},
}

def generate(n=20000, seed=42):
    np.random.seed(seed)
    rows, labels = [], []
    names = list(PROFILES.keys())
    weights = [PROFILES[n]["w"] for n in names]
    counts = np.round(np.array(weights) * n).astype(int)
    counts[-1] = n - counts[:-1].sum()
    for attack, count in zip(names, counts):
        p = PROFILES[attack]
        for _ in range(int(count)):
            dur = abs(np.random.normal(p["dur"][0], p["dur"][1]))
            fwd = max(1, int(abs(np.random.normal(10, 5))))
            bwd = max(0, int(abs(np.random.normal(5, 3))))
            bps = abs(np.random.normal(p["bps"][0], p["bps"][1]))
            pps = abs(np.random.normal(p["pps"][0], p["pps"][1]))
            syn = int(np.random.uniform(*p["syn"]))
            
            # Timestamp hour simulation
            if attack == "BENIGN":
                hr = np.random.normal(13.0, 3.0) % 24.0
            else:
                hr = np.random.uniform(0.0, 24.0)
                
            # Date simulation within the last 7 days
            now = datetime.datetime.now()
            dt = now - datetime.timedelta(days=int(np.random.randint(0, 7)))
            dt = dt.replace(hour=int(hr), minute=int((hr%1)*60), second=int(((hr*60)%1)*60))
            timestamp_str = dt.isoformat()
            
            # Feature calculation: payload entropy
            fwd_len = fwd * 80
            bwd_len = bwd * 150
            total_len = fwd_len + bwd_len
            entropy = 0.0
            if total_len > 0.0:
                p_f = fwd_len / total_len
                p_b = bwd_len / total_len
                if p_f > 0.0:
                    entropy -= p_f * np.log2(p_f)
                if p_b > 0.0:
                    entropy -= p_b * np.log2(p_b)
                    
            # Feature calculation: cyclical time
            time_sin = np.sin(2.0 * np.pi * hr / 24.0)
            time_cos = np.cos(2.0 * np.pi * hr / 24.0)
            
            rows.append({
                "flow_duration":dur,"total_fwd_packets":fwd,"total_bwd_packets":bwd,
                "total_len_fwd_packets":fwd_len,"total_len_bwd_packets":bwd_len,
                "fwd_packet_len_max":100,"fwd_packet_len_min":40,"fwd_packet_len_mean":80,"fwd_packet_len_std":10,
                "bwd_packet_len_max":200,"bwd_packet_len_min":80,"bwd_packet_len_mean":150,"bwd_packet_len_std":15,
                "flow_bytes_per_sec":bps,"flow_packets_per_sec":pps,
                "flow_iat_mean":dur/max(fwd+bwd,1),"flow_iat_std":100,"flow_iat_max":dur,"flow_iat_min":1,
                "fwd_iat_total":dur*0.5,"fwd_iat_mean":dur/max(fwd,1),"fwd_iat_std":50,"fwd_iat_max":dur,"fwd_iat_min":1,
                "bwd_iat_total":dur*0.4,"bwd_iat_mean":dur/max(bwd,1),"bwd_iat_std":60,"bwd_iat_max":dur,"bwd_iat_min":1,
                "fwd_psh_flags":1,"bwd_psh_flags":1,"fwd_urg_flags":0,"bwd_urg_flags":0,
                "fin_flag_count":1,"syn_flag_count":syn,"rst_flag_count":0,"psh_flag_count":fwd,"ack_flag_count":bwd,"urg_flag_count":0,
                "fwd_header_len":fwd*20,"bwd_header_len":bwd*20,"fwd_avg_bytes_per_bulk":80,"bwd_avg_bytes_per_bulk":150,
                "timestamp":timestamp_str,
                "payload_entropy":entropy,
                "time_of_day_sin":time_sin,
                "time_of_day_cos":time_cos,
                "label":attack,
            })
            labels.append(attack)
    df = pd.DataFrame(rows).sample(frac=1, random_state=seed).reset_index(drop=True)
    return df

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--rows", type=int, default=20000)
    parser.add_argument("--output", type=str, default="datasets/synthetic.csv")
    args = parser.parse_args()
    Path(args.output).parent.mkdir(parents=True, exist_ok=True)
    df = generate(args.rows)
    df.to_csv(args.output, index=False)
    print(f"Generated {len(df):,} rows -> {args.output}")
    print(df["label"].value_counts().to_string())
