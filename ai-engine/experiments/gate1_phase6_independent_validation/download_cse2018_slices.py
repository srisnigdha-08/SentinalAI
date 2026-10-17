#!/usr/bin/env python3
"""
Downloads target CSE-CIC-IDS2018 CSV files to D:/sentinelai_datasets/cse_cic_ids2018/
Files:
- Friday-23-02-2018 (Web Attacks: Brute Force Web, XSS, SQL Injection)
- Wednesday-14-02-2018 (SSH-Bruteforce, FTP-BruteForce)
- Friday-02-03-2018 (Botnet)
- Wednesday-21-02-2018 (DDoS LOIC-HTTP, HOIC)
- Thursday-15-02-2018 (DoS GoldenEye, DoS Hulk)
"""

import os
import time
import urllib.request
from pathlib import Path

DEST_DIR = Path("D:/sentinelai_datasets/cse_cic_ids2018")
DEST_DIR.mkdir(parents=True, exist_ok=True)

BASE_URL = "https://cse-cic-ids2018.s3.amazonaws.com/Processed%20Traffic%20Data%20for%20ML%20Algorithms/"

FILES_TO_DOWNLOAD = [
    ("Friday-23-02-2018_TrafficForML_CICFlowMeter.csv", 365.11),
    ("Wednesday-14-02-2018_TrafficForML_CICFlowMeter.csv", 341.63),
    ("Friday-02-03-2018_TrafficForML_CICFlowMeter.csv", 336.04),
    ("Wednesday-21-02-2018_TrafficForML_CICFlowMeter.csv", 313.66),
    ("Thursday-15-02-2018_TrafficForML_CICFlowMeter.csv", 358.53)
]

print("================================================================================")
print("CSE-CIC-IDS2018 Targeted Slice Downloader (Secondary Storage: Drive D:)")
print(f"Target Directory: {DEST_DIR}")
print("================================================================================")

for fname, exp_mb in FILES_TO_DOWNLOAD:
    dst_path = DEST_DIR / fname
    if dst_path.exists():
        actual_mb = dst_path.stat().st_size / (1024 * 1024)
        if actual_mb >= exp_mb * 0.95:
            print(f"[EXISTS] {fname} ({actual_mb:.2f} MB). Skipping download.")
            continue

    url = BASE_URL + fname
    print(f"\n[DOWNLOADING] {fname} (~{exp_mb:.2f} MB)...")
    t0 = time.time()
    try:
        urllib.request.urlretrieve(url, dst_path)
        el = time.time() - t0
        sz_mb = dst_path.stat().st_size / (1024 * 1024)
        print(f"[COMPLETED] {fname}: {sz_mb:.2f} MB in {el:.2f}s ({sz_mb/el:.2f} MB/s)")
    except Exception as e:
        print(f"[ERROR] Failed to download {fname}: {e}")

print("\nAll target downloads finished.")
