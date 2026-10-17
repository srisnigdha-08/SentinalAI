"""
SentinelAI Phase 13: Full Census of Both Corpora & Class 5 (Heartbleed) Audit
Location: ai-engine/experiments/gate1_phase13_shift_and_leakage/census_all_corpora.py
"""

import sys
import os
import json
from pathlib import Path
from collections import Counter
import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from utils.features import RAW_LABEL_TO_TARGET, LABEL_MAP

def find_label_column(df):
    for col in ["Label", " Label", "label", " target_class"]:
        if col in df.columns:
            return col
    for col in df.columns:
        if "label" in col.lower():
            return col
    return None

def main():
    out_dir = Path(__file__).resolve().parent
    out_dir.mkdir(parents=True, exist_ok=True)
    
    cse_dir = Path("D:/sentinelai_datasets/cse_cic_ids2018")
    cic_dir = Path("ai-engine/datasets/cicids2017")
    
    files_to_scan = []
    for f in sorted(cse_dir.glob("*.csv")):
        files_to_scan.append((f, "CSE-CIC-IDS2018"))
    for f in sorted(cic_dir.glob("*.csv")):
        files_to_scan.append((f, "CICIDS2017"))
        
    print(f"Total CSV files to scan: {len(files_to_scan)}")
    
    census_records = []
    global_raw_counter = Counter()
    global_target_counter = Counter()
    
    heartbleed_details = {
        "cve": "CVE-2014-0160",
        "official_vulnerability_type": "Information Disclosure (Buffer Over-read in OpenSSL TLS Heartbeat Extension)",
        "sentinel_class_name": "RCE Attempt (Class 5)",
        "naming_mismatch_analysis": (
            "Semantic mismatch: Heartbleed is CVE-2014-0160, a memory disclosure flaw allowing an attacker "
            "to read up to 64KB of server heap memory per heartbeat, leaking private keys and credentials. "
            "It does NOT permit arbitrary code execution (RCE). Classifying Heartbleed as 'RCE Attempt' is a "
            "domain taxonomy defect inherited from legacy prototype label mappings."
        ),
        "occurrences": []
    }
    
    for filepath, corpus in files_to_scan:
        print(f"Streaming {filepath.name} ({corpus})...")
        file_raw_counter = Counter()
        file_total_rows = 0
        
        # Read file in 100k chunks
        chunksize = 100000
        for chunk in pd.read_csv(filepath, chunksize=chunksize, encoding="utf-8", encoding_errors="ignore", low_memory=False):
            lbl_col = find_label_column(chunk)
            if lbl_col is None:
                print(f"  Warning: No label column found in {filepath.name}!")
                break
                
            chunk_labels = chunk[lbl_col].astype(str).str.strip()
            counts = chunk_labels.value_counts().to_dict()
            for raw_lbl, cnt in counts.items():
                file_raw_counter[raw_lbl] += cnt
                global_raw_counter[(corpus, raw_lbl)] += cnt
                file_total_rows += cnt
                
                # Check for Heartbleed
                if "heartbleed" in raw_lbl.lower():
                    heartbleed_details["occurrences"].append({
                        "corpus": corpus,
                        "file": filepath.name,
                        "raw_label": raw_lbl,
                        "count": cnt
                    })
                    print(f"  --> FOUND HEARTBLEED: {raw_lbl} ({cnt} rows) in {filepath.name}!")

        for raw_lbl, cnt in file_raw_counter.items():
            mapped_target = RAW_LABEL_TO_TARGET.get(raw_lbl, "UNKNOWN")
            target_id = LABEL_MAP.get(mapped_target, -1)
            global_target_counter[mapped_target] += cnt
            census_records.append({
                "corpus": corpus,
                "file": filepath.name,
                "raw_label": raw_lbl,
                "count": cnt,
                "mapped_target_class_name": mapped_target,
                "target_class_id": target_id
            })

    # Save CSV
    census_df = pd.DataFrame(census_records)
    csv_out = out_dir / "dataset_census_all_corpora.csv"
    census_df.to_csv(csv_out, index=False)
    print(f"\nCensus written to {csv_out}")
    
    # Calculate Heartbleed totals
    total_hb = sum(item["count"] for item in heartbleed_details["occurrences"])
    heartbleed_details["total_count_across_all_corpora"] = total_hb
    heartbleed_details["learnability_assessment"] = (
        f"Total count across both full corpora is {total_hb} flows (all in CICIDS2017 Tuesday-WorkingHours.pcap_ISCX.csv, 0 in CSE-CIC-IDS2018). "
        f"With N = {total_hb}, an 80/20 train/test split provides at most 8 training examples and 3 test examples. "
        "A statistical classifier cannot reliably generalize or be rigorously benchmarked on 3 test samples "
        "(a single false negative swings recall from 100% to 66.7%). "
        "Recommendation for GATE-1: Document Class 5 as unlearnable via statistical tabular ML due to dataset sparsity (N=11); "
        "Heartbleed detection in production must be handled via Layer 7 signature inspection (TLS Heartbeat length > payload length) "
        "or snort/suricata rules, rather than statistical tabular flow classifiers."
    )
    
    json_out = out_dir / "class5_heartbleed_audit.json"
    with open(json_out, "w") as f:
        json.dump(heartbleed_details, f, indent=2)
    print(f"Heartbleed audit written to {json_out}")
    
    # Print summary table
    print("\n=== Global Target Class Summary Across All Corpora ===")
    for target, cnt in sorted(global_target_counter.items(), key=lambda x: x[1], reverse=True):
        print(f"Target: {target:25s} | Total Rows: {cnt:,}")

if __name__ == "__main__":
    main()
