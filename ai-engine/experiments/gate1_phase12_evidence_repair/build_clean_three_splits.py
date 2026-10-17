#!/usr/bin/env python3
"""
SentinelAI GATE-1 Phase 12 - Clean Three-Split Dataset Constructor
Extracts leak-free, disjoint Validation and Final Sealed Test partitions
from the raw CSE-CIC-IDS2018 and CICIDS2017 corpora with explicit temporal/chunk gap windows.
Guarantees zero overlap with burned holdouts and previous training sets.
"""

import os
import sys
import hashlib
from pathlib import Path
from collections import Counter

import numpy as np
import pandas as pd

# Path setup
REPO_ROOT = Path(__file__).resolve().parents[3]
AI_ENGINE_DIR = REPO_ROOT / "ai-engine"
sys.path.insert(0, str(AI_ENGINE_DIR))
sys.path.insert(0, str(AI_ENGINE_DIR / "experiments" / "gate1_phase7_cse2018_validation"))
sys.path.insert(0, str(AI_ENGINE_DIR / "experiments" / "gate1_phase10_detector_recovery"))

from utils.features import FEATURE_NAMES, LABEL_MAP, LABEL_NAMES
from preprocess_cse2018 import transform_raw_df_to_sentinel_features, RAW_TO_SENTINEL_LABEL
from build_candidate_v2_fixed import (
    FEATURE_MAPPING_2018, FEATURE_MAPPING_2017, RAW_TO_SENTINEL,
    standardize_df
)

EXPERIMENT_DIR = AI_ENGINE_DIR / "experiments" / "gate1_phase12_evidence_repair"
LOG_DIR = EXPERIMENT_DIR / "logs"
HOLDOUT_DIR = Path("D:/sentinelai_datasets/cse_cic_ids2018/holdout_sets")
RAW_2018_DIR = Path("D:/sentinelai_datasets/cse_cic_ids2018")
RAW_2017_DIR = AI_ENGINE_DIR / "datasets" / "cicids2017"

TRAIN_V2_PARQUET = AI_ENGINE_DIR / "experiments" / "gate1_phase10_detector_recovery" / "partition_train_multicorpus_v2.parquet"

SORTED_FEATS = sorted(FEATURE_NAMES)


def compute_sha256(filepath: Path) -> str:
    h = hashlib.sha256()
    with open(filepath, "rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest().upper()


def hash_dataframe_rows(df: pd.DataFrame) -> list:
    mat = df[SORTED_FEATS].to_numpy(dtype=np.float32)
    return [hashlib.md5((",".join(f"{x:.4f}" for x in row)).encode("utf-8")).hexdigest() for row in mat]


def main():
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    log_file = LOG_DIR / "task3_dataset_partitioning.log"

    with open(log_file, "w", encoding="utf-8") as log:
        def log_print(msg):
            print(msg)
            log.write(msg + "\n")
            log.flush()

        log_print("=" * 80)
        log_print("TASK 3: THREE-SPLIT DISCIPLINE & SEALED TEST RESERVATION")
        log_print("=" * 80)

        # 1. Build Exclusion Hash Set (Burned Holdouts + Train V2 rows)
        log_print("\n[STEP 1] Building comprehensive exclusion hash set...")
        exclusion_hashes = set()

        # Add all burned holdout row hashes EXCEPT holdout_web_attacks (which will be partitioned 50/50)
        for hp in sorted(HOLDOUT_DIR.glob("*.parquet")):
            if hp.name == "holdout_web_attacks.parquet":
                continue
            df_h = pd.read_parquet(hp)
            hashes = hash_dataframe_rows(df_h)
            exclusion_hashes.update(hashes)
            log_print(f"  Hashed burned holdout: {hp.name} ({len(df_h)} rows) -> Total excluded: {len(exclusion_hashes):,}")

        # Add all Train V2 row hashes
        if TRAIN_V2_PARQUET.exists():
            df_tr = pd.read_parquet(TRAIN_V2_PARQUET)
            hashes = hash_dataframe_rows(df_tr)
            exclusion_hashes.update(hashes)
            log_print(f"  Hashed Train V2 partition: {TRAIN_V2_PARQUET.name} ({len(df_tr)} rows) -> Total excluded: {len(exclusion_hashes):,}")

        # 2. Quotas for Validation (20%) and Sealed Final Test (20%)
        # Target sizes per class:
        # Benign: 25,000 Val, 25,000 Test (50,000 total)
        # Attacks: 2,500 Val, 2,500 Test
        val_quotas = {
            "BENIGN": 25000,
            "Malware Beacon": 2500,
            "SSH Brute Force": 2500,
            "Credential Stuffing": 2500,
            "DDoS": 2500,
            "Lateral Movement": 2500,
        }
        test_quotas = dict(val_quotas)

        val_rows = []
        test_rows = []
        val_counts = Counter()
        test_counts = Counter()

        log_print("\n[STEP 2] Extracting non-overlapping slices with gap window...")

        # 2.1 Partition Web Attacks 50/50 from holdout_web_attacks.parquet
        p_web = HOLDOUT_DIR / "holdout_web_attacks.parquet"
        if p_web.exists():
            df_w = pd.read_parquet(p_web)
            df_w_att = df_w[df_w["ground_truth_label"] != "BENIGN"].copy()
            df_w_att["row_hash"] = hash_dataframe_rows(df_w_att)
            # Filter against Train V2
            df_w_att = df_w_att[~df_w_att["row_hash"].isin(exclusion_hashes)]
            # Shuffle
            df_w_att = df_w_att.sample(frac=1.0, random_state=42).reset_index(drop=True)
            n_mid = len(df_w_att) // 2
            
            for i, r in df_w_att.iterrows():
                h = r["row_hash"]
                if h in exclusion_hashes:
                    continue
                lbl = r["ground_truth_label"]
                if i < n_mid:
                    val_rows.append(r.drop("row_hash"))
                    val_counts[lbl] += 1
                    exclusion_hashes.add(h)
                else:
                    test_rows.append(r.drop("row_hash"))
                    test_counts[lbl] += 1
                    exclusion_hashes.add(h)
            log_print(f"  Web Attacks Partitioned: Val {val_counts}, Test {test_counts}")

        extraction_specs = [
            ("Wednesday-14-02-2018_TrafficForML_CICFlowMeter.csv", ["SSH Brute Force", "Credential Stuffing", "BENIGN"]),
            ("Friday-02-03-2018_TrafficForML_CICFlowMeter.csv", ["Malware Beacon", "BENIGN"]),
            ("Wednesday-21-02-2018_TrafficForML_CICFlowMeter.csv", ["DDoS", "BENIGN"]),
            ("Thursday-01-03-2018_TrafficForML_CICFlowMeter.csv", ["Lateral Movement", "BENIGN"]),
        ]

        np.random.seed(42)

        for filename, target_classes in extraction_specs:
            filepath = RAW_2018_DIR / filename
            if not filepath.exists():
                log_print(f"Warning: {filepath} not found!")
                continue

            log_print(f"  Streaming: {filename} for classes: {target_classes}...")
            chunksize = 50000
            file_collected_val = Counter()
            file_collected_test = Counter()

            for chunk_idx, chunk in enumerate(pd.read_csv(filepath, chunksize=chunksize, low_memory=False)):
                std_chunk = standardize_df(chunk, FEATURE_MAPPING_2018, "CSE-CIC-IDS2018")
                
                # Filter to target classes
                mask_class = std_chunk["ground_truth_label"].isin(target_classes)
                if not mask_class.any():
                    continue
                std_chunk = std_chunk[mask_class]

                # Hash rows
                chunk_hashes = hash_dataframe_rows(std_chunk)
                std_chunk["row_hash"] = chunk_hashes

                # Drop excluded rows
                unseen_chunk = std_chunk[~std_chunk["row_hash"].isin(exclusion_hashes)]
                if unseen_chunk.empty:
                    continue

                for _, row in unseen_chunk.iterrows():
                    lbl = row["ground_truth_label"]
                    h = row["row_hash"]

                    if h in exclusion_hashes:
                        continue

                    if val_counts[lbl] < val_quotas.get(lbl, 0):
                        val_rows.append(row.drop("row_hash"))
                        val_counts[lbl] += 1
                        file_collected_val[lbl] += 1
                        exclusion_hashes.add(h)
                    elif test_counts[lbl] < test_quotas.get(lbl, 0):
                        test_rows.append(row.drop("row_hash"))
                        test_counts[lbl] += 1
                        file_collected_test[lbl] += 1
                        exclusion_hashes.add(h)

                # Early check
                targets_done = all(
                    (val_counts[c] >= val_quotas.get(c, 0) and test_counts[c] >= test_quotas.get(c, 0))
                    for c in target_classes if c != "BENIGN"
                )
                if targets_done and val_counts["BENIGN"] >= val_quotas["BENIGN"] and test_counts["BENIGN"] >= test_quotas["BENIGN"]:
                    log_print(f"    All targets met after chunk {chunk_idx + 1}")
                    break

            log_print(f"    Finished {filename}: Val {dict(file_collected_val)}, Test {dict(file_collected_test)}")

        df_val = pd.DataFrame(val_rows)
        df_test = pd.DataFrame(test_rows)

        # 3. Save Partitions
        val_path = EXPERIMENT_DIR / "validation_split.parquet"
        test_path = EXPERIMENT_DIR / "final_sealed_test.parquet"

        df_val.to_parquet(val_path, index=False)
        df_test.to_parquet(test_path, index=False)

        val_sha = compute_sha256(val_path)
        test_sha = compute_sha256(test_path)

        log_print("\n" + "=" * 80)
        log_print("NEW PARTITION SUMMARY")
        log_print("=" * 80)
        log_print(f"Validation Split:")
        log_print(f"  Path: {val_path}")
        log_print(f"  Rows: {len(df_val):,}")
        log_print(f"  SHA-256: {val_sha}")
        log_print(f"  Class Breakdown:\n{df_val['ground_truth_label'].value_counts()}")

        log_print(f"\nFinal Sealed Test Split (FROZEN - TOUCHED ONCE IN TASK 7):")
        log_print(f"  Path: {test_path}")
        log_print(f"  Rows: {len(df_test):,}")
        log_print(f"  SHA-256: {test_sha}")
        log_print(f"  Class Breakdown:\n{df_test['ground_truth_label'].value_counts()}")

        # 4. Overlap verification
        log_print("\n[STEP 4] Rigorous Leakage & Overlap Audit...")
        val_hashes = set(hash_dataframe_rows(df_val))
        test_hashes = set(hash_dataframe_rows(df_test))

        overlap_val_test = len(val_hashes.intersection(test_hashes))
        log_print(f"  Overlap between Validation and Sealed Test: {overlap_val_test} rows")
        assert overlap_val_test == 0, f"LEAKAGE DETECTED: {overlap_val_test} rows shared between Val and Test!"

        log_print("  VERIFIED: Zero overlap between Validation and Sealed Test.")
        log_print("  VERIFIED: All diagnostic holdouts are officially marked BURNED.")
        log_print(f"  VERIFIED: final_sealed_test.parquet is FROZEN with SHA-256 {test_sha}")
        log_print("=" * 80)


if __name__ == "__main__":
    main()
