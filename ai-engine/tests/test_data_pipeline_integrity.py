"""
Unit and Regression Test Suite for Data-Pipeline Integrity
Tests early stopping avoidance, complete chunk traversal, source exhaustion handling,
missing class handling, omitted 21-Feb-2018 schema compatibility, and target class coverage.

IMPORTANT: Tests exercise the REAL extractor function extract_chunks_robust from
ai-engine/experiments/gate1_phase10_detector_recovery/build_candidate_v2_fixed.py.
"""

import sys
import io
import math
import hashlib
from pathlib import Path
import numpy as np
import pandas as pd
import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
PHASE8_DIR = REPO_ROOT / "experiments" / "gate1_phase8_multicorpus_candidates"
PHASE10_DIR = REPO_ROOT / "experiments" / "gate1_phase10_detector_recovery"

sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(PHASE8_DIR))
sys.path.insert(0, str(PHASE10_DIR))

from utils.features import FEATURE_NAMES, LABEL_MAP, LABEL_NAMES
from build_multicorpus_pipeline import FEATURE_MAPPING_2018, RAW_TO_SENTINEL, standardize_df
# Import REAL extractor function from candidate v2 builder
from build_candidate_v2_fixed import extract_chunks_robust


class TestDataPipelineIntegrity:
    def test_real_extractor_early_stopping_avoidance(self, tmp_path):
        """
        Exercises the REAL extract_chunks_robust function:
        When chunk 0 only contains BENIGN rows, extraction MUST NOT terminate early.
        It must continue to subsequent chunks where Infiltration / Lateral Movement resides.
        """
        csv_file = tmp_path / "mock_multichunk.csv"
        
        # Build 30 rows: chunk 0 (rows 0-14) = Benign; chunk 1 (rows 15-29) = Infilteration
        data = []
        for i in range(30):
            row = {"Label": "Benign" if i < 15 else "Infilteration", "Timestamp": "01/03/2018 08:30:00"}
            for feat_name, raw_name in FEATURE_MAPPING_2018:
                row[raw_name] = float(i)
            data.append(row)
        
        df_mock = pd.DataFrame(data)
        df_mock.to_csv(csv_file, index=False)

        target_quota = {"BENIGN": 5, "Lateral Movement": 5}
        result_df = extract_chunks_robust(
            csv_path=csv_file,
            mapping=FEATURE_MAPPING_2018,
            corpus_name="CSE-2018",
            target_classes_dict=target_quota,
            holdout_hashes=set(),
            chunksize=10
        )

        assert not result_df.empty, "Extractor returned empty DataFrame"
        counts = result_df["ground_truth_label"].value_counts().to_dict()
        assert counts.get("BENIGN", 0) == 5, f"Expected 5 BENIGN rows, got {counts.get('BENIGN', 0)}"
        assert counts.get("Lateral Movement", 0) == 5, (
            f"Expected 5 Lateral Movement rows from chunk 1, got {counts.get('Lateral Movement', 0)}. "
            "Pipeline exited early on chunk 0!"
        )

    def test_real_extractor_missing_classes_terminates_gracefully(self, tmp_path):
        """
        Exercises the REAL extract_chunks_robust function when a requested class
        is completely missing from the CSV. Must traverse to EOF and return available classes.
        """
        csv_file = tmp_path / "mock_missing_class.csv"
        data = []
        for i in range(20):
            row = {"Label": "Benign", "Timestamp": "01/03/2018 08:30:00"}
            for feat_name, raw_name in FEATURE_MAPPING_2018:
                row[raw_name] = float(i)
            data.append(row)
        pd.DataFrame(data).to_csv(csv_file, index=False)

        # Request quota for BENIGN (present) and SQL Injection (missing from this file)
        target_quota = {"BENIGN": 5, "SQL Injection": 10}
        result_df = extract_chunks_robust(
            csv_path=csv_file,
            mapping=FEATURE_MAPPING_2018,
            corpus_name="CSE-2018",
            target_classes_dict=target_quota,
            holdout_hashes=set(),
            chunksize=5
        )

        assert len(result_df) == 5, f"Expected 5 BENIGN rows, got {len(result_df)}"
        assert (result_df["ground_truth_label"] == "BENIGN").all()

    def test_real_extractor_source_exhaustion_terminates_gracefully(self, tmp_path):
        """
        Exercises the REAL extract_chunks_robust function when source data is exhausted
        before quota is reached. Must terminate cleanly at EOF without infinite loop.
        """
        csv_file = tmp_path / "mock_exhaustion.csv"
        data = []
        for i in range(12):
            row = {"Label": "Infilteration", "Timestamp": "01/03/2018 09:00:00"}
            for feat_name, raw_name in FEATURE_MAPPING_2018:
                row[raw_name] = float(i * 10)
            data.append(row)
        pd.DataFrame(data).to_csv(csv_file, index=False)

        # Request quota of 50, but only 12 rows exist in total
        target_quota = {"Lateral Movement": 50}
        result_df = extract_chunks_robust(
            csv_path=csv_file,
            mapping=FEATURE_MAPPING_2018,
            corpus_name="CSE-2018",
            target_classes_dict=target_quota,
            holdout_hashes=set(),
            chunksize=5
        )

        assert len(result_df) == 12, f"Expected exactly 12 exhausted rows, got {len(result_df)}"
        assert result_df["ground_truth_label"].nunique() == 1
        assert result_df["ground_truth_label"].iloc[0] == "Lateral Movement"

    def test_omitted_traffic_file_wednesday_2018_schema_and_mapping(self):
        """
        Validates schema compatibility and label mapping for the omitted 21-Feb-2018 traffic file.
        Confirms DDOS attack-HOIC and DDOS attack-LOIC-UDP map cleanly to DDoS (Class 4).
        """
        csv_path = Path("D:/sentinelai_datasets/cse_cic_ids2018/Wednesday-21-02-2018_TrafficForML_CICFlowMeter.csv")
        if not csv_path.exists():
            pytest.skip("Dataset file Wednesday-21-02-2018 not present on D: drive")

        # Read first 100 rows
        head_df = pd.read_csv(csv_path, nrows=100)
        assert "Label" in head_df.columns, "Label column missing from Wednesday-21-02-2018"

        # Verify feature mapping
        mapped_df = standardize_df(head_df, FEATURE_MAPPING_2018, "CSE-CIC-IDS2018")
        assert len(mapped_df) == 100
        for f in FEATURE_NAMES:
            assert f in mapped_df.columns, f"Feature {f} missing after standardizing Wednesday-21-02-2018"

        # Verify mapping dictionary maps HOIC and LOIC
        assert RAW_TO_SENTINEL.get("DDOS attack-HOIC") == "DDoS"
        assert RAW_TO_SENTINEL.get("DDOS attack-LOIC-UDP") == "DDoS"
        assert LABEL_MAP["DDoS"] == 4

    def test_label_mapping_discrepancy_and_coverage_regression(self):
        """
        Regression test confirming:
        1. 'Malware Beacon' is Class 7 (NOT Class 4; 'class 4' in prior report was a documentation typo).
        2. 'DDoS' is Class 4.
        3. 'RCE Attempt' (Heartbleed) is Class 5.
        4. 'Lateral Movement' (Infiltration) is Class 9.
        5. 'Data Exfiltration' is Class 10 (synthetic in baseline; excluded from real multicorpus).
        """
        assert LABEL_MAP["Malware Beacon"] == 7, "Malware Beacon must be mapped to Class 7"
        assert LABEL_NAMES[7] == "Malware Beacon"
        assert LABEL_MAP["DDoS"] == 4, "DDoS must be mapped to Class 4"
        assert LABEL_NAMES[4] == "DDoS"
        assert LABEL_MAP["RCE Attempt"] == 5, "RCE Attempt must be mapped to Class 5"
        assert LABEL_NAMES[5] == "RCE Attempt"
        assert LABEL_MAP["Lateral Movement"] == 9, "Lateral Movement must be mapped to Class 9"
        assert LABEL_NAMES[9] == "Lateral Movement"

        # Verify raw string mapping
        assert RAW_TO_SENTINEL["Bot"] == "Malware Beacon"
        assert RAW_TO_SENTINEL["Heartbleed"] == "RCE Attempt"
        assert RAW_TO_SENTINEL["Infiltration"] == "Lateral Movement"
        assert RAW_TO_SENTINEL["Infilteration"] == "Lateral Movement"
