"""
CI feature parity against hand-computed fixtures (tests/fixtures/feature_parity_cases.json).

Each expected vector is a literal in the fixture, never produced by the code under test. No dataset or model is used,
so this says nothing about accuracy, and nothing about whether a live packet extractor matches the training tool.
"""
import importlib.util
import json
import os
from pathlib import Path

import numpy as np
import pandas as pd
import pytest

os.environ.setdefault("SENTINEL_KEY", "test-sentinel-secret-key-12345")
from inference import main  # noqa: E402
from utils.features import FEATURE_NAMES, extract_features_from_record, prepare_features  # noqa: E402

ENGINE = Path(__file__).resolve().parent.parent
FIXTURE = json.loads((ENGINE / "tests/fixtures/feature_parity_cases.json").read_text(encoding="utf-8"))
FIELDS = FIXTURE["fields"]
NAMES = [f["schema"] for f in FIELDS] + FIXTURE["derived"]
CASES = FIXTURE["cases"]
IDS = [c["name"] for c in CASES]
SOURCE_IP = "192.0.2.10"


def expected(case, time=(0.0, 0.0)):
    return np.array([*case["values"], case["entropy"], *time], dtype=float)


def by(column, case):
    return {f[column]: v for f, v in zip(FIELDS, case["values"])}


def served(body):
    return extract_features_from_record(main._record_payload(main.Record.model_validate({"sourceIP": SOURCE_IP, **body})))


def same(got, want):
    assert np.asarray(got).shape == (53,)
    np.testing.assert_allclose(np.asarray(got, dtype=float), want, rtol=1e-12, atol=1e-12)


def test_feature_names_and_order_equal_the_fixture_and_the_deployed_metadata():
    assert FEATURE_NAMES == NAMES and len(set(NAMES)) == 53
    assert [f["position"] for f in FIELDS] == list(range(50))
    for name in ("xgb_classifier_xgb_cicids_v1_meta.json", "isolation_forest_xgb_cicids_v1_meta.json"):
        assert json.loads((ENGINE / "models" / name).read_text(encoding="utf-8"))["feature_names"] == NAMES


@pytest.mark.parametrize("case", CASES, ids=IDS)
def test_training_preparation_matches_the_hand_computed_vector(case):
    frame = pd.DataFrame([{**by("csv_header", case), " Label": "BENIGN"}])
    matrix, labels = prepare_features(frame, max_missing=0)
    same(matrix[0], expected(case))
    assert matrix.dtype == np.float64 and labels.tolist() == [0]


@pytest.mark.parametrize("case", CASES, ids=IDS)
def test_direct_extraction_matches_for_schema_names_and_csv_aliases(case):
    same(extract_features_from_record(by("schema", case)), expected(case))
    same(extract_features_from_record({k.strip(): v for k, v in by("csv_header", case).items()}), expected(case))


@pytest.mark.parametrize("case", CASES, ids=IDS)
def test_inference_input_preparation_matches_and_is_complete(case):
    for body in (by("schema", case), {k.strip(): v for k, v in by("csv_header", case).items()}):
        same(served(body), expected(case))
        record = main.Record.model_validate({"sourceIP": SOURCE_IP, **body})
        assert main._defaulted_features(record) == []


@pytest.mark.parametrize("case", CASES, ids=IDS)
def test_sniffer_mapping_matches(case):
    spec = importlib.util.spec_from_file_location("flow_mapping", ENGINE.parent / "honeypot/sniffer/flow_mapping.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    row = {"src_ip": SOURCE_IP, **{k: str(v) for k, v in by("cicflowmeter", case).items()}}
    payload = module.to_detection_payload(row)
    same(extract_features_from_record(payload), expected(case))


@pytest.mark.parametrize("case", CASES, ids=IDS)
def test_a_timestamp_changes_only_the_two_time_features(case):
    stamp = FIXTURE["timestamp"]
    same(served({**by("schema", case), "timestamp": stamp["value"]}), expected(case, (stamp["sin"], stamp["cos"])))
