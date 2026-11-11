"""Feature-parity remediation: non-finite flows, missing features, timestamp zero, strict numbers, class names."""
import importlib.util
import json
import math
import os
from collections import Counter
from pathlib import Path

import numpy as np
import pytest
from pydantic import ValidationError

os.environ.setdefault("SENTINEL_KEY", "test-sentinel-secret-key-12345")
from inference import main  # noqa: E402
from inference.predictor import LABEL_NAMES, SentinelPredictor  # noqa: E402
from utils.features import FEATURE_NAMES, extract_features_from_record  # noqa: E402

ENGINE = Path(__file__).resolve().parent.parent
NUMERIC = json.loads((ENGINE / "tests/fixtures/strict_numeric_cases.json").read_text(encoding="utf-8"))
RAW_FIELDS = FEATURE_NAMES[:50]
# Written out here so the test does not depend on the production list.
NON_ZERO_DEFAULT_FIELDS = {
    "flow_duration", "total_fwd_packets", "total_len_fwd_packets", "fwd_packet_len_max", "fwd_packet_len_min",
    "fwd_packet_len_mean", "flow_bytes_per_sec", "flow_packets_per_sec", "flow_iat_mean", "flow_iat_max",
    "flow_iat_min", "syn_flag_count", "fwd_header_len",
}
ZERO_DEFAULT_FIELDS = [f for f in RAW_FIELDS if f not in NON_ZERO_DEFAULT_FIELDS]


def sniffer():
    spec = importlib.util.spec_from_file_location("flow_mapping", ENGINE.parent / "honeypot/sniffer/flow_mapping.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def complete():
    return {"sourceIP": "198.51.100.7", **{f: float(i + 1) for i, f in enumerate(RAW_FIELDS)}}


def policy(body, action="BLOCK"):
    return main._input_policy({"action": action}, main.Record.model_validate(body))


def without(*fields):
    body = complete()
    for f in fields:
        body.pop(f)
    return body


# Fix 1: present but non-finite values skip the flow instead of being replaced by defaults
ROW = {"src_ip": "198.51.100.4", "flow_duration": "1200", "tot_fwd_pkts": "3", "flow_byts_s": "100.5", "flow_pkts_s": "2.5"}


@pytest.mark.parametrize("column", ["flow_byts_s", "flow_pkts_s"])
@pytest.mark.parametrize("value", ["inf", "Infinity", "-inf", "nan", "NaN"])
def test_sniffer_skips_a_flow_with_a_non_finite_rate(column, value):
    assert sniffer().to_detection_payload({**ROW, column: value}) is None


def test_sniffer_counts_rejections_by_field_name_only():
    rejected = Counter()
    assert sniffer().to_detection_payload({**ROW, "flow_byts_s": "inf", "flow_pkts_s": "nan"}, rejected=rejected) is None
    assert rejected == Counter({"flow_bytes_per_sec": 1, "flow_packets_per_sec": 1})


def test_sniffer_keeps_flows_that_merely_lack_a_column():
    payload = sniffer().to_detection_payload(ROW)
    assert payload["flow_bytes_per_sec"] == 100.5 and "fwd_header_len" not in payload


# Fix 2: fabricated defaults make the input incomplete
@pytest.mark.parametrize("field", sorted(NON_ZERO_DEFAULT_FIELDS))
def test_one_missing_non_zero_default_is_incomplete_and_never_blocks(field):
    result = policy(without(field))
    assert result["incompleteInput"] is True
    assert result["action"] == "MONITOR" and result["actionCappedReason"] == "incomplete_input"
    assert result["defaultedFeatures"] == [field]


def test_the_production_list_is_exactly_the_non_zero_serving_defaults():
    assert set(main.FABRICATED_DEFAULT_FEATURES) == NON_ZERO_DEFAULT_FIELDS
    for field in RAW_FIELDS:
        record = main._record_payload(main.Record.model_validate(without(field)))
        value = float(extract_features_from_record(record)[FEATURE_NAMES.index(field)])
        assert (value != 0.0) == (field in NON_ZERO_DEFAULT_FIELDS), field


def test_up_to_five_missing_zero_default_fields_stay_complete():
    result = policy(without(*ZERO_DEFAULT_FIELDS[:5]))
    assert result["incompleteInput"] is False and result["action"] == "BLOCK"


def test_a_sixth_missing_zero_default_field_is_incomplete():
    result = policy(without(*ZERO_DEFAULT_FIELDS[:6]))
    assert result["incompleteInput"] is True and result["action"] == "MONITOR"


@pytest.mark.parametrize("field", sorted(NON_ZERO_DEFAULT_FIELDS))
def test_a_measured_zero_is_not_a_missing_feature(field):
    result = policy({**complete(), field: 0})
    assert result["defaultedFeatures"] == [] and result["incompleteInput"] is False and result["action"] == "BLOCK"


def test_derived_features_are_never_reported_as_missing():
    assert not {"payload_entropy", "time_of_day_sin", "time_of_day_cos"} & set(policy(complete())["defaultedFeatures"])


@pytest.mark.parametrize("action", ["MONITOR", "REVIEW", "ALLOW"])
def test_incomplete_input_keeps_non_block_decisions(action):
    result = policy(without("flow_duration"), action=action)
    assert result["incompleteInput"] is True and result["action"] == action and "actionCappedReason" not in result


# Fix 3: timestamp zero is a timestamp
@pytest.mark.parametrize("key", ["timestamp", "Timestamp"])
def test_epoch_zero_is_midnight_not_a_missing_timestamp(key):
    vector = extract_features_from_record({**complete(), key: 0})
    assert vector[51] == pytest.approx(0.0, abs=1e-12) and vector[52] == pytest.approx(1.0, abs=1e-12)


def test_a_missing_timestamp_still_gives_the_neutral_origin():
    vector = extract_features_from_record(complete())
    assert vector[51] == 0.0 and vector[52] == 0.0


# Fix 4: one numeric rule, one table
VALID = [(c["name"], c["value"], c["number"]) for c in NUMERIC["valid"]]
INVALID = [(c["name"], c["value"]) for c in NUMERIC["invalid"]]


@pytest.mark.parametrize("name,value,number", VALID, ids=[c[0] for c in VALID])
def test_sniffer_accepts_valid_numbers(name, value, number):
    assert sniffer()._number(value) == number


@pytest.mark.parametrize("name,value", INVALID, ids=[c[0] for c in INVALID])
def test_sniffer_rejects_invalid_numbers(name, value):
    assert sniffer()._number(value) is None


ENGINE_KEYS = ["flow_duration", "Flow Duration", " flow  duration", "init_win_bytes_forward", "Init_Win_bytes_forward"]


def engine_vector(key, value):
    target = "flow_duration" if "duration" in key.lower() else "init_win_bytes_forward"
    body = {k: v for k, v in complete().items() if k != target}
    record = main._record_payload(main.Record.model_validate({**body, key: value}))
    return float(extract_features_from_record(record)[FEATURE_NAMES.index(target)])


@pytest.mark.parametrize("key", ENGINE_KEYS)
@pytest.mark.parametrize("name,value,number", VALID, ids=[c[0] for c in VALID])
def test_engine_accepts_valid_numbers(key, name, value, number):
    assert engine_vector(key, value) == number


@pytest.mark.parametrize("key", ENGINE_KEYS)
@pytest.mark.parametrize("name,value", INVALID, ids=[c[0] for c in INVALID])
def test_engine_rejects_invalid_numbers(key, name, value):
    with pytest.raises(ValidationError):
        engine_vector(key, value)


@pytest.mark.parametrize("value", [float("nan"), float("inf"), float("-inf"), 10 ** 400])
def test_non_finite_python_numbers_are_rejected_everywhere(value):
    assert sniffer()._number(value) is None
    with pytest.raises(ValidationError):
        engine_vector("flow_duration", value)


def test_rejection_message_does_not_echo_the_value():
    with pytest.raises(ValidationError) as caught:
        engine_vector("flow_duration", "attacker-controlled-text")
    assert "attacker-controlled-text" not in str(caught.value.errors()[0]["msg"])


# Fix 5: probability names follow classes_
class StubClassifier:
    classes_ = np.array([0, 2, 5])


def assembled(proba):
    predictor = SentinelPredictor.__new__(SentinelPredictor)
    predictor.rf = StubClassifier()
    predictor.rf_meta, predictor._low_data_classes = {"version": "stub"}, set()
    position = int(np.argmax(proba))
    label = StubClassifier.classes_[position]
    return predictor._assemble({}, np.zeros(len(FEATURE_NAMES)), label, np.array(proba), position, 0.0, 0.0, False, None)


def test_probabilities_are_named_by_classes_not_position():
    result = assembled([0.1, 0.2, 0.7])
    assert result["classProbabilities"] == {LABEL_NAMES[0]: 0.1, LABEL_NAMES[2]: 0.2, LABEL_NAMES[5]: 0.7}
    assert result["predictedClass"] == LABEL_NAMES[5]
    assert math.isclose(sum(result["classProbabilities"].values()), 1.0)


def test_probabilities_without_classes_keep_positional_names():
    predictor = SentinelPredictor.__new__(SentinelPredictor)
    predictor.rf = object()
    predictor.rf_meta, predictor._low_data_classes = {"version": "stub"}, set()
    result = predictor._assemble({}, np.zeros(len(FEATURE_NAMES)), 1, np.array([0.4, 0.6]), 1, 0.0, 0.0, False, None)
    assert result["classProbabilities"] == {LABEL_NAMES[0]: 0.4, LABEL_NAMES[1]: 0.6}
