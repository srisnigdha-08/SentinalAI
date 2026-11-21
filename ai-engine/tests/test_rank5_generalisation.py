"""
Rank 5 evaluation tooling (evaluation/rank5_generalisation.py) on SYNTHETIC fixtures only.

These tests check the evaluation code: metrics, overlap / duplicate detection, schema and artifact checks, drift
statistics, insufficient-data and missing-class handling, status interpretation and non-overwriting output. Their
numbers are not SentinelAI model performance. Nothing here loads the served model, reads a real dataset or writes
outside pytest's tmp_path; the shipped models directory is hash-checked before and after.
"""
import hashlib
import json
import sys
from pathlib import Path

import numpy as np
import pandas as pd
import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))
from evaluation import rank5_generalisation as R  # noqa: E402

MODELS = Path(__file__).resolve().parent.parent / "models"
NAMES = {0: "BENIGN", 1: "SSH Brute Force", 2: "SQL Injection", 3: "Port Scan", 4: "DDoS"}


def _snapshot():
    return {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in MODELS.iterdir() if p.is_file()}


BEFORE = _snapshot()


@pytest.fixture(autouse=True)
def models_untouched():
    yield
    assert _snapshot() == BEFORE


# ── metrics ──────────────────────────────────────────────────────────────────────────────────────────────────────
def test_metrics_match_hand_computed_values():
    y_true = [0, 0, 0, 0, 1, 1, 4, 4]
    y_pred = [0, 0, 0, 1, 1, 0, 4, 4]
    m = R.classification_metrics(y_true, y_pred, NAMES)
    assert m["n"] == 8 and m["accuracy"] == pytest.approx(6 / 8)
    pc = m["per_class"]
    assert pc["BENIGN"]["precision"] == pytest.approx(3 / 4) and pc["BENIGN"]["recall"] == pytest.approx(3 / 4)
    assert pc["SSH Brute Force"]["precision"] == pytest.approx(1 / 2) and pc["SSH Brute Force"]["recall"] == pytest.approx(1 / 2)
    assert pc["DDoS"]["f1"] == 1.0
    assert m["balanced_accuracy"] == pytest.approx((0.75 + 0.5 + 1.0) / 3)
    assert m["f1_macro"] == pytest.approx((0.75 + 0.5 + 1.0) / 3)
    assert m["f1_weighted"] == pytest.approx((0.75 * 4 + 0.5 * 2 + 1.0 * 2) / 8)
    assert m["confusion_matrix"] == {"labels": ["BENIGN", "SSH Brute Force", "DDoS"],
                                     "rows_true_cols_pred": [[3, 1, 0], [1, 1, 0], [0, 0, 2]]}
    b = m["binary"]
    assert (b["benign"], b["attack"], b["fp"], b["fn"]) == (4, 4, 1, 1)
    assert b["fpr"] == pytest.approx(0.25) and b["fnr"] == pytest.approx(0.25)
    assert b["fpr_wilson95"][0] < 0.25 < b["fpr_wilson95"][1]


def test_missing_and_absent_classes_are_explicit():
    # SQL Injection is predicted but has no true rows; Port Scan is in the name map but absent entirely
    m = R.classification_metrics([0, 0, 4], [0, 2, 4], NAMES)
    assert m["macro_over_classes"] == ["BENIGN", "DDoS"]  # macro only over classes with true rows
    assert m["predicted_but_absent"] == ["SQL Injection"]
    assert m["per_class"]["SQL Injection"]["recall"] is None and m["per_class"]["SQL Injection"]["support"] == 0
    assert "Port Scan" not in m["per_class"]


def test_small_supports_are_flagged_unreliable():
    m = R.classification_metrics([0] * 40 + [1] * 3, [0] * 40 + [1] * 3, NAMES)
    assert m["per_class"]["BENIGN"]["reliable"] is True
    assert m["per_class"]["SSH Brute Force"]["reliable"] is False


def test_auc_is_reported_only_when_defined():
    m = R.classification_metrics([0, 0, 1, 1], [0, 1, 1, 1], NAMES, p_attack=[0.1, 0.6, 0.7, 0.9])
    assert m["binary"]["roc_auc"] == 1.0 and m["binary"]["pr_auc"] == 1.0
    one_class = R.classification_metrics([1, 1], [1, 1], NAMES, p_attack=[0.9, 0.8])
    assert one_class["binary"]["roc_auc"] is None and one_class["binary"]["auc_not_computed_because"]


def test_alert_line_flags_replace_argmax_for_the_binary_view():
    m = R.classification_metrics([0, 1, 1], [1, 1, 1], NAMES, flagged=[False, True, False])
    assert (m["binary"]["fp"], m["binary"]["fn"]) == (0, 1)


def test_empty_input_is_insufficient_data():
    assert R.classification_metrics([], [], NAMES)["status"] == "INSUFFICIENT_DATA"
    assert R.majority_baseline([], NAMES)["status"] == "INSUFFICIENT_DATA"


def test_majority_baseline():
    b = R.majority_baseline([0, 0, 0, 1], NAMES)
    assert b["predicts"] == "BENIGN" and b["accuracy"] == 0.75 and b["balanced_accuracy"] == 0.5


def test_per_day_rows_keep_supports_separate():
    days = ["2018-02-14"] * 3 + ["2018-02-15"] * 2
    rows = R.group_rows(days, [0, 1, 1, 0, 0], [0, 1, 0, 1, 0], NAMES)
    assert [r["group"] for r in rows] == ["2018-02-14", "2018-02-15"]
    d1, d2 = rows
    assert (d1["n"], d1["benign"], d1["attack"], d1["fnr"]) == (3, 1, 2, 0.5)
    assert (d2["n"], d2["attack"], d2["fpr"], d2["fnr"]) == (2, 0, 0.5, None)
    assert json.loads(d1["class_support"]) == {"BENIGN": 1, "SSH Brute Force": 2}


# ── overlap, duplicates, schema, chronology ─────────────────────────────────────────────────────────────────────
def test_overlap_and_duplicate_detection():
    train = np.array([[1.0, 2.0], [3.0, 4.0]])
    test = np.array([[3.0, 4.0], [5.0, 6.0], [5.0, 6.0], [1.0, 2.0000001]])
    m = R.overlap_mask(R.row_hashes(test), R.row_hashes(train))
    assert m.tolist() == [True, False, False, False]  # exact values only; 2.0000001 is not a duplicate
    first = R.first_occurrence_mask(R.row_hashes(test))
    assert first.tolist() == [True, True, False, True]
    by_label = R.first_occurrence_mask(R.row_hashes(test), labels=[0, 0, 1, 0])
    assert by_label.tolist() == [True, True, True, True]  # same vector, different label: both kept


def test_feature_schema_validation():
    expected = ["a", "b", "c"]
    assert R.validate_feature_matrix(np.zeros((2, 3)), expected, expected) == []
    p = R.validate_feature_matrix(np.zeros((2, 3)), ["a", "c", "b"], expected)
    assert p[0]["check"] == "feature_names" and p[0]["order_differs"] is True
    p = R.validate_feature_matrix(np.zeros((2, 2)), ["a", "b"], expected)
    assert {x["check"] for x in p} == {"feature_names", "shape"}
    bad = np.zeros((3, 3))
    bad[1, 2] = np.inf
    assert R.validate_feature_matrix(bad, expected, expected) == [{"check": "finite", "non_finite_rows": 1}]


def test_2017_days_come_from_the_published_schedule():
    assert R.day_of_2017("Monday-WorkingHours.pcap_ISCX.csv") == "2017-07-03"
    assert R.day_of_2017("Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv") == "2017-07-07"
    with pytest.raises(ValueError):
        R.day_of_2017("Saturday.csv")


def test_timestamp_range_and_chronology(tmp_path):
    f = tmp_path / "Wednesday-14-02-2018_TrafficForML_CICFlowMeter.csv"
    pd.DataFrame({"Timestamp": ["14/02/2018 08:31:01", "14/02/2018 10:00:00", "Timestamp", "not a date"],
                  "Label": ["Benign"] * 4}).to_csv(f, index=False)
    r = R.timestamp_range_2018(f)
    assert r["rows"] == 3 and r["invalid"] == 1 and r["dates"] == ["2018-02-14"]
    assert r["min"] > "2017-07-08"  # after every 2017 training day


def test_protected_days_are_refused_before_opening(tmp_path, monkeypatch):
    from evaluation.protected_data import ProtectedDataError
    f = tmp_path / "Friday-16-02-2018_TrafficForML_CICFlowMeter.csv"  # name only; the file need not exist
    opened = []
    monkeypatch.setattr(pd, "read_csv", lambda *a, **k: opened.append(a) or pd.DataFrame())
    with pytest.raises(ProtectedDataError):
        R.timestamp_range_2018(f)
    with pytest.raises(ProtectedDataError):
        next(R.iter_2018_chunks(f))
    assert opened == []


def test_2018_chunks_map_columns_drop_non_finite_and_cap_rows(tmp_path):
    from evaluation.dev_experiments import _mapping_2018
    mapping = _mapping_2018()
    raw_cols = list(mapping)[:5]
    df = pd.DataFrame({c: [1.0, 2.0, float("inf"), 4.0] for c in raw_cols})
    df["Label"] = ["Benign", "DDoS attack-HOIC", "Benign", "Label"]
    f = tmp_path / "Thursday-01-03-2018_TrafficForML_CICFlowMeter.csv"
    df.to_csv(f, index=False)
    parts = list(R.iter_2018_chunks(f))
    part, raw, dropped, total = parts[0]
    assert list(part.columns) == [mapping[c] for c in raw_cols]
    assert raw == ["benign", "ddos attack hoic"] and dropped == 1  # inf row dropped, repeated header removed
    capped = list(R.iter_2018_chunks(f, max_rows=1))
    assert len(capped[0][0]) == 1


def test_cicids_cleaning_keeps_csv_row_positions(tmp_path):
    f = tmp_path / "Monday-WorkingHours.pcap_ISCX.csv"
    pd.DataFrame({" Flow Duration": [10, "x", 30, np.inf], " Label": ["BENIGN"] * 4}).to_csv(f, index=False)
    c = R.clean_cicids_file(f)
    assert c.index.tolist() == [0, 2]  # non-numeric and infinite rows dropped, positions kept for pool matching
    assert c["label"].tolist() == ["BENIGN", "BENIGN"]


# ── drift ────────────────────────────────────────────────────────────────────────────────────────────────────────
def test_psi_and_ks_detect_a_shift_and_not_an_identical_sample():
    rng = np.random.default_rng(0)
    ref = rng.normal(0, 1, 5000)
    assert R.psi(ref, ref) == pytest.approx(0.0, abs=1e-9)
    shifted = R.psi(ref, rng.normal(1.5, 1, 5000))
    assert shifted >= 0.25 and R.psi_band(shifted) == "large"
    assert R.psi_band(0.05) == "small" and R.psi_band(0.2) == "moderate" and R.psi_band(None) == "constant_reference"
    assert R.psi(np.zeros(100), np.ones(100)) is None  # constant reference: undefined, never invented
    k, p = R.ks(ref, rng.normal(1.5, 1, 5000))
    assert k > 0.4 and p < 1e-6


def test_drift_compare_reports_insufficient_data_and_constant_features():
    rng = np.random.default_rng(1)
    small = R.drift_compare(rng.normal(size=(100, 2)), rng.normal(size=(100, 2)), ["a", "b"])
    assert small["status"] == "INSUFFICIENT_DATA"
    ref = np.column_stack([rng.normal(size=2000), np.zeros(2000)])
    cur = np.column_stack([rng.normal(2, 1, size=2000), np.zeros(2000)])
    d = R.drift_compare(ref, cur, ["moved", "constant"])
    assert d["status"] == "OK" and d["features_large_psi"] == 1 and d["features_constant"] == 1
    assert d["top_psi"][0]["feature"] == "moved"


# ── artifacts, status, outputs ───────────────────────────────────────────────────────────────────────────────────
def _fake_model_dir(tmp_path, version="xgb_cicids_v1"):
    d = tmp_path / "models"
    d.mkdir(parents=True)
    reg = {}
    for role, name in (("classifier", "c.pkl"), ("anomaly", "a.pkl"), ("golden", "g.json")):
        (d / name).write_bytes(role.encode())
        reg[role] = {"file": name, "sha256": hashlib.sha256(role.encode()).hexdigest(), "version": version}
    (d / "registry.json").write_text(json.dumps(reg))
    return d


def test_artifact_integrity_passes_and_fails_closed(tmp_path):
    d = _fake_model_dir(tmp_path)
    assert R.verify_artifacts(d)["version"] == "xgb_cicids_v1"
    (d / "a.pkl").write_bytes(b"tampered")
    with pytest.raises(R.IntegrityError, match="anomaly sha256 mismatch"):
        R.verify_artifacts(d)
    other = _fake_model_dir(tmp_path / "x", version="candidate_v4")
    with pytest.raises(R.IntegrityError, match="expected 'xgb_cicids_v1'"):
        R.verify_artifacts(other)


def test_the_real_registry_still_verifies():
    assert R.verify_artifacts(MODELS)["version"] == "xgb_cicids_v1"


def test_status_never_claims_verified_generalisation():
    base = {"integrity_before_ok": True, "integrity_after_ok": True, "parity_ok": True, "provenance_ok": True,
            "e1_reproduced": True, "leakage_assessment": "LIMITED", "drift_ok": True}
    good = R.rank5_status({**base, "e3": {"status": "OK", "macro_f1": 0.97}})
    assert good["evaluation_tooling"] == "READY" and good["independent_generalisation"] == "NOT_VERIFIED"
    assert good["chronological_evaluation"] == "LIMITED" and good["generalisation_finding"] == "LIMITED_EVIDENCE"
    poor = R.rank5_status({**base, "e3": {"status": "OK", "macro_f1": 0.2}})
    assert poor["generalisation_finding"] == "POOR_ON_LATER_DIFFERENT_NETWORK"
    none = R.rank5_status({**base, "e3": {"status": "INSUFFICIENT_DATA"}, "drift_ok": False})
    assert none["chronological_evaluation"] == "INSUFFICIENT_DATA" and none["drift_diagnostics"] == "INSUFFICIENT_DATA"
    broken = R.rank5_status({**base, "integrity_after_ok": False, "e3": {}})
    assert broken["model_integrity"] == "FAILED" and broken["evaluation_tooling"] == "FAILED"


def test_outputs_are_never_overwritten(tmp_path):
    d1 = R.new_run_dir(tmp_path, "20261114T000000Z")
    d2 = R.new_run_dir(tmp_path, "20261114T000000Z")
    assert d1 != d2 and d1.exists() and d2.exists()
    R.write_json(d1 / "metrics.json", {"a": np.int64(1), "b": np.float32(0.5), "c": np.arange(2)})
    assert json.loads((d1 / "metrics.json").read_text()) == {"a": 1, "b": 0.5, "c": [0, 1]}
    with pytest.raises(FileExistsError):
        R.write_json(d1 / "metrics.json", {})
    R.write_csv(d1 / "per_class_metrics.csv", [{"class": "BENIGN", "recall": 1.0}])
    with pytest.raises(FileExistsError):
        R.write_csv(d1 / "per_class_metrics.csv", [])


def test_chronology_check_separates_clock_artefacts_from_real_dates():
    ok = {"a.csv": {"timestamps": {"rows_per_date": {"1970-01-05": 3, "2018-02-14": 100}, "invalid": 0}}}
    r = R.chronology_check(ok)
    assert r["result"] == "PASS" and r["rows_with_implausible_dates"] == 3 and r["rows_dated_on_or_before_training"] == 0
    bad = {"b.csv": {"timestamps": {"rows_per_date": {"2017-07-05": 2, "2018-02-14": 9}, "invalid": 1}}}
    r = R.chronology_check(bad)
    assert r["result"] == "FAIL" and r["rows_dated_on_or_before_training"] == 2
    assert R.chronology_check({"c.csv": {"timestamps": {"skipped": "smoke run"}}})["result"] == "NOT_CHECKED"
    assert R.chronology_check({})["result"] == "NOT_CHECKED"


def test_truncation_check_flags_the_spreadsheet_row_limit():
    r = R.truncation_check({"a.csv": {"csv_rows": R.EXCEL_ROW_LIMIT}, "b.csv": {"csv_rows": 331100}})
    assert r["result"] == "SUSPECTED" and r["files"] == {"a.csv": R.EXCEL_ROW_LIMIT}
    assert R.truncation_check({"b.csv": {"csv_rows": 10}})["result"] == "NO"
