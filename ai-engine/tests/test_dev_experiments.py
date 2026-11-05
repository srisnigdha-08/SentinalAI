"""Development-experiment infrastructure (audit/ML_DEV_PROTOCOL.md): protected-data guard, taxonomies, feature
variants, folds and the two architectures — synthetic data only, no CICIDS files, trivial estimators."""
import sys
from pathlib import Path

import numpy as np
import pandas as pd
import pytest
from sklearn.tree import DecisionTreeClassifier

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from evaluation import dev_experiments as D, feature_sets as F, protected_data as P, taxonomies as T  # noqa: E402
from utils.features import FEATURE_NAMES  # noqa: E402


# ── protected final external test ───────────────────────────────────────────────────────────────────────────
@pytest.mark.parametrize("name", ["Friday-16-02-2018_TrafficForML_CICFlowMeter.csv",
                                  "Thuesday-20-02-2018_TrafficForML_CICFlowMeter.csv",
                                  "Thursday-22-02-2018_TrafficForML_CICFlowMeter.csv",
                                  "Wednesday-28-02-2018_TrafficForML_CICFlowMeter.csv"])
def test_protected_days_cannot_be_read(name, tmp_path, monkeypatch):
    monkeypatch.delenv("SENTINEL_FINAL_EXTERNAL_EVAL", raising=False)
    with pytest.raises(P.ProtectedDataError):
        P.assert_permitted(tmp_path / name)
    with pytest.raises(P.ProtectedDataError):
        D.load_2018_file(tmp_path / name)  # the loader refuses before touching the file
    with pytest.raises(P.ProtectedDataError):  # the approval only works for the final-evaluation call
        monkeypatch.setenv("SENTINEL_FINAL_EXTERNAL_EVAL", P.APPROVAL_VALUE)
        P.assert_permitted(tmp_path / name)


def test_development_days_are_permitted_and_listing_skips_protected(tmp_path):
    for n in ["Wednesday-14-02-2018_TrafficForML_CICFlowMeter.csv", "Friday-16-02-2018_TrafficForML_CICFlowMeter.csv"]:
        (tmp_path / n).write_text("x\n")
    ok, skipped = P.permitted_files(tmp_path)
    assert [f.name for f in ok] == ["Wednesday-14-02-2018_TrafficForML_CICFlowMeter.csv"]
    assert skipped == ["Friday-16-02-2018_TrafficForML_CICFlowMeter.csv"]
    P.assert_permitted(ok[0])


# ── taxonomies ───────────────────────────────────────────────────────────────────────────────────────────────
def test_raw_labels_of_both_corpora_map_and_unknown_labels_raise():
    raw = ["BENIGN", "Web Attack � Brute Force", "FTP-Patator", "FTP-BruteForce", "DDOS attack-HOIC", "Infilteration"]
    assert list(T.map_labels(raw, "T0")) == ["BENIGN", "Credential Stuffing", "Credential Stuffing", "Credential Stuffing", "DDoS", "Lateral Movement"]
    assert list(T.map_labels(raw, "T1"))[1:4] == ["Web Brute Force", "FTP Brute Force", "FTP Brute Force"]
    assert list(T.map_labels(raw, "T2")) == ["Benign", "Brute Force", "Brute Force", "Brute Force", "DoS/DDoS", "Infiltration"]
    assert set(T.map_labels(raw, "TB")) == {"Benign", "Attack"}
    with pytest.raises(KeyError):
        T.map_labels(["Something New"], "T0")


def test_t0_matches_the_deployed_label_contract():
    from utils.features import LABEL_MAP
    assert set(T.describe("T0")) | set(T.NO_DATA) == set(LABEL_MAP)


# ── feature variants ─────────────────────────────────────────────────────────────────────────────────────────
def test_feature_variants_drop_and_transform_as_documented():
    X = np.abs(np.random.default_rng(0).normal(size=(5, len(FEATURE_NAMES)))) * 100
    a, na = F.variant(X, "A")
    assert na == list(FEATURE_NAMES) and np.allclose(a, X)
    b, nb = F.variant(X, "B")
    assert len(nb) == 47 and not set(F.CONSTANT_IN_POOL) & set(nb)
    c, nc = F.variant(X, "C")
    assert len(nc) == 45 and "init_win_bytes_backward" not in nc
    d, nd = F.variant(X, "D")
    i = nd.index("flow_duration")
    assert np.allclose(d[:, i], np.log1p(X[:, i])) and np.allclose(d[:, nd.index("syn_flag_count")], X[:, FEATURE_NAMES.index("syn_flag_count")])
    e, ne = F.variant(X, "E")
    h = ne.index("fwd_header_len")
    assert np.allclose(e[:, h], X[:, FEATURE_NAMES.index("fwd_header_len")] / np.maximum(X[:, FEATURE_NAMES.index("total_fwd_packets")], 1))
    with pytest.raises(ValueError):
        F.variant(X[:, :10], "A")


def test_variants_are_row_wise_so_they_cannot_leak_between_splits():
    X = np.abs(np.random.default_rng(1).normal(size=(20, len(FEATURE_NAMES))))
    for v in F.VARIANTS:
        whole, _ = F.variant(X, v)
        parts = np.vstack([F.variant(X[:7], v)[0], F.variant(X[7:], v)[0]])
        assert np.allclose(whole, parts)


# ── folds and architectures ──────────────────────────────────────────────────────────────────────────────────
def _toy():
    rng = np.random.default_rng(2)
    n = 240
    X = np.abs(rng.normal(size=(n, len(FEATURE_NAMES))))
    raw = np.array(["benign"] * 120 + ["ftp patator"] * 40 + ["ddos"] * 40 + ["ftp bruteforce"] * 40, dtype=object)
    X[120:, 0] += 5  # attacks separable on flow_duration
    meta = pd.DataFrame({"corpus": ["2017"] * 200 + ["2018"] * 40, "file": "f", "row": np.arange(n), "raw": raw,
                         "day": (["Monday", "Tuesday"] * 100) + ["14-02-2018"] * 20 + ["21-02-2018"] * 20})
    return X, raw, meta


def test_2017_only_candidates_never_train_on_2018_and_folds_are_disjoint():
    X, raw, meta = _toy()
    for name, tr, te in D.folds(meta, "D17", "2017"):
        assert not (tr & te).any() and not (tr & (meta["corpus"] == "2018").to_numpy()).any()
    d18 = D.folds(meta, "D18", "2017+2018dev")
    assert [n for n, _, _ in d18] == ["2018-14-02-2018", "2018-21-02-2018"]
    tr, te = d18[0][1], d18[0][2]
    assert (meta["day"][te] == "14-02-2018").all() and not (meta["day"][tr] == "14-02-2018").any()


@pytest.mark.parametrize("arch,tax", [("multiclass", "T0"), ("two_stage", "T1")])
def test_both_architectures_produce_scored_predictions(arch, tax):
    X, raw, meta = _toy()
    tr = np.arange(len(raw)) % 2 == 0
    te = ~tr
    cfg = {"features": "C", "taxonomy": tax, "arch": arch, "model": "xgb", "data": "2017+2018dev"}
    pred, p_attack, *_ = D.fit_predict(cfg, X, raw, tr, te, factory=lambda: DecisionTreeClassifier(random_state=0))
    assert len(pred) == te.sum() and ((p_attack >= 0) & (p_attack <= 1)).all()
    s = D.score(cfg, raw, te, pred, p_attack)
    assert s["binary_argmax"]["tp"] + s["binary_argmax"]["fn"] == int((raw[te] != "benign").sum())
    assert set(s["by_family"]) == {"Brute Force", "DoS/DDoS"}


def test_run_refuses_without_approval(monkeypatch):
    monkeypatch.setattr(sys, "argv", ["dev_experiments.py", "--run"])
    with pytest.raises(SystemExit, match="approval"):
        D.main()
