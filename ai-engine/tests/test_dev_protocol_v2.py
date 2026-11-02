"""Protocol v2 additions (audit/ML_DEV_PROTOCOL_V2.md): frozen C4-A/C4-B configs, the guarded prediction dump,
macro-vs-pooled summaries and the integrity helpers — synthetic data only, nothing is trained on CICIDS files."""
import sys
from pathlib import Path

import numpy as np
import pandas as pd
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from evaluation import dev_experiments as D, dev_summary as S, feature_sets as F, pipeline_integrity as I  # noqa: E402
from utils.features import FEATURE_NAMES  # noqa: E402


def test_v2_candidates_differ_from_c4_only_in_features():
    c4 = D.CANDIDATES["C4"]
    for cid, feats in (("C4A", "A"), ("C4B", "B")):
        cfg = D.CANDIDATES[cid]
        assert cfg["features"] == feats
        assert {k: v for k, v in cfg.items() if k not in ("features", "note")} == {k: v for k, v in c4.items() if k not in ("features", "note")}
    X = np.zeros((1, len(FEATURE_NAMES)))
    names_b = F.variant(X, "B")[1]
    assert len(names_b) == 47 and "init_win_bytes_forward" in names_b and "init_win_bytes_backward" in names_b
    assert not set(F.CONSTANT_IN_POOL) & set(names_b)


def test_dump_predictions_requires_run(monkeypatch):
    monkeypatch.setattr(sys, "argv", ["dev_experiments.py", "--dump-predictions"])
    with pytest.raises(SystemExit, match="--run"):
        D.main()


def test_prediction_rows_keep_pool_identifiers():
    meta = pd.DataFrame({"corpus": ["2018"] * 3, "day": ["21-02-2018"] * 3, "file": "f.csv", "row": [7, 8, 9],
                         "raw": ["Benign", "Benign", "DDOS attack-HOIC"]})
    te = np.array([True, False, True])
    d = D.prediction_rows(meta, te, "2018-21-02-2018", np.array(["Benign", "DDoS"]), np.array([0.1, 0.9]))
    assert list(d["row"]) == [7, 9] and list(d["pred"]) == ["Benign", "DDoS"] and set(d["fold"]) == {"2018-21-02-2018"}


def _fold(name, tp, fp, fn, tn):
    return {"fold": name, "binary_argmax": {"tp": tp, "fp": fp, "fn": fn, "tn": tn,
                                            "attack_recall": tp / max(1, tp + fn), "benign_fpr": fp / max(1, fp + tn)}}


def test_macro_and_pooled_are_reported_separately_and_homogeneous_fold_split_out():
    res = {"candidates": {"X": {"folds": [_fold("2018-14-02-2018", 10, 1, 90, 999),
                                          _fold("2018-21-02-2018", 900, 300, 100, 700)]}}}
    s = S.summary(res)["X D18"]
    assert s["macro_recall"] == pytest.approx(0.5) and s["pooled_recall"] == pytest.approx(910 / 1100, abs=1e-4)
    assert s["macro_fpr"] == pytest.approx((0.001 + 0.3) / 2, abs=1e-6) and s["pooled_fpr"] == pytest.approx(301 / 2000, abs=1e-6)
    assert s["worst_fold_fpr"][0] == "2018-21-02-2018"
    assert s["without_homogeneous_folds"]["macro_fpr"] == pytest.approx(0.001)


def test_shared_vectors_counts_same_and_other_label():
    X = np.array([[1, 1], [2, 2], [1, 1], [2, 2], [3, 3]], dtype=float)
    labels = np.array(["a", "b", "a", "a", "a"])
    tr = np.array([True, True, False, False, False])
    assert I.shared_vectors(X, labels, tr, ~tr) == (1, 1)  # [1,1]/a same; [2,2]/a only seen as b; [3,3] unseen


def test_probe_signature_matches_only_tiny_window_1024_flows():
    from evaluation import thursday_fp_2017 as T
    df = pd.DataFrame({"Init_Win_bytes_forward": [1024, 1024, 29200, 1024], "Total Fwd Packets": [2, 3, 1, 1],
                       "Total Backward Packets": [2, 1, 1, 1], "Init_Win_bytes_backward": [0, 0, 0, 256]})
    assert T.probe_signature(df).tolist() == [True, False, False, False]


def _labelled(src, dst, ts):
    return pd.DataFrame({"Source IP": src, "Destination IP": dst, "Timestamp": ts})


def test_label_rule_verifies_scheduled_scan_and_rejects_otherwise():
    from evaluation import verify_labels_2017 as V
    n = 40
    ok = _labelled(["192.168.10.8"] * n, [f"192.168.10.{5 + i % 5}" for i in range(n)], ["6/7/2017 3:10"] * n)
    assert V.decide(ok)["verdict"] == "VERIFIED"
    wrong_host = _labelled(["192.168.10.9"] * n, ["192.168.10.5"] * n, ["6/7/2017 3:10"] * n)
    assert V.decide(wrong_host)["verdict"] == "NOT VERIFIED"
    wrong_time = _labelled(["192.168.10.8"] * n, [f"192.168.10.{5 + i % 5}" for i in range(n)], ["6/7/2017 1:30"] * n)
    assert V.decide(wrong_time)["verdict"] == "NOT VERIFIED"
    one_peer = _labelled(["192.168.10.8"] * n, ["192.168.10.5"] * n, ["6/7/2017 3:10"] * n)
    assert V.decide(one_peer)["verdict"] == "NOT VERIFIED"


def test_label_join_requires_row_alignment():
    from evaluation import verify_labels_2017 as V
    base = pd.DataFrame({c: [1, 2] for c in V.JOIN_COLS})
    assert V.join_rows(base, base.iloc[:1])[0] is None
    other = base.copy()
    other.loc[1, "Flow Duration"] = 99
    assert V.join_rows(base, other)[1] == 0.5


def test_label_join_compares_numbers_numerically():
    from evaluation import verify_labels_2017 as V
    a = pd.DataFrame({c: [48, 0] for c in V.JOIN_COLS if c != "Label"} | {"Label": ["BENIGN", " BENIGN"]})
    b = pd.DataFrame({c: [48.0, 0.0] for c in V.JOIN_COLS if c != "Label"} | {"Label": ["BENIGN", "BENIGN"]})
    assert V.join_rows(a, b)[1] == 1.0


# ── protocol v3 ──────────────────────────────────────────────────────────────────────────────────────────────────
def test_v3_correction_changes_only_listed_benign_rows_of_one_file(tmp_path, monkeypatch):
    import hashlib
    body = "row\n5\n7\n"
    f = tmp_path / "rows.csv"
    f.write_text(body, encoding="utf-8", newline="\n")
    monkeypatch.setitem(D.CORRECTION_V3, "rows_csv", f)
    monkeypatch.setitem(D.CORRECTION_V3, "sha256", hashlib.sha256(body.encode()).hexdigest())
    fn = D.CORRECTION_V3["file"]
    meta = pd.DataFrame({"corpus": ["2017", "2017", "2017", "2017", "2018"], "file": [fn, fn, fn, "other.csv", fn],
                         "row": [5, 7, 9, 5, 5], "raw": ["benign", "infiltration", "benign", "benign", "benign"]})
    raw, rep = D.apply_label_set(meta, "corrected_v3")
    assert raw.tolist() == ["portscan", "infiltration", "benign", "benign", "benign"]
    assert rep["pool_rows_changed"] == 1 and rep["pool_rows_in_list"] == 2
    assert D.apply_label_set(meta, "published")[0].tolist() == meta["raw"].tolist()


def test_v3_correction_refuses_a_modified_list(tmp_path, monkeypatch):
    f = tmp_path / "rows.csv"
    f.write_text("row\n5\n", encoding="utf-8")
    monkeypatch.setitem(D.CORRECTION_V3, "rows_csv", f)
    with pytest.raises(RuntimeError, match="sha256"):
        D.apply_label_set(pd.DataFrame({"corpus": [], "file": [], "row": [], "raw": []}), "corrected_v3")


def test_frozen_correction_file_matches_pinned_hash():
    import hashlib
    assert hashlib.sha256(Path(D.CORRECTION_V3["rows_csv"]).read_bytes()).hexdigest() == D.CORRECTION_V3["sha256"]


def test_c4ai_drops_infiltration_from_training_only():
    raw = np.array(["benign", "infiltration", "infilteration", "bot", "infiltration"])
    tr = np.array([True, True, True, True, False])
    m = D.train_mask(D.CANDIDATES["C4AI"], raw, tr)
    assert m.tolist() == [True, False, False, True, False]
    assert D.train_mask(D.CANDIDATES["C4A"], raw, tr).tolist() == tr.tolist()
    c4a = {k: v for k, v in D.CANDIDATES["C4A"].items() if k != "note"}
    c4ai = {k: v for k, v in D.CANDIDATES["C4AI"].items() if k not in ("note", "exclude_train_families")}
    assert c4a == c4ai


def test_v3_report_treats_both_benign_spellings_as_benign():
    from evaluation import v3_report as R
    p = pd.DataFrame({"fold": ["2017-Monday"] * 4, "raw": ["benign", "benign", "bot", "bot"],
                      "pred": ["BENIGN", "Benign", "Malware Beacon", "BENIGN"]})
    b = R.folds_from_predictions(p, "raw")[0]["binary_argmax"]
    assert (b["tp"], b["fp"], b["fn"], b["tn"]) == (1, 0, 1, 2)


def test_operating_line_picks_smallest_threshold_meeting_wilson_bound():
    from evaluation import operating_line as L
    assert L.wilson_upper(0, 1000) == pytest.approx(0.00383, abs=1e-4)  # standard Wilson value
    benign = np.concatenate([np.zeros(100000), np.full(50, 0.6), np.full(50, 0.9)])
    line = L.choose_line(benign)
    # at t=0.5 or 0.6 -> 100 FPs (UB > 0.1 %); at 0.9 -> 50 FPs of 100100 (UB ~ 0.066 %) qualifies
    assert line["t"] == 0.9 and line["fp"] == 50 and line["wilson_ub"] <= 0.001
    assert L.choose_line(np.full(100, 0.99)) is None
