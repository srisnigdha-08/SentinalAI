"""evaluation/xgb_holdout_eval.py: fold construction and the per-fold scoring path, with a trivial estimator
(no XGBoost fit, no data files)."""
import sys
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.tree import DecisionTreeClassifier

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from evaluation import xgb_holdout_eval as H  # noqa: E402

FILES = ["Monday-WorkingHours.pcap_ISCX.csv", "Tuesday-WorkingHours.pcap_ISCX.csv",
         "Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv", "Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv",
         "Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv"]


def _meta():
    files = np.repeat(FILES, 4)
    return pd.DataFrame({"_file": files, "_row": np.tile(np.arange(4), len(FILES)), "day": [H.day_of(f) for f in files]})


def test_day_holdout_groups_both_thursday_files_and_file_holdout_does_not():
    p = H.protocols(_meta())
    days = [f for f, _, _ in p["P4"]]
    assert days == ["Monday", "Tuesday", "Thursday", "Friday"]  # 4 days present -> 4 folds, not 5 files
    thu = next(te for f, _, te in p["P4"] if f == "Thursday")
    assert thu.sum() == 8  # both Thursday files held out together
    assert len(p["P4f"]) == 5
    p3_train, p3_test = p["P3"][0][1], p["P3"][0][2]
    assert not (p3_train & p3_test).any() and (p3_train | p3_test).all()


def test_manifest_hash_depends_only_on_the_split():
    meta = _meta()
    tr = meta["day"].to_numpy() != "Friday"
    a, _ = H.manifest(meta, tr, ~tr)
    b, _ = H.manifest(meta, tr.copy(), ~tr)
    c, _ = H.manifest(meta, ~tr, tr)
    assert a["sha256"] == b["sha256"] != c["sha256"]


def test_a_class_absent_from_training_is_flagged_and_scored_only_as_attack_vs_benign():
    rng = np.random.default_rng(0)
    # class 0 benign, 4 DDoS in training; class 3 (Port Scan) only in the test fold
    X = np.vstack([rng.normal(0, 1, (60, 3)), rng.normal(5, 1, (60, 3)), rng.normal(5, 1, (20, 3))])
    y = np.array([0] * 60 + [4] * 60 + [3] * 20)
    tr = np.array([True] * 50 + [False] * 10 + [True] * 50 + [False] * 10 + [False] * 20)
    te = ~tr
    table = H.class_table(y, tr, te)
    assert table["absent_from_training"] == ["Port Scan"] and table["attack_test_rows_of_unseen_classes"] == 20
    res = H.fit_and_score(X, y, tr, te, make_model=lambda: DecisionTreeClassifier(random_state=0))
    assert set(res["per_class_seen"]) == {"BENIGN", "DDoS"}  # no per-class number for the unseen class
    ps = res["unseen_classes"]["Port Scan"]
    assert ps["rows"] == 20 and ps["flagged_as_attack"] == 20 and ps["predicted_as"] == {"DDoS": 20}
    b = res["binary_classifier_argmax"]
    assert b["tp"] + b["fn"] == 30 and b["fp"] + b["tn"] == 10
    assert res["confusion_matrix"]["labels"] == ["BENIGN", "Port Scan", "DDoS"]
    # the lines are a subset of the argmax decision (lower bound without the Isolation Forest term)
    assert res["binary_alert_line_0.90_lower_bound"]["tp"] <= b["tp"]
    assert res["collisions"] == {"test_rows_vector_in_train_same_label": 0, "test_rows_vector_in_train_other_label": 0}


def test_run_refuses_without_explicit_approval(monkeypatch, capsys):
    monkeypatch.setattr(sys, "argv", ["xgb_holdout_eval.py", "--run"])
    try:
        H.main()
    except SystemExit as e:
        assert "approval" in str(e.code)
    else:
        raise AssertionError("--run without --approved did not stop")


def test_hybrid_scoring_fits_the_forest_on_benign_training_rows_only():
    from sklearn.ensemble import IsolationForest
    rng = np.random.default_rng(1)
    X = np.vstack([rng.normal(0, 1, (80, 3)), rng.normal(6, 1, (40, 3))])
    y = np.array([0] * 80 + [4] * 40)
    tr = np.array([True] * 60 + [False] * 20 + [True] * 30 + [False] * 10)
    seen = []

    class Spy(IsolationForest):
        def fit(self, Xf, *a, **k):
            seen.append(len(Xf))
            return super().fit(Xf, *a, **k)

    res = H.fit_and_score(X, y, tr, ~tr, make_model=lambda: DecisionTreeClassifier(random_state=0),
                          make_if=lambda: Spy(n_estimators=20, random_state=0))
    assert seen == [60]  # benign rows of the training fold, never the held-out rows or attacks
    h = res["hybrid"]
    assert h["if_benign_training_rows"] == 60 and h["lines"]["alert"] == 0.9
    assert h["alert_line"]["tp"] + h["alert_line"]["fn"] == 10  # every held-out attack is accounted for
    # the served rule can only raise an attack score: hybrid recall >= classifier-only lower bound
    assert h["alert_line"]["tp"] >= res["binary_alert_line_0.90_lower_bound"]["tp"]


def test_hybrid_mode_refuses_without_its_own_approval(monkeypatch):
    monkeypatch.setattr(sys, "argv", ["xgb_holdout_eval.py", "--run", "--approved", "--with-if"])
    try:
        H.main()
    except SystemExit as e:
        assert "approved-if" in str(e.code)
    else:
        raise AssertionError("--with-if without --approved-if did not stop")
