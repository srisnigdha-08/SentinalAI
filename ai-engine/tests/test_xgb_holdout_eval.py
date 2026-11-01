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
    assert res["unseen_attack_rows"] == 20 and res["unseen_attack_rows_flagged"] == 20  # flagged as an attack class
    assert res["binary"]["tp"] + res["binary"]["fn"] == 30


def test_run_refuses_without_explicit_approval(monkeypatch, capsys):
    monkeypatch.setattr(sys, "argv", ["xgb_holdout_eval.py", "--run"])
    try:
        H.main()
    except SystemExit as e:
        assert "approval" in str(e.code)
    else:
        raise AssertionError("--run without --approved did not stop")
