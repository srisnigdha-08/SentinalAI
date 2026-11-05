"""C2: duplicates never straddle a split, and a trained artifact records how to rebuild it."""
import argparse
import json

import numpy as np
import pandas as pd
import pytest

from evaluation import day_holdout_eval as ev
from training import train as T
from utils.features import FEATURE_NAMES, LABEL_MAP


def test_train_drop_duplicate_rows_keeps_first_copy_and_counts_label_conflicts():
    X = np.array([[1.0, 2.0], [1.0, 2.0], [3.0, 4.0], [1.0, 2.0], [3.0, 4.0]])
    y = np.array([0, 0, 1, 0, 2])
    Xd, yd, stats = T.drop_duplicate_rows(X, y)
    assert Xd.tolist() == [[1.0, 2.0], [3.0, 4.0], [3.0, 4.0]] and yd.tolist() == [0, 1, 2]
    assert stats == {"rows_before": 5, "rows_after": 3, "removed": 2, "conflicting_label_vectors": 1}


def test_train_split_has_no_identical_rows_across_train_and_test():
    rng = np.random.default_rng(1)
    base = rng.random((300, 4))
    X = np.vstack([base, base[:150]])                    # 150 exact duplicates
    y = np.concatenate([np.arange(300) % 3, (np.arange(150) % 3)])
    Xd, yd, _ = T.drop_duplicate_rows(X, y)
    X_train, X_test, _, _ = T.train_test_split(Xd, yd, test_size=0.2, random_state=42, stratify=yd)
    train_rows = {r.tobytes() for r in X_train}
    assert not any(r.tobytes() in train_rows for r in X_test)


def frame(values, days, targets):
    df = pd.DataFrame(np.array(values, dtype=np.float32).reshape(len(values), 1).repeat(len(FEATURE_NAMES), 1),
                      columns=FEATURE_NAMES)
    df["day"], df["target"] = days, targets
    df["y"] = df["target"].map(LABEL_MAP)
    df["file"] = [d.lower() + ".csv" for d in days]
    df["order"] = df.groupby("file").cumcount()
    return df


def test_holdout_dedupe_keeps_the_earliest_day_and_respects_labels():
    data = frame([1, 1, 2, 2, 3], ["Monday", "Friday", "Tuesday", "Tuesday", "Monday"],
                 ["BENIGN", "BENIGN", "BENIGN", "DDoS", "BENIGN"])
    out = ev.drop_duplicates(data)
    assert len(out) == 4 and out.attrs["duplicates_removed"] == 1
    assert list(out[out[FEATURE_NAMES[0]] == 1]["day"]) == ["Monday"]   # Friday's copy dropped
    assert sorted(out[out[FEATURE_NAMES[0]] == 2]["target"]) == ["BENIGN", "DDoS"]  # same flow, different label: kept


def test_holdout_loads_files_monday_to_friday(tmp_path, monkeypatch):
    seen = []
    for name in ("Friday-x.csv", "Monday-x.csv", "Wednesday-x.csv"):
        (tmp_path / name).write_text("")
    monkeypatch.setattr(ev, "load_file", lambda f, max_rows=None: seen.append(f.name) or frame([len(seen)], ["Monday"], ["BENIGN"]))
    ev.load_all(tmp_path, dedupe=False)
    assert seen == ["Monday-x.csv", "Wednesday-x.csv", "Friday-x.csv"]


def _args(tmp_path, **kw):
    return argparse.Namespace(data=None, synthetic=True, rows=1500, model_dir=str(tmp_path), model="rf", cv=False,
                              tune=False, smote=False, version="t1", **kw)


def test_versioned_training_writes_new_files_with_provenance_and_never_overwrites(tmp_path, monkeypatch):
    monkeypatch.setitem(T.RF_PARAMS, "n_estimators", 5)
    monkeypatch.setitem(T.IF_PARAMS, "n_estimators", 5)
    T.train(_args(tmp_path))
    meta = json.loads((tmp_path / "rf_classifier_t1_meta.json").read_text())
    assert (tmp_path / "rf_classifier_t1.pkl").exists() and (tmp_path / "isolation_forest_t1.pkl").exists()
    assert meta["version"] == "t1" and meta["smote"] is False
    assert meta["evaluation"] == {**meta["evaluation"], "split": "stratified_random_80_20", "deduplicated": True,
                                  "independent_holdout": False}
    assert meta["deduplication"]["rows_before"] == 1500
    assert sum(meta["class_counts"]["train"].values()) + sum(meta["class_counts"]["test"].values()) == \
        meta["deduplication"]["rows_after"]
    assert meta["params"]["rf__n_estimators"] == 5 and meta["params"]["rf__random_state"] == 42
    assert meta["provenance"]["cli_args"]["version"] == "t1" and meta["provenance"]["sklearn"]
    if_meta = json.loads((tmp_path / "isolation_forest_t1_meta.json").read_text())
    assert if_meta["version"] == "t1" and if_meta["feature_names"] == FEATURE_NAMES
    with pytest.raises(SystemExit, match="Refusing to overwrite"):
        T.train(_args(tmp_path))
