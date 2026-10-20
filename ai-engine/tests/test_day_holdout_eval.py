"""evaluation/day_holdout_eval.py: split hygiene, metrics and the production scoring replica."""
import numpy as np
import pandas as pd
import pytest

from evaluation import day_holdout_eval as ev
from utils.features import FEATURE_NAMES, LABEL_MAP


def frame(rows):
    """rows: list of (file, target, day) in file order."""
    df = pd.DataFrame(np.random.default_rng(0).random((len(rows), len(FEATURE_NAMES))), columns=FEATURE_NAMES)
    df["file"] = [r[0] for r in rows]
    df["target"] = [r[1] for r in rows]
    df["day"] = [r[2] for r in rows]
    df["y"] = df["target"].map(LABEL_MAP)
    df["order"] = df.groupby("file").cumcount()
    return df


def test_chronological_split_keeps_every_test_row_after_every_train_row_per_class():
    rows = [("tue.csv", "BENIGN", "Tuesday")] * 200 + [("tue.csv", "SSH Brute Force", "Tuesday")] * 100
    train, test = ev.chronological_split(frame(rows))
    assert set(train.index).isdisjoint(test.index)
    for target in ("BENIGN", "SSH Brute Force"):
        tr, te = train[train.target == target], test[test.target == target]
        assert len(tr) > 0 and len(te) > 0
        assert tr["order"].max() < te["order"].min()


def test_purge_gap_separates_train_and_test():
    rows = [("f.csv", "DDoS", "Friday")] * 1000
    train, test = ev.chronological_split(frame(rows), train_fraction=0.7, purge_fraction=0.01)
    assert len(train) == 700
    assert test["order"].min() - train["order"].max() > 10  # 10 purged rows in between
    assert len(train) + len(test) == 990


def test_cap_limits_per_file_and_class_only_for_capped_classes():
    rows = ([("a.csv", "BENIGN", "Monday")] * 50 + [("b.csv", "BENIGN", "Tuesday")] * 50
            + [("b.csv", "SSH Brute Force", "Tuesday")] * 40)
    capped = ev.cap(frame(rows), {"BENIGN": 10})
    counts = capped.groupby(["file", "target"]).size().to_dict()
    assert counts == {("a.csv", "BENIGN"): 10, ("b.csv", "BENIGN"): 10, ("b.csv", "SSH Brute Force"): 40}


def test_wilson_interval_bounds():
    assert ev.wilson(0, 1000)[0] == 0.0 and 0 < ev.wilson(0, 1000)[1] < 0.005
    low, high = ev.wilson(28, 25000)
    assert low < 28 / 25000 < high
    assert ev.wilson(0, 0) == [None, None]


class StubRF:
    classes_ = np.array([0, 4])

    def __init__(self, proba):
        self._p = np.asarray(proba)

    def predict_proba(self, X):
        return self._p


class StubIF:
    """score_samples returns fixed values; offset_ mirrors sklearn's attribute."""
    def __init__(self, scores, offset=-0.47):
        self.named_steps = {"if": self, "scaler": self}
        self._s = np.asarray(scores)
        self.offset_ = offset

    def transform(self, X):
        return X

    def score_samples(self, X):
        return self._s


def test_production_score_replica_matches_predictor_formula():
    # Confident DDoS, IF inlier: the legacy blend gave 0.7 * 0.99 = 0.693 (below the 0.70 threat line);
    # the current rule keeps the classifier confidence as a floor -> 0.99.
    cls, score, unknown = ev.production_scores(StubRF([[0.01, 0.99]]), StubIF([-0.40]), np.zeros((1, 3)))
    assert cls[0] == 4 and score[0] == pytest.approx(0.99) and not unknown[0]
    _, legacy, _ = ev.production_scores(StubRF([[0.01, 0.99]]), StubIF([-0.40]), np.zeros((1, 3)), rule="legacy_blend")
    assert legacy[0] == pytest.approx(0.693)
    # Same flow flagged anomalous (deflection 0.2 -> if_sig 1.0) -> 0.693 + 0.3
    _, score, _ = ev.production_scores(StubRF([[0.01, 0.99]]), StubIF([-0.67]), np.zeros((1, 3)))
    assert score[0] == pytest.approx(0.993)
    # BENIGN keeps the plain blend: rf_s = 1 - 0.9 = 0.1, inlier -> 0.07
    _, score, _ = ev.production_scores(StubRF([[0.9, 0.1]]), StubIF([-0.40]), np.zeros((1, 3)))
    assert score[0] == pytest.approx(0.07)
    # RF says BENIGN but IF below -0.55 -> "Unknown" with score floored at 0.55
    cls, score, unknown = ev.production_scores(StubRF([[0.9, 0.1]]), StubIF([-0.60]), np.zeros((1, 3)))
    assert cls[0] == 0 and unknown[0] and score[0] >= 0.55
