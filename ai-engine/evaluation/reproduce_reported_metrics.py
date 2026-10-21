#!/usr/bin/env python3
"""
Re-score the shipped classifiers on the exact test split that produced the reported metrics.

training/train.py builds its data set (per-file caps, global caps, NaN/inf drop) and then calls
train_test_split(test_size=0.2, random_state=42, stratify=y). This script runs train.py's own loading
code unchanged, intercepts that split call (nothing is trained or written), and evaluates the model
files in models/ (plus the root models/ copy) on the captured X_test. It also measures how many test
rows are exact duplicates of training rows, which a random row split does not prevent.

  python evaluation/reproduce_reported_metrics.py                 # as reported (duplicates kept), ~2-3 min
  python evaluation/reproduce_reported_metrics.py --deduplicated  # train.py's current, de-duplicated split

By default train.py's de-duplication (C2) is switched off so the August split that produced the paper's
numbers is rebuilt exactly. With --deduplicated only the registered model is a fair comparison: the older
artifacts were trained on rows that land in the de-duplicated test set. The split is random and row-level
either way; evaluation/day_holdout_eval.py gives the chronological and leave-one-day-out estimates.
"""
import argparse
import sys
import tempfile
import warnings
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix, f1_score

warnings.filterwarnings("ignore")
ENGINE_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ENGINE_ROOT))
import training.train as T  # noqa: E402
from utils.features import FEATURE_NAMES, LABEL_NAMES  # noqa: E402
from inference.predictor import (  # noqa: E402
    ANOMALY_THRESHOLD, BLOCK_THRESHOLD, MONITOR_THRESHOLD, anomaly_signal, combine_threat_score)

MODELS = {
    "registered   (models/registry.json)": None,
    "Aug RF       models/rf_classifier_cicids_v2.pkl": ENGINE_ROOT / "models" / "rf_classifier_cicids_v2.pkl",
    "root copy    ../models/rf_classifier_cicids_v2.pkl": ENGINE_ROOT.parent / "models" / "rf_classifier_cicids_v2.pkl",
    "RF v1        models/rf_classifier_cicids.pkl": ENGINE_ROOT / "models" / "rf_classifier_cicids.pkl",
    "XGBoost      models/xgb_classifier_cicids.pkl": ENGINE_ROOT / "models" / "xgb_classifier_cicids.pkl",
    "Stacking     models/stacking_classifier_cicids.pkl": ENGINE_ROOT / "models" / "stacking_classifier_cicids.pkl",
}
DETAILED = ("registered", "XGBoost")


class _Captured(Exception):
    pass


def capture_split(data_dir: Path, deduplicated: bool):
    captured = {}
    real_split, real_dedupe = T.train_test_split, T.drop_duplicate_rows
    if not deduplicated:
        T.drop_duplicate_rows = lambda X, y: (X, y, {"rows_before": len(X), "rows_after": len(X), "removed": 0,
                                                     "conflicting_label_vectors": 0})

    def spy(X, y, **kw):
        captured["split"] = real_split(X, y, **kw)
        raise _Captured()

    T.train_test_split = spy
    try:
        T.train(argparse.Namespace(data=str(data_dir), synthetic=False, rows=0, model="rf", cv=False, tune=False,
                                   smote=False, model_dir=tempfile.mkdtemp(prefix="sentinel_repro_")))
    except _Captured:
        pass
    finally:
        T.train_test_split, T.drop_duplicate_rows = real_split, real_dedupe
    return captured["split"]


def row_keys(X):
    return [bytes(r) for r in np.ascontiguousarray(X).view(np.uint8).reshape(len(X), -1)]


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[1])
    ap.add_argument("--data", default=str(ENGINE_ROOT / "datasets" / "cicids2017"))
    ap.add_argument("--deduplicated", action="store_true", help="use train.py's current de-duplicated split")
    args = ap.parse_args()

    from inference.predictor import load_registry
    reg = load_registry(ENGINE_ROOT / "models")
    MODELS["registered   (models/registry.json)"] = ENGINE_ROOT / "models" / reg["classifier"]["file"] if reg else None
    X_train, X_test, y_train, y_test = capture_split(Path(args.data), args.deduplicated)
    print(f"\ntrain={len(X_train):,} test={len(X_test):,}")
    train_keys = set(row_keys(X_train))
    dup = np.array([k in train_keys for k in row_keys(X_test)])
    print(f"test rows with an identical feature vector in train: {dup.sum():,} ({dup.mean():.1%})")
    for c in np.unique(y_test):
        m = y_test == c
        print(f"  {LABEL_NAMES[c]:<20} {dup[m].mean():6.1%} of {m.sum():,}")

    benign = y_test == 0
    ifo = joblib.load(ENGINE_ROOT / "models" / (reg["anomaly"]["file"] if reg else "isolation_forest_cicids.pkl"))
    preds = {}
    for name, path in MODELS.items():
        if path is None or not path.exists():
            print(f"\n{name}: missing, skipped")
            continue
        model = joblib.load(path)
        proba = model.predict_proba(X_test)
        cls = model.classes_[proba.argmax(1)]
        preds[name] = cls
        print(f"\n=== {name}")
        print(f"  accuracy={accuracy_score(y_test, cls):.4f}  weighted F1={f1_score(y_test, cls, average='weighted', zero_division=0):.4f}"
              f"  macro F1={f1_score(y_test, cls, average='macro', zero_division=0):.4f}"
              f"  accuracy on non-duplicated test rows={accuracy_score(y_test[~dup], cls[~dup]):.4f}")
        print(f"  benign misclassified={np.mean(cls[benign] != 0):.3%}  attacks classified as attack={np.mean(cls[~benign] != 0):.4f}")
        if not name.startswith(DETAILED):
            continue
        labels = sorted(set(y_test) | set(cls))
        print(classification_report(y_test, cls, labels=labels, target_names=[LABEL_NAMES[i] for i in labels],
                                    digits=4, zero_division=0))
        print(pd.DataFrame(confusion_matrix(y_test, cls, labels=labels),
                           index=[LABEL_NAMES[i][:12] for i in labels], columns=[LABEL_NAMES[i][:6] for i in labels]))
        if name.startswith("registered"):
            max_p = proba.max(1)
            if_score = ifo.named_steps["if"].score_samples(ifo.named_steps["scaler"].transform(X_test))
            score = combine_threat_score(np.where(cls != 0, max_p, 1 - max_p), anomaly_signal(if_score), cls != 0)
            unknown = (cls == 0) & (if_score < ANOMALY_THRESHOLD)
            score = np.where(unknown, np.maximum(score, 0.55), score)
            flagged = (cls != 0) | unknown
            for line in (0.70, MONITOR_THRESHOLD, BLOCK_THRESHOLD):
                hit = flagged & (score >= line)
                print(f"  threatScore >= {line}: benign alert rate={hit[benign].mean():.3%}  attack detection={hit[~benign].mean():.4f}")
            print(f"  IsolationForest alone (score < {ANOMALY_THRESHOLD}): benign flagged={np.mean(if_score[benign] < ANOMALY_THRESHOLD):.2%}"
                  f"  attacks flagged={np.mean(if_score[~benign] < ANOMALY_THRESHOLD):.2%}")
            imp = model.named_steps["rf"].feature_importances_
            print("  top features:", ", ".join(f"{FEATURE_NAMES[i]}={imp[i]:.3f}" for i in np.argsort(-imp)[:8]))
            print("  zero-importance:", ", ".join(FEATURE_NAMES[i] for i in np.flatnonzero(imp == 0)))
    a, b = (preds.get(k) for k in list(MODELS)[1:3])
    if a is not None and b is not None:
        print(f"\nAug RF vs root copy disagree on {np.sum(a != b):,} of {len(a):,} test rows ({np.mean(a != b):.3%})")


if __name__ == "__main__":
    main()
