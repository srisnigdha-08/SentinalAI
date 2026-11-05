#!/usr/bin/env python3
"""
Metrics audit (2026-10-22): measurements the existing evaluation runs do not record.

Read-only with respect to the project: it loads the served artifacts pinned in
ai-engine/models/registry.json, never writes to models/, and saves everything under
metrics_report/raw/. Two test sets:

  A. served   The served XGBoost + IsolationForest artifacts scored on the exact de-duplicated
              stratified-random 20% test split that training/train.py held out when it trained them
              (recovered with evaluation/reproduce_reported_metrics.capture_split). Optimistic:
              random row split, flows from the same burst sit on both sides.
  B. chrono   The same recipe (XGBoost + benign-only IsolationForest) retrained on the earliest 70%
              of every (file, class) and tested on the latest 29% (evaluation/day_holdout_eval.py's
              chronological protocol). Independent of the served artifact; the honest estimate.

For each: multiclass report + confusion matrix, binary attack-vs-benign metrics for
(1) classifier alone, (2) IsolationForest alone, (3) production combined rule, ROC-AUC / PR-AUC,
and FNR/FPR. Plus: artifact sizes, load time, per-request and batch inference latency.

Run from repo root:  ai-engine/.venv/Scripts/python.exe metrics_report/scripts/ml_eval.py
"""
import json
import os
import platform
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import joblib
import numpy as np
from sklearn.metrics import (accuracy_score, average_precision_score, confusion_matrix, f1_score,
                             precision_recall_fscore_support, roc_auc_score)

REPO = Path(__file__).resolve().parents[2]
ENGINE = REPO / "ai-engine"
OUT = REPO / "metrics_report" / "raw"
sys.path.insert(0, str(ENGINE))
sys.path.insert(0, str(ENGINE / "evaluation"))
os.chdir(ENGINE)

from utils.features import FEATURE_NAMES, LABEL_NAMES  # noqa: E402
from inference.predictor import (ANOMALY_THRESHOLD, BLOCK_THRESHOLD, MONITOR_THRESHOLD,  # noqa: E402
                                 anomaly_signal, combine_threat_score, load_registry)
import day_holdout_eval as D  # noqa: E402
import reproduce_reported_metrics as R  # noqa: E402

BENIGN = 0


def scores(clf, ifo, X):
    """Vectorised inference/predictor.py scoring (same as day_holdout_eval.production_scores),
    returning the extra continuous outputs needed for AUCs."""
    proba = clf.predict_proba(X)
    classes = clf.classes_
    cls = classes[proba.argmax(1)]
    max_p = proba.max(1)
    benign_col = list(classes).index(BENIGN)
    p_attack = 1.0 - proba[:, benign_col]
    rf_s = np.where(cls != BENIGN, max_p, 1.0 - max_p)
    if_score = ifo.named_steps["if"].score_samples(ifo.named_steps["scaler"].transform(X))
    score = combine_threat_score(rf_s, anomaly_signal(if_score), cls != BENIGN)
    unknown = (cls == BENIGN) & (if_score < ANOMALY_THRESHOLD)
    score = np.where(unknown, np.maximum(score, 0.55), score)
    return dict(proba=proba, classes=classes, cls=cls, p_attack=p_attack, if_score=if_score,
                score=score, unknown=unknown)


def binary(y_attack, pred_attack, cont=None):
    tp = int((pred_attack & y_attack).sum()); fn = int((~pred_attack & y_attack).sum())
    fp = int((pred_attack & ~y_attack).sum()); tn = int((~pred_attack & ~y_attack).sum())
    n = tp + fn + fp + tn
    prec = tp / max(1, tp + fp); rec = tp / max(1, tp + fn)
    out = {"tp": tp, "fn": fn, "fp": fp, "tn": tn,
           "accuracy": round((tp + tn) / n, 6), "precision": round(prec, 6), "recall": round(rec, 6),
           "f1": round(2 * prec * rec / max(1e-12, prec + rec), 6),
           "fpr": round(fp / max(1, fp + tn), 6), "fpr_ci95": D.wilson(fp, fp + tn),
           "fnr": round(fn / max(1, tp + fn), 6)}
    if cont is not None:
        out["roc_auc"] = round(float(roc_auc_score(y_attack, cont)), 6)
        out["pr_auc"] = round(float(average_precision_score(y_attack, cont)), 6)
    return out


def full_report(name, clf, ifo, X, y):
    s = scores(clf, ifo, X)
    cls = s["cls"]
    labels = sorted(set(y) | set(cls))
    p, r, f, sup = precision_recall_fscore_support(y, cls, labels=labels, zero_division=0)
    present = sorted(set(y))
    y_att = y != BENIGN
    flagged = (cls != BENIGN) | s["unknown"]
    combined_cont = np.where(flagged, s["score"], s["score"] - 1.0)  # flagged rows rank above unflagged
    rep = {
        "name": name, "n_test": int(len(y)), "n_benign": int((~y_att).sum()), "n_attack": int(y_att.sum()),
        "multiclass": {
            "accuracy": round(float(accuracy_score(y, cls)), 6),
            "f1_macro": round(float(f1_score(y, cls, labels=present, average="macro", zero_division=0)), 6),
            "f1_weighted": round(float(f1_score(y, cls, labels=present, average="weighted", zero_division=0)), 6),
            "labels": [LABEL_NAMES[int(l)] for l in labels],
            "confusion_matrix": confusion_matrix(y, cls, labels=labels).tolist(),
            "per_class": {LABEL_NAMES[int(l)]: {"precision": round(float(pi), 4), "recall": round(float(ri), 4),
                                                "f1": round(float(fi), 4), "support": int(si)}
                          for l, pi, ri, fi, si in zip(labels, p, r, f, sup)},
        },
        "binary": {
            "classifier_alone": binary(y_att, cls != BENIGN, s["p_attack"]),
            "isolation_forest_alone": binary(y_att, s["if_score"] < ANOMALY_THRESHOLD, -s["if_score"]),
            "classifier_or_isolation_forest": binary(y_att, flagged),
            f"combined_alert_line_{MONITOR_THRESHOLD}": binary(y_att, flagged & (s["score"] >= MONITOR_THRESHOLD),
                                                                combined_cont),
            f"combined_block_line_{BLOCK_THRESHOLD}": binary(y_att, flagged & (s["score"] >= BLOCK_THRESHOLD)),
        },
    }
    # Multiclass one-vs-rest ROC-AUC over classes present in both test labels and model output columns
    cols = [i for i, c in enumerate(s["classes"]) if c in set(y)]
    try:
        yy = np.array([list(s["classes"]).index(v) if v in s["classes"] else -1 for v in y])
        keep = yy >= 0
        auc = {}
        for i in cols:
            pos = yy[keep] == i
            if 0 < pos.sum() < keep.sum():
                auc[LABEL_NAMES[int(s["classes"][i])]] = round(float(roc_auc_score(pos, s["proba"][keep, i])), 6)
        rep["multiclass"]["roc_auc_ovr_per_class"] = auc
        rep["multiclass"]["roc_auc_ovr_macro"] = round(float(np.mean(list(auc.values()))), 6)
    except Exception as e:  # noqa: BLE001
        rep["multiclass"]["roc_auc_error"] = str(e)
    # Per-attack-class detection by the combined alert rule
    det = {}
    for l in present:
        if l == BENIGN:
            continue
        m = y == l
        det[LABEL_NAMES[int(l)]] = {"n": int(m.sum()),
                                    "classifier_says_attack": round(float((cls[m] != BENIGN).mean()), 4),
                                    "correct_class": round(float((cls[m] == l).mean()), 4),
                                    "alert_raised": round(float((flagged[m] & (s["score"][m] >= MONITOR_THRESHOLD)).mean()), 4),
                                    "isolation_forest_flags": round(float((s["if_score"][m] < ANOMALY_THRESHOLD).mean()), 4)}
    rep["per_attack_class_detection"] = det
    # Severity distribution of raised alerts (predictor.score_to_severity bands)
    from inference.predictor import score_to_severity
    raised = flagged & (s["score"] >= MONITOR_THRESHOLD)
    sev = {}
    for v in s["score"][raised]:
        k = score_to_severity(float(v)); sev[k] = sev.get(k, 0) + 1
    rep["alert_severity_distribution"] = sev
    return rep


def latency(clf, ifo, X):
    rng = np.random.default_rng(0)
    idx = rng.choice(len(X), size=1000, replace=False)
    for i in idx[:50]:  # warm-up
        clf.predict_proba(X[i:i + 1]); ifo.named_steps["if"].score_samples(ifo.named_steps["scaler"].transform(X[i:i + 1]))
    t = []
    for i in idx:
        t0 = time.perf_counter()
        clf.predict_proba(X[i:i + 1]); ifo.named_steps["if"].score_samples(ifo.named_steps["scaler"].transform(X[i:i + 1]))
        t.append((time.perf_counter() - t0) * 1000)
    t = np.array(t)
    out = {"single_row_ms": {"n": len(t), "mean": round(float(t.mean()), 3), "p50": round(float(np.percentile(t, 50)), 3),
                             "p95": round(float(np.percentile(t, 95)), 3), "p99": round(float(np.percentile(t, 99)), 3),
                             "max": round(float(t.max()), 3)}}
    n = min(20000, len(X))
    t0 = time.perf_counter()
    clf.predict_proba(X[:n]); ifo.named_steps["if"].score_samples(ifo.named_steps["scaler"].transform(X[:n]))
    dt = time.perf_counter() - t0
    out["batch"] = {"rows": n, "seconds": round(dt, 3), "rows_per_second": round(n / dt, 1)}
    return out


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    t_start = time.time()
    reg = load_registry(ENGINE / "models")
    mdir = ENGINE / "models"
    clf_path, if_path = mdir / reg["classifier"]["file"], mdir / reg["anomaly"]["file"]
    loads = []
    for _ in range(3):
        t0 = time.perf_counter(); clf = joblib.load(clf_path); ifo = joblib.load(if_path); loads.append(time.perf_counter() - t0)
    env = {"generated_at": datetime.now(timezone.utc).isoformat(), "python": sys.version.split()[0],
           "platform": platform.platform(), "processor": platform.processor(), "cpu_count": os.cpu_count()}
    artifacts = {
        "registry": reg,
        "classifier_file": clf_path.name, "classifier_mb": round(clf_path.stat().st_size / 2**20, 3),
        "anomaly_file": if_path.name, "anomaly_mb": round(if_path.stat().st_size / 2**20, 3),
        "load_seconds_runs": [round(x, 4) for x in loads],
        "load_seconds_mean": round(float(np.mean(loads)), 4),
    }
    other = {p.name: round(p.stat().st_size / 2**20, 3) for p in sorted(mdir.glob("*.pkl"))}
    artifacts["all_pkl_sizes_mb"] = other
    print("artifacts:", json.dumps({k: v for k, v in artifacts.items() if k != "registry"}, indent=1), flush=True)

    # ── A: served artifact on its own held-out (random, de-duplicated) split
    print("\n[A] recovering train.py de-duplicated split ...", flush=True)
    X_tr, X_te, y_tr, y_te = R.capture_split(ENGINE / "datasets" / "cicids2017", deduplicated=True)
    train_keys = set(R.row_keys(X_tr))
    dup = int(np.sum([k in train_keys for k in R.row_keys(X_te)]))
    A = full_report("served_artifact_on_trainpy_random_dedup_test", clf, ifo, X_te, y_te)
    A["split"] = {"protocol": "stratified random 80/20 after exact de-duplication (training/train.py, random_state=42)",
                  "train_rows": int(len(X_tr)), "test_rows": int(len(X_te)),
                  "test_rows_with_identical_vector_in_train": dup,
                  "independent": False}
    A["latency"] = latency(clf, ifo, X_te)
    print(json.dumps(A["binary"], indent=1), flush=True)

    # ── B: chronological retrain of the served recipe
    print("\n[B] chronological protocol (retrain XGBoost recipe) ...", flush=True)
    D.CLASSIFIER = "xgboost"
    data = D.load_all(ENGINE / "datasets" / "cicids2017")
    train, test = D.chronological_split(data)
    train, test = D.cap(train, D.TRAIN_CAPS), D.cap(test, D.TEST_CAPS)
    t0 = time.perf_counter()
    c2, i2 = D.fit(train)
    fit_s = time.perf_counter() - t0
    B = full_report("xgb_recipe_chronological", c2, i2, test[FEATURE_NAMES].to_numpy(), test["y"].to_numpy())
    B["split"] = {"protocol": "chronological within each (file,class): first 70% train, 1% purge, last 29% test; "
                              "per-file caps train BENIGN 15k/PortScan 10k/DDoS 10k, test BENIGN 20k/PortScan 10k/DDoS 10k",
                  "train_rows": int(len(train)), "test_rows": int(len(test)), "independent": True,
                  "rows_after_cleaning_and_dedup": int(len(data)),
                  "duplicates_removed": int(data.attrs.get("duplicates_removed", -1)),
                  "train_classes": D.class_counts(train), "test_classes": D.class_counts(test)}
    B["training_seconds_xgb_plus_if"] = round(fit_s, 2)
    print(json.dumps(B["binary"], indent=1), flush=True)

    report = {"environment": env, "thresholds": {"alert": MONITOR_THRESHOLD, "block": BLOCK_THRESHOLD,
                                                 "if_anomaly": ANOMALY_THRESHOLD},
              "artifacts": artifacts, "A_served_random_split": A, "B_chronological": B,
              "runtime_seconds": round(time.time() - t_start, 1)}
    (OUT / "ml_eval.json").write_text(json.dumps(report, indent=1, default=str))
    print(f"\nwrote {OUT / 'ml_eval.json'} in {report['runtime_seconds']}s")


if __name__ == "__main__":
    main()
