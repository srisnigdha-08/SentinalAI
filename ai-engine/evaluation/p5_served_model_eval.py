"""
P5 (audit/ML_EVAL_PLAN.md): inference-only evaluation of the served classifier on its own held-out split.

Nothing is trained, saved into models/, reloaded or promoted. The script
  1. checks the served files against models/registry.json (sha256) and loads them through SentinelPredictor,
     which also runs the golden-set check;
  2. rebuilds the training-time dataset exactly as training/train.py does for a CICIDS2017 directory
     (per-file pre-caps, global caps, prepare_features, exact-duplicate removal, stratified 80/20 split,
     random_state 42) and REFUSES to report metrics unless the dedup statistics and every per-class train/test
     count equal the ones recorded in the model's meta file;
  3. scores the test rows with the served code path (classifier + Isolation Forest + combine_threat_score and
     the Unknown/REVIEW override from SentinelPredictor._assemble, vectorised) and reports per-class metrics,
     confusion matrix, FPR/FNR at the alert and block lines, PR-AUC, Brier score and Wilson intervals.

  .venv/Scripts/python evaluation/p5_served_model_eval.py [--data datasets/cicids2017] [--out experiments/p5_...]

The loading code in load_cicids_dir() is a copy of train.py's real-data branch (train.py lines 90-236 at
6883308; unchanged since the model's commit cf667f1). It is copied, not imported, so training code stays
untouched; the count check in step 2 is what proves the copy reproduces the split.
"""
import argparse, hashlib, json, math, sys, time
from datetime import datetime, timezone
from pathlib import Path

import numpy as np
import pandas as pd

ENGINE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ENGINE))
from sklearn.metrics import (accuracy_score, average_precision_score, brier_score_loss, confusion_matrix,  # noqa: E402
                             f1_score, precision_recall_fscore_support)
from sklearn.model_selection import train_test_split  # noqa: E402

from utils.features import CANDIDATES, FEATURE_NAMES, LABEL_NAMES, RAW_LABEL_TO_TARGET, prepare_features  # noqa: E402
from training.train import drop_duplicate_rows  # noqa: E402
from inference import predictor as P  # noqa: E402


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def load_cicids_dir(data_path: Path, keep_source: bool = False) -> pd.DataFrame:
    """train.py's directory branch, minus its progress printing. keep_source adds `_file` / `_row` (position in the
    CSV) after cleaning, so sampling and order are unchanged (xgb_holdout_eval.py uses them for its manifests)."""
    dfs = []
    for csv_file in sorted(data_path.glob("*.csv")):
        header_df = pd.read_csv(csv_file, nrows=1)
        needed_cols = ["label", "Label", "target_class"]
        for _fn, cands in CANDIDATES.items():
            needed_cols.extend(cands)
        cols_to_use = []
        for cand in needed_cols:
            matched = False
            for h_col in header_df.columns:
                if cand == h_col.strip():
                    cols_to_use.append(h_col)
                    matched = True
                    break
            if not matched:
                cand_lower = cand.lower().replace("_", "").replace(" ", "").replace("/", "")
                for h_col in header_df.columns:
                    if h_col.strip().lower().replace("_", "").replace(" ", "").replace("/", "") == cand_lower:
                        cols_to_use.append(h_col)
                        break
        cols_to_use = list(set(cols_to_use))
        file_df = pd.read_csv(csv_file, usecols=cols_to_use)
        file_df.columns = file_df.columns.str.strip()
        label_col = next((c for c in file_df.columns if c.lower() == "label"), "Label")
        file_df["label"] = file_df[label_col].astype(str).str.strip()
        if label_col != "label" and label_col in file_df.columns:
            file_df = file_df.drop(columns=[label_col])
        file_df["target_class"] = file_df["label"].map(lambda x: RAW_LABEL_TO_TARGET.get(x, x))
        feature_cols = [c for c in file_df.columns if c.lower() != "label" and c != "target_class"]
        for col in feature_cols:
            file_df[col] = pd.to_numeric(file_df[col], errors="coerce")
        file_df = file_df.replace([float("inf"), float("-inf")], float("nan")).dropna(subset=feature_cols)
        if keep_source:
            file_df["_file"], file_df["_row"] = csv_file.name, file_df.index.to_numpy()
        pre_caps = {"BENIGN": 15000, "Port Scan": 10000, "DDoS": 10000}
        sub_dfs = []
        for tc, grp in file_df.groupby("target_class"):
            cap = pre_caps.get(str(tc))
            sub_dfs.append(grp.sample(n=min(len(grp), cap), random_state=42) if cap else grp)
        if sub_dfs:
            file_df = pd.concat(sub_dfs, ignore_index=True)
        if len(file_df) > 0:
            dfs.append(file_df)
    df = pd.concat(dfs, ignore_index=True)
    caps = {"BENIGN": 100000, "Port Scan": 40000, "DDoS": 40000}
    out = []
    for label_name, grp in df.groupby("target_class"):
        cap = caps.get(str(label_name))
        out.append(grp.sample(n=min(len(grp), cap), random_state=42) if cap else grp)
    return pd.concat(out, ignore_index=True).drop(columns=["target_class"])


def wilson(k, n, z=1.96):
    if n == 0:
        return None
    p = k / n
    d = 1 + z * z / n
    c = p + z * z / (2 * n)
    r = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n))
    return [round((c - r) / d, 4), round((c + r) / d, 4)]


def served_scores(pred, X):
    """SentinelPredictor.predict_many / _assemble, vectorised: class, score, action per row."""
    labels, proba, _pos = pred._classify_many(X)
    if_scores = np.asarray(pred.ifo.named_steps["if"].score_samples(pred.ifo.named_steps["scaler"].transform(X)), dtype=float)
    labels = np.asarray(labels).astype(int)
    max_p = proba.max(axis=1)
    is_attack = labels != 0
    rf_s = np.where(is_attack, max_p, 1 - max_p)
    if_sig = P.anomaly_signal(if_scores)
    score = np.round(P.combine_threat_score(rf_s, if_sig, is_attack), 4)
    unknown = (~is_attack) & (if_scores < P.ANOMALY_THRESHOLD)
    score = np.where(unknown, np.maximum(score, 0.55), score)
    action = np.where(score >= P.BLOCK_THRESHOLD, "BLOCK", np.where(score >= P.MONITOR_THRESHOLD, "MONITOR", "ALLOW"))
    action = np.where(unknown & (if_sig >= P.REVIEW_MIN_SIGNAL) & (action == "ALLOW"), "REVIEW", action)
    return labels, proba, score, action, unknown, if_scores


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", default=str(ENGINE / "datasets" / "cicids2017"))
    ap.add_argument("--model-dir", default=str(ENGINE / "models"))
    ap.add_argument("--out", default=str(ENGINE / "experiments" / f"p5_served_eval_{datetime.now():%Y%m%d}"))
    args = ap.parse_args()
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    model_dir = Path(args.model_dir)
    report = {"generated_at": datetime.now(timezone.utc).isoformat(), "protocol": "P5 inference-only, served model, "
              "reconstructed stratified_random_80_20 test split", "thresholds": {
                  "alert": P.MONITOR_THRESHOLD, "block": P.BLOCK_THRESHOLD, "anomaly": P.ANOMALY_THRESHOLD,
                  "review_min_signal": P.REVIEW_MIN_SIGNAL}}

    # 1. Artefacts
    reg = json.loads((model_dir / "registry.json").read_text(encoding="utf-8"))
    checks = {}
    for role in ("classifier", "anomaly"):
        f = model_dir / reg[role]["file"]
        checks[role] = {"file": f.name, "registry_sha256": reg[role]["sha256"], "actual_sha256": sha256(f)}
        assert checks[role]["actual_sha256"] == reg[role]["sha256"], f"{role} sha256 mismatch"
    meta = json.loads((model_dir / reg["classifier"]["meta"]).read_text(encoding="utf-8"))
    pred = P.SentinelPredictor(model_dir=str(model_dir))
    pred.load()
    assert pred._loaded, "SentinelPredictor did not load the served models"
    report["artefacts"] = {**checks, "version": reg["classifier"]["version"], "loaded_via": "SentinelPredictor.load "
                           "(registry sha256 + golden set)", "dataset_sha256_match": {}}
    for name, h in meta["provenance"]["data_sha256"].items():
        report["artefacts"]["dataset_sha256_match"][name] = sha256(Path(args.data) / name) == h

    # 2. Split reconstruction
    t0 = time.time()
    df = load_cicids_dir(Path(args.data))
    X, y = prepare_features(df, max_missing=0)
    X, y, dedup = drop_duplicate_rows(X, y)
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)
    names = lambda arr: {LABEL_NAMES[int(k)]: int(v) for k, v in zip(*np.unique(arr, return_counts=True))}  # noqa: E731
    rebuilt = {"deduplication": dedup, "class_counts": {"train": names(y_train), "test": names(y_test)}}
    expected = {"deduplication": meta["deduplication"], "class_counts": meta["class_counts"]}
    split_ok = rebuilt == expected
    report["split_reconstruction"] = {"matches_meta": split_ok, "rebuilt": rebuilt, "expected": expected,
                                      "load_seconds": round(time.time() - t0, 1)}
    if not split_ok:
        (out / "results.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
        sys.exit("Split reconstruction does not match the model meta; no metrics reported. See results.json")

    # Leakage: test feature vectors that also occur in training (labels may differ: conflicting vectors are kept)
    train_keys = {r.tobytes() for r in np.ascontiguousarray(X_train)}
    shared = int(sum(r.tobytes() in train_keys for r in np.ascontiguousarray(X_test)))
    leak_cols = [f for f in FEATURE_NAMES if any(k in f.lower() for k in ("ip", "port", "timestamp", "flow_id"))]
    report["leakage"] = {"test_rows_with_feature_vector_in_train": shared, "of_test_rows": int(len(X_test)),
                         "time_of_day_columns_constant": bool(all(np.unique(X[:, FEATURE_NAMES.index(c)]).size == 1
                                                                 for c in FEATURE_NAMES if c.startswith("time_of_day"))),
                         "identifier_like_feature_names": leak_cols}

    # 3. Served scoring
    t0 = time.time()
    labels, proba, score, action, unknown, if_scores = served_scores(pred, X_test)
    report["scoring_ms_per_row_batch"] = round((time.time() - t0) * 1000 / len(X_test), 4)
    present = sorted(set(np.unique(y_test)) | set(np.unique(labels)))
    pnames = [LABEL_NAMES[int(i)] for i in present]
    p, r, f, s = precision_recall_fscore_support(y_test, labels, labels=present, zero_division=0)
    cm = confusion_matrix(y_test, labels, labels=present)
    per_class = {}
    for i, c in enumerate(present):
        tp = int(cm[i, i])
        per_class[LABEL_NAMES[int(c)]] = {"precision": round(float(p[i]), 4), "recall": round(float(r[i]), 4),
                                          "f1": round(float(f[i]), 4), "support": int(s[i]), "tp": tp,
                                          "recall_wilson95": wilson(tp, int(s[i]))}
    acc = accuracy_score(y_test, labels)
    report["classifier"] = {
        "accuracy": round(float(acc), 4),
        "f1_macro": round(float(f1_score(y_test, labels, average="macro", labels=sorted(np.unique(y_test)), zero_division=0)), 4),
        "f1_weighted": round(float(f1_score(y_test, labels, average="weighted", zero_division=0)), 4),
        "precision_macro": round(float(np.mean(p[[present.index(c) for c in np.unique(y_test)]])), 4),
        "recall_macro": round(float(np.mean(r[[present.index(c) for c in np.unique(y_test)]])), 4),
        "meta_recorded": meta["metrics"], "per_class": per_class,
        "confusion_matrix": {"labels": pnames, "rows_true_cols_pred": cm.tolist()},
        "classes_never_seen": [n for k, n in LABEL_NAMES.items() if k not in set(np.unique(y_train))],
    }
    pd.DataFrame(cm, index=pnames, columns=pnames).to_csv(out / "confusion_matrix.csv")

    # Binary attack-vs-benign at the served operating lines
    attack = y_test != 0
    benign = ~attack
    flagged_cls = labels != 0
    p_attack = 1.0 - proba[:, 0]
    lines = {}
    for name, flagged in (("classifier_argmax", flagged_cls),
                          ("alert_line", flagged_cls & (score >= P.MONITOR_THRESHOLD)),
                          ("block_line", flagged_cls & (score >= P.BLOCK_THRESHOLD))):
        tp = int((flagged & attack).sum()); fp = int((flagged & benign).sum())
        fn = int((~flagged & attack).sum()); tn = int((~flagged & benign).sum())
        lines[name] = {"attack_recall": round(tp / max(1, tp + fn), 4), "benign_fpr": round(fp / max(1, fp + tn), 6),
                       "fnr": round(fn / max(1, tp + fn), 4), "tp": tp, "fp": fp, "fn": fn, "tn": tn,
                       "benign_fpr_wilson95": wilson(fp, fp + tn)}
    review = int(((action == "REVIEW") & benign).sum()), int(((action == "REVIEW") & attack).sum())
    report["operating_lines"] = {**lines, "unknown_override_rows": int(unknown.sum()),
                                 "review_queue": {"benign": review[0], "attack": review[1]},
                                 "actions": {a: int((action == a).sum()) for a in ("ALLOW", "MONITOR", "BLOCK", "REVIEW")}}
    report["probabilistic"] = {"pr_auc_attack_vs_benign": round(float(average_precision_score(attack, p_attack)), 4),
                               "brier_attack_probability": round(float(brier_score_loss(attack, p_attack)), 6),
                               "reliability": []}
    bins = np.linspace(0, 1, 11)
    for lo, hi in zip(bins[:-1], bins[1:]):
        m = (p_attack >= lo) & (p_attack < hi if hi < 1 else p_attack <= hi)
        if m.sum():
            report["probabilistic"]["reliability"].append({"bin": [round(lo, 1), round(hi, 1)], "n": int(m.sum()),
                                                           "mean_p": round(float(p_attack[m].mean()), 4),
                                                           "attack_rate": round(float(attack[m].mean()), 4)})
    # Errors by (true, predicted) pair, largest first
    errs = {}
    for t_, l_ in zip(y_test[labels != y_test], labels[labels != y_test]):
        k = f"{LABEL_NAMES[int(t_)]} -> {LABEL_NAMES[int(l_)]}"
        errs[k] = errs.get(k, 0) + 1
    report["errors_by_pair"] = dict(sorted(errs.items(), key=lambda kv: -kv[1]))

    (out / "results.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(json.dumps({k: report[k] for k in ("split_reconstruction",)}, indent=1)[:400])
    print("accuracy", report["classifier"]["accuracy"], "f1_macro", report["classifier"]["f1_macro"],
          "| alert line:", report["operating_lines"]["alert_line"])
    print("written:", out)


if __name__ == "__main__":
    main()
