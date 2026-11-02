"""
P3 / P4 / P4f (audit/ML_EVAL_PLAN.md): holdout evaluation of the served XGBoost *recipe*.

Default mode is --plan: builds the data pool exactly as training/train.py does (P5 verified that reconstruction),
keeps each row's source file and calendar day, and writes for every protocol a frozen split manifest (row ids +
sha256), per-fold class tables (classes absent from training flagged) and size-based cost estimates. Nothing is
trained and nothing in models/ is read or written.

--run --approved trains one throwaway model per fold with the served recipe (StandardScaler + XGBClassifier,
balanced sample weights, train.py's parameters) on the manifest's training rows, scores the manifest's test rows
and writes metrics. It never saves a model. It needs explicit approval (ML_EVAL_PLAN.md §6) and has not been run.

  .venv/Scripts/python evaluation/xgb_holdout_eval.py                       # plan only
  .venv/Scripts/python evaluation/xgb_holdout_eval.py --run --approved --protocols P3,P4
"""
import argparse, hashlib, json, sys, time
from datetime import datetime, timezone
from pathlib import Path

import numpy as np
import pandas as pd

ENGINE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ENGINE))
from evaluation.p5_served_model_eval import load_cicids_dir, sha256 as file_sha256  # noqa: E402
from utils.features import LABEL_NAMES, prepare_features  # noqa: E402

DAYS = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday"]
XGB_PARAMS = {"n_estimators": 200, "max_depth": 6, "learning_rate": 0.1, "random_state": 42, "n_jobs": -1,
              "eval_metric": "mlogloss"}  # training/train.py
SERVED_TRAIN_ROWS = 99627  # P5: training rows of the served model, the size the cost estimates scale from


def day_of(name: str) -> str:
    return name.split("-")[0].capitalize()


def build_pool(data_dir: Path):
    """train.py's pool (caps + exact-duplicate removal) with each kept row's file, day and source position."""
    df = load_cicids_dir(data_dir, keep_source=True)
    X, y = prepare_features(df.drop(columns=["_file", "_row"]), max_missing=0)
    rows = np.column_stack([X, y])
    _, first = np.unique(rows, axis=0, return_index=True)  # same rule as train.drop_duplicate_rows
    keep = np.sort(first)
    meta = df.iloc[keep][["_file", "_row"]].reset_index(drop=True)
    meta["day"] = meta["_file"].map(day_of)
    return X[keep], np.asarray(y)[keep].astype(int), meta


def protocols(meta: pd.DataFrame):
    """{name: [(fold, train_mask, test_mask)]} — P3 chronological, P4 calendar-day, P4f file holdout."""
    day, file = meta["day"].to_numpy(), meta["_file"].to_numpy()
    out = {"P3": [("Mon-Wed -> Thu+Fri", np.isin(day, DAYS[:3]), np.isin(day, DAYS[3:]))]}
    out["P4"] = [(d, day != d, day == d) for d in DAYS if (day == d).any()]
    out["P4f"] = [(f, file != f, file == f) for f in sorted(set(file))]
    return out


def manifest(meta, tr, te):
    ids = lambda m: [f"{f}#{r}" for f, r in zip(meta["_file"][m], meta["_row"][m])]  # noqa: E731
    body = json.dumps({"train": ids(tr), "test": ids(te)}, separators=(",", ":")).encode()
    return {"sha256": hashlib.sha256(body).hexdigest(), "train_rows": int(tr.sum()), "test_rows": int(te.sum())}, body


def class_table(y, tr, te):
    names = lambda m: {LABEL_NAMES[int(k)]: int(v) for k, v in zip(*np.unique(y[m], return_counts=True))}  # noqa: E731
    train, test = names(tr), names(te)
    return {"train": train, "test": test,
            "absent_from_training": sorted(c for c in test if c not in train),
            "attack_test_rows_of_unseen_classes": int(sum(v for c, v in test.items() if c not in train))}


def wilson(k, n, z=1.96):
    if n == 0:
        return None
    p, d = k / n, 1 + z * z / n
    c, r = p + z * z / (2 * n), z * ((p * (1 - p) / n + z * z / (4 * n * n)) ** 0.5)
    return [round((c - r) / d, 4), round((c + r) / d, 4)]


def binary(flagged, attack):
    tp, fp = int((attack & flagged).sum()), int((~attack & flagged).sum())
    fn, tn = int((attack & ~flagged).sum()), int((~attack & ~flagged).sum())
    prec = tp / max(1, tp + fp)
    rec = tp / max(1, tp + fn)
    return {"attack_recall": round(rec, 4), "attack_recall_ci95": wilson(tp, tp + fn),
            "benign_fpr": round(fp / max(1, fp + tn), 6), "benign_fpr_ci95": wilson(fp, fp + tn),
            "precision": round(prec, 4), "f1": round(2 * prec * rec / max(1e-12, prec + rec), 4),
            "tp": tp, "fp": fp, "fn": fn, "tn": tn}


def collisions(X, y, tr, te):
    """Test rows whose exact feature vector also occurs in training (same label, or a different one)."""
    key = lambda m: {r.tobytes(): None for r in np.ascontiguousarray(X[m])}  # noqa: E731
    train_labels = {}
    for r, lab in zip(np.ascontiguousarray(X[tr]), y[tr]):
        train_labels.setdefault(r.tobytes(), set()).add(int(lab))
    same = diff = 0
    for r, lab in zip(np.ascontiguousarray(X[te]), y[te]):
        labs = train_labels.get(r.tobytes())
        if labs is None:
            continue
        if int(lab) in labs:
            same += 1
        else:
            diff += 1
    return {"test_rows_vector_in_train_same_label": same, "test_rows_vector_in_train_other_label": diff}


def fit_and_score(X, y, tr, te, make_model=None, make_if=None):
    """One fold of the served recipe. Labels are re-encoded to 0..k-1 over the classes present in training
    (XGBoost needs contiguous labels); a test row of a class absent from training can only be right on the binary
    attack-vs-benign question, so per-class metrics are reported for classes seen in training only.
    Operating lines use the classifier term of the served threat score only: the served rule takes
    max(confidence, 0.7*confidence + 0.3*IF signal) for attack predictions, so omitting the Isolation Forest (not
    refitted per fold: outside the approved fits) can only lower an attack's score — recall at the lines is a lower
    bound, and benign rows the served IF would push over a line are not counted."""
    from sklearn.metrics import average_precision_score, confusion_matrix, f1_score, precision_recall_fscore_support
    from sklearn.pipeline import Pipeline
    from sklearn.preprocessing import StandardScaler
    from sklearn.utils.class_weight import compute_sample_weight
    assert not (tr & te).any(), "train and test overlap"
    classes = np.unique(y[tr])
    enc = {c: i for i, c in enumerate(classes)}
    y_tr = np.array([enc[c] for c in y[tr]])
    if make_model is None:
        from xgboost import XGBClassifier
        make_model = lambda: XGBClassifier(**XGB_PARAMS)  # noqa: E731
    pipe = Pipeline([("scaler", StandardScaler()), ("clf", make_model())])  # scaler fitted on training rows only
    t0 = time.time()
    pipe.fit(X[tr], y_tr, clf__sample_weight=compute_sample_weight("balanced", y_tr))
    fit_s = time.time() - t0
    proba = pipe.predict_proba(X[te])
    pred = classes[proba.argmax(axis=1)]
    max_p = proba.max(axis=1)
    benign_col = list(classes).index(0) if 0 in classes else None
    p_attack = 1 - proba[:, benign_col] if benign_col is not None else np.ones(len(pred))
    yt = y[te]
    attack, flagged = yt != 0, pred != 0
    seen = np.isin(yt, classes)
    present = sorted(set(np.unique(yt)) | set(np.unique(pred)))
    cm = confusion_matrix(yt, pred, labels=present)
    p, r, f, s = precision_recall_fscore_support(yt[seen], pred[seen], labels=classes, zero_division=0)
    per_class = {}
    for i, c in enumerate(classes):
        if s[i] == 0:
            continue
        tp = int(((yt == c) & (pred == c)).sum())
        per_class[LABEL_NAMES[int(c)]] = {"precision": round(float(p[i]), 4), "recall": round(float(r[i]), 4),
                                          "f1": round(float(f[i]), 4), "support": int(s[i]), "recall_ci95": wilson(tp, int(s[i]))}
    unseen = {}
    for c in sorted(set(np.unique(yt)) - set(classes)):
        m = yt == c
        got = {LABEL_NAMES[int(k)]: int(v) for k, v in zip(*np.unique(pred[m], return_counts=True))}
        unseen[LABEL_NAMES[int(c)]] = {"rows": int(m.sum()), "flagged_as_attack": int(flagged[m].sum()),
                                       "flagged_ci95": wilson(int(flagged[m].sum()), int(m.sum())), "predicted_as": got}
    seen_test = [c for c in classes if (yt[seen] == c).any()]
    return {"fit_seconds": round(fit_s, 1), "classes_in_training": [LABEL_NAMES[int(c)] for c in classes],
            "binary_classifier_argmax": binary(flagged, attack),
            "binary_alert_line_0.90_lower_bound": binary(flagged & (max_p >= 0.90), attack),
            "binary_block_line_0.92_lower_bound": binary(flagged & (max_p >= 0.92), attack),
            "pr_auc_attack_vs_benign": round(float(average_precision_score(attack, p_attack)), 4) if attack.any() and (~attack).any() else None,
            "per_class_seen": per_class,
            "macro_f1_seen_classes": round(float(f1_score(yt[seen], pred[seen], labels=seen_test, average="macro", zero_division=0)), 4) if seen_test else None,
            "unseen_classes": unseen,
            "confusion_matrix": {"labels": [LABEL_NAMES[int(c)] for c in present], "rows_true_cols_pred": cm.tolist()},
            "collisions": collisions(X, y, tr, te),
            **({"hybrid": hybrid(X, y, tr, te, pred, max_p, make_if)} if make_if else {})}


def hybrid(X, y, tr, te, pred, max_p, make_if):
    """The served threat score on a fold: an Isolation Forest fitted on the fold's BENIGN training rows only (as
    train.py does), then inference/predictor.py's own combination — anomaly_signal (fixed boundary -0.55, span 0.20),
    combine_threat_score, the BENIGN->Unknown override (score >= 0.55) and the REVIEW tier — at the served alert and
    block lines. Nothing from the held-out day is used for fitting, calibration or line selection."""
    from sklearn.pipeline import Pipeline
    from sklearn.preprocessing import StandardScaler
    from inference import predictor as P
    benign_train = tr & (y == 0)
    ifo = Pipeline([("scaler", StandardScaler()), ("if", make_if())])
    t0 = time.time()
    ifo.fit(X[benign_train])
    fit_s = time.time() - t0
    if_scores = np.asarray(ifo.score_samples(X[te]), dtype=float)
    is_attack = pred != 0
    rf_s = np.where(is_attack, max_p, 1 - max_p)
    if_sig = P.anomaly_signal(if_scores)
    score = np.round(P.combine_threat_score(rf_s, if_sig, is_attack), 4)
    unknown = (~is_attack) & (if_scores < P.ANOMALY_THRESHOLD)
    score = np.where(unknown, np.maximum(score, 0.55), score)
    review = unknown & (if_sig >= P.REVIEW_MIN_SIGNAL) & (score < P.MONITOR_THRESHOLD)
    attack = y[te] != 0
    return {"if_fit_seconds": round(fit_s, 1), "if_benign_training_rows": int(benign_train.sum()),
            "lines": {"alert": P.MONITOR_THRESHOLD, "block": P.BLOCK_THRESHOLD, "anomaly_boundary": P.ANOMALY_THRESHOLD},
            "alert_line": binary(is_attack & (score >= P.MONITOR_THRESHOLD), attack),
            "block_line": binary(is_attack & (score >= P.BLOCK_THRESHOLD), attack),
            "unknown_override_rows": {"benign": int((unknown & ~attack).sum()), "attack": int((unknown & attack).sum())},
            "review_queue": {"benign": int((review & ~attack).sum()), "attack": int((review & attack).sum())}}


def _versions():
    import subprocess
    import sklearn
    try:
        import xgboost
        xgb = xgboost.__version__
    except ImportError:
        xgb = None
    def git(*a):
        try:
            return subprocess.run(["git", "-C", str(ENGINE), *a], capture_output=True, text=True, timeout=10).stdout.strip()
        except OSError:
            return None
    return {"python": sys.version.split()[0], "numpy": np.__version__, "pandas": pd.__version__, "sklearn": sklearn.__version__,
            "xgboost": xgb, "git_commit": git("rev-parse", "HEAD"), "git_dirty": bool(git("status", "--porcelain", "--", ".."))}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", default=str(ENGINE / "datasets" / "cicids2017"))
    ap.add_argument("--out", default=str(ENGINE / "experiments" / f"xgb_holdout_{datetime.now():%Y%m%d}"))
    ap.add_argument("--protocols", default="P3,P4,P4f")
    ap.add_argument("--run", action="store_true", help="train and score (needs --approved)")
    ap.add_argument("--approved", action="store_true", help="the owner approved training throwaway fold models")
    ap.add_argument("--with-if", action="store_true", help="also fit an Isolation Forest per fold (full served score)")
    ap.add_argument("--approved-if", action="store_true", help="the owner approved the per-fold Isolation Forest fits")
    ap.add_argument("--expect", help="earlier results.json: the refitted classifiers must reproduce its argmax metrics")
    args = ap.parse_args()
    if args.run and not args.approved:
        sys.exit("--run trains models: pass --approved only with the owner's approval (audit/ML_EVAL_PLAN.md §6)")
    if args.with_if and not (args.run and args.approved_if):
        sys.exit("--with-if fits Isolation Forests: needs --run and --approved-if (owner approval, ML_EVAL_PLAN.md §5e)")
    expected = {}
    if args.expect:
        for name, rows in json.loads(Path(args.expect).read_text(encoding="utf-8"))["protocols"].items():
            for r in rows:
                expected[(name, r["fold"])] = r["result"]["binary_classifier_argmax"]
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    t0 = time.time()
    X, y, meta = build_pool(Path(args.data))
    report = {"generated_at": datetime.now(timezone.utc).isoformat(), "mode": "run" if args.run else "plan",
              "pool": {"rows": int(len(y)), "build_seconds": round(time.time() - t0, 1),
                       "by_day": {d: int((meta["day"] == d).sum()) for d in DAYS},
                       "by_file": meta["_file"].value_counts().sort_index().to_dict(),
                       "data_sha256": {f.name: file_sha256(f) for f in sorted(Path(args.data).glob("*.csv"))}},
              "recipe": {"model": "StandardScaler + XGBClassifier", "params": XGB_PARAMS, "sample_weight": "balanced",
                         "label_encoding": "per fold, over classes present in training",
                         "versions": _versions()},
              "protocols": {}}
    wanted = set(args.protocols.split(","))
    plan_file = out / "plan.json"
    frozen = {}
    if args.run and plan_file.exists():
        for name, rows in json.loads(plan_file.read_text(encoding="utf-8"))["protocols"].items():
            for r in rows:
                frozen[(name, r["fold"])] = r["sha256"]
    # Feature vectors carrying more than one label in the pool (kept by train.py's dedup, which keys on vector+label)
    _, inv = np.unique(X, axis=0, return_inverse=True)
    inv = inv.reshape(-1)
    multi = pd.Series(y).groupby(inv).nunique()
    conflicting = multi[multi > 1].index
    rows_conf = np.isin(inv, conflicting)
    pairs = pd.Series([tuple(sorted(LABEL_NAMES[int(v)] for v in set(y[inv == g]))) for g in conflicting]).value_counts()
    report["pool"]["conflicting_label_vectors"] = {"vectors": int(len(conflicting)), "rows": int(rows_conf.sum()),
                                                   "label_sets": {" / ".join(k): int(v) for k, v in pairs.items()}}
    for name, folds in protocols(meta).items():
        if name not in wanted:
            continue
        rows = []
        for fold, tr, te in folds:
            man, body = manifest(meta, tr, te)
            if args.run:
                assert not (tr & te).any(), f"{name} {fold}: train/test overlap"
                if frozen:
                    assert frozen.get((name, fold)) == man["sha256"], f"{name} {fold}: manifest differs from plan.json"
            (out / f"manifest_{name}_{fold.replace(' ', '_').replace('>', '').replace('+', 'and')}.json").write_bytes(body)
            entry = {"fold": fold, **man, "classes": class_table(y, tr, te),
                     "estimated_fit_minutes": f"~{max(1, round(tr.sum() / SERVED_TRAIN_ROWS * 2))} (size-scaled guess; unmeasured)"}
            if args.run:
                make_if = None
                if args.with_if:
                    from sklearn.ensemble import IsolationForest
                    from training.train import IF_PARAMS
                    make_if = lambda: IsolationForest(**IF_PARAMS)  # noqa: E731
                entry["result"] = fit_and_score(X, y, tr, te, make_if=make_if)
                if (name, fold) in expected:
                    same = entry["result"]["binary_classifier_argmax"] == expected[(name, fold)]
                    entry["result"]["reproduces_expected_argmax"] = same
                    assert same, f"{name} {fold}: refitted classifier differs from {args.expect}; stopping"
            rows.append(entry)
        report["protocols"][name] = rows
    (out / "plan.json" if not args.run else out / "results.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    for name, rows in report["protocols"].items():
        for r in rows:
            print(f"{name:4s} {r['fold']:<52s} train {r['train_rows']:>7,} test {r['test_rows']:>7,}  "
                  f"absent from training: {', '.join(r['classes']['absent_from_training']) or '-'}")
    print("written:", out)


if __name__ == "__main__":
    main()
