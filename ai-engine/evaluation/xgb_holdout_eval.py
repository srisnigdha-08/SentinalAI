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


def fit_and_score(X, y, tr, te, make_model=None):
    """One fold of the served recipe. Labels are re-encoded to 0..k-1 over the classes present in training
    (XGBoost needs contiguous labels); a test row of a class absent from training can only be right on the binary
    attack-vs-benign question."""
    from sklearn.metrics import f1_score, precision_recall_fscore_support
    from sklearn.pipeline import Pipeline
    from sklearn.preprocessing import StandardScaler
    from sklearn.utils.class_weight import compute_sample_weight
    classes = np.unique(y[tr])
    enc = {c: i for i, c in enumerate(classes)}
    y_tr = np.array([enc[c] for c in y[tr]])
    if make_model is None:
        from xgboost import XGBClassifier
        make_model = lambda: XGBClassifier(**XGB_PARAMS)  # noqa: E731
    pipe = Pipeline([("scaler", StandardScaler()), ("clf", make_model())])
    t0 = time.time()
    pipe.fit(X[tr], y_tr, clf__sample_weight=compute_sample_weight("balanced", y_tr))
    fit_s = time.time() - t0
    pred = classes[pipe.predict(X[te])]
    yt = y[te]
    attack, flagged = yt != 0, pred != 0
    tp, fp = int((attack & flagged).sum()), int((~attack & flagged).sum())
    fn, tn = int((attack & ~flagged).sum()), int((~attack & ~flagged).sum())
    seen = np.isin(yt, classes)
    p, r, f, s = precision_recall_fscore_support(yt[seen], pred[seen], labels=classes, zero_division=0)
    return {"fit_seconds": round(fit_s, 1),
            "binary": {"attack_recall": round(tp / max(1, tp + fn), 4), "benign_fpr": round(fp / max(1, fp + tn), 6),
                       "tp": tp, "fp": fp, "fn": fn, "tn": tn},
            "per_class_seen": {LABEL_NAMES[int(c)]: {"precision": round(float(p[i]), 4), "recall": round(float(r[i]), 4),
                                                    "f1": round(float(f[i]), 4), "support": int(s[i])}
                               for i, c in enumerate(classes) if s[i] > 0},
            "macro_f1_seen": round(float(f1_score(yt[seen], pred[seen], labels=[c for c in classes if (yt[seen] == c).any()],
                                                  average="macro", zero_division=0)), 4) if seen.any() else None,
            "unseen_attack_rows_flagged": int((~seen & flagged).sum()), "unseen_attack_rows": int((~seen).sum())}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", default=str(ENGINE / "datasets" / "cicids2017"))
    ap.add_argument("--out", default=str(ENGINE / "experiments" / f"xgb_holdout_{datetime.now():%Y%m%d}"))
    ap.add_argument("--protocols", default="P3,P4,P4f")
    ap.add_argument("--run", action="store_true", help="train and score (needs --approved)")
    ap.add_argument("--approved", action="store_true", help="the owner approved training throwaway fold models")
    args = ap.parse_args()
    if args.run and not args.approved:
        sys.exit("--run trains models: pass --approved only with the owner's approval (audit/ML_EVAL_PLAN.md §6)")
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
                         "label_encoding": "per fold, over classes present in training"},
              "protocols": {}}
    wanted = set(args.protocols.split(","))
    for name, folds in protocols(meta).items():
        if name not in wanted:
            continue
        rows = []
        for fold, tr, te in folds:
            man, body = manifest(meta, tr, te)
            (out / f"manifest_{name}_{fold.replace(' ', '_').replace('>', '').replace('+', 'and')}.json").write_bytes(body)
            entry = {"fold": fold, **man, "classes": class_table(y, tr, te),
                     "estimated_fit_minutes": f"~{max(1, round(tr.sum() / SERVED_TRAIN_ROWS * 2))} (size-scaled guess; unmeasured)"}
            if args.run:
                entry["result"] = fit_and_score(X, y, tr, te)
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
