#!/usr/bin/env python3
"""
C1 re-evaluation: how much of the reported CICIDS2017 accuracy survives an independent split?

The deployed RF metadata (98.43% accuracy, 0.9862 weighted F1, 0.8448 macro F1) comes from
training/train.py: a stratified *random row* split. Flows from the same attack episode then sit on
both sides of the split, which inflates the score. This script retrains the production recipe
(same per-file caps, StandardScaler + RandomForest(RF_PARAMS), benign-only IsolationForest(IF_PARAMS),
production threat score) under three protocols on the same cleaned data:

  random    stratified random 80/20 row split               -> reproduces the reported number
  temporal  chronological split inside every (file, class)  -> known attacks, later in time
            first 70% train, 1% purge gap, last 29% test
  lodo      leave-one-day-out (Mon..Fri)                    -> attacks from a day never trained on

Reported per protocol: accuracy, macro/weighted F1, per-class precision/recall/support, benign FPR
with a 95% Wilson interval, and operational detection (production threatScore >= 0.70, i.e. the
backend would raise a threat; see backend/services/aiService.js storePrediction) plus the block line
(>= 0.92, auto-block when enabled). Both score rules are reported on the same trained models:
"current" = inference/predictor.py::combine_threat_score, "legacy_blend" = 0.7*rf + 0.3*if (pre-C3).

Exact duplicate rows (same features and label) are dropped before any split, keeping the copy from the
earliest day, so no test row has an identical twin in train (C2); --no-dedupe reproduces the older runs.

Nothing here writes to models/ or touches the running services. Usage:
  python evaluation/day_holdout_eval.py --data datasets/cicids2017 --out experiments/c1_day_holdout_eval
  python evaluation/day_holdout_eval.py --smoke   # small, fast run to check the pipeline
"""
import argparse
import json
import math
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.metrics import accuracy_score, f1_score, precision_recall_fscore_support
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler

ENGINE_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ENGINE_ROOT))
from utils.features import FEATURE_NAMES, LABEL_MAP, LABEL_NAMES, RAW_LABEL_TO_TARGET, prepare_features  # noqa: E402
from training.train import IF_PARAMS, RF_PARAMS  # noqa: E402
from inference.predictor import (  # noqa: E402
    ANOMALY_THRESHOLD, BLOCK_THRESHOLD, MONITOR_THRESHOLD, REVIEW_MIN_SIGNAL, anomaly_signal, combine_threat_score)

BENIGN = LABEL_MAP["BENIGN"]
DAYS = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday"]
# Same per-file caps as training/train.py, so the training sets resemble the deployed model's.
TRAIN_CAPS = {"BENIGN": 15000, "Port Scan": 10000, "DDoS": 10000}
TEST_CAPS = {"BENIGN": 20000, "Port Scan": 10000, "DDoS": 10000}
TRAIN_FRACTION, PURGE_FRACTION = 0.70, 0.01
SWEEP_LINES = [0.70, 0.75, 0.80, 0.85, 0.90, 0.92, 0.95, 0.97, 0.99]


# ── data ──────────────────────────────────────────────────────────────────────────────────────────
def day_of(path: Path) -> str:
    return path.name.split("-")[0].capitalize()


def load_file(path: Path, max_rows=None) -> pd.DataFrame:
    """One CSV → frame of FEATURE_NAMES + y + day/file/order, cleaned like training/train.py."""
    df = pd.read_csv(path, low_memory=False, nrows=max_rows)
    df.columns = df.columns.str.strip()
    label_col = next(c for c in df.columns if c.lower() == "label")
    numeric = df.drop(columns=[label_col]).apply(pd.to_numeric, errors="coerce")
    finite = np.isfinite(numeric.to_numpy(dtype=float)).all(axis=1)  # train.py drops NaN/inf rows
    df = df.loc[finite].reset_index(drop=True)
    X, y = prepare_features(df, max_missing=0)
    out = pd.DataFrame(X.astype(np.float32), columns=FEATURE_NAMES)
    out["y"] = y
    out["target"] = df[label_col].astype(str).str.strip().map(lambda v: RAW_LABEL_TO_TARGET.get(v, v)).values
    out["day"], out["file"], out["order"] = day_of(path), path.name, np.arange(len(out))
    return out


def load_all(data_dir: Path, max_rows=None, dedupe=True) -> pd.DataFrame:
    files = sorted(data_dir.glob("*.csv"), key=lambda f: (DAYS.index(day_of(f)) if day_of(f) in DAYS else 99, f.name))
    if not files:
        raise FileNotFoundError(f"No CSV files in {data_dir}")
    frames = []
    for f in files:
        t0 = time.time()
        frames.append(load_file(f, max_rows))
        print(f"  loaded {f.name}: {len(frames[-1]):,} rows ({time.time() - t0:.1f}s)", flush=True)
    data = pd.concat(frames, ignore_index=True)
    if dedupe:
        data = drop_duplicates(data)
    return data


def drop_duplicates(data: pd.DataFrame) -> pd.DataFrame:
    """Drop rows whose features and label repeat an earlier row; files are loaded Monday..Friday, so the
    earliest capture keeps its copy and a later day never re-tests a flow already seen in training."""
    before = len(data)
    data = data.drop_duplicates(subset=FEATURE_NAMES + ["y"], keep="first").reset_index(drop=True)
    data.attrs["duplicates_removed"] = before - len(data)
    print(f"  removed {before - len(data):,} exact duplicate rows ({(before - len(data)) / max(1, before):.1%})", flush=True)
    return data


def cap(df: pd.DataFrame, caps: dict, seed=42) -> pd.DataFrame:
    """Random cap per (file, class); classes without a cap are kept whole."""
    parts = []
    for (_, target), grp in df.groupby(["file", "target"], sort=False):
        limit = caps.get(target)
        parts.append(grp.sample(n=limit, random_state=seed) if limit and len(grp) > limit else grp)
    return pd.concat(parts) if parts else df.iloc[0:0]


def chronological_split(df: pd.DataFrame, train_fraction=TRAIN_FRACTION, purge_fraction=PURGE_FRACTION):
    """Within every (file, class): earliest rows train, a purge gap, latest rows test."""
    train_idx, test_idx = [], []
    for _, grp in df.groupby(["file", "target"], sort=False):
        grp = grp.sort_values("order")
        n = len(grp)
        if n < 3:  # too few to split in time; keep for training only
            train_idx.extend(grp.index)
            continue
        cut = max(1, int(n * train_fraction))
        gap = int(n * purge_fraction)
        train_idx.extend(grp.index[:cut])
        test_idx.extend(grp.index[min(n - 1, cut + gap):])
    return df.loc[train_idx], df.loc[test_idx]


# ── model (production recipe) ─────────────────────────────────────────────────────────────────────
def fit(train: pd.DataFrame, n_estimators=None):
    rf_params = dict(RF_PARAMS, **({"n_estimators": n_estimators} if n_estimators else {}))
    if_params = dict(IF_PARAMS, **({"n_estimators": n_estimators} if n_estimators else {}))
    X, y = train[FEATURE_NAMES].to_numpy(), train["y"].to_numpy()
    rf = Pipeline([("scaler", StandardScaler()), ("rf", RandomForestClassifier(**rf_params))]).fit(X, y)
    ifo = Pipeline([("scaler", StandardScaler()), ("if", IsolationForest(**if_params))]).fit(X[y == BENIGN])
    return rf, ifo


def production_scores(rf, ifo, X, rule="current"):
    """Vectorised inference/predictor.py::predict: class, threatScore, and the Unknown override.
    rule="current" uses predictor.combine_threat_score; "legacy_blend" is the pre-C3 0.7/0.3 blend."""
    proba = rf.predict_proba(X)
    classes = rf.classes_
    cls = classes[proba.argmax(axis=1)]
    max_p = proba.max(axis=1)
    rf_s = np.where(cls != BENIGN, max_p, 1.0 - max_p)
    if_score = ifo.named_steps["if"].score_samples(ifo.named_steps["scaler"].transform(X))
    if_sig = anomaly_signal(if_score)  # same function the live predictor uses
    if rule == "current":
        score = combine_threat_score(rf_s, if_sig, cls != BENIGN)
    elif rule == "legacy_blend":
        score = 0.7 * rf_s + 0.3 * if_sig
    else:
        raise ValueError(f"unknown score rule {rule}")
    unknown = (cls == BENIGN) & (if_score < ANOMALY_THRESHOLD)
    score = np.where(unknown, np.maximum(score, 0.55), score)
    return cls, score, unknown


# ── metrics ───────────────────────────────────────────────────────────────────────────────────────
def wilson(k: int, n: int, z=1.96):
    if n == 0:
        return [None, None]
    p = k / n
    denom = 1 + z * z / n
    centre = (p + z * z / (2 * n)) / denom
    half = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / denom
    return [round(max(0.0, centre - half), 6), round(min(1.0, centre + half), 6)]


def operational(y, cls, score, unknown) -> dict:
    """What the backend would do: raise a threat (>= 0.70, non-BENIGN or Unknown) / block (>= 0.92)."""
    benign, attacks = y == BENIGN, y != BENIGN
    flagged = (cls != BENIGN) | unknown
    out = {}
    for name, line in (("threat_raised", MONITOR_THRESHOLD), ("block_line", BLOCK_THRESHOLD)):
        hit = flagged & (score >= line)
        fp = int(hit[benign].sum())
        out[name] = {
            "benign_fpr": round(fp / max(1, int(benign.sum())), 6),
            "benign_fpr_ci95": wilson(fp, int(benign.sum())),
            "attack_detection": round(float(hit[attacks].mean()), 4) if attacks.any() else None,
        }
    # Threshold sweep: where would the threat line have to sit to meet a given benign FPR target?
    out["sweep"] = []
    for line in SWEEP_LINES:
        hit = flagged & (score >= line)
        out["sweep"].append({
            "line": line,
            "benign_fpr": round(int(hit[benign].sum()) / max(1, int(benign.sum())), 6),
            "attack_detection": round(float(hit[attacks].mean()), 4) if attacks.any() else None,
        })
    return out


def evaluate(rf, ifo, test: pd.DataFrame, trained_classes=None) -> dict:
    X, y = test[FEATURE_NAMES].to_numpy(), test["y"].to_numpy()
    cls, score, unknown = production_scores(rf, ifo, X)
    _, legacy_score, _ = production_scores(rf, ifo, X, rule="legacy_blend")
    labels = sorted(set(y) | set(cls))
    p, r, f, s = precision_recall_fscore_support(y, cls, labels=labels, zero_division=0)
    per_class = {
        LABEL_NAMES[int(l)]: {"precision": round(float(pi), 4), "recall": round(float(ri), 4),
                              "f1": round(float(fi), 4), "support": int(si), "reliable": bool(si >= MIN_RELIABLE_SUPPORT),
                              **({"seen_in_training": bool(int(l) in trained_classes)} if trained_classes is not None else {})}
        for l, pi, ri, fi, si in zip(labels, p, r, f, s) if si > 0
    }
    benign = y == BENIGN
    attacks = ~benign
    if_sig = anomaly_signals(ifo, X)
    threat = score >= MONITOR_THRESHOLD  # backend creates a ThreatLog at >= 0.70 for non-BENIGN classes
    raised = threat & ((cls != BENIGN) | unknown)
    fp_cls = int((cls[benign] != BENIGN).sum())
    fp_alert = int(raised[benign].sum())
    present = sorted(set(y))
    out = {
        "n_test": int(len(y)),
        "accuracy": round(float(accuracy_score(y, cls)), 4),
        "f1_macro": round(float(f1_score(y, cls, labels=present, average="macro", zero_division=0)), 4),
        "f1_weighted": round(float(f1_score(y, cls, labels=present, average="weighted", zero_division=0)), 4),
        "benign": {"n": int(benign.sum()),
                   "fpr_classifier": round(fp_cls / max(1, benign.sum()), 6), "fpr_classifier_ci95": wilson(fp_cls, int(benign.sum())),
                   "fpr_threat_raised": round(fp_alert / max(1, benign.sum()), 6), "fpr_threat_raised_ci95": wilson(fp_alert, int(benign.sum()))},
        "attacks": {"n": int(attacks.sum()),
                    "detection_rate_classifier": round(float((cls[attacks] != BENIGN).mean()), 4) if attacks.any() else None,
                    "detection_rate_threat_raised": round(float(raised[attacks].mean()), 4) if attacks.any() else None},
        "per_class": per_class,
        "isolation_forest": isolation_forest_report(y, cls, if_sig, REVIEW_MIN_SIGNAL),
        "score_rules": {"current": operational(y, cls, score, unknown),
                        "legacy_blend": operational(y, cls, legacy_score, unknown)},
    }
    if trained_classes is not None and attacks.any():
        unseen = attacks & ~np.isin(y, list(trained_classes))
        out["attacks"]["unseen_class_n"] = int(unseen.sum())
        out["attacks"]["unseen_class_detection_rate_threat_raised"] = (
            round(float(raised[unseen].mean()), 4) if unseen.any() else None)
    return out


# ── protocols ─────────────────────────────────────────────────────────────────────────────────────
def class_counts(df):
    return {str(k): int(v) for k, v in df["target"].value_counts().items()}


def run_random(pool, n_estimators):
    train, test = train_test_split(pool, test_size=0.2, random_state=42, stratify=pool["y"])
    rf, ifo = fit(train, n_estimators)
    return {"train_rows": len(train), "train_classes": class_counts(train), **evaluate(rf, ifo, test)}


def run_temporal(data, n_estimators):
    train, test = chronological_split(data)
    train, test = cap(train, TRAIN_CAPS), cap(test, TEST_CAPS)
    rf, ifo = fit(train, n_estimators)
    return {"train_rows": len(train), "train_classes": class_counts(train), **evaluate(rf, ifo, test)}


def anomaly_signals(ifo, X):
    """The live predictor's bounded anomaly signal (0 = not anomalous) for every row."""
    return anomaly_signal(ifo.named_steps["if"].score_samples(ifo.named_steps["scaler"].transform(X)))


def isolation_forest_report(y, cls, if_sig, review_level) -> dict:
    """
    What the Isolation Forest contributes on its own (H5): its flag rate on benign and attack flows, and the
    analyst-review queue = flows the classifier calls BENIGN whose anomaly signal is >= review_level
    (inference/predictor.py: predictedClass "Unknown", action "REVIEW"). Attack flows in that queue are the
    only attacks the anomaly tier recovers; it never raises an alert by itself.
    """
    benign, attacks = y == BENIGN, y != BENIGN
    flagged = if_sig > 0
    review = (cls == BENIGN) & (if_sig >= review_level) & flagged
    missed = attacks & (cls == BENIGN)
    return {
        "flag_rate_benign": round(float(flagged[benign].mean()), 6) if benign.any() else None,
        "flag_rate_attack": round(float(flagged[attacks].mean()), 6) if attacks.any() else None,
        "review_level": review_level,
        "review_rate_benign": round(float(review[benign].mean()), 6) if benign.any() else None,
        "review_queue_size": int(review.sum()),
        "review_queue_attack_share": round(float(attacks[review].mean()), 6) if review.any() else None,
        "attacks_missed_by_classifier": int(missed.sum()),
        "missed_attacks_sent_to_review": int((missed & review).sum()),
    }


REVIEW_BENIGN_TARGET = 0.005  # at most 0.5 % of benign flows may enter the analyst-review queue
REVIEW_LEVELS = [round(0.05 * i, 2) for i in range(21)]  # anomaly signal 0.00 .. 1.00


def run_review(data, n_estimators, target=REVIEW_BENIGN_TARGET):
    """
    Choose the anomaly signal at which a BENIGN-classified flow is sent to analyst review, without touching the
    test rows: same fit / validation / test split as run_threshold; the lowest level whose benign review rate
    on validation is <= target is selected, then measured once on test.
    """
    train_all, test = chronological_split(data)
    fit_rows, validation = chronological_split(train_all, train_fraction=0.80, purge_fraction=PURGE_FRACTION)
    fit_rows, validation, test = cap(fit_rows, TRAIN_CAPS), cap(validation, TEST_CAPS), cap(test, TEST_CAPS)
    rf, ifo = fit(fit_rows, n_estimators)

    def at(frame, level):
        X, y = frame[FEATURE_NAMES].to_numpy(), frame["y"].to_numpy()
        cls, _, _ = production_scores(rf, ifo, X)
        return isolation_forest_report(y, cls, anomaly_signals(ifo, X), level)

    sweep = [at(validation, level) for level in REVIEW_LEVELS]
    chosen = next((s["review_level"] for s in sweep if s["review_rate_benign"] <= target), REVIEW_LEVELS[-1])
    return {"target_benign_review_rate": target, "validation_sweep": sweep, "chosen_level": chosen,
            "test_at_chosen_level": at(test, chosen),
            "test_sweep_not_used_for_selection": [at(test, level) for level in REVIEW_LEVELS]}


MIN_RELIABLE_SUPPORT = 30  # per-class test rows below this: metric reported but marked unreliable (H2)
ALERT_FPR_TARGET = 0.001
CANDIDATE_LINES = [round(0.70 + 0.01 * i, 2) for i in range(30)]  # 0.70 .. 0.99


def alert_rates(rf, ifo, frame, line):
    X, y = frame[FEATURE_NAMES].to_numpy(), frame["y"].to_numpy()
    cls, score, unknown = production_scores(rf, ifo, X)
    hit = ((cls != BENIGN) | unknown) & (score >= line)
    benign = y == BENIGN
    fp = int(hit[benign].sum())
    return {
        "line": line,
        "benign_fpr": round(fp / max(1, int(benign.sum())), 6),
        "benign_fpr_ci95": wilson(fp, int(benign.sum())),
        "attack_detection": round(float(hit[~benign].mean()), 4) if (~benign).any() else None,
    }


def run_threshold(data, n_estimators, target=ALERT_FPR_TARGET):
    """
    Choose the alert line without touching the test rows: the chronological training portion is split
    chronologically again (fit 80 % / validation 20 %), the lowest line whose benign alert rate on
    validation is <= target is selected, and only then is it measured once on the held-out test rows.
    """
    train_all, test = chronological_split(data)
    fit_rows, validation = chronological_split(train_all, train_fraction=0.80, purge_fraction=PURGE_FRACTION)
    fit_rows, validation, test = cap(fit_rows, TRAIN_CAPS), cap(validation, TEST_CAPS), cap(test, TEST_CAPS)
    rf, ifo = fit(fit_rows, n_estimators)
    sweep = [alert_rates(rf, ifo, validation, line) for line in CANDIDATE_LINES]
    # Point rule: validation estimate within target. Conservative rule: the 95 % Wilson upper bound on
    # validation is within target, which leaves room for drift between validation and later traffic.
    point = next((s["line"] for s in sweep if s["benign_fpr"] <= target), CANDIDATE_LINES[-1])
    conservative = next((s["line"] for s in sweep if s["benign_fpr_ci95"][1] <= target), CANDIDATE_LINES[-1])
    return {
        "target_benign_fpr": target,
        "fit_rows": len(fit_rows),
        "validation_rows": len(validation),
        "validation_sweep": sweep,
        "chosen_line": point,
        "test_at_chosen_line": alert_rates(rf, ifo, test, point),
        "conservative_line": conservative,
        "test_at_conservative_line": alert_rates(rf, ifo, test, conservative),
        "test_at_0_70": alert_rates(rf, ifo, test, 0.70),
        # Reported for transparency only; never used to pick a line.
        "test_sweep_not_used_for_selection": [alert_rates(rf, ifo, test, line) for line in CANDIDATE_LINES],
    }


def run_lodo(pool, n_estimators):
    results = {}
    for day in [d for d in DAYS if d in set(pool["day"])]:
        train, test = pool[pool["day"] != day], pool[pool["day"] == day]
        rf, ifo = fit(train, n_estimators)
        trained = set(int(c) for c in np.unique(train["y"]))
        results[day] = {"train_rows": len(train), "test_classes": class_counts(test),
                        **evaluate(rf, ifo, test, trained_classes=trained)}
        print(f"    lodo {day}: acc={results[day]['accuracy']} "
              f"detect={results[day]['attacks']['detection_rate_threat_raised']} "
              f"benignFPR={results[day]['benign']['fpr_threat_raised']}", flush=True)
    return results


def run_deployed(data, model_dir: Path):
    """The registered (served) artifact on the temporal test rows. It was trained on a random split of
    these same files, so this is NOT an independent estimate; reported for comparison only."""
    import joblib
    from inference.predictor import load_registry
    reg = load_registry(model_dir)
    if reg is None:
        return {"skipped": "no models/registry.json"}
    rf_path, if_path = model_dir / reg["classifier"]["file"], model_dir / reg["anomaly"]["file"]
    if not (rf_path.exists() and if_path.exists()):
        return {"skipped": "deployed model files not found"}
    _, test = chronological_split(data)
    test = cap(test, TEST_CAPS)
    return {"independent": False, "model": rf_path.name,
            **evaluate(joblib.load(rf_path), joblib.load(if_path), test)}


def markdown(report: dict) -> str:
    rows = ["| Protocol | Accuracy | Macro F1 | Weighted F1 | Benign FPR (threat raised) | Attack detection (threat raised) |",
            "|---|---|---|---|---|---|"]

    def line(name, r):
        b, a = r["benign"], r["attacks"]
        ci = b["fpr_threat_raised_ci95"]
        rows.append(f"| {name} | {r['accuracy']:.4f} | {r['f1_macro']:.4f} | {r['f1_weighted']:.4f} | "
                    f"{b['fpr_threat_raised']:.4%} [{ci[0]:.4%}, {ci[1]:.4%}] | "
                    f"{'-' if a['detection_rate_threat_raised'] is None else format(a['detection_rate_threat_raised'], '.4f')} |")

    for key, name in (("random", "Random 80/20 (as reported)"), ("temporal", "Chronological per class"),
                      ("deployed_on_temporal", "Deployed artifact on chronological test (not independent)")):
        if key in report["protocols"] and "accuracy" in report["protocols"][key]:
            line(name, report["protocols"][key])
    for day, r in report["protocols"].get("lodo", {}).items():
        line(f"Leave-out {day}", r)

    rows += ["", "Score rule comparison (same models): attack detection / benign FPR",
             "",
             "| Protocol | Threat raised: legacy blend | Threat raised: current | Block line: legacy blend | Block line: current |",
             "|---|---|---|---|---|"]

    def cell(o):
        det = "-" if o["attack_detection"] is None else f"{o['attack_detection']:.2%}"
        return f"{det} / {o['benign_fpr']:.4%}"

    def rule_line(name, r):
        sr = r.get("score_rules")
        if not sr:
            return
        rows.append(f"| {name} | {cell(sr['legacy_blend']['threat_raised'])} | {cell(sr['current']['threat_raised'])} | "
                    f"{cell(sr['legacy_blend']['block_line'])} | {cell(sr['current']['block_line'])} |")

    for key, name in (("random", "Random 80/20"), ("temporal", "Chronological per class"),
                      ("deployed_on_temporal", "Deployed artifact (not independent)")):
        if key in report["protocols"] and "accuracy" in report["protocols"][key]:
            rule_line(name, report["protocols"][key])
    for day, r in report["protocols"].get("lodo", {}).items():
        rule_line(f"Leave-out {day}", r)
    return "\n".join(rows)


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[1], formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--data", default=str(ENGINE_ROOT / "datasets" / "cicids2017"))
    ap.add_argument("--out", default=str(ENGINE_ROOT / "experiments" / "c1_day_holdout_eval"))
    ap.add_argument("--protocols", default="random,temporal,lodo,deployed")
    ap.add_argument("--n-estimators", type=int, default=None, help="override RF/IF trees (default: production 200)")
    ap.add_argument("--max-rows-per-file", type=int, default=None)
    ap.add_argument("--smoke", action="store_true", help="20k rows/file, 30 trees: quick pipeline check")
    ap.add_argument("--no-dedupe", action="store_true", help="keep exact duplicate rows (reproduces pre-C2 runs)")
    ap.add_argument("--drop-features", default="",
                    help="comma-separated features set to 0 everywhere (ablation, e.g. init_win_bytes_forward,"
                         "init_win_bytes_backward); constant columns are never split on, so this equals removing them")
    args = ap.parse_args()
    if args.smoke:
        args.max_rows_per_file, args.n_estimators = args.max_rows_per_file or 20000, args.n_estimators or 30

    t_start = time.time()
    print("Loading CICIDS2017 CSVs...", flush=True)
    data = load_all(Path(args.data), args.max_rows_per_file, dedupe=not args.no_dedupe)
    dropped = [f.strip() for f in args.drop_features.split(",") if f.strip()]
    unknown = [f for f in dropped if f not in FEATURE_NAMES]
    if unknown:
        ap.error(f"unknown feature(s): {', '.join(unknown)}")
    if dropped:
        data[dropped] = 0.0
        print(f"  ablation: {', '.join(dropped)} set to 0", flush=True)
    pool = cap(data, TEST_CAPS)
    wanted = [p.strip() for p in args.protocols.split(",") if p.strip()]
    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "data_dir": str(Path(args.data).resolve()),
        "rows_after_cleaning": int(len(data)),
        "deduplicated": not args.no_dedupe,
        "dropped_features": dropped,
        "duplicates_removed": int(data.attrs.get("duplicates_removed", 0)),
        "class_counts_after_cleaning": class_counts(data),
        "recipe": {"rf_params": dict(RF_PARAMS, **({"n_estimators": args.n_estimators} if args.n_estimators else {})),
                   "if_params": dict(IF_PARAMS, **({"n_estimators": args.n_estimators} if args.n_estimators else {})),
                   "train_caps_per_file": TRAIN_CAPS, "test_caps_per_file": TEST_CAPS,
                   "chronological": {"train_fraction": TRAIN_FRACTION, "purge_fraction": PURGE_FRACTION},
                   "threat_raised_threshold": MONITOR_THRESHOLD, "block_threshold": BLOCK_THRESHOLD,
                   "score_rule": "current = max(rf_s, 0.7*rf_s + 0.3*if_sig) for attack classes"},
        "smoke": bool(args.smoke),
        "protocols": {},
    }
    for name in wanted:
        t0 = time.time()
        print(f"Protocol {name}...", flush=True)
        if name == "random":
            report["protocols"]["random"] = run_random(pool, args.n_estimators)
        elif name == "temporal":
            report["protocols"]["temporal"] = run_temporal(data, args.n_estimators)
        elif name == "lodo":
            report["protocols"]["lodo"] = run_lodo(pool, args.n_estimators)
        elif name == "deployed":
            report["protocols"]["deployed_on_temporal"] = run_deployed(data, ENGINE_ROOT / "models")
        elif name == "threshold":
            report["protocols"]["threshold"] = run_threshold(data, args.n_estimators)
        elif name == "review":
            report["protocols"]["review"] = run_review(data, args.n_estimators)
        else:
            ap.error(f"unknown protocol {name}")
        print(f"  done in {time.time() - t0:.1f}s", flush=True)
    report["runtime_seconds"] = round(time.time() - t_start, 1)

    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    stem = "smoke" if args.smoke else "results"
    (out / f"{stem}.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    (out / f"{stem}_summary.md").write_text(markdown(report) + "\n", encoding="utf-8")
    print("\n" + markdown(report))
    print(f"\nWrote {out / (stem + '.json')}")


if __name__ == "__main__":
    main()
