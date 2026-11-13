#!/usr/bin/env python3
"""
Protocol v4 (audit/ML_DEV_PROTOCOL_V4.md): domain-balanced candidates C5 / C5E against the served recipe C0 and the
v3 reference C4AI, on the frozen v3 folds (D17 + D18, corrected_v3 labels, protected 2018 days never opened).

Isolation: fold models are throwaway objects in memory. Nothing is written to models/, nothing is registered, the
deployed model is never loaded. Output: results.json (metrics only, no rows, no weights) in --out.

  .venv/Scripts/python evaluation/candidate_v4.py --run --approved            # full run (~10 min)
  .venv/Scripts/python evaluation/candidate_v4.py --smoke                      # synthetic data, seconds (tests)
"""
import argparse, json, sys, time
from datetime import datetime, timezone
from pathlib import Path

import numpy as np

ENGINE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ENGINE))
from evaluation import feature_sets, taxonomies  # noqa: E402
from evaluation.xgb_holdout_eval import wilson  # noqa: E402

SEED = 42
BOOT_SEED = 20261113
BOOT_N = 10_000
C5_PARAMS = {"n_estimators": 400, "max_depth": 4, "learning_rate": 0.05, "min_child_weight": 5, "subsample": 0.8,
             "colsample_bytree": 0.8, "reg_lambda": 2.0, "random_state": SEED, "n_jobs": -1}
CANDIDATES_V4 = {
    "C5": {"features": "A", "taxonomy": "T1", "arch": "two_stage", "data": "2017+2018dev", "weights": "domain",
           "exclude_train_families": ["Infiltration"], "params": C5_PARAMS},
    "C5E": {"features": "E", "taxonomy": "T1", "arch": "two_stage", "data": "2017+2018dev", "weights": "domain",
            "exclude_train_families": ["Infiltration"], "params": C5_PARAMS},
}
REFERENCE = ("C0", "C4AI")  # run through evaluation/dev_experiments.py unchanged (must reproduce v3)
FPR_MARGIN_PP = 0.10
WORST_FOLD_FPR_MAX = 0.02


# ── weights ───────────────────────────────────────────────────────────────────────────────────────────────────
def domain_weights(groups, labels):
    """Every group (capture day) gets the same total weight; inside a group the weight is split equally across the
    labels present. Normalised to mean 1. Pure function of its inputs (unit-tested)."""
    groups, labels = np.asarray(groups), np.asarray(labels)
    w = np.zeros(len(labels), dtype=float)
    ugroups = np.unique(groups)
    for g in ugroups:
        gm = groups == g
        labs = np.unique(labels[gm])
        for lab in labs:
            m = gm & (labels == lab)
            w[m] = 1.0 / (len(ugroups) * len(labs) * m.sum())
    return w * (len(w) / w.sum()) if w.sum() else w


# ── metrics ───────────────────────────────────────────────────────────────────────────────────────────────────
def ece(p, y, bins=10):
    """Expected calibration error of p(attack) against the binary truth, equal-width bins."""
    p, y = np.clip(np.asarray(p, float), 0, 1), np.asarray(y, float)
    idx = np.minimum((p * bins).astype(int), bins - 1)
    total = 0.0
    for b in range(bins):
        m = idx == b
        if m.any():
            total += m.mean() * abs(p[m].mean() - y[m].mean())
    return round(float(total), 5)


def extra_metrics(attack, flagged, p_attack):
    tp = int((attack & flagged).sum()); fn = int((attack & ~flagged).sum())
    tn = int((~attack & ~flagged).sum()); fp = int((~attack & flagged).sum())
    tpr = tp / max(1, tp + fn) if (tp + fn) else None
    tnr = tn / max(1, tn + fp) if (tn + fp) else None
    bal = round((tpr + tnr) / 2, 4) if tpr is not None and tnr is not None else None
    return {"balanced_accuracy": bal, "ece": ece(p_attack, attack), "confusion_binary": {"tp": tp, "fp": fp, "fn": fn, "tn": tn}}


def summarise(folds):
    """Macro recall over folds with attacks, pooled recall/FPR from summed counts, worst-fold FPR."""
    with_attacks = [f for f in folds if f["binary_argmax"]["tp"] + f["binary_argmax"]["fn"] > 0]
    tp = sum(f["binary_argmax"]["tp"] for f in folds); fn = sum(f["binary_argmax"]["fn"] for f in folds)
    fp = sum(f["binary_argmax"]["fp"] for f in folds); tn = sum(f["binary_argmax"]["tn"] for f in folds)
    return {"folds": len(folds),
            "macro_recall": round(float(np.mean([f["binary_argmax"]["attack_recall"] for f in with_attacks])), 4) if with_attacks else None,
            "pooled_recall": round(tp / max(1, tp + fn), 4), "pooled_recall_ci95": wilson(tp, tp + fn),
            "pooled_fpr": round(fp / max(1, fp + tn), 6), "pooled_fpr_ci95": wilson(fp, fp + tn),
            "worst_fold_fpr": round(max(f["binary_argmax"]["benign_fpr"] for f in folds), 6),
            "mean_balanced_accuracy": round(float(np.mean([f["balanced_accuracy"] for f in folds if f["balanced_accuracy"] is not None])), 4)}


def paired_bootstrap(a, b, n=BOOT_N, seed=BOOT_SEED):
    """Mean of (a - b) over paired folds with a percentile 95 % interval from resampling folds."""
    d = np.asarray(a, float) - np.asarray(b, float)
    rng = np.random.default_rng(seed)
    means = d[rng.integers(0, len(d), size=(n, len(d)))].mean(axis=1)
    return {"mean_diff": round(float(d.mean()), 4), "ci95": [round(float(np.percentile(means, 2.5)), 4),
                                                             round(float(np.percentile(means, 97.5)), 4)], "folds": int(len(d))}


def eligible(cand, ref):
    """Protocol v4 §5 against C4AI: {fold_set: summary}. Returns (bool, reasons)."""
    reasons = []
    for fs in ("D17", "D18"):
        c, r = cand[fs], ref[fs]
        if not (c["macro_recall"] is not None and r["macro_recall"] is not None and c["macro_recall"] > r["macro_recall"]):
            reasons.append(f"{fs}: macro recall {c['macro_recall']} not above C4AI {r['macro_recall']}")
        if c["pooled_fpr"] > r["pooled_fpr"] + FPR_MARGIN_PP / 100:
            reasons.append(f"{fs}: pooled FPR {c['pooled_fpr']:.4%} > C4AI {r['pooled_fpr']:.4%} + {FPR_MARGIN_PP} pp")
        if c["worst_fold_fpr"] > WORST_FOLD_FPR_MAX:
            reasons.append(f"{fs}: worst-fold FPR {c['worst_fold_fpr']:.4%} > {WORST_FOLD_FPR_MAX:.0%}")
    return (not reasons), reasons


# ── fitting ───────────────────────────────────────────────────────────────────────────────────────────────────
def _fit_weighted(X, labels, weights, params):
    from sklearn.pipeline import Pipeline
    from sklearn.preprocessing import StandardScaler
    from xgboost import XGBClassifier
    classes = np.unique(labels)
    enc = {c: i for i, c in enumerate(classes)}
    yi = np.array([enc[c] for c in labels])
    clf = XGBClassifier(**params, eval_metric="logloss" if len(classes) == 2 else "mlogloss")
    pipe = Pipeline([("scaler", StandardScaler()), ("clf", clf)])
    pipe.fit(X, yi, clf__sample_weight=weights)
    return pipe, classes


def fit_predict_v4(cfg, X, raw, groups, tr, te):
    """Two-stage, domain-weighted: stage 1 benign vs attack, stage 2 attack family (T1) on attack rows only."""
    Xv, _ = feature_sets.variant(X, cfg["features"])
    labels = taxonomies.map_labels(raw, cfg["taxonomy"])
    benign = np.array([taxonomies.RAW_LABELS[r][1] == "Benign" for r in raw])
    t0 = time.time()
    y1 = np.where(benign[tr], "Benign", "Attack")
    s1, s1c = _fit_weighted(Xv[tr], y1, domain_weights(groups[tr], y1), cfg["params"])
    atr = tr & ~benign
    s2, s2c = _fit_weighted(Xv[atr], labels[atr], domain_weights(groups[atr], labels[atr]), cfg["params"])
    fit_s = time.time() - t0
    p_attack = s1.predict_proba(Xv[te])[:, list(s1c).index("Attack")]
    pred = np.where(p_attack >= 0.5, s2c[s2.predict_proba(Xv[te]).argmax(axis=1)], "Benign")
    return pred, p_attack, fit_s


# ── run ───────────────────────────────────────────────────────────────────────────────────────────────────────
def run(X, meta, raw, cands, fold_sets=("D17", "D18"), expect=None, log=print):
    from evaluation import dev_experiments as dev
    groups = (meta["corpus"].astype(str) + ":" + meta["day"].astype(str)).to_numpy()
    out = {}
    for cid in cands:
        cfg = dev.CANDIDATES[cid] if cid in REFERENCE else CANDIDATES_V4[cid]
        entry = {"config": {k: v for k, v in cfg.items()}, "folds": {fs: [] for fs in fold_sets}}
        for fs in fold_sets:
            for name, tr, te in dev.folds(meta, fs, cfg["data"]):
                tr = dev.train_mask(cfg, raw, tr)
                assert not (tr & te).any(), "train/test overlap"
                if cid in REFERENCE:
                    pred, p_attack, fit_s, _, _ = dev.fit_predict(cfg, X, raw, tr, te)
                else:
                    pred, p_attack, fit_s = fit_predict_v4(cfg, X, raw, groups, tr, te)
                s = dev.score(cfg, raw, te, pred, p_attack)
                attack = np.array([taxonomies.RAW_LABELS[r][1] != "Benign" for r in raw[te]])
                flagged = np.array([p not in ("BENIGN", "Benign") for p in pred])
                f = {"fold": name, "train_rows": int(tr.sum()), "test_rows": int(te.sum()), "fit_seconds": round(fit_s, 1),
                     "manifest_sha256": dev.manifest_hash(meta, tr, te), **s, **extra_metrics(attack, flagged, p_attack)}
                if expect and (cid, name) in expect:
                    f["reproduces_v3"] = expect[(cid, name)] == s["binary_argmax"]
                entry["folds"][fs].append(f)
                log(f"{cid:5s} {name:20s} recall {s['binary_argmax']['attack_recall']:.4f}  fpr {s['binary_argmax']['benign_fpr']:.5f}  ({fit_s:.0f}s)")
        entry["summary"] = {fs: summarise(entry["folds"][fs]) for fs in fold_sets}
        out[cid] = entry
    comparisons, decision = {}, {}
    for cid in [c for c in cands if c in CANDIDATES_V4]:
        for ref in [r for r in REFERENCE if r in out]:
            for fs in fold_sets:
                a, b = out[cid]["folds"][fs], out[ref]["folds"][fs]
                comparisons[f"{cid}-{ref}:{fs}"] = {
                    "recall": paired_bootstrap([f["binary_argmax"]["attack_recall"] for f in a], [f["binary_argmax"]["attack_recall"] for f in b]),
                    "fpr": paired_bootstrap([f["binary_argmax"]["benign_fpr"] for f in a], [f["binary_argmax"]["benign_fpr"] for f in b])}
        if "C4AI" in out and set(fold_sets) == {"D17", "D18"}:
            ok, why = eligible(out[cid]["summary"], out["C4AI"]["summary"])
            decision[cid] = {"eligible_as_shadow_candidate": ok, "reasons_not_eligible": why}
    return out, comparisons, decision


def _smoke_data(n=6000, seed=0):
    """Synthetic 53-column data with two corpora and day groups, for tests only (never a result)."""
    import pandas as pd
    from utils.features import FEATURE_NAMES
    rng = np.random.default_rng(seed)
    X = rng.normal(size=(n, len(FEATURE_NAMES)))
    days17, days18 = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday"], ["14-02-2018", "15-02-2018"]
    corpus = np.where(rng.random(n) < 0.7, "2017", "2018")
    day = np.array([rng.choice(days17) if c == "2017" else rng.choice(days18) for c in corpus])
    raw = np.where(X[:, 0] + X[:, 1] > 1.2, "ddos", "benign").astype(object)
    raw[(corpus == "2017") & (day == "Monday")] = "benign"
    X[raw == "ddos", 2] += 2.0
    meta = pd.DataFrame({"corpus": corpus, "day": day, "file": day, "row": np.arange(n), "raw": raw})
    return X, meta, raw


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=str(ENGINE / "experiments" / f"candidate_v4_{datetime.now():%Y%m%d}"))
    ap.add_argument("--candidates", default="C0,C4AI,C5,C5E")
    ap.add_argument("--run", action="store_true")
    ap.add_argument("--approved", action="store_true", help="the owner approved training throwaway fold models")
    ap.add_argument("--smoke", action="store_true", help="synthetic data, no real dataset read")
    ap.add_argument("--expect", default=str(ENGINE / "experiments" / "dev_20261102_v3_corrected" / "results.json"))
    a = ap.parse_args()
    cands = a.candidates.split(",")
    if a.smoke:
        X, meta, raw = _smoke_data()
        res, comp, dec = run(X, meta, raw, [c for c in cands if c in CANDIDATES_V4], fold_sets=("D17",), log=lambda *_: None)
        print(json.dumps({c: e["summary"] for c, e in res.items()}, indent=1))
        return
    if not (a.run and a.approved):
        sys.exit("training throwaway fold models needs --run --approved (audit/ML_DEV_PROTOCOL_V4.md)")
    from evaluation import dev_experiments as dev
    from evaluation.protected_data import permitted_files
    import pandas as pd
    t0 = time.time()
    X17, m17 = dev.pool_2017(ENGINE / "datasets" / "cicids2017")
    files18, protected_seen = permitted_files(dev.DATA_2018)
    X18, m18 = dev.pool_2018(dev.DATA_2018, files18)
    X, meta = np.vstack([X17, X18]), pd.concat([m17, m18], ignore_index=True)
    raw, label_report = dev.apply_label_set(meta, "corrected_v3")
    expect = {}
    if a.expect and Path(a.expect).exists():
        for cid, e in json.loads(Path(a.expect).read_text(encoding="utf-8"))["candidates"].items():
            for f in e["folds"]:
                if "binary_argmax" in f:
                    expect[(cid, f["fold"])] = f["binary_argmax"]
    res, comp, dec = run(X, meta, raw, cands, expect=expect)
    out = Path(a.out); out.mkdir(parents=True, exist_ok=True)
    report = {"protocol": "audit/ML_DEV_PROTOCOL_V4.md", "generated_at": datetime.now(timezone.utc).isoformat(),
              "labels": label_report, "versions": dev._versions(),
              "pool": {"rows_2017": int(len(m17)), "rows_2018": int(len(m18)), "files_2018": [f.name for f in files18],
                       "protected_files_present_not_read": protected_seen, "build_seconds": round(time.time() - t0, 1)},
              "bootstrap": {"n": BOOT_N, "seed": BOOT_SEED}, "candidates": res, "paired_comparisons": comp,
              "decision": dec, "deployed_model_changed": False}
    (out / "results.json").write_text(json.dumps(report, indent=2, default=str), encoding="utf-8")
    print(json.dumps({c: e["summary"] for c, e in res.items()}, indent=1))
    print(json.dumps(dec, indent=1))
    print("written:", out / "results.json")


if __name__ == "__main__":
    main()
