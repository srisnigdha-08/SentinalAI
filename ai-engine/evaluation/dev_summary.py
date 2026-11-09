"""
Read-only summary of dev_experiments results.json files (audit/ML_DEV_PROTOCOL_V2.md §5). For every candidate and
fold set it reports the macro average (mean of per-fold rates, as protocol v1 §7 uses) next to pooled counts
(tp/fp/fn/tn summed over folds), the worst fold, and the FPR without the homogeneous-benign fold, so that one fold's
single traffic pattern cannot hide inside a mean. Nothing is fitted.

  .venv/Scripts/python evaluation/dev_summary.py experiments/dev_20261102_batch1/results.json experiments/dev_20261102_batch3/results.json
"""
import json, sys
from pathlib import Path

HOMOGENEOUS_FOLDS = ("2018-21-02-2018",)  # benign top-pattern share 99.3 % (pipeline_integrity.py); reported separately


def summarise(folds, exclude=()):
    fs = [f for f in folds if f["fold"] not in exclude and "binary_argmax" in f]
    if not fs:
        return None
    b = [f["binary_argmax"] for f in fs]
    tp, fp, fn, tn = (sum(x[k] for x in b) for k in ("tp", "fp", "fn", "tn"))
    with_attacks = [x for x in b if x["tp"] + x["fn"] > 0]
    worst = max(fs, key=lambda f: f["binary_argmax"]["benign_fpr"])
    return {"folds": len(fs),
            "macro_recall": round(sum(x["attack_recall"] for x in with_attacks) / max(1, len(with_attacks)), 4),
            "macro_fpr": round(sum(x["benign_fpr"] for x in b) / len(b), 6),
            "pooled_recall": round(tp / max(1, tp + fn), 4), "pooled_fpr": round(fp / max(1, fp + tn), 6),
            "pooled": {"tp": tp, "fp": fp, "fn": fn, "tn": tn},
            "worst_fold_fpr": [worst["fold"], worst["binary_argmax"]["benign_fpr"]]}


def summary(results):
    out = {}
    for cid, e in results["candidates"].items():
        for fs in ("D17", "D18"):
            folds = [f for f in e["folds"] if f["fold"].startswith("2017" if fs == "D17" else "2018")]
            s = summarise(folds)
            if s is None:
                continue
            ex = summarise(folds, HOMOGENEOUS_FOLDS)
            if ex and ex["folds"] != s["folds"]:
                s["without_homogeneous_folds"] = {k: ex[k] for k in ("macro_recall", "macro_fpr", "pooled_recall", "pooled_fpr", "worst_fold_fpr")}
            out[f"{cid} {fs}"] = s
    return out


def main(paths):
    rep = {}
    for p in paths:
        rep.update(summary(json.loads(Path(p).read_text(encoding="utf-8"))))
    print(json.dumps(rep, indent=1))


if __name__ == "__main__":
    main(sys.argv[1:])
