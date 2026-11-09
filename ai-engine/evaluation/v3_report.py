"""
Protocol v3 report (audit/ML_DEV_PROTOCOL_V3.md §5). Read-only over the run outputs: per-fold counts, macro and pooled
metrics, worst fold, eligibility under the unchanged §7 rule with C0 on the same label set as baseline, the external-
test recommendation rule, infiltration recall, 2017-Thursday / 21-02 FP counts, how many corrected rows each model
flags, and every corrected-label run re-scored under the published labels (from its prediction dump). Nothing is fitted.

  .venv/Scripts/python evaluation/v3_report.py
"""
import json, sys
from pathlib import Path

import numpy as np
import pandas as pd

ENGINE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ENGINE))
from evaluation import dev_summary as S, taxonomies  # noqa: E402

EXP = ENGINE / "experiments"
RUNS = {"corrected_v3": EXP / "dev_20261102_v3_corrected", "published": EXP / "dev_20261102_v3_published"}
EXISTING_PUBLISHED = {"C0": EXP / "dev_20261102_batch1", "C4A": EXP / "dev_20261102_v2batch1"}


def folds_from_predictions(p: pd.DataFrame, label_col: str):
    """Binary counts per fold recomputed from a prediction dump under the given label column."""
    out = []
    for fold, g in p.groupby("fold", sort=False):
        attack = np.array([taxonomies.RAW_LABELS[r][1] != "Benign" for r in g[label_col]])
        flagged = (~g["pred"].isin(["Benign", "BENIGN"])).to_numpy()
        tp, fp = int((attack & flagged).sum()), int((~attack & flagged).sum())
        fn, tn = int((attack & ~flagged).sum()), int((~attack & ~flagged).sum())
        out.append({"fold": fold, "binary_argmax": {"tp": tp, "fp": fp, "fn": fn, "tn": tn,
                                                     "attack_recall": round(tp / max(1, tp + fn), 4),
                                                     "benign_fpr": round(fp / max(1, fp + tn), 6),
                                                     "precision": round(tp / max(1, tp + fp), 4)}})
    return out


def eligibility(s, base):
    why = []
    for fs in ("D17", "D18"):
        lim = base[fs]["macro_fpr"] + 0.001
        if s[fs]["macro_fpr"] > lim:
            why.append(f"{fs} mean FPR {s[fs]['macro_fpr']:.3%} > {lim:.3%}")
        if s[fs]["worst_fold_fpr"][1] > 0.02:
            why.append(f"{fs} fold {s[fs]['worst_fold_fpr'][0]} {s[fs]['worst_fold_fpr'][1]:.2%} > 2%")
    rec = (s["D18"]["macro_recall"] >= base["D18"]["macro_recall"] + 0.10) and (s["D17"]["macro_recall"] >= base["D17"]["macro_recall"])
    return {"eligible": not why, "reasons": why, "meets_external_test_recall_rule": bool(rec)}


def per_fold(folds):
    return {f["fold"]: {k: f["binary_argmax"][k] for k in ("tp", "fp", "tn", "fn", "attack_recall", "benign_fpr", "precision")} for f in folds}


def extras(p: pd.DataFrame, label_col: str):
    ben = p[label_col] == "benign"
    fp = p[ben & ~p["pred"].isin(["Benign", "BENIGN"])]
    inf = p[p["raw"].isin(["infiltration", "infilteration"])]
    r = {"thursday_fp": int((fp["fold"] == "2017-Thursday").sum()), "feb21_fp": int((fp["fold"] == "2018-21-02-2018").sum()),
         "fp_pred_class_d18": fp[fp["fold"].str.startswith("2018")]["pred"].value_counts().head(5).to_dict(),
         "fp_pred_class_d17": fp[fp["fold"].str.startswith("2017")]["pred"].value_counts().head(5).to_dict(),
         "infiltration_recall_by_fold": {f: [round(float((~g["pred"].isin(["Benign", "BENIGN"])).mean()), 4), int(len(g))] for f, g in inf.groupby("fold")}}
    if "label_used" in p:
        corr = p[(p["raw"] == "benign") & (p["label_used"] == "portscan")]
        r["corrected_rows_in_test"] = int(len(corr))
        r["corrected_rows_flagged"] = int((~corr["pred"].isin(["Benign", "BENIGN"])).sum())
        r["corrected_rows_pred_class"] = corr["pred"].value_counts().head(3).to_dict()
    return r


def main():
    rep = {"summary": {}, "per_fold": {}, "extras": {}, "eligibility": {}}
    res = {ls: json.loads((d / "results.json").read_text(encoding="utf-8")) for ls, d in RUNS.items()}
    for ls, r in res.items():
        assert r["labels"]["label_set"] == ls
        rep["labels_" + ls] = r["labels"]
    sets = {}  # (label_set, candidate) -> folds
    for ls, r in res.items():
        for c, e in r["candidates"].items():
            sets[(ls, c)] = e["folds"]
    for c, d in EXISTING_PUBLISHED.items():
        sets[("published", c)] = json.loads((d / "results.json").read_text(encoding="utf-8"))["candidates"][c]["folds"]
    # corrected runs re-scored under the published labels
    for c in res["corrected_v3"]["candidates"]:
        p = pd.read_csv(RUNS["corrected_v3"] / f"predictions_{c}.csv", low_memory=False)
        sets[("corrected_run_scored_published", c)] = folds_from_predictions(p, "raw")
        rep["extras"][f"corrected_v3 {c}"] = extras(p, "label_used")
    p = pd.read_csv(RUNS["published"] / "predictions_C4AI.csv", low_memory=False)
    rep["extras"]["published C4AI"] = extras(p, "raw")
    for (ls, c), folds in sets.items():
        key = f"{ls} {c}"
        rep["per_fold"][key] = per_fold(folds)
        res_like = {"candidates": {c: {"folds": folds}}}
        sm = S.summary(res_like)
        rep["summary"][key] = {fs: sm[f"{c} {fs}"] for fs in ("D17", "D18")}
    for ls in ("corrected_v3", "published", "corrected_run_scored_published"):
        base_key = f"{ls} C0"
        if base_key not in rep["summary"]:
            continue
        for key, s in rep["summary"].items():
            if key.startswith(ls + " ") and key != base_key:
                rep["eligibility"][key] = eligibility(s, rep["summary"][base_key])
    out = RUNS["corrected_v3"] / "v3_report.json"
    out.write_text(json.dumps(rep, indent=1, default=str), encoding="utf-8")
    for key, s in rep["summary"].items():
        print(f"{key:45s} D17 R {s['D17']['macro_recall']:.3f}/{s['D17']['pooled_recall']:.3f} FPR {s['D17']['macro_fpr']:.4f}/{s['D17']['pooled_fpr']:.4f} worst {s['D17']['worst_fold_fpr']} | "
              f"D18 R {s['D18']['macro_recall']:.3f}/{s['D18']['pooled_recall']:.3f} FPR {s['D18']['macro_fpr']:.4f}/{s['D18']['pooled_fpr']:.4f} worst {s['D18']['worst_fold_fpr']}")
    print(json.dumps(rep["eligibility"], indent=1))
    print(json.dumps(rep["extras"], indent=1))
    print("written:", out)


if __name__ == "__main__":
    main()
