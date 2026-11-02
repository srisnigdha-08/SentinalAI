"""
Stability check report (audit/ML_DEV_PROTOCOL_V3.md §10). Read-only: compares the full-data v3 run with the
training-subsample replicates for C0 and C4AI on corrected_v3 labels, at the argmax decision (with §5 eligibility per
replicate) and at the FROZEN operating lines; reports the line §2 would pick per replicate for information only.

  .venv/Scripts/python evaluation/stability_report.py
"""
import json, sys
from pathlib import Path

import numpy as np
import pandas as pd

ENGINE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ENGINE))
from evaluation import dev_summary as S, operating_line as L, taxonomies  # noqa: E402
from evaluation.v3_report import eligibility  # noqa: E402

EXP = ENGINE / "experiments"
RUNS = {"full": EXP / "dev_20261102_v3_corrected", "s1": EXP / "dev_20261102_v3_stab_s1", "s2": EXP / "dev_20261102_v3_stab_s2"}
FROZEN = {"C4AI": 0.915614, "C0": 0.974834}


def main():
    rep = {"frozen_lines": FROZEN, "replicates": {}, "spread": {}}
    per_fold = {}
    for name, d in RUNS.items():
        res = json.loads((d / "results.json").read_text(encoding="utf-8"))
        assert res["labels"]["label_set"] == "corrected_v3"
        r = {"train_subsample": res.get("train_subsample", {"fraction": 1.0}), "argmax": {}, "frozen_line": {}, "line_would_be": {}}
        summ = {}
        for c in FROZEN:
            sm = S.summary({"candidates": {c: res["candidates"][c]}})
            summ[c] = {fs: sm[f"{c} {fs}"] for fs in ("D17", "D18")}
            r["argmax"][c] = {fs: {k: summ[c][fs][k] for k in ("macro_recall", "pooled_recall", "macro_fpr", "pooled_fpr", "worst_fold_fpr")} for fs in ("D17", "D18")}
            p = pd.read_csv(d / f"predictions_{c}.csv", low_memory=False)
            benign = np.array([taxonomies.RAW_LABELS[x][1] == "Benign" for x in p["label_used"]])
            at = L.at_line(p, FROZEN[c])
            fp = int(round(at["pooled_fpr"] * benign.sum()))
            r["frozen_line"][c] = {"pooled_recall": at["pooled_recall"], "pooled_fpr": at["pooled_fpr"],
                                   "wilson_ub": round(float(L.wilson_upper(fp, benign.sum())), 6),
                                   "macro_recall_2017": at["macro_recall_2017"], "macro_recall_2018": at["macro_recall_2018"],
                                   "per_fold": at["per_fold"]}
            r["line_would_be"][c] = L.choose_line(p.loc[benign, "p_attack"].to_numpy())
            for f in res["candidates"][c]["folds"]:
                b = f["binary_argmax"]
                per_fold.setdefault((c, f["fold"]), []).append((b["attack_recall"], b["benign_fpr"]))
        r["eligibility_C4AI_vs_C0"] = eligibility(summ["C4AI"], summ["C0"])
        rep["replicates"][name] = r
    for (c, fold), v in per_fold.items():
        rec = [x[0] for x in v]
        fpr = [x[1] for x in v]
        rep["spread"][f"{c} {fold}"] = {"recall_min_max": [min(rec), max(rec)], "fpr_min_max": [min(fpr), max(fpr)]}
    out = RUNS["full"] / "stability_report.json"
    out.write_text(json.dumps(rep, indent=1, default=str), encoding="utf-8")
    print(json.dumps(rep, indent=1, default=str))


if __name__ == "__main__":
    main()
