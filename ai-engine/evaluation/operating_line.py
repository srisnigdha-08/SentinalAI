"""
Operating line for the external test (audit/OPERATING_LINE_V3.md §2). Read-only over out-of-fold prediction dumps:
the line is the smallest threshold t >= 0.5 on p_attack whose pooled benign-FPR Wilson 95 % upper bound over all
development test rows is <= 0.10 %. Nothing is fitted; no production threshold is touched.

  .venv/Scripts/python evaluation/operating_line.py
"""
import hashlib, json, math, sys
from pathlib import Path

import numpy as np
import pandas as pd

ENGINE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ENGINE))
from evaluation import taxonomies  # noqa: E402

RUN = ENGINE / "experiments" / "dev_20261102_v3_corrected"
CANDIDATES = ("C4AI", "C0")
MAX_UB, Z, T_MIN = 0.001, 1.959963984540054, 0.5


def wilson_upper(k, n, z=Z):
    """Exact (unrounded) Wilson score upper bound; works elementwise on arrays."""
    k, n = np.asarray(k, float), np.asarray(n, float)
    p = k / n
    centre = p + z * z / (2 * n)
    spread = z * np.sqrt(p * (1 - p) / n + z * z / (4 * n * n))
    return (centre + spread) / (1 + z * z / n)


def choose_line(p_benign: np.ndarray, max_ub=MAX_UB, t_min=T_MIN):
    """Smallest t in {t_min} U {distinct scores >= t_min} with Wilson UB of P(benign score >= t) <= max_ub; else None."""
    n = len(p_benign)
    cand = np.unique(np.concatenate([[t_min], p_benign[p_benign >= t_min]]))
    s = np.sort(p_benign)
    fp = n - np.searchsorted(s, cand, side="left")  # benign rows with score >= t
    ok = wilson_upper(fp, n) <= max_ub
    if not ok.any():
        return None
    i = int(np.argmax(ok))  # first (smallest) qualifying t; UB is non-increasing in t
    return {"t": float(cand[i]), "fp": int(fp[i]), "benign": int(n), "fpr": fp[i] / n, "wilson_ub": float(wilson_upper(fp[i], n))}


def at_line(p: pd.DataFrame, t: float) -> dict:
    fam = np.array([taxonomies.RAW_LABELS[r][1] for r in p["label_used"]])
    attack = fam != "Benign"
    flag = p["p_attack"].to_numpy() >= t
    out = {"pooled_recall": round(float(flag[attack].mean()), 4), "pooled_fpr": round(float(flag[~attack].mean()), 6),
           "per_fold": {}, "per_family_flagged": {}}
    for fold, g in p.assign(_a=attack, _f=flag).groupby("fold", sort=False):
        a, f = g["_a"].to_numpy(), g["_f"].to_numpy()
        out["per_fold"][fold] = {"recall": round(float(f[a].mean()), 4) if a.any() else None, "fpr": round(float(f[~a].mean()), 6),
                                 "fp": int(f[~a].sum())}
    for name in sorted(set(fam) - {"Benign"}):
        m = fam == name
        out["per_family_flagged"][name] = round(float(flag[m].mean()), 4)
    for fs in ("2017", "2018"):
        folds = [v for k, v in out["per_fold"].items() if k.startswith(fs)]
        out[f"macro_recall_{fs}"] = round(float(np.mean([v["recall"] for v in folds if v["recall"] is not None])), 4)
        out[f"macro_fpr_{fs}"] = round(float(np.mean([v["fpr"] for v in folds])), 6)
    return out


def main():
    rep = {"rule": {"max_wilson_ub": MAX_UB, "z": Z, "t_min": T_MIN, "pooled_over": "all 11 D17+D18 test folds",
                    "labels": "corrected_v3"}, "candidates": {}}
    for c in CANDIDATES:
        f = RUN / f"predictions_{c}.csv"
        p = pd.read_csv(f, low_memory=False)
        assert {"label_used", "p_attack", "fold"} <= set(p.columns)
        benign = np.array([taxonomies.RAW_LABELS[r][1] == "Benign" for r in p["label_used"]])
        line = choose_line(p.loc[benign, "p_attack"].to_numpy())
        entry = {"predictions_sha256": hashlib.sha256(f.read_bytes()).hexdigest(), "line": line,
                 "at_argmax_equivalent_0_5": at_line(p, T_MIN)}
        if line:
            entry["at_line"] = at_line(p, line["t"])
        rep["candidates"][c] = entry
    out = RUN / "operating_line.json"
    out.write_text(json.dumps(rep, indent=1, default=str), encoding="utf-8")
    print(json.dumps(rep, indent=1, default=str))


if __name__ == "__main__":
    main()
