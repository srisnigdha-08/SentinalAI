"""
Descriptive error breakdown of saved v3 predictions (no fitting). For C4AI and C0 on corrected_v3 labels, at the argmax
decision and at the frozen operating lines: benign FPR and attack recall per day, benign false positives per flow
pattern, and how much the pooled-FPR uncertainty grows when correlated flows are resampled together (cluster
bootstrap over (day, pattern) clusters) instead of row by row (Wilson). Purely descriptive: no result, criterion or
line is changed.

  .venv/Scripts/python evaluation/error_breakdown.py
"""
import json, sys
from pathlib import Path

import numpy as np
import pandas as pd

ENGINE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ENGINE))
from evaluation import dev_experiments as D, operating_line as L, taxonomies  # noqa: E402
from evaluation.protected_data import permitted_files  # noqa: E402
from utils.features import FEATURE_NAMES  # noqa: E402

RUN = ENGINE / "experiments" / "dev_20261102_v3_corrected"
LINES = {"C4AI": 0.915614, "C0": 0.974834}
PATTERN = ("init_win_bytes_forward", "init_win_bytes_backward", "total_fwd_packets", "fwd_packet_len_max")
B = 2000


def pattern_keys(X):
    cols = [FEATURE_NAMES.index(c) for c in PATTERN]
    return ["/".join(str(int(v)) for v in r) for r in X[:, cols]]


def cluster_bootstrap_ub(flags, clusters, b=B, seed=0):
    """95th percentile of pooled rate when whole clusters are resampled with replacement."""
    df = pd.DataFrame({"f": flags.astype(int), "c": clusters})
    g = df.groupby("c")["f"].agg(["sum", "count"])
    s, n = g["sum"].to_numpy(), g["count"].to_numpy()
    rng = np.random.default_rng(seed)
    idx = rng.integers(0, len(s), size=(b, len(s)))
    rates = s[idx].sum(axis=1) / n[idx].sum(axis=1)
    return float(np.quantile(rates, 0.95)), int(len(s))


def main():
    X17, m17 = D.pool_2017(ENGINE / "datasets" / "cicids2017")
    X18, m18 = D.pool_2018(D.DATA_2018, permitted_files(D.DATA_2018)[0])
    meta = pd.concat([m17, m18], ignore_index=True)
    meta["pattern"] = pattern_keys(np.vstack([X17, X18]))
    meta["corpus"] = meta["corpus"].astype(str)
    rep = {"lines": LINES, "bootstrap_resamples": B, "candidates": {}}
    for c, t in LINES.items():
        p = pd.read_csv(RUN / f"predictions_{c}.csv", low_memory=False)
        p["corpus"] = p["corpus"].astype(str)
        p = p.merge(meta[["corpus", "file", "row", "pattern"]], on=["corpus", "file", "row"], how="left")
        assert p["pattern"].notna().all()
        fam = np.array([taxonomies.RAW_LABELS[x][1] for x in p["label_used"]])
        ben = fam == "Benign"
        entry = {}
        for dec, flag in (("argmax", ~p["pred"].isin(["Benign", "BENIGN"]).to_numpy()), ("line", p["p_attack"].to_numpy() >= t)):
            day = p["fold"].to_numpy()
            per_day = {}
            for d in pd.unique(day):
                m = day == d
                per_day[d] = {"benign_fpr": round(float(flag[m & ben].mean()), 5), "fp": int(flag[m & ben].sum()),
                              "recall": round(float(flag[m & ~ben].mean()), 4) if (m & ~ben).any() else None,
                              "recall_by_raw": {r: round(float(flag[m & ~ben & (p["label_used"].to_numpy() == r)].mean()), 4)
                                                for r in sorted(set(p.loc[m & ~ben, "label_used"]))}}
            fp = p[ben & flag]
            by_pat = fp.groupby(["fold", "pattern"]).size().sort_values(ascending=False)
            clusters = (p["fold"] + "|" + p["pattern"]).to_numpy()
            k, n = int(flag[ben].sum()), int(ben.sum())
            boot_ub, n_clusters = cluster_bootstrap_ub(flag[ben], clusters[ben])
            entry[dec] = {"per_day": per_day,
                          "benign_fp": k, "benign_rows": n, "benign_clusters": n_clusters,
                          "fp_distinct_patterns": int(len(by_pat)),
                          "fp_share_top10_patterns": round(float(by_pat.head(10).sum() / max(1, k)), 3),
                          "top_fp_patterns": {f"{a} {b}": int(v) for (a, b), v in by_pat.head(8).items()},
                          "pooled_fpr": round(k / n, 6), "wilson_ub_rows_independent": round(float(L.wilson_upper(k, n)), 6),
                          "cluster_bootstrap_ub95": round(boot_ub, 6)}
        rep["candidates"][c] = entry
    out = RUN / "error_breakdown.json"
    out.write_text(json.dumps(rep, indent=1, default=str), encoding="utf-8")
    print(json.dumps(rep, indent=1, default=str))


if __name__ == "__main__":
    main()
