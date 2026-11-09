"""
Distribution-shift analysis of the CICIDS2017 pool (no model is fitted). For the same pool as the served model
(train.py caps + de-duplication, via xgb_holdout_eval.build_pool) it reports:
  - constant features (carry no information);
  - benign traffic: per-feature two-sample Kolmogorov-Smirnov distance between each calendar day and the other days;
  - same class, different tool: DDoS Wednesday (DoS Hulk/GoldenEye/slowloris/Slowhttptest) vs Friday (LOIC), and
    "Credential Stuffing" Tuesday (FTP-Patator) vs Thursday (HTTP brute force).
KS = 1 means the two samples do not overlap at all on that feature.

  .venv/Scripts/python evaluation/shift_analysis.py [--out experiments/shift_analysis_<date>]
"""
import argparse, json, sys
from datetime import datetime
from pathlib import Path

import numpy as np
from scipy.stats import ks_2samp

ENGINE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ENGINE))
from evaluation.xgb_holdout_eval import DAYS, build_pool  # noqa: E402
from utils.features import FEATURE_NAMES, LABEL_MAP  # noqa: E402


def ks_table(A, B, live):
    out = {}
    for j in live:
        a, b = A[:, j], B[:, j]
        out[FEATURE_NAMES[j]] = round(float(ks_2samp(a, b).statistic), 3) if len(a) and len(b) else None
    return dict(sorted(out.items(), key=lambda kv: -(kv[1] or 0)))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", default=str(ENGINE / "datasets" / "cicids2017"))
    ap.add_argument("--out", default=str(ENGINE / "experiments" / f"shift_analysis_{datetime.now():%Y%m%d}"))
    args = ap.parse_args()
    X, y, meta = build_pool(Path(args.data))
    day = meta["day"].to_numpy()
    constant = [FEATURE_NAMES[j] for j in range(X.shape[1]) if np.unique(X[:, j]).size == 1]
    live = [j for j in range(X.shape[1]) if FEATURE_NAMES[j] not in constant]
    benign = y == LABEL_MAP["BENIGN"]
    report = {"pool_rows": int(len(y)), "constant_features": constant, "benign_day_vs_rest": {}, "same_class_other_tool": {}}
    for d in DAYS:
        tbl = ks_table(X[benign & (day == d)], X[benign & (day != d)], live)
        report["benign_day_vs_rest"][d] = {"rows": int((benign & (day == d)).sum()), "mean_ks": round(float(np.mean(list(tbl.values()))), 3),
                                           "top5": dict(list(tbl.items())[:5])}
    for name, cls, d1, d2 in (("DDoS: Wednesday DoS tools vs Friday LOIC", "DDoS", "Wednesday", "Friday"),
                              ("Credential Stuffing: Tuesday FTP-Patator vs Thursday HTTP brute force", "Credential Stuffing", "Tuesday", "Thursday")):
        m = y == LABEL_MAP[cls]
        tbl = ks_table(X[m & (day == d1)], X[m & (day == d2)], live)
        report["same_class_other_tool"][name] = {"rows": [int((m & (day == d1)).sum()), int((m & (day == d2)).sum())],
                                                 "mean_ks": round(float(np.mean(list(tbl.values()))), 3),
                                                 "features_ks_above_0.9": [k for k, v in tbl.items() if v and v > 0.9],
                                                 "top5": dict(list(tbl.items())[:5])}
    Path(args.out).mkdir(parents=True, exist_ok=True)
    (Path(args.out) / "shift.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(json.dumps(report, indent=1))


if __name__ == "__main__":
    main()
