"""Row-level analysis of benign false positives on the D18 folds of a v2 run (audit/ML_DEV_PROTOCOL_V2.md §6).
Reads predictions_C4.csv / predictions_C4A.csv and the 2018 development pool; diagnosis only, nothing is fitted.

  .venv/Scripts/python evaluation/fp_rows_v2.py
"""
import json, sys
from pathlib import Path
import numpy as np, pandas as pd
ENGINE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ENGINE))
from evaluation import dev_experiments as D
from evaluation.protected_data import permitted_files
from utils.features import FEATURE_NAMES

out = ENGINE / "experiments" / "dev_20261102_v2batch1"
X18, m18 = D.pool_2018(D.DATA_2018, permitted_files(D.DATA_2018)[0])
m18 = m18.reset_index(drop=True)
PAT = ("init_win_bytes_forward", "init_win_bytes_backward", "total_fwd_packets", "fwd_packet_len_max")
pc = [FEATURE_NAMES.index(c) for c in PAT]
m18["pattern"] = [tuple(int(v) for v in r) for r in X18[:, pc]]
m18["vector"] = [hash(r.tobytes()) for r in np.ascontiguousarray(X18)]
m18["winpair"] = [(int(a), int(b)) for a, b in X18[:, pc[:2]]]
ben18 = m18["raw"] == "benign"
top_by_day = {d: g["pattern"].value_counts().index[0] for d, g in m18[ben18].groupby("day")}
rep = {"top_benign_pattern_by_day": {d: list(p) for d, p in top_by_day.items()}}
for c in ("C4", "C4A"):
    p = pd.read_csv(out / f"predictions_{c}.csv", low_memory=False)
    p = p[p["corpus"] == 2018].copy() if p["corpus"].dtype != object else p[p["corpus"] == "2018"].copy()
    p = p.merge(m18[["file", "row", "pattern", "vector", "winpair"]], on=["file", "row"], how="left")
    assert p["pattern"].notna().all()
    rc = {}
    for fold, g in p.groupby("fold"):
        day = fold[5:]
        b = g[g["raw"] == "benign"]
        fp = b[b["pred"] != "Benign"]
        top = top_by_day[day]
        in_top = b["pattern"] == top
        r = {"benign": int(len(b)), "fp": int(len(fp)),
             "fp_distinct_vectors": int(fp["vector"].nunique()), "fp_distinct_patterns": int(fp["pattern"].nunique()),
             "fp_top5_patterns_share": round(float(fp["pattern"].value_counts().head(5).sum() / max(1, len(fp))), 3),
             "fp_pred_class": fp["pred"].value_counts().head(5).to_dict(),
             "fp_p_attack_q": {q: round(float(fp["p_attack"].quantile(q)), 3) for q in (0.1, 0.5, 0.9)} if len(fp) else None,
             "benign_p_attack_q": {q: round(float(b["p_attack"].quantile(q)), 4) for q in (0.5, 0.9, 0.99)},
             "fpr_in_day_top_pattern": round(float((b.loc[in_top, "pred"] != "Benign").mean()), 4),
             "fpr_outside_top_pattern": round(float((b.loc[~in_top, "pred"] != "Benign").mean()), 4),
             "benign_in_top_pattern": int(in_top.sum()),
             "fp_top_winpairs": {str(k): int(v) for k, v in fp["winpair"].value_counts().head(3).items()},
             "attack_recall_by_raw": {k: [round(float((gg["pred"] != "Benign").mean()), 3), int(len(gg))] for k, gg in g[g["raw"] != "benign"].groupby("raw")}}
        rc[fold] = r
    rep[c] = rc
(out / "v2_rows.json").write_text(json.dumps(rep, indent=1, default=str), encoding="utf-8")
print(json.dumps(rep, indent=1, default=str))
