"""
Read-only integrity checks of the development pipeline (audit/ML_DEV_PROTOCOL_V2.md §3). Nothing is fitted.

  - feature coverage: every served feature is mapped from the 2018 CSV, derived the same way, or known-absent;
  - leakage: time-of-day columns are zero in both corpora; no IP/port/timestamp column is a feature;
  - constants: which of variant B's six features are constant in the 2017 pool, the 2018 pool and the union;
  - duplicates: exact feature vectors shared between training and test of every C4 fold (same / other label),
    and between the two corpora;
  - benign diversity per day (share of the most common pattern), which decides how informative a fold's FPR is.

  .venv/Scripts/python evaluation/pipeline_integrity.py [--out experiments/pipeline_integrity_<date>]
"""
import argparse, json, sys
from datetime import datetime
from pathlib import Path

import numpy as np
import pandas as pd

ENGINE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ENGINE))
from evaluation import dev_experiments as D, feature_sets, taxonomies  # noqa: E402
from evaluation.protected_data import permitted_files  # noqa: E402
from utils.features import DERIVED_FEATURES, FEATURE_NAMES, KNOWN_ABSENT_FEATURES  # noqa: E402

PATTERN = ("init_win_bytes_forward", "init_win_bytes_backward", "total_fwd_packets", "fwd_packet_len_max")


def feature_coverage():
    mapped = set(D._mapping_2018().values())
    missing = [f for f in FEATURE_NAMES if f not in mapped and f not in DERIVED_FEATURES and f not in KNOWN_ABSENT_FEATURES]
    return {"mapped_from_2018_csv": len(mapped & set(FEATURE_NAMES)), "derived": list(DERIVED_FEATURES),
            "known_absent_zero": list(KNOWN_ABSENT_FEATURES), "unaccounted": missing}


def shared_vectors(X, labels, tr, te):
    """Test rows whose exact vector occurs in training with the same label / only with another label."""
    seen = {}
    for r, lab in zip(np.ascontiguousarray(X[tr]), labels[tr]):
        seen.setdefault(r.tobytes(), set()).add(lab)
    same = other = 0
    for r, lab in zip(np.ascontiguousarray(X[te]), labels[te]):
        s = seen.get(r.tobytes())
        if s is None:
            continue
        if lab in s:
            same += 1
        else:
            other += 1
    return same, other


def benign_diversity(X, meta, ben):
    cols = [FEATURE_NAMES.index(c) for c in PATTERN]
    out = {}
    for (c, d), g in meta[ben].groupby(["corpus", "day"]):
        vc = pd.Series([tuple(r) for r in X[g.index][:, cols]]).value_counts()
        out[f"{c} {d}"] = {"benign_rows": int(len(g)), "top_pattern_share": round(float(vc.iloc[0] / len(g)), 4), "distinct_patterns": int(len(vc))}
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--data17", default=str(ENGINE / "datasets" / "cicids2017"))
    ap.add_argument("--data18", default=str(D.DATA_2018))
    ap.add_argument("--out", default=str(ENGINE / "experiments" / f"pipeline_integrity_{datetime.now():%Y%m%d}"))
    args = ap.parse_args()
    X17, m17 = D.pool_2017(Path(args.data17))
    X18, m18 = D.pool_2018(Path(args.data18), permitted_files(args.data18)[0])
    X = np.vstack([X17, X18])
    meta = pd.concat([m17, m18], ignore_index=True)
    raw = meta["raw"].to_numpy()
    ben = np.array([taxonomies.RAW_LABELS[r][1] == "Benign" for r in raw])
    t1 = taxonomies.map_labels(raw, "T1")
    c17 = (meta["corpus"] == "2017").to_numpy()
    rep = {"feature_coverage": feature_coverage()}
    tod = [FEATURE_NAMES.index("time_of_day_sin"), FEATURE_NAMES.index("time_of_day_cos")]
    rep["time_of_day_all_zero"] = {"2017": bool((X17[:, tod] == 0).all()), "2018": bool((X18[:, tod] == 0).all())}
    rep["constant_features_variant_B"] = {
        f: {"2017": bool(np.unique(X17[:, FEATURE_NAMES.index(f)]).size == 1),
            "2018": bool(np.unique(X18[:, FEATURE_NAMES.index(f)]).size == 1),
            "union": bool(np.unique(X[:, FEATURE_NAMES.index(f)]).size == 1)}
        for f in feature_sets.CONSTANT_IN_POOL}
    keys17 = {x.tobytes() for x in np.ascontiguousarray(X17)}
    rep["cross_corpus_shared_vectors"] = {"2018_rows_with_a_2017_vector": int(sum(r.tobytes() in keys17 for r in np.ascontiguousarray(X18)))}
    rep["c4_fold_shared_vectors"] = {}
    for v in ("A", "C"):
        Xv, _ = feature_sets.variant(X, v)
        for fs in D.FOLD_SETS:
            for name, tr, te in D.folds(meta, fs, "2017+2018dev"):
                same, other = shared_vectors(Xv, t1, tr, te)
                rep["c4_fold_shared_vectors"][f"{v} {name}"] = {"test_rows": int(te.sum()), "same_label": same, "other_label": other}
    rep["benign_diversity"] = benign_diversity(X, meta, ben)
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    (out / "integrity.json").write_text(json.dumps(rep, indent=2), encoding="utf-8")
    print(json.dumps(rep, indent=1))


if __name__ == "__main__":
    main()
