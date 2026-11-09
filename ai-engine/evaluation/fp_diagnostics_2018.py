"""
Model-free diagnostics for the 21-02-2018 false positives of candidate C4 (audit/ML_DEV_PROTOCOL_V2.md §2).
No model is fitted: the analysis compares the held-out day's BENIGN rows with (a) the same fold's training rows
(nearest neighbour in the scaled feature space, exact duplicates), (b) benign rows of the other development days,
and (c) the day's own attack rows, plus timing and destination port. Timestamp, Dst Port and Protocol are read from
the raw CSV for diagnosis only; they are never model features. Only development days are read
(protected_data.assert_permitted is applied by the loaders).

  .venv/Scripts/python evaluation/fp_diagnostics_2018.py [--day 21-02-2018] [--out experiments/fp_diag_<date>]
"""
import argparse, json, sys
from datetime import datetime
from pathlib import Path

import numpy as np
import pandas as pd
from scipy.stats import ks_2samp

ENGINE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ENGINE))
from evaluation import dev_experiments as D, feature_sets, taxonomies  # noqa: E402
from evaluation.protected_data import assert_permitted, permitted_files  # noqa: E402
from utils.features import FEATURE_NAMES  # noqa: E402


def family(raw):
    return np.array([taxonomies.RAW_LABELS[r][1] for r in raw])


def raw_metadata(path: Path, rows: np.ndarray) -> pd.DataFrame:
    """Timestamp / Dst Port / Protocol / Label of the given data rows of one development file (diagnosis only)."""
    assert_permitted(path)
    meta = pd.read_csv(path, usecols=lambda c: c.strip() in ("Timestamp", "Dst Port", "Protocol", "Label"), low_memory=False)
    meta.columns = meta.columns.str.strip()
    meta = meta.loc[rows]
    meta["Timestamp"] = pd.to_datetime(meta["Timestamp"], format="%d/%m/%Y %H:%M:%S", errors="coerce")
    meta["Dst Port"] = pd.to_numeric(meta["Dst Port"], errors="coerce")
    return meta


def nn_labels(X_train, fam_train, X_query, k=1):
    """Family of each query row's nearest training neighbour (Euclidean, scaler fitted on the training rows)."""
    from sklearn.neighbors import NearestNeighbors
    from sklearn.preprocessing import StandardScaler
    sc = StandardScaler().fit(X_train)
    nn = NearestNeighbors(n_neighbors=k, n_jobs=-1).fit(sc.transform(X_train))
    dist, idx = nn.kneighbors(sc.transform(X_query))
    return fam_train[idx[:, 0]], dist[:, 0]


def exact_overlap(X_a, X_b):
    """Number of rows of X_a whose exact vector occurs in X_b."""
    keys = {r.tobytes() for r in np.ascontiguousarray(X_b)}
    return int(sum(r.tobytes() in keys for r in np.ascontiguousarray(X_a)))


def ks_top(A, B, names, n=8):
    out = []
    for j, name in enumerate(names):
        if np.unique(np.concatenate([A[:, j], B[:, j]])).size > 1:
            out.append((name, round(float(ks_2samp(A[:, j], B[:, j]).statistic), 3)))
    return dict(sorted(out, key=lambda t: -t[1])[:n])


def describe(values):
    v = pd.Series(values)
    return {"n": int(v.size), "median": float(v.median()), "p10": float(v.quantile(0.1)), "p90": float(v.quantile(0.9)),
            "top_values": {str(k): int(c) for k, c in v.value_counts().head(5).items()}}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--data17", default=str(ENGINE / "datasets" / "cicids2017"))
    ap.add_argument("--data18", default=str(D.DATA_2018))
    ap.add_argument("--day", default="21-02-2018")
    ap.add_argument("--out", default=str(ENGINE / "experiments" / f"fp_diag_{datetime.now():%Y%m%d}"))
    args = ap.parse_args()
    X17, m17 = D.pool_2017(Path(args.data17))
    files18 = permitted_files(args.data18)[0]
    X18, m18 = D.pool_2018(Path(args.data18), files18)
    X = np.vstack([X17, X18])
    meta = pd.concat([m17, m18], ignore_index=True)
    raw = meta["raw"].to_numpy()
    fam = family(raw)
    test = (meta["corpus"] == "2018").to_numpy() & (meta["day"] == args.day).to_numpy()
    train = ~test  # C4's training side for this fold: 2017 + the other five 2018 development days
    ben = fam == "Benign"
    q = test & ben
    day_file = next(f for f in files18 if args.day in f.name)
    rep = {"day": args.day, "file": day_file.name, "model_free": True,
           "rows": {"test": int(test.sum()), "test_benign": int(q.sum()), "test_attack_by_raw": dict(pd.Series(raw[test & ~ben]).value_counts().astype(int)),
                    "train": int(train.sum())}}

    # 1. nearest training neighbour of each benign test row, under the C4 features (C) and the full set (A)
    for v in ("C", "A"):
        Xv, names = feature_sets.variant(X, v)
        nnfam, dist = nn_labels(Xv[train], fam[train], Xv[q])
        counts = pd.Series(nnfam).value_counts()
        rep[f"nn_family_of_benign_test_rows_features_{v}"] = {k: int(c) for k, c in counts.items()}
        rep[f"nn_attack_share_features_{v}"] = round(float((nnfam != "Benign").mean()), 4)
        if v == "C":
            nn_attack_c = nnfam != "Benign"
        rep[f"exact_duplicates_benign_test_vs_train_attack_features_{v}"] = exact_overlap(Xv[q], Xv[train & ~ben])
        rep[f"exact_duplicates_benign_test_vs_train_benign_features_{v}"] = exact_overlap(Xv[q], Xv[train & ben])

    # 2. how different is this day's benign traffic from other development days' benign traffic / from its own attacks
    Xa, names = feature_sets.variant(X, "A")
    other18_ben = (meta["corpus"] == "2018").to_numpy() & ~test & ben
    rep["ks_benign_day_vs_other_2018_benign"] = ks_top(Xa[q], Xa[other18_ben], names)
    rep["ks_benign_day_vs_2017_benign"] = ks_top(Xa[q], Xa[(meta["corpus"] == "2017").to_numpy() & ben], names)
    rep["ks_benign_day_vs_own_attacks"] = ks_top(Xa[q], Xa[test & ~ben], names)
    iw = names.index("init_win_bytes_forward"), names.index("init_win_bytes_backward")
    for label, m in (("benign_day", q), ("benign_other_2018", other18_ben), ("attacks_day", test & ~ben)):
        rep[f"init_win_bytes_forward_{label}"] = describe(Xa[m, iw[0]])
        rep[f"init_win_bytes_backward_{label}"] = describe(Xa[m, iw[1]])
        rep[f"flow_duration_{label}"] = describe(Xa[m, names.index("flow_duration")])
        rep[f"total_fwd_packets_{label}"] = describe(Xa[m, names.index("total_fwd_packets")])

    # 3. timing and destination port (raw metadata, diagnosis only)
    rows = meta["row"].to_numpy()
    md = raw_metadata(day_file, rows[test])
    md["benign"] = ben[test]
    md["nn_attack_C"] = False
    md.loc[md["benign"], "nn_attack_C"] = nn_attack_c
    att = md[~md["benign"]]
    windows = att.groupby("Label")["Timestamp"].agg(["min", "max"])
    rep["attack_windows"] = {k: [str(a), str(b)] for k, (a, b) in windows.iterrows()}
    in_win = np.zeros(len(md), dtype=bool)
    for _, (a, b) in windows.iterrows():
        in_win |= ((md["Timestamp"] >= a) & (md["Timestamp"] <= b)).to_numpy()
    md["in_attack_window"] = in_win
    b = md[md["benign"]]
    rep["benign_in_attack_window"] = {"rows": int(b["in_attack_window"].sum()), "of": int(len(b)),
                                      "nn_attack_share_in_window": round(float(b.loc[b["in_attack_window"], "nn_attack_C"].mean()), 4) if b["in_attack_window"].any() else None,
                                      "nn_attack_share_outside": round(float(b.loc[~b["in_attack_window"], "nn_attack_C"].mean()), 4) if (~b["in_attack_window"]).any() else None}
    rep["benign_by_hour"] = {int(h): {"rows": int(len(g)), "nn_attack_share": round(float(g["nn_attack_C"].mean()), 4)}
                             for h, g in b.groupby(b["Timestamp"].dt.hour)}
    rep["benign_dst_port_top"] = {str(int(p)) if pd.notna(p) else "nan": {"rows": int(len(g)), "nn_attack_share": round(float(g["nn_attack_C"].mean()), 4)}
                                  for p, g in sorted(b.groupby("Dst Port"), key=lambda t: -len(t[1]))[:8]}
    rep["attack_dst_port_top"] = {str(int(p)): int(c) for p, c in att["Dst Port"].value_counts().head(5).items()}
    rep["benign_protocol"] = {str(int(p)) if pd.notna(p) else "nan": int(c) for p, c in b["Protocol"].value_counts().items()}

    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    (out / f"fp_diag_{args.day}.json").write_text(json.dumps(rep, indent=2, default=str), encoding="utf-8")
    print(json.dumps(rep, indent=1, default=str))


if __name__ == "__main__":
    main()
