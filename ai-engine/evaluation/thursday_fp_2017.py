"""
Model-free look at the 2017-Thursday benign false positives (audit/ML_DEV_RESULTS.md, v2 batch 1). Nothing is fitted:
it reads the stored fold predictions of a v2 run and the 2017 CSVs. The MachineLearningCVE files have no IPs or
timestamps; `Destination Port` and the row position inside a file (the files are in capture order) are used for
diagnosis only and are never model features.

  .venv/Scripts/python evaluation/thursday_fp_2017.py [--run experiments/dev_20261102_v2batch1] [--candidate C4A]
"""
import argparse, json, sys
from pathlib import Path

import numpy as np
import pandas as pd
from scipy.stats import ks_2samp

ENGINE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ENGINE))
from evaluation import dev_experiments as D  # noqa: E402
from utils.features import FEATURE_NAMES  # noqa: E402

SHAPE = ("total_fwd_packets", "total_bwd_packets", "flow_duration", "init_win_bytes_forward", "init_win_bytes_backward",
         "total_len_fwd_packets", "total_len_bwd_packets")


def ports(path: Path) -> pd.Series:
    s = pd.read_csv(path, usecols=lambda c: c.strip() == "Destination Port", low_memory=False).iloc[:, 0]
    return pd.to_numeric(s, errors="coerce")


def position_profile(rows: np.ndarray, n_file: int, bins=20):
    h, _ = np.histogram(rows / n_file, bins=bins, range=(0, 1))
    return h.tolist()


def describe(X, names):
    return {n: {"median": float(np.median(X[:, FEATURE_NAMES.index(n)])), "p90": float(np.quantile(X[:, FEATURE_NAMES.index(n)], 0.9))} for n in names}


def probe_signature(df: pd.DataFrame) -> pd.Series:
    """Tiny probe flows: forward initial window 1024, <= 2 packets each way, no backward window (raw 2017 columns)."""
    return ((df["Init_Win_bytes_forward"] == 1024) & (df["Total Fwd Packets"] <= 2) & (df["Total Backward Packets"] <= 2)
            & (df["Init_Win_bytes_backward"] <= 0))


def signature_by_file(data_dir: Path):
    """Raw (un-pooled) count of the probe signature per 2017 file, by label, ports and position in the file."""
    cols = {"Destination Port", "Total Fwd Packets", "Total Backward Packets", "Init_Win_bytes_forward", "Init_Win_bytes_backward", "Label"}
    out = {}
    for f in sorted(data_dir.glob("*.csv")):
        df = pd.read_csv(f, usecols=lambda c: c.strip() in cols, low_memory=False)
        df.columns = df.columns.str.strip()
        sig = probe_signature(df)
        pos = np.flatnonzero(sig.to_numpy()) / len(df)
        out[f.name] = {"rows": int(len(df)), "signature_rows": int(sig.sum()),
                       "by_label": {str(k).strip(): int(v) for k, v in df.loc[sig, "Label"].value_counts().items()},
                       "distinct_dst_ports": int(df.loc[sig, "Destination Port"].nunique()),
                       "position_p05_p95": [round(float(np.quantile(pos, q)), 3) for q in (0.05, 0.95)] if len(pos) else None}
        inf = np.flatnonzero((df["Label"].astype(str).str.strip() == "Infiltration").to_numpy()) / len(df)
        if len(inf):
            out[f.name]["infiltration_label_position_range"] = [round(float(inf.min()), 3), round(float(inf.max()), 3)]
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--data17", default=str(ENGINE / "datasets" / "cicids2017"))
    ap.add_argument("--run", default=str(ENGINE / "experiments" / "dev_20261102_v2batch1"))
    ap.add_argument("--candidate", default="C4A")
    args = ap.parse_args()
    X, meta = D.pool_2017(Path(args.data17))
    meta = meta.reset_index(drop=True)
    p = pd.read_csv(Path(args.run) / f"predictions_{args.candidate}.csv", low_memory=False)
    p = p[p["fold"] == "2017-Thursday"].merge(meta.reset_index()[["index", "file", "row"]], on=["file", "row"], how="left")
    assert p["index"].notna().all()
    p["index"] = p["index"].astype(int)
    ben = p["raw"] == "benign"
    fp = p[ben & (p["pred"] != "Benign")]
    tn = p[ben & (p["pred"] == "Benign")]
    rep = {"candidate": args.candidate, "thursday_rows": int(len(p)), "benign": int(ben.sum()), "fp": int(len(fp)),
           "fp_pred_class": fp["pred"].value_counts().to_dict(),
           "fp_by_file": fp["file"].value_counts().to_dict(), "benign_by_file": p.loc[ben, "file"].value_counts().to_dict(),
           "attack_by_file_raw": {f"{f} | {r}": int(n) for (f, r), n in p[~ben].groupby(["file", "raw"]).size().items()}}
    ps = fp[fp["pred"] == "Port Scan"]
    # destination ports and row positions (diagnosis only)
    for fname in sorted(set(p["file"])):
        path = Path(args.data17) / fname
        dport = ports(path)
        n_file = len(dport)
        sub = {"file_rows": n_file}
        for label, d in (("fp_port_scan", ps), ("fp_other", fp[fp["pred"] != "Port Scan"]), ("benign_correct", tn),
                         ("attack", p[~ben])):
            d = d[d["file"] == fname]
            if not len(d):
                continue
            rows = d["row"].to_numpy()
            dp = dport.iloc[rows]
            sub[label] = {"rows": int(len(d)), "distinct_dst_ports": int(dp.nunique()),
                          "top_dst_ports": {str(int(k)): int(v) for k, v in dp.value_counts().head(6).items()},
                          "share_dst_port_ge_1024": round(float((dp >= 1024).mean()), 3),
                          "row_position_first_last": [round(float(rows.min() / n_file), 3), round(float(rows.max() / n_file), 3)],
                          "row_position_histogram_20_bins": position_profile(rows, n_file)}
        rep[fname] = sub
    # flow shape: Port-Scan-predicted FPs vs correctly classified Thursday benign vs Friday Port Scan training rows
    scan_tr = (meta["raw"] == "portscan").to_numpy()
    Xs, Xt, Xp = X[ps["index"].to_numpy()], X[tn["index"].to_numpy()], X[scan_tr]
    rep["shape_fp_port_scan"] = describe(Xs, SHAPE)
    rep["shape_thursday_benign_correct"] = describe(Xt, SHAPE)
    rep["shape_portscan_training"] = describe(Xp, SHAPE)
    rep["ks_fp_port_scan_vs_portscan_training"] = {n: round(float(ks_2samp(Xs[:, FEATURE_NAMES.index(n)], Xp[:, FEATURE_NAMES.index(n)]).statistic), 3) for n in SHAPE}
    rep["ks_fp_port_scan_vs_thursday_benign_correct"] = {n: round(float(ks_2samp(Xs[:, FEATURE_NAMES.index(n)], Xt[:, FEATURE_NAMES.index(n)]).statistic), 3) for n in SHAPE}
    rep["fp_port_scan_p_attack_q"] = {q: round(float(ps["p_attack"].quantile(q)), 3) for q in (0.1, 0.5, 0.9)}
    # are the Port-Scan-predicted FPs a few repeated flows or many distinct ones?
    shape_cols = [FEATURE_NAMES.index(n) for n in ("total_fwd_packets", "total_bwd_packets", "init_win_bytes_forward", "init_win_bytes_backward")]
    rep["fp_port_scan_distinct_vectors"] = int(np.unique(Xs, axis=0).shape[0])
    rep["fp_port_scan_distinct_shapes"] = int(np.unique(Xs[:, shape_cols], axis=0).shape[0])
    rep["fp_port_scan_top_shapes"] = {str(tuple(int(v) for v in k)): int(c) for k, c in pd.Series([tuple(r) for r in Xs[:, shape_cols]]).value_counts().head(5).items()}
    rep["raw_probe_signature_by_file"] = signature_by_file(Path(args.data17))
    out = Path(args.run) / f"thursday_fp_{args.candidate}.json"
    out.write_text(json.dumps(rep, indent=1, default=str), encoding="utf-8")
    print(json.dumps(rep, indent=1, default=str))


if __name__ == "__main__":
    main()
