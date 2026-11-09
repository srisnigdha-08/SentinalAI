"""
Independent check of the 2017-Thursday probe-flow labels (audit/LABEL_VERIFICATION_PLAN.md). Read-only: nothing is
fitted, nothing is relabelled. It joins the MachineLearningCVE Thursday-afternoon file used by every experiment to
the CIC "GeneratedLabelledFlows" file of the same capture (which has Source/Destination IP and Timestamp) and applies
the pre-registered decision rule below to the probe-signature rows (thursday_fp_2017.probe_signature).

Pre-registered rule (fixed 2026-11-02, before the GeneratedLabelledFlows file was obtained or read):
  The rows are VERIFIED as the dataset authors' scheduled port scan if, among the signature rows that join,
    (a) >= 95 % have 192.168.10.8 (the Windows Vista victim turned attacker) as Source or Destination IP,
    (b) >= 95 % have a timestamp within 15:04-15:45 on 6 July 2017, widened by 5 minutes on each side
        (15:00-15:50; 12-hour times without AM/PM are read as afternoon), and
    (c) the other endpoints cover >= 3 distinct 192.168.10.x hosts (the schedule says "all other clients").
  Otherwise NOT VERIFIED. The join itself must succeed for >= 99 % of the MachineLearningCVE rows, or the check is
  INCONCLUSIVE. Row-level results are reported for every row (which rows meet all three), whatever the verdict.

  .venv/Scripts/python evaluation/verify_labels_2017.py --labelled PATH\\Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv
"""
import argparse, hashlib, json, sys
from datetime import datetime, time
from pathlib import Path

import numpy as np
import pandas as pd

ENGINE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ENGINE))
from evaluation.thursday_fp_2017 import probe_signature  # noqa: E402

ML_FILE = "Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv"
SCANNER = "192.168.10.8"
WINDOW = (time(15, 0), time(15, 50))  # schedule 15:04-15:45, +-5 min
THRESHOLD, MIN_HOSTS, MIN_JOIN = 0.95, 3, 0.99
JOIN_COLS = ["Destination Port", "Flow Duration", "Total Fwd Packets", "Total Backward Packets", "Init_Win_bytes_forward",
             "Init_Win_bytes_backward", "Total Length of Fwd Packets", "Label"]


def read(path: Path) -> pd.DataFrame:
    df = pd.read_csv(path, encoding="latin-1", low_memory=False)
    df.columns = df.columns.str.strip()
    return df.dropna(how="all")


def afternoon_time(ts: pd.Series) -> pd.Series:
    """Time of day from CIC timestamps ('6/7/2017 3:04' or '06/07/2017 03:04:05 PM'); hours 1-7 read as afternoon."""
    t = pd.to_datetime(ts.astype(str).str.strip(), dayfirst=True, errors="coerce", format="mixed")
    hour = t.dt.hour.where(t.dt.hour >= 8, t.dt.hour + 12)
    return pd.Series([time(int(h), int(m)) if pd.notna(h) else None for h, m in zip(hour, t.dt.minute)], index=ts.index)


def join_rows(ml: pd.DataFrame, gl: pd.DataFrame):
    """Row-aligned join when the files have the same length and agree on JOIN_COLS; else None."""
    if len(ml) != len(gl):
        return None, 0.0
    agree = np.ones(len(ml), dtype=bool)
    for c in JOIN_COLS:  # numbers compared as numbers (one file writes 48, the other 48.0); text stripped
        a, b = ml[c].reset_index(drop=True), gl[c].reset_index(drop=True)
        if pd.api.types.is_numeric_dtype(a) and pd.api.types.is_numeric_dtype(b):
            agree &= np.isclose(a.to_numpy(float), b.to_numpy(float), rtol=0, atol=1e-9, equal_nan=True)
        else:
            agree &= (a.astype(str).str.strip() == b.astype(str).str.strip()).to_numpy()
    return agree, float(agree.mean())


def meets_all(rows: pd.DataFrame) -> pd.Series:
    """Per row: scanner IP on either side and timestamp inside the window (conditions a and b; c is a set property)."""
    ip = (rows["Source IP"].astype(str).str.strip() == SCANNER) | (rows["Destination IP"].astype(str).str.strip() == SCANNER)
    in_window = afternoon_time(rows["Timestamp"]).map(lambda v: v is not None and WINDOW[0] <= v <= WINDOW[1])
    return ip & in_window.astype(bool)


def decide(rows: pd.DataFrame) -> dict:
    ip = (rows["Source IP"].astype(str).str.strip() == SCANNER) | (rows["Destination IP"].astype(str).str.strip() == SCANNER)
    t = afternoon_time(rows["Timestamp"])
    in_window = t.map(lambda v: v is not None and WINDOW[0] <= v <= WINDOW[1])
    other = np.where(rows["Source IP"].astype(str).str.strip() == SCANNER, rows["Destination IP"], rows["Source IP"])
    other = pd.Series(other).astype(str).str.strip()
    hosts = other[ip.to_numpy() & other.str.startswith("192.168.10.").to_numpy()].nunique()
    a, b = float(ip.mean()), float(in_window.mean())
    verdict = "VERIFIED" if a >= THRESHOLD and b >= THRESHOLD and hosts >= MIN_HOSTS else "NOT VERIFIED"
    return {"verdict": verdict, "rows": int(len(rows)), "share_scanner_ip": round(a, 4), "share_in_window": round(b, 4),
            "distinct_internal_peers": int(hosts), "rows_meeting_all": int((ip & in_window).sum()),
            "source_ip_top": rows["Source IP"].astype(str).str.strip().value_counts().head(5).to_dict(),
            "destination_ip_top": rows["Destination IP"].astype(str).str.strip().value_counts().head(5).to_dict(),
            "time_range": [str(min((v for v in t if v), default=None)), str(max((v for v in t if v), default=None))]}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--labelled", required=True, help="GeneratedLabelledFlows Thursday-afternoon CSV (obtained by the owner)")
    ap.add_argument("--data17", default=str(ENGINE / "datasets" / "cicids2017"))
    ap.add_argument("--out", default=str(ENGINE / "experiments" / f"label_verification_{datetime.now():%Y%m%d}"))
    args = ap.parse_args()
    ml, gl = read(Path(args.data17) / ML_FILE), read(Path(args.labelled))
    agree, rate = join_rows(ml, gl)
    rep = {"ml_rows": int(len(ml)), "labelled_rows": int(len(gl)), "join_agreement": round(rate, 6),
           "rule": {"scanner": SCANNER, "window": [str(WINDOW[0]), str(WINDOW[1])], "threshold": THRESHOLD,
                    "min_internal_peers": MIN_HOSTS, "min_join": MIN_JOIN}}
    if agree is None or rate < MIN_JOIN:
        rep["verdict"] = "INCONCLUSIVE (files do not align row for row)"
    else:
        sig = probe_signature(ml).to_numpy() & agree
        rep["signature"] = decide(gl[sig])
        rep["verdict"] = rep["signature"]["verdict"]
        if rep["verdict"] == "VERIFIED":  # the frozen correction list for protocol v3: row positions in ML_FILE
            rows = gl[sig].index[meets_all(gl[sig]).to_numpy()]
            out = Path(args.out)
            out.mkdir(parents=True, exist_ok=True)
            body = "row\n" + "".join(f"{int(r)}\n" for r in rows)
            (out / "thursday_scan_rows.csv").write_text(body, encoding="utf-8", newline="\n")
            rep["correction"] = {"file": ML_FILE, "rows": int(len(rows)), "sha256": hashlib.sha256(body.encode()).hexdigest()}
        inf = gl[gl["Label"].astype(str).str.strip() == "Infiltration"]
        rep["infiltration_labelled_rows"] = {"rows": int(len(inf)), "source_ip_top": inf["Source IP"].astype(str).str.strip().value_counts().head(3).to_dict()}
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    (out / "thursday_label_verification.json").write_text(json.dumps(rep, indent=2, default=str), encoding="utf-8")
    print(json.dumps(rep, indent=1, default=str))


if __name__ == "__main__":
    main()
