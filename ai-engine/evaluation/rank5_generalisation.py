#!/usr/bin/env python3
"""
Rank 5: generalisation evidence for the FROZEN served network-flow model (xgb_cicids_v1). Evaluation only.

Nothing is trained, fitted on test data, saved into models/, promoted or reloaded into the running engine. The model
files are hash-checked against models/registry.json before and after the run, loaded through SentinelPredictor (which
also runs the golden-set check) and scored with the served code path:
  * features: utils.features.prepare_features (the training path); a sample of every file is ALSO scored through
    SentinelPredictor.predict(record) -> extract_features_from_record + _assemble (the production request path) and
    must agree, so the vectorised path is proven to be the production path for these inputs;
  * scores: evaluation.p5_served_model_eval.served_scores (classifier + Isolation Forest + combine_threat_score + the
    Unknown/REVIEW override), at the served alert / block lines.

Three evaluation sets, never pooled into one headline number:
  E1  random split    the model's own held-out 20 % (stratified random, random_state 42), rebuilt by P5's loader and
                      refused unless every count equals the model meta. Same capture days and attack episodes as
                      training: in-distribution, NOT independent.
  E2  2017 unseen     CICIDS2017 rows that were never in the training pool (excluded by the training caps) and whose
                      feature vector does not occur anywhere in the pool. Same days, same episodes: in-distribution,
                      NOT independent, but large and per-day.
  E3  2018 later      the six CSE-CIC-IDS2018 development days (Feb-Mar 2018, another network and CICFlowMeter build),
                      every row. Never used to train this model or choose its lines. Chronologically later and from a
                      different environment; it has been used in earlier development protocols for OTHER candidates.
The four protected 2018 days (evaluation.protected_data) are never opened: every path passes assert_permitted().

Leakage checks: exact feature-vector overlap E1-test/train, E2/pool, E3/pool (64-bit row hashes); within-set
duplication with de-duplicated sensitivity metrics; timestamp range of every 2018 file vs the 2017 training days;
feature-name contract; time-of-day columns constant; no IP / port / timestamp column among the features.

Drift: Population Stability Index (reference-quantile bins) and two-sample Kolmogorov-Smirnov per feature, training
rows vs every 2018 day (all rows and benign rows, deterministic samples), plus per-day prediction and score mixes.

  .venv/Scripts/python evaluation/rank5_generalisation.py                    # full run (about 20-40 min)
  .venv/Scripts/python evaluation/rank5_generalisation.py --max-rows 20000   # quick smoke run (not evidence)

Outputs go to a NEW directory audit/rank5_network_flow_generalisation/run_<UTC timestamp>/ (never overwritten).
"""
import argparse
import hashlib
import json
import math
import os
import platform
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import numpy as np
import pandas as pd

ENGINE = Path(__file__).resolve().parent.parent
REPO = ENGINE.parent
sys.path.insert(0, str(ENGINE))

SEED = 20261114
RANK5_VERSION = "rank5/1"
DEFAULT_OUT = REPO / "audit" / "rank5_network_flow_generalisation"
DATA_2017 = ENGINE / "datasets" / "cicids2017"
DATA_2018 = Path(os.getenv("SENTINEL_2018_DEV_DIR", "D:/sentinelai_datasets/cse_cic_ids2018"))
# Published CICIDS2017 capture schedule (the MachineLearningCVE CSVs carry no timestamp column)
DAYS_2017 = {"Monday": "2017-07-03", "Tuesday": "2017-07-04", "Wednesday": "2017-07-05", "Thursday": "2017-07-06",
             "Friday": "2017-07-07"}
MIN_SUPPORT = 30          # below this a per-class metric is reported but flagged unreliable
DRIFT_SAMPLE = 20000      # rows per 2018 day used for KS / PSI (deterministic)
MIN_DRIFT_ROWS = 500      # fewer rows than this -> INSUFFICIENT_DATA for that comparison
PARITY_SAMPLE = 150       # rows per file scored through the production request path


# ── pure helpers (unit-tested with synthetic data) ────────────────────────────────────────────────────────────────
class IntegrityError(RuntimeError):
    pass


def sha256_file(path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def verify_artifacts(model_dir, expected_version="xgb_cicids_v1") -> dict:
    """Registry entries vs files on disk. Raises IntegrityError on any mismatch (no repair, no fallback)."""
    model_dir = Path(model_dir)
    reg = json.loads((model_dir / "registry.json").read_text(encoding="utf-8"))
    out = {"registry_sha256": sha256_file(model_dir / "registry.json"), "entries": {}}
    for role in ("classifier", "anomaly", "golden"):
        entry = reg.get(role)
        if not entry:
            raise IntegrityError(f"registry has no {role} entry")
        f = model_dir / entry["file"]
        if not f.is_file():
            raise IntegrityError(f"{role} file missing: {entry['file']}")
        actual = sha256_file(f)
        out["entries"][role] = {"file": entry["file"], "registry_sha256": entry["sha256"], "actual_sha256": actual,
                                "version": entry.get("version")}
        if actual != entry["sha256"]:
            raise IntegrityError(f"{role} sha256 mismatch ({entry['file']})")
    version = reg["classifier"].get("version")
    if version != expected_version:
        raise IntegrityError(f"registered classifier is {version!r}, expected {expected_version!r}")
    out["version"] = version
    return out


def validate_feature_matrix(X, names, expected_names) -> list:
    """Problems with a feature matrix against the served contract (empty list = valid)."""
    problems = []
    if list(names) != list(expected_names):
        missing = [n for n in expected_names if n not in names]
        extra = [n for n in names if n not in expected_names]
        problems.append({"check": "feature_names", "missing": missing, "unexpected": extra,
                         "order_differs": not missing and not extra})
    X = np.asarray(X)
    if X.ndim != 2 or X.shape[1] != len(expected_names):
        problems.append({"check": "shape", "shape": list(X.shape), "expected_columns": len(expected_names)})
    elif not np.isfinite(X).all():
        problems.append({"check": "finite", "non_finite_rows": int((~np.isfinite(X)).any(axis=1).sum())})
    return problems


def row_hashes(X) -> np.ndarray:
    """64-bit hash of every row's exact float64 values (collision probability negligible at these sizes)."""
    df = pd.DataFrame(np.ascontiguousarray(np.asarray(X, dtype=np.float64)))
    return pd.util.hash_pandas_object(df, index=False).to_numpy(dtype=np.uint64)


def overlap_mask(hashes, reference_hashes) -> np.ndarray:
    """True where a row's exact feature vector occurs in the reference set."""
    return np.isin(np.asarray(hashes, dtype=np.uint64), np.asarray(reference_hashes, dtype=np.uint64))


def first_occurrence_mask(hashes, labels=None) -> np.ndarray:
    """True for the first occurrence of every (vector[, label]) - the de-duplicated sensitivity subset."""
    h = np.asarray(hashes, dtype=np.uint64)
    if labels is not None:
        h = h ^ (np.asarray(labels, dtype=np.uint64) * np.uint64(0x9E3779B97F4A7C15))
    _, first = np.unique(h, return_index=True)
    m = np.zeros(len(h), dtype=bool)
    m[first] = True
    return m


def wilson(k, n, z=1.96):
    if not n:
        return None
    p = k / n
    d = 1 + z * z / n
    c = p + z * z / (2 * n)
    r = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n))
    return [round((c - r) / d, 6), round((c + r) / d, 6)]


def _auc(y_bin, s):
    """(roc_auc, pr_auc) for a binary target, or (None, None, reason) when undefined."""
    y_bin = np.asarray(y_bin, dtype=bool)
    if y_bin.all() or (~y_bin).all():
        return None, None, "only one of benign / attack present"
    from sklearn.metrics import average_precision_score, roc_auc_score
    return round(float(roc_auc_score(y_bin, s)), 6), round(float(average_precision_score(y_bin, s)), 6), None


def classification_metrics(y_true, y_pred, class_names, p_attack=None, flagged=None, benign=0) -> dict:
    """Multiclass + attack-vs-benign metrics with supports. Macro averages are over the classes PRESENT in y_true
    (a class with no test rows has no recall); classes predicted but absent are listed separately."""
    y_true = np.asarray(y_true, dtype=int)
    y_pred = np.asarray(y_pred, dtype=int)
    n = int(len(y_true))
    out = {"n": n}
    if n == 0:
        out["status"] = "INSUFFICIENT_DATA"
        out["reason"] = "no rows"
        return out
    present = sorted(set(y_true.tolist()))
    labels = sorted(set(present) | set(y_pred.tolist()))
    idx = {c: i for i, c in enumerate(labels)}
    lut = np.full(max(labels) + 1, -1, dtype=np.int64)
    lut[labels] = np.arange(len(labels))
    cm = np.zeros((len(labels), len(labels)), dtype=np.int64)
    np.add.at(cm, (lut[y_true], lut[y_pred]), 1)
    per = {}
    for c in labels:
        i = idx[c]
        tp = int(cm[i, i])
        support = int(cm[i].sum())
        predicted = int(cm[:, i].sum())
        prec = tp / predicted if predicted else None
        rec = tp / support if support else None
        f1 = (2 * prec * rec / (prec + rec) if prec and rec else 0.0) if prec is not None and rec is not None else None
        per[class_names[c]] = {"support": support, "predicted": predicted, "tp": tp,
                               "precision": None if prec is None else round(prec, 6),
                               "recall": None if rec is None else round(rec, 6),
                               "f1": None if f1 is None else round(f1, 6),
                               "recall_wilson95": wilson(tp, support),
                               "reliable": support >= MIN_SUPPORT}
    pres = [per[class_names[c]] for c in present]
    out.update({
        "class_distribution": {class_names[c]: int((y_true == c).sum()) for c in present},
        "accuracy": round(float((y_true == y_pred).mean()), 6),
        "balanced_accuracy": round(float(np.mean([p["recall"] for p in pres])), 6),
        "precision_macro": round(float(np.mean([p["precision"] or 0.0 for p in pres])), 6),
        "recall_macro": round(float(np.mean([p["recall"] for p in pres])), 6),
        "f1_macro": round(float(np.mean([p["f1"] or 0.0 for p in pres])), 6),
        "f1_weighted": round(float(sum((p["f1"] or 0.0) * p["support"] for p in pres) / n), 6),
        "macro_over_classes": [class_names[c] for c in present],
        "predicted_but_absent": [class_names[c] for c in labels if c not in present],
        "per_class": per,
        "confusion_matrix": {"labels": [class_names[c] for c in labels], "rows_true_cols_pred": cm.tolist()},
    })
    attack = y_true != benign
    pred_attack = (y_pred != benign) if flagged is None else np.asarray(flagged, dtype=bool)
    nb, na = int((~attack).sum()), int(attack.sum())
    fp, fn = int((pred_attack & ~attack).sum()), int((~pred_attack & attack).sum())
    binary = {"benign": nb, "attack": na, "fp": fp, "fn": fn,
              "fpr": round(fp / nb, 6) if nb else None, "fpr_wilson95": wilson(fp, nb),
              "fnr": round(fn / na, 6) if na else None, "fnr_wilson95": wilson(fn, na),
              "attack_recall": round(1 - fn / na, 6) if na else None}
    if p_attack is not None:
        roc, pr, why = _auc(attack, np.asarray(p_attack, dtype=float))
        binary.update({"roc_auc": roc, "pr_auc": pr, "auc_not_computed_because": why})
    out["binary"] = binary
    return out


def majority_baseline(y_true, class_names) -> dict:
    """Always predict the most common class of THESE labels (an upper bound for a trivial baseline)."""
    y_true = np.asarray(y_true, dtype=int)
    if not len(y_true):
        return {"n": 0, "status": "INSUFFICIENT_DATA"}
    vals, counts = np.unique(y_true, return_counts=True)
    maj = int(vals[np.argmax(counts)])
    m = classification_metrics(y_true, np.full(len(y_true), maj), class_names)
    return {"predicts": class_names[maj], "accuracy": m["accuracy"], "balanced_accuracy": m["balanced_accuracy"],
            "f1_macro": m["f1_macro"], "n": m["n"]}


def group_rows(groups, y_true, y_pred, class_names, p_attack=None, flagged=None) -> list:
    """One flat metrics row per group (e.g. capture day), with supports."""
    groups = np.asarray(groups)
    rows = []
    for g in sorted(set(groups.tolist())):
        m = groups == g
        r = classification_metrics(np.asarray(y_true)[m], np.asarray(y_pred)[m], class_names,
                                   None if p_attack is None else np.asarray(p_attack)[m],
                                   None if flagged is None else np.asarray(flagged)[m])
        b = r.get("binary", {})
        rows.append({"group": g, "n": r["n"], "benign": b.get("benign"), "attack": b.get("attack"),
                     "accuracy": r.get("accuracy"), "balanced_accuracy": r.get("balanced_accuracy"),
                     "f1_macro": r.get("f1_macro"), "fpr": b.get("fpr"), "fnr": b.get("fnr"),
                     "roc_auc": b.get("roc_auc"), "pr_auc": b.get("pr_auc"),
                     "class_support": json.dumps(r.get("class_distribution", {}), sort_keys=True)})
    return rows


def psi(reference, current, bins=10, eps=1e-6):
    """Population Stability Index with bins at the reference quantiles. None when the reference is constant."""
    ref = np.asarray(reference, dtype=float)
    cur = np.asarray(current, dtype=float)
    edges = np.unique(np.quantile(ref, np.linspace(0, 1, bins + 1)))
    if len(edges) < 2:
        return None
    inner = edges[1:-1]
    r = np.bincount(np.searchsorted(inner, ref, side="right"), minlength=len(inner) + 1) / len(ref)
    c = np.bincount(np.searchsorted(inner, cur, side="right"), minlength=len(inner) + 1) / len(cur)
    r, c = np.clip(r, eps, None), np.clip(c, eps, None)
    return round(float(np.sum((c - r) * np.log(c / r))), 6)


def psi_band(v):
    if v is None:
        return "constant_reference"
    return "large" if v >= 0.25 else "moderate" if v >= 0.10 else "small"


def ks(reference, current):
    from scipy.stats import ks_2samp
    r = ks_2samp(np.asarray(reference, dtype=float), np.asarray(current, dtype=float))
    return round(float(r.statistic), 6), float(r.pvalue)


def drift_compare(ref_X, cur_X, names, min_rows=MIN_DRIFT_ROWS) -> dict:
    """Per-feature PSI and KS between two samples. INSUFFICIENT_DATA when either side is too small."""
    ref_X, cur_X = np.asarray(ref_X, dtype=float), np.asarray(cur_X, dtype=float)
    if len(ref_X) < min_rows or len(cur_X) < min_rows:
        return {"status": "INSUFFICIENT_DATA", "reference_rows": int(len(ref_X)), "current_rows": int(len(cur_X)),
                "min_rows": min_rows}
    feats = {}
    for j, name in enumerate(names):
        p = psi(ref_X[:, j], cur_X[:, j])
        if p is None and np.unique(cur_X[:, j]).size == 1:
            feats[name] = {"psi": None, "band": "constant_both", "ks": 0.0}
            continue
        k, _pv = ks(ref_X[:, j], cur_X[:, j])
        feats[name] = {"psi": p, "band": psi_band(p), "ks": k}
    bands = [f["band"] for f in feats.values()]
    ranked = sorted(((n, f) for n, f in feats.items() if f["psi"] is not None), key=lambda kv: -kv[1]["psi"])
    return {"status": "OK", "reference_rows": int(len(ref_X)), "current_rows": int(len(cur_X)),
            "features_large_psi": bands.count("large"), "features_moderate_psi": bands.count("moderate"),
            "features_small_psi": bands.count("small"),
            "features_constant": bands.count("constant_reference") + bands.count("constant_both"),
            "median_ks": round(float(np.median([f["ks"] for f in feats.values()])), 6),
            "top_psi": [{"feature": n, **f} for n, f in ranked[:10]], "per_feature": feats}


def rank5_status(evidence: dict) -> dict:
    """Machine-readable status. Infrastructure readiness is kept apart from generalisation evidence: a working
    evaluator never makes generalisation VERIFIED; only a clean independent holdout with acceptable results could."""
    integrity_ok = bool(evidence.get("integrity_before_ok")) and bool(evidence.get("integrity_after_ok"))
    e3 = evidence.get("e3") or {}
    e3_ok = e3.get("status") == "OK"
    status = {
        "evaluation_tooling": "READY" if integrity_ok and evidence.get("parity_ok") else "FAILED",
        "model_integrity": "READY" if integrity_ok else "FAILED",
        "dataset_provenance": "READY" if evidence.get("provenance_ok") else "LIMITED",
        "random_split_reproduced": "READY" if evidence.get("e1_reproduced") else "FAILED",
        "chronological_evaluation": "LIMITED" if e3_ok else "INSUFFICIENT_DATA",
        "leakage_checks": evidence.get("leakage_assessment", "NOT_VERIFIED"),
        "drift_diagnostics": "READY" if evidence.get("drift_ok") else "INSUFFICIENT_DATA",
        # No holdout here satisfies all of: never used in development, untouched by any decision, same label
        # semantics. The protected 2018 days are the registered candidate and remain sealed.
        "independent_generalisation": "NOT_VERIFIED",
    }
    if e3_ok and e3.get("macro_f1") is not None and e3["macro_f1"] < 0.5:
        status["generalisation_finding"] = "POOR_ON_LATER_DIFFERENT_NETWORK"
    elif e3_ok:
        status["generalisation_finding"] = "LIMITED_EVIDENCE"
    else:
        status["generalisation_finding"] = "INSUFFICIENT_DATA"
    return status


def new_run_dir(base: Path, stamp: str) -> Path:
    """A fresh directory; an existing one is never reused or overwritten."""
    base = Path(base)
    base.mkdir(parents=True, exist_ok=True)
    d = base / f"run_{stamp}"
    n = 1
    while d.exists():
        d = base / f"run_{stamp}_{n}"
        n += 1
    d.mkdir()
    return d


def write_json(path: Path, obj):
    if path.exists():
        raise FileExistsError(path)
    path.write_text(json.dumps(obj, indent=1, default=_json_default), encoding="utf-8")


def write_csv(path: Path, rows: list):
    if path.exists():
        raise FileExistsError(path)
    pd.DataFrame(rows).to_csv(path, index=False)


def _json_default(o):
    if isinstance(o, (np.integer,)):
        return int(o)
    if isinstance(o, (np.floating,)):
        return float(o)
    if isinstance(o, np.ndarray):
        return o.tolist()
    raise TypeError(type(o))


# ── data access (read-only) ──────────────────────────────────────────────────────────────────────────────────────
def day_of_2017(file_name: str) -> str:
    for k, v in DAYS_2017.items():
        if file_name.lower().startswith(k.lower()):
            return v
    raise ValueError(f"cannot date {file_name}")


def clean_cicids_file(csv_file: Path) -> pd.DataFrame:
    """The per-file cleaning of p5_served_model_eval.load_cicids_dir (= train.py), before any sampling: same column
    selection, numeric coercion, inf -> NaN and NaN-row drop. The index is the CSV row position, which is what
    load_cicids_dir(keep_source=True) records as _row, so pool membership can be checked row by row. The run
    verifies that every pool row is found here with identical feature values."""
    from utils.features import CANDIDATES, RAW_LABEL_TO_TARGET
    header_df = pd.read_csv(csv_file, nrows=1)
    needed_cols = ["label", "Label", "target_class"]
    for _fn, cands in CANDIDATES.items():
        needed_cols.extend(cands)
    cols_to_use = []
    for cand in needed_cols:
        matched = False
        for h_col in header_df.columns:
            if cand == h_col.strip():
                cols_to_use.append(h_col)
                matched = True
                break
        if not matched:
            cand_lower = cand.lower().replace("_", "").replace(" ", "").replace("/", "")
            for h_col in header_df.columns:
                if h_col.strip().lower().replace("_", "").replace(" ", "").replace("/", "") == cand_lower:
                    cols_to_use.append(h_col)
                    break
    cols_to_use = list(set(cols_to_use))
    file_df = pd.read_csv(csv_file, usecols=cols_to_use)
    file_df.columns = file_df.columns.str.strip()
    label_col = next((c for c in file_df.columns if c.lower() == "label"), "Label")
    file_df["label"] = file_df[label_col].astype(str).str.strip()
    if label_col != "label" and label_col in file_df.columns:
        file_df = file_df.drop(columns=[label_col])
    file_df["target_class"] = file_df["label"].map(lambda x: RAW_LABEL_TO_TARGET.get(x, x))
    feature_cols = [c for c in file_df.columns if c.lower() != "label" and c != "target_class"]
    for col in feature_cols:
        file_df[col] = pd.to_numeric(file_df[col], errors="coerce")
    return file_df.replace([float("inf"), float("-inf")], float("nan")).dropna(subset=feature_cols)


def iter_2018_chunks(path: Path, chunksize=200_000, max_rows=None):
    """Chunks of one 2018 development day mapped onto the served feature names, cleaned exactly like
    evaluation.dev_experiments.load_2018_file (non-finite mapped value -> row dropped, repeated header lines dropped),
    but in float64 and streamed. Timestamp, IPs and ports are never read here."""
    from evaluation import taxonomies
    from evaluation.dev_experiments import _mapping_2018
    from evaluation.protected_data import assert_permitted
    assert_permitted(path)
    rename = _mapping_2018()
    header = pd.read_csv(path, nrows=0).columns.str.strip()
    use = [c for c in header if c in rename] + ["Label"]
    seen = 0
    for chunk in pd.read_csv(path, usecols=lambda c: c.strip() in use, chunksize=chunksize, low_memory=False):
        chunk.columns = chunk.columns.str.strip()
        chunk = chunk[chunk["Label"].astype(str).str.strip() != "Label"]
        feats = chunk.drop(columns=["Label"]).apply(pd.to_numeric, errors="coerce").astype("float64")
        feats = feats.replace([np.inf, -np.inf], np.nan)
        ok = feats.notna().all(axis=1).to_numpy()
        part = feats[ok].rename(columns=rename)
        raw = [taxonomies.norm(v) for v in chunk["Label"].to_numpy()[ok]]
        dropped = int((~ok).sum())
        if max_rows is not None:
            take = max(0, min(len(part), max_rows - seen))
            part, raw = part.iloc[:take], raw[:take]
        seen += len(part)
        yield part, raw, dropped, len(chunk)
        if max_rows is not None and seen >= max_rows:
            return


def timestamp_range_2018(path: Path, chunksize=500_000) -> dict:
    """Read ONLY the Timestamp column: min / max / unparseable count / rows per calendar date."""
    from evaluation.protected_data import assert_permitted
    assert_permitted(path)
    lo, hi, bad, n, dates = None, None, 0, 0, {}
    for chunk in pd.read_csv(path, usecols=lambda c: c.strip() == "Timestamp", chunksize=chunksize, low_memory=False):
        s = chunk.iloc[:, 0].astype(str)
        s = s[s.str.strip() != "Timestamp"]
        t = pd.to_datetime(s, format="%d/%m/%Y %H:%M:%S", errors="coerce")
        n += len(t)
        bad += int(t.isna().sum())
        t = t.dropna()
        if len(t):
            lo = t.min() if lo is None else min(lo, t.min())
            hi = t.max() if hi is None else max(hi, t.max())
            for d, c in t.dt.strftime("%Y-%m-%d").value_counts().items():
                dates[d] = dates.get(d, 0) + int(c)
    return {"rows": n, "invalid": bad, "min": None if lo is None else lo.isoformat(),
            "max": None if hi is None else hi.isoformat(), "dates": sorted(dates), "rows_per_date": dict(sorted(dates.items()))}


EXCEL_ROW_LIMIT = 1_048_575  # data rows in a sheet saved by a spreadsheet program (1,048,576 incl. the header)
TRAINING_LAST_DAY = "2017-07-07"
IMPLAUSIBLE_BEFORE = "2000-01-01"  # clock artefacts (e.g. 1970 epoch dates), not real capture dates


def chronology_check(prov18: dict) -> dict:
    """Every plausibly dated row of every 2018 file must fall after the last 2017 training day. Rows dated before
    2000 are clock artefacts: counted and reported, not treated as evidence either way."""
    if not prov18 or any("rows_per_date" not in v.get("timestamps", {}) for v in prov18.values()):
        return {"check": "E3 chronologically after every training row", "result": "NOT_CHECKED",
                "note": "timestamps not scanned (smoke run or no 2018 data)"}
    before, artefacts, per_file = 0, 0, {}
    for name, v in prov18.items():
        rpd = v["timestamps"]["rows_per_date"]
        art = sum(c for d, c in rpd.items() if d < IMPLAUSIBLE_BEFORE)
        early = sum(c for d, c in rpd.items() if IMPLAUSIBLE_BEFORE <= d <= TRAINING_LAST_DAY)
        before += early
        artefacts += art
        per_file[name] = {"implausible_dates": art, "dated_on_or_before_training": early,
                          "unparseable": v["timestamps"]["invalid"]}
    return {"check": "E3 chronologically after every training row", "result": "PASS" if before == 0 else "FAIL",
            "rows_dated_on_or_before_training": before, "rows_with_implausible_dates": artefacts,
            "per_file": per_file,
            "note": f"2017 training days 2017-07-03..{TRAINING_LAST_DAY} (published schedule; file names). Rows dated "
                    f"before {IMPLAUSIBLE_BEFORE} are clock artefacts in the source CSV and are reported separately"}


def truncation_check(prov18: dict) -> dict:
    hits = {n: v["csv_rows"] for n, v in prov18.items() if v.get("csv_rows") == EXCEL_ROW_LIMIT}
    return {"check": "2018 files cut at the spreadsheet row limit", "result": "SUSPECTED" if hits else "NO",
            "files": hits, "note": f"exactly {EXCEL_ROW_LIMIT:,} data rows suggests the published CSV was saved by a "
                                   "spreadsheet program and later flows of that day are missing; metrics cover only "
                                   "the rows present"}


# ── the run ──────────────────────────────────────────────────────────────────────────────────────────────────────
def _served(pred, X):
    from evaluation.p5_served_model_eval import served_scores
    labels, proba, score, action, unknown, _if = served_scores(pred, X)
    from inference import predictor as P
    p_attack = 1.0 - proba[:, 0]
    alert = (labels != 0) & (score >= P.MONITOR_THRESHOLD)
    return labels.astype(np.int16), p_attack.astype(np.float32), score.astype(np.float32), alert, action


def _parity(pred, raw_rows: pd.DataFrame, X, labels, score, rng) -> dict:
    """Score a sample through SentinelPredictor.predict(record) (production request path) and compare."""
    from utils.features import LABEL_NAMES
    k = min(PARITY_SAMPLE, len(raw_rows))
    if k == 0:
        return {"checked": 0, "mismatches": 0}
    idx = np.sort(rng.choice(len(raw_rows), size=k, replace=False))
    mism = 0
    for i in idx:
        rec = {c: (float(v) if isinstance(v, (int, float, np.integer, np.floating)) else v)
               for c, v in raw_rows.iloc[int(i)].items() if c not in ("label", "target_class", "Label")}
        r = pred.predict(rec)
        want = LABEL_NAMES[int(labels[i])]
        cls = r["predictedClass"]
        same_cls = cls == want or (cls == "Unknown" and want == "BENIGN")
        if not same_cls or abs(float(r["threatScore"]) - float(score[i])) > 1e-4:
            mism += 1
    return {"checked": int(k), "mismatches": int(mism)}


def run(args) -> Path:
    from evaluation.p5_served_model_eval import load_cicids_dir
    from evaluation.protected_data import PROTECTED_DAYS, permitted_files
    from evaluation import taxonomies
    from inference import predictor as P
    from sklearn.model_selection import train_test_split
    from training.train import drop_duplicate_rows
    from utils.features import FEATURE_NAMES, FEATURE_SCHEMA_VERSION, LABEL_MAP, LABEL_NAMES, prepare_features

    t_start = time.time()
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    rng = np.random.default_rng(SEED)
    model_dir = Path(args.model_dir)
    class_names = dict(LABEL_NAMES)
    notes, failed_checks = [], []

    # 1. integrity before
    integ_before = verify_artifacts(model_dir)
    meta = json.loads((model_dir / "xgb_classifier_xgb_cicids_v1_meta.json").read_text(encoding="utf-8"))
    thresholds = {"alert": P.MONITOR_THRESHOLD, "block": P.BLOCK_THRESHOLD, "anomaly": P.ANOMALY_THRESHOLD,
                  "review_min_signal": P.REVIEW_MIN_SIGNAL}
    if (P.MONITOR_THRESHOLD, P.BLOCK_THRESHOLD) != (0.90, 0.92):
        notes.append(f"operating lines overridden by environment: {thresholds}")
    pred = P.SentinelPredictor(model_dir=str(model_dir))
    pred.load()
    if not pred._loaded:
        raise IntegrityError("SentinelPredictor did not load the served models (registry / golden-set check)")
    contract = {"feature_schema_version": FEATURE_SCHEMA_VERSION, "feature_count": len(FEATURE_NAMES),
                "feature_names_sha256": hashlib.sha256(",".join(FEATURE_NAMES).encode()).hexdigest(),
                "model_meta_n_features": meta.get("n_features"), "label_map": LABEL_MAP}
    if len(FEATURE_NAMES) != 53 or meta.get("n_features") != 53:
        raise IntegrityError("feature contract is not the 53-feature schema")

    # 2. provenance of the 2017 training data
    data17 = Path(args.data_2017)
    prov17 = {}
    for name, h in meta["provenance"]["data_sha256"].items():
        f = data17 / name
        actual = sha256_file(f) if f.is_file() else None
        prov17[name] = {"recorded_sha256": h, "actual_sha256": actual, "match": actual == h, "day": day_of_2017(name)}
    provenance_ok = all(v["match"] for v in prov17.values())

    # 3. E1: rebuild the served split (refused unless it equals the meta)
    t0 = time.time()
    df = load_cicids_dir(data17, keep_source=True)
    src_file, src_row = df["_file"].to_numpy(), df["_row"].to_numpy()
    X_pool, y_pool = prepare_features(df.drop(columns=["_file", "_row"]), max_missing=0)
    del df
    X_pool = np.asarray(X_pool, dtype=np.float64)
    pool_hashes = row_hashes(X_pool)
    # The same rows drop_duplicate_rows keeps (it is called for the split itself below)
    Xd, yd, dedup = drop_duplicate_rows(X_pool, np.asarray(y_pool))
    rows = np.column_stack([X_pool, y_pool])
    _, first = np.unique(rows, axis=0, return_index=True)
    keep = np.sort(first)
    del rows
    if not np.array_equal(Xd, X_pool[keep]):
        raise IntegrityError("de-duplication order differs from training.train.drop_duplicate_rows")
    day_keep = np.array([day_of_2017(f) for f in src_file[keep]])
    idx_train, idx_test = train_test_split(np.arange(len(keep)), test_size=0.2, random_state=42, stratify=yd)
    y_train, y_test = yd[idx_train], yd[idx_test]
    counts = lambda a: {LABEL_NAMES[int(k)]: int(v) for k, v in zip(*np.unique(a, return_counts=True))}  # noqa: E731
    rebuilt = {"deduplication": dedup, "class_counts": {"train": counts(y_train), "test": counts(y_test)}}
    e1_reproduced = rebuilt == {"deduplication": meta["deduplication"], "class_counts": meta["class_counts"]}
    if not e1_reproduced:
        failed_checks.append("E1 split reconstruction differs from the model meta: E1 metrics withheld")
    X_train, X_test = Xd[idx_train], Xd[idx_test]
    train_hashes = row_hashes(X_train)
    test_hashes = row_hashes(X_test)
    e1 = {"protocol": "stratified random 80/20, random_state 42 (train.py), rebuilt and count-checked",
          "independent": False, "reproduced": e1_reproduced, "rebuild_seconds": round(time.time() - t0, 1),
          "train_rows": int(len(idx_train)), "test_rows": int(len(idx_test)),
          "training_class_counts": counts(y_train),
          "classes_without_training_rows": [n for k, n in LABEL_NAMES.items() if k not in set(y_train.tolist())],
          "test_rows_whose_vector_is_in_train": int(overlap_mask(test_hashes, train_hashes).sum())}
    per_day_rows = []
    if e1_reproduced:
        labels, p_att, score, alert, _ = _served(pred, X_test)
        e1["metrics_argmax"] = classification_metrics(y_test, labels, class_names, p_att)
        e1["metrics_alert_line"] = classification_metrics(y_test, labels, class_names, p_att, flagged=alert)["binary"]
        e1["majority_baseline"] = majority_baseline(y_test, class_names)
        e1["meta_recorded_metrics"] = meta.get("metrics")
        for r in group_rows(day_keep[idx_test], y_test, labels, class_names, p_att):
            per_day_rows.append({"set": "E1_random_split", **r})

    # 4. E2: 2017 rows never in the pool and whose vector is not in the pool
    pool_keys = set(zip(src_file.tolist(), src_row.tolist()))
    pool_set = np.unique(pool_hashes)
    e2_true, e2_pred, e2_patt, e2_alert, e2_day, e2_hash = [], [], [], [], [], []
    e2_files, parity = {}, {"checked": 0, "mismatches": 0}
    for f in sorted(data17.glob("*.csv")):
        cleaned = clean_cicids_file(f)
        in_pool = np.array([(f.name, int(r)) in pool_keys for r in cleaned.index], dtype=bool)
        # verify pool rows are identical in this cleaning (proves the copy matches the training loader)
        Xf, yf = prepare_features(cleaned, max_missing=0)
        Xf = np.asarray(Xf, dtype=np.float64)
        hf = row_hashes(Xf)
        pool_rows_found = int(in_pool.sum())
        expected_pool_rows = int(sum(1 for fl in src_file if fl == f.name))
        pool_match = pool_rows_found == expected_pool_rows and bool(np.isin(hf[in_pool], pool_set).all())
        unseen = ~in_pool & ~np.isin(hf, pool_set)
        if args.max_rows:
            unseen &= np.cumsum(unseen) <= args.max_rows
        Xu, yu = Xf[unseen], np.asarray(yf)[unseen]
        if len(Xu):
            labels, p_att, score, alert, _ = _served(pred, Xu)
        else:
            labels, p_att, alert = np.array([], np.int16), np.array([], np.float32), np.array([], bool)
        if len(Xu):
            pr = _parity(pred, cleaned[unseen].reset_index(drop=True), Xu, labels, score, rng)
            parity["checked"] += pr["checked"]
            parity["mismatches"] += pr["mismatches"]
        e2_files[f.name] = {"day": day_of_2017(f.name), "cleaned_rows": int(len(cleaned)), "pool_rows": pool_rows_found,
                            "pool_rows_identical": pool_match,
                            "excluded_vector_in_pool": int((~in_pool & np.isin(hf, pool_set)).sum()),
                            "evaluated_rows": int(len(Xu))}
        if not pool_match:
            failed_checks.append(f"E2: pool rows of {f.name} not reproduced by the per-file cleaning")
        e2_true.append(yu.astype(np.int16))
        e2_pred.append(labels)
        e2_patt.append(p_att)
        e2_alert.append(alert)
        e2_day.append(np.full(len(Xu), day_of_2017(f.name)))
        e2_hash.append(hf[unseen])
        del cleaned, Xf, Xu
    e2y, e2p = np.concatenate(e2_true), np.concatenate(e2_pred)
    e2pa, e2al, e2d, e2h = np.concatenate(e2_patt), np.concatenate(e2_alert), np.concatenate(e2_day), np.concatenate(e2_hash)
    e2_first = first_occurrence_mask(e2h, e2y)
    e2 = {"protocol": "CICIDS2017 rows never sampled into the training pool, minus any row whose exact vector is in the pool",
          "independent": False, "files": e2_files,
          "metrics_argmax": classification_metrics(e2y, e2p, class_names, e2pa),
          "metrics_alert_line": classification_metrics(e2y, e2p, class_names, e2pa, flagged=e2al)["binary"],
          "dedup_sensitivity": classification_metrics(e2y[e2_first], e2p[e2_first], class_names, e2pa[e2_first]),
          "unique_vector_label_rows": int(e2_first.sum()),
          "majority_baseline": majority_baseline(e2y, class_names),
          "classes_absent_note": "only classes the training caps sampled (BENIGN, Port Scan, DDoS) leave unseen rows; "
                                 "every row of every other class was in the training pool, so E2 cannot test them"}
    for r in group_rows(e2d, e2y, e2p, class_names, e2pa):
        per_day_rows.append({"set": "E2_2017_unseen_rows", **r})

    # 5. E3: 2018 development days (protected days never opened)
    data18 = Path(args.data_2018)
    e3 = {"status": "INSUFFICIENT_DATA", "reason": f"{data18} not found"}
    drift = {"reference": "E1 training rows (2017)", "method": {
        "psi": "10 bins at reference quantiles; bands: <0.10 small, 0.10-0.25 moderate, >=0.25 large (convention)",
        "ks": "two-sample Kolmogorov-Smirnov statistic (p-values are ~0 at these sample sizes and not reported)",
        "sample": f"up to {DRIFT_SAMPLE} rows per day, deterministic (seed {SEED})"}, "by_day": {}}
    prov18 = {}
    if data18.is_dir():
        files, skipped = permitted_files(data18)
        e3_true, e3_pred, e3_patt, e3_alert, e3_day, e3_hash = [], [], [], [], [], []
        ref_sample = X_train[rng.choice(len(X_train), size=min(len(X_train), DRIFT_SAMPLE), replace=False)]
        ben = np.flatnonzero(y_train == 0)
        ref_benign = X_train[rng.choice(ben, size=min(len(ben), DRIFT_SAMPLE), replace=False)]
        for f in files:
            date = f.name.split("_")[0].split("-", 1)[1]
            day = datetime.strptime(date, "%d-%m-%Y").strftime("%Y-%m-%d")
            ts = timestamp_range_2018(f) if not args.max_rows else {"skipped": "smoke run"}
            ys, ps, pas, als, hs, dropped, total, raws = [], [], [], [], [], 0, 0, set()
            drift_rows, drift_benign = [], []
            for part, raw, drop, n in iter_2018_chunks(f, max_rows=args.max_rows):
                total += n
                dropped += drop
                if not len(part):
                    continue
                raws |= set(raw)
                X, _ = prepare_features(part.assign(Label="BENIGN"), max_missing=0)
                X = np.asarray(X, dtype=np.float64)
                y = np.array([LABEL_MAP[c] for c in taxonomies.map_labels(raw, "T0")], dtype=np.int16)
                labels, p_att, score, alert, _ = _served(pred, X)
                if not ys:
                    pr = _parity(pred, part.reset_index(drop=True), X, labels, score, rng)
                    parity["checked"] += pr["checked"]
                    parity["mismatches"] += pr["mismatches"]
                ys.append(y)
                ps.append(labels)
                pas.append(p_att)
                als.append(alert)
                hs.append(row_hashes(X))
                take = rng.random(len(X)) < 0.05
                drift_rows.append(X[take])
                drift_benign.append(X[take & (y == 0)])
            y, p_, pa, al, h = map(np.concatenate, (ys, ps, pas, als, hs))
            in_pool = overlap_mask(h, pool_set)
            prov18[f.name] = {"sha256": sha256_file(f), "day": day, "csv_rows": total, "dropped_non_finite": dropped,
                              "evaluated_rows": int(len(y)), "raw_labels": sorted(raws), "timestamps": ts,
                              "vector_in_2017_pool": int(in_pool.sum()),
                              "unique_vector_label_rows": int(first_occurrence_mask(h, y).sum())}
            dr, db = np.vstack(drift_rows), np.vstack(drift_benign)
            dr = dr[rng.permutation(len(dr))[:DRIFT_SAMPLE]]
            db = db[rng.permutation(len(db))[:DRIFT_SAMPLE]]
            drift["by_day"][day] = {"all_rows": drift_compare(ref_sample, dr, FEATURE_NAMES),
                                    "benign_rows": drift_compare(ref_benign, db, FEATURE_NAMES),
                                    "predicted_class_mix": {LABEL_NAMES[int(k)]: int(v) for k, v in zip(*np.unique(p_, return_counts=True))},
                                    "mean_p_attack": round(float(pa.mean()), 6),
                                    "alert_rate": round(float(al.mean()), 6),
                                    "true_class_mix": {LABEL_NAMES[int(k)]: int(v) for k, v in zip(*np.unique(y, return_counts=True))}}
            e3_true.append(y)
            e3_pred.append(p_)
            e3_patt.append(pa)
            e3_alert.append(al)
            e3_day.append(np.full(len(y), day))
            e3_hash.append(h)
            del ys, ps, pas, als, hs, drift_rows, drift_benign
        y3, p3, pa3, al3, d3, h3 = map(np.concatenate, (e3_true, e3_pred, e3_patt, e3_alert, e3_day, e3_hash))
        clean = ~overlap_mask(h3, pool_set)
        first3 = first_occurrence_mask(h3, y3)
        m_arg = classification_metrics(y3, p3, class_names, pa3)
        e3 = {"status": "OK", "protocol": "every row of the six CSE-CIC-IDS2018 development days, labels mapped to the "
                                            "served 11 classes by evaluation.taxonomies (T0)",
              "independent": False, "files": sorted(prov18), "protected_days_skipped_by_guard": skipped,
              "protected_days": list(PROTECTED_DAYS),
              "metrics_argmax": m_arg,
              "metrics_alert_line": classification_metrics(y3, p3, class_names, pa3, flagged=al3)["binary"],
              "excluding_vectors_in_2017_pool": classification_metrics(y3[clean], p3[clean], class_names, pa3[clean]),
              "dedup_sensitivity": classification_metrics(y3[first3], p3[first3], class_names, pa3[first3]),
              "majority_baseline": majority_baseline(y3, class_names),
              "macro_f1": m_arg.get("f1_macro")}
        for r in group_rows(d3, y3, p3, class_names, pa3):
            per_day_rows.append({"set": "E3_2018_development_days", **r})
        for r in group_rows(d3, y3, p3, class_names, pa3, flagged=al3):
            per_day_rows.append({"set": "E3_2018_alert_line", **r})

    # 6. integrity after
    integ_after = verify_artifacts(model_dir)
    integrity_same = integ_after == integ_before

    # 7. leakage assessment
    leak = {
        "checks": [
            {"check": "E1 test vectors also in E1 train", "count": e1["test_rows_whose_vector_is_in_train"],
             "of": e1["test_rows"], "note": "drop_duplicate_rows removes identical (vector, label) rows only; a vector "
                                            "with conflicting labels can sit on both sides"},
            {"check": "E1 split is random over rows of the same days and attack episodes", "result": "IN-DISTRIBUTION",
             "note": "not chronological; inflates generalisation estimates by construction"},
            {"check": "E2 rows sharing a vector with the training pool", "result": "excluded before scoring",
             "count": int(sum(v["excluded_vector_in_pool"] for v in e2_files.values()))},
            {"check": "E2 rows from the same capture days and attack episodes as training", "result": "LEAKY BY DESIGN",
             "note": "E2 measures unseen rows, not unseen traffic"},
            {"check": "E3 rows sharing an exact vector with the 2017 training pool",
             "count": int(sum(v.get("vector_in_2017_pool", 0) for v in prov18.values())),
             "of": int(sum(v.get("evaluated_rows", 0) for v in prov18.values()))},
            chronology_check(prov18),
            truncation_check(prov18),
            {"check": "protected 2018 days opened", "result": "NO", "note": "assert_permitted on every path; none on disk"},
            {"check": "preprocessing fitted on test data", "result": "NO",
             "note": "the served StandardScaler / models were fitted once at training; nothing is fitted here"},
            {"check": "time-of-day features", "result": "constant 0 in training and in every set here (no timestamp passed)"},
            {"check": "E3 used in earlier development", "result": "YES",
             "note": "the six days trained / selected OTHER candidates (protocols v2-v4); never this model or its lines"},
            {"check": "near-duplicate flows", "result": "NOT_CHECKED", "note": "only exact duplicates are measured"},
        ],
    }
    leak["assessment"] = "LIMITED"
    status_inputs = {"integrity_before_ok": True, "integrity_after_ok": integrity_same,
                     "parity_ok": parity["checked"] > 0 and parity["mismatches"] == 0,
                     "provenance_ok": provenance_ok, "e1_reproduced": e1_reproduced, "e3": e3,
                     "leakage_assessment": leak["assessment"],
                     "drift_ok": bool(drift["by_day"]) and all(d["all_rows"].get("status") == "OK" for d in drift["by_day"].values())}
    status = rank5_status(status_inputs)

    run_dir = new_run_dir(Path(args.out), stamp + ("_smoke" if args.max_rows else ""))
    common = {"rank5_version": RANK5_VERSION, "generated_at": datetime.now(timezone.utc).isoformat(),
              "smoke_run_not_evidence": bool(args.max_rows), "seed": SEED,
              "software": {"python": platform.python_version(), "numpy": np.__version__, "pandas": pd.__version__},
              "model_id": integ_before["version"], "runtime_seconds": round(time.time() - t_start, 1)}
    metrics = {**common, "model": {"integrity_before": integ_before, "integrity_after": integ_after,
                                   "unchanged": integrity_same, "contract": contract, "thresholds": thresholds,
                                   "training_meta": {**{k: meta.get(k) for k in ("version", "trained_at", "metrics", "evaluation", "deduplication", "class_counts")},
                                                    "provenance": {k: meta.get("provenance", {}).get(k) for k in ("git_commit", "git_dirty", "sklearn", "numpy", "python")}}},
               "production_path_parity": parity, "E1_random_split": e1, "E2_2017_unseen_rows": e2, "E3_2018_development_days": e3,
               "notes": notes, "failed_checks": failed_checks}
    write_json(run_dir / "metrics.json", metrics)
    pc = []
    for set_name, block in (("E1_random_split", e1.get("metrics_argmax")), ("E2_2017_unseen_rows", e2["metrics_argmax"]),
                            ("E3_2018_development_days", e3.get("metrics_argmax"))):
        for cname, m in ((block or {}).get("per_class") or {}).items():
            pc.append({"set": set_name, "class": cname, "training_rows": e1["training_class_counts"].get(cname, 0), **{
                k: m[k] for k in ("support", "predicted", "tp", "precision", "recall", "f1", "reliable")}})
    write_csv(run_dir / "per_class_metrics.csv", pc)
    write_csv(run_dir / "per_day_metrics.csv", per_day_rows)
    cm_rows = []
    for set_name, block in (("E1_random_split", e1.get("metrics_argmax")), ("E2_2017_unseen_rows", e2["metrics_argmax"]),
                            ("E3_2018_development_days", e3.get("metrics_argmax"))):
        if block and "confusion_matrix" in block:
            labs = block["confusion_matrix"]["labels"]
            for i, row in enumerate(block["confusion_matrix"]["rows_true_cols_pred"]):
                cm_rows.append({"set": set_name, "actual": labs[i], **{f"pred:{labs[j]}": v for j, v in enumerate(row)}})
    write_csv(run_dir / "confusion_matrix.csv", cm_rows)
    write_json(run_dir / "drift_diagnostics.json", {**common, **drift})
    write_json(run_dir / "data_provenance.json", {**common, "cicids2017_training_files": prov17,
                                                  "cicids2017_provenance_ok": provenance_ok,
                                                  "e1_split": {k: e1[k] for k in ("protocol", "reproduced", "train_rows", "test_rows")},
                                                  "e1_rebuilt_counts": rebuilt, "e2_files": e2_files,
                                                  "cse_cic_ids2018_development_days": prov18, "leakage": leak})
    write_json(run_dir / "rank5_status.json", {**common, "status": status, "leakage_assessment": leak["assessment"],
                                               "failed_checks": failed_checks,
                                               "headline": {
                                                   "e1_accuracy": (e1.get("metrics_argmax") or {}).get("accuracy"),
                                                   "e1_f1_macro": (e1.get("metrics_argmax") or {}).get("f1_macro"),
                                                   "e2_accuracy": e2["metrics_argmax"].get("accuracy"),
                                                   "e2_f1_macro": e2["metrics_argmax"].get("f1_macro"),
                                                   "e3_accuracy": (e3.get("metrics_argmax") or {}).get("accuracy"),
                                                   "e3_balanced_accuracy": (e3.get("metrics_argmax") or {}).get("balanced_accuracy"),
                                                   "e3_f1_macro": (e3.get("metrics_argmax") or {}).get("f1_macro"),
                                                   "e3_attack_recall_alert_line": (e3.get("metrics_alert_line") or {}).get("attack_recall"),
                                                   "e3_benign_fpr_alert_line": (e3.get("metrics_alert_line") or {}).get("fpr")}})
    report = render_report(metrics, status, prov17, prov18, e2_files, leak, drift, per_day_rows)
    (run_dir / "RANK5_GENERALISATION_REPORT.md").write_text(report, encoding="utf-8")
    print(json.dumps({"run_dir": str(run_dir), "status": status, "runtime_s": common["runtime_seconds"]}, indent=1))
    return run_dir


def _f(v, digits=4):
    return "n/a" if v is None else f"{v:.{digits}f}" if isinstance(v, float) else str(v)


def _metrics_row(name, m, alert):
    b = m.get("binary", {})
    return (f"| {name} | {m.get('n', 0):,} | {_f(m.get('accuracy'))} | {_f(m.get('balanced_accuracy'))} | "
            f"{_f(m.get('precision_macro'))} | {_f(m.get('recall_macro'))} | {_f(m.get('f1_macro'))} | "
            f"{_f(m.get('f1_weighted'))} | {_f(b.get('fpr'))} | {_f(b.get('fnr'))} | {_f(b.get('roc_auc'))} | "
            f"{_f(b.get('pr_auc'))} | {_f((alert or {}).get('attack_recall'))} | {_f((alert or {}).get('fpr'))} |")


def render_report(metrics, status, prov17, prov18, e2_files, leak, drift, per_day_rows) -> str:
    """Human-readable report generated from the same objects as the JSON / CSV files (nothing typed by hand)."""
    e1, e2, e3 = metrics["E1_random_split"], metrics["E2_2017_unseen_rows"], metrics["E3_2018_development_days"]
    mod = metrics["model"]
    L = [f"# Rank 5: generalisation evidence for the frozen network-flow model ({metrics['model_id']})", "",
         f"Generated {metrics['generated_at']} by `ai-engine/evaluation/rank5_generalisation.py` ({RANK5_VERSION}, "
         f"seed {SEED}, {metrics['runtime_seconds']} s)." + (" **SMOKE RUN: NOT EVIDENCE.**" if metrics["smoke_run_not_evidence"] else ""),
         "", "## Status", "", "| Item | Status |", "|---|---|"]
    L += [f"| {k} | {v} |" for k, v in status.items()]
    L += ["", "## Model identity and integrity", "",
          f"- Model `{mod['integrity_before']['version']}`; artifacts unchanged before/after the run: **{mod['unchanged']}**.",
          *[f"- {r}: `{e['file']}` sha256 `{e['actual_sha256']}` (registry match)" for r, e in mod["integrity_before"]["entries"].items()],
          f"- Feature contract {mod['contract']['feature_schema_version']}, {mod['contract']['feature_count']} features; "
          f"operating lines alert {mod['thresholds']['alert']}, block {mod['thresholds']['block']}.",
          f"- Production request path parity: {metrics['production_path_parity']['checked']} sampled rows scored through "
          f"`SentinelPredictor.predict(record)`, {metrics['production_path_parity']['mismatches']} mismatches.",
          f"- Training provenance (model meta): {json.dumps(mod['training_meta'].get('provenance'))}; "
          f"meta evaluation: {json.dumps(mod['training_meta'].get('evaluation'))}.", "",
          "## Dataset provenance", "", "| File | Day | sha256 matches training record |", "|---|---|---|"]
    L += [f"| {n} | {v['day']} | {v['match']} |" for n, v in sorted(prov17.items(), key=lambda kv: kv[1]['day'])]
    L += ["", "| 2018 file | Day | CSV rows | Evaluated | Unique (vector,label) | Vector in 2017 pool | Timestamp range | Labels |",
          "|---|---|---|---|---|---|---|---|"]
    for n, v in sorted(prov18.items(), key=lambda kv: kv[1]["day"]):
        t = v["timestamps"]
        L.append(f"| {n} | {v['day']} | {v['csv_rows']:,} | {v['evaluated_rows']:,} | {v['unique_vector_label_rows']:,} | "
                 f"{v['vector_in_2017_pool']:,} | {t.get('min')} .. {t.get('max')} | {', '.join(v['raw_labels'])} |")
    L += ["", "## Leakage and split checks", ""]
    for c in leak["checks"]:
        extra = {k: v for k, v in c.items() if k not in ("check", "note", "per_file")}
        L.append(f"- **{c['check']}**: {json.dumps(extra)}" + (f" ({c['note']})" if c.get("note") else ""))
    L += ["", f"Leakage assessment: **{leak['assessment']}**.", "",
          "## Overall metrics (argmax class; binary = attack vs benign)", "",
          "| Set | n | Accuracy | Balanced acc. | Macro P | Macro R | Macro F1 | Weighted F1 | FPR | FNR | ROC-AUC | PR-AUC | Recall @ alert line | FPR @ alert line |",
          "|---|---|---|---|---|---|---|---|---|---|---|---|---|---|"]
    if e1.get("metrics_argmax"):
        L.append(_metrics_row("E1 random split (not independent)", e1["metrics_argmax"], e1.get("metrics_alert_line")))
    L.append(_metrics_row("E2 2017 unseen rows (same days)", e2["metrics_argmax"], e2.get("metrics_alert_line")))
    L.append(_metrics_row("E2 de-duplicated", e2["dedup_sensitivity"], None))
    if e3.get("status") == "OK":
        L.append(_metrics_row("E3 2018 development days", e3["metrics_argmax"], e3.get("metrics_alert_line")))
        L.append(_metrics_row("E3 de-duplicated", e3["dedup_sensitivity"], None))
        L.append(_metrics_row("E3 without vectors seen in 2017", e3["excluding_vectors_in_2017_pool"], None))
    L += ["", "| Majority baseline | Predicts | Accuracy | Balanced acc. | Macro F1 |", "|---|---|---|---|---|"]
    for name, b in (("E1", e1.get("majority_baseline")), ("E2", e2["majority_baseline"]), ("E3", e3.get("majority_baseline"))):
        if b:
            L.append(f"| {name} | {b.get('predicts')} | {_f(b.get('accuracy'))} | {_f(b.get('balanced_accuracy'))} | {_f(b.get('f1_macro'))} |")
    L += ["", "## Per-class metrics", "", "| Set | Class | Training rows | Support | Predicted | Precision | Recall | F1 | Reliable (support >= 30) |",
          "|---|---|---|---|---|---|---|---|---|"]
    train_counts = e1["training_class_counts"]
    for set_name, block in (("E1", e1.get("metrics_argmax")), ("E2", e2["metrics_argmax"]), ("E3", e3.get("metrics_argmax"))):
        for c, v in ((block or {}).get("per_class") or {}).items():
            L.append(f"| {set_name} | {c} | {train_counts.get(c, 0):,} | {v['support']:,} | {v['predicted']:,} | {_f(v['precision'])} | "
                     f"{_f(v['recall'])} | {_f(v['f1'])} | {v['reliable']} |")
    L += ["", f"Classes with no training rows: {', '.join(e1['classes_without_training_rows']) or 'none'}. The model cannot "
          "have learned them; no detection of them is claimed.", "",
          "## Per-day metrics", "", "| Set | Day | n | Benign | Attack | Accuracy | Balanced acc. | Macro F1 | FPR | FNR | ROC-AUC |",
          "|---|---|---|---|---|---|---|---|---|---|---|"]
    for r in per_day_rows:
        L.append(f"| {r['set']} | {r['group']} | {r['n']:,} | {r['benign']} | {r['attack']} | {_f(r['accuracy'])} | "
                 f"{_f(r['balanced_accuracy'])} | {_f(r['f1_macro'])} | {_f(r['fpr'])} | {_f(r['fnr'])} | {_f(r['roc_auc'])} |")
    L += ["", "## Drift diagnostics (training rows vs each 2018 day)", "",
          f"Method: {json.dumps(drift['method'])}.", "",
          "| Day | Features PSI large / moderate / small (all rows) | Median KS (all) | Benign: PSI large | Median KS (benign) | Top PSI features | Alert rate | Mean P(attack) |",
          "|---|---|---|---|---|---|---|---|"]
    for day, v in sorted(drift["by_day"].items()):
        a, b = v["all_rows"], v["benign_rows"]
        if a.get("status") != "OK":
            L.append(f"| {day} | {a.get('status')} | | | | | | |")
            continue
        L.append(f"| {day} | {a['features_large_psi']} / {a['features_moderate_psi']} / {a['features_small_psi']} | {a['median_ks']} | "
                 f"{b.get('features_large_psi')} | {b.get('median_ks')} | {', '.join(x['feature'] for x in a['top_psi'][:4])} | "
                 f"{v['alert_rate']} | {v['mean_p_attack']} |")
    L += ["", "Feature shift is not proof of concept drift: the 2018 days come from another network, another attack "
          "toolset and another CICFlowMeter build, so covariate, measurement and label-definition differences cannot be "
          "separated with this data.", "",
          "## Limitations", "",
          "- E1 and E2 share capture days and attack episodes with the training data: they measure in-distribution performance only.",
          "- E3 is later and from a different network, but its six days were used in earlier development (other candidates), its labels "
          "are the dataset's own (known noisy, e.g. infiltration labelled by time window) and mapped to the served classes by evaluation/taxonomies.py.",
          "- Several 2018 files appear cut at the spreadsheet row limit (see checks); later flows of those days are missing.",
          "- Only exact duplicates are measured; near-duplicates are not.",
          "- The four protected 2018 days were not used; they remain the registered one-shot external test (owner approval).", ""]
    return "\n".join(L)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--model-dir", default=str(ENGINE / "models"))
    ap.add_argument("--data-2017", default=str(DATA_2017))
    ap.add_argument("--data-2018", default=str(DATA_2018))
    ap.add_argument("--out", default=str(DEFAULT_OUT))
    ap.add_argument("--max-rows", type=int, default=None, help="smoke run: cap rows per file (NOT evidence)")
    run(ap.parse_args())


if __name__ == "__main__":
    main()
