"""
Controlled model-development experiments (audit/ML_DEV_PROTOCOL.md). Pre-registered candidates, fixed folds, fixed
selection rule. Default mode --plan builds the development pools and fold manifests and writes plan.json; nothing is
trained. --run --approved trains throwaway fold models (never saved into models/) and writes results.json.

Data: CICIDS2017 (8 files) and the six CSE-CIC-IDS2018 development days. The four protected days
(evaluation/protected_data.py) are never opened.

  .venv/Scripts/python evaluation/dev_experiments.py                                  # plan
  .venv/Scripts/python evaluation/dev_experiments.py --run --approved --candidates C0,C1 --folds D17
"""
import argparse, hashlib, json, sys, time
from datetime import datetime, timezone
from pathlib import Path

import numpy as np
import pandas as pd

ENGINE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ENGINE))
from evaluation import feature_sets, taxonomies  # noqa: E402
from evaluation.protected_data import assert_permitted, permitted_files  # noqa: E402
from evaluation.p5_served_model_eval import load_cicids_dir, sha256 as file_sha256  # noqa: E402
from evaluation.xgb_holdout_eval import DAYS, binary, day_of, wilson, _versions  # noqa: E402
from utils.features import FEATURE_NAMES, prepare_features  # noqa: E402

DATA_2018 = Path("D:/sentinelai_datasets/cse_cic_ids2018")
CAPS_2018 = {"benign": 15000}  # per file; every attack label: CAP_2018_ATTACK
CAP_2018_ATTACK = 10000
SEED = 42

# Pre-registered candidates (frozen in audit/ML_DEV_PROTOCOL.md §6; change only by a new, dated protocol version)
CANDIDATES = {
    "C0": {"features": "A", "taxonomy": "T0", "arch": "multiclass", "model": "xgb", "data": "2017", "note": "served recipe (baseline)"},
    "C0rf": {"features": "A", "taxonomy": "T0", "arch": "multiclass", "model": "rf", "data": "2017", "note": "Random Forest baseline"},
    "C1": {"features": "C", "taxonomy": "T0", "arch": "multiclass", "model": "xgb", "data": "2017", "note": "testbed-robust features"},
    "C1e": {"features": "E", "taxonomy": "T0", "arch": "multiclass", "model": "xgb", "data": "2017", "note": "C + header-per-packet (+ log)"},
    "C2": {"features": "C", "taxonomy": "T1", "arch": "two_stage", "model": "xgb", "data": "2017", "note": "binary-first"},
    "C3": {"features": "C", "taxonomy": "T2", "arch": "multiclass", "model": "xgb", "data": "2017", "note": "family taxonomy"},
    "C4": {"features": "C", "taxonomy": "T1", "arch": "two_stage", "model": "xgb", "data": "2017+2018dev", "note": "multi-dataset"},
    # Protocol v2 (audit/ML_DEV_PROTOCOL_V2.md §4): C4 with the TCP-window features kept; C4 itself is C4-C
    "C4A": {"features": "A", "taxonomy": "T1", "arch": "two_stage", "model": "xgb", "data": "2017+2018dev", "note": "v2: multi-dataset, 53 features"},
    "C4B": {"features": "B", "taxonomy": "T1", "arch": "two_stage", "model": "xgb", "data": "2017+2018dev", "note": "v2: multi-dataset, 47 features (constants removed)"},
    # Protocol v3 (audit/ML_DEV_PROTOCOL_V3.md §3): C4-A without infiltration rows in training (still in every test fold)
    "C4AI": {"features": "A", "taxonomy": "T1", "arch": "two_stage", "model": "xgb", "data": "2017+2018dev",
             "exclude_train_families": ["Infiltration"], "note": "v3: C4-A, infiltration excluded from training"},
}
# Protocol v3 label set "corrected_v3": the independently verified 2017-Thursday scan rows (audit/LABEL_VERIFICATION_PLAN.md
# §8), frozen as row positions of one file and pinned by hash. Applied after pooling, so fold manifests do not change.
CORRECTION_V3 = {"file": "Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv",
                 "rows_csv": ENGINE / "evaluation" / "label_corrections" / "cicids2017_thursday_scan_v3.csv",
                 "sha256": "c4e3f1c19567b24c192d347985c506aef835aba4ae86314ebdc40ba4547e6807",
                 "from": "benign", "to": "portscan"}
FOLD_SETS = ("D17", "D18")  # 2017 leave-one-day-out (5) ; 2018 leave-one-development-day-out (6)


# ── data ──────────────────────────────────────────────────────────────────────────────────────────────────────
def pool_2017(data_dir: Path):
    """The served model's pool (caps + dedup on vector + T0 label), with raw labels and provenance kept."""
    df = load_cicids_dir(data_dir, keep_source=True)
    raw = df["label"].to_numpy()
    X, y_t0 = prepare_features(df.drop(columns=["_file", "_row"]), max_missing=0)
    _, first = np.unique(np.column_stack([X, y_t0]), axis=0, return_index=True)
    keep = np.sort(first)
    meta = pd.DataFrame({"corpus": "2017", "file": df["_file"].to_numpy()[keep], "row": df["_row"].to_numpy()[keep],
                         "raw": [taxonomies.norm(r) for r in raw[keep]]})
    meta["day"] = meta["file"].map(day_of)
    return X[keep].astype(float), meta


def _mapping_2018():
    """The reviewed Phase 8 column mapping, read as a literal (the script itself is not executed)."""
    import ast
    src = (ENGINE / "experiments" / "gate1_phase8_multicorpus_candidates" / "build_multicorpus_pipeline.py").read_text(encoding="utf-8")
    for node in ast.parse(src).body:
        if isinstance(node, ast.Assign) and getattr(node.targets[0], "id", None) == "FEATURE_MAPPING_2018":
            return {raw: feat for feat, raw in ast.literal_eval(node.value)}
    raise RuntimeError("FEATURE_MAPPING_2018 not found")


def load_2018_file(path: Path, chunksize=250_000):
    """One development day -> DataFrame of the mapped features + raw label, cleaned like the 2017 loader (rows with
    a non-finite mapped value dropped; repeated header lines dropped); Timestamp, ports, IPs never read."""
    assert_permitted(path)
    rename = _mapping_2018()
    header = pd.read_csv(path, nrows=0).columns.str.strip()
    use = [c for c in header if c in rename] + ["Label"]
    parts = []
    for chunk in pd.read_csv(path, usecols=lambda c: c.strip() in use, chunksize=chunksize, low_memory=False):
        chunk.columns = chunk.columns.str.strip()
        chunk = chunk[chunk["Label"].astype(str).str.strip() != "Label"]
        feats = chunk.drop(columns=["Label"]).apply(pd.to_numeric, errors="coerce").astype("float32")
        feats = feats.replace([np.inf, -np.inf], np.nan)
        ok = feats.notna().all(axis=1).to_numpy()
        part = feats[ok].rename(columns=rename)
        part["raw"] = [taxonomies.norm(v) for v in chunk["Label"].to_numpy()[ok]]
        part["row"] = chunk.index.to_numpy()[ok]
        parts.append(part)
    return pd.concat(parts, ignore_index=True)


def pool_2018(data_dir: Path, files=None):
    files = files or permitted_files(data_dir)[0]
    frames = []
    for f in files:
        df = load_2018_file(f)
        sampled = [g.sample(n=min(len(g), CAPS_2018.get(lab, CAP_2018_ATTACK)), random_state=SEED) for lab, g in df.groupby("raw")]
        df = pd.concat(sampled, ignore_index=True)
        df["file"] = f.name
        frames.append(df)
    df = pd.concat(frames, ignore_index=True)
    feats = df.drop(columns=["raw", "row", "file"]).assign(Label="BENIGN")  # labels are mapped by taxonomies, not here
    X, _ = prepare_features(feats, max_missing=0)
    t0 = taxonomies.map_labels(df["raw"], "T0")
    _, first = np.unique(np.column_stack([X, pd.factorize(t0)[0]]), axis=0, return_index=True)
    keep = np.sort(first)
    meta = pd.DataFrame({"corpus": "2018", "file": df["file"].to_numpy()[keep], "row": df["row"].to_numpy()[keep],
                         "raw": df["raw"].to_numpy()[keep]})
    meta["day"] = meta["file"].str.extract(r"(\d\d-\d\d-2018)")[0]
    return X[keep].astype(float), meta


# ── folds ─────────────────────────────────────────────────────────────────────────────────────────────────────
def folds(meta: pd.DataFrame, fold_set: str, data: str):
    """[(name, train_mask, test_mask)]. D17: one 2017 day held out; D18: one 2018 development day held out. The
    training side uses only the corpora the candidate's `data` allows."""
    corpus, day = meta["corpus"].to_numpy(), meta["day"].to_numpy()
    allowed = np.isin(corpus, ["2017"] if data == "2017" else ["2017", "2018"])
    out = []
    if fold_set == "D17":
        for d in DAYS:
            te = (corpus == "2017") & (day == d)
            if te.any():
                out.append((f"2017-{d}", allowed & ~te, te))
    elif fold_set == "D18":
        for d in sorted(set(day[corpus == "2018"])):
            te = (corpus == "2018") & (day == d)
            out.append((f"2018-{d}", allowed & ~te, te))
    else:
        raise KeyError(fold_set)
    return out


def manifest_hash(meta, tr, te):
    ids = lambda m: [f"{c}:{f}#{r}" for c, f, r in zip(meta["corpus"][m], meta["file"][m], meta["row"][m])]  # noqa: E731
    return hashlib.sha256(json.dumps({"train": ids(tr), "test": ids(te)}, separators=(",", ":")).encode()).hexdigest()


# ── models ────────────────────────────────────────────────────────────────────────────────────────────────────
def make_model(kind, n_classes):
    if kind == "xgb":
        from xgboost import XGBClassifier
        return XGBClassifier(n_estimators=200, max_depth=6, learning_rate=0.1, random_state=SEED, n_jobs=-1,
                             eval_metric="logloss" if n_classes == 2 else "mlogloss")
    if kind == "rf":
        from sklearn.ensemble import RandomForestClassifier
        from training.train import RF_PARAMS
        return RandomForestClassifier(**RF_PARAMS)
    raise KeyError(kind)


def _fit(kind, X, labels, factory=None):
    """Scaler + classifier with balanced sample weights; labels re-encoded over the classes present."""
    from sklearn.pipeline import Pipeline
    from sklearn.preprocessing import StandardScaler
    from sklearn.utils.class_weight import compute_sample_weight
    classes = np.unique(labels)
    enc = {c: i for i, c in enumerate(classes)}
    yi = np.array([enc[c] for c in labels])
    clf = factory() if factory else make_model(kind, len(classes))
    pipe = Pipeline([("scaler", StandardScaler()), ("clf", clf)])
    pipe.fit(X, yi, clf__sample_weight=compute_sample_weight("balanced", yi))
    return pipe, classes


def fit_predict(cfg, X, raw, tr, te, factory=None):
    """(predicted class names, p_attack, fit_seconds, predict_seconds, model_bytes) for one fold."""
    import pickle
    Xv, _ = feature_sets.variant(X, cfg["features"])
    labels = taxonomies.map_labels(raw, cfg["taxonomy"])
    benign = np.array([taxonomies.RAW_LABELS[r][1] == "Benign" for r in raw])
    t0 = time.time()
    if cfg["arch"] == "multiclass":
        pipe, classes = _fit(cfg["model"], Xv[tr], labels[tr], factory)
        fit_s = time.time() - t0
        t1 = time.time()
        proba = pipe.predict_proba(Xv[te])
        pred = classes[proba.argmax(axis=1)]
        bcol = [i for i, c in enumerate(classes) if c in ("BENIGN", "Benign")]
        p_attack = 1 - proba[:, bcol[0]] if bcol else np.ones(len(pred))
        models = [pipe]
    elif cfg["arch"] == "two_stage":
        stage1, s1c = _fit(cfg["model"], Xv[tr], np.where(benign[tr], "Benign", "Attack"), factory)
        attack_tr = tr & ~benign
        stage2, s2c = _fit(cfg["model"], Xv[attack_tr], labels[attack_tr], factory)
        fit_s = time.time() - t0
        t1 = time.time()
        p1 = stage1.predict_proba(Xv[te])
        p_attack = p1[:, list(s1c).index("Attack")]
        pred = np.where(p_attack >= 0.5, s2c[stage2.predict_proba(Xv[te]).argmax(axis=1)], "Benign")
        models = [stage1, stage2]
    else:
        raise KeyError(cfg["arch"])
    pred_s = time.time() - t1
    return pred, p_attack, fit_s, pred_s, sum(len(pickle.dumps(m)) for m in models)


def score(cfg, raw, te, pred, p_attack):
    from sklearn.metrics import average_precision_score, brier_score_loss
    rt = raw[te]
    attack = np.array([taxonomies.RAW_LABELS[r][1] != "Benign" for r in rt])
    flagged = np.array([p not in ("BENIGN", "Benign") for p in pred])
    fam = np.array([taxonomies.RAW_LABELS[r][1] for r in rt])
    truth = taxonomies.map_labels(rt, cfg["taxonomy"])
    by_family = {}
    for f in sorted(set(fam) - {"Benign"}):
        m = fam == f
        k = int(flagged[m].sum())
        by_family[f] = {"rows": int(m.sum()), "flagged_as_attack": k, "ci95": wilson(k, int(m.sum())),
                        "correct_class": int((pred[m] == truth[m]).sum())}
    out = {"binary_argmax": binary(flagged, attack), "by_family": by_family}
    if attack.any() and (~attack).any():
        out["pr_auc"] = round(float(average_precision_score(attack, p_attack)), 4)
        out["brier"] = round(float(brier_score_loss(attack, np.clip(p_attack, 0, 1))), 5)
    return out


def apply_label_set(meta: pd.DataFrame, label_set: str):
    """Returns (raw labels, report). 'published' = as distributed; 'corrected_v3' = CORRECTION_V3 applied (hash-checked)."""
    raw = meta["raw"].to_numpy().copy()
    if label_set == "published":
        return raw, {"label_set": "published"}
    if label_set != "corrected_v3":
        raise KeyError(label_set)
    c = CORRECTION_V3
    body = Path(c["rows_csv"]).read_bytes()
    if hashlib.sha256(body).hexdigest() != c["sha256"]:
        raise RuntimeError("label correction file does not match its pinned sha256")
    rows = set(pd.read_csv(Path(c["rows_csv"]))["row"].astype(int))
    hit = (meta["corpus"] == "2017").to_numpy() & (meta["file"] == c["file"]).to_numpy() & meta["row"].isin(rows).to_numpy()
    changed = hit & (raw == c["from"])
    raw[changed] = c["to"]
    return raw, {"label_set": "corrected_v3", "correction_sha256": c["sha256"], "pool_rows_in_list": int(hit.sum()),
                 "pool_rows_changed": int(changed.sum()), "change": f"{c['from']} -> {c['to']}"}


def train_mask(cfg, raw, tr):
    """Training rows of a fold, minus any families the candidate excludes from training (test rows are unaffected)."""
    excl = cfg.get("exclude_train_families")
    if not excl:
        return tr
    return tr & ~np.isin(np.array([taxonomies.RAW_LABELS[r][1] for r in raw]), excl)


def prediction_rows(meta, te, fold, pred, p_attack, labels_used=None):
    """One row per test row: identifiers of the pooled row (corpus/file/row), raw label, prediction, p(attack);
    with a corrected label set also the label the run used."""
    d = meta.loc[te, ["corpus", "day", "file", "row", "raw"]].reset_index(drop=True)
    if labels_used is not None:
        d["label_used"] = labels_used[te]
    d.insert(0, "fold", fold)
    d["pred"] = pred
    d["p_attack"] = np.round(p_attack, 6)
    return d


# ── main ──────────────────────────────────────────────────────────────────────────────────────────────────────
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--data17", default=str(ENGINE / "datasets" / "cicids2017"))
    ap.add_argument("--data18", default=str(DATA_2018))
    ap.add_argument("--out", default=str(ENGINE / "experiments" / f"dev_{datetime.now():%Y%m%d}"))
    ap.add_argument("--candidates", default=",".join(CANDIDATES))
    ap.add_argument("--folds", default=",".join(FOLD_SETS))
    ap.add_argument("--run", action="store_true")
    ap.add_argument("--approved", action="store_true", help="the owner approved this training batch")
    ap.add_argument("--labels", default="published", choices=["published", "corrected_v3"],
                    help="label set (audit/ML_DEV_PROTOCOL_V3.md); corrected_v3 applies the verified Thursday scan correction")
    ap.add_argument("--dump-predictions", action="store_true",
                    help="with --run: write each test row's prediction (predictions_<candidate>.csv; development rows only)")
    args = ap.parse_args()
    if args.dump_predictions and not args.run:
        sys.exit("--dump-predictions needs --run")
    if args.run and not args.approved:
        sys.exit("--run trains models: pass --approved only with the owner's approval (audit/ML_DEV_PROTOCOL.md §9)")
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    t0 = time.time()
    X17, m17 = pool_2017(Path(args.data17))
    files18, protected_seen = permitted_files(args.data18)
    X18, m18 = pool_2018(Path(args.data18), files18) if files18 else (np.empty((0, len(FEATURE_NAMES))), m17.iloc[:0])
    X = np.vstack([X17, X18])
    meta = pd.concat([m17, m18], ignore_index=True)
    raw, label_report = apply_label_set(meta, args.labels)
    report = {"generated_at": datetime.now(timezone.utc).isoformat(), "mode": "run" if args.run else "plan", "labels": label_report,
              "versions": _versions(), "seed": SEED, "caps_2018": {**CAPS_2018, "each_attack_label": CAP_2018_ATTACK},
              "pool": {"rows_2017": int(len(m17)), "rows_2018": int(len(m18)), "build_seconds": round(time.time() - t0, 1),
                       "raw_label_counts": {f"{c}:{r}": int(n) for (c, r), n in meta.groupby(["corpus", "raw"]).size().items()},
                       "files_2018_used": [f.name for f in files18], "protected_files_present_not_read": protected_seen,
                       "data_sha256": {f.name: file_sha256(f) for f in sorted(Path(args.data17).glob("*.csv")) + list(files18)}},
              "candidates": {}}
    for cid in args.candidates.split(","):
        cfg = CANDIDATES[cid]
        dumps = []
        entry = {"config": cfg, "features": feature_sets.variant(X[:1], cfg["features"])[1], "folds": []}
        for fs in args.folds.split(","):
            for name, tr, te in folds(meta, fs, cfg["data"]):
                tr = train_mask(cfg, raw, tr)
                f = {"fold": name, "train_rows": int(tr.sum()), "test_rows": int(te.sum()), "manifest_sha256": manifest_hash(meta, tr, te),
                     "test_families_absent_from_training": sorted(
                         {taxonomies.RAW_LABELS[r][1] for r in raw[te]} - {taxonomies.RAW_LABELS[r][1] for r in raw[tr]})}
                assert not (tr & te).any()
                if args.run:
                    pred, p_attack, fit_s, pred_s, size = fit_predict(cfg, X, raw, tr, te)
                    f.update(score(cfg, raw, te, pred, p_attack), fit_seconds=round(fit_s, 1),
                             predict_us_per_row=round(pred_s * 1e6 / max(1, te.sum()), 2), model_bytes=size)
                    if args.dump_predictions:
                        dumps.append(prediction_rows(meta, te, name, pred, p_attack, raw))
                entry["folds"].append(f)
        if dumps:
            pd.concat(dumps, ignore_index=True).to_csv(out / f"predictions_{cid}.csv", index=False)
        report["candidates"][cid] = entry
    (out / ("results.json" if args.run else "plan.json")).write_text(json.dumps(report, indent=2, default=str), encoding="utf-8")
    print(json.dumps(report["pool"], indent=1, default=str)[:3000])
    for cid, e in report["candidates"].items():
        for f in e["folds"]:
            print(f"{cid:5s} {f['fold']:22s} train {f['train_rows']:>7,} test {f['test_rows']:>6,}  unseen families: {', '.join(f['test_families_absent_from_training']) or '-'}")
    print("written:", out)


if __name__ == "__main__":
    main()
