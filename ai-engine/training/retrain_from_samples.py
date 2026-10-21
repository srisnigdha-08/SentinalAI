#!/usr/bin/env python3
"""
Supervised retraining loop with human-approved promotion.

  1. Export analyst-approved samples:   (backend) node utils/exportTrainingSamples.js --out <file.jsonl>
  2. Train + gate a candidate:          python training/retrain_from_samples.py --samples <file.jsonl>
  3. Promote (explicit, gated):         python training/retrain_from_samples.py --samples <file.jsonl> --promote
  4. Load it without a restart:         POST /model/reload  (backend: POST /api/ai/engine/reload, admin)

The candidate uses the production recipe (evaluation/day_holdout_eval.py). Training rows are the
chronological training portion of CICIDS2017 plus the approved samples; the chronological test rows are
never trained on and score both the candidate and a baseline trained the same way without the samples.
Promotion requires the gates below; it writes new versioned files (never overwrites) and re-pins
models/registry.json. Nothing is promoted without --promote.
"""
import argparse
import json
import shutil
import sys
from datetime import datetime, timezone
from pathlib import Path

import joblib
import numpy as np
import pandas as pd

ENGINE_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ENGINE_ROOT))
from evaluation import day_holdout_eval as ev  # noqa: E402
from inference.predictor import REGISTRY_FILE, file_sha256  # noqa: E402
from utils.features import FEATURE_NAMES, FEATURE_SCHEMA_VERSION, LABEL_MAP  # noqa: E402

# A candidate may not be worse than the baseline by more than these margins.
MAX_MACRO_F1_DROP = 0.005
MAX_ALERT_FPR = 0.001  # benign "threat raised" rate on the sealed chronological test


def load_samples(path: Path) -> pd.DataFrame:
    """JSONL from exportTrainingSamples.js -> rows in the evaluation frame layout (schema-checked)."""
    rows, skipped = [], 0
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        s = json.loads(line)
        vec, label = s.get("featureVector"), s.get("label")
        if (s.get("featureSchemaVersion") != FEATURE_SCHEMA_VERSION or label not in LABEL_MAP
                or not isinstance(vec, list) or len(vec) != len(FEATURE_NAMES)
                or not all(isinstance(v, (int, float)) and np.isfinite(v) for v in vec)):
            skipped += 1
            continue
        rows.append({**dict(zip(FEATURE_NAMES, map(float, vec))), "y": LABEL_MAP[label], "target": label,
                     "day": "analyst", "file": "analyst_samples", "order": len(rows)})
    if skipped:
        print(f"  skipped {skipped} sample(s) with a different schema, unknown label or invalid vector")
    return pd.DataFrame(rows)


def gate(candidate: dict, baseline: dict) -> dict:
    checks = {
        "macro_f1_not_worse": candidate["f1_macro"] >= baseline["f1_macro"] - MAX_MACRO_F1_DROP,
        "alert_fpr_within_target": candidate["score_rules"]["current"]["threat_raised"]["benign_fpr"] <= MAX_ALERT_FPR,
    }
    return {"passed": all(checks.values()), "checks": checks,
            "limits": {"max_macro_f1_drop": MAX_MACRO_F1_DROP, "max_alert_fpr": MAX_ALERT_FPR}}


def promote(out_dir: Path, model_dir: Path, version: str, report: dict) -> dict:
    """Copy candidate files into model_dir under new versioned names and re-pin the registry."""
    clf_name, if_name = f"rf_classifier_{version}.pkl", f"isolation_forest_{version}.pkl"
    for name in (clf_name, if_name):
        if (model_dir / name).exists():
            raise SystemExit(f"Refusing to overwrite existing model file {name}")
    shutil.copy2(out_dir / "rf_classifier.pkl", model_dir / clf_name)
    shutil.copy2(out_dir / "isolation_forest.pkl", model_dir / if_name)
    meta = {"model_type": "RandomForestClassifier", "version": version, "trained_at": report["trained_at"],
            "n_features": len(FEATURE_NAMES), "feature_names": FEATURE_NAMES, "classes": LABEL_MAP,
            "metrics": {k: report["candidate"][k] for k in ("accuracy", "f1_weighted", "f1_macro")},
            "evaluation": {"split": "chronological_per_class", "independent_holdout": True},
            "analyst_samples": report["analyst_samples"]}
    (model_dir / f"rf_classifier_{version}_meta.json").write_text(json.dumps(meta, indent=2), encoding="utf-8")
    (model_dir / f"isolation_forest_{version}_meta.json").write_text(json.dumps(
        {"model_type": "IsolationForest", "version": version, "n_features": len(FEATURE_NAMES)}, indent=2), encoding="utf-8")
    import sklearn
    registry = {
        "registered_at": datetime.now(timezone.utc).isoformat(),
        "sklearn_version": sklearn.__version__,
        "classifier": {"file": clf_name, "type": "rf", "meta": f"rf_classifier_{version}_meta.json",
                       "version": version, "sha256": file_sha256(model_dir / clf_name)},
        "anomaly": {"file": if_name, "meta": f"isolation_forest_{version}_meta.json",
                    "version": version, "sha256": file_sha256(model_dir / if_name)},
    }
    previous = model_dir / REGISTRY_FILE
    if previous.exists():
        shutil.copy2(previous, out_dir / "registry.previous.json")  # one-step rollback
    (model_dir / REGISTRY_FILE).write_text(json.dumps(registry, indent=2) + "\n", encoding="utf-8")
    return registry


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[1])
    ap.add_argument("--data", default=str(ENGINE_ROOT / "datasets" / "cicids2017"))
    ap.add_argument("--samples", help="JSONL from backend utils/exportTrainingSamples.js (optional)")
    ap.add_argument("--out", default=None, help="candidate directory (default experiments/retraining/<version>)")
    ap.add_argument("--model-dir", default=str(ENGINE_ROOT / "models"))
    ap.add_argument("--promote", action="store_true", help="copy the candidate into --model-dir and re-pin the registry if gates pass")
    ap.add_argument("--n-estimators", type=int, default=None)
    ap.add_argument("--max-rows-per-file", type=int, default=None)
    args = ap.parse_args()

    version = "retrained_" + datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    out_dir = Path(args.out) if args.out else ENGINE_ROOT / "experiments" / "retraining" / version
    out_dir.mkdir(parents=True, exist_ok=True)

    print("Loading CICIDS2017...", flush=True)
    data = ev.load_all(Path(args.data), args.max_rows_per_file)
    train, test = ev.chronological_split(data)
    train, test = ev.cap(train, ev.TRAIN_CAPS), ev.cap(test, ev.TEST_CAPS)
    samples = load_samples(Path(args.samples)) if args.samples else pd.DataFrame()
    print(f"  analyst samples: {len(samples)}", flush=True)

    print("Training baseline (no analyst samples)...", flush=True)
    base_rf, base_if = ev.fit(train, args.n_estimators)
    baseline = ev.evaluate(base_rf, base_if, test)
    if len(samples):
        print("Training candidate (with analyst samples)...", flush=True)
        rf, ifo = ev.fit(pd.concat([train, samples], ignore_index=True), args.n_estimators)
        candidate = ev.evaluate(rf, ifo, test)
    else:
        rf, ifo, candidate = base_rf, base_if, baseline

    joblib.dump(rf, out_dir / "rf_classifier.pkl")
    joblib.dump(ifo, out_dir / "isolation_forest.pkl")
    report = {
        "version": version,
        "trained_at": datetime.now(timezone.utc).isoformat(),
        "analyst_samples": int(len(samples)),
        "train_rows": int(len(train) + len(samples)),
        "test_rows": int(len(test)),
        "baseline": {k: baseline[k] for k in ("accuracy", "f1_macro", "f1_weighted")},
        "candidate": {k: candidate[k] for k in ("accuracy", "f1_macro", "f1_weighted")},
        "candidate_alerts": candidate["score_rules"]["current"],
        "gate": gate(candidate, baseline),
    }
    report["candidate_per_class"] = candidate["per_class"]
    print(json.dumps({k: report[k] for k in ("baseline", "candidate", "gate")}, indent=2))

    if args.promote:
        if not report["gate"]["passed"]:
            report["promoted"] = False
            print("Gate failed: candidate NOT promoted.")
        else:
            report["registry"] = promote(out_dir, Path(args.model_dir), version, report)
            report["promoted"] = True
            print(f"Promoted {version}; call POST /model/reload (or restart the engine) to serve it.")
    (out_dir / "report.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(f"Candidate and report written to {out_dir}")


if __name__ == "__main__":
    main()
