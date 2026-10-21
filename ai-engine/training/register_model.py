#!/usr/bin/env python3
"""
Pin the deployed models in models/registry.json (file, type, metadata, SHA-256).

The inference engine loads exactly the registered files and refuses to start inference when a hash does
not match, so a stray or swapped .pkl can no longer become the live model unnoticed.

  python training/register_model.py --classifier rf_classifier_cicids_v2.pkl --type rf \
      --anomaly isolation_forest_cicids.pkl
  python training/register_model.py --check     # verify the current registry against the files
"""
import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

ENGINE_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ENGINE_ROOT))
from inference.predictor import MODEL_TYPES, REGISTRY_FILE, file_sha256, load_registry  # noqa: E402
from inference.model_checks import GOLDEN_FILE, append_history, build_golden  # noqa: E402
from utils.features import FEATURE_NAMES  # noqa: E402


def write_golden(model_dir: Path, clf_file: str, if_file: str) -> dict:
    """Score the golden vectors with the models being registered and pin the result (P5)."""
    import joblib
    golden = build_golden(joblib.load(model_dir / clf_file), joblib.load(model_dir / if_file), len(FEATURE_NAMES))
    (model_dir / GOLDEN_FILE).write_text(json.dumps(golden), encoding="utf-8")
    return {"file": GOLDEN_FILE, "rows": golden["rows"], "sha256": file_sha256(model_dir / GOLDEN_FILE)}


def default_meta(model_file: str) -> str:
    return model_file[:-4] + "_meta.json" if model_file.endswith(".pkl") else ""


def entry(model_dir: Path, model_file: str, meta_file: str, **extra) -> dict:
    path = model_dir / model_file
    if not path.is_file():
        raise SystemExit(f"Model file not found: {path}")
    meta = meta_file or default_meta(model_file)
    out = {"file": model_file, **extra, "sha256": file_sha256(path)}
    if meta and (model_dir / meta).is_file():
        out["meta"] = meta
        out["version"] = json.loads((model_dir / meta).read_text(encoding="utf-8")).get("version")
    return out


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[1])
    ap.add_argument("--model-dir", default=str(ENGINE_ROOT / "models"))
    ap.add_argument("--classifier", help="classifier .pkl in --model-dir")
    ap.add_argument("--type", default="rf", choices=MODEL_TYPES)
    ap.add_argument("--classifier-meta", default="")
    ap.add_argument("--anomaly", help="IsolationForest .pkl in --model-dir")
    ap.add_argument("--anomaly-meta", default="")
    ap.add_argument("--check", action="store_true", help="verify the existing registry and exit")
    ap.add_argument("--note", default=None, help="reason for this registration, recorded in registry_history.jsonl")
    args = ap.parse_args()
    model_dir = Path(args.model_dir)

    if args.check:
        reg = load_registry(model_dir)
        if reg is None:
            raise SystemExit(f"No {REGISTRY_FILE} in {model_dir}")
        ok = True
        for role in ("classifier", "anomaly"):
            actual = file_sha256(model_dir / reg[role]["file"])
            match = actual == reg[role]["sha256"]
            ok &= match
            print(f"{role:<10} {reg[role]['file']:<40} {'OK' if match else 'MISMATCH ' + actual[:12]}")
        if reg.get("golden"):
            golden_path = model_dir / reg["golden"]["file"]
            match = golden_path.exists() and file_sha256(golden_path) == reg["golden"]["sha256"]
            ok &= match
            print(f"{'golden':<10} {reg['golden']['file']:<40} {'OK' if match else 'MISMATCH'}")
        print(f"registry   sha256 {file_sha256(model_dir / REGISTRY_FILE)} (value for MODEL_REGISTRY_SHA256)")
        sys.exit(0 if ok else 1)

    if not args.classifier or not args.anomaly:
        ap.error("--classifier and --anomaly are required (or use --check)")
    import sklearn
    registry = {
        "registered_at": datetime.now(timezone.utc).isoformat(),
        # The engine refuses to load the models under a different scikit-learn version.
        "sklearn_version": sklearn.__version__,
        "classifier": entry(model_dir, args.classifier, args.classifier_meta, type=args.type),
        "anomaly": entry(model_dir, args.anomaly, args.anomaly_meta),
    }
    registry["golden"] = write_golden(model_dir, args.classifier, args.anomaly)
    (model_dir / REGISTRY_FILE).write_text(json.dumps(registry, indent=2) + "\n", encoding="utf-8")
    meta_file = registry["classifier"].get("meta")
    metrics = json.loads((model_dir / meta_file).read_text(encoding="utf-8")).get("metrics") if meta_file else None
    append_history(model_dir, registry, source="register_model.py", note=args.note, metrics=metrics)
    print(f"Wrote {model_dir / REGISTRY_FILE}")
    print(json.dumps(registry, indent=2))
    # L11: pin the registry itself from outside the model volume (environment / secret store)
    print(f"Registry sha256, for MODEL_REGISTRY_SHA256: {file_sha256(model_dir / REGISTRY_FILE)}")


if __name__ == "__main__":
    main()
