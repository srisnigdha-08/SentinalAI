#!/usr/bin/env python3
"""
One reproducible entry point (P3): train -> evaluate under every protocol -> summarise -> (optionally) register.

  python training/pipeline.py --version cicids_v4                       # RF, the deployed recipe
  python training/pipeline.py --version xgb_v1 --model xgboost          # XGBoost candidate
  python training/pipeline.py --version cicids_v4 --register --note "why"
  python training/pipeline.py --version check --smoke                   # quick plumbing check (small eval)

Steps, all with the repository's own tools so nothing is re-implemented:
  1. training/train.py --version V           de-duplicated split, full provenance metadata
                                              (into experiments/pipeline/V/models, never models/ directly)
  2. evaluation/day_holdout_eval.py           random, chronological and leave-one-day-out protocols
  3. evaluation/day_holdout_eval.py           threshold validation: the alert line this candidate would need
  4. experiments/pipeline/V/summary.{json,md}
  5. --register: copy both files into models/ and run training/register_model.py (golden set + history).
     Then POST /model/reload (or restart) to serve it. Nothing is registered without --register.
"""
import argparse
import json
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

ENGINE_ROOT = Path(__file__).resolve().parent.parent
PY = sys.executable
PREFIX = {"rf": "rf_classifier", "xgboost": "xgb_classifier"}


def run(cmd):
    print("$ " + " ".join(str(c) for c in cmd), flush=True)
    subprocess.run([str(c) for c in cmd], cwd=ENGINE_ROOT, check=True)


def summarise(out: Path, version: str, model: str, meta: dict) -> dict:
    ev = json.loads((out / "eval" / ("smoke.json" if (out / "eval" / "smoke.json").exists() else "results.json")).read_text())
    th_dir = out / "threshold"
    th_file = th_dir / ("smoke.json" if (th_dir / "smoke.json").exists() else "results.json")
    th = json.loads(th_file.read_text())["protocols"]["threshold"]
    p = ev["protocols"]
    alert = ev["recipe"]["threat_raised_threshold"]

    def at_alert(r):
        sweep = {s["line"]: s for s in r["score_rules"]["current"]["sweep"]}
        s = sweep.get(alert) or min(sweep.values(), key=lambda v: abs(v["line"] - alert))
        return {"attack_detection": s["attack_detection"], "benign_fpr": s["benign_fpr"]}

    summary = {
        "version": version, "model": model, "generated_at": datetime.now(timezone.utc).isoformat(),
        "smoke": bool(ev.get("smoke")),
        "random_split_train_py": meta.get("metrics"),
        "random": {k: p["random"][k] for k in ("accuracy", "f1_macro", "f1_weighted")},
        "chronological": {**{k: p["temporal"][k] for k in ("accuracy", "f1_macro", "f1_weighted")},
                          f"at_alert_line_{alert}": at_alert(p["temporal"])},
        "leave_one_day_out_detection": {d: r["attacks"].get("detection_rate_threat_raised") for d, r in p["lodo"].items()},
        "threshold_validation": {"selected_line": th["chosen_line"], "test_at_selected": th["test_at_chosen_line"],
                                 "conservative_line": th["conservative_line"]},
    }
    (out / "summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    md = [f"# Pipeline summary: {version} ({model})", "",
          f"- train.py random split (de-duplicated): {summary['random_split_train_py']}",
          f"- chronological: macro F1 {summary['chronological']['f1_macro']}, at alert line {alert}: "
          f"{summary['chronological'][f'at_alert_line_{alert}']}",
          f"- leave-one-day-out attack detection: {summary['leave_one_day_out_detection']}",
          f"- threshold validation selects {th['chosen_line']} (test: {th['test_at_chosen_line']})"]
    (out / "summary.md").write_text("\n".join(md) + "\n", encoding="utf-8")
    print("\n".join(md))
    return summary


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[1])
    ap.add_argument("--version", required=True, help="artifact version, e.g. cicids_v4")
    ap.add_argument("--model", choices=sorted(PREFIX), default="rf")
    ap.add_argument("--data", default=str(ENGINE_ROOT / "datasets" / "cicids2017"))
    ap.add_argument("--smoke", action="store_true", help="small, fast evaluation (pipeline check, not results)")
    ap.add_argument("--register", action="store_true", help="copy into models/ and register (golden set + history)")
    ap.add_argument("--note", default=None, help="reason recorded in models/registry_history.jsonl")
    args = ap.parse_args()

    out = ENGINE_ROOT / "experiments" / "pipeline" / args.version
    if (out / "models").exists():
        raise SystemExit(f"{out} already exists; choose a new --version")
    (out / "models").mkdir(parents=True)

    run([PY, "training/train.py", "--data", args.data, "--model-dir", out / "models", "--model", args.model,
         "--version", args.version])
    clf, ifo = f"{PREFIX[args.model]}_{args.version}.pkl", f"isolation_forest_{args.version}.pkl"
    meta = json.loads((out / "models" / f"{PREFIX[args.model]}_{args.version}_meta.json").read_text())

    smoke = ["--smoke"] if args.smoke else []
    run([PY, "evaluation/day_holdout_eval.py", "--data", args.data, "--classifier", args.model,
         "--protocols", "random,temporal,lodo", "--out", out / "eval", *smoke])
    run([PY, "evaluation/day_holdout_eval.py", "--data", args.data, "--classifier", args.model,
         "--protocols", "threshold", "--out", out / "threshold", *smoke])
    summarise(out, args.version, args.model, meta)

    if not args.register:
        print(f"\nNot registered. To serve it: python training/pipeline.py ... --register, or copy {clf} and {ifo} "
              f"into models/ and run training/register_model.py.")
        return
    if args.smoke:
        raise SystemExit("Refusing to register after a --smoke evaluation")
    models = ENGINE_ROOT / "models"
    for name in (clf, ifo, clf[:-4] + "_meta.json", ifo[:-4] + "_meta.json"):
        if (models / name).exists():
            raise SystemExit(f"Refusing to overwrite models/{name}")
        shutil.copy2(out / "models" / name, models / name)
    run([PY, "training/register_model.py", "--classifier", clf, "--type", args.model, "--anomaly", ifo,
         "--note", args.note or f"training/pipeline.py --version {args.version}"])
    print("Registered. POST /model/reload (or restart the engine) to serve it.")


if __name__ == "__main__":
    main()
