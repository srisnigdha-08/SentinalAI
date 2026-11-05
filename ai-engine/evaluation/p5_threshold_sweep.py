"""
Descriptive threshold sweep for the served model on the P5 test split (inference only). Uses the served scoring
path (classifier + Isolation Forest, p5_served_model_eval.served_scores) and reports attack recall and benign FPR at
each candidate alert line. Descriptive only: choosing a line from this table would be tuning on the test split, so
any new operating line must be selected on a separate validation split (audit/ML_EVAL_PLAN.md).

  .venv/Scripts/python evaluation/p5_threshold_sweep.py [--out experiments/p5_served_eval_<date>]
"""
import argparse, json, sys
from pathlib import Path

import numpy as np

ENGINE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ENGINE))
from sklearn.model_selection import train_test_split  # noqa: E402

from evaluation.p5_served_model_eval import load_cicids_dir, served_scores, wilson  # noqa: E402
from inference import predictor as P  # noqa: E402
from training.train import drop_duplicate_rows  # noqa: E402
from utils.features import prepare_features  # noqa: E402

LINES = [0.50, 0.60, 0.70, 0.80, 0.85, 0.90, 0.92, 0.95, 0.97, 0.99, 0.995, 0.999]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", default=str(ENGINE / "datasets" / "cicids2017"))
    ap.add_argument("--out", default=str(ENGINE / "experiments" / "p5_served_eval_20261102"))
    args = ap.parse_args()
    pred = P.SentinelPredictor(model_dir=str(ENGINE / "models"))
    pred.load()
    X, y = prepare_features(load_cicids_dir(Path(args.data)), max_missing=0)
    X, y, _ = drop_duplicate_rows(X, y)
    _, X_test, _, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)
    labels, _, score, _, _, _ = served_scores(pred, X_test)
    attack = np.asarray(y_test) != 0
    flagged_cls = labels != 0
    rows = []
    for line in LINES:
        f = flagged_cls & (score >= line)
        tp, fp = int((f & attack).sum()), int((f & ~attack).sum())
        fn, tn = int((~f & attack).sum()), int((~f & ~attack).sum())
        rows.append({"line": line, "attack_recall": round(tp / (tp + fn), 4), "benign_fpr_pct": round(100 * fp / (fp + tn), 4),
                     "benign_fpr_ci95_pct": [round(100 * v, 3) for v in wilson(fp, fp + tn)], "fp": fp, "fn": fn})
    out = {"split": "P5 reconstructed test split (24,907 rows)", "served_lines": {"alert": P.MONITOR_THRESHOLD, "block": P.BLOCK_THRESHOLD},
           "note": "descriptive; do not pick an operating line from the test split", "sweep": rows}
    Path(args.out).mkdir(parents=True, exist_ok=True)
    (Path(args.out) / "threshold_sweep.json").write_text(json.dumps(out, indent=2), encoding="utf-8")
    for r in rows:
        print(f"line {r['line']:<6} recall {r['attack_recall']:.4f}  benign FPR {r['benign_fpr_pct']:.3f}%  fp {r['fp']:>3}  fn {r['fn']:>4}")


if __name__ == "__main__":
    main()
