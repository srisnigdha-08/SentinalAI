r"""
In-process single-row timing of the served models with their saved n_jobs (-1, all cores) versus n_jobs=1, and a
check that both settings give bit-identical outputs. Read-only: models are loaded from models/, never written.

  ai-engine\.venv\Scripts\python scripts\perf\njobs_breakdown.py
"""
import json, sys, time
from pathlib import Path

import numpy as np

ENGINE = Path(__file__).resolve().parents[2] / "ai-engine"
sys.path.insert(0, str(ENGINE))
from inference.predictor import SentinelPredictor  # noqa: E402
from utils.features import FEATURE_NAMES, extract_features_from_record  # noqa: E402


def timed(fn, rows, reps=5):
    out, t = [], []
    for _ in range(reps):
        for x in rows:
            s = time.perf_counter()
            out.append(fn(x))
            t.append((time.perf_counter() - s) * 1000)
    t.sort()
    return out, {"p50_ms": round(t[len(t) // 2], 2), "p95_ms": round(t[int(len(t) * 0.95)], 2), "mean_ms": round(sum(t) / len(t), 2)}


def main():
    p = SentinelPredictor(model_dir=str(ENGINE / "models"))
    golden = json.loads((ENGINE / "models" / "golden_set.json").read_text(encoding="utf-8"))["vectors"]
    rows = [extract_features_from_record(dict(zip(FEATURE_NAMES, v))).reshape(1, -1) for v in golden]
    xgb = p.clf.named_steps["xgb"]
    xgb = getattr(xgb, "model_", xgb)
    ifo = p.ifo.named_steps["if"]
    rep = {}
    for label, nj in (("saved n_jobs=-1", -1), ("n_jobs=1", 1)):
        xgb.set_params(n_jobs=nj)
        ifo.set_params(n_jobs=nj)
        clf_out, clf_t = timed(lambda x: p.rf.predict_proba(x), rows)
        if_out, if_t = timed(lambda x: p.ifo.named_steps["if"].score_samples(p.ifo.named_steps["scaler"].transform(x)), rows)
        full_out, full_t = timed(lambda x: p.predict(dict(zip(FEATURE_NAMES, x.reshape(-1).tolist()))), rows)
        rep[label] = {"classifier": clf_t, "isolation_forest": if_t, "full_predict": full_t,
                      "_out": (np.vstack(clf_out), np.concatenate(if_out), [(r["predictedClass"], r["threatScore"]) for r in full_out])}
    a, b = rep["saved n_jobs=-1"].pop("_out"), rep["n_jobs=1"].pop("_out")
    rep["identical_outputs"] = {"classifier_probabilities": bool(np.array_equal(a[0], b[0])),
                                "isolation_forest_scores": bool(np.array_equal(a[1], b[1])),
                                "class_and_threat_score": a[2] == b[2]}
    print(json.dumps(rep, indent=1))


if __name__ == "__main__":
    main()
