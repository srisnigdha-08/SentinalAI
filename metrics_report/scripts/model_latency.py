#!/usr/bin/env python3
"""Quiet-machine re-measurement of served-model load time and in-process inference latency (metrics audit).
Uses real CICIDS2017 rows (first 30k rows of two capture files). Read-only.
Run from repo root: ai-engine/.venv/Scripts/python.exe metrics_report/scripts/model_latency.py"""
import json
import subprocess
import sys
from pathlib import Path

import numpy as np

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "ai-engine")); sys.path.insert(0, str(REPO / "ai-engine" / "evaluation"))
sys.path.insert(0, str(Path(__file__).parent))
import day_holdout_eval as D  # noqa: E402
from ml_eval import latency  # noqa: E402
from utils.features import FEATURE_NAMES  # noqa: E402

ENGINE = REPO / "ai-engine"
# Cold load in fresh interpreters (3 runs), so import + unpickle are both counted
code = ("import time,joblib,json;t=time.perf_counter();import sys;sys.path.insert(0,'.');"
        "from inference.predictor import load_registry;from pathlib import Path;r=load_registry(Path('models'));"
        "c=joblib.load('models/'+r['classifier']['file']);i=joblib.load('models/'+r['anomaly']['file']);"
        "print(json.dumps(time.perf_counter()-t))")
cold = [float(subprocess.run([sys.executable, "-c", code], cwd=ENGINE, capture_output=True, text=True).stdout.strip().splitlines()[-1])
        for _ in range(3)]
import joblib  # noqa: E402
from inference.predictor import load_registry  # noqa: E402
reg = load_registry(ENGINE / "models")
clf = joblib.load(ENGINE / "models" / reg["classifier"]["file"]); ifo = joblib.load(ENGINE / "models" / reg["anomaly"]["file"])
frames = [D.load_file(ENGINE / "datasets/cicids2017" / f, 15000) for f in
          ("Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv", "Tuesday-WorkingHours.pcap_ISCX.csv")]
X = np.vstack([f[FEATURE_NAMES].to_numpy() for f in frames])
out = {"cold_load_seconds_including_imports": [round(x, 3) for x in cold], "rows_available": int(len(X)), **latency(clf, ifo, X)}
(REPO / "metrics_report/raw/model_latency_quiet.json").write_text(json.dumps(out, indent=1))
print(json.dumps(out, indent=1))
