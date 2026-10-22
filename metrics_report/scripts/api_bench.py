#!/usr/bin/env python3
"""
Local, non-destructive API latency benchmark (metrics audit 2026-10-22).

Targets services already running on loopback:
  AI engine  http://127.0.0.1:8000   GET /health, POST /predict/eval (documented side-effect free)
  Backend    http://127.0.0.1:5000   GET /health, POST /api/ai/analyze (stores predictions/threats in the
                                     database the backend was started with: use an isolated bench DB),
                                     GET /api/threats (authenticated list, exercises MongoDB)

Flows are real CICIDS2017 rows chosen by ai-engine/demo/replay_cicids.load_curated_sample; labels are kept
client-side only and compared after the response. Source IPs for the backend are RFC 5737 TEST-NET-2.
Load is low: sequential requests, plus one short 8-thread burst against /predict/eval only.

Env: SENTINEL_KEY (engine API key), BENCH_EMAIL / BENCH_PASSWORD (bench-DB analyst/admin) for backend phases.
Run: ai-engine/.venv/Scripts/python.exe metrics_report/scripts/api_bench.py [--skip-backend]
"""
import argparse
import json
import os
import statistics
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path

import requests

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "ai-engine" / "demo"))
import replay_cicids as RC  # noqa: E402

OUT = REPO / "metrics_report" / "raw"
DATA = REPO / "ai-engine" / "datasets" / "cicids2017"
FILES = ["Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv", "Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv",
         "Tuesday-WorkingHours.pcap_ISCX.csv", "Wednesday-workingHours.pcap_ISCX.csv",
         "Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv", "Friday-WorkingHours-Morning.pcap_ISCX.csv"]


def stats(ms):
    if not ms:
        return None
    s = sorted(ms)
    q = lambda p: s[min(len(s) - 1, int(round(p * (len(s) - 1))))]  # noqa: E731
    return {"n": len(s), "mean": round(statistics.fmean(s), 2), "p50": round(q(0.5), 2), "p95": round(q(0.95), 2),
            "p99": round(q(0.99), 2), "min": round(s[0], 2), "max": round(s[-1], 2)}


def timed(fn):
    t0 = time.perf_counter()
    try:
        r = fn()
        return (time.perf_counter() - t0) * 1000, r, None
    except Exception as e:  # noqa: BLE001
        return (time.perf_counter() - t0) * 1000, None, type(e).__name__


def run_get(url, n, **kw):
    ms, err = [], 0
    for _ in range(n):
        t, r, e = timed(lambda: requests.get(url, timeout=10, **kw))
        if e or r.status_code >= 400:
            err += 1
        ms.append(t)
    return {"latency_ms": stats(ms), "errors": err, "error_rate": round(err / n, 4)}


def flows(per_file):
    out = []
    for f in FILES:
        for item in RC.load_curated_sample(DATA / f, per_file):
            out.append({"file": f, "label": item["ground_truth_label"], "features": item["raw_features"]})
    return out


def is_attack_label(lbl):
    return str(lbl).strip().upper() != "BENIGN"


def replay(target_post, sample, ip_fn):
    ms, err, rows = [], 0, []
    for i, it in enumerate(sample):
        payload = dict(it["features"]); payload["sourceIP"] = ip_fn(i)
        payload["timestamp"] = datetime.now(timezone.utc).isoformat()
        sent = datetime.now(timezone.utc)
        t, r, e = timed(lambda: target_post(payload))
        ms.append(t)
        if e or r.status_code >= 400:
            err += 1; rows.append({"label": it["label"], "error": e or r.status_code}); continue
        body = r.json()
        res = body.get("result") or body.get("data", {}).get("result", {}) or {}
        rows.append({"label": it["label"], "file": it["file"], "sent": sent.isoformat(), "ms": round(t, 2),
                     "pred": res.get("predictedClass") or res.get("prediction"), "score": res.get("threatScore"),
                     "action": res.get("action"), "engine_ms": res.get("inferenceTimeMs") or res.get("processingTimeMs"),
                     "sourceIP": payload["sourceIP"]})
    ok = [x for x in rows if "error" not in x]
    att = [x for x in ok if is_attack_label(x["label"])]
    ben = [x for x in ok if not is_attack_label(x["label"])]
    pa = lambda x: x["pred"] not in (None, "BENIGN")  # noqa: E731
    summ = {"requests": len(sample), "errors": err, "error_rate": round(err / max(1, len(sample)), 4),
            "latency_ms": stats(ms), "engine_reported_inference_ms": stats([x["engine_ms"] for x in ok if isinstance(x.get("engine_ms"), (int, float))]),
            "replayed_attack_flows": len(att), "replayed_benign_flows": len(ben),
            "attack_flows_classified_attack": sum(pa(x) for x in att), "benign_flows_classified_attack": sum(pa(x) for x in ben),
            "actions": {a: sum(1 for x in ok if x["action"] == a) for a in sorted({str(x["action"]) for x in ok})},
            "labels": {l: sum(1 for x in ok if x["label"] == l) for l in sorted({x["label"] for x in ok})}}
    return summ, rows


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--engine", default="http://127.0.0.1:8000")
    ap.add_argument("--backend", default="http://127.0.0.1:5000")
    ap.add_argument("--per-file", type=int, default=50)
    ap.add_argument("--skip-backend", action="store_true")
    args = ap.parse_args()
    key = os.environ["SENTINEL_KEY"]
    H = {"X-API-Key": key, "Content-Type": "application/json"}
    report = {"generated_at": datetime.now(timezone.utc).isoformat(), "engine": args.engine, "backend": args.backend}

    sample = flows(args.per_file)
    report["sample"] = {"flows": len(sample), "per_file": args.per_file, "files": FILES}
    print(f"sample: {len(sample)} flows", flush=True)

    # ── AI engine
    report["engine_health"] = run_get(f"{args.engine}/health", 300)
    print("engine /health", report["engine_health"], flush=True)
    for it in sample[:20]:  # warm-up
        requests.post(f"{args.engine}/predict/eval", json=dict(it["features"], sourceIP="192.0.2.1"), headers=H, timeout=10)
    s, rows = replay(lambda p: requests.post(f"{args.engine}/predict/eval", json=p, headers=H, timeout=10), sample,
                     lambda i: f"192.0.2.{(i % 254) + 1}")
    report["engine_predict_eval"] = s
    print("engine /predict/eval", json.dumps(s), flush=True)
    s2, _ = replay(lambda p: requests.post(f"{args.engine}/predict/eval?explain=true", json=p, headers=H, timeout=30),
                   sample[:100], lambda i: f"192.0.2.{(i % 254) + 1}")
    report["engine_predict_eval_with_shap"] = s2
    print("engine /predict/eval?explain=true", json.dumps(s2["latency_ms"]), flush=True)
    # 8-thread burst, 1,000 requests, to estimate sustainable throughput on this machine
    burst = (sample * 10)[:1000]
    def one(it):
        t, r, e = timed(lambda: requests.post(f"{args.engine}/predict/eval", json=dict(it["features"], sourceIP="192.0.2.9"), headers=H, timeout=30))
        return t, (e is None and r.status_code < 400)
    t0 = time.perf_counter()
    with ThreadPoolExecutor(8) as ex:
        res = list(ex.map(one, burst))
    wall = time.perf_counter() - t0
    report["engine_predict_eval_concurrency8"] = {"requests": len(burst), "wall_seconds": round(wall, 2),
                                                  "requests_per_second": round(len(burst) / wall, 1),
                                                  "errors": sum(1 for _, ok in res if not ok),
                                                  "latency_ms": stats([t for t, _ in res])}
    print("engine burst", report["engine_predict_eval_concurrency8"], flush=True)
    (OUT / "engine_replay_rows.json").write_text(json.dumps(rows, indent=1))

    # ── Backend (bench DB)
    if not args.skip_backend:
        report["backend_health"] = run_get(f"{args.backend}/health", 300)
        print("backend /health", report["backend_health"], flush=True)
        bt = RC.BackendTarget(args.backend, os.environ["BENCH_EMAIL"], os.environ["BENCH_PASSWORD"], "http://localhost:3000")
        t, _, e = timed(bt.login)
        report["backend_login_ms"] = round(t, 2)
        bsample = sample[: min(len(sample), 120)]
        s3, rows3 = replay(bt.analyze, bsample, lambda i: f"198.51.100.{(i % 254) + 1}")
        report["backend_ai_analyze_end_to_end"] = s3
        print("backend /api/ai/analyze", json.dumps(s3), flush=True)
        (OUT / "backend_replay_rows.json").write_text(json.dumps(rows3, indent=1))
        report["backend_threats_list"] = run_get(f"{args.backend}/api/threats?limit=20", 200, headers=bt._auth())
        print("backend GET /api/threats", report["backend_threats_list"], flush=True)

    (OUT / "api_bench.json").write_text(json.dumps(report, indent=1))
    print("wrote", OUT / "api_bench.json")


if __name__ == "__main__":
    main()
