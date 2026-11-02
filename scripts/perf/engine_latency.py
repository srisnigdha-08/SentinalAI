r"""
Single-flow inference latency of the served AI engine (no model change; read-only use of the golden set).

Starts `uvicorn inference.main:app` on a free local port with a throwaway SENTINEL_KEY (generated, never printed),
waits for /ready, then sends N sequential POST /predict/internal requests built from models/golden_set.json vectors
(with and without ?explain=true for SHAP), and reports p50/p95/p99 latency, /health latency, time to ready and the
engine's resident memory. The engine process is stopped at the end.

  ai-engine\.venv\Scripts\python scripts\perf\engine_latency.py [--n 300] [--port 18300]
"""
import argparse, json, os, secrets, statistics, subprocess, sys, time, urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
ENGINE = ROOT / "ai-engine"
sys.path.insert(0, str(ENGINE))
from utils.features import FEATURE_NAMES  # noqa: E402


def post_json(url, key, body, timeout=30):
    r = urllib.request.Request(url, data=json.dumps(body).encode(), method="POST",
                               headers={"Content-Type": "application/json", "X-API-Key": key})
    with urllib.request.urlopen(r, timeout=timeout) as resp:
        return json.loads(resp.read())


def req(url, key=None, body=None, timeout=30):
    data = json.dumps(body).encode() if body is not None else None
    r = urllib.request.Request(url, data=data, method="POST" if body is not None else "GET",
                               headers={"Content-Type": "application/json", **({"X-API-Key": key} if key else {})})
    t = time.perf_counter()
    with urllib.request.urlopen(r, timeout=timeout) as resp:
        resp.read()
        status = resp.status
    return status, (time.perf_counter() - t) * 1000


def pct(xs, p):
    xs = sorted(xs)
    return round(xs[min(len(xs) - 1, int(round(p / 100 * (len(xs) - 1))))], 2)


def rss_mb(port):
    """Working set of the process that owns the listening port (on Windows the venv python.exe is a launcher whose
    child is the real interpreter, so the launcher's own PID would under-report)."""
    try:
        ps = (f"(Get-Process -Id (Get-NetTCPConnection -LocalPort {port} -State Listen | "
              f"Select-Object -First 1).OwningProcess).WorkingSet64")
        out = subprocess.run(["powershell", "-NoProfile", "-Command", ps],
                             capture_output=True, text=True, timeout=20).stdout.strip()
        return round(int(out) / 2**20, 1)
    except Exception:
        return None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--n", type=int, default=300)
    ap.add_argument("--port", type=int, default=18300)
    a = ap.parse_args()
    key = secrets.token_hex(32)
    env = {**os.environ, "SENTINEL_KEY": key, "SENTINEL_ADMIN_KEY": secrets.token_hex(32),
           "BACKEND_API": "http://127.0.0.1:9/api", "Q_TABLE_PATH": str(ENGINE / "runtime" / "perf_q_table_unused.json")}
    base = f"http://127.0.0.1:{a.port}"
    t0 = time.perf_counter()
    proc = subprocess.Popen([str(ENGINE / ".venv" / "Scripts" / "python.exe"), "-m", "uvicorn", "inference.main:app",
                             "--host", "127.0.0.1", "--port", str(a.port), "--log-level", "warning"],
                            cwd=ENGINE, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    try:
        ready = None
        while time.perf_counter() - t0 < 120:
            try:
                if req(base + "/ready")[0] == 200:
                    ready = round(time.perf_counter() - t0, 2)
                    break
            except Exception:
                time.sleep(0.25)
        if ready is None:
            sys.exit("engine did not become ready: " + proc.stderr.read(4000).decode(errors="replace") if proc.poll() is not None else "timeout")
        golden = json.loads((ENGINE / "models" / "golden_set.json").read_text(encoding="utf-8"))["vectors"]
        bodies = [{**dict(zip(FEATURE_NAMES, v)), "sourceIP": "198.51.100.77"} for v in golden]
        for b in bodies[:10]:  # warm-up, not measured
            req(base + "/predict/internal", key, b)
        rep = {"time_to_ready_s": ready, "n": a.n, "payload": "golden_set vectors (53 features), sequential, one client"}
        for label, path in (("predict", "/predict/internal"), ("predict_with_shap", "/predict/internal?explain=true")):
            lat, codes = [], set()
            for i in range(a.n):
                c, ms = req(base + path, key, bodies[i % len(bodies)])
                codes.add(c)
                lat.append(ms)
            rep[label] = {"status_codes": sorted(codes), "mean_ms": round(statistics.mean(lat), 2), "p50_ms": pct(lat, 50),
                          "p95_ms": pct(lat, 95), "p99_ms": pct(lat, 99), "max_ms": round(max(lat), 2)}
        # On-demand per-threat explanation (batch 11): the stored vector, as /predict/internal returns it
        stored = [post_json(base + "/predict/internal", key, b)["result"] for b in bodies]
        lat, codes, reproduced = [], set(), 0
        for i in range(a.n):
            r0 = stored[i % len(stored)]
            c, ms = req(base + "/explain/vector", key, {"featureVector": r0["featureVector"],
                                                        "featureSchemaVersion": r0["featureSchemaVersion"]})
            codes.add(c)
            lat.append(ms)
        for r0 in stored:
            e = post_json(base + "/explain/vector", key, {"featureVector": r0["featureVector"],
                                                           "featureSchemaVersion": r0["featureSchemaVersion"]})["result"]
            reproduced += int(e["predictedClass"] == r0["predictedClass"] and e["threatScore"] == r0["threatScore"])
        rep["explain_vector"] = {"status_codes": sorted(codes), "mean_ms": round(statistics.mean(lat), 2), "p50_ms": pct(lat, 50),
                                 "p95_ms": pct(lat, 95), "p99_ms": pct(lat, 99), "max_ms": round(max(lat), 2),
                                 "reproduced": f"{reproduced}/{len(stored)}"}
        # SHAP content check (not timed): how many golden flows come back with a non-empty explanation
        shap = [post_json(base + "/predict/internal?explain=true", key, b)["result"] for b in bodies]
        non_empty = [r for r in shap if r.get("featureImportance")]
        rep["shap"] = {"flows": len(shap), "with_feature_importance": len(non_empty),
                       "sample": {"class": non_empty[0].get("predictedClass") if non_empty else None,
                                  "top": non_empty[0]["featureImportance"][:3] if non_empty else None}}
        rep["predicted_classes"] = sorted({r.get("predictedClass") for r in shap})
        h = [req(base + "/health")[1] for _ in range(100)]
        rep["health"] = {"p50_ms": pct(h, 50), "p95_ms": pct(h, 95)}
        rep["engine_rss_mb_after"] = rss_mb(a.port)
        print(json.dumps(rep, indent=1))
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=15)
        except subprocess.TimeoutExpired:
            proc.kill()
        q = ENGINE / "runtime" / "perf_q_table_unused.json"
        if q.exists():
            q.unlink()


if __name__ == "__main__":
    main()
