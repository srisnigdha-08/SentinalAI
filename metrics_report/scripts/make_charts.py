#!/usr/bin/env python3
"""
Charts for the metrics report, drawn ONLY from measured/recorded JSON (no illustrative values).
Run with any Python that has matplotlib:  python metrics_report/scripts/make_charts.py
Inputs: metrics_report/raw/{ml_eval,api_bench,api_bench_run2,e2e_db_latency,db_metrics,resources_summary}.json,
        ai-engine/experiments/m5_xgboost_eval/results.json (existing evidence, LODO).
"""
import json
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
import numpy as np  # noqa: E402

REPO = Path(__file__).resolve().parents[2]
RAW = REPO / "metrics_report" / "raw"
OUT = REPO / "metrics_report" / "charts"
OUT.mkdir(parents=True, exist_ok=True)

SURFACE, INK, INK2, GRID = "#fcfcfb", "#0b0b0b", "#52514e", "#e4e3df"
S1, S2, S3 = "#2a78d6", "#eb6834", "#1baf7a"   # validated categorical slots 1-3
SEQ = ["#fcfcfb", "#cde2fb", "#9ec5f4", "#6da7ec", "#3987e5", "#256abf", "#184f95", "#0d366b"]
plt.rcParams.update({"figure.facecolor": SURFACE, "axes.facecolor": SURFACE, "axes.edgecolor": GRID,
                     "axes.labelcolor": INK2, "xtick.color": INK2, "ytick.color": INK2, "text.color": INK,
                     "font.size": 10, "axes.spines.top": False, "axes.spines.right": False,
                     "axes.grid": True, "grid.color": GRID, "grid.linewidth": 0.8, "axes.axisbelow": True})

ml = json.loads((RAW / "ml_eval.json").read_text())
B = ml["B_chronological"]
A = ml["A_served_random_split"]


def foot(fig, text):
    fig.text(0.01, -0.01, text, fontsize=7.5, color=INK2, ha="left", va="top", wrap=True)


def save(fig, name):
    fig.savefig(OUT / name, dpi=200, bbox_inches="tight")
    plt.close(fig)
    print("wrote", OUT / name)


# 1. Classifier vs Isolation Forest vs combined (binary attack-vs-benign, chronological test)
systems = [("XGBoost classifier alone", "classifier_alone", S1),
           ("Isolation Forest alone", "isolation_forest_alone", S2),
           ("Combined SentinelAI alert (score >= 0.90)", "combined_alert_line_0.9", S3)]
metrics = [("Accuracy", "accuracy"), ("Precision", "precision"), ("Recall", "recall"), ("F1", "f1")]
fig, ax = plt.subplots(figsize=(9, 4.6))
x = np.arange(len(metrics)); w = 0.26
for i, (label, key, col) in enumerate(systems):
    vals = [B["binary"][key][m] * 100 for _, m in metrics]
    bars = ax.bar(x + (i - 1) * w, vals, w - 0.03, color=col, label=label)
    for b, v in zip(bars, vals):
        ax.text(b.get_x() + b.get_width() / 2, v + 1, f"{v:.1f}", ha="center", va="bottom", fontsize=8, color=INK)
ax.set_xticks(x, [m for m, _ in metrics]); ax.set_ylim(0, 110); ax.set_ylabel("%")
ax.set_title("Binary intrusion detection: chronological CICIDS2017 test", loc="left", fontsize=12)
ax.legend(frameon=False, loc="upper center", bbox_to_anchor=(0.5, -0.1), ncol=3, fontsize=8.5)
foot(fig, f"Test: {B['n_test']:,} flows ({B['n_attack']:,} attack / {B['n_benign']:,} benign), latest 29% of every (file, class), "
          f"de-duplicated. Models retrained on earliest 70% with the served XGBoost recipe. Source: metrics_report/raw/ml_eval.json")
fig.subplots_adjust(bottom=0.18)
save(fig, "01_model_comparison_chronological.png")

# 2. Confusion matrix (chronological), row-normalised colour, raw counts printed
labels = B["multiclass"]["labels"]; cm = np.array(B["multiclass"]["confusion_matrix"])
rn = cm / cm.sum(1, keepdims=True)
fig, ax = plt.subplots(figsize=(9.5, 8))
from matplotlib.colors import LinearSegmentedColormap  # noqa: E402
cmap = LinearSegmentedColormap.from_list("seq", SEQ)
ax.imshow(rn, cmap=cmap, vmin=0, vmax=1); ax.grid(False)
for i in range(len(labels)):
    for j in range(len(labels)):
        if cm[i, j]:
            ax.text(j, i, f"{cm[i, j]:,}", ha="center", va="center", fontsize=7.5, color="white" if rn[i, j] > 0.55 else INK)
short = [l.replace(" Attempt", "").replace("Credential Stuffing", "Cred. Stuffing").replace("SSH Brute Force", "SSH Brute")
         .replace("Malware Beacon", "Beacon (Bot)").replace("Lateral Movement", "Lateral Mov.") for l in labels]
ax.set_xticks(range(len(labels)), short, rotation=40, ha="right"); ax.set_yticks(range(len(labels)), [f"{s} (n={cm[i].sum():,})" for i, s in enumerate(short)])
ax.set_xlabel("Predicted class"); ax.set_ylabel("True class")
ax.set_title("Confusion matrix, XGBoost recipe, chronological test (counts; shading = row %)", loc="left", fontsize=11)
foot(fig, "SQL Injection (7), RCE (4) and Lateral Movement (11) have too few test rows for reliable per-class figures. Source: ml_eval.json B_chronological")
save(fig, "02_confusion_matrix_chronological.png")

# 3. Per-attack-class detection (chronological)
det = B["per_attack_class_detection"]
order = sorted(det, key=lambda k: -det[k]["n"])
fig, ax = plt.subplots(figsize=(9, 5))
y = np.arange(len(order)); h = 0.38
v1 = [det[k]["correct_class"] * 100 for k in order]; v2 = [det[k]["alert_raised"] * 100 for k in order]
ax.barh(y - h / 2, v1, h - 0.04, color=S1, label="Recall (correct class)")
ax.barh(y + h / 2, v2, h - 0.04, color=S2, label="Alert raised (score >= 0.90)")
for yy, a, b in zip(y, v1, v2):
    ax.text(a + 1, yy - h / 2, f"{a:.1f}", va="center", fontsize=8); ax.text(b + 1, yy + h / 2, f"{b:.1f}", va="center", fontsize=8)
ax.set_yticks(y, [f"{k}  (n={det[k]['n']:,}){' *' if det[k]['n'] < 30 else ''}" for k in order]); ax.invert_yaxis()
ax.set_xlim(0, 112); ax.set_xlabel("% of that class's test flows")
ax.set_title("Detection by attack category, chronological CICIDS2017 test", loc="left", fontsize=12)
ax.legend(frameon=False, loc="upper center", bbox_to_anchor=(0.5, -0.12), ncol=2, fontsize=8.5)
foot(fig, "* fewer than 30 test flows: not statistically meaningful. Data Exfiltration has no CICIDS2017 data. Source: ml_eval.json")
save(fig, "03_attack_category_detection.png")

# 4. Protocol comparison: random vs chronological vs leave-one-day-out (existing evidence m5 + measured)
m5 = json.loads((REPO / "ai-engine/experiments/m5_xgboost_eval/results.json").read_text())["protocols"]
rows = [("Random 80/20\n(served artifact)", A["multiclass"]["f1_macro"], A["binary"]["combined_alert_line_0.9"]["recall"]),
        ("Chronological", B["multiclass"]["f1_macro"], B["binary"]["combined_alert_line_0.9"]["recall"])]
for day in ["Tuesday", "Wednesday", "Thursday", "Friday"]:
    d = m5["lodo"][day]; rows.append((f"Unseen day:\n{day}", d["f1_macro"], d["attacks"]["detection_rate_threat_raised"]))
fig, ax = plt.subplots(figsize=(10, 4.6))
x = np.arange(len(rows)); w = 0.36
b1 = ax.bar(x - w / 2, [r[1] * 100 for r in rows], w - 0.03, color=S1, label="Macro F1 (x100)")
b2 = ax.bar(x + w / 2, [r[2] * 100 for r in rows], w - 0.03, color=S2, label="Attack flows alerted (%)")
for bars in (b1, b2):
    for b in bars:
        ax.text(b.get_x() + b.get_width() / 2, b.get_height() + 1, f"{b.get_height():.1f}", ha="center", fontsize=8)
ax.set_xticks(x, [r[0] for r in rows], fontsize=8.5); ax.set_ylim(0, 110)
ax.set_title("How the evaluation split changes the result (XGBoost recipe)", loc="left", fontsize=12)
ax.legend(frameon=False, loc="upper right", fontsize=8.5)
foot(fig, "Random/chronological: measured here (ml_eval.json). Leave-one-day-out: existing run ai-engine/experiments/m5_xgboost_eval/results.json (2026-10-21).")
save(fig, "04_split_protocol_comparison.png")

# 5. Latency (two runs, p50 and p95)
r1 = json.loads((RAW / "api_bench.json").read_text()); r2 = json.loads((RAW / "api_bench_run2.json").read_text())
e2e = json.loads((RAW / "e2e_db_latency.json").read_text())
items = [("AI engine GET /health", "engine_health"), ("AI engine POST /predict/eval", "engine_predict_eval"),
         ("AI engine /predict/eval + SHAP", "engine_predict_eval_with_shap"), ("Backend GET /health", "backend_health"),
         ("Backend GET /api/threats", "backend_threats_list"), ("Backend POST /api/ai/analyze (end to end)", "backend_ai_analyze_end_to_end")]
fig, ax = plt.subplots(figsize=(9.5, 4.8))
y = np.arange(len(items) + 1)
def lat(r, k):
    v = r[k]; return v["latency_ms"] if "latency_ms" in v else v
for i, (lab, k) in enumerate(items):
    for r, mk in ((r1, "o"), (r2, "s")):
        L = lat(r, k)
        ax.plot([L["p50"], L["p95"]], [i, i], color=GRID, lw=2, zorder=1)
        ax.scatter([L["p50"]], [i], color=S1, s=40, marker=mk, zorder=2); ax.scatter([L["p95"]], [i], color=S2, s=40, marker=mk, zorder=2)
L = e2e["sent_to_threatlog_stored_ms"]
ax.plot([L["p50"], L["p95"]], [len(items), len(items)], color=GRID, lw=2); ax.scatter([L["p50"]], [len(items)], color=S1, s=40); ax.scatter([L["p95"]], [len(items)], color=S2, s=40)
ax.set_yticks(y, [l for l, _ in items] + ["Flow sent -> ThreatLog stored in MongoDB"]); ax.invert_yaxis()
ax.set_xlabel("milliseconds"); ax.set_title("Request latency on one laptop (p50 blue, p95 orange; circle = run 1, square = run 2)", loc="left", fontsize=11)
foot(fig, "i5-12500H, 16 logical CPUs, 7.7 GB RAM, Windows 11, all services on localhost, sequential requests (300 / 100 / 120 / 200). "
          "Sources: api_bench.json, api_bench_run2.json, e2e_db_latency.json")
save(fig, "05_latency.png")

# 6. Honeypot sessions from the real Cowrie test runs (local paramiko/OpenSSH clients, not internet attackers)
dbm = json.loads((RAW / "db_metrics.json").read_text())["databases"]
real = ["sentinel-honeypot-verify", "sentinel-cowrie-verify-20261022", "sentinel-runbook-verify-20261022", "sentinel-demo"]
cls = {}
for n in real:
    for k, v in dbm[n]["honeypot"]["classification"].items():
        if k in ("null", "None"):
            continue
        cls.setdefault(k, {}); cls[k][n] = v
names = sorted(cls, key=lambda k: -sum(cls[k].values()))
fig, ax = plt.subplots(figsize=(9, 4.3))
left = np.zeros(len(names)); cols = [S1, S2, S3, "#eda100"]
for n, c in zip(real, cols):
    vals = np.array([cls[k].get(n, 0) for k in names])
    ax.barh(names, vals, left=left, color=c, label=f"{n} ({dbm[n]['honeypot']['sessions']} sessions)", edgecolor=SURFACE, linewidth=2)
    left += vals
for i, t in enumerate(left):
    ax.text(t + 0.3, i, str(int(t)), va="center", fontsize=8.5)
ax.invert_yaxis(); ax.set_xlabel("sessions")
ax.set_title("Cowrie honeypot sessions by rule-based classification (local test runs)", loc="left", fontsize=11)
ax.legend(frameon=False, fontsize=7.5, loc="lower right")
foot(fig, "Verification runs only: real Cowrie sessions from local SSH clients (127.0.0.1 / WSL host), plus 10 API-injected test sessions in sentinel-honeypot-verify "
          "(203.0.113.x / fixture IPs). No internet attacker traffic. Source: db_metrics.json")
save(fig, "06_honeypot_sessions.png")

# 7. Resource usage during the benchmark
res = json.loads((RAW / "resources_summary.json").read_text())
fig, axs = plt.subplots(1, 2, figsize=(9, 3.6))
procs = [("python", "AI engine (uvicorn)"), ("node", "Backend (Node.js)")]
for ax, (metric, unit, keys) in zip(axs, [("CPU", "% of 16 logical CPUs", ("cpu_pct_mean", "cpu_pct_max")),
                                          ("Memory", "private bytes, MB", ("private_mb_mean", "private_mb_max"))]):
    x = np.arange(len(procs))
    for j, (k, c, lab) in enumerate(zip(keys, (S1, S2), ("mean", "max"))):
        v = [res[p][k] for p, _ in procs]
        bars = ax.bar(x + (j - 0.5) * 0.36, v, 0.33, color=c, label=lab)
        for b in bars:
            ax.text(b.get_x() + b.get_width() / 2, b.get_height(), f"{b.get_height():.1f}", ha="center", va="bottom", fontsize=8)
    ax.set_xticks(x, [l for _, l in procs]); ax.set_title(f"{metric} ({unit})", loc="left", fontsize=10)
axs[0].legend(frameon=False, fontsize=8)
foot(fig, "Sampled once per second during benchmark run 2 (Get-Process; memory = committed private bytes). mongod CPU could not be read without elevation. Source: resources_summary.json")
fig.subplots_adjust(bottom=0.2)
save(fig, "07_resource_usage.png")
