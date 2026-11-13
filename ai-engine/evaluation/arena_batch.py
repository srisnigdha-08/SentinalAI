#!/usr/bin/env python3
"""
SIMULATED static-vs-adaptive comparison across Deception Arena attacker profiles (docs/DECEPTION_ARENA.md).

For every profile it runs R independent replications (different seeds) of P paired trials through the real Arena
runner (demo/deception_arena.run): the learner is a temporary copy of the shipped seed, never saved, and the runner
itself verifies that the seed and repository runtime tables did not change. This script additionally checks the
operator's live demo Q-table and v2 shadow state (if present) by SHA-256 before and after.

Pre-declared (2026-11-13) analysis:
  * per pair: adaptive minus static, for duration, command depth (commands), interaction diversity (distinct
    commands), persona recognition (fingerprinted), reward; switches are counted on the adaptive arm
  * mean paired difference with a 95 % bootstrap interval (10,000 resamples, seed 7) and the paired effect size dz
  * "statistically meaningful": the interval excludes 0
  * "practically meaningful": also |mean difference| >= 10 % of the static mean (5 percentage points for rates)
  * resource overhead: the learner's decision + update time per adaptive trial (microbenchmark on a copy)
Every row is labelled SIMULATED and evidenceSource=simulated: it describes the simulator's ASSUMED attacker
parameters, never real attackers.

  python evaluation/arena_batch.py --pairs 50 --replications 4 --json out.json
"""
import argparse, hashlib, json, os, random, statistics as st, sys, tempfile, time
from pathlib import Path

import numpy as np

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT)); sys.path.insert(0, str(ROOT / "demo"))
import deception_arena as da  # noqa: E402
from rl_engine.deception_scorer import DeceptionQLearner  # noqa: E402

PROFILES = list(da.PROFILE_SCENARIOS) + ["persona_sensitive_sim"]
BASELINE = "centos_7"   # the persona the shipped cowrie.cfg serves (static arm)
METRICS = ("durationSeconds", "depth", "diversity", "fingerprinted", "reward")
RATES = {"fingerprinted"}


def _live_paths():
    home = Path(os.environ.get("USERPROFILE") or Path.home())
    return [home / ".sentinelai" / "demo" / "q_table.json", home / ".sentinelai" / "demo" / "persona_policy_v2.json"]


def _hashes(paths):
    return {str(p): hashlib.sha256(p.read_bytes()).hexdigest() if p.exists() else None for p in paths}


def bootstrap(d, n=10_000, seed=7):
    d = np.asarray(d, float)
    rng = np.random.default_rng(seed)
    means = d[rng.integers(0, len(d), size=(n, len(d)))].mean(axis=1)
    return [round(float(np.percentile(means, 2.5)), 4), round(float(np.percentile(means, 97.5)), 4)]


def collect(profile, pairs, replications, seed0):
    rows = []
    for rep in range(replications):
        trials = []
        da.run({"scenario": profile, "baselinePersona": BASELINE, "trialsPerStrategy": pairs, "maxTrialSeconds": 1800,
                "seed": seed0 + rep}, on_trial=lambda t: trials.append(t) and False)
        by = {}
        for t in trials:
            by.setdefault(t["index"], {})[t["strategy"]] = t
        prev = BASELINE
        for i in sorted(by):
            s, a = by[i]["STATIC"], by[i]["ADAPTIVE"]
            rows.append({"replication": rep, "pair": i, "switch": a["persona"] != prev, "adaptivePersona": a["persona"],
                         **{f"static_{k}": v for k, v in _m(s).items()}, **{f"adaptive_{k}": v for k, v in _m(a).items()}})
            prev = a["persona"]
    return rows


def _m(t):
    cmds = [c["command"] for c in t["commands"]]
    return {"durationSeconds": t["durationSeconds"], "depth": len(cmds), "diversity": len(set(cmds)),
            "fingerprinted": int(bool(t["fingerprinted"])), "reward": t["reward"]}


def analyse(rows):
    out = {}
    for k in METRICS:
        s = [r[f"static_{k}"] for r in rows]
        a = [r[f"adaptive_{k}"] for r in rows]
        d = [x - y for x, y in zip(a, s)]
        mean_d, sd = st.mean(d), (st.stdev(d) if len(d) > 1 else 0.0)
        ci = bootstrap(d)
        base = st.mean(s)
        practical = abs(mean_d) >= (0.05 if k in RATES else 0.10 * abs(base) if base else 0)
        out[k] = {"static": round(base, 4), "adaptive": round(st.mean(a), 4), "meanDiff": round(mean_d, 4), "ci95": ci,
                  "dz": round(mean_d / sd, 3) if sd else None,
                  "statisticallyMeaningful": not (ci[0] <= 0 <= ci[1]),
                  "practicallyMeaningful": bool(practical and not (ci[0] <= 0 <= ci[1]))}
    out["switchesPer100"] = round(100 * sum(r["switch"] for r in rows) / len(rows), 2)
    out["adaptivePersonaShare"] = {p: round(sum(r["adaptivePersona"] == p for r in rows) / len(rows), 3)
                                   for p in sorted({r["adaptivePersona"] for r in rows})}
    return out


def overhead_us(n=2000):
    with tempfile.TemporaryDirectory() as d:
        L = DeceptionQLearner(q_table_path=str(Path(d) / "q.json"))
        L.save = lambda: None
        random.seed(0)
        t0 = time.perf_counter()
        state = BASELINE
        for i in range(n):
            a = L.choose_action(state)
            L.update(state, a, 1.0, a)
            state = a
        return round((time.perf_counter() - t0) / n * 1e6, 2)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--pairs", type=int, default=50)
    ap.add_argument("--replications", type=int, default=4)
    ap.add_argument("--seed", type=int, default=1000)
    ap.add_argument("--profiles", default=",".join(PROFILES))
    ap.add_argument("--json")
    a = ap.parse_args()
    live = _live_paths()
    before = _hashes(live)
    report = {"label": "SIMULATED", "evidenceSource": "simulated", "preDeclared": "2026-11-13", "baselinePersona": BASELINE,
              "pairsPerReplication": a.pairs, "replications": a.replications, "seed0": a.seed, "profiles": {}}
    for p in a.profiles.split(","):
        rows = collect(p, a.pairs, a.replications, a.seed)
        report["profiles"][p] = {"title": da.SCENARIOS[p]["title"], "kind": da.SCENARIOS[p]["kind"], "pairs": len(rows), **analyse(rows)}
    report["decisionOverheadMicroseconds"] = overhead_us()
    after = _hashes(live)
    if before != after:
        raise RuntimeError("live demo Q-table or v2 state changed during the run")
    report["isolation"] = {"liveStateUnchanged": True, "liveFilesChecked": sum(v is not None for v in before.values())}
    text = json.dumps(report, indent=1)
    if a.json:
        Path(a.json).write_text(text, encoding="utf-8")
    print(text)


if __name__ == "__main__":
    main()
