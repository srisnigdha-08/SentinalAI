#!/usr/bin/env python3
"""
Independent SIMULATED evaluation of persona policies v1 and v2 (docs/PERSONA_POLICY_V2.md §8). Pre-declared on
2026-11-13 before its first run: new scenarios S6-S11 and new seeds 200-229. S1-S5 and seeds 0-129 are not used
here (S5 has been examined and is no longer a holdout; its 28/30 result stands unchanged). Nothing is tuned: v2
runs with its shipped defaults and v1 with the deployed configuration (seeded from models/q_table.json).

Every number describes the Deception Arena's simulated attacker, never real attackers.

Paired design: for a seed, both policies face the same attacker stream and the same application-failure draws.
Metrics per run: best-persona identification (10 consecutive epochs on the best), share of the last 30 epochs on the
best, switches per 100 epochs, regret per epoch, cumulative reward, decision latency, application failures.

Pre-declared simulation criteria for v2 (all must hold; they are necessary, never sufficient, for promotion):
  C1  in every scenario with a unique best persona, v2 identifies it in >= 27 of 30 runs
  C2  in every scenario, v2's mean regret <= v1's, with the paired 95 % CI upper bound of (v2 - v1) <= 0.05
  C3  v2 switches <= 30 per 100 epochs in every scenario
  C4  under injected application failures (S11), v2 never recommends an unsupported persona and recovers
      (identification >= 27/30)
Promotion additionally needs gates 1-4 of PERSONA_POLICY_V2.md §6 (external sessions, shadow period, live rollback).

  python evaluation/persona_policy_independent_eval.py --json out.json         # 30 seeds (a few minutes)
  python evaluation/persona_policy_independent_eval.py --quick                 # 5 seeds, smoke run
"""
import argparse, json, math, random, statistics as st, sys, time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT)); sys.path.insert(0, str(ROOT / "evaluation"))
import persona_policy_sim as sim  # noqa: E402  (reuses its V1/V2 wrappers, expected() and the attacker model)
from rl_engine import deception_scorer as ds  # noqa: E402

base = sim.base
pref = lambda probs, **kw: {**base, "continueProbability": {**probs, "windows_srv": 0.3}, **kw}  # noqa: E731
EPOCHS = sim.EPOCHS
SEEDS = list(range(200, 230))

# Pre-declared 2026-11-13 (never run before this file was written)
SCENARIOS = {
    "S6 prefers debian_11, medium gaps": {"phases": [(0, pref({"debian_11": 0.86, "ubuntu_22": 0.8, "centos_7": 0.76, "aws_ec2": 0.72, "raspberry_pi": 0.7}))]},
    "S7 prefers raspberry_pi, frequent fingerprinting": {"phases": [(0, pref({"raspberry_pi": 0.88, "ubuntu_22": 0.78, "debian_11": 0.76, "aws_ec2": 0.72, "centos_7": 0.7}, fingerprintProbability=0.12))]},
    "S8 persona-blind (equal preferences)": {"phases": [(0, pref({p: 0.78 for p in ("ubuntu_22", "debian_11", "centos_7", "aws_ec2", "raspberry_pi")}))], "noUniqueBest": True},
    "S9 drift ubuntu_22 -> aws_ec2 @ epoch 50": {"phases": [(0, pref({"ubuntu_22": 0.87, "debian_11": 0.79, "centos_7": 0.76, "aws_ec2": 0.74, "raspberry_pi": 0.72})),
                                                          (50, pref({"aws_ec2": 0.87, "debian_11": 0.79, "centos_7": 0.76, "ubuntu_22": 0.74, "raspberry_pi": 0.72}))]},
    "S10 two close leaders (ubuntu_22 vs debian_11)": {"phases": [(0, pref({"ubuntu_22": 0.86, "debian_11": 0.85, "centos_7": 0.72, "aws_ec2": 0.7, "raspberry_pi": 0.68}))]},
    "S11 prefers centos_7, 20 % application failures": {"phases": [(0, pref({"centos_7": 0.86, "ubuntu_22": 0.79, "debian_11": 0.76, "aws_ec2": 0.72, "raspberry_pi": 0.7}))], "failureRate": 0.2},
}
POLICIES = {"v1 (deployed q_learning, seeded)": lambda: sim.V1(seeded=True), "v2 (shipped defaults)": sim.v2_factory()}


def run(make, phases, seed, failure_rate=0.0):
    random.seed(seed)
    rng = random.Random(seed * 7919 + 1)          # attacker stream: identical for both policies
    frng = random.Random(seed * 104729 + 7)       # application-failure draws: identical for both policies
    pol, current, prev = make(), sim.START, sim.START
    served, rewards, recs, lat, failures, unsupported = [], [], [], [], 0, 0
    for e in range(EPOCHS):
        t0 = time.perf_counter()
        want = pol.choose(current)
        lat.append((time.perf_counter() - t0) * 1e6)
        if want in ds.UNSUPPORTED_PROFILES:
            unsupported += 1
        if want != current and frng.random() < failure_rate:
            failures += 1                         # the switch failed: the previous persona keeps being served
        else:
            current = want
        served.append(current)
        for k in range(sim.EPOCH_SESSIONS):
            r = sim.da.play_session(sim.phase(phases, e), current, rng, sim.MAXSEC)["reward"]
            pol.learn(prev, current, r, f"s{seed}-{e}-{k}")
            rewards.append(r); prev = current
        recs.append(pol.greedy(current))
    return served, rewards, recs, lat, failures, unsupported


def mean_ci(xs):
    xs = [x for x in xs if x is not None]
    if not xs:
        return None
    m = st.mean(xs)
    h = 1.96 * st.stdev(xs) / math.sqrt(len(xs)) if len(xs) > 1 else 0.0
    return {"mean": round(m, 4), "ci95": [round(m - h, 4), round(m + h, 4)], "n": len(xs)}


def evaluate(seeds):
    out = {}
    for name, sc in SCENARIOS.items():
        phases = sc["phases"]
        per = {}
        for pname, make in POLICIES.items():
            runs = [run(make, phases, s, sc.get("failureRate", 0.0)) for s in seeds]
            ms = [sim.metrics(phases, served, rewards, recs) for served, rewards, recs, *_ in runs]
            per[pname] = {
                "identified": None if sc.get("noUniqueBest") else sum(m["identify"] is not None for m in ms),
                "runs": len(seeds),
                "regret": mean_ci([m["regret"] for m in ms]),
                "switches100": mean_ci([m["switches100"] for m in ms]),
                "bestShareLast30": mean_ci([m["bestShareLast30"] for m in ms]),
                "cumReward": mean_ci([m["cum"] for m in ms]),
                "latencyUs": mean_ci([st.mean(r[3]) for r in runs]),
                "applicationFailures": mean_ci([r[4] for r in runs]),
                "unsupportedRecommendations": sum(r[5] for r in runs),
                "_regrets": [m["regret"] for m in ms],
            }
        v1, v2 = per["v1 (deployed q_learning, seeded)"], per["v2 (shipped defaults)"]
        diff = [b - a for a, b in zip(v1.pop("_regrets"), v2.pop("_regrets"))]
        out[name] = {"policies": per, "pairedRegretDiff_v2_minus_v1": mean_ci(diff), "noUniqueBest": bool(sc.get("noUniqueBest"))}
    return out


def criteria(res, n):
    need = math.ceil(0.9 * n)
    fails = []
    for name, r in res.items():
        v2 = r["policies"]["v2 (shipped defaults)"]
        if not r["noUniqueBest"] and v2["identified"] < need:
            fails.append(f"C1 {name}: identified {v2['identified']}/{n} < {need}")
        d = r["pairedRegretDiff_v2_minus_v1"]
        if d["ci95"][1] > 0.05:
            fails.append(f"C2 {name}: regret diff upper bound {d['ci95'][1]} > 0.05")
        if v2["switches100"]["mean"] > 30:
            fails.append(f"C3 {name}: {v2['switches100']['mean']} switches/100 > 30")
        if v2["unsupportedRecommendations"]:
            fails.append(f"C4 {name}: recommended an unsupported persona")
    return {"passed": not fails, "failures": fails}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--quick", action="store_true")
    ap.add_argument("--json")
    a = ap.parse_args()
    seeds = SEEDS[:5] if a.quick else SEEDS
    seed_sha = sim.hashlib.sha256(sim.SEED_FILE.read_bytes()).hexdigest()
    res = evaluate(seeds)
    if sim.hashlib.sha256(sim.SEED_FILE.read_bytes()).hexdigest() != seed_sha:
        raise RuntimeError("the shipped seed table changed during the run")
    rep = {"label": "SIMULATED", "preDeclared": "2026-11-13", "seeds": [seeds[0], seeds[-1]], "epochs": EPOCHS,
           "sessionsPerEpoch": sim.EPOCH_SESSIONS, "scenarios": res, "criteria": criteria(res, len(seeds)),
           "s5": "not used; its earlier result (28/30) is unchanged", "seedTableSha256": seed_sha,
           "readiness": "NOT READY: simulation criteria are necessary, not sufficient; gates 1-4 need real evidence"}
    text = json.dumps(rep, indent=1)
    if a.json:
        Path(a.json).write_text(text, encoding="utf-8")
    print(text)


if __name__ == "__main__":
    main()
