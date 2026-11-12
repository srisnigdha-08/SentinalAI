#!/usr/bin/env python3
"""
SIMULATED comparison of persona-selection policies (docs/PERSONA_POLICY_V2.md). Every number this prints describes
the Deception Arena's simulated attacker (assumed persona preferences), never real attackers.

It drives the real code unchanged: deception_scorer.DeceptionQLearner / calc_reward (v1), rl_engine.persona_policy_v2
(v2) and demo/deception_arena.play_session (the attacker). Learners run on in-memory copies (save() disabled); the
shipped seed models/q_table.json is only read, and its SHA-256 is checked before and after.

Decisions are made per rotation EPOCH (one persona served for EPOCH_SESSIONS sessions, like the rotator's interval);
learning is per session. Paired design: for a given seed every policy faces the same attacker random stream.
Tuning uses seeds 0-9; reported results use held-out seeds 100-129.

  python evaluation/persona_policy_sim.py                # full run (a few minutes)
  python evaluation/persona_policy_sim.py --quick        # 5 seeds, smoke run
"""
import argparse, copy, hashlib, json, math, os, random, statistics as st, sys, tempfile, time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
os.environ.setdefault("SENTINEL_TEST_MODE", "1")
os.environ.setdefault("DEFAULT_RUNTIME_Q_TABLE_PATH", str(Path(tempfile.mkdtemp()) / "unused.json"))
sys.path.insert(0, str(ROOT)); sys.path.insert(0, str(ROOT / "demo"))
from rl_engine import deception_scorer as ds  # noqa: E402
from rl_engine.persona_policy_v2 import PersonaPolicyV2, prior_from_q_table  # noqa: E402
import deception_arena as da  # noqa: E402

SEED_FILE = ROOT / "models" / "q_table.json"
SEED = json.loads(SEED_FILE.read_text())
SERVABLE = ds.servable_profiles()
EPOCH_SESSIONS, EPOCHS, DRIFT_AT, MAXSEC, START = 4, 150, 75, 600, "centos_7"
base = da.SCENARIOS["persona_sensitive_sim"]
pref = lambda order: {**base, "continueProbability": dict(zip(order, (0.88, 0.8, 0.72, 0.7, 0.62)), windows_srv=0.3)}
SCENARIOS = {
    "S1 prefers raspberry_pi (Arena sim)": [(0, base)],
    "S2 prefers centos_7 (agrees with seed)": [(0, pref(["centos_7", "ubuntu_22", "debian_11", "aws_ec2", "raspberry_pi"]))],
    "S3 persona-blind (scripted)": [(0, da.SCENARIOS["scripted_recon"])],
    "S4 drift raspberry_pi -> centos_7 @ epoch 75": [(0, base), (DRIFT_AT, pref(["centos_7", "ubuntu_22", "debian_11", "aws_ec2", "raspberry_pi"]))],
}


# ── policies behind one interface: choose(current) per epoch, learn(prev, persona, reward, sid) per session ──────
class V1:
    def __init__(self, seeded, epsilon_from_real=False, rescale=1.0, ucb=False):
        self.L = ds.DeceptionQLearner(q_table_path=str(Path(tempfile.mkdtemp()) / "none.json"))
        self.L.save = lambda: None
        self.L.policy = "ucb1" if ucb else "q_learning"
        if seeded:
            self.L.q_table = ds.DeceptionQLearner._fill_missing({s: {a: v * rescale for a, v in r.items()}
                                                                 for s, r in copy.deepcopy(SEED["q_table"]).items()})
            self.L.episode_count = 0 if epsilon_from_real else SEED["episode_count"]
    def choose(self, current): return self.L.choose_action(current)
    def learn(self, prev, persona, reward, sid): self.L.update(prev, persona, reward, persona)
    def greedy(self, current): return self.L.greedy_action(current)


class V2:
    def __init__(self, **params):
        prior_w = params.pop("prior_weight", 1.0)
        self.P = PersonaPolicyV2(Path(tempfile.mkdtemp()) / "v2.json", prior_means=prior_from_q_table(SEED["q_table"]),
                                 prior_source="sim", prior_episodes=SEED["episode_count"], prior_weight=prior_w, **params)
    def choose(self, current): return self.P.recommend(current)
    def learn(self, prev, persona, reward, sid): self.P.observe(sid, persona, reward, persist=False)
    def greedy(self, current): return self.P.greedy()


def v2_factory(**kw):
    return lambda: V2(**kw)


EXP = {}
def expected(scen, persona):
    k = (id(scen), persona)
    if k not in EXP:
        rng = random.Random(12345)
        EXP[k] = st.mean(da.play_session(scen, persona, rng, MAXSEC)["reward"] for _ in range(3000))
    return EXP[k]


def phase(phases, epoch):
    return [s for start, s in phases if epoch >= start][-1]


def run(make, phases, seed):
    random.seed(seed)                       # v1 exploration draws
    rng = random.Random(seed * 7919 + 1)    # attacker stream (same for every policy: paired)
    pol, current, prev = make(), START, START
    served, rewards, recs, t0, n_ops = [], [], [], time.perf_counter(), 0
    for e in range(EPOCHS):
        current = pol.choose(current); n_ops += 1
        served.append(current)
        for k in range(EPOCH_SESSIONS):
            r = da.play_session(phase(phases, e), current, rng, MAXSEC)["reward"]
            pol.learn(prev, current, r, f"s{seed}-{e}-{k}"); n_ops += 1
            rewards.append(r); prev = current
        recs.append(pol.greedy(current))
    return served, rewards, recs, (time.perf_counter() - t0) / n_ops * 1e6


def metrics(phases, served, rewards, recs):
    best = lambda e: max(SERVABLE, key=lambda p: expected(phase(phases, e), p))
    regret = st.mean(expected(phase(phases, e), max(SERVABLE, key=lambda p: expected(phase(phases, e), p))) -
                     expected(phase(phases, e), served[e]) for e in range(EPOCHS))
    switches = sum(served[e] != served[e - 1] for e in range(1, EPOCHS))
    bad_switch = sum(served[e] != served[e - 1] and served[e - 1] == best(e) for e in range(1, EPOCHS))
    start = phases[-1][0]
    def identify(hold=10):
        run_len = 0
        for e in range(start, EPOCHS):
            run_len = run_len + 1 if served[e] == best(e) else 0
            if run_len == hold:
                return e - hold + 1 - start
        return None
    share = {p: served.count(p) / EPOCHS for p in SERVABLE}
    ent = -sum(v * math.log(v) for v in share.values() if v > 0) / math.log(len(SERVABLE))
    first_cov = next((e for e in range(EPOCHS) if len(set(served[:e + 1])) == len(SERVABLE)), None)
    return {"cum": sum(rewards), "regret": regret, "switches100": switches * 100 / (EPOCHS - 1), "awayFromBest": bad_switch,
            "coverage": len(set(served)), "firstFullCov": first_cov, "identify": identify(), "entropy": ent,
            "bestShareLast30": served[-30:].count(best(EPOCHS - 1)) / 30, "stabilityLast30": sum(served[e] != served[e - 1] for e in range(EPOCHS - 30, EPOCHS))}


def ci(xs):
    xs = [x for x in xs if x is not None]
    if not xs:
        return "n/a"
    m = st.mean(xs); h = 1.96 * st.stdev(xs) / math.sqrt(len(xs)) if len(xs) > 1 else 0.0
    return f"{m:.2f}±{h:.2f}"


def evaluate(policies, seeds, scenarios=SCENARIOS, show=True):
    table = {}
    for sname, phases in scenarios.items():
        if show:
            best0 = max(SERVABLE, key=lambda p: expected(phases[-1][1], p))
            print(f"\n### {sname}   [SIMULATED; best persona{' after drift' if len(phases) > 1 else ''}: {best0}; "
                  f"{len(seeds)} paired seeds; {EPOCHS} epochs x {EPOCH_SESSIONS} sessions]")
            print(f"  {'policy':<38}{'cum reward':>16}{'regret/sess':>14}{'switch/100ep':>15}{'identify(ep)':>20}"
                  f"{'cov':>5}{'1st full cov':>15}{'entropy':>13}{'best share L30':>16}{'us/op':>7}")
        for pname, make in policies.items():
            rows = [run(make, phases, s) for s in seeds]
            ms = [metrics(phases, *r[:3]) for r in rows]
            ident = [m["identify"] for m in ms]
            table[(sname, pname)] = ms
            if show:
                found = sum(i is not None for i in ident)
                print(f"  {pname:<38}{ci([m['cum'] for m in ms]):>16}{ci([m['regret'] for m in ms]):>14}"
                      f"{ci([m['switches100'] for m in ms]):>15}{(ci(ident) + f' ({found}/{len(seeds)})') if found else f'never (0/{len(seeds)})':>20}"
                      f"{st.mean(m['coverage'] for m in ms):>5.1f}{ci([m['firstFullCov'] for m in ms]):>15}{ci([m['entropy'] for m in ms]):>13}"
                      f"{ci([m['bestShareLast30'] for m in ms]):>16}{st.mean(r[3] for r in rows):>7.0f}")
    return table


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--quick", action="store_true")
    ap.add_argument("--json-out", help="write a machine-readable summary (read by evaluation/v2_readiness.py)")
    a = ap.parse_args()
    seed_hash = hashlib.sha256(SEED_FILE.read_bytes()).hexdigest()
    tune_seeds, eval_seeds = (range(0, 3), range(100, 105)) if a.quick else (range(0, 10), range(100, 130))

    # 1) Tune v2 on seeds 0-9 (S1, S2, S4): minimise regret subject to <= 30 switches per 100 epochs.
    grid = [dict(discount=d, exploration=c, switch_margin=m) for d in (0.97, 0.99) for c in (0.15, 0.3, 0.6) for m in (0.0, 0.04)]
    tune = {k: v for k, v in SCENARIOS.items() if not k.startswith("S3")}
    print("## Tuning v2 (seeds %d-%d; S1, S2, S4) [SIMULATED]" % (tune_seeds[0], tune_seeds[-1]))
    scored = []
    for g in grid:
        t = evaluate({"v2": v2_factory(**g)}, list(tune_seeds), tune, show=False)
        reg = st.mean(m["regret"] for ms in t.values() for m in ms)
        sw = st.mean(m["switches100"] for ms in t.values() for m in ms)
        scored.append((reg, sw, g)); print(f"  {g}: regret/sess {reg:.3f}, switches/100 epochs {sw:.1f}")
    ok = [x for x in scored if x[1] <= 30] or scored
    chosen = min(ok, key=lambda x: x[0])[2]
    print("  chosen:", chosen)

    # 2) Held-out comparison of all candidates.
    policies = {
        "A seeded Q-learning (current v1)": lambda: V1(seeded=True),
        "B cold-start Q-learning": lambda: V1(seeded=False),
        "C rescaled seed x0.1, eps from real": lambda: V1(seeded=True, rescale=0.1, epsilon_from_real=True),
        "D seeded Q, eps from real episodes": lambda: V1(seeded=True, epsilon_from_real=True),
        "E1 UCB1 (existing v1 option)": lambda: V1(seeded=False, ucb=True),
        "E2 UCB + switch margin (no discount)": v2_factory(**{**chosen, "discount": 1.0}),
        "F discounted UCB (no switch margin)": v2_factory(**{**chosen, "switch_margin": 0.0}),
        "G v2: discounted UCB + margin + prior": v2_factory(**chosen),
    }
    print("\n## Held-out comparison (seeds %d-%d) [SIMULATED]" % (eval_seeds[0], eval_seeds[-1]))
    held = evaluate(policies, list(eval_seeds))

    # 3) Sensitivity of v2 to the synthetic prior's weight (how much the seed is allowed to matter).
    print("\n## Sensitivity to synthetic prior weight (v2, chosen params) [SIMULATED]")
    sens = {f"G prior_weight={w}": v2_factory(**{**chosen, "prior_weight": w}) for w in (0, 1, 10, 100, SEED["episode_count"])}
    evaluate(sens, list(eval_seeds), {k: v for k, v in SCENARIOS.items() if k.startswith(("S1", "S2"))})

    assert hashlib.sha256(SEED_FILE.read_bytes()).hexdigest() == seed_hash, "shipped seed changed!"
    print("\nshipped seed models/q_table.json unchanged; no learner state was written")
    if a.json_out:
        def cell(ms):
            reg = [m["regret"] for m in ms]
            h = 1.96 * st.stdev(reg) / math.sqrt(len(reg)) if len(reg) > 1 else 0.0
            return {"regretMean": round(st.mean(reg), 4), "regretCi95": round(h, 4), "runs": len(ms),
                    "identified": sum(m["identify"] is not None for m in ms),
                    "switchesPer100": round(st.mean(m["switches100"] for m in ms), 2)}
        summary = {"kind": "SIMULATED", "simulator": "demo/deception_arena.play_session (assumed persona preferences)",
                   "tuneSeeds": [tune_seeds[0], tune_seeds[-1]], "evalSeeds": [eval_seeds[0], eval_seeds[-1]],
                   "chosenParams": chosen, "seedSha256": seed_hash,
                   "results": {sc: {pol: cell(ms) for (sc2, pol), ms in held.items() if sc2 == sc} for sc in SCENARIOS}}
        Path(a.json_out).write_text(json.dumps(summary, indent=2), encoding="utf-8")
        print("summary written to", a.json_out)


if __name__ == "__main__":
    main()
