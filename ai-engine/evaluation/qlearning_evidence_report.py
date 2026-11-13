#!/usr/bin/env python3
"""
How much of the v1 Q-learner's behaviour comes from real sessions versus the synthetic warm start
(docs/QLEARNING_EVIDENCE.md). Read-only: the table is COPIED to a temporary file before it is parsed, and the
live file's SHA-256 is checked before and after.

Reported:
  * episodes: synthetic seed vs session-driven, and session episodes by evidence source (operator / external /
    simulated / unknown / untracked = learned before provenance was recorded)
  * per persona: real sessions (arm_stats.n), the mean normalised reward from real sessions only, and a bound on
    the seed's remaining weight in that persona's Q-values: each TD update keeps (1 - alpha) of the old value, so
    after n updates on one cell the seed still contributes (1 - alpha)^n. Updates are spread over the six states,
    so the per-cell figure (1 - alpha)^(n / 6) is the typical case and (1 - alpha)^n the most favourable to real data.
  * decisions: the greedy persona from every state under (a) the seed alone and (b) the current table. Where
    they agree, real sessions have not changed the decision.
  * ranking: personas ranked by the seed's average Q versus by real-session mean reward (personas with no real
    session cannot be ranked by real data).

  python evaluation/qlearning_evidence_report.py --table %USERPROFILE%/.sentinelai/demo/q_table.json --json out.json
"""
import argparse, hashlib, json, shutil, sys, tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from rl_engine.deception_scorer import EVIDENCE_SOURCES, PROFILES_LIST, SUPPORTED_PROFILES  # noqa: E402

ALPHA = 0.1


def sha(p: Path):
    return hashlib.sha256(p.read_bytes()).hexdigest()


def greedy(table, state, actions):
    row = table.get(state, {})
    return max(actions, key=lambda a: row.get(a, 0.0))


def report(table_path: Path, seed_path: Path) -> dict:
    before = sha(table_path)
    with tempfile.TemporaryDirectory() as d:
        copy = Path(d) / "q_copy.json"
        shutil.copyfile(table_path, copy)
        cur = json.loads(copy.read_text(encoding="utf-8"))
    if sha(table_path) != before:
        raise RuntimeError("the live table changed while it was being read; run again")
    seed = json.loads(seed_path.read_text(encoding="utf-8"))
    prov = cur.get("seed_provenance") or {}
    seed_n = int(prov.get("episodes", seed.get("episode_count", 0)))
    total = int(cur.get("episode_count", 0))
    session_n = max(0, total - seed_n)
    ev = cur.get("evidence") or {}
    by_source = {s: int((ev.get("counts") or {}).get(s, 0)) for s in EVIDENCE_SOURCES}
    tracked = sum(by_source.values())
    arms = cur.get("arm_stats") or {}
    per_persona = {}
    for a in PROFILES_LIST:
        n = int((arms.get(a) or {}).get("n", 0))
        per_persona[a] = {
            "servable": a in SUPPORTED_PROFILES,
            "realSessions": n,
            "realMeanNormalisedReward": round(float((arms.get(a) or {}).get("mean", 0.0)), 4) if n else None,
            "seedWeightTypical": round((1 - ALPHA) ** (n / len(PROFILES_LIST)), 4),
            "seedWeightBestCase": round((1 - ALPHA) ** n, 4),
            "bySource": (ev.get("per_persona") or {}).get(a),
        }
    decisions = {}
    for s in PROFILES_LIST:
        g_seed = greedy(seed["q_table"], s, SUPPORTED_PROFILES)
        g_cur = greedy(cur["q_table"], s, SUPPORTED_PROFILES)
        decisions[s] = {"seedOnly": g_seed, "current": g_cur, "changedByRealData": g_seed != g_cur}
    avg = lambda t, a: sum(t[s].get(a, 0.0) for s in PROFILES_LIST) / len(PROFILES_LIST)  # noqa: E731
    seed_rank = sorted(SUPPORTED_PROFILES, key=lambda a: -avg(seed["q_table"], a))
    real_rank = sorted([a for a in SUPPORTED_PROFILES if per_persona[a]["realSessions"]],
                       key=lambda a: -per_persona[a]["realMeanNormalisedReward"])
    rewards = [float(r) for r in cur.get("reward_history", [])]
    return {
        "table": str(table_path), "tableSha256": before, "readOnly": True,
        "episodes": {"total": total, "syntheticSeed": seed_n, "sessionDriven": session_n,
                     "syntheticShare": round(seed_n / total, 5) if total else None,
                     "bySource": by_source, "untracked": max(0, session_n - tracked),
                     "independentExternal": by_source["external"]},
        "perPersona": per_persona,
        "personasWithRealEvidence": [a for a in SUPPORTED_PROFILES if per_persona[a]["realSessions"]],
        "personasWithoutRealEvidence": [a for a in SUPPORTED_PROFILES if not per_persona[a]["realSessions"]],
        "decisions": decisions,
        "decisionsChangedByRealData": sum(d["changedByRealData"] for d in decisions.values()),
        "rankingSeedAvgQ": seed_rank,
        "rankingRealMeanReward": real_rank,
        "recentRewards": {"n": len(rewards), "mean": round(sum(rewards) / len(rewards), 3) if rewards else None},
        "verdict": ("Synthetic initialisation dominates: " if seed_n and session_n < seed_n * 0.01 else "") +
                   f"{session_n} session-driven updates against {seed_n} synthetic seed episodes; "
                   f"{by_source['external']} independent external sessions.",
    }


def main():
    import os
    ap = argparse.ArgumentParser()
    ap.add_argument("--table", default=os.path.expandvars(r"%USERPROFILE%/.sentinelai/demo/q_table.json")
                    if os.name == "nt" else str(Path.home() / ".sentinelai/demo/q_table.json"))
    ap.add_argument("--seed", default=str(ROOT / "models" / "q_table.json"))
    ap.add_argument("--json", help="write the report here")
    a = ap.parse_args()
    r = report(Path(a.table), Path(a.seed))
    text = json.dumps(r, indent=1)
    if a.json:
        Path(a.json).write_text(text, encoding="utf-8")
    print(text)


if __name__ == "__main__":
    main()
