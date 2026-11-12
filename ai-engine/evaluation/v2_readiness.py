#!/usr/bin/env python3
"""
Evidence-based promotion readiness for persona policy v2 (docs/PERSONA_POLICY_V2.md section 6). Read-only: it
loads copies of state, reads report files and (optionally) GETs the engine's recommendation; it changes nothing.

Six categories, each PASS / NOT MET / FAIL with the evidence behind it:
  1 engineering readiness     the shipped code, parameters, state file and accounting are consistent
  2 simulation performance    SIMULATED evidence from evaluation/persona_policy_sim.py --json-out (never sufficient)
  3 real-session coverage     gate 1: >= 30 EXTERNAL sessions per servable persona (evaluation/real_session_report.py)
  4 real-world effectiveness  gate 2: randomised-assignment data showing v2's choice is not worse than v1's
  5 operational safety        gate 3: >= 14 days of shadow, intact state, engine still in shadow
  6 rollback readiness        gate 4: automated rollback tests plus a recorded live rollback rehearsal
Overall READY only if all six PASS; otherwise "NOT READY FOR PRODUCTION PROMOTION". The gates are not adjustable
from the command line except the shadow duration's reference time (--now), for reproducible re-runs.

  python evaluation/v2_readiness.py --report-json r.json --sim-json sim.json \
      --v2-state %USERPROFILE%\\.sentinelai\\demo\\persona_policy_v2.json --engine-url http://127.0.0.1:8000 --current debian_11
"""
import argparse, json, math, os, shutil, statistics as st, sys, tempfile, urllib.request
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from rl_engine import deception_scorer as ds  # noqa: E402
from rl_engine import persona_policy_v2 as v2mod  # noqa: E402

MIN_PER_PERSONA, MIN_SHADOW_DAYS, MIN_ADHERENCE, MAX_LOSS = 30, 14, 0.9, 0.5
V1_NAME, V2_NAME = "A seeded Q-learning (current v1)", "G v2: discounted UCB + margin + prior"


def check(ok, text, missing=False):
    return {"status": "PASS" if ok else ("NOT MET" if missing else "FAIL"), "evidence": text}


def engineering(sim, state_path):
    items = []
    items.append(check(v2mod.POLICY_VERSION == "persona-ducb-v2", f"policy version {v2mod.POLICY_VERSION}"))
    if sim:
        chosen = {k: float(v) for k, v in sim["chosenParams"].items()}
        shipped = {k: v2mod.DEFAULTS[k] for k in chosen}
        items.append(check(chosen == shipped, f"shipped defaults {shipped} == simulation-evaluated {chosen}"))
    else:
        items.append(check(False, "no simulation summary to compare the shipped defaults with", missing=True))
    if state_path and Path(state_path).is_file():
        tmp = Path(tempfile.mkdtemp()) / "v2.json"
        shutil.copyfile(state_path, tmp)                 # never load (and possibly quarantine) the live file itself
        p = v2mod.PersonaPolicyV2(tmp, prior_means={})
        items.append(check(p.quarantined is None, "live state file loads (copy) without quarantine" if p.quarantined is None
                           else f"live state file is unusable ({Path(p.quarantined).name})"))
        consistent = p.real_episodes == len(p.seen) if p.real_episodes <= v2mod.SEEN_LIMIT else len(p.seen) == v2mod.SEEN_LIMIT
        items.append(check(consistent, f"exactly-once accounting: realEpisodes {p.real_episodes}, deduplicated ids {len(p.seen)}"))
    else:
        items.append(check(False, "no v2 state file found (has the engine scored a session in shadow yet?)", missing=True))
    return items


def simulation(sim):
    if not sim:
        return [check(False, "no simulation summary (run evaluation/persona_policy_sim.py --json-out)", missing=True)]
    items, res = [], sim["results"]
    for sc, pols in res.items():
        v1, v2 = pols.get(V1_NAME), pols.get(V2_NAME)
        if not (v1 and v2):
            continue
        items.append(check(v2["identified"] == v2["runs"], f"[SIMULATED] {sc}: v2 identified the best persona in {v2['identified']}/{v2['runs']} runs (v1 {v1['identified']}/{v1['runs']})"))
        if "persona-blind" not in sc:
            not_worse = v2["regretMean"] - v2["regretCi95"] <= v1["regretMean"] + v1["regretCi95"] + MAX_LOSS
            items.append(check(not_worse, f"[SIMULATED] {sc}: regret/session v2 {v2['regretMean']}±{v2['regretCi95']} vs v1 {v1['regretMean']}±{v1['regretCi95']} (allowed loss {MAX_LOSS})"))
        items.append(check(v2["switchesPer100"] <= v1["switchesPer100"], f"[SIMULATED] {sc}: Cowrie restarts/100 decisions v2 {v2['switchesPer100']} vs v1 {v1['switchesPer100']}"))
    return items


def coverage(report):
    if not report:
        return [check(False, "no real-session report (run evaluation/real_session_report.py report --json-out)", missing=True)]
    counts = report["externalCountsPerServablePersona"]
    items = [check(n >= MIN_PER_PERSONA, f"external sessions served {p}: {n} (need {MIN_PER_PERSONA})", missing=n < MIN_PER_PERSONA)
             for p, n in counts.items()]
    items.append({"status": "INFO", "evidence": f"evidence classes in the data: {report['evidenceClasses']} (operator and simulated sessions never count)"})
    return items


def effectiveness(report):
    if not report or not report.get("gate1", {}).get("met"):
        return [check(False, "not evaluable: gate 1 (coverage) is not met, so there is no randomised real-attacker data to compare policies on", missing=True)]
    adh = (report.get("adherence") or {}).get("adherence")
    if adh is None or adh < MIN_ADHERENCE:
        return [check(False, f"not evaluable: sessions must come from the randomised schedule (adherence {adh}, need >= {MIN_ADHERENCE})", missing=True)]
    ext = report["perPersona"]["external"]
    rows = report.get("replay") or {}
    v1_pick = max(rows.get("v1Recommendations", {}) or {"?": 0}, key=lambda k: rows["v1Recommendations"][k])
    v2_pick = max(rows.get("v2Recommendations", {}) or {"?": 0}, key=lambda k: rows["v2Recommendations"][k])
    a, b = ext.get(v2_pick, {}).get("reward", {}), ext.get(v1_pick, {}).get("reward", {})
    if not (a.get("sd") and b.get("sd")):
        return [check(False, "not evaluable: no variance estimate for the chosen personas", missing=True)]
    diff = a["mean"] - b["mean"]
    se = math.sqrt(a["sd"] ** 2 / a["n"] + b["sd"] ** 2 / b["n"])
    lo, hi = diff - 1.96 * se, diff + 1.96 * se
    text = (f"v2's preferred persona {v2_pick} vs v1's {v1_pick}: reward difference {diff:.2f}, 95% CI [{lo:.2f}, {hi:.2f}] "
            f"(needs difference >= 0 and lower bound >= -{MAX_LOSS})")
    if diff >= 0 and lo >= -MAX_LOSS:
        return [check(True, text)]
    if hi < -MAX_LOSS:
        return [check(False, text + ": v2's choice is measurably worse")]
    return [check(False, text + ": too uncertain, collect more randomised sessions", missing=True)]


def safety(state_path, engine, now):
    items = []
    if state_path and Path(state_path).is_file():
        try:
            created = datetime.fromisoformat(json.loads(Path(state_path).read_text(encoding="utf-8"))["createdAt"])
        except (OSError, ValueError, KeyError, TypeError):
            created = None
        if created is None:
            items.append(check(False, "v2 state unreadable: shadow duration unknown"))
        else:
            days = (now - created).total_seconds() / 86400
            items.append(check(days >= MIN_SHADOW_DAYS, f"shadow running {days:.1f} days (need {MIN_SHADOW_DAYS})", missing=days < MIN_SHADOW_DAYS))
    else:
        items.append(check(False, "no v2 state: shadow has not run", missing=True))
    if engine:
        live_ok = engine.get("policy") == "q_learning" and (engine.get("shadow") or {}).get("applied") is False
        items.append(check(live_ok, f"engine decides with {engine.get('policy')}; v2 present as shadow (applied={(engine.get('shadow') or {}).get('applied')})"))
    else:
        items.append(check(False, "engine not queried (pass --engine-url)", missing=True))
    items.append({"status": "INFO", "evidence": "v2 errors are logged as 'Persona policy v2 ... failed' in the engine window; review it for the shadow period"})
    return items


def rollback(rehearsal):
    tests = (ROOT / "tests" / "test_persona_policy_v2.py").read_text(encoding="utf-8")
    items = [check(all(t in tests for t in ("test_active_mode_serves_v2_and_still_reports_v1", "test_v2_recommendation_failure_falls_back_to_v1",
                                              "test_shadow_recommendation_is_reported_but_never_drives_the_decision")),
                   "automated tests cover active, shadow and failure fallback")]
    if rehearsal and Path(rehearsal).is_file():
        r = json.loads(Path(rehearsal).read_text(encoding="utf-8"))
        ok = r.get("activeObservedPolicy") == v2mod.POLICY_VERSION and r.get("rolledBackObservedPolicy") == "q_learning"
        items.append(check(ok, f"live rollback rehearsal recorded {r.get('date')}: active -> {r.get('activeObservedPolicy')}, rollback -> {r.get('rolledBackObservedPolicy')}"))
    else:
        items.append(check(False, "no recorded live rollback rehearsal (see docs/PERSONA_POLICY_V2.md section 7)", missing=True))
    return items


def engine_state(url, current):
    key = os.getenv("SENTINEL_KEY", "")
    if not (url and key):
        return None
    req = urllib.request.Request(f"{url.rstrip('/')}/deception/recommendation?current={current}", headers={"X-API-Key": key})
    with urllib.request.urlopen(req, timeout=10) as r:
        return json.loads(r.read())


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[1])
    ap.add_argument("--report-json"); ap.add_argument("--sim-json"); ap.add_argument("--v2-state")
    ap.add_argument("--engine-url"); ap.add_argument("--current", default="centos_7", choices=ds.servable_profiles())
    ap.add_argument("--rollback-rehearsal"); ap.add_argument("--now", help="ISO time for the shadow-duration check")
    ap.add_argument("--json-out")
    a = ap.parse_args(argv)
    load = lambda p: json.loads(Path(p).read_text(encoding="utf-8")) if p and Path(p).is_file() else None
    sim, report = load(a.sim_json), load(a.report_json)
    now = datetime.fromisoformat(a.now) if a.now else datetime.now(timezone.utc)
    try:
        engine = engine_state(a.engine_url, a.current)
    except OSError as e:
        engine = None; print(f"(engine not reachable: {type(e).__name__})")
    cats = {"1 engineering readiness": engineering(sim, a.v2_state), "2 simulation performance (SIMULATED)": simulation(sim),
            "3 real-session coverage (gate 1)": coverage(report), "4 real-world effectiveness (gate 2)": effectiveness(report),
            "5 operational safety (gate 3)": safety(a.v2_state, engine, now), "6 rollback readiness (gate 4)": rollback(a.rollback_rehearsal)}
    verdicts = {}
    for name, items in cats.items():
        scored = [i for i in items if i["status"] != "INFO"]
        verdicts[name] = "PASS" if scored and all(i["status"] == "PASS" for i in scored) else (
            "FAIL" if any(i["status"] == "FAIL" for i in scored) else "NOT MET")
        print(f"\n{name}: {verdicts[name]}")
        for i in items:
            print(f"  [{i['status']}] {i['evidence']}")
    ready = all(v == "PASS" for v in verdicts.values())
    overall = "READY FOR PRODUCTION PROMOTION (owner approval still required)" if ready else "NOT READY FOR PRODUCTION PROMOTION"
    print(f"\nOVERALL: {overall}")
    if not ready:
        print("  blocking: " + "; ".join(n for n, v in verdicts.items() if v != "PASS"))
    print("  note: simulation results are never sufficient on their own; gates 1-4 need real, randomised, external data")
    if a.json_out:
        Path(a.json_out).write_text(json.dumps({"generatedAt": now.isoformat(), "overall": overall, "verdicts": verdicts, "categories": cats}, indent=2), encoding="utf-8")
    return 0 if ready else 2


if __name__ == "__main__":
    sys.exit(main())
