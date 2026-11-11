"""Deception Arena runner: isolation from the deployed Q-table, fairness of pairing, bounds, determinism."""
import importlib.util
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location("deception_arena", ROOT / "demo" / "deception_arena.py")
arena = importlib.util.module_from_spec(spec)
spec.loader.exec_module(arena)

CFG = {"scenario": "persona_sensitive_sim", "baselinePersona": "centos_7", "trialsPerStrategy": 8, "seed": 3, "maxTrialSeconds": 600}


def collect(cfg):
    trials = []
    prov = arena.run(cfg, lambda t: trials.append(t) and False)
    return prov, trials


def strip(trials):
    return [{k: v for k, v in t.items() if k not in ("startedAt", "endedAt")} for t in trials]


def test_deterministic_for_a_seed():
    assert strip(collect(CFG)[1]) == strip(collect(CFG)[1])
    assert strip(collect({**CFG, "seed": 4})[1]) != strip(collect(CFG)[1])


def test_q_tables_never_written(monkeypatch):
    def refuse(self):
        raise AssertionError("save() must never run")
    monkeypatch.setattr(arena.DeceptionQLearner, "save", refuse, raising=True)  # the class method, as a guard
    before = (arena.sha256(arena.SEED_TABLE), arena.sha256(arena.RUNTIME_TABLE))
    prov, _ = collect(CFG)
    assert (arena.sha256(arena.SEED_TABLE), arena.sha256(arena.RUNTIME_TABLE)) == before
    assert prov["qTableHashes"]["before"] == prov["qTableHashes"]["after"]


def test_static_never_consults_the_learner_and_adaptive_records_decisions():
    _, trials = collect(CFG)
    static = [t for t in trials if t["strategy"] == "STATIC"]
    adaptive = [t for t in trials if t["strategy"] == "ADAPTIVE"]
    assert len(static) == len(adaptive) == 8
    assert all(t["persona"] == "centos_7" and t["decision"] is None for t in static)
    assert all(t["decision"]["appliedPersona"] == t["persona"] for t in adaptive)
    assert all(t["persona"] in arena.servable_profiles() for t in adaptive)
    assert [t["pairPosition"] for t in trials[:4]] == [0, 1, 0, 1]
    assert trials[0]["strategy"] == "STATIC" and trials[2]["strategy"] == "ADAPTIVE"  # order alternates per pair


def test_scripted_scenarios_ignore_the_persona():
    import random
    for name in ("scripted_recon", "scripted_dropper"):
        sessions = [arena.play_session(arena.SCENARIOS[name], p, random.Random(1), 600) for p in arena.PROFILES_LIST]
        assert all(s == sessions[0] for s in sessions)


def test_reward_is_the_existing_scorer_reward():
    import random
    s = arena.play_session(arena.SCENARIOS["scripted_recon"], "centos_7", random.Random(0), 600)
    assert s["reward"] == round(arena.calc_reward({k: s[k] for k in ("durationSeconds", "commands", "loginSucceeded", "iocCount")}), 4)


@pytest.mark.parametrize("bad", [{"scenario": "nmap 10.0.0.0/8"}, {"baselinePersona": "kali"}, {"trialsPerStrategy": 0},
                                 {"trialsPerStrategy": 51}, {"maxTrialSeconds": 5}])
def test_bounds_and_allowlist(bad):
    with pytest.raises(ValueError):
        arena.validate({**CFG, **bad})


def test_cancellation_stops_after_the_current_trial():
    seen = []
    prov = arena.run(CFG, lambda t: seen.append(t) or len(seen) == 3)
    assert prov["cancelled"] is True and len(seen) == 3


def test_time_limit_bounds_simulated_sessions():
    _, trials = collect({**CFG, "maxTrialSeconds": 30})
    assert all(t["durationSeconds"] <= 30 for t in trials)


def test_runner_refuses_non_local_backends(monkeypatch):
    monkeypatch.setattr("sys.argv", ["x", "--backend", "http://203.0.113.5:5000", "--experiment", "e"])
    with pytest.raises(SystemExit, match="local SentinelAI backend"):
        arena.main()
