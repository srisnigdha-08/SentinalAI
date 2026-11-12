"""
evaluation/real_session_report.py and evaluation/v2_readiness.py (docs/PERSONA_POLICY_V2.md sections 5-7).
Offline fixtures only: no database, no engine, no learner state is written.
"""
import json
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "evaluation"))
import real_session_report as rsr  # noqa: E402
import v2_readiness as vr  # noqa: E402
from rl_engine import deception_scorer as ds  # noqa: E402
from rl_engine import persona_policy_v2 as v2mod  # noqa: E402

T0 = datetime(2026, 11, 1, tzinfo=timezone.utc)


def sess(sid, ip, persona, minutes=0, duration=60, cmds=2, closed=True):
    return {"sessionId": sid, "sourceIP": ip, "servedProfile": persona, "status": "closed" if closed else "active",
            "closureAnalysisState": "complete" if closed else "processing",
            "startTime": {"$date": (T0 + timedelta(minutes=minutes)).isoformat()}, "durationSeconds": duration,
            "commands": [{"command": "uname -a", "intent": "RECONNAISSANCE"}] * cmds, "credentials": [{"success": True}],
            "iocExtracted": {"urls": []}}


def run_report(tmp_path, sessions, decisions=(), extra=()):
    sf, df, out = tmp_path / "s.json", tmp_path / "d.json", tmp_path / "r.json"
    sf.write_text(json.dumps(sessions)); df.write_text(json.dumps(list(decisions)))
    rsr.main(["report", "--sessions-file", str(sf), "--decisions-file", str(df), "--json-out", str(out), *extra])
    return json.loads(out.read_text())


def test_classification_dedupe_and_exclusions(tmp_path, capsys):
    data = [sess("demo-1", "81.2.69.160", "ubuntu_22"),          # backend synthetic, even from a public IP
            sess("op1", "127.0.0.1", "ubuntu_22"), sess("op2", "172.29.32.1", "centos_7"),
            sess("ext1", "81.2.69.160", "debian_11"), sess("ext1", "81.2.69.160", "debian_11"),   # duplicate id
            sess("open", "81.2.69.161", "aws_ec2", closed=False), {"sessionId": "", "status": "closed"}]
    r = run_report(tmp_path, data)
    assert r["input"]["duplicatesDropped"] == 1 and r["input"]["excluded"] == {"not closed/analysed": 1, "no sessionId": 1}
    assert r["evidenceClasses"] == {"simulated": 1, "operator": 2, "external": 1}
    assert r["externalCountsPerServablePersona"] == {"ubuntu_22": 0, "debian_11": 1, "centos_7": 0, "aws_ec2": 0, "raspberry_pi": 0}
    assert r["gate1"]["met"] is False
    assert "never observed" in r["counterfactual"]
    assert "NOT MET" in capsys.readouterr().out


def test_operator_overrides_and_lab_external_ranges(tmp_path):
    data = [sess("a", "81.2.69.160", "ubuntu_22"), sess("b", "10.9.9.9", "ubuntu_22"), sess("c", "81.2.69.170", "ubuntu_22")]
    ops = tmp_path / "ops.txt"; ops.write_text("c\n")
    r = run_report(tmp_path, data, extra=["--operator-ip", "81.2.69.160", "--external-cidr", "10.9.0.0/16", "--operator-sessions", str(ops)])
    cls = {s["sessionId"]: s["evidenceClass"] for s in r["sessions"]}
    assert cls == {"a": "operator", "b": "external", "c": "operator"}


def test_rewards_are_the_learners_own_and_small_samples_are_flagged(tmp_path):
    data = [sess(f"e{i}", "81.2.69.160", "raspberry_pi", minutes=i, duration=120, cmds=3) for i in range(3)]
    r = run_report(tmp_path, data)
    expected = ds.calc_reward({"durationSeconds": 120, "commands": [{"command": "uname -a", "intent": "RECONNAISSANCE"}] * 3,
                               "iocCount": 0, "loginSucceeded": True})
    rp = r["perPersona"]["external"]["raspberry_pi"]
    assert rp["reward"]["mean"] == pytest.approx(round(expected, 3)) and rp["reward"]["n"] == 3
    assert "insufficient" in rp["warning"] and r["perPersona"]["external"]["ubuntu_22"]["warning"] == "no sessions"


def test_policy_in_force_and_switch_history(tmp_path):
    decisions = [{"decisionId": "d1", "state": "ubuntu_22", "action": "centos_7", "status": "APPLIED", "policy": "q_learning",
                  "appliedAt": {"$date": (T0 + timedelta(minutes=10)).isoformat()}},
                 {"decisionId": "d2", "state": "centos_7", "action": "debian_11", "status": "FAILED", "policy": "q_learning"}]
    data = [sess("before", "81.2.69.160", "ubuntu_22", minutes=5), sess("after", "81.2.69.160", "centos_7", minutes=20)]
    r = run_report(tmp_path, data, decisions)
    pol = {s["sessionId"]: s["policyInForce"] for s in r["sessions"]}
    assert pol["after"] == "q_learning" and pol["before"].startswith("no rotation")
    assert [t["to"] for t in r["switchHistory"]] == ["centos_7"]          # FAILED decisions are not history
    assert r["replay"]["agreement"][1] == 2


def test_plan_is_balanced_reproducible_and_adherence_is_measured(tmp_path):
    a, b = tmp_path / "a.json", tmp_path / "b.json"
    for out in (a, b):
        rsr.main(["plan", "--start", T0.isoformat(), "--interval-hours", "1", "--blocks", "3", "--seed", "7", "--out", str(out)])
    pa = json.loads(a.read_text())
    assert pa == json.loads(b.read_text())
    for blk in range(3):
        assert sorted(s["persona"] for s in pa["slots"] if s["block"] == blk) == sorted(ds.servable_profiles())
    first = pa["slots"][0]["persona"]; second = pa["slots"][1]["persona"]
    data = [sess("x1", "81.2.69.160", first, minutes=10), sess("x2", "81.2.69.160", first, minutes=70)]   # 2nd is off-schedule
    r = run_report(tmp_path, data, extra=["--schedule", str(a)])
    assert r["adherence"] == {"sessionsInSchedule": 2, "servedAsScheduled": 1, "adherence": 0.5} and first != second


# ── readiness ──────────────────────────────────────────────────────────────────────────────────────────────────
def _sim(tmp_path, v2_identified=30):
    res = lambda reg, ident, sw: {"regretMean": reg, "regretCi95": 0.05, "runs": 30, "identified": ident, "switchesPer100": sw}
    sim = {"chosenParams": {k: v2mod.DEFAULTS[k] for k in ("discount", "exploration", "switch_margin")},
           "results": {"S1": {vr.V1_NAME: res(2.75, 0, 96), vr.V2_NAME: res(1.0, v2_identified, 17)}}}
    p = tmp_path / "sim.json"; p.write_text(json.dumps(sim)); return p


def _state(tmp_path, days_old):
    p = tmp_path / "v2state.json"
    pol = v2mod.PersonaPolicyV2(p, prior_means={})
    pol.observe("s1", "centos_7", 5.0)
    data = json.loads(p.read_text()); data["createdAt"] = (datetime.now(timezone.utc) - timedelta(days=days_old)).isoformat()
    p.write_text(json.dumps(data)); return p


def _full_report(tmp_path):
    # Enough randomised external data for gate 2's CI (sd 3, n 400 per persona); centos_7 5.0, raspberry_pi 5.5
    per = {p: {"reward": {"n": 400, "mean": 5.5 if p == "raspberry_pi" else 5.0, "sd": 3.0, "ci95": [4.7, 5.8]}} for p in ds.servable_profiles()}
    rep = {"externalCountsPerServablePersona": {p: 400 for p in ds.servable_profiles()}, "evidenceClasses": {"external": 2000},
           "gate1": {"required": 30, "met": True}, "adherence": {"adherence": 0.95},
           "perPersona": {"external": per}, "replay": {"v1Recommendations": {"centos_7": 5}, "v2Recommendations": {"raspberry_pi": 5}}}
    p = tmp_path / "rep.json"; p.write_text(json.dumps(rep)); return p


def test_readiness_is_not_ready_without_real_external_evidence(tmp_path, monkeypatch, capsys):
    data = [sess("op1", "127.0.0.1", "ubuntu_22")]
    run_report(tmp_path, data)
    monkeypatch.setattr(vr, "engine_state", lambda url, cur: {"policy": "q_learning", "shadow": {"applied": False}})
    code = vr.main(["--report-json", str(tmp_path / "r.json"), "--sim-json", str(_sim(tmp_path)), "--v2-state", str(_state(tmp_path, 30)),
                    "--engine-url", "http://x", "--json-out", str(tmp_path / "ready.json")])
    out = json.loads((tmp_path / "ready.json").read_text())
    assert code == 2 and out["overall"] == "NOT READY FOR PRODUCTION PROMOTION"
    assert out["verdicts"]["1 engineering readiness"] == "PASS" and out["verdicts"]["2 simulation performance (SIMULATED)"] == "PASS"
    assert out["verdicts"]["3 real-session coverage (gate 1)"] == "NOT MET" and out["verdicts"]["6 rollback readiness (gate 4)"] == "NOT MET"


def test_readiness_needs_every_gate_including_a_live_rollback_rehearsal(tmp_path, monkeypatch):
    monkeypatch.setattr(vr, "engine_state", lambda url, cur: {"policy": "q_learning", "shadow": {"applied": False}})
    args = ["--report-json", str(_full_report(tmp_path)), "--sim-json", str(_sim(tmp_path)), "--v2-state", str(_state(tmp_path, 20)),
            "--engine-url", "http://x"]
    assert vr.main(args) == 2                                       # everything but the rehearsal
    reh = tmp_path / "rehearsal.json"
    reh.write_text(json.dumps({"date": "2026-12-01", "activeObservedPolicy": v2mod.POLICY_VERSION, "rolledBackObservedPolicy": "q_learning"}))
    assert vr.main(args + ["--rollback-rehearsal", str(reh)]) == 0


def test_readiness_rejects_a_simulation_where_v2_misses_the_best_persona(tmp_path, monkeypatch):
    monkeypatch.setattr(vr, "engine_state", lambda url, cur: None)
    vr.main(["--sim-json", str(_sim(tmp_path, v2_identified=25)), "--json-out", str(tmp_path / "o.json")])
    assert json.loads((tmp_path / "o.json").read_text())["verdicts"]["2 simulation performance (SIMULATED)"] == "FAIL"


def test_readiness_never_loads_the_live_state_file_in_place(tmp_path, monkeypatch):
    bad = tmp_path / "v2state.json"; bad.write_text("{corrupt")
    monkeypatch.setattr(vr, "engine_state", lambda url, cur: None)
    vr.main(["--v2-state", str(bad), "--json-out", str(tmp_path / "o.json")])
    assert bad.read_text() == "{corrupt" and not list(tmp_path.glob("v2state.json.corrupt-*"))   # only a copy was quarantined


def test_gate2_does_not_pass_on_the_minimum_coverage_alone(tmp_path):
    """30-40 sessions per persona meet gate 1 but cannot bound a 0.5 loss at the observed spread (sd ~3)."""
    per = {p: {"reward": {"n": 40, "mean": 5.0, "sd": 3.0}} for p in ds.servable_profiles()}
    rep = {"gate1": {"met": True}, "adherence": {"adherence": 1.0}, "perPersona": {"external": per},
           "replay": {"v1Recommendations": {"centos_7": 1}, "v2Recommendations": {"raspberry_pi": 1}}}
    assert vr.effectiveness(rep)[0]["status"] == "NOT MET" and "too uncertain" in vr.effectiveness(rep)[0]["evidence"]


def test_gate2_requires_v2_not_worse_on_the_estimate_itself(tmp_path):
    """Documented gate: v2's estimated reward >= v1's AND the CI excludes a loss > 0.5. A precise but negative
    estimate (-0.2, CI within -0.5) must not pass."""
    per = {p: {"reward": {"n": 5000, "mean": 4.8 if p == "raspberry_pi" else 5.0, "sd": 3.0}} for p in ds.servable_profiles()}
    rep = {"gate1": {"met": True}, "adherence": {"adherence": 1.0}, "perPersona": {"external": per},
           "replay": {"v1Recommendations": {"centos_7": 1}, "v2Recommendations": {"raspberry_pi": 1}}}
    assert vr.effectiveness(rep)[0]["status"] != "PASS"


def test_session_records_carry_intents_recommendations_and_decision_outcomes(tmp_path):
    decisions = [{"decisionId": "f1", "state": "centos_7", "action": "debian_11", "status": "FAILED", "policy": "q_learning",
                  "closedAt": {"$date": T0.isoformat()}},
                 {"decisionId": "s1", "state": "centos_7", "action": "debian_11", "status": "SUPERSEDED", "policy": "q_learning"}]
    data = [sess("a", "81.2.69.160", "centos_7", duration=5, cmds=1), sess("b", "81.2.69.160", "centos_7", minutes=3, duration=900, cmds=1)]
    r = run_report(tmp_path, data, decisions)
    a = next(x for x in r["sessions"] if x["sessionId"] == "a")
    assert a["intents"] == {"RECONNAISSANCE": 1} and a["v1RecommendationAfter"] in ds.servable_profiles()
    assert a["v2ShadowRecommendationAfter"] in ds.servable_profiles()
    assert r["decisionOutcomes"]["byStatusAndPolicy"] == {"FAILED/q_learning": 1, "SUPERSEDED/q_learning": 1}
    assert [f["decisionId"] for f in r["decisionOutcomes"]["failed"]] == ["f1"]
    dur = r["perPersona"]["external"]["centos_7"]["durationSeconds"]
    assert dur["ci95"][0] >= 0 and dur["median"] == 452.5              # no impossible negative duration bound
