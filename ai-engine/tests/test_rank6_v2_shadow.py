"""
Rank 6: persona policy v2 shadow isolation, persona validation, shadow evidence, evaluation and readiness.

Every learner here lives in pytest's tmp_path (conftest isolates the default runtime path too). The shipped seed,
the repository runtime table and every per-user / demo policy file are hash-checked before and after the module.
Sessions used here are SYNTHETIC fixtures for testing the code; none is reported as evidence.
"""
import copy
import hashlib
import json
import os
import random
import sys
from argparse import Namespace
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))
from evaluation import rank6_v2_shadow_eval as R6  # noqa: E402
from rl_engine import deception_scorer as ds  # noqa: E402
from rl_engine import persona_policy_v2 as v2mod  # noqa: E402

SEED = json.loads((Path(ds.__file__).resolve().parent.parent / "models" / "q_table.json").read_text())
ARTIFACTS = R6.production_artifacts()
BEFORE = R6.hash_artifacts(ARTIFACTS)


@pytest.fixture(autouse=True, scope="module")
def production_artifacts_unchanged():
    yield
    assert R6.hash_artifacts(ARTIFACTS) == BEFORE


def scorer(tmp_path, with_v2=True):
    table = tmp_path / "q.json"
    table.write_text(json.dumps(SEED))
    sc = ds.SessionScorer(q_table_path=str(table))
    if with_v2:
        sc.v2 = v2mod.PersonaPolicyV2(tmp_path / "v2.json", prior_means=v2mod.prior_from_q_table(SEED["q_table"]))
        sc.v2_mode = "shadow"
    return sc, table


def session(i, persona="ubuntu_22", source="operator"):
    return {"sessionId": f"s{i}", "durationSeconds": 60 + i, "loginSucceeded": True, "evidenceSource": source,
            "commands": [{"command": "uname -a", "intent": "RECONNAISSANCE"}], "deceptionProfile": persona}


# ── persona validation ───────────────────────────────────────────────────────────────────────────────────────────
@pytest.mark.parametrize("persona", ["ubuntu_22", "debian_11", "centos_7", "aws_ec2", "raspberry_pi"])
def test_servable_personas_are_accepted(persona):
    assert v2mod.validate_recommendation(persona) == (persona, "OK")


@pytest.mark.parametrize("bad", ["windows_srv", "alpine_3", "", None, 3, {"p": 1}, "UBUNTU_22", "ubuntu_22 "])
def test_unsupported_unknown_and_malformed_picks_are_rejected_not_substituted(bad):
    assert v2mod.validate_recommendation(bad) == (None, "INVALID_RECOMMENDATION")


def test_registry_is_consistent_and_windows_srv_stays_unsupported():
    reg = R6.persona_registry()
    assert reg["ok"] is True
    assert reg["checks"]["windows_srv_not_servable"] and reg["checks"]["unsupported_is_windows_srv_everywhere"]
    assert reg["checks"]["historical_alpine_3_present"] is False  # the historical list was wrong; not invented here
    assert reg["registries"]["engine_servable"] == ["ubuntu_22", "debian_11", "centos_7", "aws_ec2", "raspberry_pi"]
    assert reg["persona_configs"]["windows_srv"]["servable"] is False


def test_v2_never_recommends_windows_even_when_its_evidence_favours_it(tmp_path, monkeypatch):
    monkeypatch.setenv("DECEPTION_EXCLUDED_PROFILES", "")  # cannot re-enable an unsupported persona
    p = v2mod.PersonaPolicyV2(tmp_path / "v2.json", prior_means={"windows_srv": 1.0})
    for i in range(50):
        p.observe(f"w{i}", "windows_srv", 20.0, persist=False)
    assert p.recommend("centos_7") != "windows_srv"
    assert "windows_srv" not in p.indices()


# ── shadow isolation ─────────────────────────────────────────────────────────────────────────────────────────────
def test_isolation_self_checks_pass():
    iso = R6.isolation_self_checks(copy.deepcopy(SEED))
    assert iso["ok"] is True
    for name, v in iso["variants"].items():
        if name != "v2_state_path_equal_to_v1_table":
            assert v["v1_decisions_identical"] and v["v1_q_table_identical"], name


def _v1_outputs(sc, n=8):
    random.seed(11)
    return [(r["nextProfile"], r["rawReward"], r["learned"]) for r in (sc.process_session(session(i)) for i in range(n))]


def test_v1_decisions_and_learning_are_identical_with_and_without_v2(tmp_path):
    (tmp_path / "a").mkdir()
    (tmp_path / "b").mkdir()
    a, ta = scorer(tmp_path / "a", with_v2=False)
    b, tb = scorer(tmp_path / "b", with_v2=True)
    assert _v1_outputs(a) == _v1_outputs(b)
    assert R6.table_fingerprint(ta) == R6.table_fingerprint(tb)
    assert (tmp_path / "b" / "v2.json").exists() and not (tmp_path / "a" / "v2.json").exists()


@pytest.mark.parametrize("failure", [RuntimeError("boom"), TimeoutError("lock busy"), OSError("disk full"), MemoryError()])
def test_v2_failures_are_recorded_and_never_change_v1(tmp_path, failure):
    (tmp_path / "a").mkdir()
    (tmp_path / "b").mkdir()
    a, ta = scorer(tmp_path / "a", with_v2=False)
    b, tb = scorer(tmp_path / "b", with_v2=True)
    b.v2.observe = MagicMock(side_effect=failure)
    assert _v1_outputs(a) == _v1_outputs(b)
    assert R6.table_fingerprint(ta) == R6.table_fingerprint(tb)
    r = b.process_session(session(99))
    assert r["policyV2"]["status"] == "ERROR" and r["policyV2"]["recommendation"] is None
    assert r["policyV2"]["error"] == type(failure).__name__


def test_v2_invalid_output_is_rejected_and_reported(tmp_path):
    sc, _ = scorer(tmp_path)
    sc.v2.recommend = lambda current=None: "windows_srv"
    r = sc.process_session(session(1))
    assert r["policyV2"]["status"] == "INVALID_RECOMMENDATION" and r["policyV2"]["recommendation"] is None
    assert r["nextProfile"] in ds.servable_profiles()  # v1's decision is unaffected


def test_v2_saves_only_its_own_file(tmp_path):
    sc, table = scorer(tmp_path)
    before = table.read_bytes()
    sc.v2.observe("only-v2", "debian_11", 5.0, persist=True)
    assert table.read_bytes() == before
    assert json.loads((tmp_path / "v2.json").read_text())["policyVersion"] == v2mod.POLICY_VERSION


def test_v2_cannot_live_in_models_and_cannot_share_the_v1_table(tmp_path, monkeypatch):
    with pytest.raises(PermissionError):
        v2mod.PersonaPolicyV2(Path(ds.__file__).resolve().parent.parent / "models" / "v2.json")
    from inference import deception
    seed = Path(ds.__file__).resolve().parent.parent / "models" / "q_table.json"
    for target in ("table", "seed"):
        sc, table = scorer(tmp_path / target if (tmp_path / target).mkdir() is None else None, with_v2=False)
        monkeypatch.setenv("DECEPTION_V2_STATE_PATH", str(table if target == "table" else seed))
        before, seed_before = table.read_bytes(), seed.read_bytes()
        deception._attach_policy_v2(sc, str(table), seed)
        assert sc.v2 is None and sc.v2_mode == "off"
        assert table.read_bytes() == before and seed.read_bytes() == seed_before
    (tmp_path / "ok").mkdir()
    sc, table = scorer(tmp_path / "ok", with_v2=False)
    monkeypatch.setenv("DECEPTION_V2_STATE_PATH", str(tmp_path / "ok" / "own_v2.json"))
    deception._attach_policy_v2(sc, str(table), seed)
    assert sc.v2 is not None and sc.v2_mode == "shadow"


# ── recommendation endpoint: shadow never applies; active falls back on invalid picks ──────────────────────────
@pytest.fixture
def engine(tmp_path, monkeypatch):
    os.environ.setdefault("SENTINEL_KEY", "test-sentinel-secret-key-12345")
    with patch("inference.predictor.SentinelPredictor.load"), \
         patch("inference.predictor.SentinelPredictor.init_explainer"), \
         patch("joblib.load", return_value=MagicMock()):
        import inference.main as main
    from fastapi.testclient import TestClient
    sc, table = scorer(tmp_path)
    monkeypatch.setattr(main, "get_scorer", lambda: sc)
    monkeypatch.setattr(main, "_deception_error", None)
    with patch("inference.main._notify"), \
         patch("inference.predictor.SentinelPredictor.get_model_info", return_value={"version": "test"}), \
         TestClient(main.app) as client:
        yield client, sc, table, {"X-API-Key": os.environ["SENTINEL_KEY"]}


def _rec(client, h, current="centos_7"):
    random.seed(3)
    r = client.get(f"/deception/recommendation?current={current}", headers=h)
    assert r.status_code == 200
    return r.json()


def test_shadow_mode_reports_v2_and_never_applies_it(engine):
    client, sc, table, h = engine
    before = table.read_bytes()
    out = _rec(client, h)
    assert out["policy"] == "q_learning" and out["nextProfile"] in ds.servable_profiles()
    assert out["shadow"]["applied"] is False and out["shadow"]["status"] == "OK"
    assert out["shadow"]["recommendation"] in ds.servable_profiles()
    assert table.read_bytes() == before


def test_invalid_or_failing_v2_never_reaches_next_profile(engine):
    client, sc, table, h = engine
    v1_only = _rec(client, h)["nextProfile"]
    sc.v2.recommend = lambda current=None: "windows_srv"
    out = _rec(client, h)
    assert out["nextProfile"] == v1_only and out["shadow"]["status"] == "INVALID_RECOMMENDATION"
    sc.v2.stats = MagicMock(side_effect=RuntimeError("v2 down"))
    out = _rec(client, h)
    assert out["nextProfile"] == v1_only and "shadow" not in out


def test_active_mode_falls_back_to_v1_on_an_invalid_pick(engine):
    client, sc, table, h = engine
    v1_only = _rec(client, h)["nextProfile"]
    sc.v2_mode = "active"  # the manual owner switch; never set by this code
    sc.v2.recommend = lambda current=None: "windows_srv"
    out = _rec(client, h)
    assert out["nextProfile"] == v1_only and out["policy"] == "q_learning"
    assert out["shadow"]["status"] == "INVALID_RECOMMENDATION" and out["shadow"]["applied"] is False


# ── evaluation ───────────────────────────────────────────────────────────────────────────────────────────────────
def rec(v1, v2, served="ubuntu_22", status="OK", ref=None, source="operator"):
    return {"schemaVersion": R6.EVIDENCE_SCHEMA, "policyVersion": v2mod.POLICY_VERSION, "sessionRef": ref or os.urandom(4).hex(),
            "stateVersion": R6.STATE_VERSION, "stateHash": "x", "evidenceSource": source, "productionPersona": served,
            "v1Recommendation": v1, "shadowPersona": v2 if status == "OK" else None, "decisionTimestamp": None,
            "decisionReason": {}, "decisionStatus": status, "errorCode": None if status == "OK" else "E"}


def test_agreement_distribution_and_concentration():
    recs = [rec("centos_7", "centos_7"), rec("centos_7", "aws_ec2"), rec("ubuntu_22", "ubuntu_22"),
            rec("centos_7", None, status="ERROR"), rec("debian_11", None, status="INVALID_RECOMMENDATION")]
    c = R6.compare(recs)
    assert (c["samples"], c["v1_successful"], c["v2_successful"], c["v2_errors"], c["v2_invalid_or_unsupported"]) == (5, 5, 3, 1, 1)
    assert (c["agreement"], c["disagreement"], c["agreement_pct"]) == (2, 1, 66.67)
    assert c["v1"] == {"centos_7": 3, "ubuntu_22": 1, "debian_11": 1} and c["v2"] == {"centos_7": 1, "aws_ec2": 1, "ubuntu_22": 1}
    assert c["v2_concentration"]["never_selected"] == ["debian_11", "raspberry_pi"]
    assert c["fallbacks"] == 0
    even = R6.concentration({p: 1 for p in ds.servable_profiles()}, ds.servable_profiles())
    assert even["normalised_entropy"] == 1.0 and even["max_share"] == 0.2


def test_empty_dataset_is_handled():
    c = R6.compare([])
    assert c["samples"] == 0 and c["agreement_pct"] is None and c["v1_concentration"]["total"] == 0


def test_evidence_records_are_validated():
    good = [rec("centos_7", "centos_7", ref="a"), rec("centos_7", "aws_ec2", ref="b")]
    assert R6.validate_records(good) == []
    bad = [dict(good[0], sourceIP="203.0.113.5"), rec("x", "windows_srv", ref="c"), rec("x", "centos_7", ref="a"),
           dict(rec("x", "centos_7", ref="d"), evidenceSource="attacker"), dict(rec("x", None, ref="e", status="ERROR"), shadowPersona="debian_11")]
    kinds = {k for p in R6.validate_records(bad) for k in p if k != "record"}
    assert {"forbidden", "shadowPersona", "duplicate_sessionRef", "evidenceSource", "shadowPersona_on_failure"} <= kinds


def test_replay_is_deterministic_writes_nothing_and_excludes_identifiers(tmp_path):
    sessions = [{"sessionId": f"x{i}", "servedProfile": ds.servable_profiles()[i % 2], "reward": float(i % 5),
                 "evidenceSource": "simulated", "startTime": f"2026-11-0{1 + i % 9}T00:00:00+00:00"} for i in range(20)]
    a, b = R6.replay(sessions, copy.deepcopy(SEED)), R6.replay(sessions, copy.deepcopy(SEED))
    assert json.dumps(a["records"], sort_keys=True) == json.dumps(b["records"], sort_keys=True)
    assert R6.validate_records(a["records"]) == []
    text = json.dumps(a["records"])
    assert "x1\"" not in text and "sessionId" not in text
    assert a["v1_learning"]["episodes"] == SEED["episode_count"] + 20 and a["v2_learning"]["realEpisodes"] == 20
    assert R6.hash_artifacts(ARTIFACTS) == BEFORE


def test_sessions_are_deduplicated_unsupported_skipped_and_classified(tmp_path):
    raw = [{"sessionId": "a", "servedProfile": "ubuntu_22", "sourceIP": "127.0.0.1", "startTime": "2026-11-01T00:00:00Z",
            "durationSeconds": 10, "commands": []},
           {"sessionId": "a", "servedProfile": "ubuntu_22", "sourceIP": "127.0.0.1", "startTime": "2026-11-01T00:00:00Z"},
           {"sessionId": "b", "servedProfile": "windows_srv", "sourceIP": "198.51.100.1"},
           {"sessionId": "c", "servedProfile": None},
           {"sessionId": "demo-1", "servedProfile": "centos_7", "sourceIP": "198.51.100.2", "startTime": "2026-11-02T00:00:00Z"},
           {"sessionId": "d", "servedProfile": "debian_11", "sourceIP": "1.2.3.4", "startTime": "2026-11-03T00:00:00Z",
            "shadowPolicy": {"recommendation": "centos_7", "status": "OK"}, "recommendedProfile": "centos_7"}]
    f = tmp_path / "sessions.json"
    f.write_text(json.dumps(raw))
    args = Namespace(mongo_uri=None, sessions_file=str(f), decisions_file=None, operator_ip=None, operator_cidr=None)
    sessions, skipped, live = R6.load_sessions(args)
    assert [s["sessionId"] for s in sessions] == ["a", "demo-1", "d"]
    assert skipped == {"unsupported_served_persona": 1, "no_served_persona": 1, "duplicate_session_id": 1}
    assert [s["evidenceSource"] for s in sessions] == ["operator", "simulated", "external"]
    ev = R6.evidence_summary(sessions, live)
    assert ev["independent_external_sessions"] == 1 and ev["live_shadow_agreement_with_v1"] == 1
    assert ev["synthetic_seed_episodes"] == 12087 and ev["q_table_untracked_updates"] == 19  # Rank 3 report, never "external"


# ── readiness ────────────────────────────────────────────────────────────────────────────────────────────────────
def _ev(per):
    return {"recorded_sessions_per_persona_by_source": per}


def test_insufficient_evidence_is_never_ready():
    reg = R6.persona_registry()
    iso = R6.isolation_self_checks(copy.deepcopy(SEED))
    comp = {"records_valid": True, "record_problems": []}
    few = R6.readiness(reg, iso, comp, True, _ev({p: {"operator": 16} for p in ds.servable_profiles()}), {"passed": True})
    assert few["overall"] == "NOT_READY" and few["shadow_engineering"] == "PASS"
    assert few["gates"]["7_adequate_session_evidence"]["status"] == "INSUFFICIENT_DATA"
    many_operator = R6.readiness(reg, iso, comp, True, _ev({p: {"operator": 500} for p in ds.servable_profiles()}), {"passed": True})
    assert many_operator["gates"]["7_adequate_session_evidence"]["status"] == "PASS"
    assert many_operator["gates"]["8_independent_evidence"]["status"] == "INSUFFICIENT_DATA"  # operator is not independent
    assert many_operator["overall"] == "NOT_READY"
    # even with everything else passing, the documented acceptance criteria stay NOT_MET here: no automatic promotion
    best = R6.readiness(reg, iso, comp, True, _ev({p: {"external": 500} for p in ds.servable_profiles()}), {"passed": True})
    assert best["gates"]["10_documented_acceptance_criteria"]["status"] == "NOT_MET" and best["overall"] == "NOT_READY"
    failed_sim = R6.readiness(reg, iso, comp, False, _ev({}), {"passed": False, "failures": ["C2"]})
    assert failed_sim["gates"]["9_decision_stability"]["status"] == "FAIL"
    assert failed_sim["gates"]["6_reproducible_evaluation"]["status"] == "FAIL" and failed_sim["shadow_engineering"] == "FAIL"


def test_runs_never_overwrite(tmp_path):
    a = R6.new_run_dir(tmp_path, "20261114T000000Z")
    b = R6.new_run_dir(tmp_path, "20261114T000000Z")
    assert a != b
    R6._write(a / "x.json", "{}")
    with pytest.raises(FileExistsError):
        R6._write(a / "x.json", "{}")


def test_shipped_seed_untouched_by_this_module():
    assert hashlib.sha256((Path(ds.__file__).resolve().parent.parent / "models" / "q_table.json").read_bytes()).hexdigest() \
        == BEFORE["shipped_seed"]["sha256"]


# ── provenance reconciliation (Rank 6 corrections) ───────────────────────────────────────────────────────────────
def _prov_sessions():
    return [{"sessionId": f"p{i}", "servedProfile": "ubuntu_22" if i < 3 else "centos_7", "evidenceSource": lbl}
            for i, lbl in enumerate(["operator", "operator", "operator", "external", "operator"])]


def test_a_replay_label_without_recorded_provenance_stays_untracked():
    prov = R6.reconcile_provenance(_prov_sessions(), {}, ql={})
    assert prov["total_sessions_evaluated"] == 5 and prov["labelled_operator_in_replay"] == 4
    assert prov["with_recorded_source_provenance"] == 0 and prov["with_recorded_and_verified_provenance"] == 0
    assert prov["with_untracked_or_unverifiable_provenance"] == 5
    # an address-inferred "external" label is not independent evidence
    assert prov["independently_verified_external"] == 0 and prov["synthetic_seed_episodes_counted_as_sessions"] == 0
    assert "remains untracked" in prov["statement"]


def test_recorded_and_admin_verified_provenance_are_kept_apart():
    rec = {"p0": {"recorded": "operator", "method": "automatic", "scored": True},
           "p1": {"recorded": "operator", "method": "admin", "scored": True},
           "p3": {"recorded": "external", "method": "admin", "scored": False}}
    prov = R6.reconcile_provenance(_prov_sessions(), rec, ql={})
    assert prov["with_recorded_source_provenance"] == 3 and prov["with_recorded_and_verified_provenance"] == 2
    assert prov["with_untracked_or_unverifiable_provenance"] == 3 and prov["scored_by_engine"] == 2
    assert prov["independently_verified_external"] == 1
    assert prov["independently_verified_external_per_persona"]["centos_7"] == 1


def test_the_q_table_updates_are_never_linked_to_replayed_sessions():
    ql = {"episodes": {"sessionDriven": 19, "untracked": 19}, "learnedSessionIndex": {"sessions": 0}}
    link = R6.reconcile_provenance(_prov_sessions(), {}, ql=ql)["q_table_link"]
    assert link["linked_to_replayed_sessions"] is False and link["q_table_untracked_updates"] == 19


def test_independent_evidence_gate_counts_recorded_external_only():
    reg = R6.persona_registry()
    iso = R6.isolation_self_checks(copy.deepcopy(SEED))
    comp = {"records_valid": True, "record_problems": []}
    inferred = _ev({p: {"external": 500} for p in ds.servable_profiles()})
    prov = R6.reconcile_provenance([], {}, ql={})
    r = R6.readiness(reg, iso, comp, True, inferred, {"passed": True}, prov)
    assert r["gates"]["8_independent_evidence"]["status"] == "INSUFFICIENT_DATA"
    assert set(r["gates"]["8_independent_evidence"]["evidence"]["external_per_persona"].values()) == {0}


def test_recorded_provenance_is_read_from_the_session_records(tmp_path):
    f = tmp_path / "sessions.json"
    f.write_text(json.dumps([{"sessionId": "a", "evidenceSource": "operator", "evidenceLabel": {"method": "admin"}},
                             {"sessionId": "b", "evidenceSource": "bogus", "deceptionScoredAt": "2026-11-01T00:00:00Z"},
                             {"sessionId": "c"}]))
    args = Namespace(mongo_uri=None, sessions_file=str(f), decisions_file=None, operator_ip=None, operator_cidr=None)
    assert R6.recorded_provenance(args) == {"a": {"recorded": "operator", "method": "admin", "scored": False},
                                            "b": {"recorded": None, "method": None, "scored": True},
                                            "c": {"recorded": None, "method": None, "scored": False}}
