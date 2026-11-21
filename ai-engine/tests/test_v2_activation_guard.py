"""Rank 6 corrections: fail-closed activation of persona policy v2 (rl_engine/v2_activation.py,
docs/PERSONA_POLICY_V2.md section 10).

DECEPTION_V2=active (the owner's switch) is necessary but not sufficient: v2 serves only with a valid, current
READY readiness file in which every mandatory gate passes, and only a servable persona. Everything else keeps v1
authoritative. Readiness files here are temporary fixtures; the real environment is never switched to active and
production artifacts are hashed before and after the module.
"""
import json
import os
import itertools
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))
from evaluation import rank6_v2_shadow_eval as R6  # noqa: E402
from rl_engine import deception_scorer as ds  # noqa: E402
from rl_engine import persona_policy_v2 as v2mod  # noqa: E402
from rl_engine import v2_activation as guard  # noqa: E402
from v2_readiness_fixture import readiness, write_run  # noqa: E402

SEED = json.loads((Path(ds.__file__).resolve().parent.parent / "models" / "q_table.json").read_text())
ARTIFACTS = R6.production_artifacts()
BEFORE = R6.hash_artifacts(ARTIFACTS)
REAL_EVIDENCE = R6.DEFAULT_OUT
REAL_EVIDENCE_BEFORE = {p.relative_to(REAL_EVIDENCE).as_posix(): p.read_bytes() for p in REAL_EVIDENCE.rglob("*") if p.is_file()} \
    if REAL_EVIDENCE.is_dir() else {}


@pytest.fixture(autouse=True, scope="module")
def production_artifacts_unchanged():
    yield
    assert R6.hash_artifacts(ARTIFACTS) == BEFORE
    after = {p.relative_to(REAL_EVIDENCE).as_posix(): p.read_bytes() for p in REAL_EVIDENCE.rglob("*") if p.is_file()} \
        if REAL_EVIDENCE.is_dir() else {}
    assert after == REAL_EVIDENCE_BEFORE


# ── the guard on its own ─────────────────────────────────────────────────────────────────────────────────────────
def test_valid_ready_evidence_is_the_only_thing_that_allows_activation(tmp_path):
    d = guard.activation_decision("active", write_run(tmp_path))
    assert d["allowed"] is True and d["readiness"] == "READY" and d["requested"] is True


@pytest.mark.parametrize("overall", ["NOT_READY", "NOT_VERIFIED", "LIMITED", "INSUFFICIENT_DATA", "FAILED", "", None, "ready"])
def test_every_status_other_than_ready_blocks(tmp_path, overall):
    data = readiness(overall)
    if overall is None:
        data.pop("overall")
    d = guard.activation_decision("active", write_run(tmp_path, data))
    assert d["allowed"] is False and d["reason"].startswith("READINESS_")


@pytest.mark.parametrize("case", ["no_dir", "empty_dir", "run_without_file"])
def test_missing_readiness_evidence_blocks(tmp_path, case):
    base = tmp_path / "r6"
    if case != "no_dir":
        base.mkdir()
    if case == "run_without_file":
        (base / "run_20991231T000000Z").mkdir()
    d = guard.activation_decision("active", base)
    assert d["allowed"] is False and d["reason"] == "READINESS_EVIDENCE_MISSING"


@pytest.mark.parametrize("raw,reason", [("{not json", "READINESS_EVIDENCE_INVALID_JSON"), ("", "READINESS_EVIDENCE_INVALID_JSON"),
                                        ("[1, 2]", "READINESS_EVIDENCE_INVALID"), ('"READY"', "READINESS_EVIDENCE_INVALID")])
def test_invalid_json_blocks(tmp_path, raw, reason):
    assert guard.activation_decision("active", write_run(tmp_path, raw=raw))["reason"] == reason


def test_unreadable_file_blocks(tmp_path):
    base = write_run(tmp_path)
    (base / "run_20991231T000000Z" / "readiness_status.json").write_bytes(b"\xff\xfe\x00bad")
    assert guard.activation_decision("active", base)["allowed"] is False


@pytest.mark.parametrize("gate", guard.MANDATORY_GATES)
def test_a_failed_mandatory_gate_blocks_even_when_overall_says_ready(tmp_path, gate):
    d = guard.activation_decision("active", write_run(tmp_path, readiness("READY", **{gate: "FAIL"})))
    assert d["allowed"] is False and d["reason"] == "READINESS_GATES_FAILED" and d["failedGates"] == {gate: "FAIL"}


def test_missing_mandatory_gates_block(tmp_path):
    data = readiness()
    del data["gates"]["8_independent_evidence"]
    d = guard.activation_decision("active", write_run(tmp_path, data))
    assert d["reason"] == "READINESS_GATES_MISSING" and d["failedGates"] == ["8_independent_evidence"]
    data.pop("gates")
    assert guard.activation_decision("active", write_run(tmp_path / "b", data))["reason"] == "READINESS_GATES_MISSING"


def test_insufficient_evidence_blocks(tmp_path):
    data = readiness("NOT_READY", **{"7_adequate_session_evidence": "INSUFFICIENT_DATA", "8_independent_evidence": "INSUFFICIENT_DATA"})
    d = guard.activation_decision("active", write_run(tmp_path, data))
    assert d["allowed"] is False and d["readiness"] == "NOT_READY"
    assert d["failedGates"] == {"7_adequate_session_evidence": "INSUFFICIENT_DATA", "8_independent_evidence": "INSUFFICIENT_DATA"}


@pytest.mark.parametrize("change,reason", [
    ({"smoke": True}, "READINESS_EVIDENCE_NOT_PRODUCTION_RUN"),
    ({"fixture": True}, "READINESS_EVIDENCE_NOT_PRODUCTION_RUN"),
    ({"data_source": "sessions file export"}, "READINESS_EVIDENCE_NOT_PRODUCTION_RUN"),
    ({"rank6_version": "rank6/0"}, "READINESS_EVIDENCE_NOT_PRODUCTION_RUN"),
    ({"policy_version": "persona-ducb-v1"}, "READINESS_EVIDENCE_STALE"),
    ({"v2_defaults": {**v2mod.DEFAULTS, "exploration": 0.5}}, "READINESS_EVIDENCE_STALE"),
    ({"generated_at": "2999-01-01T00:00:00+00:00"}, "READINESS_EVIDENCE_INVALID"),
    ({"generated_at": "yesterday"}, "READINESS_EVIDENCE_INVALID"),
    ({"shadow_engineering": "FAIL"}, "READINESS_GATES_FAILED"),
])
def test_smoke_stale_or_invalid_evidence_blocks(tmp_path, change, reason):
    assert guard.activation_decision("active", write_run(tmp_path, {**readiness(), **change}))["reason"] == reason


@pytest.mark.parametrize("integrity", [False, None])
def test_altered_production_artifacts_or_missing_integrity_record_blocks(tmp_path, integrity):
    d = guard.activation_decision("active", write_run(tmp_path, integrity=integrity))
    assert d["reason"] == "READINESS_EVIDENCE_INTEGRITY_FAILED"


def test_a_newer_invalid_run_is_not_replaced_by_an_older_ready_one(tmp_path):
    write_run(tmp_path, name="run_20261101T000000Z")
    write_run(tmp_path, raw="{broken", name="run_20261102T000000Z")
    assert guard.activation_decision("active", tmp_path)["allowed"] is False


def test_ready_evidence_without_the_owner_switch_activates_nothing(tmp_path):
    for mode in ("shadow", "off", "", "ACTIVE", "true"):
        d = guard.activation_decision(mode, write_run(tmp_path))
        assert d == {"allowed": False, "requested": False, "readiness": None, "reason": "NOT_REQUESTED"}


def test_a_guard_crash_blocks(tmp_path, monkeypatch):
    monkeypatch.setattr(guard, "readiness_decision", MagicMock(side_effect=RuntimeError("boom")))
    d = guard.activation_decision("active", tmp_path)
    assert d["allowed"] is False and d["reason"] == "READINESS_CHECK_ERROR:RuntimeError"


def test_the_current_real_evidence_blocks_activation():
    """Read-only: the repository's own newest Rank 6 run is NOT_READY, so active mode would be refused today."""
    d = guard.activation_decision("active")
    assert d["allowed"] is False and d["readiness"] == "NOT_READY"


# ── the endpoint ─────────────────────────────────────────────────────────────────────────────────────────────────
def scorer(tmp_path, mode):
    tmp_path.mkdir(parents=True, exist_ok=True)
    table = tmp_path / "q.json"
    table.write_text(json.dumps(SEED))
    sc = ds.SessionScorer(q_table_path=str(table))
    sc.v2 = v2mod.PersonaPolicyV2(tmp_path / "v2.json", prior_means=v2mod.prior_from_q_table(SEED["q_table"]))
    sc.v2_mode = mode  # set on a test object only; the environment's DECEPTION_V2 is never touched
    sc.v1_pick = "centos_7"
    sc.learner.choose_action = lambda current: sc.v1_pick
    return sc, table


@pytest.fixture
def engine(tmp_path, monkeypatch):
    os.environ.setdefault("SENTINEL_KEY", "test-sentinel-secret-key-12345")
    with patch("inference.predictor.SentinelPredictor.load"), patch("inference.predictor.SentinelPredictor.init_explainer"), \
         patch("joblib.load", return_value=MagicMock()):
        import inference.main as main
    from fastapi.testclient import TestClient
    monkeypatch.setattr(main, "_v2_last_block", None)
    counter = itertools.count()

    def make(mode="active", evidence=None, v2_pick="raspberry_pi"):
        sc, table = scorer(tmp_path / f"s{next(counter)}", mode)
        sc.v2_readiness_dir = evidence
        sc.v2.stats = lambda current: {"policyVersion": v2mod.POLICY_VERSION, "recommendation": v2_pick, "explored": False}
        monkeypatch.setattr(main, "_deception_scorer", lambda: sc)
        return sc, table

    with patch("inference.main._notify"), patch("inference.predictor.SentinelPredictor.get_model_info", return_value={"version": "test"}), \
         TestClient(main.app) as client:
        def call():
            r = client.get("/deception/recommendation?current=ubuntu_22", headers={"X-API-Key": os.environ["SENTINEL_KEY"]})
            assert r.status_code == 200
            return r.json()
        yield make, call, main


def assert_v1_serves(out, reason_prefix=None):
    assert out["nextProfile"] == "centos_7" and out["policy"] == "q_learning" and "policyV1" not in out
    if "shadow" in out:
        assert out["shadow"]["applied"] is False
    if reason_prefix:
        assert out["v2Activation"]["allowed"] is False and out["v2Activation"]["reason"].startswith(reason_prefix)


def test_1_active_and_not_ready_v1_serves(engine, tmp_path):
    make, call, _ = engine
    make(evidence=write_run(tmp_path / "e", readiness("NOT_READY", **{"9_decision_stability": "FAIL"})))
    out = call()
    assert_v1_serves(out, "READINESS_NOT_READY")
    assert out["v2Activation"]["requested"] is True and out["shadow"]["recommendation"] == "raspberry_pi"


def test_2_active_and_missing_readiness_file_v1_serves(engine, tmp_path):
    make, call, _ = engine
    make(evidence=tmp_path / "nothing-here")
    assert_v1_serves(call(), "READINESS_EVIDENCE_MISSING")


def test_3_active_and_invalid_json_v1_serves(engine, tmp_path):
    make, call, _ = engine
    make(evidence=write_run(tmp_path / "e", raw="{oops"))
    assert_v1_serves(call(), "READINESS_EVIDENCE_INVALID_JSON")


def test_4_active_and_failed_mandatory_gate_v1_serves(engine, tmp_path):
    make, call, _ = engine
    make(evidence=write_run(tmp_path / "e", readiness("READY", **{"1_shadow_isolation": "FAIL"})))
    assert_v1_serves(call(), "READINESS_GATES_FAILED")


def test_5_active_and_insufficient_evidence_v1_serves(engine, tmp_path):
    make, call, _ = engine
    make(evidence=write_run(tmp_path / "e", readiness("INSUFFICIENT_DATA", **{"8_independent_evidence": "INSUFFICIENT_DATA"})))
    assert_v1_serves(call(), "READINESS_INSUFFICIENT_DATA")


@pytest.mark.parametrize("bad", ["windows_srv", "alpine_3", None, 7])
def test_6_active_ready_and_unsupported_v2_persona_v1_serves(engine, tmp_path, bad):
    make, call, _ = engine
    make(evidence=write_run(tmp_path / "e"), v2_pick=bad)
    out = call()
    assert_v1_serves(out)
    assert out["v2Activation"]["allowed"] is True and out["shadow"]["status"] == "INVALID_RECOMMENDATION"


def test_7_v2_exception_v1_continues(engine, tmp_path):
    make, call, _ = engine
    sc, _ = make(evidence=write_run(tmp_path / "e"))
    sc.v2.stats = MagicMock(side_effect=RuntimeError("v2 down"))
    out = call()
    assert_v1_serves(out)
    assert "shadow" not in out


def test_7b_a_crashing_guard_keeps_v1(engine, tmp_path, monkeypatch):
    make, call, _ = engine
    make(evidence=write_run(tmp_path / "e"))
    monkeypatch.setattr(guard, "activation_decision", MagicMock(side_effect=RuntimeError("guard down")))
    assert_v1_serves(call(), "READINESS_CHECK_ERROR")


def test_8_shadow_mode_v1_serves_whatever_v2_says(engine, tmp_path):
    make, call, _ = engine
    for pick in ("raspberry_pi", "debian_11", "windows_srv"):
        make(mode="shadow", evidence=write_run(tmp_path / "e"), v2_pick=pick)
        out = call()
        assert_v1_serves(out)
        assert out["v2Activation"]["reason"] == "NOT_REQUESTED"


def test_9_ready_fixture_without_the_owner_switch_does_not_activate(engine, tmp_path):
    make, call, _ = engine
    make(mode="shadow", evidence=write_run(tmp_path / "e"))
    out = call()
    assert_v1_serves(out)
    assert out["v2Activation"] == {"allowed": False, "requested": False, "readiness": None, "reason": "NOT_REQUESTED"}
    # positive control: the same READY file with the owner's switch is the only way v2 serves
    make(mode="active", evidence=write_run(tmp_path / "e"))
    out = call()
    assert out["nextProfile"] == "raspberry_pi" and out["policy"] == v2mod.POLICY_VERSION
    assert out["policyV1"]["nextProfile"] == "centos_7"


def test_10_a_readiness_failure_cannot_modify_the_q_table(engine, tmp_path):
    make, call, _ = engine
    for evidence in (tmp_path / "missing", write_run(tmp_path / "bad", raw="{x"), write_run(tmp_path / "nr", readiness("NOT_READY"))):
        sc, table = make(evidence=evidence)
        before_table, before_q = table.read_bytes(), json.dumps(sc.learner.q_table, sort_keys=True)
        v2_state = sc.v2.state_path.read_bytes() if sc.v2.state_path.exists() else None
        for _ in range(3):
            assert_v1_serves(call(), "READINESS_")
        assert table.read_bytes() == before_table and json.dumps(sc.learner.q_table, sort_keys=True) == before_q
        assert (sc.v2.state_path.read_bytes() if sc.v2.state_path.exists() else None) == v2_state


def test_blocked_activation_is_logged_once_per_reason_and_visible_in_stats(engine, tmp_path, caplog):
    make, call, main = engine
    make(evidence=write_run(tmp_path / "e", readiness("NOT_READY")))
    with caplog.at_level("WARNING"):
        call(), call(), call()
    assert sum("requested but blocked" in r.getMessage() for r in caplog.records) == 1
    from fastapi.testclient import TestClient
    with patch("inference.main._notify"), patch("inference.predictor.SentinelPredictor.get_model_info", return_value={"version": "test"}), \
         TestClient(main.app) as c:
        st = c.get("/deception/stats", headers={"X-API-Key": os.environ["SENTINEL_KEY"]}).json()
    assert st["v2Activation"]["allowed"] is False and st["v2Activation"]["reason"] == "READINESS_NOT_READY"
