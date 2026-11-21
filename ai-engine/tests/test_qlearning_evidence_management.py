"""
Q-learning evidence management (docs/QLEARNING_EVIDENCE.md, "How it is verified"): provenance, source
classification, duplicate-session protection, the bounded update log, failure handling and the read-only report.

Every learner here writes to pytest's tmp_path (conftest also isolates the default runtime path). The shipped seed
models/q_table.json is only read; the test asserts its hash is unchanged. No real table, seed or v2 state is
written, no training run is started, and no policy setting is changed.
"""
import hashlib
import json
import os
import stat
import sys
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))
from rl_engine import deception_scorer as ds  # noqa: E402

SEED = Path(ds.__file__).resolve().parent.parent / "models" / "q_table.json"
SEED_SHA = hashlib.sha256(SEED.read_bytes()).hexdigest()


@pytest.fixture(autouse=True)
def seed_is_never_written():
    yield
    assert hashlib.sha256(SEED.read_bytes()).hexdigest() == SEED_SHA


@pytest.fixture
def table(tmp_path):
    return tmp_path / "q.json"


def learner(path):
    return ds.DeceptionQLearner(q_table_path=str(path))


def session(sid, source="operator", persona="ubuntu_22", duration=120, **extra):
    s = {"sessionId": sid, "durationSeconds": duration, "loginSucceeded": True,
         "commands": [{"command": "uname -a", "intent": "RECONNAISSANCE"}], "deceptionProfile": persona,
         "evidenceSource": source}
    s.update(extra)
    return s


def frozen(L):
    return json.dumps({"q": L.q_table, "n": L.episode_count, "arms": L.arm_stats, "c": L.evidence_counts,
                       "log": L.update_log, "ids": L.learned_sessions}, sort_keys=True)


# ── provenance and source classification ──────────────────────────────────────────────────────────────────────────
@pytest.mark.parametrize("raw,source,issue", [
    ("operator", "operator", None), ("external", "external", None), ("simulated", "simulated", None),
    ("unknown", "unknown", None), (" Operator ", "operator", None), ("EXTERNAL", "external", None),
    (None, "unknown", "missing"), ("", "unknown", "missing"), ("   ", "unknown", "missing"),
    ("real", "unknown", "invalid"), ("observed", "unknown", "invalid"), ("synthetic", "unknown", "invalid"),
    ("analyst", "unknown", "invalid"), ("external;operator", "unknown", "invalid"), (42, "unknown", "invalid"),
])
def test_source_classification(raw, source, issue):
    assert ds.normalise_source(raw) == source
    assert ds.source_issue(raw) == issue


def test_unknown_or_invalid_sources_are_never_counted_as_independent_or_real(table):
    sc = ds.SessionScorer(q_table_path=str(table))
    for i, raw in enumerate([None, "", "real", "independent", "analyst-verified", "external-ish"]):
        r = sc.process_session(session(f"s{i}", source=raw))
        assert r["learned"] is True and r["evidenceSource"] == "unknown"
    p = sc.learner.provenance()
    assert p["bySource"] == {"operator": 0, "external": 0, "simulated": 0, "unknown": 6}
    assert p["independentExternalSessions"] == 0
    assert p["provenanceIssues"] == {"missing": 2, "invalid": 4}
    assert [e.get("sourceIssue") for e in sc.learner.update_log] == ["missing"] * 2 + ["invalid"] * 4


def test_source_is_preserved_from_session_to_update_log_to_disk(table):
    sc = ds.SessionScorer(q_table_path=str(table))
    for sid, src, persona in [("op-1", "operator", "ubuntu_22"), ("ext-1", "external", "debian_11"),
                              ("sim-1", "simulated", "centos_7")]:
        assert sc.process_session(session(sid, source=src, persona=persona))["evidenceSource"] == src
    reloaded = learner(table)
    assert reloaded.provenance()["bySource"] == {"operator": 1, "external": 1, "simulated": 1, "unknown": 0}
    assert reloaded.learned_sessions == {"op-1": "operator", "ext-1": "external", "sim-1": "simulated"}
    assert [(e["sessionId"], e["source"], e["persona"]) for e in reloaded.update_log] == [
        ("op-1", "operator", "ubuntu_22"), ("ext-1", "external", "debian_11"), ("sim-1", "simulated", "centos_7")]
    assert reloaded.arm_evidence["debian_11"]["external"] == 1 and reloaded.arm_evidence["ubuntu_22"]["operator"] == 1


def test_the_api_model_keeps_the_evidence_label():
    """SessionData allows extra fields, so the backend's evidenceSource reaches process_session."""
    with patch("inference.predictor.SentinelPredictor.load"), \
         patch("inference.predictor.SentinelPredictor.init_explainer"), \
         patch("joblib.load", return_value=MagicMock()):
        os.environ.setdefault("SENTINEL_KEY", "test-sentinel-secret-key-12345")
        import inference.main as main
    dumped = main.SessionData(sessionId="s", evidenceSource="operator").model_dump()
    assert dumped["evidenceSource"] == "operator"


def test_synthetic_seed_is_reported_separately_from_session_evidence(table):
    data = json.loads(SEED.read_text())
    data["seed_provenance"] = {"source": "models/q_table.json (synthetic warm start)",
                               "episodes": data["episode_count"], "synthetic": True}
    table.write_text(json.dumps(data))
    L = learner(table)
    p = L.provenance()
    assert p["synthetic"] is True and p["seedEpisodes"] == data["episode_count"] and p["sessionEpisodes"] == 0
    assert sum(p["bySource"].values()) == 0  # the seed never appears as session evidence of any source
    L.update("centos_7", "ubuntu_22", 3.0, "ubuntu_22", session_id="op-1", source="operator")
    p = L.provenance()
    assert p["sessionEpisodes"] == 1 and p["bySource"]["operator"] == 1 and p["untrackedSessionEpisodes"] == 0


# ── historical compatibility ─────────────────────────────────────────────────────────────────────────────────────
def test_historical_tables_load_without_reclassification(table):
    legacy = {"q_table": {"ubuntu_22": {"centos_7": 1.25}}, "episode_count": 119,
              "seed_provenance": {"source": "seed", "episodes": 100, "synthetic": True},
              "evidence": {"counts": {"operator": 0}, "update_log": [{"sessionId": "old", "source": "operator"}]}}
    table.write_text(json.dumps(legacy))
    L = learner(table)
    p = L.provenance()
    assert p["untrackedSessionEpisodes"] == 19 and p["trackedSessionEpisodes"] == 0
    assert p["provenanceIssues"] == {"missing": 0, "invalid": 0} and p["missingSessionIdRejected"] == 0
    assert L.q_table["ubuntu_22"]["centos_7"] == 1.25  # values are read, never rescaled
    L.update("centos_7", "ubuntu_22", 3.0, "ubuntu_22", session_id="new-1", source="operator")
    saved = json.loads(table.read_text())
    assert saved["episode_count"] == 120
    assert saved["evidence"]["counts"]["operator"] == 1  # the untracked 19 are not relabelled as anything
    assert saved["evidence"]["update_log"][0] == {"sessionId": "old", "source": "operator"}
    assert saved["seed_provenance"] == legacy["seed_provenance"]


# ── duplicate-session protection ─────────────────────────────────────────────────────────────────────────────────
def test_first_ingestion_then_replays_are_refused(table):
    sc = ds.SessionScorer(q_table_path=str(table))
    assert sc.process_session(session("s-1"))["learned"] is True
    before = frozen(sc.learner)
    for variant in [session("s-1"), session("s-1", duration=9999), session("s-1", source="external"),
                    session("s-1", persona="debian_11")]:
        r = sc.process_session(variant)
        assert r["learned"] is False and r["duplicate"] is True
    assert frozen(sc.learner) == before  # no TD update, episode, arm sample, count or log entry
    assert sc.learner.duplicates_rejected == 4
    assert learner(table).provenance()["bySource"]["operator"] == 1


def test_sessions_without_an_id_are_scored_but_never_learned(table):
    sc = ds.SessionScorer(q_table_path=str(table))
    before = frozen(sc.learner)
    for sid in ["", None, "   "]:
        r = sc.process_session(session(sid))
        assert r["learned"] is False and r["missingSessionId"] is True and r["duplicate"] is False
        assert r["nextProfile"] in ds.servable_profiles() and r["deceptionScore"] > 0  # still answered
    assert frozen(sc.learner) == before
    assert sc.learner.missing_session_id_rejected == 3
    assert sc.learner.provenance()["missingSessionIdRejected"] == 3


def test_different_sessions_with_identical_contents_are_each_learned(table):
    sc = ds.SessionScorer(q_table_path=str(table))
    assert sc.process_session(session("a"))["learned"] and sc.process_session(session("b"))["learned"]
    assert sc.learner.provenance()["bySource"]["operator"] == 2 and sc.learner.duplicates_rejected == 0


def test_concurrent_processes_learning_the_same_session_apply_one_update(table, monkeypatch):
    monkeypatch.setenv("Q_SAVE_EVERY", "1000")  # both hold the update pending, then write over each other
    a, b = learner(table), learner(table)
    single = learner(table.with_name("single.json"))
    for L in (a, b, single):
        assert L.update("centos_7", "ubuntu_22", 3.0, "ubuntu_22", session_id="same", source="operator")
    b.update("centos_7", "debian_11", 2.0, "debian_11", session_id="only-b", source="external")
    a.save()
    b.save()
    merged = learner(table)
    # One TD update for "same" (before the fix the merge replayed it: Q moved twice, 2 episodes, n=2)
    assert merged.q_table["centos_7"]["ubuntu_22"] == single.q_table["centos_7"]["ubuntu_22"]
    assert merged.episode_count == 2 and merged.arm_stats["ubuntu_22"]["n"] == 1
    assert merged.provenance()["bySource"] == {"operator": 1, "external": 1, "simulated": 0, "unknown": 0}
    assert merged.duplicates_rejected == 1
    assert [e["sessionId"] for e in merged.update_log] == ["same", "only-b"]


def test_concurrent_api_submissions_of_one_session_learn_once(tmp_path, monkeypatch):
    with patch("inference.predictor.SentinelPredictor.load"), \
         patch("inference.predictor.SentinelPredictor.init_explainer"), \
         patch("joblib.load", return_value=MagicMock()):
        os.environ.setdefault("SENTINEL_KEY", "test-sentinel-secret-key-12345")
        import inference.main as main
    from fastapi.testclient import TestClient
    scorer = ds.SessionScorer(q_table_path=str(tmp_path / "api.json"))
    monkeypatch.setattr(main, "get_scorer", lambda: scorer)
    monkeypatch.setattr(main, "_deception_error", None)
    headers = {"X-API-Key": os.environ["SENTINEL_KEY"]}
    with patch("inference.main._notify"), \
         patch("inference.predictor.SentinelPredictor.get_model_info", return_value={"version": "test"}), \
         TestClient(main.app) as client:
        body = {**session("api-dup"), "sourceIP": "203.0.113.5"}
        with ThreadPoolExecutor(max_workers=8) as pool:
            results = list(pool.map(lambda _: client.post("/deception/score", json=body, headers=headers), range(8)))
    assert all(r.status_code == 200 for r in results)
    learned = [r.json()["result"]["learned"] for r in results]
    assert learned.count(True) == 1 and learned.count(False) == 7
    assert scorer.learner.provenance()["bySource"]["operator"] == 1
    assert scorer.learner.episode_count == 1 and scorer.learner.duplicates_rejected == 7


# ── failure handling: no false success record ─────────────────────────────────────────────────────────────────────
@pytest.mark.parametrize("error", [TimeoutError("Q-table lock busy"), PermissionError("read-only"), OSError("disk full")])
def test_a_failed_save_records_nothing_and_a_retry_succeeds(table, error):
    sc = ds.SessionScorer(q_table_path=str(table))
    sc.process_session(session("ok-1"))
    before = frozen(sc.learner)
    disk_before = table.read_bytes()
    real_save = sc.learner.save
    sc.learner.save = MagicMock(side_effect=error)
    with pytest.raises(type(error)):
        sc.process_session(session("retry-1"))
    assert frozen(sc.learner) == before  # not marked learned, not counted, not logged
    assert not sc.learner.already_learned("retry-1") and table.read_bytes() == disk_before
    sc.learner.save = real_save
    r = sc.process_session(session("retry-1"))  # the backend's deferred retry
    assert r["learned"] is True and r["duplicate"] is False
    persisted = learner(table)
    assert persisted.already_learned("retry-1") and persisted.provenance()["bySource"]["operator"] == 2


def test_the_endpoint_reports_a_failed_update_and_the_retry_learns(tmp_path, monkeypatch):
    with patch("inference.predictor.SentinelPredictor.load"), \
         patch("inference.predictor.SentinelPredictor.init_explainer"), \
         patch("joblib.load", return_value=MagicMock()):
        os.environ.setdefault("SENTINEL_KEY", "test-sentinel-secret-key-12345")
        import inference.main as main
    from fastapi.testclient import TestClient
    scorer = ds.SessionScorer(q_table_path=str(tmp_path / "api2.json"))
    monkeypatch.setattr(main, "get_scorer", lambda: scorer)
    monkeypatch.setattr(main, "_deception_error", None)
    headers = {"X-API-Key": os.environ["SENTINEL_KEY"]}
    real_save = scorer.learner.save
    scorer.learner.save = MagicMock(side_effect=TimeoutError("Q-table lock busy"))
    with patch("inference.main._notify"), \
         patch("inference.predictor.SentinelPredictor.get_model_info", return_value={"version": "test"}), \
         TestClient(main.app) as client:
        body = {**session("api-retry"), "sourceIP": "203.0.113.6"}
        first = client.post("/deception/score", json=body, headers=headers)
        assert first.status_code == 500 and first.json()["detail"]["error"] == "DECEPTION_SCORING_FAILED"
        scorer.learner.save = real_save
        second = client.post("/deception/score", json=body, headers=headers)
    assert second.status_code == 200 and second.json()["result"]["learned"] is True
    assert scorer.learner.episode_count == 1


# ── bounded update log ────────────────────────────────────────────────────────────────────────────────────────────
def test_update_log_is_bounded_and_counts_stay_exact(table, monkeypatch):
    monkeypatch.setattr(ds, "UPDATE_LOG_MAX", 5)
    sc = ds.SessionScorer(q_table_path=str(table))
    sources = ["operator", "external", "simulated", None, "bogus"] * 4  # 20 sessions
    for i, src in enumerate(sources):
        sc.process_session(session(f"log-{i}", source=src, persona=ds.SUPPORTED_PROFILES[i % 5]))
    L = learner(table)
    assert len(L.update_log) == 5
    assert [e["sessionId"] for e in L.update_log] == [f"log-{i}" for i in range(15, 20)]  # oldest dropped first
    assert L.provenance()["bySource"] == {"operator": 4, "external": 4, "simulated": 4, "unknown": 8}
    assert sum(sum(r.values()) for r in L.arm_evidence.values()) == 20
    assert L.provenance()["provenanceIssues"] == {"missing": 4, "invalid": 4}
    assert len(L.learned_sessions) == 20 and L.episode_count == 20
    assert L.provenance()["updateLog"] == {"entries": 5, "max": 5}


def test_update_log_entries_hold_provenance_and_nothing_sensitive(table):
    sc = ds.SessionScorer(q_table_path=str(table))
    sc.process_session(session("priv-1", sourceIP="198.51.100.77", credentials=[{"password": "hunter2"}],
                               previousProfile="centos_7"))
    (entry,) = learner(table).update_log
    assert set(entry) == {"sessionId", "source", "state", "persona", "reward", "at"}
    assert (entry["sessionId"], entry["source"], entry["state"], entry["persona"]) == \
        ("priv-1", "operator", "centos_7", "ubuntu_22")
    assert datetime.fromisoformat(entry["at"]).tzinfo is not None
    raw = table.read_text()
    assert "198.51.100.77" not in raw and "hunter2" not in raw and "uname" not in raw


def test_dedupe_window_is_bounded_and_drops_the_oldest(table, monkeypatch):
    monkeypatch.setattr(ds, "LEARNED_SESSIONS_MAX", 3)
    L = learner(table)
    for i in range(5):
        L.update("centos_7", "ubuntu_22", 1.0, "ubuntu_22", session_id=f"w{i}", source="operator")
    assert list(learner(table).learned_sessions) == ["w2", "w3", "w4"]
    assert learner(table).provenance()["bySource"]["operator"] == 5  # counts are not reduced by the window


# ── read-only, reproducible evidence report ──────────────────────────────────────────────────────────────────────
def make_live(tmp_path, changed=False):
    data = json.loads(SEED.read_text())
    data["seed_provenance"] = {"source": "models/q_table.json (synthetic warm start)",
                               "episodes": data["episode_count"], "synthetic": True}
    live = tmp_path / "live.json"
    live.write_text(json.dumps(data))
    L = learner(live)
    L.update("centos_7", "ubuntu_22", 4.0, "ubuntu_22", session_id="op-1", source="operator")
    L.update("ubuntu_22", "centos_7", 3.0, "centos_7", session_id="sim-1", source="simulated")
    L.update("ubuntu_22", "centos_7", 3.0, "centos_7", session_id="u-1", source="whatever")
    L.update("ubuntu_22", "centos_7", 3.0, "centos_7", session_id="op-1", source="operator")  # duplicate
    if changed:
        greedy = max(ds.SUPPORTED_PROFILES, key=lambda a: L.q_table["debian_11"].get(a, 0.0))
        other = next(a for a in ds.SUPPORTED_PROFILES if a != greedy)
        L.q_table["debian_11"][other] = L.q_table["debian_11"][greedy] + 50  # a decision real data changed
        L.save()
    return live


def test_report_is_read_only_reproducible_and_complete(tmp_path):
    from evaluation.qlearning_evidence_report import report
    live = make_live(tmp_path)
    os.chmod(live, stat.S_IREAD)  # a report that tried to write would fail
    try:
        h, mtime = hashlib.sha256(live.read_bytes()).hexdigest(), live.stat().st_mtime_ns
        r1, r2 = report(live, SEED, "fixture"), report(live, SEED, "fixture")
        assert hashlib.sha256(live.read_bytes()).hexdigest() == h and live.stat().st_mtime_ns == mtime
    finally:
        os.chmod(live, stat.S_IREAD | stat.S_IWRITE)
    assert json.dumps(r1, sort_keys=True) == json.dumps(r2, sort_keys=True)
    assert r1["readOnly"] is True and r1["table"] == "fixture" and r1["reportVersion"] == 2
    ep = r1["episodes"]
    assert ep["sessionDriven"] == 3 and ep["bySource"] == {"operator": 1, "external": 0, "simulated": 1, "unknown": 1}
    assert ep["realOperatorGenerated"] == 1 and ep["realIndependent"] == 0 and ep["independentExternal"] == 0
    assert ep["untracked"] == 0 and ep["syntheticSeed"] == json.loads(SEED.read_text())["episode_count"]
    assert r1["learning"]["duplicatesRejected"] == 1 and r1["learning"]["traceableUpdates"] == 3
    assert r1["provenanceQuality"] == {"unknownSource": 1, "untracked": 0, "missingLabel": 0, "invalidLabel": 1}
    assert r1["updateLog"]["entries"] == 3 and r1["updateLog"]["max"] == ds.UPDATE_LOG_MAX
    assert r1["updateLog"]["bySource"]["simulated"] == 1
    assert r1["perPersona"]["centos_7"]["bySource"]["simulated"] == 1
    assert set(r1["definitions"]) >= {"syntheticSeed", "sessionDriven", "operator", "external", "unknown", "untracked"}
    assert any("No independent external session" in x for x in r1["limitations"])
    assert r1["decisionsEvaluated"] == len(ds.PROFILES_LIST)


def test_report_counts_decision_changes_accurately(tmp_path):
    from evaluation.qlearning_evidence_report import report
    unchanged = report(make_live(tmp_path / "a" if (tmp_path / "a").mkdir() is None else None, False), SEED)
    assert unchanged["decisionsChangedByRealData"] == 0
    assert any("changed none of the" in x for x in unchanged["limitations"])
    (tmp_path / "b").mkdir()
    changed = report(make_live(tmp_path / "b", True), SEED)
    assert changed["decisionsChangedByRealData"] == 1
    assert changed["decisions"]["debian_11"]["changedByRealData"] is True
    assert not any("changed none of the" in x for x in changed["limitations"])


def test_report_refuses_a_table_that_changes_while_read(tmp_path, monkeypatch):
    import evaluation.qlearning_evidence_report as rep
    live = make_live(tmp_path)
    real_copy = rep.shutil.copyfile

    def copy_then_modify(src, dst):
        real_copy(src, dst)
        Path(src).write_text(Path(src).read_text() + " ")
    monkeypatch.setattr(rep.shutil, "copyfile", copy_then_modify)
    with pytest.raises(RuntimeError, match="changed while it was being read"):
        rep.report(live, SEED)


def test_report_cli_will_not_write_over_the_table_or_seed(tmp_path, monkeypatch, capsys):
    import evaluation.qlearning_evidence_report as rep
    live = make_live(tmp_path)
    h = hashlib.sha256(live.read_bytes()).hexdigest()
    for target in (live, SEED):
        monkeypatch.setattr(sys, "argv", ["r", "--table", str(live), "--seed", str(SEED), "--json", str(target)])
        with pytest.raises(SystemExit):
            rep.main()
    assert hashlib.sha256(live.read_bytes()).hexdigest() == h


def test_a_synthetic_only_table_reports_no_real_evidence(tmp_path):
    from evaluation.qlearning_evidence_report import report
    data = json.loads(SEED.read_text())
    data["seed_provenance"] = {"source": "seed", "episodes": data["episode_count"], "synthetic": True}
    live = tmp_path / "seed_only.json"
    live.write_text(json.dumps(data))
    r = report(live, SEED)
    assert r["episodes"]["sessionDriven"] == 0 and r["episodes"]["realNotSynthetic"] == 0
    assert r["episodes"]["syntheticShare"] == 1.0
    assert r["personasWithRealEvidence"] == [] and r["decisionsChangedByRealData"] == 0


def test_the_committed_v2_report_matches_the_audited_figures():
    """experiments/qlearning_evidence_v2_20261113/report.json was produced by this report from the operator demo table
    (read from a copy); the table hash ties it to the same file the 2026-11-13 audit measured."""
    root = Path(__file__).resolve().parent.parent / "experiments"
    v2 = json.loads((root / "qlearning_evidence_v2_20261113" / "report.json").read_text(encoding="utf-8"))
    v1 = json.loads((root / "qlearning_evidence_20261113" / "report.json").read_text(encoding="utf-8"))
    assert v2["tableSha256"] == v1["tableSha256"] and v2["seedSha256"] == SEED_SHA
    assert v2["episodes"]["total"] == 12106 and v2["episodes"]["syntheticSeed"] == 12087
    assert v2["episodes"]["sessionDriven"] == 19 and v2["episodes"]["untracked"] == 19
    assert v2["episodes"]["realIndependent"] == 0
    assert v2["personasWithoutRealEvidence"] == ["debian_11", "aws_ec2", "raspberry_pi"]
    assert v2["decisionsChangedByRealData"] == 0 and v2["decisionsEvaluated"] == 6
    for k in ("episodes", "perPersona", "decisions", "personasWithRealEvidence", "verdict"):
        if k == "episodes":
            assert {x: v2[k][x] for x in v1[k]} == v1[k]
        else:
            assert v2[k] == v1[k], k


def test_rejection_counts_are_persisted_and_survive_another_process_saving(table, monkeypatch):
    a = learner(table)
    a.update("centos_7", "ubuntu_22", 3.0, "ubuntu_22", session_id="r-1", source="operator")
    monkeypatch.setenv("Q_SAVE_EVERY", "1000")
    b = learner(table)  # loaded before a's rejections
    b.update("centos_7", "debian_11", 2.0, "debian_11", session_id="r-2", source="operator")  # pending in b
    assert a.update("centos_7", "ubuntu_22", 3.0, "ubuntu_22", session_id="r-1", source="operator") is False
    a.note_rejection("missing_session_id")
    assert learner(table).provenance()["duplicatesRejected"] == 1  # written at once, not only in memory
    b.save()  # merges with a's writes: a's counts are kept, not replaced
    merged = learner(table).provenance()
    assert merged["duplicatesRejected"] == 1 and merged["missingSessionIdRejected"] == 1
    assert merged["bySource"]["operator"] == 2


def test_a_rejection_whose_write_fails_stays_pending_and_never_raises(table):
    L = learner(table)
    L.update("centos_7", "ubuntu_22", 3.0, "ubuntu_22", session_id="p-1", source="operator")
    real_save = L.save
    L.save = MagicMock(side_effect=TimeoutError("busy"))
    assert L.update("centos_7", "ubuntu_22", 3.0, "ubuntu_22", session_id="p-1", source="operator") is False
    assert L.duplicates_rejected == 1 and learner(table).duplicates_rejected == 0
    L.save = real_save
    L.save()
    assert learner(table).duplicates_rejected == 1
