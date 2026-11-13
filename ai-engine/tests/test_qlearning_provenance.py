"""v1 Q-learner evidence provenance, duplicate-learning protection and persistence (docs/QLEARNING_EVIDENCE.md)."""
import json

import pytest

from rl_engine import deception_scorer as ds


@pytest.fixture
def table(tmp_path):
    return tmp_path / "q.json"


def learner(path):
    return ds.DeceptionQLearner(q_table_path=str(path))


def test_update_is_traced_and_counted_by_source(table):
    L = learner(table)
    assert L.update("centos_7", "ubuntu_22", 3.0, "ubuntu_22", session_id="s1", source="operator") is True
    assert L.update("ubuntu_22", "ubuntu_22", 2.0, "ubuntu_22", session_id="s2", source="EXTERNAL") is True
    assert L.update("ubuntu_22", "debian_11", 1.0, "debian_11", session_id="s3", source="made-up") is True
    p = L.provenance()
    assert p["bySource"] == {"operator": 1, "external": 1, "simulated": 0, "unknown": 1}
    assert p["perPersona"]["ubuntu_22"]["operator"] == 1 and p["perPersona"]["debian_11"]["unknown"] == 1
    assert [e["sessionId"] for e in L.update_log] == ["s1", "s2", "s3"]
    assert p["independentExternalSessions"] == 1


def test_duplicate_session_is_never_learned_twice(table):
    L = learner(table)
    L.update("centos_7", "ubuntu_22", 3.0, "ubuntu_22", session_id="dup", source="operator")
    q = json.loads(json.dumps(L.q_table))
    episodes = L.episode_count
    assert L.update("centos_7", "ubuntu_22", 9.0, "ubuntu_22", session_id="dup", source="operator") is False
    assert L.q_table == q and L.episode_count == episodes
    assert L.provenance()["duplicatesRejected"] == 1


def test_dedupe_survives_a_restart(table):
    L = learner(table)
    L.update("centos_7", "ubuntu_22", 3.0, "ubuntu_22", session_id="s1", source="operator")
    L2 = learner(table)
    assert L2.already_learned("s1")
    assert L2.update("centos_7", "ubuntu_22", 3.0, "ubuntu_22", session_id="s1") is False
    assert L2.provenance()["bySource"]["operator"] == 1


def test_concurrent_writers_merge_evidence_without_double_counting(table, monkeypatch):
    monkeypatch.setenv("Q_SAVE_EVERY", "1000")  # hold updates pending so both processes write over each other
    a, b = learner(table), learner(table)
    a.update("centos_7", "ubuntu_22", 3.0, "ubuntu_22", session_id="a1", source="operator")
    b.update("centos_7", "debian_11", 2.0, "debian_11", session_id="b1", source="external")
    b.update("centos_7", "debian_11", 2.0, "debian_11", session_id="a1", source="operator")  # same session as a1
    a.save()
    b.save()
    merged = learner(table)
    assert merged.provenance()["bySource"] == {"operator": 1, "external": 1, "simulated": 0, "unknown": 0}
    assert set(merged.learned_sessions) == {"a1", "b1"}


def test_old_tables_without_evidence_load_and_report_untracked(table):
    table.write_text(json.dumps({"q_table": {}, "episode_count": 105,
                                 "seed_provenance": {"source": "seed", "episodes": 100, "synthetic": True}}))
    p = learner(table).provenance()
    assert p["seedEpisodes"] == 100 and p["sessionEpisodes"] == 5
    assert p["trackedSessionEpisodes"] == 0 and p["untrackedSessionEpisodes"] == 5


def test_session_scorer_passes_the_source_and_reports_duplicates(table):
    sc = ds.SessionScorer(q_table_path=str(table))
    s = {"sessionId": "x1", "durationSeconds": 60, "commands": [], "deceptionProfile": "ubuntu_22", "evidenceSource": "operator"}
    r1 = sc.process_session(s)
    r2 = sc.process_session(s)
    assert r1["learned"] is True and r1["evidenceSource"] == "operator"
    assert r2["learned"] is False and r2["duplicate"] is True
    assert sc.learner.provenance()["bySource"]["operator"] == 1


def test_missing_source_is_unknown_never_external(table):
    sc = ds.SessionScorer(q_table_path=str(table))
    r = sc.process_session({"sessionId": "y", "commands": [], "deceptionProfile": "ubuntu_22"})
    assert r["evidenceSource"] == "unknown"


def test_learner_never_recommends_an_unsupported_persona(table, monkeypatch):
    monkeypatch.setenv("DECEPTION_EXCLUDED_PROFILES", "")
    L = learner(table)
    for state in ds.PROFILES_LIST:
        L.q_table[state]["windows_srv"] = 1e6
    for _ in range(200):
        assert L.choose_action("centos_7") != "windows_srv"
    assert L.greedy_action("centos_7") != "windows_srv"


def test_evidence_report_is_read_only_and_quantifies_seed_dominance(tmp_path):
    from evaluation.qlearning_evidence_report import report, sha
    seed = ds.Path(ds.__file__).resolve().parent.parent / "models" / "q_table.json"
    live = tmp_path / "live.json"
    data = json.loads(seed.read_text())
    data["seed_provenance"] = {"source": "models/q_table.json (synthetic warm start)", "episodes": data["episode_count"], "synthetic": True}
    data["episode_count"] += 3
    data["arm_stats"] = {"ubuntu_22": {"n": 3, "mean": 0.4}}
    data["evidence"] = {"counts": {"operator": 3}}
    live.write_text(json.dumps(data))
    h = sha(live)
    r = report(live, seed)
    assert sha(live) == h
    assert r["episodes"]["sessionDriven"] == 3 and r["episodes"]["bySource"]["operator"] == 3
    assert r["episodes"]["independentExternal"] == 0
    assert r["perPersona"]["ubuntu_22"]["seedWeightBestCase"] == pytest.approx(0.9 ** 3, abs=1e-4)
    assert "windows_srv" not in r["personasWithoutRealEvidence"]
    assert r["verdict"].startswith("Synthetic initialisation dominates")
