"""Q-learner provenance: stats separate episodes inherited from the synthetic seed from sessions scored here."""
import hashlib
import json
from pathlib import Path

import pytest

from inference import deception
from rl_engine.deception_scorer import DeceptionQLearner

SEED = Path(__file__).resolve().parents[1] / "models" / "q_table.json"
SESSION = {"sessionId": "p1", "durationSeconds": 60, "loginSucceeded": True, "iocCount": 0,
           "commands": [{"command": "id", "intent": "RECONNAISSANCE"}], "deceptionProfile": "centos_7"}


@pytest.fixture
def fresh_scorer(monkeypatch, tmp_path):
    target = tmp_path / "runtime" / "q_table.json"
    monkeypatch.setenv("DEFAULT_RUNTIME_Q_TABLE_PATH", str(target))
    monkeypatch.delenv("Q_TABLE_PATH", raising=False)
    monkeypatch.setattr(deception, "_scorer", None)
    yield target
    monkeypatch.setattr(deception, "_scorer", None)


def test_seed_copy_is_labelled_synthetic_and_the_seed_is_untouched(fresh_scorer):
    seed_hash = hashlib.sha256(SEED.read_bytes()).hexdigest()
    seed_episodes = json.loads(SEED.read_text())["episode_count"]
    scorer = deception.get_scorer()
    prov = scorer.learner.get_stats()["provenance"]
    assert prov == {"seed": "models/q_table.json (synthetic warm start)", "seedEpisodes": seed_episodes,
                    "sessionEpisodes": 0, "synthetic": True}
    scorer.process_session(SESSION)
    assert scorer.learner.get_stats()["provenance"]["sessionEpisodes"] == 1
    saved = json.loads(fresh_scorer.read_text())
    assert saved["seed_provenance"]["episodes"] == seed_episodes  # survives save
    assert hashlib.sha256(SEED.read_bytes()).hexdigest() == seed_hash


def test_cold_start_learns_only_from_sessions(fresh_scorer, monkeypatch):
    monkeypatch.setenv("DECEPTION_COLD_START", "1")
    scorer = deception.get_scorer()
    assert scorer.learner.episode_count == 0
    assert all(v == 0.0 for row in scorer.learner.q_table.values() for v in row.values())
    scorer.process_session(SESSION)
    prov = scorer.learner.get_stats()["provenance"]
    assert prov["synthetic"] is False and prov["seedEpisodes"] == 0 and prov["sessionEpisodes"] == 1


def test_existing_runtime_table_is_never_reseeded(fresh_scorer, monkeypatch):
    fresh_scorer.parent.mkdir(parents=True, exist_ok=True)
    fresh_scorer.write_text(json.dumps({"q_table": {}, "episode_count": 7}))
    monkeypatch.setenv("DECEPTION_COLD_START", "1")
    scorer = deception.get_scorer()
    assert scorer.learner.episode_count == 7
    assert scorer.learner.get_stats()["provenance"]["seed"] == "unknown"


def test_provenance_survives_a_concurrent_writer_merge(tmp_path):
    path = tmp_path / "q.json"
    path.write_text(json.dumps({"q_table": {}, "episode_count": 5,
                                "seed_provenance": {"source": "s", "episodes": 5, "synthetic": True}}))
    a, b = DeceptionQLearner(q_table_path=str(path)), DeceptionQLearner(q_table_path=str(path))
    a.update("centos_7", "ubuntu_22", 1.0, "ubuntu_22")
    b.update("centos_7", "debian_11", 1.0, "debian_11")  # merges a's write
    assert b.get_stats()["provenance"]["sessionEpisodes"] == 2
    assert json.loads(path.read_text())["seed_provenance"]["episodes"] == 5
