"""H5 / L3 / L6: the learner never recommends a persona Cowrie cannot serve, scores are never negative, and the
fallback persona is the one the shipped cowrie.cfg serves."""
import random

import pytest

from rl_engine import deception_scorer as ds


@pytest.fixture
def learner(tmp_path, monkeypatch):
    monkeypatch.delenv("DECEPTION_EXCLUDED_PROFILES", raising=False)
    return ds.DeceptionQLearner(q_table_path=str(tmp_path / "q.json"))


def test_windows_is_excluded_by_default():
    assert "windows_srv" not in ds.servable_profiles()
    assert len(ds.servable_profiles()) == len(ds.PROFILES_LIST) - 1


def test_epsilon_greedy_never_explores_into_windows(learner):
    learner.epsilon, learner.episode_count = 1.0, 0  # always explore
    random.seed(7)
    assert "windows_srv" not in {learner.choose_action("centos_7") for _ in range(500)}


def test_greedy_skips_windows_even_when_it_has_the_best_q(learner):
    learner.q_table["centos_7"]["windows_srv"] = 999.0
    learner.q_table["centos_7"]["debian_11"] = 5.0
    learner.epsilon = 0.0
    assert learner.greedy_action("centos_7") == "debian_11"


def test_ucb_does_not_pick_the_untried_windows_arm(learner):
    learner.policy = "ucb1"
    for a in ds.servable_profiles():
        learner._record_arm(a, 1.0)  # every servable arm tried; windows_srv untried (UCB score = inf)
    assert learner.choose_action("centos_7") != "windows_srv"
    assert learner.greedy_action("centos_7") != "windows_srv"


def test_unsupported_persona_cannot_be_re_enabled(learner, monkeypatch):
    # Changed deliberately (limitation 5): clearing the exclusion list used to re-enable windows_srv. An
    # unsupported persona is now excluded under every setting; the override can only exclude more.
    monkeypatch.setenv("DECEPTION_EXCLUDED_PROFILES", "")
    assert ds.servable_profiles() == ds.SUPPORTED_PROFILES
    assert "windows_srv" not in ds.servable_profiles()
    monkeypatch.setenv("DECEPTION_EXCLUDED_PROFILES", "debian_11")
    assert ds.servable_profiles() == [p for p in ds.SUPPORTED_PROFILES if p != "debian_11"]
    monkeypatch.setenv("DECEPTION_EXCLUDED_PROFILES", ",".join(ds.PROFILES_LIST))  # nothing left: all Linux personas
    assert ds.servable_profiles() == ds.SUPPORTED_PROFILES


def test_deception_score_is_never_negative_and_fallback_is_centos(tmp_path):
    scorer = ds.SessionScorer(q_table_path=str(tmp_path / "q.json"))
    assert scorer.current == "centos_7"
    res = scorer.process_session({"sessionId": "fp", "durationSeconds": 0, "loginSucceeded": False, "iocCount": 0,
                                  "commands": [{"command": "cat /proc/1/cgroup", "intent": "UNKNOWN"}]})
    assert res["rawReward"] < 0 and res["deceptionScore"] == 0.0
    assert res["activeProfile"] == "centos_7"
