from rl_engine.deception_scorer import SessionScorer, calc_reward


def _session(sid, profile, **extra):
    base = {"sessionId": sid, "durationSeconds": 300, "loginSucceeded": True, "iocCount": 1,
            "commands": [{"intent": "MALWARE_DOWNLOAD"}], "deceptionProfile": profile}
    base.update(extra)
    return base


def test_reward_is_credited_to_the_profile_active_during_the_session(tmp_path):
    scorer = SessionScorer(q_table_path=str(tmp_path / "q.json"))
    s = _session("s1", "centos_7", previousProfile="ubuntu_22")
    before = {a: v for a, v in scorer.learner.q_table["ubuntu_22"].items()}

    res = scorer.process_session(s)

    reward = calc_reward(s)
    row = scorer.learner.q_table["ubuntu_22"]
    # Fresh table: Q(centos_7, *) == 0, so the update is alpha * reward
    assert abs(row["centos_7"] - round(0.1 * reward, 4)) < 1e-4
    for a, v in row.items():
        if a != "centos_7":
            assert v == before[a]
    assert res["activeProfile"] == "centos_7"
    assert res["prevProfile"] == "ubuntu_22"
    assert res["recommendationApplied"] is False


def test_previous_active_profile_chains_between_sessions(tmp_path):
    scorer = SessionScorer(q_table_path=str(tmp_path / "q.json"))
    scorer.process_session(_session("s1", "debian_11"))
    before = scorer.learner.q_table["debian_11"]["centos_7"]

    res = scorer.process_session(_session("s2", "centos_7"))

    assert res["prevProfile"] == "debian_11"
    assert scorer.learner.q_table["debian_11"]["centos_7"] > before


def test_unknown_profile_falls_back_safely(tmp_path):
    scorer = SessionScorer(q_table_path=str(tmp_path / "q.json"))
    res = scorer.process_session(_session("s1", "not_a_profile"))
    assert res["activeProfile"] in scorer.learner.q_table
