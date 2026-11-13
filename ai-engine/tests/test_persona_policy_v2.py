"""
Persona policy v2 (rl_engine/persona_policy_v2.py, docs/PERSONA_POLICY_V2.md): a discounted-UCB persona bandit with
a weak synthetic prior and a switching margin, run in shadow next to the v1 Q-learner. Deterministic tests: no
randomness is involved in v2's choices.
"""
import json
import math
import os
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))
from rl_engine import deception_scorer as ds  # noqa: E402
from rl_engine.persona_policy_v2 import (  # noqa: E402
    DEFAULTS, POLICY_VERSION, PersonaPolicyV2, normalise, prior_from_q_table,
)

SEED = json.loads((Path(__file__).parent.parent / "models" / "q_table.json").read_text())
FLAT = {a: 0.5 for a in ds.PROFILES_LIST}


def policy(tmp_path, **kw):
    kw.setdefault("prior_means", FLAT)
    return PersonaPolicyV2(tmp_path / "v2.json", **kw)


def test_normalise_uses_the_v1_reward_bounds():
    assert normalise(ds.REWARD_MIN) == 0.0 and normalise(ds.REWARD_MAX) == 1.0
    assert normalise(-1000) == 0.0 and normalise(1000) == 1.0
    assert normalise(5.0) == pytest.approx(0.5)


def test_observe_applies_the_discount_to_every_arm_then_adds_the_session(tmp_path):
    p = policy(tmp_path, prior_weight=1.0, discount=0.9)
    assert p.observe("s1", "debian_11", 5.0) is True
    assert p.arms["debian_11"]["n"] == pytest.approx(0.9 + 1.0)
    assert p.arms["debian_11"]["s"] == pytest.approx(0.9 * 0.5 + 0.5)
    assert p.arms["ubuntu_22"]["n"] == pytest.approx(0.9)
    assert p.real_episodes == 1


def test_a_session_is_learned_at_most_once(tmp_path):
    p = policy(tmp_path)
    assert p.observe("dup", "centos_7", 10.0) is True
    before = json.loads(json.dumps(p.arms))
    assert p.observe("dup", "centos_7", 10.0) is False
    assert p.arms == before and p.real_episodes == 1
    reloaded = policy(tmp_path)                       # dedupe survives a restart
    assert reloaded.observe("dup", "centos_7", 10.0) is False


def test_unknown_persona_is_ignored(tmp_path):
    p = policy(tmp_path)
    assert p.observe("x", "not_a_persona", 10.0) is False and p.real_episodes == 0


def test_never_recommends_an_unservable_persona(tmp_path):
    p = policy(tmp_path, prior_means={**FLAT, "windows_srv": 1.0})
    for i in range(20):
        p.observe(f"w{i}", "windows_srv", 20.0)        # even if it was served by hand and scored well
    assert p.recommend("ubuntu_22") != "windows_srv"
    assert "windows_srv" not in p.indices()


def test_switch_margin_keeps_the_current_persona_unless_another_is_clearly_better(tmp_path):
    p = policy(tmp_path, switch_margin=0.05, exploration=0.0, discount=1.0)
    p.observe("a", "centos_7", 5.0)                    # mean slightly above the 0.5 prior
    p.observe("b", "debian_11", 5.3)                   # 0.01 higher normalised mean: within the margin
    assert p.recommend("centos_7") == "centos_7"
    for i in range(5):
        p.observe(f"d{i}", "debian_11", 15.0)          # now clearly better
    assert p.recommend("centos_7") == "debian_11"


def test_recommendations_are_deterministic(tmp_path):
    a, b = policy(tmp_path / "a"), policy(tmp_path / "b")
    for i, (persona, r) in enumerate([("ubuntu_22", 3), ("centos_7", 8), ("debian_11", 1), ("aws_ec2", 6)]):
        a.observe(f"s{i}", persona, r); b.observe(f"s{i}", persona, r)
    assert a.recommend("ubuntu_22") == b.recommend("ubuntu_22")
    assert a.stats("ubuntu_22") == b.stats("ubuntu_22")


def test_state_round_trips_and_is_versioned(tmp_path):
    p = policy(tmp_path, prior_source="test", prior_episodes=12087)
    p.observe("s1", "raspberry_pi", 9.0)
    data = json.loads((tmp_path / "v2.json").read_text())
    assert data["policyVersion"] == POLICY_VERSION and data["realEpisodes"] == 1
    assert data["prior"]["syntheticEpisodesRepresented"] == 12087 and data["prior"]["weight"] == DEFAULTS["prior_weight"]
    q = policy(tmp_path)
    assert q.arms == p.arms and q.real_episodes == 1


def test_other_version_state_is_kept_aside_never_overwritten(tmp_path):
    f = tmp_path / "v2.json"
    original = json.dumps({"policyVersion": "persona-ducb-v1-experimental", "realEpisodes": 99})
    f.write_text(original)
    p = policy(tmp_path)
    assert p.real_episodes == 0 and p.quarantined and Path(p.quarantined).name.startswith("v2.json.incompatible-")
    assert Path(p.quarantined).read_text() == original          # evidence preserved byte for byte
    p.observe("s1", "centos_7", 5.0)                            # the next save cannot destroy it
    assert Path(p.quarantined).read_text() == original and json.loads(f.read_text())["realEpisodes"] == 1


@pytest.mark.parametrize("content", [
    "{not json",
    json.dumps({"policyVersion": POLICY_VERSION, "arms": {"ubuntu_22": {"n": "lots", "s": 1}}}),
    json.dumps({"policyVersion": POLICY_VERSION, "arms": {"ubuntu_22": {"n": -1, "s": 0}}}),
    json.dumps({"policyVersion": POLICY_VERSION, "arms": {"ubuntu_22": {"n": 1, "s": 5}}}),
    json.dumps({"policyVersion": POLICY_VERSION, "seenSessionIds": "abc"}),
    json.dumps({"policyVersion": POLICY_VERSION, "realEpisodes": -3}),
    json.dumps(["not", "an", "object"]),
])
def test_malformed_state_is_quarantined_and_the_policy_still_works(tmp_path, content):
    (tmp_path / "v2.json").write_text(content)
    p = policy(tmp_path)
    assert p.quarantined and Path(p.quarantined).read_text() == content
    assert p.real_episodes == 0 and p.recommend("ubuntu_22") in ds.servable_profiles()


def test_a_session_without_an_id_is_never_learned(tmp_path):
    p = policy(tmp_path)
    assert p.observe("", "centos_7", 9.0) is False and p.observe(None, "centos_7", 9.0) is False
    assert p.observe("   ", "centos_7", 9.0) is False and p.real_episodes == 0


def test_only_the_five_linux_personas_are_ever_recommended(tmp_path):
    p = policy(tmp_path, exploration=1.0, switch_margin=0.0)
    recs = set()
    for i in range(200):
        cur = p.recommend(list(recs)[-1] if recs else "ubuntu_22")
        recs.add(cur)
        p.observe(f"x{i}", cur, (i * 7) % 20, persist=False)
    assert recs == set(ds.servable_profiles()) and len(recs) == 5 and "windows_srv" not in recs


def test_refuses_to_store_state_in_the_protected_models_directory():
    with pytest.raises(PermissionError):
        PersonaPolicyV2(Path(__file__).parent.parent / "models" / "persona_policy_v2.json", prior_means=FLAT)


def test_prior_from_the_seed_keeps_its_preference_but_not_its_weight():
    m = prior_from_q_table(SEED["q_table"])
    assert set(m) == set(ds.PROFILES_LIST) and all(0.0 <= v <= 1.0 for v in m.values())
    assert max(m, key=m.get) == "ubuntu_22"            # the seed's favourite


def _favour_raspberry(p, n):
    for i in range(n):                                  # real sessions: raspberry_pi engages, the others don't
        persona = ["raspberry_pi", "ubuntu_22", "centos_7"][i % 3]
        p.observe(f"r{i}", persona, 15.0 if persona == "raspberry_pi" else 1.0, persist=False)


def test_weak_prior_lets_real_sessions_override_the_seed(tmp_path):
    """The fix: 12,087 synthetic episodes weigh as much as one real session, so a few real sessions decide."""
    p = policy(tmp_path, prior_means=prior_from_q_table(SEED["q_table"]), prior_weight=1.0)
    assert p.greedy() == "ubuntu_22"                    # before any real data: the seed's preference
    _favour_raspberry(p, 12)
    assert p.greedy() == "raspberry_pi" and p.recommend("ubuntu_22") == "raspberry_pi"


def test_full_seed_weight_reproduces_the_lock_in(tmp_path):
    """Control: weighting the prior like 12,087 real sessions recreates v1's seed dominance."""
    p = policy(tmp_path, prior_means=prior_from_q_table(SEED["q_table"]), prior_weight=12087.0, discount=1.0)
    _favour_raspberry(p, 12)
    assert p.greedy() == "ubuntu_22"


def test_discounting_follows_a_change_in_attacker_behaviour(tmp_path):
    p = policy(tmp_path, discount=0.95, exploration=0.0, switch_margin=0.0)
    for i in range(40):
        p.observe(f"a{i}", ["debian_11", "aws_ec2"][i % 2], 15.0 if i % 2 == 0 else 2.0, persist=False)
    assert p.greedy() == "debian_11"
    for i in range(40):                                 # behaviour changes: aws_ec2 now engages
        p.observe(f"b{i}", ["debian_11", "aws_ec2"][i % 2], 2.0 if i % 2 == 0 else 15.0, persist=False)
    assert p.greedy() == "aws_ec2"


def test_exploration_bonus_grows_for_rarely_served_personas(tmp_path):
    p = policy(tmp_path, exploration=0.3, discount=1.0)
    for i in range(30):
        p.observe(f"u{i}", "ubuntu_22", 5.0, persist=False)
    idx = p.indices()
    assert idx["debian_11"] > idx["ubuntu_22"]          # same mean (0.5), far fewer observations
    assert math.isfinite(idx["debian_11"])


# ── Integration: SessionScorer / get_scorer / endpoints ─────────────────────────────────────────────────────────
@pytest.fixture
def fresh_scorer(tmp_path, monkeypatch):
    from inference import deception
    monkeypatch.setattr(deception, "_scorer", None)
    monkeypatch.setenv("Q_TABLE_PATH", str(tmp_path / "rt" / "q_table.json"))
    monkeypatch.delenv("DECEPTION_V2_STATE_PATH", raising=False)
    def make(mode=None):
        if mode is None:
            monkeypatch.delenv("DECEPTION_V2", raising=False)
        else:
            monkeypatch.setenv("DECEPTION_V2", mode)
        monkeypatch.setattr(deception, "_scorer", None)
        return deception.get_scorer()
    return make


SESSION = {"sessionId": "real-1", "durationSeconds": 120, "loginSucceeded": True, "iocCount": 0,
           "commands": [{"command": "uname -a", "intent": "RECONNAISSANCE"}], "deceptionProfile": "debian_11",
           "previousProfile": "ubuntu_22"}


def test_shadow_is_the_default_and_learns_from_the_same_session_once(fresh_scorer, tmp_path):
    sc = fresh_scorer()
    assert sc.v2_mode == "shadow" and sc.v2.state_path == tmp_path / "rt" / "persona_policy_v2.json"
    e0 = sc.learner.episode_count
    r = sc.process_session(dict(SESSION))
    assert r["policyV2"]["mode"] == "shadow" and r["policyV2"]["learned"] is True and r["policyV2"]["realEpisodes"] == 1
    assert r["nextProfile"] in ds.servable_profiles() and r["recommendationApplied"] is False   # v1 result unchanged
    r2 = sc.process_session(dict(SESSION))
    assert r2["policyV2"]["learned"] is False and sc.v2.real_episodes == 1
    # v1 now also refuses a session it already learned (limitation 4 dedupe); it used to learn it twice here
    assert sc.learner.episode_count == e0 + 1 and r2["learned"] is False and r2["duplicate"] is True
    assert (tmp_path / "rt" / "q_table.json").exists() and (tmp_path / "rt" / "persona_policy_v2.json").exists()
    assert "arms" not in json.loads((tmp_path / "rt" / "q_table.json").read_text()).get("q_table", {})


def test_v2_state_never_mixes_with_the_v1_table(fresh_scorer, tmp_path):
    sc = fresh_scorer()
    sc.process_session(dict(SESSION))
    v1 = json.loads((tmp_path / "rt" / "q_table.json").read_text())
    v2 = json.loads((tmp_path / "rt" / "persona_policy_v2.json").read_text())
    assert "policyVersion" not in v1 and v2["policyVersion"] == POLICY_VERSION and "q_table" not in v2


def test_off_disables_v2(fresh_scorer):
    sc = fresh_scorer("off")
    assert sc.v2 is None and "policyV2" not in sc.process_session(dict(SESSION))


def test_v2_failure_never_breaks_v1_scoring(fresh_scorer, monkeypatch):
    sc = fresh_scorer()
    monkeypatch.setattr(sc.v2, "observe", MagicMock(side_effect=OSError("disk full")))
    r = sc.process_session(dict(SESSION))
    assert r["policyV2"] == {"mode": "shadow", "error": "OSError"} and r["deceptionScore"] >= 0


os.environ["SENTINEL_KEY"] = "test-sentinel-secret-key-12345"
with patch("inference.predictor.SentinelPredictor.load"), \
     patch("inference.predictor.SentinelPredictor.init_explainer"), \
     patch("joblib.load", return_value=MagicMock()):
    import inference.main as main  # noqa: E402
HEADERS = {"X-API-Key": "test-sentinel-secret-key-12345"}


@pytest.fixture
def client():
    from fastapi.testclient import TestClient
    with patch("inference.main._notify"), \
         patch("inference.predictor.SentinelPredictor.get_model_info", return_value={"version": "test"}), \
         TestClient(main.app) as c:
        yield c


def test_shadow_recommendation_is_reported_but_never_drives_the_decision(fresh_scorer, client, monkeypatch):
    sc = fresh_scorer()
    monkeypatch.setattr(main, "_deception_scorer", lambda: sc)
    monkeypatch.setattr(sc.v2, "stats", lambda current: {"policyVersion": POLICY_VERSION, "recommendation": "raspberry_pi",
                                                         "explored": False, "realEpisodes": 3})
    monkeypatch.setattr(sc.learner, "choose_action", lambda current: "centos_7")
    d = client.get("/deception/recommendation", params={"current": "ubuntu_22"}, headers=HEADERS).json()
    assert d["nextProfile"] == "centos_7" and d["policy"] == "q_learning"
    assert d["shadow"]["recommendation"] == "raspberry_pi" and d["shadow"]["applied"] is False


def test_active_mode_serves_v2_and_still_reports_v1(fresh_scorer, client, monkeypatch):
    sc = fresh_scorer("active")
    monkeypatch.setattr(main, "_deception_scorer", lambda: sc)
    monkeypatch.setattr(sc.v2, "stats", lambda current: {"policyVersion": POLICY_VERSION, "recommendation": "raspberry_pi",
                                                         "explored": False, "realEpisodes": 3})
    monkeypatch.setattr(sc.learner, "choose_action", lambda current: "centos_7")
    d = client.get("/deception/recommendation", params={"current": "ubuntu_22"}, headers=HEADERS).json()
    assert d["nextProfile"] == "raspberry_pi" and d["policy"] == POLICY_VERSION
    assert d["policyV1"]["nextProfile"] == "centos_7" and "shadow" not in d


def test_v2_recommendation_failure_falls_back_to_v1(fresh_scorer, client, monkeypatch):
    sc = fresh_scorer("active")
    monkeypatch.setattr(main, "_deception_scorer", lambda: sc)
    monkeypatch.setattr(sc.v2, "stats", MagicMock(side_effect=ValueError("corrupt")))
    monkeypatch.setattr(sc.learner, "choose_action", lambda current: "centos_7")
    d = client.get("/deception/recommendation", params={"current": "ubuntu_22"}, headers=HEADERS).json()
    assert d["nextProfile"] == "centos_7" and d["policy"] == "q_learning"
