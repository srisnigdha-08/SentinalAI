"""Deception Arena attacker profiles (SIMULATED) and the batch evaluator's statistics and isolation."""
import random
import statistics as st
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "demo"))
import deception_arena as da  # noqa: E402
from evaluation import arena_batch  # noqa: E402

PROFILES = list(da.PROFILE_SCENARIOS)


def sessions(name, persona, n=300, seed=1):
    rng = random.Random(seed)
    return [da.play_session(da.SCENARIOS[name], persona, rng, 1800) for _ in range(n)]


def test_profiles_are_labelled_simulated():
    for name in PROFILES:
        assert da.SCENARIOS[name]["kind"] == "SIMULATED" and da.SCENARIOS[name]["model"] == "profile"


def test_profiles_are_not_identical_scripts():
    """Within a profile, sessions vary; across profiles, behaviour differs (depth, timing, intents)."""
    for name in PROFILES:
        runs = sessions(name, "ubuntu_22", 100)
        assert len({tuple(c["command"] for c in r["commands"]) for r in runs}) > 5, name
    depth = {n: st.mean(len(r["commands"]) for r in sessions(n, "ubuntu_22")) for n in PROFILES}
    dur = {n: st.mean(r["durationSeconds"] for r in sessions(n, "ubuntu_22")) for n in PROFILES}
    assert depth["profile_interactive_explorer"] > depth["profile_recon_scanner"]
    assert dur["profile_interactive_explorer"] > 5 * dur["profile_recon_scanner"]
    intents = lambda n: {c["intent"] for r in sessions(n, "ubuntu_22") for c in r["commands"]}  # noqa: E731
    assert "MALWARE_DOWNLOAD" in intents("profile_opportunistic_dropper")
    assert "PERSISTENCE" in intents("profile_persistence_seeker")
    assert "MALWARE_DOWNLOAD" not in intents("profile_recon_scanner")


def test_authentication_attempts_and_recognition_are_modelled():
    brute = sessions("profile_credential_bruteforcer", "centos_7")
    assert any(r["termination"] == "login_failed" for r in brute)
    fp = lambda p: st.mean(r["fingerprinted"] for r in sessions("profile_cautious_fingerprinter", p, 600))  # noqa: E731
    assert fp("raspberry_pi") > fp("aws_ec2")  # persona recognition depends on the persona (assumed parameters)


def test_existing_scenarios_are_unchanged_for_the_policy_simulator():
    rng = random.Random(3)
    r = da.play_session(da.SCENARIOS["scripted_recon"], "ubuntu_22", rng, 600)
    assert [c["command"] for c in r["commands"]] == ["uname -a", "id", "cat /etc/passwd", "ps aux", "netstat -tulnp"]
    assert "model" not in da.SCENARIOS["persona_sensitive_sim"]


def test_unsupported_persona_cannot_be_a_baseline():
    with pytest.raises(ValueError, match="not servable"):
        da.validate({"scenario": "profile_recon_scanner", "baselinePersona": "windows_srv", "trialsPerStrategy": 2})


def test_bootstrap_and_analysis_flags():
    rows = [{"static_durationSeconds": 10, "adaptive_durationSeconds": 20, "static_depth": 2, "adaptive_depth": 2,
             "static_diversity": 1, "adaptive_diversity": 1, "static_fingerprinted": 0, "adaptive_fingerprinted": 0,
             "static_reward": 1.0, "adaptive_reward": 1.0, "switch": i % 2 == 0, "adaptivePersona": "ubuntu_22"} for i in range(40)]
    a = arena_batch.analyse(rows)
    assert a["durationSeconds"]["statisticallyMeaningful"] and a["durationSeconds"]["practicallyMeaningful"]
    assert not a["depth"]["statisticallyMeaningful"]
    assert a["switchesPer100"] == 50.0


def test_batch_run_is_isolated_and_labelled(tmp_path, monkeypatch):
    live = [tmp_path / "q.json", tmp_path / "v2.json"]
    for p in live:
        p.write_text("{}")
    monkeypatch.setattr(arena_batch, "_live_paths", lambda: live)
    out = tmp_path / "r.json"
    monkeypatch.setattr(sys, "argv", ["arena_batch", "--pairs", "3", "--replications", "2", "--profiles",
                                      "profile_recon_scanner,profile_interactive_explorer", "--json", str(out)])
    arena_batch.main()
    import json
    r = json.loads(out.read_text())
    assert r["label"] == "SIMULATED" and r["evidenceSource"] == "simulated"
    assert r["isolation"] == {"liveStateUnchanged": True, "liveFilesChecked": 2}
    assert r["profiles"]["profile_recon_scanner"]["pairs"] == 6
