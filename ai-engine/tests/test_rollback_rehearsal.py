"""Isolated rollback rehearsal (honeypot/rollback_rehearsal.py) and per-persona consistency, served over a socket."""
import importlib.util
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "honeypot"))


def _load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


rehearsal = _load("rollback_rehearsal", ROOT / "honeypot" / "rollback_rehearsal.py")
switch_profile = rehearsal.switch_profile
rot = rehearsal.rot

from rl_engine import deception_scorer as ds  # noqa: E402


@pytest.mark.parametrize("scenario", list(rehearsal.SCENARIOS))
def test_rollback_rehearsal_scenario(scenario):
    r = rehearsal.run_scenario(scenario, verify_timeout=2.0)
    assert r["passed"], r
    if r["outcome"] == "FAILED":
        assert r["cfgRestored"] and r["recorded"] == []


SELECTABLE = [p for p in switch_profile.PROFILES if p not in switch_profile.UNSERVABLE]


def test_selectable_personas_are_exactly_the_learner_servable_ones(monkeypatch):
    monkeypatch.delenv("DECEPTION_EXCLUDED_PROFILES", raising=False)
    assert SELECTABLE == ds.servable_profiles() == ds.SUPPORTED_PROFILES
    assert "windows_srv" not in SELECTABLE


@pytest.mark.parametrize("persona", SELECTABLE)
def test_persona_identity_is_consistent_across_components(persona):
    sp, sc = switch_profile.PROFILES[persona], ds.PROFILES[persona]
    assert sp["banner"] == sc["banner"]                        # SSH fingerprint
    assert sp["os"] == sc["os"]                                # operating-system identity
    assert sp["kernel_version"] in sc["kernel"]                # uname
    assert "Windows" not in sp["banner"] and "Windows" not in sp["os"]


@pytest.mark.parametrize("persona", SELECTABLE)
def test_served_banner_matches_the_persona_over_a_socket(tmp_path, monkeypatch, persona):
    """Writes the persona's cowrie.cfg, serves it from a local endpoint and checks it with the rotator's own
    verify_served, i.e. what an SSH client actually receives, not only the config file."""
    monkeypatch.setenv("COWRIE_LISTEN_ADDR", "127.0.0.1")
    monkeypatch.setattr(switch_profile, "CFG_PATH", tmp_path / "cowrie.cfg")
    switch_profile.generate_config(persona)
    cowrie = rehearsal.FakeCowrie(tmp_path / "cowrie.cfg", tmp_path / "m", "normal")
    try:
        assert rot.served_persona(tmp_path / "cowrie.cfg") == persona
        assert rot.verify_served(tmp_path / "cowrie.cfg", persona, ("127.0.0.1", cowrie.port), timeout_s=2) is None
        other = next(p for p in SELECTABLE if switch_profile.PROFILES[p]["banner"] != switch_profile.PROFILES[persona]["banner"])
        assert rot.verify_served(tmp_path / "cowrie.cfg", other, ("127.0.0.1", cowrie.port), timeout_s=1) is not None
    finally:
        cowrie.close()
