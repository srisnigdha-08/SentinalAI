"""
honeypot/cowrie/cowrie.cfg against the rules real Cowrie applies (checked on cowrie c7773f4, 2026-10-15).

Cowrie loads an enabled [output_X] section as module cowrie.output.<section.split("_")[1]>, so a plugin
name with an underscore silently loads the wrong (usually missing) module. The SentinelAI blocker shipped as
[output_sentinel_blocker] and never ran for that reason.
"""
import configparser
from pathlib import Path

HONEYPOT = Path(__file__).resolve().parents[2] / "honeypot"
# Output engines bundled with Cowrie that our config may enable (module names in cowrie/output/).
BUNDLED_OUTPUTS = {"jsonlog", "textlog", "pcap"}


def _cfg():
    cfg = configparser.ConfigParser(interpolation=None)
    cfg.read(HONEYPOT / "cowrie" / "cowrie.cfg")
    return cfg


def cowrie_engine(section: str) -> str:
    return section.split("_")[1]  # cowrie.core.output.load_plugins


def test_every_enabled_output_section_loads_an_existing_module():
    cfg = _cfg()
    ours = {p.stem for p in (HONEYPOT / "cowrie").glob("*.py")}
    for section in cfg.sections():
        if section.startswith("output_") and cfg.getboolean(section, "enabled", fallback=False):
            engine = cowrie_engine(section)
            assert engine == section[len("output_"):], f"[{section}] would load cowrie.output.{engine}"
            assert engine in BUNDLED_OUTPUTS | ours, f"no module for [{section}]"


def test_blocker_plugin_is_enabled_under_its_loadable_name():
    cfg = _cfg()
    assert cfg.getboolean("output_sentinelblocker", "enabled")
    assert (HONEYPOT / "cowrie" / "sentinelblocker.py").is_file()


def test_keys_sit_in_the_sections_cowrie_reads():
    cfg = _cfg()
    assert cfg.has_option("ssh", "listen_endpoints") and cfg.has_option("ssh", "version")
    assert cfg.get("ssh", "forwarding") == "false"  # Cowrie's default is true
    for key in ("kernel_version", "kernel_build_string", "hardware_platform", "operating_system"):
        assert cfg.has_option("shell", key) and not cfg.has_option("honeypot", key)
    assert not cfg.has_option("honeypot", "max_sessions")  # not read by Cowrie
