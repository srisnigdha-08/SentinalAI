"""honeypot/build_honeyfs.py: per-persona fake file contents; switch_profile.py only points Cowrie at them on opt-in."""
import configparser
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "honeypot"))
import build_honeyfs  # noqa: E402
import switch_profile  # noqa: E402


@pytest.fixture
def cowrie_honeyfs(tmp_path):
    src = tmp_path / "honeyfs"
    (src / "etc").mkdir(parents=True)
    (src / "proc").mkdir()
    (src / "etc/passwd").write_text("root:x:0:0:root:/root:/bin/bash\nphil:x:1000:1000:Phil California,,,:/home/phil:/bin/bash\n")
    (src / "etc/shadow").write_text("root:*:15800:0:99999:7:::\nphil:$6$x:15800:0:99999:7:::\n")
    (src / "etc/group").write_text("root:x:0:\nphil:x:1000:\n")
    (src / "etc/issue").write_text("Debian GNU/Linux 7 \\n \\l\n")
    (src / "proc/cpuinfo").write_text("processor : 0\n")
    return src


def test_every_linux_persona_gets_a_consistent_tree(cowrie_honeyfs, tmp_path):
    build_honeyfs.main(["--source", str(cowrie_honeyfs), "--out", str(tmp_path / "out")])
    for persona, distro in build_honeyfs.DISTROS.items():
        root = tmp_path / "out" / persona
        profile = switch_profile.PROFILES[persona]
        user = distro["user"][0]
        passwd = (root / "etc/passwd").read_text()
        assert "phil" not in passwd and "phil" not in (root / "etc/shadow").read_text()
        assert "phil" not in (root / "etc/group").read_text()
        assert passwd.startswith("root:") and f"\n{user}:x:1000:1000:" in passwd
        assert f'PRETTY_NAME="{distro["PRETTY_NAME"]}"' in (root / "etc/os-release").read_text()
        assert (root / "etc/hostname").read_text().strip() == profile["hostname"]
        assert profile["kernel_version"] in (root / "proc/version").read_text()
        assert (root / "proc/cpuinfo").read_text() == "processor : 0\n"  # untouched defaults are kept
    assert not (tmp_path / "out" / "windows_srv").exists()
    assert "phil" in (cowrie_honeyfs / "etc/passwd").read_text()  # the source is never modified


def test_rebuild_replaces_a_previous_tree(cowrie_honeyfs, tmp_path):
    out = tmp_path / "out"
    build_honeyfs.build_persona(cowrie_honeyfs, out, "centos_7")
    (out / "centos_7/stale").write_text("old")
    build_honeyfs.build_persona(cowrie_honeyfs, out, "centos_7")
    assert not (out / "centos_7/stale").exists()


def test_source_must_be_a_honeyfs(tmp_path):
    with pytest.raises(SystemExit):
        build_honeyfs.main(["--source", str(tmp_path), "--out", str(tmp_path / "out")])


def _generate(tmp_path, monkeypatch, persona, honeyfs=None):
    if honeyfs is None:
        monkeypatch.delenv("COWRIE_PERSONA_HONEYFS", raising=False)
    else:
        monkeypatch.setenv("COWRIE_PERSONA_HONEYFS", honeyfs)
    monkeypatch.setattr(switch_profile, "CFG_PATH", tmp_path / "cowrie.cfg")
    switch_profile.generate_config(persona)
    cfg = configparser.ConfigParser(interpolation=None)
    cfg.read(tmp_path / "cowrie.cfg")
    return cfg


def test_switch_profile_uses_persona_contents_only_when_opted_in(tmp_path, monkeypatch):
    assert not _generate(tmp_path, monkeypatch, "ubuntu_22").has_option("honeypot", "contents_path")
    cfg = _generate(tmp_path, monkeypatch, "ubuntu_22", "honeyfs-personas")
    assert cfg.get("honeypot", "contents_path") == "honeyfs-personas/ubuntu_22"
    assert not _generate(tmp_path, monkeypatch, "windows_srv", "honeyfs-personas").has_option("honeypot", "contents_path")
