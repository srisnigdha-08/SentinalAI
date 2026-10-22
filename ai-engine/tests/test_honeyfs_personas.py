"""honeypot/build_honeyfs.py: per-persona fake file contents; switch_profile.py only points Cowrie at them on opt-in."""
import configparser
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2] / "honeypot"
sys.path.insert(0, str(ROOT))
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
    switch_profile.generate_config(persona, allow_unservable=True)  # windows_srv is written on purpose here
    cfg = configparser.ConfigParser(interpolation=None)
    cfg.read(tmp_path / "cowrie.cfg")
    return cfg


def test_switch_profile_uses_persona_contents_only_when_opted_in(tmp_path, monkeypatch):
    assert not _generate(tmp_path, monkeypatch, "ubuntu_22").has_option("honeypot", "contents_path")
    cfg = _generate(tmp_path, monkeypatch, "ubuntu_22", "honeyfs-personas")
    assert cfg.get("honeypot", "contents_path") == "honeyfs-personas/ubuntu_22"
    assert not _generate(tmp_path, monkeypatch, "windows_srv", "honeyfs-personas").has_option("honeypot", "contents_path")


# ---- fs.pickle mode (current Cowrie: contents inside the pickle). Shapes copied from cowrie c7773f4's
# fs.pickle: /etc/os-release is a link with a root-relative target, its target file has no contents, and
# /home holds the demo user's directory.
import pickle  # noqa: E402

T_LINK, T_DIR, T_FILE = 0, 1, 2


def _f(name, data, mode=0o100644):
    return [name, T_FILE, 0, 0, len(data), mode, 1700000000, data, None, None]


def _d(name, children, uid=0):
    return [name, T_DIR, uid, uid, 4096, 0o40755, 1700000000, children, None, None]


@pytest.fixture
def cowrie_pickle(tmp_path):
    tree = _d("", [
        _d("etc", [
            _f("passwd", b"root:x:0:0:root:/root:/bin/bash\nphil:x:1000:1000:Phil California,,,:/home/phil:/bin/bash\n"),
            _f("shadow", b"root:*:19000:0:99999:7:::\nphil:$6$x:19000:0:99999:7:::\n", 0o100640),
            _f("group", b"root:x:0:\nphil:x:1000:\n"),
            ["os-release", T_LINK, 0, 0, 21, 0o120777, 1700000000, [], "usr/lib/os-release", None],
            _f("issue", b"Debian GNU/Linux 12 \n \l\n"),
            _f("hostname", b"svr04\n"),
        ]),
        _d("usr", [_d("lib", [["os-release", T_FILE, 0, 0, 267, 0o100644, 1700000000, [], None, None]])]),
        _d("proc", [_f("version", b"Linux version 6.1.0\n", 0o100444)]),
        _d("home", [_d("phil", [], uid=1000)]),
    ])
    path = tmp_path / "fs.pickle"
    path.write_bytes(pickle.dumps(tree))
    return path


def _find(tree, path):
    node = tree
    for part in [p for p in path.split("/") if p]:
        node = next((c for c in node[7] if c[0] == part), None)
        if node is None:
            return None
    return node


def test_pickle_mode_builds_a_consistent_filesystem_per_persona(cowrie_pickle, tmp_path):
    out = tmp_path / "personas"
    build_honeyfs.main(["--fs-pickle", str(cowrie_pickle), "--out", str(out)])
    for persona, distro in build_honeyfs.DISTROS.items():
        tree = pickle.loads((out / f"{persona}.pickle").read_bytes())
        user = distro["user"][0]
        passwd = _find(tree, "/etc/passwd")[7].decode()
        assert "phil" not in passwd and f"\n{user}:x:1000:1000:" in passwd
        assert "phil" not in _find(tree, "/etc/shadow")[7].decode()
        assert _find(tree, "/etc/shadow")[5] == 0o100640  # mode kept
        home = [c[0] for c in _find(tree, "/home")[7]]
        assert home == [user] and _find(tree, f"/home/{user}")[2] == 1000
        os_release = _find(tree, "/usr/lib/os-release")  # written through the link, as Cowrie resolves it
        assert f'PRETTY_NAME="{distro["PRETTY_NAME"]}"' in os_release[7].decode()
        assert os_release[4] == len(os_release[7])
        assert _find(tree, "/etc/os-release")[1] == T_LINK  # the link itself is untouched
        assert _find(tree, "/etc/hostname")[7].decode().strip() == switch_profile.PROFILES[persona]["hostname"]
        assert _find(tree, "/etc/issue.net") is not None  # created when missing
    assert not (out / "windows_srv.pickle").exists()
    assert b"phil" in cowrie_pickle.read_bytes()  # source untouched


def test_pickle_without_contents_is_rejected(tmp_path):
    old = tmp_path / "old.pickle"
    old.write_bytes(pickle.dumps(_d("", [_d("etc", [["passwd", T_FILE, 0, 0, 0, 0o100644, 0, None, None, None]])])))
    with pytest.raises(SystemExit, match="honeyfs directory"):
        build_honeyfs.main(["--fs-pickle", str(old), "--out", str(tmp_path / "o")])


def test_switch_profile_points_shell_filesystem_at_the_persona_pickle(tmp_path, monkeypatch):
    monkeypatch.setenv("COWRIE_PERSONA_FS", "personas")
    cfg = _generate(tmp_path, monkeypatch, "aws_ec2")
    assert cfg.get("shell", "filesystem") == "personas/aws_ec2.pickle"
    assert not _generate(tmp_path, monkeypatch, "windows_srv").has_option("shell", "filesystem")


def test_pickle_mode_plants_canaries_and_motd(cowrie_pickle, tmp_path):
    out = tmp_path / "personas"
    build_honeyfs.main(["--fs-pickle", str(cowrie_pickle), "--out", str(out)])
    tree = pickle.loads((out / "centos_7.pickle").read_bytes())
    aws_dir = _find(tree, "/root/.aws")
    assert aws_dir[1] == T_DIR and aws_dir[5] == 0o40700  # created, private
    creds = _find(tree, "/root/.aws/credentials")
    assert creds[5] == 0o100600 and b"aws_access_key_id = AKIA" in creds[7]
    assert _find(tree, "/root/.ssh/id_rsa")[7].startswith(b"-----BEGIN OPENSSH PRIVATE KEY-----")
    assert b"CentOS Linux 7" in _find(tree, "/etc/motd")[7]
    other = pickle.loads((out / "debian_11.pickle").read_bytes())
    assert _find(other, "/root/.aws/credentials")[7] != creds[7]  # per-persona decoys


def test_canaries_are_deterministic():
    assert build_honeyfs.canary_files("aws_ec2") == build_honeyfs.canary_files("aws_ec2")


# ---- Phase 5 guide fixes (docs/COWRIE_COMPLETE_GUIDE.md)

def test_windows_persona_is_refused_without_the_explicit_override(tmp_path, monkeypatch):
    """H2: a Windows banner over a Linux shell gives the honeypot away."""
    monkeypatch.setattr(switch_profile, "CFG_PATH", tmp_path / "cowrie.cfg")
    with pytest.raises(SystemExit) as exit_:
        switch_profile.generate_config("windows_srv")
    assert exit_.value.code == 2 and not (tmp_path / "cowrie.cfg").exists()


def test_template_sensor_textlog_listen_and_txtcmds(tmp_path, monkeypatch):
    monkeypatch.setenv("COWRIE_PERSONA_FS", "personas")
    monkeypatch.setenv("COWRIE_LISTEN_ADDR", "127.0.0.1")
    monkeypatch.delenv("COWRIE_SENSOR_NAME", raising=False)
    cfg = _generate(tmp_path, monkeypatch, "ubuntu_22")
    assert cfg.get("honeypot", "sensor_name") == "sentinel-hp-01"  # L1
    assert cfg.get("output_textlog", "enabled") == "false"  # M5
    assert cfg.get("ssh", "listen_endpoints") == "tcp:2222:interface=127.0.0.1"  # H3
    assert cfg.get("honeypot", "txtcmds_path") == "personas/ubuntu_22-txtcmds"  # H2
    monkeypatch.delenv("COWRIE_LISTEN_ADDR")
    monkeypatch.delenv("COWRIE_PERSONA_FS")
    cfg = _generate(tmp_path, monkeypatch, "centos_7")
    assert cfg.get("ssh", "listen_endpoints") == "tcp:2222:interface=0.0.0.0"
    assert not cfg.has_option("honeypot", "txtcmds_path")


def test_lsb_release_only_where_the_distribution_ships_it(cowrie_pickle, tmp_path):
    """H2: Debian-family personas answer lsb_release; CentOS 7 / Amazon Linux 2 do not install it."""
    out = tmp_path / "personas"
    build_honeyfs.main(["--fs-pickle", str(cowrie_pickle), "--out", str(out)])
    ubuntu = (out / "ubuntu_22-txtcmds" / "usr" / "bin" / "lsb_release").read_text(encoding="utf-8")
    assert "Description:\tUbuntu 22.04.3 LTS" in ubuntu and "Codename:\tjammy" in ubuntu
    node = _find(pickle.loads((out / "ubuntu_22.pickle").read_bytes()), "/usr/bin/lsb_release")
    assert node is not None and node[5] == 0o100755  # Cowrie runs a txtcmd only for a path that exists
    for persona in ("centos_7", "aws_ec2"):
        assert (out / f"{persona}-txtcmds").is_dir()
        assert not any((out / f"{persona}-txtcmds").rglob("lsb_release"))
        assert _find(pickle.loads((out / f"{persona}.pickle").read_bytes()), "/usr/bin/lsb_release") is None


def test_userdb_holds_only_root_and_no_textbook_honeypot_logins():
    """H2: every persona has root; per-distro users (pi, ubuntu) on the wrong persona were a tell."""
    entries = [line.split(":") for line in (ROOT / "cowrie" / "userdb.txt").read_text().split()]
    assert entries and all(user == "root" for user, _, _ in entries)
    assert not {"toor", "password", "root"} & {password for _, _, password in entries}
