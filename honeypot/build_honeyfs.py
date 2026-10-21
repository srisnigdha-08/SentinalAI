#!/usr/bin/env python3
"""
Builds one Cowrie honeyfs (fake file contents) per deception persona, so a persona changes what an attacker
reads, not only the hostname and banner.

Each persona tree is a copy of Cowrie's own default honeyfs with:
  - the default demo user "phil" removed from /etc/passwd, /etc/shadow and /etc/group (a well-known Cowrie
    fingerprint) and the distribution's usual login user added instead;
  - /etc/os-release, /etc/issue, /etc/issue.net, /etc/hostname and /proc/version matching the persona's
    distribution, kernel and hostname (from switch_profile.PROFILES).

  python build_honeyfs.py --source ~/cowrie/honeyfs --out ~/cowrie/honeyfs-personas
  COWRIE_PERSONA_HONEYFS=honeyfs-personas python switch_profile.py ubuntu_22   # then restart Cowrie

Limits: Cowrie serves a file's contents only if the path exists in its fake filesystem (fs.pickle), and
`ls /home` still lists phil because the pickle is unchanged. windows_srv gets no tree: Cowrie only emulates
a Linux shell, so no file set can make it look like Windows.
"""
import argparse
import shutil
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import switch_profile  # noqa: E402

# os-release fields and the default login user of each distribution
DISTROS = {
    "ubuntu_22": {"NAME": "Ubuntu", "VERSION": "22.04.3 LTS (Jammy Jellyfish)", "ID": "ubuntu", "ID_LIKE": "debian",
                  "VERSION_ID": "22.04", "PRETTY_NAME": "Ubuntu 22.04.3 LTS", "user": ("ubuntu", 1000),
                  "issue": "Ubuntu 22.04.3 LTS \\n \\l", "gcc": "gcc (Ubuntu 11.4.0-1ubuntu1~22.04) 11.4.0"},
    "debian_11": {"NAME": "Debian GNU/Linux", "VERSION": "11 (bullseye)", "ID": "debian", "VERSION_ID": "11",
                  "PRETTY_NAME": "Debian GNU/Linux 11 (bullseye)", "user": ("admin", 1000),
                  "issue": "Debian GNU/Linux 11 \\n \\l", "gcc": "gcc-10 (Debian 10.2.1-6) 10.2.1 20210110"},
    "centos_7": {"NAME": "CentOS Linux", "VERSION": "7 (Core)", "ID": "centos", "ID_LIKE": "rhel fedora",
                 "VERSION_ID": "7", "PRETTY_NAME": "CentOS Linux 7 (Core)", "user": ("centos", 1000),
                 "issue": "\\S\nKernel \\r on an \\m", "gcc": "gcc version 4.8.5 20150623 (Red Hat 4.8.5-44) (GCC)"},
    "aws_ec2": {"NAME": "Amazon Linux", "VERSION": "2", "ID": "amzn", "ID_LIKE": "centos rhel fedora",
                "VERSION_ID": "2", "PRETTY_NAME": "Amazon Linux 2", "user": ("ec2-user", 1000),
                "issue": "\\S\nKernel \\r on an \\m", "gcc": "gcc version 7.3.1 20180712 (Red Hat 7.3.1-17) (GCC)"},
    "raspberry_pi": {"NAME": "Raspbian GNU/Linux", "VERSION": "11 (bullseye)", "ID": "raspbian", "ID_LIKE": "debian",
                     "VERSION_ID": "11", "PRETTY_NAME": "Raspbian GNU/Linux 11 (bullseye)", "user": ("pi", 1000),
                     "issue": "Raspbian GNU/Linux 11 \\n \\l", "gcc": "gcc-10 (Raspbian 10.2.1-6+rpi1) 10.2.1 20210110"},
}
OS_RELEASE_KEYS = ("PRETTY_NAME", "NAME", "VERSION_ID", "VERSION", "ID", "ID_LIKE")
DEFAULT_USER = "phil"


def _without_user(text, user):
    return "".join(line for line in text.splitlines(keepends=True) if line.split(":", 1)[0] != user)


def _edit(path, change):
    if path.is_file():
        path.write_text(change(path.read_text(encoding="utf-8")), encoding="utf-8")


def _append_line(text, line):
    return text + ("" if not text or text.endswith("\n") else "\n") + line + "\n"


def build_persona(source: Path, out: Path, persona: str) -> Path:
    distro, profile = DISTROS[persona], switch_profile.PROFILES[persona]
    target = out / persona
    if target.exists():
        shutil.rmtree(target)
    shutil.copytree(source, target)
    user, uid = distro["user"]
    etc = target / "etc"
    etc.mkdir(exist_ok=True)

    _edit(etc / "passwd", lambda t: _append_line(_without_user(t, DEFAULT_USER),
                                                 f"{user}:x:{uid}:{uid}:{user}:/home/{user}:/bin/bash"))
    _edit(etc / "shadow", lambda t: _append_line(_without_user(t, DEFAULT_USER), f"{user}:!:19700:0:99999:7:::"))
    _edit(etc / "group", lambda t: _append_line(_without_user(t, DEFAULT_USER), f"{user}:x:{uid}:"))

    os_release = "".join(f'{k}="{distro[k]}"\n' for k in OS_RELEASE_KEYS if k in distro)
    (etc / "os-release").write_text(os_release, encoding="utf-8")
    (etc / "issue").write_text(distro["issue"] + "\n\n", encoding="utf-8")
    (etc / "issue.net").write_text(distro["PRETTY_NAME"] + "\n", encoding="utf-8")
    (etc / "hostname").write_text(profile["hostname"] + "\n", encoding="utf-8")
    proc = target / "proc"
    proc.mkdir(exist_ok=True)
    (proc / "version").write_text(
        f"Linux version {profile['kernel_version']} (builder@{distro['ID']}) ({distro['gcc']}) "
        f"{profile['kernel_build_string']}\n", encoding="utf-8")
    return target


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[1])
    ap.add_argument("--source", required=True, help="Cowrie's default honeyfs directory")
    ap.add_argument("--out", required=True, help="directory to create one tree per persona in")
    args = ap.parse_args(argv)
    source, out = Path(args.source), Path(args.out)
    if not (source / "etc").is_dir():
        ap.error(f"{source} does not look like a Cowrie honeyfs (no etc/)")
    out.mkdir(parents=True, exist_ok=True)
    for persona in DISTROS:
        print(f"[+] {build_persona(source, out, persona)}")
    print("[i] windows_srv has no tree: Cowrie emulates a Linux shell only.")


if __name__ == "__main__":
    main()
