#!/usr/bin/env python3
"""
Builds one Cowrie fake filesystem per deception persona, so a persona changes what an attacker reads and
lists, not only the hostname and banner.

Current Cowrie (file contents stored inside fs.pickle; checked against cowrie c7773f4, 2026-10-15):
  python build_honeyfs.py --fs-pickle ~/cowrie/src/cowrie/data/fs.pickle --out ~/cowrie/personas
  COWRIE_PERSONA_FS=personas python switch_profile.py ubuntu_22      # writes [shell] filesystem
writes personas/<persona>.pickle: a copy of Cowrie's tree in which
  - the default demo user "phil" (a well-known Cowrie fingerprint) is replaced by the distribution's usual
    login user in /etc/passwd, /etc/shadow, /etc/group and /home;
  - /etc/os-release (stock Cowrie ships it empty), /etc/issue, /etc/issue.net, /etc/hostname and
    /proc/version match the persona's distribution, kernel and hostname (switch_profile.PROFILES).

Older Cowrie (separate honeyfs directory of file contents):
  python build_honeyfs.py --source ~/cowrie/honeyfs --out ~/cowrie/honeyfs-personas
  COWRIE_PERSONA_HONEYFS=honeyfs-personas python switch_profile.py ubuntu_22   # writes contents_path
writes honeyfs-personas/<persona>/: a full copy with the same changes (/home is not changed: it lives in
the pickle there).

windows_srv gets nothing: Cowrie only emulates a Linux shell, so no file set can make it look like Windows.
"""
import argparse
import copy
import pickle
import posixpath
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

# fs.pickle node layout (cowrie.shell.fs): [name, type, uid, gid, size, mode, ctime, contents, target, realfile]
A_NAME, A_TYPE, A_UID, A_GID, A_SIZE, A_MODE, A_CTIME, A_CONTENTS, A_TARGET = range(9)
T_LINK, T_DIR, T_FILE = 0, 1, 2


def _without_user(text, user):
    return "".join(line for line in text.splitlines(keepends=True) if line.split(":", 1)[0] != user)


def _append_line(text, line):
    return text + ("" if not text or text.endswith("\n") else "\n") + line + "\n"


def persona_files(persona):
    """Path -> new content (str), or a function old content -> new content."""
    distro, profile = DISTROS[persona], switch_profile.PROFILES[persona]
    user, uid = distro["user"]
    return {
        "/etc/passwd": lambda t: _append_line(_without_user(t, DEFAULT_USER), f"{user}:x:{uid}:{uid}:{user}:/home/{user}:/bin/bash"),
        "/etc/shadow": lambda t: _append_line(_without_user(t, DEFAULT_USER), f"{user}:!:19700:0:99999:7:::"),
        "/etc/group": lambda t: _append_line(_without_user(t, DEFAULT_USER), f"{user}:x:{uid}:"),
        "/etc/os-release": "".join(f'{k}="{distro[k]}"\n' for k in OS_RELEASE_KEYS if k in distro),
        "/etc/issue": distro["issue"] + "\n\n",
        "/etc/issue.net": distro["PRETTY_NAME"] + "\n",
        "/etc/hostname": profile["hostname"] + "\n",
        "/proc/version": (f"Linux version {profile['kernel_version']} (builder@{distro['ID']}) ({distro['gcc']}) "
                          f"{profile['kernel_build_string']}\n"),
    }


# ---------------------------------------------------------------- fs.pickle mode (current Cowrie)

def _child(node, name):
    kids = node[A_CONTENTS] if isinstance(node[A_CONTENTS], list) else []
    return next((c for c in kids if c[A_NAME] == name), None)


def _resolve(tree, path, depth=0):
    """(parent dir node, node or None, absolute path) for path, following symlinks; None if a parent is missing."""
    if depth > 16:
        return None
    parts = [p for p in posixpath.normpath(path).split("/") if p]
    node, walked = tree, "/"
    for i, part in enumerate(parts):
        nxt = _child(node, part)
        if nxt is not None and nxt[A_TYPE] == T_LINK:
            # Same rule as cowrie.core.honeyfs._find: a link target is a path from the tree root, even
            # without a leading slash (/etc/os-release -> "usr/lib/os-release").
            target = "/" + nxt[A_TARGET].lstrip("/")
            rest = "/".join(parts[i + 1:])
            return _resolve(tree, posixpath.join(target, rest) if rest else target, depth + 1)
        if i == len(parts) - 1:
            return node, nxt, posixpath.join(walked, part)
        if nxt is None or nxt[A_TYPE] != T_DIR:
            return None
        node, walked = nxt, posixpath.join(walked, part)
    return None


def _set_file(tree, path, content):
    found = _resolve(tree, path)
    if found is None:
        return False
    parent, node, _ = found
    if node is None:
        node = [posixpath.basename(path), T_FILE, 0, 0, 0, 0o100644, parent[A_CTIME], b"", None, None]
        parent[A_CONTENTS].append(node)
    if node[A_TYPE] != T_FILE:
        return False
    old = node[A_CONTENTS] if isinstance(node[A_CONTENTS], bytes) else b""
    new = content(old.decode("utf-8", "replace")) if callable(content) else content
    node[A_CONTENTS] = new.encode("utf-8")
    node[A_SIZE] = len(node[A_CONTENTS])
    return True


def build_persona_pickle(tree, out: Path, persona: str) -> Path:
    t = copy.deepcopy(tree)
    user, uid = DISTROS[persona]["user"]
    missing = [p for p, c in persona_files(persona).items() if not _set_file(t, p, c)]
    home = _resolve(t, "/home")
    home_dir = home[1] if home else None
    phil = _child(home_dir, DEFAULT_USER) if home_dir else None
    if phil is not None and _child(home_dir, user) is None:
        phil[A_NAME], phil[A_UID], phil[A_GID] = user, uid, uid
    if missing:
        print(f"[!] {persona}: could not place {', '.join(missing)}")
    target = out / f"{persona}.pickle"
    with open(target, "wb") as f:
        pickle.dump(t, f, protocol=4)
    return target


def _load_tree(fs_pickle: Path):
    with open(fs_pickle, "rb") as f:
        try:
            tree = pickle.load(f)
        except UnicodeDecodeError:
            f.seek(0)
            tree = pickle.load(f, encoding="utf8")
    passwd = _resolve(tree, "/etc/passwd")
    if not passwd or passwd[1] is None or not isinstance(passwd[1][A_CONTENTS], bytes):
        raise SystemExit(f"{fs_pickle} holds no file contents: this Cowrie uses a honeyfs directory, use --source")
    return tree


# ---------------------------------------------------------------- honeyfs directory mode (older Cowrie)

def build_persona(source: Path, out: Path, persona: str) -> Path:
    target = out / persona
    if target.exists():
        shutil.rmtree(target)
    shutil.copytree(source, target)
    for path, content in persona_files(persona).items():
        f = target / path.lstrip("/")
        if callable(content):
            if not f.is_file():
                continue
            content = content(f.read_text(encoding="utf-8"))
        f.parent.mkdir(parents=True, exist_ok=True)
        f.write_text(content, encoding="utf-8")
    return target


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[1])
    src = ap.add_mutually_exclusive_group(required=True)
    src.add_argument("--fs-pickle", help="Cowrie's fs.pickle (current Cowrie: contents inside the pickle)")
    src.add_argument("--source", help="Cowrie's default honeyfs directory (older Cowrie)")
    ap.add_argument("--out", required=True, help="directory to write one filesystem per persona to")
    args = ap.parse_args(argv)
    out = Path(args.out)
    if args.fs_pickle:
        tree = _load_tree(Path(args.fs_pickle))
        out.mkdir(parents=True, exist_ok=True)
        for persona in DISTROS:
            print(f"[+] {build_persona_pickle(tree, out, persona)}")
    else:
        source = Path(args.source)
        if not (source / "etc").is_dir():
            ap.error(f"{source} does not look like a Cowrie honeyfs (no etc/)")
        out.mkdir(parents=True, exist_ok=True)
        for persona in DISTROS:
            print(f"[+] {build_persona(source, out, persona)}")
    print("[i] windows_srv has none: Cowrie emulates a Linux shell only.")


if __name__ == "__main__":
    main()
