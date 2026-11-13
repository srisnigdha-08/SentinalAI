# Honeypot personas

Cowrie emulates a **Linux** shell. A persona changes the SSH banner, hostname, `uname` strings, `/etc/os-release`,
`/etc/motd` and the planted files (`honeypot/build_honeyfs.py`). It cannot change the shell itself.

| Persona | OS identity | SSH banner | Status |
|---|---|---|---|
| `ubuntu_22` | Ubuntu 22.04 LTS | OpenSSH_8.9p1 Ubuntu-3ubuntu0.6 | servable |
| `debian_11` | Debian GNU/Linux 11 | OpenSSH_8.4p1 Debian-5+deb11u3 | servable |
| `centos_7` | CentOS Linux 7 | OpenSSH_7.4 | servable |
| `aws_ec2` | Amazon Linux 2 | OpenSSH_7.4 (same as `centos_7`) | servable |
| `raspberry_pi` | Raspbian GNU/Linux 11 | OpenSSH_8.4p1 Raspbian | servable |
| `windows_srv` | Windows Server 2019 | — | **unsupported** |

## The Windows persona (resolution of limitation 5)

A Windows banner over a Linux shell gives itself away at the first command, and it would falsely claim a Windows
host. A genuine Windows target would need an isolated Windows VM with a restricted command environment. That is not
available here, and exposing the real Windows host is never acceptable.

`windows_srv` is therefore **unsupported** under every setting:
- **Learner:** never recommends it (`UNSUPPORTED_PROFILES`). `DECEPTION_EXCLUDED_PROFILES` can only exclude more
  personas.
- **Profile switcher:** `switch_profile.py` never writes it (`--allow-unservable` no longer bypasses this).
- **Backend:** refuses to record it as served and does not offer it.
- **Arena:** refuses it as a baseline.
- **Rotator:** marks a decision for it FAILED.

It stays in the Q-table's keys only, so the shipped seed and history keep their shape.

## Verification

`ai-engine/tests/test_rollback_rehearsal.py` checks every selectable persona:
- **Consistency:** banner, OS identity and kernel agree between `switch_profile.py` and the learner.
- **Served behaviour:** the generated `cowrie.cfg` is served from a loopback endpoint and checked with the rotator's
  own `verify_served`, which is what an SSH client actually receives.
- **Wrong banners:** a mismatching banner is rejected.

`centos_7` and `aws_ec2` share a banner. The rotator also requires the pre-restart connection to have been dropped.

These tests use a local banner server, not the live Cowrie: the live honeypot is never touched by tests. The
rotator itself verifies the live banner after every real switch (PR #26).
