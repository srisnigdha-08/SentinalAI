"""Opt-in hook that would put the simulated Windows shell into Cowrie (Rank 7). OFF by default; NOT deployed.

install() swaps the shell class Cowrie's protocol module constructs (`honeypot.HoneyPotShell`) for
WindowsCowrieShell, and only when ALL of these hold:
  1. enabled is True (an owner's explicit [output_sentinelwindows] enabled = true; the default is false);
  2. the persona Cowrie serves is windows_srv (the switch_profile.py header);
  3. allow_experimental is True (a second, separate acknowledgement that the persona is experimental).
Anything else leaves Cowrie's Linux shell untouched. It changes the shell only: SSH, authentication, logging and
the deny-list stay Cowrie's. uninstall() restores the original class.

Production serving stays disabled independently of this hook: switch_profile.py still refuses to write windows_srv,
and the learner, persona policy v2, rotator and backend still exclude it (deception_scorer.UNSUPPORTED_PROFILES).
"""
from __future__ import annotations

from .cowrie_shell import WindowsCowrieShell
from .persona import PERSONA_ID

_ORIGINAL = {}


def should_install(enabled, persona, allow_experimental) -> tuple[bool, str]:
    if enabled is not True:
        return False, "DISABLED"
    if persona != PERSONA_ID:
        return False, "PERSONA_NOT_WINDOWS"
    if allow_experimental is not True:
        return False, "EXPERIMENTAL_NOT_ACKNOWLEDGED"
    return True, "INSTALLED"


def install(honeypot_module, *, enabled=False, persona=None, allow_experimental=False) -> str:
    ok, reason = should_install(enabled, persona, allow_experimental)
    if not ok:
        return reason
    if id(honeypot_module) not in _ORIGINAL:
        _ORIGINAL[id(honeypot_module)] = (honeypot_module, honeypot_module.HoneyPotShell)
    honeypot_module.HoneyPotShell = WindowsCowrieShell
    return reason


def uninstall(honeypot_module) -> bool:
    entry = _ORIGINAL.pop(id(honeypot_module), None)
    if entry is None:
        return False
    honeypot_module.HoneyPotShell = entry[1]
    return True
