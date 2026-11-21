"""Simulated Windows persona (windows_srv) for SentinelAI's Cowrie honeypot (Rank 7, docs/PERSONAS.md).

A Windows-like shell simulation over Cowrie's SSH transport: an isolated in-memory filesystem and an allowlisted
command emulator. It is not a Windows host and never executes anything on the real host. Experimental, not
production-eligible, and not served unless an owner enables the Cowrie hook (cowrie_hook.py); the production
persona selection sets (V1, V2, rotator, switch_profile, backend) still exclude windows_srv.
"""
from .persona import CMD_PROMPT, IDENTITY, NETWORK, PERSONA_ID, STATUS, metadata
from .shell import Result, WindowsShell, supported_commands
from .telemetry import attack_techniques, classify_windows_intent
from .vfs import VfsError, VirtualFS

__all__ = ["CMD_PROMPT", "IDENTITY", "NETWORK", "PERSONA_ID", "STATUS", "metadata", "Result", "WindowsShell",
           "supported_commands", "attack_techniques", "classify_windows_intent", "VfsError", "VirtualFS"]
