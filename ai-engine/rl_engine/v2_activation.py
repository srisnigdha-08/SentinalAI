"""Fail-closed activation guard for persona policy v2 (docs/PERSONA_POLICY_V2.md section 10).

DECEPTION_V2=active is the owner's manual switch. It is necessary but no longer sufficient: v2 may only drive
/deception/recommendation when the newest Rank 6 readiness evidence (audit/rank6_persona_policy_v2/run_*/
readiness_status.json, written by evaluation/rank6_v2_shadow_eval.py) is valid, current and READY with every
mandatory gate PASS. Anything else (NOT_READY, FAILED, missing, unreadable, malformed, a smoke or fixture run, a
different policy version or parameters, or an altered production artifact) blocks activation and v1 serves.

A READY file never activates v2 on its own: without the owner's switch this module is not even consulted for
serving. Read-only: it opens one or two small JSON files and writes nothing.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

ENGINE = Path(__file__).resolve().parent.parent
DEFAULT_EVIDENCE_DIR = ENGINE.parent / "audit" / "rank6_persona_policy_v2"

# The ten gates evaluation/rank6_v2_shadow_eval.py writes; every one must be PASS.
MANDATORY_GATES = (
    "1_shadow_isolation",
    "2_persona_compatibility",
    "3_invalid_action_handling",
    "4_failure_isolation",
    "5_evidence_schema_and_provenance",
    "6_reproducible_evaluation",
    "7_adequate_session_evidence",
    "8_independent_evidence",
    "9_decision_stability",
    "10_documented_acceptance_criteria",
)
KNOWN_RANK6_VERSIONS = ("rank6/1",)


def _blocked(reason, **extra):
    return {"allowed": False, "readiness": extra.pop("readiness", "NOT_VERIFIED"), "reason": reason, **extra}


def readiness_decision(evidence_dir: Path | str | None = None) -> dict:
    """Validate the newest Rank 6 run. Returns {"allowed", "readiness", "reason", "evidence", "failedGates"}.
    Only the newest run counts: an older READY run never stands in for a newer invalid one."""
    from rl_engine.persona_policy_v2 import DEFAULTS, POLICY_VERSION

    base = Path(evidence_dir) if evidence_dir is not None else DEFAULT_EVIDENCE_DIR
    try:
        runs = sorted((d for d in base.iterdir() if d.is_dir() and d.name.startswith("run_")), key=lambda d: d.name)
    except OSError:
        return _blocked("READINESS_EVIDENCE_MISSING")
    if not runs:
        return _blocked("READINESS_EVIDENCE_MISSING")
    run = runs[-1]
    where = {"evidence": f"audit/rank6_persona_policy_v2/{run.name}/"}
    try:
        data = json.loads((run / "readiness_status.json").read_text(encoding="utf-8"))
    except FileNotFoundError:
        return _blocked("READINESS_EVIDENCE_MISSING", **where)
    except (OSError, UnicodeDecodeError):
        return _blocked("READINESS_EVIDENCE_UNREADABLE", **where)
    except ValueError:
        return _blocked("READINESS_EVIDENCE_INVALID_JSON", **where)
    if not isinstance(data, dict):
        return _blocked("READINESS_EVIDENCE_INVALID", **where)

    overall = data.get("overall")
    readiness = overall if isinstance(overall, str) and overall else "NOT_VERIFIED"
    where["readiness"] = readiness
    if data.get("smoke") or data.get("fixture") or data.get("rank6_version") not in KNOWN_RANK6_VERSIONS:
        return _blocked("READINESS_EVIDENCE_NOT_PRODUCTION_RUN", **where)
    if not str(data.get("data_source", "")).startswith("mongosh read-only find"):
        return _blocked("READINESS_EVIDENCE_NOT_PRODUCTION_RUN", **where)
    # Evidence for another policy version or other parameters says nothing about the policy that would serve.
    if data.get("policy_version") != POLICY_VERSION or data.get("v2_defaults") != DEFAULTS:
        return _blocked("READINESS_EVIDENCE_STALE", **where)
    try:
        at = datetime.fromisoformat(str(data.get("generated_at")))
        if at.tzinfo is None or at > datetime.now(timezone.utc):
            raise ValueError
    except ValueError:
        return _blocked("READINESS_EVIDENCE_INVALID", **where)
    try:
        integrity = json.loads((run / "artifact_integrity.json").read_text(encoding="utf-8"))
        if integrity.get("unchanged") is not True:
            return _blocked("READINESS_EVIDENCE_INTEGRITY_FAILED", **where)
    except (OSError, ValueError, AttributeError):
        return _blocked("READINESS_EVIDENCE_INTEGRITY_FAILED", **where)

    gates = data.get("gates")
    if not isinstance(gates, dict):
        return _blocked("READINESS_GATES_MISSING", **where)
    missing = [g for g in MANDATORY_GATES if not isinstance(gates.get(g), dict) or "status" not in gates[g]]
    if missing:
        return _blocked("READINESS_GATES_MISSING", failedGates=missing, **where)
    failed = {g: gates[g]["status"] for g in MANDATORY_GATES if gates[g]["status"] != "PASS"}
    if overall != "READY":
        return _blocked(f"READINESS_{readiness}", failedGates=failed, **where)
    if failed or data.get("shadow_engineering") != "PASS":
        return _blocked("READINESS_GATES_FAILED", failedGates=failed, **where)
    return {"allowed": True, "readiness": "READY", "reason": "READY", "failedGates": {}, **where}


def activation_decision(mode: str, evidence_dir: Path | str | None = None) -> dict:
    """Whether v2 may serve. Requires the owner's DECEPTION_V2=active AND a valid READY evidence file.
    Any exception here is itself a block: the guard can only ever keep v1 in charge."""
    if mode != "active":
        return {"allowed": False, "requested": False, "readiness": None, "reason": "NOT_REQUESTED"}
    try:
        d = readiness_decision(evidence_dir)
    except Exception as e:  # noqa: BLE001 - fail closed
        d = _blocked(f"READINESS_CHECK_ERROR:{type(e).__name__}")
    return {"requested": True, **d}
