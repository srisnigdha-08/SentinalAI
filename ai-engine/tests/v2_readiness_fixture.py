"""Test helper (not a test module): writes a temporary Rank 6 readiness run for the v2 activation guard.

Fixtures only. Nothing here is evidence, and it never writes under audit/.
"""
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

from rl_engine.persona_policy_v2 import DEFAULTS, POLICY_VERSION
from rl_engine.v2_activation import MANDATORY_GATES


def readiness(overall="READY", **gate_status):
    gates = {g: {"status": gate_status.get(g, "PASS"), "evidence": "fixture"} for g in MANDATORY_GATES}
    return {"rank6_version": "rank6/1", "generated_at": (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat(),
            "policy_version": POLICY_VERSION, "v2_defaults": dict(DEFAULTS),
            "data_source": "mongosh read-only find (real_session_report.load)",
            "overall": overall, "shadow_engineering": "PASS", "gates": gates}


def write_run(base: Path, data=None, raw: str | None = None, integrity=True, name="run_20991231T000000Z") -> Path:
    """Write base/<name>/readiness_status.json (data, or raw text) plus artifact_integrity.json; return base."""
    run = Path(base) / name
    run.mkdir(parents=True, exist_ok=True)
    text = raw if raw is not None else json.dumps(readiness() if data is None else data)
    (run / "readiness_status.json").write_text(text, encoding="utf-8")
    if integrity is not None:
        (run / "artifact_integrity.json").write_text(json.dumps({"unchanged": integrity}), encoding="utf-8")
    return Path(base)
