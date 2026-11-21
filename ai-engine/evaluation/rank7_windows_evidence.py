"""Rank 7 evidence: the simulated Windows persona (docs/PERSONAS.md "Simulated Windows persona").

Read-only. Collects the persona configuration, the command allowlist, recorded test results, production eligibility,
artifact hashes and known limitations into a NEW directory audit/rank7_windows_persona/run_<UTC>/ (never overwrites).
It runs no tests itself: test results are read from the files passed in (pytest JUnit XML, Jest --json, the node
--test summary line, and the last JSON line printed by tests/cowrie_windows_integration.py under Cowrie's interpreter).

    .venv/Scripts/python evaluation/rank7_windows_evidence.py --engine-xml r7_engine.xml --backend-json r7_backend.json \
        --frontend-summary r7_fe.txt --cowrie-result r7_cowrie.txt
"""
import argparse
import hashlib
import json
import re
import sys
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path

ENGINE = Path(__file__).resolve().parents[1]
REPO = ENGINE.parent
sys.path.insert(0, str(ENGINE))
sys.path.insert(0, str(REPO / "honeypot"))

from evaluation import rank6_v2_shadow_eval as R6  # noqa: E402
from rl_engine import deception_scorer as ds  # noqa: E402
from rl_engine import v2_activation as guard  # noqa: E402
from windows_persona import metadata, supported_commands  # noqa: E402
from windows_persona.telemetry import ATTACK_RULES, INTENT_RULES  # noqa: E402

OUT = REPO / "audit" / "rank7_windows_persona"
KEY_FILES = ["ai-engine/rl_engine/v2_activation.py", "ai-engine/rl_engine/persona_policy_v2.py",
             "ai-engine/rl_engine/deception_scorer.py", "ai-engine/evaluation/protected_data.py",
             "honeypot/switch_profile.py", "backend/utils/deceptionProfiles.js", "backend/utils/shadowPolicy.js"]


def sha(p: Path):
    return hashlib.sha256(p.read_bytes()).hexdigest() if p.is_file() else None


def junit(path):
    root = ET.parse(path).getroot()
    suite = root if root.tag == "testsuite" else root.find("testsuite")
    a = {k: int(suite.get(k, 0)) for k in ("tests", "failures", "errors", "skipped")}
    return {**a, "passed": a["tests"] - a["failures"] - a["errors"] - a["skipped"]}


def run_dir():
    OUT.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    d, n = OUT / f"run_{stamp}", 1
    while d.exists():
        d, n = OUT / f"run_{stamp}_{n}", n + 1
    d.mkdir()
    return d


def write(d, name, obj):
    p = d / name
    if p.exists():
        raise FileExistsError(p)
    p.write_text(json.dumps(obj, indent=1, default=str), encoding="utf-8")


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--engine-xml", required=True)
    ap.add_argument("--backend-json", required=True)
    ap.add_argument("--frontend-summary", required=True)
    ap.add_argument("--cowrie-result", required=True)
    a = ap.parse_args(argv)

    eng = junit(a.engine_xml)
    be = json.loads(Path(a.backend_json).read_text(encoding="utf-8"))
    be = {"tests": be["numTotalTests"], "passed": be["numPassedTests"], "failed": be["numFailedTests"],
          "skipped": be["numPendingTests"]}
    fe_txt = Path(a.frontend_summary).read_text(encoding="utf-8")
    fe = {"passed": int(re.search(r"pass (\d+)", fe_txt).group(1)), "failed": int(re.search(r"fail (\d+)", fe_txt).group(1))}
    cw_line = next(ln for ln in Path(a.cowrie_result).read_text(encoding="utf-8").splitlines() if ln.startswith("{"))
    cw = json.loads(cw_line)
    cw_new = re.search(r"NEWFILES=(\d+)", Path(a.cowrie_result).read_text(encoding="utf-8"))

    failed = eng["failures"] + eng["errors"] + be["failed"] + fe["failed"] + cw["failures"] + cw["errors"]
    tests = {
        "unit_and_security_engine": {"file": "ai-engine/tests/test_windows_persona.py", "kind": "unit + security + mocked adapter", **eng},
        "backend": {"file": "backend/tests/rank7WindowsPersona.test.js", "kind": "unit + integration (in-memory MongoDB, mocked logger)", **be},
        "frontend": {"file": "frontend/tests/personaLabels.test.mjs", "kind": "unit", **fe},
        "cowrie_in_process": {"file": "ai-engine/tests/cowrie_windows_integration.py",
                              "kind": "integration: real Cowrie protocol objects with Cowrie's own fake transport; no listener, no live service",
                              "cowrieVersion": cw["cowrieVersion"], "tests": cw["testsRun"], "failures": cw["failures"],
                              "errors": cw["errors"], "forbiddenCalls": cw["forbiddenCalls"],
                              "filesWrittenInCowrieDir": int(cw_new.group(1)) if cw_new else None},
        "passed": failed == 0, "failed": failed,
    }
    cmds = supported_commands()
    count = len(set(cmds["cmd"]) | set(cmds["native"]) | set(cmds["powershell"]))
    gd = guard.activation_decision("active")
    prod = {"persona": "windows_srv", **{k: v for k, v in metadata().items() if k in ("supported", "experimental", "productionEligible", "servingEnabled")},
            "v1_servable_profiles": ds.servable_profiles(), "v1_unsupported": sorted(ds.UNSUPPORTED_PROFILES),
            "experimental_sessions_learned": False, "cowrie_hook_default": "DISABLED", "shipped_cowrie_cfg_enables_plugin":
            "output_sentinelwindows" in (REPO / "honeypot" / "cowrie" / "cowrie.cfg").read_text(encoding="utf-8"),
            "v2_activation_with_active_requested": {k: gd.get(k) for k in ("allowed", "readiness", "reason")}}
    hashes = {"production_policy_artifacts": R6.hash_artifacts(R6.production_artifacts()),
              "key_files": {f: sha(REPO / f) for f in KEY_FILES}}
    limitations = [
        "A Windows-like shell SIMULATION over Cowrie's SSH transport, not a Windows host: no Windows kernel, cmd.exe, PowerShell runtime, registry, services, Active Directory, RDP, SMB or WinRM.",
        "Fixed allowlist of commands with fictional output; scripts, .bat/.ps1 files, WMI, the registry, `for`, `if`, `reg`, `schtasks` and PowerShell objects/pipelines beyond a few filters are not simulated (unknown commands get Windows-style errors).",
        "The SSH layer is still Cowrie/OpenSSH-for-Windows banner over Cowrie's SSH stack; key exchange and server fingerprints are Cowrie's, which a careful attacker can still distinguish.",
        "netstat/tasklist/sc list fictional services (RDP 3389, SMB 445, WinRM 5985) as output only; nothing listens on those ports.",
        "Not deployed: the Cowrie plugin is off by default and not installed; switch_profile.py still refuses windows_srv; no live session has been served.",
        "Sessions served by windows_srv would be scored but never learned (V1/V2), so no Windows effectiveness evidence can accumulate until an owner decides otherwise.",
        "Session ML features map windows_srv to persona_unknown (the classifier was built on the five Linux personas).",
        "A genuine Windows target would need an isolated Windows VM, which is not available and was not created.",
    ]
    d = run_dir()
    now = datetime.now(timezone.utc).isoformat()
    write(d, "implementation_summary.json", {"generated_at": now, "rank": 7, "package": "honeypot/windows_persona",
          "modules": sorted(p.name for p in (REPO / "honeypot" / "windows_persona").glob("*.py")),
          "cowrie_plugin": "honeypot/cowrie/sentinelwindows.py (not deployed, off by default)",
          "integration": ["log_parser.classify_session_intent (windows sessions only)", "backend utils/windowsPersona.js + honeypotIngest intent",
                          "mitreMapping Windows techniques", "deception_scorer: experimental persona scored, never learned",
                          "capabilityService windows_persona + windows_persona_simulation", "frontend personaLabels"],
          "behaviour_classes": {"unit_tested": True, "integration_tested": "in-process with real Cowrie 3.1.3 protocol objects and in-memory MongoDB",
                                "mocked": "Cowrie terminal/transport, logger, AI engine (backend)", "simulated": "all command output, filesystem and network",
                                "live": False}})
    write(d, "persona_configuration.json", metadata())
    write(d, "supported_commands.json", {**cmds, "count": count, "intent_rules": [i for i, _ in INTENT_RULES],
                                         "attack_techniques": sorted({t for _, (t, _n) in ATTACK_RULES})})
    write(d, "test_results.json", tests)
    write(d, "security_test_results.json", {
        "static_import_and_call_audit": "test_package_cannot_touch_the_host (no os/subprocess/socket/pathlib/io imports; no eval/exec/open/compile; literal getattr only)",
        "injection_corpus": "test_injection_never_reaches_the_host: subprocess/os/socket/open/eval/exec patched to fail; 0 calls",
        "filesystem_isolation": "test_path_traversal_cannot_leave_the_virtual_root, test_invalid_paths_are_rejected, test_writes_stay_inside_the_virtual_filesystem_and_allowed_areas, test_write_quotas",
        "network": "test_network_commands_are_simulated (socket and DNS patched to fail)",
        "inside_cowrie": {"forbiddenCalls": cw["forbiddenCalls"], "linux_commands_never_reach_cowries_shell": True},
        "all_passed": failed == 0})
    write(d, "production_eligibility.json", prod)
    write(d, "artifact_hashes.json", hashes)
    write(d, "known_limitations.json", limitations)
    write(d, "rank7_status.json", {"generated_at": now, "tests": {"passed": failed == 0, "failed": failed},
                                   "cowrieVersion": cw["cowrieVersion"], "supportedCommandCount": count,
                                   "productionEligible": False, "servingEnabled": False, "live": False})
    print(json.dumps({"run_dir": str(d), "failed": failed, "commands": count}))
    return d


if __name__ == "__main__":
    main()
