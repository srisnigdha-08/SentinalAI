#!/usr/bin/env python3
"""
Rank 6: persona policy v2 shadow verification and V1/V2 comparison (docs/PERSONA_POLICY_V2.md section 9).

Read-only. Nothing here can change what is served:
  * production artifacts (shipped seed, repository runtime table, per-user runtime table, demo Q-table, demo v2 state)
    are SHA-256 hashed before and after; every learner used here is built on a temporary COPY with saving disabled;
  * no rotator, Cowrie configuration, engine, backend or database write is involved. Sessions are read with the
    existing read-only tool (evaluation/real_session_report.load: `mongosh find` with a field projection) or from a
    --sessions-file export;
  * evidence records carry no IP address, command, credential or raw session id (a 16-hex reference instead).

What it produces (in a NEW audit/rank6_persona_policy_v2/run_<UTC>/ directory):
  artifact_integrity.json      before / after hashes of every production policy artifact
  policy_comparison.json       persona registry consistency, isolation self-checks, deterministic V1/V2 replay
                               (agreement, distributions, concentration, latency, reproducibility), live shadow records
  persona_distribution.csv     per persona: served, V1 picks, V2 picks (replay) and live shadow picks
  shadow_evidence.jsonl        one versioned shadow-evidence record per replayed decision
  shadow_evidence_summary.json evidence sources (synthetic / operator / simulated / external / untracked)
  readiness_status.json        the ten readiness gates with evidence; overall status

  .venv/Scripts/python evaluation/rank6_v2_shadow_eval.py --mongo-uri mongodb://127.0.0.1:27017/sentinel-demo
  .venv/Scripts/python evaluation/rank6_v2_shadow_eval.py --sessions-file sessions.json     # offline export
"""
import argparse
import copy
import hashlib
import json
import math
import os
import random
import re
import shutil
import sys
import tempfile
import time
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

ENGINE = Path(__file__).resolve().parent.parent
REPO = ENGINE.parent
sys.path.insert(0, str(ENGINE))
sys.path.insert(0, str(REPO / "honeypot"))

from rl_engine import deception_scorer as ds  # noqa: E402
from rl_engine import persona_policy_v2 as v2mod  # noqa: E402

RANK6_VERSION = "rank6/1"
EVIDENCE_SCHEMA = "shadow-evidence/1"
STATE_VERSION = "previous-served-persona/1"  # v1's state definition (SessionScorer.process_session)
DEFAULT_OUT = REPO / "audit" / "rank6_persona_policy_v2"
MIN_SESSIONS_PER_PERSONA = 30   # gate 1 of docs/PERSONA_POLICY_V2.md section 6 (not adjustable here)
INDEPENDENT_SIM = ENGINE / "experiments" / "persona_policy_independent_20261113" / "results.json"
QL_EVIDENCE = ENGINE / "experiments" / "qlearning_evidence_v2_20261113" / "report.json"


def production_artifacts() -> dict:
    home = Path(os.environ.get("USERPROFILE") or Path.home())
    local = Path(os.environ.get("LOCALAPPDATA") or (Path.home() / ".local" / "share"))
    return {
        "shipped_seed": ENGINE / "models" / "q_table.json",
        "repository_runtime_table": ENGINE / "runtime" / "q_table.json",
        "per_user_runtime_table": local / "SentinelAI" / "runtime" / "q_table.json",
        "per_user_v2_state": local / "SentinelAI" / "runtime" / "persona_policy_v2.json",
        "demo_q_table": home / ".sentinelai" / "demo" / "q_table.json",
        "demo_v2_state": home / ".sentinelai" / "demo" / "persona_policy_v2.json",
        "model_registry": ENGINE / "models" / "registry.json",
    }


def sha256(path: Path):
    p = Path(path)
    if not p.is_file():
        return None
    return hashlib.sha256(p.read_bytes()).hexdigest()


def hash_artifacts(paths: dict) -> dict:
    return {k: {"path": str(v).replace(str(Path.home()), "%USERPROFILE%"), "sha256": sha256(v)} for k, v in paths.items()}


def session_ref(session_id) -> str:
    return hashlib.sha256(str(session_id).encode()).hexdigest()[:16]


def state_hash(state: dict) -> str:
    return hashlib.sha256(json.dumps(state, sort_keys=True).encode()).hexdigest()[:16]


# ── persona registry ─────────────────────────────────────────────────────────────────────────────────────────────
def _js_list(path: Path, name: str):
    m = re.search(rf"const {name} = \[([^\]]*)\]", path.read_text(encoding="utf-8"))
    return [x.strip().strip("'\"") for x in m.group(1).split(",") if x.strip()] if m else None


def _py_tuple(path: Path, name: str):
    m = re.search(rf"^{name} = \(([^)]*)\)", path.read_text(encoding="utf-8"), re.M)
    return [x.strip().strip("'\"") for x in m.group(1).split(",") if x.strip()] if m else None


def persona_registry() -> dict:
    """Every place that lists personas, compared. Read-only (honeypot modules are imported, never run)."""
    import build_honeyfs
    import switch_profile
    backend = REPO / "backend" / "utils" / "deceptionProfiles.js"
    reg = {
        "engine_profiles": list(ds.PROFILES_LIST),
        "engine_unsupported": sorted(ds.UNSUPPORTED_PROFILES),
        "engine_servable": list(ds.servable_profiles()),
        "v2_arms": list(v2mod.PersonaPolicyV2(Path(tempfile.mkdtemp()) / "v2.json").arms),
        "backend_profiles": _js_list(backend, "DECEPTION_PROFILES"),
        "backend_unsupported": _js_list(backend, "UNSUPPORTED_PROFILES"),
        "switcher_profiles": list(switch_profile.PROFILES),
        "switcher_unservable": sorted(switch_profile.UNSERVABLE),
        "log_parser_personas": _py_tuple(REPO / "honeypot" / "parsers" / "log_parser.py", "PERSONAS"),
        "honeyfs_distros": list(build_honeyfs.DISTROS),
    }
    servable = reg["engine_servable"]
    configs = {}
    for p in reg["engine_profiles"]:
        cfg = switch_profile.PROFILES.get(p, {})
        try:
            files = len(build_honeyfs.persona_files(p)) if p in build_honeyfs.DISTROS else 0
        except Exception as e:  # noqa: BLE001
            files = f"error: {type(e).__name__}"
        configs[p] = {"switcher_config": bool(cfg), "banner": bool(cfg.get("banner")) if isinstance(cfg, dict) else False,
                      "honeyfs_overrides": files, "servable": p in servable}
    checks = {
        "same_six_everywhere": len({tuple(sorted(reg[k] or [])) for k in ("engine_profiles", "v2_arms", "backend_profiles",
                                                                          "switcher_profiles", "log_parser_personas")}) == 1,
        "unsupported_is_windows_srv_everywhere": reg["engine_unsupported"] == reg["switcher_unservable"]
        == sorted(reg["backend_unsupported"] or []) == ["windows_srv"],
        "every_servable_persona_has_switcher_config_and_banner": all(configs[p]["switcher_config"] and configs[p]["banner"]
                                                                     for p in servable),
        "every_servable_persona_has_honeyfs_overrides": all(isinstance(configs[p]["honeyfs_overrides"], int)
                                                           and configs[p]["honeyfs_overrides"] > 0 for p in servable),
        "windows_srv_not_servable": "windows_srv" not in servable,
        "historical_alpine_3_present": "alpine_3" in reg["engine_profiles"],
    }
    return {"registries": reg, "persona_configs": configs, "checks": checks,
            "ok": all(v for k, v in checks.items() if k != "historical_alpine_3_present")}


# ── isolation self-checks (temporary copies only) ────────────────────────────────────────────────────────────────
SYNTHETIC_SESSIONS = [  # fixtures for the self-checks only: never reported as evidence
    {"sessionId": f"selfcheck-{i}", "durationSeconds": 30 + 40 * (i % 4), "loginSucceeded": i % 2 == 0,
     "commands": [{"command": "uname -a", "intent": "RECONNAISSANCE"}] * (i % 3), "evidenceSource": "simulated",
     "deceptionProfile": ds.SUPPORTED_PROFILES[i % len(ds.SUPPORTED_PROFILES)]} for i in range(12)]


def _scorer(tmp: Path, seed_table: dict, with_v2: bool, v2_patch=None):
    table = tmp / "q.json"
    table.write_text(json.dumps(seed_table), encoding="utf-8")
    sc = ds.SessionScorer(q_table_path=str(table))
    if with_v2:
        sc.v2 = v2mod.PersonaPolicyV2(tmp / "v2.json", prior_means=v2mod.prior_from_q_table(seed_table.get("q_table", {})))
        sc.v2_mode = "shadow"
        if v2_patch:
            v2_patch(sc.v2)
    return sc, table


def table_fingerprint(path: Path) -> str:
    """Hash of a v1 table's learning content: Q-values, counters, rewards, evidence. Save timestamps are excluded
    (they differ on every save and say nothing about what was learned)."""
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    data.pop("saved_at", None)
    for e in (data.get("evidence") or {}).get("update_log") or []:
        e.pop("at", None)
    return hashlib.sha256(json.dumps(data, sort_keys=True).encode()).hexdigest()


def _v1_trace(sc, table):
    random.seed(7)
    out = []
    for s in SYNTHETIC_SESSIONS:
        r = sc.process_session(copy.deepcopy(s))
        out.append((r["nextProfile"], r["rawReward"], r["learned"], r.get("policyV2", {}).get("status")))
    return [o[:3] for o in out], table_fingerprint(table), [o[3] for o in out]


def isolation_self_checks(seed_table: dict) -> dict:
    """V1 with and without V2 (healthy, failing, invalid) must give identical decisions, learning and Q-table bytes."""
    results = {}
    base_dir = Path(tempfile.mkdtemp(prefix="rank6_iso_"))
    try:
        (base_dir / "a").mkdir()
        ref, ref_q, _ = _v1_trace(*_scorer(base_dir / "a", seed_table, False))
        variants = {
            "v2_healthy": None,
            "v2_raises_on_observe": lambda v: setattr(v, "observe", _raise(RuntimeError("boom"))),
            "v2_times_out_on_save": lambda v: setattr(v, "save", _raise(TimeoutError("lock busy"))),
            "v2_returns_unsupported_persona": lambda v: setattr(v, "recommend", lambda current=None: "windows_srv"),
            "v2_returns_garbage": lambda v: setattr(v, "recommend", lambda current=None: {"not": "a persona"}),
        }
        for name, patch in variants.items():
            d = base_dir / name
            d.mkdir()
            trace, q, statuses = _v1_trace(*_scorer(d, seed_table, True, patch))
            results[name] = {"v1_decisions_identical": trace == ref, "v1_q_table_identical": q == ref_q,
                             "v2_statuses": dict(Counter(statuses))}
        # A v2 state path equal to the v1 table is refused by the engine's attach step
        from inference import deception
        d = base_dir / "same_path"
        d.mkdir()
        tbl = d / "q.json"
        tbl.write_text(json.dumps(seed_table), encoding="utf-8")
        before = sha256(tbl)
        sc = ds.SessionScorer(q_table_path=str(tbl))
        old = os.environ.get("DECEPTION_V2_STATE_PATH")
        os.environ["DECEPTION_V2_STATE_PATH"] = str(tbl)
        try:
            deception._attach_policy_v2(sc, str(tbl), ENGINE / "models" / "q_table.json")
        finally:
            if old is None:
                os.environ.pop("DECEPTION_V2_STATE_PATH", None)
            else:
                os.environ["DECEPTION_V2_STATE_PATH"] = old
        results["v2_state_path_equal_to_v1_table"] = {"v2_attached": sc.v2 is not None, "v1_table_unchanged": sha256(tbl) == before}
    finally:
        shutil.rmtree(base_dir, ignore_errors=True)
    ok = all(v.get("v1_decisions_identical", True) and v.get("v1_q_table_identical", True) for v in results.values()) \
        and results["v2_raises_on_observe"]["v2_statuses"] == {"ERROR": len(SYNTHETIC_SESSIONS)} \
        and results["v2_returns_unsupported_persona"]["v2_statuses"] == {"INVALID_RECOMMENDATION": len(SYNTHETIC_SESSIONS)} \
        and results["v2_returns_garbage"]["v2_statuses"] == {"INVALID_RECOMMENDATION": len(SYNTHETIC_SESSIONS)} \
        and results["v2_state_path_equal_to_v1_table"] == {"v2_attached": False, "v1_table_unchanged": True}
    return {"ok": ok, "variants": results, "fixture": f"{len(SYNTHETIC_SESSIONS)} synthetic sessions (self-check only, not evidence)"}


def _raise(err):
    def f(*a, **k):
        raise err
    return f


# ── deterministic replay ─────────────────────────────────────────────────────────────────────────────────────────
def replay(sessions: list, seed_table: dict) -> dict:
    """V1 (greedy, no exploration) and V2 on the same observed sequence, learning from each observed (served persona,
    reward) after deciding. Both start from the shipped seed / prior on temporary copies; nothing is saved."""
    tmp = Path(tempfile.mkdtemp(prefix="rank6_replay_"))
    try:
        v1 = ds.DeceptionQLearner(q_table_path=str(tmp / "v1.json"))
        v1.save = lambda: None
        v1.note_rejection = lambda kind: None
        v1.q_table = ds.DeceptionQLearner._fill_missing(copy.deepcopy(seed_table["q_table"]))
        v1.episode_count = int(seed_table.get("episode_count", 0))
        v2 = v2mod.PersonaPolicyV2(tmp / "v2.json", prior_means=v2mod.prior_from_q_table(seed_table["q_table"]),
                                   prior_source="models/q_table.json (synthetic warm start)",
                                   prior_episodes=int(seed_table.get("episode_count", 0)))
        servable = ds.servable_profiles()
        records, lat1, lat2, prev = [], [], [], None
        for s in sessions:
            served = s["servedProfile"]
            state = {"previousServedPersona": prev, "servedPersona": served}
            # Production order (SessionScorer.process_session): learn from the scored session, then recommend the
            # persona to serve next with the served persona as the state.
            v1.update(prev or served, served, s["reward"], served, session_id=s["sessionId"], source=s["evidenceSource"])
            v2.observe(s["sessionId"], served, s["reward"], persist=False)
            t0 = time.perf_counter()
            v1_pick = v1.greedy_action(served)
            lat1.append(time.perf_counter() - t0)
            t0 = time.perf_counter()
            try:
                stats = v2.stats(served)
                pick, status = v2mod.validate_recommendation(stats["recommendation"])
                err = None
                reason = {a: v.get("index") for a, v in stats["arms"].items()}
            except Exception as e:  # noqa: BLE001
                pick, status, err, reason = None, "ERROR", type(e).__name__, None
            lat2.append(time.perf_counter() - t0)
            records.append({
                "schemaVersion": EVIDENCE_SCHEMA, "policyVersion": v2mod.POLICY_VERSION, "sessionRef": session_ref(s["sessionId"]),
                "stateVersion": STATE_VERSION, "stateHash": state_hash(state), "evidenceSource": s["evidenceSource"],
                "productionPersona": served, "v1Recommendation": v1_pick if v1_pick in servable else None,
                "shadowPersona": pick, "decisionTimestamp": s.get("startTime"),
                "decisionReason": {"rule": "discounted-UCB index, switch margin vs the served persona", "indices": reason},
                "decisionStatus": status, "errorCode": err,
            })
            prev = served
        return {"order": "learn from the session, then recommend the next persona (as in production)",
                "records": records, "latency_us": {"v1_median": _median_us(lat1), "v2_median": _median_us(lat2)},
                "v1_learning": {"episodes": v1.episode_count, "duplicates_rejected": v1.duplicates_rejected},
                "v2_learning": {"realEpisodes": v2.real_episodes}}
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def _median_us(xs):
    if not xs:
        return None
    xs = sorted(xs)
    return round(xs[len(xs) // 2] * 1e6, 2)


def concentration(counts: dict, personas: list) -> dict:
    total = sum(counts.get(p, 0) for p in personas)
    if not total:
        return {"total": 0, "max_share": None, "normalised_entropy": None, "never_selected": list(personas)}
    shares = [counts.get(p, 0) / total for p in personas]
    ent = -sum(x * math.log(x) for x in shares if x > 0) / math.log(len(personas))
    return {"total": total, "max_share": round(max(shares), 4), "normalised_entropy": round(ent, 4),
            "never_selected": [p for p in personas if not counts.get(p)]}


REQUIRED_FIELDS = ("schemaVersion", "policyVersion", "sessionRef", "stateVersion", "stateHash", "evidenceSource",
                   "productionPersona", "shadowPersona", "decisionTimestamp", "decisionReason", "decisionStatus", "errorCode")
FORBIDDEN_FIELDS = ("sourceIP", "sessionId", "commands", "credentials", "password", "username")
SOURCES = ("simulated", "operator", "external", "unknown")


def validate_records(records: list) -> list:
    """Problems with shadow-evidence records (empty = valid): schema, status, persona and provenance rules."""
    problems, seen = [], set()
    servable = ds.servable_profiles()
    for i, r in enumerate(records):
        missing = [f for f in REQUIRED_FIELDS if f not in r]
        if missing:
            problems.append({"record": i, "missing": missing})
        if any(f in r for f in FORBIDDEN_FIELDS):
            problems.append({"record": i, "forbidden": [f for f in FORBIDDEN_FIELDS if f in r]})
        if r.get("schemaVersion") != EVIDENCE_SCHEMA:
            problems.append({"record": i, "schemaVersion": r.get("schemaVersion")})
        if r.get("decisionStatus") not in v2mod.SHADOW_STATUSES:
            problems.append({"record": i, "decisionStatus": r.get("decisionStatus")})
        if r.get("decisionStatus") == "OK" and r.get("shadowPersona") not in servable:
            problems.append({"record": i, "shadowPersona": r.get("shadowPersona")})
        if r.get("decisionStatus") != "OK" and r.get("shadowPersona") is not None:
            problems.append({"record": i, "shadowPersona_on_failure": r.get("shadowPersona")})
        if r.get("evidenceSource") not in SOURCES:
            problems.append({"record": i, "evidenceSource": r.get("evidenceSource")})
        if r.get("sessionRef") in seen:
            problems.append({"record": i, "duplicate_sessionRef": r.get("sessionRef")})
        seen.add(r.get("sessionRef"))
    return problems


def compare(records: list) -> dict:
    servable = ds.servable_profiles()
    v1_ok = [r for r in records if r["v1Recommendation"]]
    v2_ok = [r for r in records if r["decisionStatus"] == "OK"]
    both = [r for r in records if r["v1Recommendation"] and r["decisionStatus"] == "OK"]
    agree = sum(r["v1Recommendation"] == r["shadowPersona"] for r in both)
    v1c = Counter(r["v1Recommendation"] for r in v1_ok)
    v2c = Counter(r["shadowPersona"] for r in v2_ok)
    served = Counter(r["productionPersona"] for r in records)
    return {
        "samples": len(records), "v1_successful": len(v1_ok), "v2_successful": len(v2_ok),
        "v2_errors": sum(r["decisionStatus"] == "ERROR" for r in records),
        "v2_invalid_or_unsupported": sum(r["decisionStatus"] == "INVALID_RECOMMENDATION" for r in records),
        "fallbacks": 0, "fallback_note": "shadow mode never substitutes a persona; an invalid v2 pick is recorded, v1 decides",
        "agreement": agree, "disagreement": len(both) - agree,
        "agreement_pct": round(100 * agree / len(both), 2) if both else None,
        "served": dict(served), "v1": dict(v1c), "v2": dict(v2c),
        "v1_concentration": concentration(v1c, servable), "v2_concentration": concentration(v2c, servable),
        "served_concentration": concentration(served, servable),
    }


# ── evidence ─────────────────────────────────────────────────────────────────────────────────────────────────────
def load_sessions(args) -> tuple:
    """Closed, scored sessions with a served persona, oldest first, reward recomputed with calc_reward. Classified
    by real_session_report.classify (simulated / operator / external). Returns (sessions, skipped, live_shadow)."""
    from evaluation import real_session_report as rsr
    raw, _decisions = rsr.load(args)
    out, skipped, live = [], Counter(), []
    nets = [__import__("ipaddress").ip_network(c) for c in (args.operator_cidr or [])]
    for s in raw:
        served = s.get("servedProfile")
        if served not in ds.PROFILES:
            skipped["no_served_persona"] += 1
            continue
        if served not in ds.servable_profiles():
            skipped["unsupported_served_persona"] += 1
            continue
        cls, _why = rsr.classify(s, set(args.operator_ip or []), nets, set(), [])
        when = rsr._date(s.get("startTime")) or rsr._date(s.get("createdAt"))
        out.append({"sessionId": s.get("sessionId"), "servedProfile": served, "reward": rsr.reward_of(s),
                    "evidenceSource": cls, "startTime": when.isoformat() if when else None})
        sp = s.get("shadowPolicy")
        if isinstance(sp, dict):
            live.append({"recommendation": sp.get("recommendation"), "status": sp.get("status") or "LEGACY_NO_STATUS",
                         "v1": s.get("recommendedProfile"), "source": cls})
    out.sort(key=lambda r: (r["startTime"] or "", r["sessionId"]))
    seen, dedup = set(), []
    for r in out:
        if r["sessionId"] in seen:
            skipped["duplicate_session_id"] += 1
            continue
        seen.add(r["sessionId"])
        dedup.append(r)
    return dedup, dict(skipped), live


def evidence_summary(sessions: list, live: list) -> dict:
    ql = json.loads(QL_EVIDENCE.read_text(encoding="utf-8")) if QL_EVIDENCE.is_file() else {}
    ep = ql.get("episodes", {})
    by_source = Counter(s["evidenceSource"] for s in sessions)
    per_persona = {p: dict(Counter(s["evidenceSource"] for s in sessions if s["servedProfile"] == p)) for p in ds.servable_profiles()}
    return {
        "synthetic_seed_episodes": ep.get("syntheticSeed"),
        "q_table_total_episodes": ep.get("total"),
        "q_table_session_driven_updates": ep.get("sessionDriven"),
        "q_table_untracked_updates": ep.get("untracked"),
        "q_table_independent_external": ep.get("independentExternal"),
        "q_table_report": str(QL_EVIDENCE.relative_to(REPO)) if QL_EVIDENCE.is_file() else None,
        "recorded_sessions_by_source": dict(by_source),
        "recorded_sessions_per_persona_by_source": per_persona,
        "independent_external_sessions": by_source.get("external", 0),
        "live_shadow_records": len(live),
        "live_shadow_by_status": dict(Counter(x["status"] for x in live)),
        "live_shadow_agreement_with_v1": sum(1 for x in live if x["recommendation"] and x["recommendation"] == x["v1"]),
        "notes": ["synthetic seed episodes are a warm start, never attacker evidence",
                  "untracked Q-table updates have no recorded source and are never counted as operator or external",
                  "operator labels are inferred from a private source address, not recorded provenance (see session_provenance); never independent evidence"],
    }


# ── provenance reconciliation (Rank 6 corrections) ──────────────────────────────────────────────────────────────
# The replay's "operator" label is inferred from the source address (real_session_report.classify: a private or
# loopback address is treated as operator because Cowrie is not internet-facing here). That is a label, not
# recorded provenance. Recorded provenance is the session's own evidenceSource field (backend
# utils/evidenceSource.js); verified provenance is an admin-confirmed label (evidenceLabel.method == "admin").
# External evidence counts only when recorded as external, which the backend allows only under authorised
# collection. Nothing is upgraded: a session without a recorded source stays untracked.
PROVENANCE_FIELDS = {"_id": 0, "sessionId": 1, "evidenceSource": 1, "evidenceLabel.method": 1, "deceptionScoredAt": 1}


def recorded_provenance(args) -> dict:
    """sessionId -> {"recorded", "method", "scored"} from the session records themselves (read-only)."""
    from evaluation import real_session_report as rsr
    if args.mongo_uri:
        rows = rsr._mongosh(args.mongo_uri, "honeypotsessions", PROVENANCE_FIELDS)
    else:
        rows, _ = rsr.load(args)
    out = {}
    for r in rows:
        src = r.get("evidenceSource")
        label = r.get("evidenceLabel") if isinstance(r.get("evidenceLabel"), dict) else {}
        out[r.get("sessionId")] = {"recorded": src if src in ("operator", "external", "simulated", "unknown") else None,
                                   "method": label.get("method"), "scored": bool(r.get("deceptionScoredAt"))}
    return out


def reconcile_provenance(sessions: list, prov: dict, ql: dict | None = None) -> dict:
    ql = ql if ql is not None else (json.loads(QL_EVIDENCE.read_text(encoding="utf-8")) if QL_EVIDENCE.is_file() else {})
    servable = ds.servable_profiles()
    rows = [(s, prov.get(s["sessionId"], {"recorded": None, "method": None, "scored": False})) for s in sessions]
    recorded = [(s, p) for s, p in rows if p["recorded"]]
    verified = [(s, p) for s, p in recorded if p["method"] == "admin"]
    verified_external = [(s, p) for s, p in recorded if p["recorded"] == "external"]
    ep = ql.get("episodes", {})
    index = (ql.get("learnedSessionIndex") or {}).get("sessions")
    return {
        "total_sessions_evaluated": len(sessions),
        "labelled_operator_in_replay": sum(1 for s in sessions if s["evidenceSource"] == "operator"),
        "replay_label_basis": "inferred from the source address by real_session_report.classify (private/loopback = operator); not recorded provenance",
        "replay_labels": dict(Counter(s["evidenceSource"] for s in sessions)),
        "with_recorded_source_provenance": len(recorded),
        "recorded_by_source": dict(Counter(p["recorded"] for _, p in recorded)),
        "with_recorded_and_verified_provenance": len(verified),
        "with_untracked_or_unverifiable_provenance": len(sessions) - len(verified),
        "without_any_recorded_source": len(sessions) - len(recorded),
        "independently_verified_external": len(verified_external),
        "independently_verified_external_per_persona": {p: sum(1 for s, _ in verified_external if s["servedProfile"] == p) for p in servable},
        "scored_by_engine": sum(1 for _, p in rows if p["scored"]),
        "never_scored_by_engine": sum(1 for _, p in rows if not p["scored"]),
        "q_table_link": {
            "q_table_session_driven_updates": ep.get("sessionDriven"),
            "q_table_untracked_updates": ep.get("untracked"),
            "q_table_learned_session_index": index,
            "linked_to_replayed_sessions": False,
            "note": "the Q-table's session-driven updates have no recorded session ids, so they cannot be matched to the replayed sessions; equal counts are not a match",
        },
        "synthetic_seed_episodes_counted_as_sessions": 0,
        "statement": (f"{len(sessions)} historical sessions were evaluated in the replay. "
                      f"{sum(1 for s in sessions if s['evidenceSource'] == 'operator')} are labelled operator in the evaluation context "
                      f"(inferred from a private source address); {len(recorded)} carry a recorded source and {len(verified)} a verified one, "
                      f"so the original source provenance of {len(sessions) - len(verified)} remains untracked or unverifiable. "
                      f"{len(verified_external)} are independently verified external attacker sessions."),
    }


# ── readiness ────────────────────────────────────────────────────────────────────────────────────────────────────
def readiness(reg, iso, comp, reproducible, ev, sim, prov=None) -> dict:
    """prov: reconcile_provenance() output. When given (every real run), independent evidence counts only
    sessions whose recorded provenance is external; an address-inferred "external" label never counts."""
    servable = ds.servable_profiles()
    per = ev["recorded_sessions_per_persona_by_source"]
    sessions_ok = all(sum(per.get(p, {}).values()) >= MIN_SESSIONS_PER_PERSONA for p in servable)
    ext = prov["independently_verified_external_per_persona"] if prov is not None else {p: per.get(p, {}).get("external", 0) for p in servable}
    external_ok = all(ext.get(p, 0) >= MIN_SESSIONS_PER_PERSONA for p in servable)
    sim_ok = bool(sim.get("passed")) if sim else None

    def g(status, evidence):
        return {"status": status, "evidence": evidence}

    gates = {
        "1_shadow_isolation": g("PASS" if iso["ok"] else "FAIL", "self-checks: V1 decisions, learning and Q-table bytes identical with V2 healthy, failing, timing out or invalid; V2 state on the V1 table refused"),
        "2_persona_compatibility": g("PASS" if reg["ok"] else "FAIL", reg["checks"]),
        "3_invalid_action_handling": g("PASS" if iso["variants"]["v2_returns_unsupported_persona"]["v2_statuses"] == {"INVALID_RECOMMENDATION": len(SYNTHETIC_SESSIONS)} else "FAIL",
                                       "unsupported (windows_srv) and malformed picks are rejected, never substituted"),
        "4_failure_isolation": g("PASS" if iso["variants"]["v2_raises_on_observe"]["v1_decisions_identical"] and iso["variants"]["v2_times_out_on_save"]["v1_decisions_identical"] else "FAIL",
                                 "V2 exceptions and lock timeouts recorded as ERROR; V1 unaffected"),
        "5_evidence_schema_and_provenance": g("PASS" if comp["records_valid"] else "FAIL",
                                              {"schema": EVIDENCE_SCHEMA, "problems": comp["record_problems"][:5],
                                               "note": "source classification on every record; synthetic and untracked kept apart"}),
        "6_reproducible_evaluation": g("PASS" if reproducible else "FAIL", "two replays on the same inputs gave identical records"),
        "7_adequate_session_evidence": g("PASS" if sessions_ok else "INSUFFICIENT_DATA",
                                         {p: sum(per.get(p, {}).values()) for p in servable} | {"required_per_persona": MIN_SESSIONS_PER_PERSONA}),
        "8_independent_evidence": g("PASS" if external_ok else "INSUFFICIENT_DATA",
                                    {"external_per_persona": {p: ext.get(p, 0) for p in servable},
                                     "counted": "recorded, verified external provenance only" if prov is not None else "replay labels",
                                     "required_per_persona": MIN_SESSIONS_PER_PERSONA}),
        "9_decision_stability": g("PASS" if sim_ok else ("FAIL" if sim_ok is False else "NOT_VERIFIED"),
                                  {"source": str(INDEPENDENT_SIM.relative_to(REPO)), "label": "SIMULATED", **(sim or {})}),
        "10_documented_acceptance_criteria": g("NOT_MET", "docs/PERSONA_POLICY_V2.md section 6 gates 1-4: 0 external sessions, effectiveness not evaluable, shadow period not recorded, no live rollback rehearsal"),
    }
    engineering = all(gates[k]["status"] == "PASS" for k in ("1_shadow_isolation", "2_persona_compatibility", "3_invalid_action_handling",
                                                            "4_failure_isolation", "5_evidence_schema_and_provenance", "6_reproducible_evaluation"))
    overall = "READY" if all(v["status"] == "PASS" for v in gates.values()) else "NOT_READY"
    return {"overall": overall, "shadow_engineering": "PASS" if engineering else "FAIL", "gates": gates,
            "promotion": "never automatic: DECEPTION_V2 is unchanged (default shadow); activation is an owner decision after every gate passes"}


# ── run ──────────────────────────────────────────────────────────────────────────────────────────────────────────
def new_run_dir(base: Path, stamp: str) -> Path:
    base.mkdir(parents=True, exist_ok=True)
    d, n = base / f"run_{stamp}", 1
    while d.exists():
        d = base / f"run_{stamp}_{n}"
        n += 1
    d.mkdir()
    return d


def _write(path: Path, text: str):
    if path.exists():
        raise FileExistsError(path)
    path.write_text(text, encoding="utf-8")


def run(args) -> Path:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    arts = production_artifacts()
    before = hash_artifacts(arts)
    seed_table = json.loads(arts["shipped_seed"].read_text(encoding="utf-8"))
    reg = persona_registry()
    iso = isolation_self_checks(seed_table)
    sessions, skipped, live = load_sessions(args)
    r1 = replay(sessions, seed_table)
    r2 = replay(sessions, seed_table)
    reproducible = json.dumps(r1["records"], sort_keys=True) == json.dumps(r2["records"], sort_keys=True)
    comp = compare(r1["records"])
    problems = validate_records(r1["records"])
    comp["records_valid"], comp["record_problems"] = not problems, problems
    ev = evidence_summary(sessions, live)
    sim = json.loads(INDEPENDENT_SIM.read_text(encoding="utf-8")).get("criteria") if INDEPENDENT_SIM.is_file() else None
    prov = reconcile_provenance(sessions, recorded_provenance(args))
    ev["session_provenance"] = prov
    ev["recorded_sessions_by_source_basis"] = prov["replay_label_basis"]
    ev["independent_external_sessions"] = prov["independently_verified_external"]
    ready = readiness(reg, iso, comp, reproducible, ev, sim, prov)
    ready["session_provenance"] = {k: prov[k] for k in (
        "total_sessions_evaluated", "labelled_operator_in_replay", "with_recorded_and_verified_provenance",
        "with_untracked_or_unverifiable_provenance", "independently_verified_external", "statement")}
    after = hash_artifacts(arts)
    unchanged = before == after
    if not unchanged:
        ready["overall"] = "FAILED"
    out = new_run_dir(Path(args.out), stamp)
    common = {"rank6_version": RANK6_VERSION, "generated_at": datetime.now(timezone.utc).isoformat(),
              "policy_version": v2mod.POLICY_VERSION, "v2_defaults": v2mod.DEFAULTS,
              "data_source": "mongosh read-only find (real_session_report.load)" if args.mongo_uri else "sessions file export"}
    _write(out / "artifact_integrity.json", json.dumps({**common, "before": before, "after": after, "unchanged": unchanged}, indent=1))
    _write(out / "policy_comparison.json", json.dumps({**common, "persona_registry": reg, "isolation_self_checks": iso,
                                                       "replay": {"method": "V1 greedy (no exploration) and V2 deterministic, both from the shipped seed / prior on temporary copies, deciding before learning each observed session",
                                                                  "sessions_skipped": skipped, **comp, "latency_us": r1["latency_us"],
                                                                  "reproducible": reproducible, "v1_learning": r1["v1_learning"],
                                                                  "v2_learning": r1["v2_learning"]},
                                                       "live_shadow": {k: ev[k] for k in ("live_shadow_records", "live_shadow_by_status", "live_shadow_agreement_with_v1")}},
                                                      indent=1, default=str))
    rows = ["persona,servable,served_sessions,v1_replay_picks,v2_replay_picks,live_shadow_picks"]
    live_c = Counter(x["recommendation"] for x in live if x["recommendation"])
    for p in ds.PROFILES_LIST:
        rows.append(f"{p},{p in ds.servable_profiles()},{comp['served'].get(p, 0)},{comp['v1'].get(p, 0)},{comp['v2'].get(p, 0)},{live_c.get(p, 0)}")
    _write(out / "persona_distribution.csv", "\n".join(rows) + "\n")
    _write(out / "shadow_evidence.jsonl", "".join(json.dumps(r, sort_keys=True) + "\n" for r in r1["records"]))
    _write(out / "shadow_evidence_summary.json", json.dumps({**common, **ev}, indent=1))
    _write(out / "provenance_reconciliation.json", json.dumps({**common, **prov}, indent=1))
    _write(out / "readiness_status.json", json.dumps({**common, **ready}, indent=1, default=str))
    print(json.dumps({"run_dir": str(out), "overall": ready["overall"], "samples": comp["samples"],
                      "agreement_pct": comp["agreement_pct"], "unchanged": unchanged}, indent=1))
    return out


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--mongo-uri", help="read-only source (mongosh find with a projection)")
    ap.add_argument("--sessions-file")
    ap.add_argument("--decisions-file")
    ap.add_argument("--operator-ip", action="append")
    ap.add_argument("--operator-cidr", action="append")
    ap.add_argument("--out", default=str(DEFAULT_OUT))
    return run(ap.parse_args(argv))


if __name__ == "__main__":
    main()
