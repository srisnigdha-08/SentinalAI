"""
Session features, label provenance, leakage-safe split, readiness gate and an evaluation harness.

Labels carry a METHOD:
  rule      produced by the rule-based classifier (honeypot_rules). Usable as the BASELINE, never as ground truth.
  manual    assigned by an analyst who reviewed the session (independent of the rules)
  external  from an independent source (e.g. a shared, labelled honeypot corpus) with its reference
Only manual/external labels count towards readiness or training.
"""
import math
import re
import statistics as st
from datetime import datetime, timezone
from typing import Dict, List

FEATURE_VERSION = "session_v1"
INTENTS = ("RECONNAISSANCE", "CREDENTIAL_HARVEST", "MALWARE_DOWNLOAD", "PERSISTENCE", "PRIVILEGE_ESCALATION", "REVERSE_SHELL")
INDEPENDENT_METHODS = ("manual", "external")
LABEL_METHODS = ("rule",) + INDEPENDENT_METHODS
MIN_PER_CLASS = 30           # independent labels per class before a candidate may be trained
MIN_CLASSES = 2
MIN_TIME_SPAN_DAYS = 14      # labelled sessions must span this long, so a time-aware split is possible
_FP = re.compile(r"\b(systemd-detect-virt|virt-what|dmidecode|imvirt)\b|/proc/1/cgroup|\.dockerenv")


def _ts(v):
    if isinstance(v, (int, float)):
        return float(v)
    if isinstance(v, datetime):
        return v.timestamp()
    if isinstance(v, str) and v:
        try:
            return datetime.fromisoformat(v.replace("Z", "+00:00")).timestamp()
        except ValueError:
            return None
    return None


def extract_features(session: dict) -> Dict[str, float]:
    """Behavioural features of one session. Commands are read as text and never executed."""
    cmds = session.get("commands") or []
    texts = [str(c.get("command", "")) for c in cmds]
    times = [t for t in (_ts(c.get("timestamp")) for c in cmds) if t is not None]
    gaps = [b - a for a, b in zip(times, times[1:]) if b >= a]
    intents = [c.get("intent") for c in cmds]
    first_words = [t.strip().split()[0] if t.strip() else "" for t in texts]
    bigrams = set(zip(first_words, first_words[1:]))
    f = {
        "n_commands": float(len(texts)),
        "unique_command_ratio": len(set(texts)) / len(texts) if texts else 0.0,
        "distinct_programs": float(len(set(first_words) - {""})),
        "bigram_diversity": len(bigrams) / max(1, len(first_words) - 1),
        "duration_seconds": float(session.get("durationSeconds") or 0.0),
        "login_succeeded": float(bool(session.get("loginSucceeded"))),
        "failed_logins": float(session.get("failedLogins") or 0),
        "gap_mean_s": st.mean(gaps) if gaps else 0.0,
        "gap_median_s": st.median(gaps) if gaps else 0.0,
        "gap_std_s": st.pstdev(gaps) if len(gaps) > 1 else 0.0,
        "max_command_length": float(max((len(t) for t in texts), default=0)),
        "pipes_and_redirects": float(sum(t.count("|") + t.count(">") for t in texts)),
        "downloads": float(sum(bool(re.search(r"\b(wget|curl|tftp|ftpget)\b", t)) for t in texts)),
        "executes_downloaded": float(any(re.search(r"chmod \+x|\./", t) for t in texts)),
        "fingerprint_commands": float(sum(bool(_FP.search(t)) for t in texts)),
        "ioc_count": float(session.get("iocCount") or 0),
    }
    for i in INTENTS:
        f[f"intent_{i.lower()}"] = float(sum(x == i for x in intents))
    return f


FEATURE_NAMES = sorted(extract_features({"commands": []}))


def make_label(session_id: str, label: str, method: str, labeler: str, start_time, reference: str = "") -> dict:
    if method not in LABEL_METHODS:
        raise ValueError(f"method must be one of {LABEL_METHODS}")
    if method in INDEPENDENT_METHODS and not labeler:
        raise ValueError("independent labels need a labeler")
    if method == "external" and not reference:
        raise ValueError("external labels need a reference to their source")
    return {"sessionId": str(session_id), "label": str(label), "method": method, "labeler": labeler,
            "reference": reference, "startTime": _ts(start_time), "labeledAt": datetime.now(timezone.utc).isoformat()}


def readiness(labels: List[dict]) -> dict:
    """Whether enough INDEPENDENT labels exist to train and honestly evaluate a candidate."""
    ind = [l for l in labels if l.get("method") in INDEPENDENT_METHODS]
    per_class: Dict[str, int] = {}
    for l in ind:
        per_class[l["label"]] = per_class.get(l["label"], 0) + 1
    ts = [l["startTime"] for l in ind if l.get("startTime") is not None]
    span_days = (max(ts) - min(ts)) / 86400 if len(ts) > 1 else 0.0
    usable = [c for c, n in per_class.items() if n >= MIN_PER_CLASS]
    reasons = []
    if len(usable) < MIN_CLASSES:
        reasons.append(f"needs >= {MIN_PER_CLASS} independent labels in >= {MIN_CLASSES} classes; have {per_class or 'none'}")
    if span_days < MIN_TIME_SPAN_DAYS:
        reasons.append(f"independent labels span {span_days:.1f} days; needs >= {MIN_TIME_SPAN_DAYS} for a time-aware split")
    return {"ready": not reasons, "reasons": reasons, "independentLabels": len(ind),
            "ruleLabels": sum(l.get("method") == "rule" for l in labels), "perClass": per_class, "spanDays": round(span_days, 2)}


def time_aware_split(rows: List[dict], test_fraction: float = 0.3):
    """Train on earlier sessions, test on later ones. Every row of a source IP stays on ONE side (the side of its
    first session), so the same attacker never appears in both. Returns (train, test)."""
    rows = sorted(rows, key=lambda r: r["startTime"])
    cut = rows[int(len(rows) * (1 - test_fraction))]["startTime"] if rows else 0
    first = {}
    for r in rows:
        first.setdefault(r.get("sourceIP"), r["startTime"])
    train = [r for r in rows if first[r.get("sourceIP")] < cut]
    test = [r for r in rows if first[r.get("sourceIP")] >= cut]
    assert not ({r["sessionId"] for r in train} & {r["sessionId"] for r in test})
    assert not ({r.get("sourceIP") for r in train} & {r.get("sourceIP") for r in test})
    return train, test


def per_class_report(y_true, y_pred) -> dict:
    labels = sorted(set(y_true) | set(y_pred))
    out = {}
    for c in labels:
        tp = sum(t == c and p == c for t, p in zip(y_true, y_pred))
        fp = sum(t != c and p == c for t, p in zip(y_true, y_pred))
        fn = sum(t == c and p != c for t, p in zip(y_true, y_pred))
        prec = tp / (tp + fp) if tp + fp else 0.0
        rec = tp / (tp + fn) if tp + fn else 0.0
        out[c] = {"precision": round(prec, 4), "recall": round(rec, 4),
                  "f1": round(2 * prec * rec / (prec + rec), 4) if prec + rec else 0.0, "support": sum(t == c for t in y_true)}
    cm = [[sum(t == a and p == b for t, p in zip(y_true, y_pred)) for b in labels] for a in labels]
    macro = sum(v["f1"] for v in out.values()) / len(out) if out else 0.0
    return {"perClass": out, "macroF1": round(macro, 4), "confusion": {"labels": labels, "matrix": cm}}


def train_and_evaluate(rows: List[dict], rule_predict, force_for_tests: bool = False) -> dict:
    """Shadow candidate: logistic regression on standardised features, compared with the rule baseline on the same
    later-in-time test sessions. Refuses unless readiness() passes (force_for_tests only for synthetic test data).
    Returns metrics and per-feature contributions for explanations; never writes a model anywhere."""
    labels = [{k: r[k] for k in ("sessionId", "label", "method", "startTime")} for r in rows]
    ready = readiness(labels)
    if not ready["ready"] and not force_for_tests:
        return {"trained": False, "readiness": ready}
    from sklearn.linear_model import LogisticRegression
    from sklearn.preprocessing import StandardScaler
    rows = [r for r in rows if r["method"] in INDEPENDENT_METHODS]
    train, test = time_aware_split(rows)
    X = lambda rs: [[extract_features(r["session"])[n] for n in FEATURE_NAMES] for r in rs]  # noqa: E731
    sc = StandardScaler().fit(X(train))
    clf = LogisticRegression(max_iter=2000, class_weight="balanced").fit(sc.transform(X(train)), [r["label"] for r in train])
    y_true = [r["label"] for r in test]
    cand = list(clf.predict(sc.transform(X(test))))
    base = [rule_predict(r["session"]) for r in test]
    contrib = {}
    if test:
        z = sc.transform(X(test[:1]))[0]
        k = list(clf.classes_).index(cand[0]) if len(clf.classes_) > 2 else None
        coefs = clf.coef_[k] if k is not None else clf.coef_[0] * (1 if cand[0] == clf.classes_[1] else -1)
        contrib = dict(sorted(((n, round(float(c * v), 4)) for n, c, v in zip(FEATURE_NAMES, coefs, z)),
                              key=lambda kv: -abs(kv[1]))[:8])
    return {"trained": True, "shadowOnly": True, "readiness": ready, "trainSessions": len(train), "testSessions": len(test),
            "candidate": per_class_report(y_true, cand), "ruleBaseline": per_class_report(y_true, base),
            "exampleExplanation": {"predicted": cand[0] if cand else None, "topContributions": contrib}}


def _main():
    import json
    import sys
    # Readiness of whatever label file is given (JSON list of make_label() records); prints why training is refused.
    labels = json.loads(open(sys.argv[1], encoding="utf-8").read()) if len(sys.argv) > 1 else []
    print(json.dumps(readiness(labels), indent=1))


if __name__ == "__main__":
    _main()
