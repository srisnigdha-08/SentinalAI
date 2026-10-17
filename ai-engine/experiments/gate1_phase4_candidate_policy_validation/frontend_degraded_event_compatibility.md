# SentinelAI GATE-1 Phase 4: Frontend Degraded Event Compatibility & Triage Report

**Component**: `frontend/src/pages/ThreatLogs.jsx`  
**Auditor / Engineer**: Senior ML Security Engineer & Backend Security Auditor  
**Date**: 2026-10-16  
**Status**: **Verified**

---

## 1. Context and Problem Statement

During Phase 3E, an audit of the frontend interface revealed two limitations:
1. `STATUS_STYLES` lacked an explicit mapping for `'DEGRADED'`. While it fell back safely to `STATUS_STYLES.DETECTED` (cyan outline badge), it did not visually signal to the security analyst that the record represented a degraded fallback rather than an active, confirmed detection.
2. The `TYPES` array in `ThreatLogs.jsx` omitted `'UNINSPECTED_TRAFFIC'`, preventing analysts from specifically selecting and filtering for degraded traffic using the category dropdown.

---

## 2. Implemented Frontend Enhancements

In Phase 4, `frontend/src/pages/ThreatLogs.jsx` was enhanced directly on branch `feature/gate1-phase4-candidate-policy` (commit `e9f71a0`):

```javascript
// frontend/src/pages/ThreatLogs.jsx L12-L22:

const STATUS_STYLES = {
  BLOCKED:    { background:'rgba(255,45,85,.15)',  color:'#ff2d55', border:'1px solid rgba(255,45,85,.3)'  },
  MONITORING: { background:'rgba(255,170,0,.1)',   color:'#ffaa00', border:'1px solid rgba(255,170,0,.3)'  },
  DETECTED:   { background:'rgba(0,212,255,.1)',   color:'#00d4ff', border:'1px solid rgba(0,212,255,.25)' },
  RESOLVED:   { background:'rgba(0,255,136,.1)',   color:'#00ff88', border:'1px solid rgba(0,255,136,.3)'  },
  DEGRADED:   { background:'rgba(255,170,0,.15)',  color:'#ffaa00', border:'1px dashed rgba(255,170,0,.5)' },
}

const TYPES = ['SSH Brute Force','SQL Injection','Port Scan','DDoS','RCE Attempt',
               'XSS Attempt','Malware Beacon','Credential Stuffing','Lateral Movement','Data Exfiltration',
               'UNINSPECTED_TRAFFIC']
```

### Visual & Functional Behavior:
1. **Distinct Status Badging**: Records with `status: 'DEGRADED'` now render with an amber text and dashed border badge (`#ffaa00`, `1px dashed rgba(255,170,0,.5)`). Analysts immediately recognize that the event originated from model service unavailability or corrupted inputs rather than confirmed attack detection.
2. **First-Class Category Triage**: `'UNINSPECTED_TRAFFIC'` is now a selectable option in the attack type dropdown. Selecting it issues an API request:
   `GET /api/threats?type=UNINSPECTED_TRAFFIC`
   allowing operators to isolate, audit, and investigate degraded flows exclusively.
3. **Observation Mode Safety**: Because `l.status !== 'BLOCKED'`, viewer and analyst roles see appropriate triage actions without triggering accidental automated containment.

---

## 3. End-to-End Consumer Compatibility Verification

| Consumer | Location | Compatibility Check | Verification Result |
| :--- | :--- | :--- | :---: |
| **Threat Table** | `ThreatLogs.jsx` L206-208 | Renders `STATUS_STYLES['DEGRADED']` | **Verified** |
| **Type Filter** | `ThreatLogs.jsx` L31, L59 | Dropdown includes `'UNINSPECTED_TRAFFIC'` | **Verified** |
| **Search Input** | `ThreatLogs.jsx` L60, L72 | Matches keyword `'UNINSPECTED_TRAFFIC'` | **Verified** |
| **Dashboard KPIs**| `Dashboard.jsx` L61 | Aggregates degraded records into total counts | **Verified** |
| **Vector Chart** | `Dashboard.jsx` L20, L70 | Recharts renders unmapped types using default theme palette | **Verified** |
