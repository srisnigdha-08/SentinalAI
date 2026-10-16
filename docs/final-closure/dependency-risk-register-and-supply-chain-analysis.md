# SentinelAI Final Closure: Dependency Risk Register & Supply-Chain Analysis

**Date**: October 15, 2026  
**Auditor**: Dependency & Supply-Chain Security Engineer  
**Scope**: Production Dependencies (`backend/package.json`, 221 production packages)  
**Status**: **DISPOSITIONS CLOSED & GATED**

---

## 1. Audit Scope & Executive Summary

A comprehensive production dependency audit was executed using `npm audit --omit=dev --json` on the backend service. Out of 221 production dependencies (672 total dependencies including development tooling), 12 vulnerability advisories across 6 distinct packages were identified:
- **Critical Severity**: 1 advisory (`proxy-addr`)
- **High Severity**: 6 advisories (`fast-uri` [5], `js-yaml` [1])
- **Moderate Severity**: 5 advisories (`morgan` [2], `qs` [2], `uuid` [1])

None of the vulnerable code paths are exploitable in the current local development or internal testing architecture. Defensible technical dispositions, reachability analyses, and mitigation evidence are documented below.

---

## 2. Complete Vulnerability Inventory & Dispositions

### VULN-001: `proxy-addr` — IP Spoofing via IPv4-Mapped IPv6 Subnets
- **Advisory ID**: GHSA-jqcg-44mw-7w3h
- **Severity**: **CRITICAL (CVSS: 9.1)**
- **Installed Version**: `2.0.7` (Affected range: `>=1.1.0 <2.0.8`)
- **Dependency Type**: Transitive via `express@4.18.2` (`express > proxy-addr`)
- **Vulnerability Description**: When configured with an IPv4 trust list (e.g. `127.0.0.1`), an attacker presenting an IPv4-mapped IPv6 address (e.g. `::ffff:127.0.0.1`) could bypass trust boundaries and spoof remote client IP headers (`X-Forwarded-For`).
- **Reachability in SentinelAI**: **UNREACHABLE**. SentinelAI runs bound directly to loopback (`127.0.0.1`) without upstream reverse-proxy trusting enabled (`app.set('trust proxy', false)` is the active Express default). Untrusted headers are ignored.
- **Mitigation Evidence**: Backend only accepts connections directly on loopback; no untrusted multi-hop reverse proxies exist.
- **Fix Availability**: Fixed in `proxy-addr@2.0.8`. However, Express 4.x pins older transitives; clean resolution requires Express v5.
- **Disposition**: **MITIGATED WITH EVIDENCE (ACCEPTED RESIDUAL RISK)**.

### VULN-002: `fast-uri` — SSRF & Host Confusion via Repeated Percent-Decoding
- **Advisory IDs**: GHSA-8v4j-7jgf-552f, GHSA-fph4-wmhf-6fwf, GHSA-jqff-g426-hqxp, GHSA-qw65-cvwx-89v3, GHSA-hrr3-gc8f-f4qj
- **Severity**: **HIGH (CVSS: 7.5)**
- **Installed Version**: `3.1.2` (Affected range: `>=3.0.0 <3.1.8`)
- **Dependency Type**: Transitive via `swagger-jsdoc` / `@apidevtools/json-schema-ref-parser` / `ajv`
- **Vulnerability Description**: Repeated percent-decoding and unvalidated port serialization can allow authority injection and SSRF during URI parsing.
- **Reachability in SentinelAI**: **UNREACHABLE**. `fast-uri` is utilized strictly by AJV to validate internal schema definitions. SentinelAI does not fetch arbitrary external URLs based on user-supplied URI strings parsed by `fast-uri`.
- **Mitigation Evidence**: Schema validation operates strictly on in-memory JSON schemas.
- **Fix Availability**: Fixed in `fast-uri@3.1.8`.
- **Disposition**: **MITIGATED WITH EVIDENCE**.

### VULN-003: `js-yaml` — Denial of Service via Merge Keys
- **Advisory ID**: GHSA-2883-xcg3-v3hh
- **Severity**: **HIGH (CVSS: 7.5)**
- **Installed Version**: `4.1.0` (Affected range: `>=4.0.0 <4.3.2`)
- **Dependency Type**: Transitive via `@apidevtools/json-schema-ref-parser > js-yaml`
- **Vulnerability Description**: Missing limit on CPU utilization when parsing empty merge keys (`<<:`) in untrusted YAML documents.
- **Reachability in SentinelAI**: **NOT APPLICABLE WITH EVIDENCE**. SentinelAI Swagger schemas are pre-compiled and served statically. The backend provides no public API endpoint that ingests or parses untrusted user-supplied YAML payloads.
- **Fix Availability**: Fixed in `js-yaml@4.3.2`.
- **Disposition**: **NOT APPLICABLE WITH EVIDENCE**.

### VULN-004: `morgan` — Log Forging via Unescaped Delimiters
- **Advisory IDs**: GHSA-jxfw-x594-9x9m, GHSA-9f6g-j8ch-79g4
- **Severity**: **MODERATE (CVSS: 5.3)**
- **Installed Version**: `1.10.0` (Affected range: `<=1.12.0`)
- **Dependency Type**: Direct dependency (`"morgan": "^1.10.0"`)
- **Vulnerability Description**: Unescaped Unicode line separators and quotes in logged HTTP headers can allow log injection.
- **Reachability in SentinelAI**: **MITIGATED**. SentinelAI's primary security auditing pipeline is powered by Winston and custom log sanitizer `backend/utils/logPrivacy.js`, which strips control characters and Unicode line separators. Morgan is utilized solely for auxiliary console output.
- **Fix Availability**: Fixed in `morgan@1.12.1`.
- **Disposition**: **MITIGATED WITH EVIDENCE**.

### VULN-005: `qs` — Denial of Service via Bracket-Key Comma Parsing
- **Advisory IDs**: GHSA-x5fp-wj9c-mxmx, GHSA-4mjr-xmp4-gh2g
- **Severity**: **MODERATE (CVSS: 5.3)**
- **Installed Version**: `6.13.0` (Affected range: `>=2.2.5 <6.16.0`)
- **Dependency Type**: Transitive via `body-parser` and `express@4.18.2`
- **Vulnerability Description**: Parsing crafted query strings with bracketed keys can trigger high CPU utilization or bypass array parsing limits.
- **Reachability in SentinelAI**: **MITIGATED**. SentinelAI request bodies are capped at 100KB, and query parameters are strictly normalized and bounded via `querySecurity.js` (`parsePagination`, `escapeRegex`).
- **Fix Availability**: Fixed in `qs@6.16.0`. Resolving in Express requires Express v5.
- **Disposition**: **MITIGATED WITH EVIDENCE**.

### VULN-006: `uuid` — Missing Buffer Bounds Check in v3/v5/v6
- **Advisory ID**: GHSA-w5hq-g745-h8pq
- **Severity**: **MODERATE (CVSS: 7.5)**
- **Installed Version**: `9.0.1` (Affected range: `<11.1.1`)
- **Dependency Type**: Direct dependency (`"uuid": "^9.0.0"`)
- **Vulnerability Description**: Missing buffer bounds check when invoking `uuid.v3()`, `uuid.v5()`, or `uuid.v6()` with a custom user-supplied buffer argument.
- **Reachability in SentinelAI**: **NOT APPLICABLE WITH EVIDENCE**. SentinelAI calls `uuid.v4()` exclusively throughout the entire codebase for generating cryptographically random UUIDs (`crypto.randomUUID()` / `uuidv4()`). Custom buffer-based v3, v5, or v6 functions are never called.
- **Fix Availability**: Fixed in `uuid@11.1.1`.
- **Disposition**: **NOT APPLICABLE WITH EVIDENCE**.

---

## 3. Express v5 Migration Roadmap & Release Blocker

The core transitive vulnerabilities (`proxy-addr`, `qs`) cannot be cleanly upgraded without either using risky package manager overrides or upgrading Express from v4 to v5.

### Migration Scope:
1. **Routing Path Syntax**: Express v5 uses `path-to-regexp@0.1.12`, removing legacy wildcard string patterns.
2. **Rejected Promises**: Express v5 automatically forwards unhandled promise rejections to the error handler. Existing error-handling wrappers must be audited.
3. **Query Parser Configuration**: Default query parser switches from `extended` to `simple`. `app.set('query parser', 'simple')` must be explicitly verified.

### Operational Release Gate:
> [!IMPORTANT]
> **Production Deployment Release Blocker**:  
> Prior to exposing SentinelAI to public, untrusted networks, the Express v5 migration and direct package bumps (`morgan@1.12.1`, `uuid@11.1.1`) must be completed and validated through end-to-end regression testing. For local development and internal test environments, the documented mitigations are sufficient.
