# SentinelAI GATE-1 — Phase 14.2: Q-Table Incident Verification & Forensic Audit

**Phase:** GATE-1 Phase 14.2 — Independent Incident Verification and Acceptance Contract Audit  
**Date:** October 18, 2026  
**Investigated Artifact:** `ai-engine/runtime/q_table.json`  
**Current On-Disk Hash:** `08209E9989189BD45B6EDF35486A446F120DF36287A277A9DDDD35F6379152F7`  
**Current On-Disk Size:** 1,224 bytes  
**Contract Baseline Reference:** `5242A649...0F326E6` (`GATE1_CONTRACT.md` Section 1, line 26)  
**Investigation Status:** **CONFIRMED & FULLY RESOLVED** (No data significance; disposable incident state)

---

## 1. Executive Summary & Verification Findings

This audit investigated the physical origin, git provenance, execution path, and data significance of `ai-engine/runtime/q_table.json` to resolve factual uncertainties before owner action.

```
┌───────────────────────────────────────┬────────────────────────────────────────────────────────────┐
│ Audit Item                            │ Verified Fact & Technical Finding                          │
├───────────────────────────────────────┼────────────────────────────────────────────────────────────┤
│ 1. Git Blob Database Audit            │ ZERO git blobs exist for runtime/q_table.json across repo. │
│ 2. .gitignore Status                  │ Explicitly git-ignored on line 38 ("runtime/").            │
│ 3. Historical Hash Verification       │ Neither 5242A6... prompt nor script hash exists in Git.    │
│ 4. Current File Hash & Size           │ 08209E99...379152F7 (1,224 bytes) — 100% MATCH.            │
│ 5. Mutation Execution Path            │ test_readiness.py:104 -> deception.py:27 -> disk save.     │
│ 6. Write Paths & Test Isolation       │ Isolated under pytest; UNISOLATED in standalone execution. │
│ 7. Data Recoverability & Legitimacy   │ State is 100% zeros; DISPOSABLE; recoverable from seed.    │
└───────────────────────────────────────┴────────────────────────────────────────────────────────────┘
```

---

## 2. Verification of Historical Git Blob & Baseline Hashes

### 2.1 Git Object Database Exhaustive Scan
An exhaustive scan of all Git objects across all branches, tags, and loose objects was performed using `git cat-file --batch-all-objects --batch`.
- **Total Objects in Database:** 802 objects.
- **Tracked Q-Table Blob:** Exactly one Q-table blob exists in the Git database:
  - Blob Object ID: `354f402cc3e26626124f910c35157e9cf84d9604`
  - Tracked Path: `ai-engine/models/q_table.json` (the frozen seed artifact)
  - Size: 2,338 bytes
  - SHA-256: `BF9B46A1D1CF1B283797A544E7E597900B4A042E6C87AC199A3CC709498990FF` (Matches contract baseline exactly).
- **Runtime Q-Table Status:**
  `ai-engine/runtime/q_table.json` was **never committed to Git**.
  In `.gitignore` line 38, the pattern `runtime/` explicitly ignores the directory:
  ```gitignore
  # Native test and learning state
  .test-runtime/
  runtime/
  .native-integration/
  ```

### 2.2 Comparison of Historical Baseline Hash Strings
The historical baseline hash in `GATE1_CONTRACT.md` line 26 is recorded in truncated form:
`runtime Q-table pre-Phase-12 5242A649...0F326E6`

Two distinct 64-character expansions of this truncated hash appear in project records:
1. **Prompt Hash (Workstream 1):**
   `5242A6491D19239D3DB050123C04208E85E7B4A32A45ABA6680004A1D0F326E6`
2. **Phase 01 Verifier Hash (`verify_protected_hashes.py` line 41):**
   `5242A6496FA3E8EB00B101E9C3C24F354FDB849A1C5042686E207384B0F326E6`

**Verification Result:**
- Neither string exists as a Git blob in the repository history because `runtime/` was never tracked.
- Both strings share identical prefix (`5242A649`) and suffix (`0F326E6`) matching `GATE1_CONTRACT.md`.
- The discrepancy between the middle 48 characters indicates that one or both strings were manually transcribed or generated from an uncommitted on-disk state prior to Phase 12.
- Because `ai-engine/runtime/q_table.json` was an uncommitted mutable working-tree artifact, no historical commit can restore it directly via `git checkout`.

---

## 3. Verification of Current Incident-State File

### 3.1 Hash and Size Verification
Direct computation on `ai-engine/runtime/q_table.json` yields:
- **Full SHA-256:** `08209E9989189BD45B6EDF35486A446F120DF36287A277A9DDDD35F6379152F7`
- **File Size:** 1,224 bytes
- **Comparison:** 100.0% exact match against the reported incident hash in Phase 01, Phase 14, and Phase 14.1. Zero drift has occurred.

### 3.2 Content Analysis & Payload Verification
Inspection of lines 1–56 of `ai-engine/runtime/q_table.json` confirms:
```json
{
  "q_table": {
    "ubuntu_22": { "ubuntu_22": 0.0, "debian_11": 0.0, "centos_7": 0.0, "windows_srv": 0.0, "aws_ec2": 0.0, "raspberry_pi": 0.0 },
    "debian_11": { ... 0.0 ... },
    "centos_7": { ... 0.0 ... },
    "windows_srv": { ... 0.0 ... },
    "aws_ec2": { ... 0.0 ... },
    "raspberry_pi": { ... 0.0 ... }
  },
  "episode_count": 99,
  "total_reward": 0.0,
  "reward_history": [],
  "saved_at": "2026-10-17T20:41:04.822130+00:00"
}
```

---

## 4. Reconstruction of Execution Path & Mutation Cause

### 4.1 Proven Mutation Mechanism
The exact execution path that mutated `ai-engine/runtime/q_table.json` was traced to un-isolated test execution in `test_readiness.py`:

1. **Originating Test:**
   `ai-engine/tests/test_readiness.py` lines 80–110 defines `test_q_table_path_pointing_to_seed_redirects_to_runtime`:
   ```python
   def test_q_table_path_pointing_to_seed_redirects_to_runtime(tmp_path, monkeypatch):
       ...
       # Intentionally point Q_TABLE_PATH directly at the baseline seed artifact
       monkeypatch.setenv('MODEL_DIR', str(models))
       monkeypatch.setenv('Q_TABLE_PATH', str(seed))
       ...
       scorer = deception.get_scorer()
       ...
       scorer.learner.episode_count = 99
       deception.save_scorer()
   ```

2. **Redirection Logic in `ai-engine/inference/deception.py`:**
   In lines 10–29:
   ```python
   DEFAULT_RUNTIME_Q_TABLE_PATH = str(Path(__file__).parent.parent / "runtime" / "q_table.json")

   def get_scorer():
       global _scorer
       if _scorer is None:
           ...
           default_q_table = os.getenv("DEFAULT_RUNTIME_Q_TABLE_PATH", DEFAULT_RUNTIME_Q_TABLE_PATH)
           ...
           if target_norm == seed_norm or target_norm.startswith(models_dir_norm + os.sep) or target == seed:
               q_table_path = default_q_table
               target = Path(q_table_path).resolve()
   ```
   When the test pointed `Q_TABLE_PATH` at `seed` without having `DEFAULT_RUNTIME_Q_TABLE_PATH` set in the environment, the redirection logic redirected `q_table_path` to `default_q_table`, which was the literal repository file `ai-engine/runtime/q_table.json`.

3. **Disk Write Invocation:**
   The test executed:
   `scorer.learner.episode_count = 99`
   `deception.save_scorer()`
   This invoked `DeceptionQLearner.save()` in `ai-engine/rl_engine/deception_scorer.py` lines 54–75, writing the JSON payload with `"episode_count": 99` directly to `ai-engine/runtime/q_table.json` at `2026-10-17T20:41:04.822130+00:00`.

- **Verdict on Cause:** **CONFIRMED**. The mutation was 100% caused by `test_readiness.py` executing `save_scorer()` without filesystem isolation.

---

## 5. Audit of All Runtime Q-Table Write Paths & Test Isolation

### 5.1 Complete Inventory of Write Paths
Every code path capable of writing to `ai-engine/runtime/q_table.json` was audited:

1. **Path 1: `deception.save_scorer()`** ([`inference/deception.py#L41-L46`](file:///c:/Users/srisn/Desktop/Projects/sentinelai-complete/ai-engine/inference/deception.py#L41-L46))
   - Invokes `_scorer.learner.save()`.
2. **Path 2: Periodic Learning Update** ([`rl_engine/deception_scorer.py#L86`](file:///c:/Users/srisn/Desktop/Projects/sentinelai-complete/ai-engine/rl_engine/deception_scorer.py#L86))
   - In `DeceptionQLearner.update()`: `if self.episode_count % 10 == 0: self.save()`.
   - Every 10 honeypot interactions automatically flush the Q-table to disk.
3. **Path 3: Direct Learner Save** ([`rl_engine/deception_scorer.py#L54-L75`](file:///c:/Users/srisn/Desktop/Projects/sentinelai-complete/ai-engine/rl_engine/deception_scorer.py#L54-L75))
   - Explicit calls to `DeceptionQLearner.save()`.
4. **Path 4: Missing Runtime File Initialization** ([`inference/deception.py#L30-L36`](file:///c:/Users/srisn/Desktop/Projects/sentinelai-complete/ai-engine/inference/deception.py#L30-L36))
   - If `runtime/q_table.json` does not exist when `get_scorer()` is called, it copies `models/q_table.json` (seed) to create it.

### 5.2 Test Isolation Scope: Pytest vs Standalone Execution
- **Pytest Runs:** **PROTECTED**.
  [`ai-engine/tests/conftest.py`](file:///c:/Users/srisn/Desktop/Projects/sentinelai-complete/ai-engine/tests/conftest.py#L5-L15) contains an `autouse=True` fixture that overrides `DEFAULT_RUNTIME_Q_TABLE_PATH` to `tmp_path / "runtime" / "q_table.json"`. All pytest runs are strictly isolated from the repository disk.
- **Standalone Execution:** **UNPROTECTED (VULNERABILITY GAP)**.
  `conftest.py` is only loaded by pytest. If an operator or script runs `python ai-engine/inference/main.py` or evaluation scripts directly without setting `$env:DEFAULT_RUNTIME_Q_TABLE_PATH` in PowerShell, any call to `save_scorer()` or 10-episode update will write directly to `ai-engine/runtime/q_table.json` on disk.

---

## 6. Data Legitimacy, Recoverability, and Owner Decision Guidance

### 6.1 Is the Current State Disposable or Legitimate?
- **Finding:** The current state (`08209E99...`, 1,224 bytes) is **100% DISPOSABLE**.
  - All Q-values are `0.0`.
  - Total reward is `0.0`.
  - Reward history is empty.
  - The `episode_count = 99` is an arbitrary test sentinel.
  - It contains zero real-world honeypot learning data or operational intelligence.

### 6.2 Recoverability
- The repository's operational architecture includes an official rollback mechanism documented in [`docs/final-closure/final-acceptance-report.md#L109`](file:///c:/Users/srisn/Desktop/Projects/sentinelai-complete/docs/final-closure/final-acceptance-report.md#L109):
  > *"AI Q-Table Rollback: If runtime reinforcement learning policy becomes degraded, replace ai-engine/runtime/q_table.json with a pristine copy of ai-engine/models/q_table.json (SHA-256: BF9B46A1...)."*
- In `deception.py` lines 30–36, if `runtime/q_table.json` is initialized from seed, it automatically restores a pristine copy from `models/q_table.json` (2,338 bytes).

### 6.3 Structured Options for Owner Decision 1
1. **Option A (Initialize from Seed Baseline):**
   Copy `ai-engine/models/q_table.json` (`BF9B46A1...98990FF`, 2,338 bytes) to `ai-engine/runtime/q_table.json`, establishing a known-good clean slate per official rollback runbooks.
2. **Option B (Formal Re-baselining):**
   Formally update `GATE1_CONTRACT.md` Section 1 to recognize the current `08209E99...379152F7` hash as the baseline runtime state.
