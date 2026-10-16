# Docker Deletion Safety Audit — 15 October 2026

**Document:** `docs/DOCKER_DELETION_SAFETY_AUDIT_20261015.md`  
**Date:** 15 October 2026  
**Auditor:** Antigravity (Independent Read-Only Safety Audit)  
**Project Root:** `C:\Users\srisn\Desktop\Projects\sentinelai-complete`  
**Audit Scope:** Verification of all identified Docker-related files, directories, virtual disks, configurations, recovery tooling, and application binaries across drives `C:` and `D:` following the strategic decision to discontinue Docker and standardize on native Windows execution.

---

## 1. Executive Verdict

### **PARTIALLY APPROVED**

Selective deletion of designated non-critical caches, tooling installers, disposable preflight test overlays, and redundant empty directories is **APPROVED**. However, **blanket deletion of all remaining Docker-related files is STRICTLY NOT APPROVED**.

### Key Findings Summary:
1. **Critical Virtual Disks Contain Unextracted Application/Database Data:**  
   The primary working copy (`D:\DockerInspection\A3\docker_data_A3_working.vhdx`) and previous backups (`D:\DockerBackup\`) contain historical Docker volume contents, specifically two MongoDB candidate datasets (`deployment_mongo_data` and `deepguard-platform_mongo_data`, comprising ~645 MiB of unextracted database records).  
   Crucially, `D:\MongoPreservation\` contains **only empty directories and an execution log** because the automated guest extraction phase was aborted prior to completion due to Docker Desktop daemon restarts. **No database data exists in native format outside these virtual disks.** Deleting all VHDX files would result in permanent data loss of historical application databases.
2. **Native SentinelAI Execution is Completely Decoupled from Docker:**  
   SentinelAI's native Windows execution (Node.js backend, React/Vite frontend, Python FastAPI AI engine, and native MongoDB instance) does not rely on any Docker executable, Dockerfile, docker-compose file, or Docker container service. The project codebase contains zero active Docker runtime files.
3. **Severe Local Storage Exhaustion on `C:` Demands Measured Reclaim:**  
   Drive `C:` currently has only **938.59 MB (0.92 GiB)** free space remaining, representing an immediate operational stability risk for Windows. Drive `D:` has **19.25 GB** free. Safely deleting verified disposable caches, QEMU/SystemRescue tooling, and stale temporary installers will immediately liberate **~6.22 GiB on `C:`** and **~0.2 MiB on `D:`** without risking any application data.
4. **Isolated Portable MongoDB Acceptance Instance Exists Independently:**  
   A dedicated native MongoDB 7.0.45 portable instance exists at `C:\Users\srisn\Desktop\Projects\sentinelai-complete.native-integration\mongodb-acceptance-20261014` (1,007.95 MiB, 529 files). It hosts the `sentinelai_acceptance_20261014` database and has zero dependencies on Docker or WSL.

---

## 2. Complete Inventory of Candidates and Classifications

Each identified candidate has been inspected using strictly read-only filesystem commands and classified according to the audit criteria:
- **A. SAFE TO DELETE:** Disposable, exclusively Docker/tooling-related, zero impact on native SentinelAI, no unique data.
- **B. SAFE TO UNINSTALL:** Installed software with known removal procedure.
- **C. REDUNDANT COPY — VERIFY BEFORE DELETION:** Another copy exists, but verification is required prior to removal.
- **D. PRESERVE — CONTAINS OR MAY CONTAIN VALUABLE DATA:** Contains historical databases, original backups, or essential recovery state.
- **E. UNKNOWN — NOT SAFE TO DELETE YET:** Ownership or relationship cannot be verified with certainty without further offline review.
- **F. NOT DOCKER-RELATED OR REQUIRED BY NATIVE DEVELOPMENT:** Required by native SentinelAI or other system applications.

### Comprehensive Candidate Table

| ID | Exact Path | Type | Measured Size | Purpose / Description | Primary Classification | Evidence Source |
|:---|:---|:---|:---:|:---|:---:|:---|
| **C-01** | `C:\Users\srisn\AppData\Local\Programs\DockerDesktop` | Directory (App) | 3,279.72 MiB (3.20 GiB) | Installed Docker Desktop application binaries, Electron UI, CLI plugins, and tmp installers. | **B. SAFE TO UNINSTALL** | Process inspection; FileVersion & PE header checks; no uninstaller registry entry found. |
| **C-02** | `C:\Users\srisn\AppData\Local\Docker` | Directory (User Data) | 33.10 MiB (0.03 GiB) | Docker Desktop installation logs (`install-log.txt`), CLI logs, lock files, and WSL daemon state. | **A. SAFE TO DELETE** | Directory inspection; confirmed pure text logs and runtime locks. |
| **C-03** | `C:\Users\srisn\AppData\Roaming\Docker` | Directory (Config) | 0.64 MiB (0.001 GiB) | Docker Desktop user configuration (`settings-store.json`, `features-overrides.json`, analytics). | **A. SAFE TO DELETE** | Inspected JSON files; points to protected paths (`CustomWslDistroDir`); no app data. |
| **C-04** | `C:\Users\srisn\.docker` | Directory (CLI Config) | 0.04 MiB (0.000 GiB) | Docker CLI configuration (`contexts/meta`, `daemon.json`, `buildx` tokens). | **A. SAFE TO DELETE** | Stale context metadata; references inactive named pipes. |
| **C-05** | `C:\ProgramData\DockerDesktop` | Directory (Admin Logs) | 0.02 MiB (0.000 GiB) | System-wide admin install logs (`install-log-admin.txt`). | **A. SAFE TO DELETE** | Text logs only. |
| **C-06** | `C:\RecoveryTools\overlay.qcow2` | File (Virtual Disk) | 0.20 MiB (212,992 B) | Disposable QEMU QCOW2 overlay used during read-only inspection. Backed by `docker_data_A3_working.vhdx`. | **A. SAFE TO DELETE** | `qemu-img info` confirms empty/transient overlay state (208 KiB allocated). |
| **C-07** | `C:\RecoveryTools\test_dummy\` | Directory (Test Data) | 8.38 MiB (8,781,824 B) | Disposable test files (`dummy_backing.vhdx`, `dummy_overlay.qcow2`) used in write-confinement preflight. | **A. SAFE TO DELETE** | Verified dummy synthetic test fixtures. |
| **C-08** | `C:\RecoveryTools\staging\` | Directory (Staging) | 0 B (0 files) | Staging directory configured to receive extracted MongoDB tarballs. Currently completely empty. | **A. SAFE TO DELETE** | Verified 0 items present; extraction halted before data transfer. |
| **C-09** | `C:\RecoveryTools\qemu-w64-setup-20260811.exe` | File (Installer) | 197.04 MiB (206,615,928 B) | Official QEMU installer archive downloaded for offline portable extraction. | **A. SAFE TO DELETE** | Downloaded portable artifact; not integrated into OS. |
| **C-10** | `C:\RecoveryTools\systemrescue-13.02-amd64.iso` | File (ISO Image) | 1,317.62 MiB (1.29 GiB) | SystemRescue Live CD image used as QEMU recovery kernel/initrd guest environment. | **A. SAFE TO DELETE** | Disposable upstream ISO; can be re-downloaded if ever needed. |
| **C-11** | `C:\RecoveryTools\sysrescue_boot\` | Directory (Kernel/Initrd) | 189.92 MiB (199,591,542 B) | Extracted vmlinuz and sysresccd.img kernel/initrd files. | **A. SAFE TO DELETE** | Extracted from C-10. Disposable. |
| **C-12** | `C:\RecoveryTools\qemu\` | Directory (Binaries) | 1,215.12 MiB (1.19 GiB) | Portably extracted QEMU 11.1.0 emulator binaries and shared libraries. | **A. SAFE TO DELETE** | Portable extraction. Zero native SentinelAI dependencies. |
| **C-13** | `C:\RecoveryTools\7zip\` & `7zip-full\` | Directories | 5.21 MiB (5,463,680 B) | Portable 7-Zip standalone extractors. | **A. SAFE TO DELETE** | Standalone tooling. |
| **C-14** | `C:\RecoveryTools\innoextract\` & archives | Files / Dirs | 74.08 MiB (77,678,080 B) | Innoextract and MSYS2 Zstandard packages downloaded during tooling evaluation. | **A. SAFE TO DELETE** | Intermediate tooling artifacts. |
| **C-15** | `C:\RecoveryTools\*.ps1` & `inventory_b64.txt` | Files (Scripts) | 0.05 MiB (56,962 B) | Forensic inspection and preservation orchestration scripts (`run_mongo_preservation.ps1`, etc.). | **D. PRESERVE** | Contains forensic provenance, QEMU boot recipes, and execution logs. |
| **D-01** | `D:\DockerInspection\A3\docker_data_A3_working.vhdx` | File (VHDX Disk) | 33,918.56 MiB (33.124 GiB) | **Working Copy VHDX.** Confirmed baseline SHA-256 `660D98A9...`. Contains ext4 volume with 2 unextracted MongoDB candidates (~645 MiB). | **D. PRESERVE — CONTAINS VALUABLE DATA** | Read-only inventory proved 204 database files (182 primary, 22 secondary) residing inside. |
| **D-02** | `D:\DockerDesktopData\DockerDesktopWSL\disk\docker_data.vhdx` | File (VHDX Disk) | 33,918.56 MiB (33.124 GiB) | Original Docker Desktop WSL ext4 virtual disk image before recovery isolation. | **D. PRESERVE — CONTAINS VALUABLE DATA** | Original source disk; matches baseline size (35,566,649,344 B). |
| **D-03** | `D:\DockerBackup\docker_data_pre_recovery_2026-10-13.vhdx` | File (VHDX Disk) | 33,918.56 MiB (33.124 GiB) | Forensic pre-recovery snapshot created on 2026-10-13 19:11:56 before running any recovery scripts. | **D. PRESERVE — CONTAINS VALUABLE DATA** | Primary immutable forensic fallback backup. |
| **D-04** | `D:\DockerBackup\docker_data.vhdx` | File (VHDX Disk) | 33,188.99 MiB (32.411 GiB) | Earlier historical backup from 07-10-2026 11:18:13. | **D. PRESERVE — CONTAINS VALUABLE DATA** | Historical snapshot before volume expansions. |
| **D-05** | `D:\DockerBackup\docker_data_fresh.vhdx` | File (VHDX Disk) | 33,188.99 MiB (32.411 GiB) | Historical backup from 10-10-2026 20:07:55. | **C. REDUNDANT COPY — VERIFY BEFORE DELETION** | Identical timestamp and byte size to `docker_data_restore.vhdx`. Needs hash comparison. |
| **D-06** | `D:\DockerBackup\docker_data_restore.vhdx` | File (VHDX Disk) | 33,188.99 MiB (32.411 GiB) | Historical backup from 10-10-2026 20:07:55. | **C. REDUNDANT COPY — VERIFY BEFORE DELETION** | Identical timestamp and byte size to `docker_data_fresh.vhdx`. Needs hash comparison. |
| **D-07** | `D:\DockerBackup\docker_data_new_install.vhdx` | File (VHDX Disk) | 1,568.99 MiB (1.532 GiB) | Minimal disk image from 12-10-2026 10:22:54 corresponding to a fresh/empty Docker installation. | **A. SAFE TO DELETE** | Small initial baseline containing no application volume data. |
| **D-08** | `D:\MongoPreservation\` | Directory (Preservation) | 0.001 MiB (1,116 B) | Directory created to receive extracted MongoDB files. Contains 0 database files, only `copy_log.txt`. | **A. SAFE TO DELETE** (or re-use) | Read-only scan confirmed `deployment_mongo_data` (0 items) and `deepguard-platform_mongo_data` (0 items). |
| **P-01** | `sentinelai-complete\docs\DOCKER_*.md` | Files (Documentation) | 0.03 MiB (32,042 B) | Historical reports: `DOCKER_ACCEPTANCE_REPORT_20261015.md`, `DOCKER_PREFLIGHT_BLOCKER_REPORT_20261015.md`, etc. | **F. NOT DOCKER-RELATED (PROJECT DOCS)** | Historical documentation and architectural records; part of repository audit history. |
| **P-02** | `sentinelai-complete\.test-runtime\docker-completion-*` | Directory (Evidence) | 1.85 MiB (1,940,000 B) | Test logs, completion ledger, and verification hashes from Docker preflight testing. | **F. NOT DOCKER-RELATED (TEST EVIDENCE)** | Required project audit trail proving why Docker acceptance was blocked. |
| **P-03** | `sentinelai-complete\deployment\.env*` | Files (Configuration) | 0.002 MiB (2,310 B) | Deployment environment configuration files (`.env`, `.env.example`, `.env.production`). | **D. PRESERVE / REVIEW** | Contains configuration variables and potential deployment secrets; do not delete without review. |
| **S-01** | `sentinelai-complete.native-integration\` | Sibling Directory | 1,007.95 MiB (0.984 GiB) | Native portable MongoDB 7.0.45 instance and `sentinelai_acceptance_20261014` data directory. | **D. PRESERVE (NATIVE DEV DATABASE)** | Verified active native acceptance database. Completely independent of Docker. |

---

## 3. Impact Analysis on SentinelAI and the Host System

### 1. SentinelAI Source Code and Native Execution
- **Zero Impact:** Exhaustive inspection of `backend/package.json`, `frontend/package.json`, `ai-engine/requirements.txt`, and source directories confirms **no Docker dependencies exist in SentinelAI's runtime**.
- Native startup commands documented in `docs/NATIVE_DEVELOPMENT.md` run directly on Windows:
  - Backend: `node server.js` (Express + Socket.IO on port 5000)
  - Frontend: `npm run dev -- --host 127.0.0.1` (Vite on port 3000)
  - AI Engine: `uvicorn inference.main:app --port 8000` (FastAPI + Python 3.11 in `ai-engine/.venv`)
- The project root contains **no Dockerfile and no docker-compose.yml**.

### 2. Backend, Frontend, and Python AI-Engine Functionality
- **Zero Impact:** All regression tests (364 backend tests, 125 Python AI tests, 26 frontend tests) execute natively against local host processes and pass with exit code 0.
- Offline component rendering and production builds (`vite build`) output 951 bundled modules independently of any container runtime.

### 3. MongoDB Databases and Previously Stored Application Data
- **High Risk if VHDX files are deleted:**  
  The native test runner currently points to the isolated portable MongoDB instance (`sentinelai_acceptance_20261014` at `C:\Users\srisn\Desktop\Projects\sentinelai-complete.native-integration\mongodb-acceptance-20261014`). That database is safe.  
  However, **all historical Docker-era application data** (e.g., previous threat logs, user sessions, network alerts stored in `deployment_mongo_data` and `deepguard-platform_mongo_data`) **remains exclusively locked inside the 33.12 GiB ext4 partitions of the VHDX disks** (`docker_data_A3_working.vhdx` and `docker_data_pre_recovery_2026-10-13.vhdx`).
- Deleting the VHDX files before performing an extraction permanently destroys all pre-October 14 application database history.

### 4. Trained Models, Datasets, Learning State, and Configuration
- **Zero Impact:** Models are preserved entirely in native directories:
  - `ai-engine/models/` and root `models/` (Random Forest, Isolation Forest, Scaler joblibs).
  - Runtime learning state: `ai-engine/runtime/q_table.json`.
  - Scored historical evaluation datasets: `ai-engine/datasets/`.
  - None of these assets are stored in Docker volumes or virtual disks.

### 5. Historical Project Data, Backups, Recovery Capability, and Test Evidence
- Deleting test evidence under `.test-runtime/` or documentation under `docs/` would break project compliance, ledger provenance, and auditability.
- Deleting the recovery orchestration scripts (`C:\RecoveryTools\run_mongo_preservation.ps1`) would discard the tested QEMU serial socket streaming mechanism needed to safely recover the MongoDB candidates.

### 6. Other Applications, Windows, WSL, and Development Tools
- **WSL Ubuntu Distribution:** Registered at `C:\Users\srisn\AppData\Local\wsl\{090c359e-a4ab-439e-be30-4bc80483e13a}`. It is a completely separate distribution from Docker Desktop's engine. Removing Docker Desktop files does **not** harm or deregister the user's `Ubuntu` WSL distribution.
- **Windows Services & Tasks:** No active Windows Service (`com.docker.service`) or Scheduled Task is currently registered.

---

## 4. Reclaimable Storage Analysis

Storage measurements were performed using PowerShell `Measure-Object -Property Length -Sum` across all physical and virtual paths:

```
Physical Disk 0: NVMe Micron 2450 512GB (Shared by C: and D:)
  Drive C: (OS)         Size: 201.95 GiB | Free:  938.59 MiB (CRITICAL STORAGE PRESSURE: < 1 GiB)
  Drive D: (New Volume) Size: 250.00 GiB | Free:   19.25 GiB
```

### Storage Breakdown by Classification

| Category | Location | Items / Breakdown | Measured Reclaimable Storage |
|:---|:---|:---|:---:|
| **Immediate Safe Deletion (Tooling & Caches)** | `C:\RecoveryTools\` | QEMU binaries, SystemRescue ISO, Innoextract, 7-Zip, dummy files | **3.01 GiB** (3,155,750,316 B) |
| **Immediate Safe Deletion (Docker App Data)** | `C:\Users\srisn\AppData\Local\Docker` + `Roaming` + `.docker` | Text logs, CLI caches, telemetry logs, lock files | **0.034 GiB** (35,422,072 B) |
| **Immediate Safe Deletion (Empty Staging/D)** | `D:\MongoPreservation\` + `C:\RecoveryTools\staging\` | Empty directories and log | **0.000 GiB** (1,116 B) |
| **Safe Deletion (Uninstall Docker Desktop)** | `C:\Users\srisn\AppData\Local\Programs\DockerDesktop` | Electron binaries, CLI plugins, temporary update installers | **3.20 GiB** (3,439,038,955 B) |
| **Subtotal Reclaimable on Drive C:** | **Drive C: Total** | Resolves critical disk exhaustion | **~6.24 GiB** |
| | | | |
| **Safe Deletion on Drive D: (Empty Install VHDX)** | `D:\DockerBackup\docker_data_new_install.vhdx` | Clean, empty 1.5 GiB initial VHDX from 12-10-2026 | **1.53 GiB** (1,645,215,744 B) |
| **Conditional Reclaim on Drive D: (Redundant Backups)** | `D:\DockerBackup\docker_data_fresh.vhdx` (or `restore`) | Subject to pre-deletion SHA-256 deduplication check | **32.41 GiB** (34,801,188,864 B) |
| **Subtotal Reclaimable on Drive D:** | **Drive D: Total** | (Pending deduplication check) | **33.94 GiB** |
| | | | |
| **STRICTLY PROTECTED (Historical VHDX Disks)** | `D:\DockerInspection\`, `D:\DockerBackup\`, `D:\DockerDesktopData\` | 4 distinct VHDX images containing MongoDB candidates | **132.50 GiB** (Protected) |

---

## 5. Explicit Deletion Recommendations

### A. CONFIRMED SAFE TO DELETE IMMEDIATELY (Zero Risk)
These files and directories have zero dependencies, contain no unique data, and can be removed at once to alleviate drive `C:` storage exhaustion:

1. `C:\RecoveryTools\overlay.qcow2` (0.2 MiB)
2. `C:\RecoveryTools\test_dummy\` (8.38 MiB)
3. `C:\RecoveryTools\staging\` (0 B)
4. `C:\RecoveryTools\systemrescue-13.02-amd64.iso` (1.29 GiB)
5. `C:\RecoveryTools\sysrescue_boot\` (189.92 MiB)
6. `C:\RecoveryTools\qemu-w64-setup-20260811.exe` (197.04 MiB)
7. `C:\RecoveryTools\qemu\` (1.19 GiB)
8. `C:\RecoveryTools\7zip\` & `C:\RecoveryTools\7zip-full\` (5.21 MiB)
9. `C:\RecoveryTools\innoextract\` & downloaded `.pkg.tar.zst` archives (74.08 MiB)
10. `C:\Users\srisn\AppData\Local\Docker\` (33.1 MiB)
11. `C:\Users\srisn\AppData\Roaming\Docker\` (0.64 MiB)
12. `C:\Users\srisn\.docker\` (0.04 MiB)
13. `C:\ProgramData\DockerDesktop\` (0.02 MiB)
14. `D:\DockerBackup\docker_data_new_install.vhdx` (1.53 GiB — empty fresh install disk)
15. `D:\MongoPreservation\` (0.001 MiB — empty destination folders)

### B. CONFIRMED SAFE TO REMOVE / UNINSTALL (Application Component)
1. `C:\Users\srisn\AppData\Local\Programs\DockerDesktop\` (3.20 GiB)
   - *Removal Note:* No standard Windows uninstall registry key was detected. The application directory can be removed or cleanly uninstalled via its executable launcher `C:\Users\srisn\AppData\Local\Programs\DockerDesktop\Docker desktop.exe --uninstall` (or folder deletion once processes are terminated).

### C. REDUNDANT COPIES — VERIFY HASH BEFORE DELETION
1. `D:\DockerBackup\docker_data_fresh.vhdx` (32.41 GiB)
2. `D:\DockerBackup\docker_data_restore.vhdx` (32.41 GiB)
   - *Verification Requirement:* Both files have identical lengths (34,801,188,864 bytes) and timestamps (`10-10-2026 20:07:55`). Run a SHA-256 hash check. If identical, delete one and retain the other, reclaiming **32.41 GiB** on `D:`.

### D. STRICTLY PROTECTED — MUST NOT BE DELETED
Do **NOT** delete these artifacts until an explicit decision is made that historical Docker-era MongoDB data is no longer needed:

1. `D:\DockerInspection\A3\docker_data_A3_working.vhdx` (33.12 GiB)
   - Baseline hash: `660D98A97461FE44D4B23C72D151F80985BA53010DDA67F03D2C887B82A269CC`.
   - Houses the ext4 filesystem containing the 182-file primary and 22-file secondary MongoDB datasets.
2. `D:\DockerBackup\docker_data_pre_recovery_2026-10-13.vhdx` (33.12 GiB)
   - Immutable forensic master backup of the working copy.
3. `D:\DockerBackup\docker_data.vhdx` (32.41 GiB)
   - Historical backup from 07-10-2026.
4. `D:\DockerDesktopData\DockerDesktopWSL\disk\docker_data.vhdx` (33.12 GiB)
   - Original Docker engine WSL disk.
5. `C:\RecoveryTools\run_mongo_preservation.ps1` & inspection scripts
   - Retains the exact automation logic required if database extraction is re-attempted.
6. `C:\Users\srisn\Desktop\Projects\sentinelai-complete.native-integration\` (1,007.95 MiB)
   - Active native development MongoDB 7.0.45 database instance (`sentinelai_acceptance_20261014`).
7. `docs\DOCKER_*.md` & `.test-runtime\docker-completion-*`
   - Project audit documentation and evidence logs.

---

## 6. Recommended Execution Order & Prerequisites

If the user approves selective deletion, execute strictly in this order:

### Phase 1: Immediate Drive `C:` Relief (~6.24 GiB reclaimed)
1. **Prerequisite:** Ensure no Docker or QEMU processes are running (`Get-Process -Name "*docker*","*qemu*"`).
2. Delete disposable recovery ISO, tools, and downloads under `C:\RecoveryTools\` (items C-06 through C-14).
3. Delete Docker configuration and log directories (`AppData\Local\Docker`, `AppData\Roaming\Docker`, `.docker`, `ProgramData\DockerDesktop`).
4. Remove `C:\Users\srisn\AppData\Local\Programs\DockerDesktop`.
5. *Result:* Drive `C:` free space increases from **~0.92 GiB to ~7.16 GiB**, instantly removing OS instability risks.

### Phase 2: Drive `D:` Deduplication (~33.94 GiB reclaimed)
1. Delete `D:\DockerBackup\docker_data_new_install.vhdx` (1.53 GiB).
2. Calculate SHA-256 for `D:\DockerBackup\docker_data_fresh.vhdx` and `docker_data_restore.vhdx`. If identical, delete `docker_data_restore.vhdx` (32.41 GiB).
3. Remove empty folder `D:\MongoPreservation\`.
4. *Result:* Drive `D:` free space increases from **~19.25 GiB to ~53.19 GiB**.

### Phase 3: Final Disposition of Historical Data (Owner Decision)
- **Option A (If historical MongoDB data is required):** Rerun `run_mongo_preservation.ps1` in an isolated pass (with Docker Desktop removed so it cannot restart) to extract the ~645 MiB of database files to `D:\MongoPreservation\`. Once verified against source manifests, all VHDX files on `D:` can be deleted (reclaiming an additional **~99 GiB**).
- **Option B (If historical MongoDB data is discarded):** If only the current native database (`sentinelai_acceptance_20261014`) is needed, the user can explicitly authorize deleting all four remaining VHDX files, immediately reclaiming **132.50 GiB** on `D:`.

---

## 7. Audit Limitations & Safeguards Observed
- All investigations were strictly read-only. No file, registry key, process, or disk volume was modified, deleted, mounted, repaired, or started during this audit.
- No Docker daemon or WSL distribution was executed.
- The user's `Ubuntu` WSL distribution remains completely intact and unaffected.
- The native portable MongoDB instance at `sentinelai-complete.native-integration` remains completely untouched.
