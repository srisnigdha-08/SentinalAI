# Docker recovery and deployment preflight blocker report

**Captured:** 15 October 2026, 11:35–11:37 Asia/Calcutta  
**Result:** **BLOCKED.** No Docker deployment, installation, storage migration, image operation, or service startup was attempted.

## Findings

### Docker installation and daemon

No `docker`, `docker-compose`, or Docker Desktop executable was found on `PATH` or at the inspected standard installation paths. `Get-Command docker` and `Get-Command docker-compose` returned no command. `where.exe docker` returned exit code **1** with “Could not find files for the given pattern(s).” The Docker CLI and standalone Compose version commands therefore could not run; they have no process exit code because no executable was launched. Docker Desktop's standard executable locations were absent, no Docker service or Docker-named process was listed, and the `dockerDesktopLinuxEngine` and `docker_engine` named pipes were absent.

The inspected uninstall registry locations contained no Docker entry. A read-only all-users AppX query returned **Access is denied**, so Store package registration could not be established. These results establish that Docker is not available for use from this session at the inspected locations; they do not prove that no nonstandard or per-user installation exists anywhere on the machine.

Because the CLI is absent, `docker version`, `docker info`, and `docker context ls` were not executed against a daemon. There is no verified daemon or Compose version. The only saved context metadata is named `desktop-linux` and points to `npipe:////./pipe/dockerDesktopLinuxEngine`; that stale metadata does not establish a working context or daemon.

### Docker and WSL configuration

The Docker Desktop settings file still records `SettingsVersion` **46** and `CustomWslDistroDir` **`D:\DockerDesktopData\DockerDesktopWSL`**. That location is explicitly protected and cannot be used as the destination for fresh Docker data. The per-user Docker `config.json` was absent. Context metadata was found at `C:\Users\srisn\.docker\contexts\meta\fe9c6bd7a66301f49ca9b6a70b217107cd1284598bfc254700c989b916da791e\meta.json`; its endpoint is the local Docker Desktop named pipe above.

The read-only WSL commands reported WSL **2.7.11.0**, kernel **6.18.33.2-2**, default distribution **Ubuntu**, default version **2**, and Ubuntu **Stopped**. `wsl.exe --version`, `--status`, and `--list --verbose` each returned exit code **0** in the corrected prior capture and the current read-only capture. No distribution was started or modified. The WSL1 unsupported message is informational for this WSL2 setup. An unelevated optional-Windows-feature query required elevation; no feature state is claimed from that failed query.

### Storage destination

The current storage inventory reports one physical disk: disk **0**, `NVMe Micron 2450 NVMe 512GB`, 512,110,190,592 bytes. Partition metadata maps both C: and D: to that same disk. C: has **3,526,713,344 bytes (3.28 GiB)** free. D: has **20,665,565,184 bytes (19.25 GiB)** free and is labeled `New Volume`.

There is no verified independent local Docker destination. D: is not independent storage: it is a partition on the same physical disk as C:, and the retained Docker setting points inside the protected `D:\DockerDesktopData\DockerDesktopWSL` tree. C: is also on that disk and has less free space than the previously documented planning allowance of at least 10 GiB of headroom. No other physical disk or verified remote Docker host was found in this inspection. The prior 30–40 GiB storage allowance is a planning estimate, not a measured image-size requirement.

### Recorded wildcard listeners

At **11:35:46**, read-only socket/process metadata found:

| Bind | PID | Process and executable | Windows owner | Observation |
| --- | ---: | --- | --- | --- |
| `0.0.0.0:5000` | 18040 | `node.exe`, `C:\Program Files\nodejs\node.exe` | `SNIGDHA\srisn` | Recorded earlier as appearing backend-related; arguments were not collected. |
| `0.0.0.0:8000` | 19660 | `python.exe`, `C:\Users\srisn\AppData\Local\Programs\Python\Python311\python.exe` | `SNIGDHA\srisn` | Recorded earlier as appearing AI-related; arguments were not collected. |

At **11:37:09**, a later read-only check found neither wildcard listener nor either PID. They had ended between observations; no stop, restart, connection, or reconfiguration was performed. The earlier task evidence intentionally omitted full command lines and environment values to avoid exposing credentials, so the exact parent command and the services' data destinations remain unknown. The two processes ran under the current Windows account, but this does not establish who owns or authorized their application data.

## Established blocker and uncertainties

The deployment gate remains blocked for two independently sufficient reasons: there is no usable Docker CLI/Desktop/verified daemon in this session, and the only observed Docker data setting points to protected storage while the host has no separate physical data destination. Available D: free space is not evidence of safety or independence.

Unresolved items are whether Docker is installed in an uninspected nonstandard or Store location, whether any remote Docker host exists, whether the prior listener processes were authorized and which database or files they used, and the actual image/data capacity needed by a future deployment. No listener was contacted to investigate its data.

## Minimum safe owner action

Provide a verified independent Docker host or a dedicated storage destination on a separate physical device that is outside every protected path and has capacity reviewed against a concrete deployment estimate. Confirm that the protected D: Docker data path will remain untouched. Then authorize a separate installation/storage plan for review before any Docker installation, configuration, build, pull, or startup. If no such destination is available, leave Docker postponed; do not redirect Docker to D: or assume the current free space is safe.

## Evidence

The report is based on the earlier corrected preflight and the new read-only captures below. The earlier acceptance report and source evidence were not rewritten.

- [Previous Docker acceptance report](DOCKER_ACCEPTANCE_REPORT_20261015.md)
- [Previous corrected preflight](../.test-runtime/docker-completion-20261015-6c831d9a/preflight-corrected.json)
- [Previous listener metadata](../.test-runtime/docker-completion-20261015-6c831d9a/unowned-listeners.json)
- [New install and daemon discovery](../.test-runtime/docker-completion-20261015-6c831d9a/blocker-preflight-20261015-113410/install-discovery-readonly.json)
- [New Docker settings, storage and listener capture](../.test-runtime/docker-completion-20261015-6c831d9a/blocker-preflight-20261015-113410/elevated-readonly-metadata.json)
- [New partition and listener PID metadata](../.test-runtime/docker-completion-20261015-6c831d9a/blocker-preflight-20261015-113410/partition-and-listener-metadata.json)
- [Final listener recheck](../.test-runtime/docker-completion-20261015-6c831d9a/blocker-preflight-20261015-113410/listener-state-final.json)
- [WSL version](../.test-runtime/docker-completion-20261015-6c831d9a/blocker-preflight-20261015-113410/fresh-wsl-version.json), [status](../.test-runtime/docker-completion-20261015-6c831d9a/blocker-preflight-20261015-113410/fresh-wsl-status.json), and [distribution list](../.test-runtime/docker-completion-20261015-6c831d9a/blocker-preflight-20261015-113410/fresh-wsl-list-verbose.json)

The preflight command also reported that this project directory has no `.git` directory; `git status --short --branch` exited **128** (“not a git repository”). No repository history or worktree status was inferred from the file tree.

## Recommended next action

Keep Docker postponed and continue SentinelAI work using the preserved source changes and existing task evidence. Before any later Docker work, have the owner identify an independent storage host or physical device and review its exact path and capacity. The protected backups, disks, WSL distribution, recovery images, and prior application acceptance data remain outside this investigation.
