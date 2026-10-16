# Docker security and data safety handoff

Status: blocked before build/configuration. No images, containers, networks, volumes, Dockerfiles or Compose files were created. Read-only Windows, settings/context metadata and WSL status/list/version checks were performed. No daemon/distribution was started or reconfigured.

Protected recovery paths, original disks/backups, recovered MongoDB candidates, cache.db and the retained sentinelai_acceptance_20261014 database are excluded. Existing .env files, credentials, 46 manifested model/data/config assets and all historical test evidence remain unchanged. The owner's recovery disk hash was not independently re-read. A new selected-source backup and initial asset verification are in this task's baseline.json.

No existing Docker destination is safe: retained settings refer to D:\DockerDesktopData\DockerDesktopWSL. Do not install/start Desktop against that location. Owner action is a verified separate host or a reviewed reversible fresh installation/storage proposal outside protected resources. Never prune, reset, unregister distributions, reclaim personal space or move a disk to pass the storage gate.

Future build requirements: no .env/private keys/credentials/data/profile/evidence leakage in contexts or layers; secrets delivered outside images/build arguments/source; non-root application runtime; authenticated least-privilege new database; only newly named unused volumes; no recovered bind mounts. Readiness must prove actual internal credentials, not only unauthenticated process liveness.

Network requirements: same-origin HTTPS; preserve Secure/HttpOnly/Strict auth cookies and /api/auth nonce Path; exact trusted Origin and signed CSRF; narrow IP/CIDR proxy identity and stripped client-supplied forwarding headers; internal Mongo/AI/ingestion not publicly published. Local acceptance ports bind loopback. No public Cowrie or privileged packet capture. No real firewall/containment changes. Automatic containment remains disabled; BLOCK is a model decision.

Source roles do not prove enforcement state. The fixed role header now describes permissions. Public registration is disabled; only an active administrator can provision, with default viewer role. Existing accounts still require private administrator review; no automatic cleanup or role migration has occurred. Initial admin bootstrap needs a privately supplied password, not seed/demo scripts.

Known limitations remain tracked: pre-inference HIGH/0.75 session-open heuristic, missing multi-worker business-event adapter, Cowrie retry/deduplication/crash/migration limits, unavailable managed Cowrie, unverified production PKI/network/HA/load, representative model accuracy and external reputation credentials. No exactly-once processing, live telemetry, actual enforcement or production-readiness claim is made.

Persistent-resource policy: before creation, identify the exact engine storage, unique project/image/volume/database names, bind ports, least-privilege credentials, writes and retained evidence. Review ordinary restart and recovery tests. Only owned processes/containers may be stopped; test data remains until an explicit scoped deletion decision. Backup and restore documentation is not authorization to touch protected data.
