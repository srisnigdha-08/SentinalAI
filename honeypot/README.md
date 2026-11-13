# Optional real honeypot integration

See [native requirements and integration](../docs/NATIVE_DEVELOPMENT.md).
Cowrie, its JSON parser, packet sniffer, blocker plugin and profile switcher are
preserved. No honeypot, parser, sniffer or simulated feed starts automatically.

Run Cowrie on a separately managed Linux host. Its real JSON log is ingested with
`python parsers/log_parser.py --live --log <cowrie.json>`.

## Configuration

| Component | Variables | Default backend URL |
|---|---|---|
| `parsers/log_parser.py` (the ingest path) | `SENTINEL_API`, `HONEYPOT_API_KEY` (required; the backend refuses `SENTINEL_KEY` on honeypot routes), `COWRIE_LOG`, `COWRIE_CFG` (default `<cowrie>/etc/cowrie.cfg` next to the log: the persona served is read from the header `switch_profile.py` writes and sent with each session), `COWRIE_PERSONA` (overrides it), `SENTINEL_POST_RETRIES`, `SENTINEL_POST_BACKOFF`, `PARSER_STATE_DIR` (default `~/.sentinelai/cowrie-parser`: read offset, open sessions, delivery spool), `SENTINEL_SPOOL_MAX`, `SENTINEL_SPOOL_RETRY` | `http://localhost:5000/api` |
| `cowrie/sentinelblocker.py` (Cowrie output plugin `[output_sentinelblocker]`, enabled in `cowrie.cfg`; install as `src/cowrie/output/sentinelblocker.py`: Cowrie takes the module name from the section up to the next underscore, so the name must not contain one) | `SENTINEL_API_URL`, `HONEYPOT_API_KEY` | `http://localhost:5000/api` |
| `switch_profile.py` (writes `cowrie/cowrie.cfg`) | `COWRIE_PERSONA_FS` (directory of persona pickles and txtcmds, e.g. `personas`), `COWRIE_LISTEN_ADDR` (default `0.0.0.0` for containers; `127.0.0.1` for a local test install), `COWRIE_SENSOR_NAME` (default `sentinel-hp-01`). Always refuses `windows_srv` (unsupported: Cowrie emulates a Linux shell; see docs/PERSONAS.md) | n/a |
| `deception_rotator.py` | `HONEYPOT_API_KEY`, `SENTINEL_BACKEND_URL`, `COWRIE_RESTART_CMD`. Waits while attacker sessions are open (`--force` overrides) and skips unservable personas | `http://127.0.0.1:5000` |
| `sniffer/sniffer.py` (dataset builder: labels captured flows into `flows.csv`) | `SENTINEL_API`, `HONEYPOT_API_KEY` | `http://localhost:5000/api` |

The parser resumes from its saved offset after a restart, finishes a rotated log before following the new
one, and queues deliveries on disk while the backend is unreachable. It never keeps or sends passwords (only
usernames and the outcome; the backend stores every password as `***REDACTED***` anyway). `cowrie.json` itself
still holds them in plain text: keep Cowrie's `var/` private (mode 700) and prune it with `retention.sh`. With no saved state, the first
start reads from the end of the log; pass `--from-start` to ingest the existing file.

`docker-compose.honeypot.yml` runs Cowrie and the parser in hardened containers on their own bridge;
`docker/egress-rules.sh` must then restrict that bridge to the SentinelAI ingest port. Both are untested
(written without Docker). `build_honeyfs.py --fs-pickle <cowrie>/src/cowrie/data/fs.pickle --out personas`
builds one fake filesystem per persona (no `phil` user, matching os-release/issue/hostname/kernel); set
`COWRIE_PERSONA_FS=personas` before `switch_profile.py` to use them (`--source <honeyfs>` and
`COWRIE_PERSONA_HONEYFS` for older Cowrie releases with a separate honeyfs directory).

`deception_rotator.py` authenticates with `HONEYPOT_API_KEY` on `/api/honeypot/ingest/deception/*`; it no
longer needs an admin login on the honeypot host.

Give the honeypot host only `HONEYPOT_API_KEY`, never the AI engine's `SENTINEL_KEY`.

Backend settings for the honeypot (all optional):

| Variable | Effect |
|---|---|
| `HONEYPOT_ALLOWED_SOURCES` | Addresses/CIDRs allowed to use `HONEYPOT_API_KEY` (e.g. `203.0.113.5,10.0.66.0/24`); others get 403. Set it in production. |
| `HONEYPOT_AUTOBLOCK_MAX_PER_HOUR` | Cap on honeypot-originated auto-blocks (default 20); further high-scoring sessions are left for manual review. |
| `HONEYPOT_THREAT_WINDOW_MINUTES` | Connections from one IP within this window share one threat (default 60; 0 = one per session). |
| `HONEYPOT_MAX_COMMANDS`, `HONEYPOT_MAX_CREDENTIALS` | Per-session array caps (2000 / 500); totals are kept in `commandCount` / `credentialCount`. |
| `HONEYPOT_HEARTBEAT_TIMEOUT_SECONDS` | Node shows `offline` when the blocker has not polled for this long (default 30). |
| `RETENTION_ENABLED` + `RETENTION_INTERVAL_HOURS` | Both required to schedule archive-then-delete retention; never runs at startup. |
| `DECEPTION_EXCLUDED_PROFILES` (AI engine) | Additional personas never recommended. `windows_srv` is always excluded and cannot be re-enabled. |
| `HONEYPOT_SSH_PORT` | Port shown for the node in the dashboard (default 2222; 22 when published or redirected there). |
| `HONEYPOT_AUTOBLOCK_MODE=approve` | Honeypot-originated blocks are never automatic; each raises one "Honeypot block awaiting approval" alert. |
| `PARSER_METRICS_PORT` / `--metrics-port` (parser) | Prometheus metrics on 127.0.0.1 (events read/posted/rejected/spooled, spool depth, lag). |
| `LOG_FORMAT=json` (parser) | One JSON object per log line. |

`build_honeyfs.py` also plants decoy credentials (`/root/.aws/credentials`, `/root/.ssh/id_rsa`) and a per-distro
`/etc/motd` in each persona. Reading a decoy raises a CRITICAL "Canary file read" alert. The backend stores each
session's client banner and the reference to Cowrie's TTY recording (replay it on the honeypot host with Cowrie's
`playlog`), and `GET /api/honeypot/attackers` groups sessions by HASSH.

`retention.sh` deletes rotated Cowrie logs (30 days), TTY recordings (90) and downloads (30); `--dry-run` lists
them. Schedule it daily. `cowrie.service` runs Cowrie under systemd (foreground, no stale pid file, sandboxed) for a
native install.

`redirect-ssh-port.sh` sends inbound port 22 to Cowrie on 2222 (move the real sshd first).
Set the URL variables whenever the backend is not on the same host.

`cowrie/sentinel_output.py` is an alternative ingest path (a Cowrie output plugin
posting events directly). It is **not enabled** in `cowrie.cfg` on purpose: running
it together with the parser would ingest every event twice. Use one or the other.

Install `requests` for the parser; packet capture additionally requires Scapy,
libpcap and cicflowmeter.

The profile switcher writes Cowrie configuration but never invokes Docker.
Restart the independently managed Cowrie service after reviewing the generated
configuration, then record the persona with `PUT /api/honeypot/deception/profile`
so the Q-learner credits sessions to the persona actually served. Existing profile
semantics and user database are retained.

Legacy synthetic utilities are not production startup paths. Do not run parser
demo mode, backend seed, or trigger_block against production. For model evaluation,
use the side-effect-free AI /predict/eval endpoint and real dataset replay.
