# Optional real honeypot integration

See [native requirements and integration](../docs/NATIVE_DEVELOPMENT.md).
Cowrie, its JSON parser, packet sniffer, blocker plugin and profile switcher are
preserved. No honeypot, parser, sniffer or simulated feed starts automatically.

Run Cowrie on a separately managed Linux host. Its real JSON log is ingested with
`python parsers/log_parser.py --live --log <cowrie.json>`.

## Configuration

| Component | Variables | Default backend URL |
|---|---|---|
| `parsers/log_parser.py` (the ingest path) | `SENTINEL_API`, `HONEYPOT_API_KEY` (required; the backend refuses `SENTINEL_KEY` on honeypot routes), `COWRIE_LOG`, `SENTINEL_POST_RETRIES`, `SENTINEL_POST_BACKOFF`, `PARSER_STATE_DIR` (default `~/.sentinelai/cowrie-parser`: read offset, open sessions, delivery spool), `SENTINEL_SPOOL_MAX`, `SENTINEL_SPOOL_RETRY` | `http://localhost:5000/api` |
| `cowrie/sentinelblocker.py` (Cowrie output plugin `[output_sentinelblocker]`, enabled in `cowrie.cfg`; install as `src/cowrie/output/sentinelblocker.py`: Cowrie takes the module name from the section up to the next underscore, so the name must not contain one) | `SENTINEL_API_URL`, `HONEYPOT_API_KEY` | `http://localhost:5000/api` |
| `sniffer/sniffer.py` (dataset builder: labels captured flows into `flows.csv`) | `SENTINEL_API`, `HONEYPOT_API_KEY` | `http://localhost:5000/api` |

The parser resumes from its saved offset after a restart, finishes a rotated log before following the new
one, and queues deliveries on disk while the backend is unreachable. The state directory holds captured
credentials (as `cowrie.json` does): keep it private to the parser's user. With no saved state, the first
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
| `DECEPTION_EXCLUDED_PROFILES` (AI engine) | Personas never recommended (default `windows_srv`, which Cowrie cannot serve). |

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
