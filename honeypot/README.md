# Optional real honeypot integration

See [native requirements and integration](../docs/NATIVE_DEVELOPMENT.md).
Cowrie, its JSON parser, packet sniffer, blocker plugin and profile switcher are
preserved. No honeypot, parser, sniffer or simulated feed starts automatically.

Run Cowrie on a separately managed Linux host. Its real JSON log is ingested with
`python parsers/log_parser.py --live --log <cowrie.json>`.

## Configuration

| Component | Variables | Default backend URL |
|---|---|---|
| `parsers/log_parser.py` (the ingest path) | `SENTINEL_API`, `HONEYPOT_API_KEY` (falls back to `SENTINEL_KEY` with a warning), `COWRIE_LOG`, `SENTINEL_POST_RETRIES`, `SENTINEL_POST_BACKOFF` | `http://localhost:5000/api` |
| `cowrie/sentinel_blocker.py` (Cowrie output plugin, enabled in `cowrie.cfg`) | `SENTINEL_API_URL`, `HONEYPOT_API_KEY` | `http://localhost:5000/api` |
| `sniffer/sniffer.py` (dataset builder: labels captured flows into `flows.csv`) | `SENTINEL_API`, `HONEYPOT_API_KEY` | `http://localhost:5000/api` |

Give the honeypot host only `HONEYPOT_API_KEY`, never the AI engine's `SENTINEL_KEY`.
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
