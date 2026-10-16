# Optional real honeypot integration

See [native requirements and integration](../docs/NATIVE_DEVELOPMENT.md).
Cowrie, its JSON parser, packet sniffer, blocker plugin and profile switcher are
preserved. No honeypot, parser, sniffer or simulated feed starts automatically.

Run Cowrie on a separately managed Linux host. Its real JSON log can be ingested
with `python parsers/log_parser.py --live --log <cowrie.json>`, using SENTINEL_API
and SENTINEL_KEY. Cowrie blocker uses SENTINEL_API_URL and HONEYPOT_API_KEY.
Install requests for the parser; packet capture additionally requires Scapy,
libpcap and cicflowmeter.

The profile switcher writes Cowrie configuration but never invokes Docker.
Restart the independently managed Cowrie service after reviewing the generated
configuration. Existing profile semantics and user database are retained.

Legacy synthetic utilities are not production startup paths. Do not run parser
demo mode, backend seed, or trigger_block against production. For model evaluation,
use the side-effect-free AI /predict/eval endpoint and real dataset replay.
