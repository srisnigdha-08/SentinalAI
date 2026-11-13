# Network capture: PCAP replay and opt-in live passive capture

`ai-engine/capture` turns packets into the 53-feature flow records that `POST /api/honeypot/ingest/flow` already
accepts. It runs in one of two modes:

| Mode | Source | Default | Dashboard label |
|---|---|---|---|
| `pcap_replay` | a recorded classic `.pcap` file | available | "Traffic: recorded PCAP replay" |
| `live_passive` | ONE explicitly named interface, receive-only | **off** | "Traffic: LIVE passive capture (iface)" |
| none / stale | no heartbeat for 60 s, or the service reported it cannot capture | — | "Traffic: capture unavailable" |

## Guarantees

- **Headers only.** The parser reads the link, IP and TCP/UDP headers. Payload length is measured and the bytes
  are discarded; `PacketMeta` has no field that could hold payload. Nothing is written to disk except an optional
  health file.
- **Passive.** No packet is sent, injected or scanned. The only network output is the HTTP POST of flow records and
  heartbeats to the configured backend.
- **One interface.** Live mode needs all of:
  - `SENTINEL_LIVE_CAPTURE=1`
  - `--i-understand-live-capture`
  - an interface that exists, is in `SENTINEL_CAPTURE_INTERFACES` when that list is set, and is not
    `any` or a wildcard
- **Bounded.**
  - at most `--max-flows` concurrent flows (the oldest idle flow is exported early)
  - a per-flow packet cap
  - `--max-flows-per-second` (the excess is counted and dropped)
  - `--max-seconds`
  - a bounded queue for live packets (overflow is counted as dropped)
- **Honest labels.**
  - Every prediction stores `captureSource`, set by the route that received it:
    - `live_passive` / `pcap_replay`: only from the capture service's honeypot key
    - `dataset_replay`: `demo/replay_cicids.py`
    - `manual`: other `/api/ai/analyze` calls
  - An analyst cannot claim live traffic.
  - Older records show "Capture source not recorded" in the Trust Meter.

## Feature parity

The extractor follows CICFlowMeter's definitions as used for CICIDS2017:
- **Direction:** the first packet sets the forward direction.
- **Lengths:** packet lengths are L4 payload bytes; header lengths are L4 header bytes.
- **Units:** durations and inter-arrival times are in microseconds; rates are per second.
- **Flow end:** FIN in both directions, RST, 120 s idle, or 3600 s active.
- **Activity:** active/idle periods use a 5 s activity timeout.
- **`init_win`:** -1 when a direction has no TCP packet.
- **Bulk features:** 0 (constant 0 in the training pool).

`payload_entropy` and `time_of_day_*` are not produced by the capture. The engine derives them from the record
exactly as in training (`utils.features.extract_features_from_record`), so the two paths cannot diverge.

Parity is tested by `tests/test_capture.py::test_parity_record_to_engine_vector`: the posted record becomes the
engine's 53-vector with no defaulted field.

Known approximation: CICFlowMeter-Java's exact header-length accounting may differ by a few bytes for TCP options.
Header features have never been validated against a capture of this lab's own traffic.

## Running

```bash
cd ai-engine
.venv/Scripts/python -m capture.service --pcap traffic.pcap --dry-run
HONEYPOT_API_KEY=... .venv/Scripts/python -m capture.service --pcap traffic.pcap --backend http://127.0.0.1:5000
```

Live mode (owner action; **not enabled or verified on the project laptop**):
- **Windows:** install Npcap, which is a driver installation and needs your authorisation.
- **WSL:** run as a user with `CAP_NET_RAW`, then:

```bash
SENTINEL_LIVE_CAPTURE=1 SENTINEL_CAPTURE_INTERFACES=eth0 HONEYPOT_API_KEY=... \
  .venv/Scripts/python -m capture.service --live --iface eth0 --bpf "tcp port 2222" --i-understand-live-capture
```

Environment check on 2026-11-13: scapy is installed and Npcap is not, so live capture on the Windows host is
unavailable. The adapter reports this as `unavailable` with its reason.
