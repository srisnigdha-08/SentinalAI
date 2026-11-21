# Network capture: offline PCAP replay and opt-in live passive capture

`ai-engine/capture` turns packets into the 53-feature flow records that `POST /api/honeypot/ingest/flow` already
accepts. It runs in one of two modes, which the dashboard reports as **two separate capabilities**:

| Capability | Source | Status | Dashboard |
|---|---|---|---|
| Offline PCAP replay (`pcap_replay`) | a recorded classic `.pcap` file | **Implemented and verified** (automated end-to-end tests, below) | Capability Status: "Network traffic source: offline PCAP replay"; chip "Traffic: recorded PCAP replay" |
| Live network capture (`live_passive`) | ONE explicitly named interface, receive-only | **Implemented, not enabled** (never verified on this project's hardware) | Capability Status: "Network traffic source: live network capture"; chip "Traffic: LIVE passive capture (iface)" only while a live heartbeat is fresh |
| none / stale | no heartbeat for 60 s, or the service reported it cannot capture | - | chip "Traffic: capture unavailable" |

A working offline replay says nothing about live capture: it is a different code path (driver, interface,
permissions) that has never been exercised here.

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

## Offline PCAP replay: how to run it

```bash
cd ai-engine
# 1. Check the file and see the flow records, without sending anything:
.venv/Scripts/python -m capture.service --pcap traffic.pcap --dry-run
# 2. Replay into a running SentinelAI backend (same honeypot key the Cowrie parser uses):
HONEYPOT_API_KEY=... .venv/Scripts/python -m capture.service --pcap traffic.pcap --backend http://127.0.0.1:5000 \
  --health-file replay-health.json
```

Only replay files you are authorised to use. Nothing is captured from this host in replay mode: the file is read,
no network interface is opened, and no administrator rights or Npcap are needed.

**Input requirements**
- Classic libpcap format (`.pcap`), either byte order, microsecond or nanosecond timestamps. pcapng is refused with
  a conversion hint (`editcap -F pcap in.pcapng out.pcap`).
- Link types: Ethernet (1, with 802.1Q/QinQ VLAN tags), raw IP (101), Linux cooked SLL (113), BSD loopback (0, 108).
  Anything else (e.g. 802.11 = 105) is refused with "unsupported link type N".
- TCP and UDP over IPv4 and IPv6 become flows. ARP, ICMP, non-first IP fragments and other protocols are skipped
  and counted (`skipped_frames`). IPv6 extension headers are not followed.
- A record larger than 262 144 bytes is treated as corruption.

**How flow extraction works** (`capture/packets.py` -> `capture/flows.py`)
1. `read_pcap` reads one record at a time; `parse_frame` keeps only header fields (`PacketMeta`: addresses, ports,
   protocol, payload length, header length, TCP flags, TCP window). The frame bytes are dropped immediately.
2. `FlowExtractor` groups packets by the bidirectional 5-tuple; the first packet sets the forward direction. A flow
   is exported on FIN both ways, RST, 120 s idle, 3600 s active, the per-flow packet cap, or at end of file.
3. Each flow becomes 50 CICFlowMeter-style features (see "Feature parity"); the engine derives the other 3
   (`payload_entropy`, `time_of_day_sin/cos`), giving the 53-feature contract of the deployed `xgb_cicids_v1`.
   The extractor does not change the model or its feature definitions.
4. `to_ingest_payload` adds `captureSource: "pcap_replay"` and the service POSTs it to `/api/honeypot/ingest/flow`.

**Errors are reported, never silent** (exit codes of `capture.service`)

| Situation | Result |
|---|---|
| Valid file | exit 0, heartbeat `finished` with counters (`records`, `packets`, `skipped_frames`, `flows`, `posted`, ...) |
| Header-only file, or no TCP/UDP packets | exit 0, `finished`, `lastError` "no TCP/UDP packets found (N record(s) read, M skipped ...)" |
| File cut off inside a record | exit 0, every complete record before the cut is replayed, `lastError` "pcap truncated: ..." |
| Missing file, directory, 0-byte file, too short, bad magic, pcapng, unsupported link type, corrupt record length | exit 4, JSON `{"mode":"pcap_replay","status":"failed","error":...}`, heartbeat `failed` with the reason |
| Backend refuses or is down for one flow | that flow is counted in `post_errors`; the replay continues |

**Repeated replay and duplicates.** Replaying the same file is deterministic: the same flow records every time.
The backend stores every replay as new observations (one `AIPrediction` per posted flow, each labelled
`pcap_replay`); it does not de-duplicate replays. Within one file, a duplicated packet (e.g. a retransmission) is
counted in its flow, as CICFlowMeter does.

**How prediction provenance is recorded**
- The capture service labels each flow `pcap_replay` (or `live_passive`); the backend accepts those two labels only
  on the honeypot-key route, and stores anything else as `unknown`, never as live.
- The label is removed before the record goes to the AI engine (the engine scores features only) and stored as
  `AIPrediction.captureSource`.
- The `ai_prediction` Socket.IO event carries `captureSource` and `inputSource` (all rooms, including the
  redacted viewer copy). The AI page and the live feed show it as "PCAP REPLAY"; the Trust Meter shows
  "Replayed from a recorded PCAP".

**Reading the dashboard**
- Capability Status, "offline PCAP replay": IMPLEMENTED AND VERIFIED. This label rests on the test evidence listed
  in its facts, not on a replay running now. Its summary and `facts.lastReplay` show the latest replay reported
  since the backend started (finished/failed, counters, any truncation note).
- Capability Status, "live network capture": IMPLEMENTED, NOT ENABLED while no live heartbeat is fresh, which is
  the normal state. If a live capture ever reports, the entry shows EXPERIMENTAL (running, not verified), never
  "verified".
- Dashboard chip: "recorded PCAP replay (finished)" or "PCAP replay failed (live capture not enabled)" after a
  replay; never "LIVE" for a replay.

**Known limitations**
- Feature parity with CICFlowMeter-Java is by definition, not by byte-for-byte comparison against its output; TCP
  option header lengths may differ slightly (see "Feature parity").
- Bulk features are always 0; IPv6 extension headers are not followed; IP fragments after the first are skipped.
- A replay of attack traffic is scored like any other flow; correlated auto-block (simulated adapter by default)
  applies to replayed flows as well. Replay does not change containment behaviour.
- The backend's capture status is in memory: after a backend restart, `lastReplay` is empty until the next replay.
- No live capture has been run or verified.

## How it is verified

All fixtures are tiny synthetic pcaps written to temporary directories; no network, interface or driver is used.

```bash
cd ai-engine
.venv/Scripts/python -m pytest tests/test_capture.py tests/test_pcap_replay_e2e.py -q
```

```bash
cd backend
npx jest --runInBand tests/pcapReplayIngest.test.js tests/limitationRemediation.test.js
```

```bash
cd frontend
node --test tests/capabilities.test.mjs
```

- `ai-engine/tests/test_capture.py`: header parsing, CICFlowMeter feature definitions, resource limits, live-capture
  guards, service health and rate limiting.
- `ai-engine/tests/test_pcap_replay_e2e.py`: TCP+UDP replay with the feature contract; IPv6, VLAN, Linux SLL and raw
  IP; empty, header-only, non-IP-only, invalid, pcapng, unsupported link type, corrupt and truncated files; missing
  files; file handles closed; deterministic repeated replay; duplicate packets; no payload bytes in any output;
  the engine's `/predict/internal` contract (stub predictor) and read-only scoring by the deployed `xgb_cicids_v1`
  through the side-effect-free `/predict/eval`. It also pins `tests/fixtures/pcap_replay_flows.json`.
- `backend/tests/pcapReplayIngest.test.js`: that fixture through `/api/honeypot/ingest/flow` -> pipeline -> MongoDB
  (in memory) -> `ai_prediction` event -> viewer redaction -> Trust Meter, all keeping `pcap_replay`; payload-like
  fields dropped; repeated replay; invalid input refused; heartbeats; the two Capability Status entries.
- `frontend/tests/capabilities.test.mjs`: label and chip wording (a replay is never "LIVE"), provenance badges.

## Live capture (not enabled)

Live mode (owner action; **not enabled and not verified on the project laptop**):
- **Windows:** install Npcap, which is a driver installation and needs your authorisation.
- **WSL:** run as a user with `CAP_NET_RAW`, then:

```bash
SENTINEL_LIVE_CAPTURE=1 SENTINEL_CAPTURE_INTERFACES=eth0 HONEYPOT_API_KEY=... \
  .venv/Scripts/python -m capture.service --live --iface eth0 --bpf "tcp port 2222" --i-understand-live-capture
```

Environment check on 2026-11-13: scapy is installed and Npcap is not, so live capture on the Windows host is
unavailable. The adapter reports this as `unavailable` with its reason.
