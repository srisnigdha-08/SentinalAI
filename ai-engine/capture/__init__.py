"""
Optional passive flow capture (docs/CAPTURE.md).

Two sources feed one extractor:
  * PCAP replay: a recorded capture file. Always available; used by tests and demos.
  * Live passive capture: one explicitly named interface. Off by default; needs SENTINEL_LIVE_CAPTURE=1, the
    --i-understand-live-capture flag, a packet-capture driver (Npcap on Windows, CAP_NET_RAW on Linux).

Both produce the same 53-feature flow records the existing /api/honeypot/ingest/flow endpoint accepts. Only packet
headers are read: no payload byte is stored, logged or forwarded. Nothing is ever sent onto the network except the
HTTPS/HTTP POST of a flow record to the configured SentinelAI backend.
"""
CAPTURE_SOURCES = ("pcap_replay", "live_passive")
