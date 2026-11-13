#!/usr/bin/env python3
"""
Capture service: packets -> flows -> SentinelAI backend (POST /api/honeypot/ingest/flow), with health reporting.

  # Replay a recorded capture (always available; labelled "pcap_replay" everywhere)
  python -m capture.service --pcap traffic.pcap --dry-run
  HONEYPOT_API_KEY=... python -m capture.service --pcap traffic.pcap --backend http://127.0.0.1:5000

  # Live passive capture of ONE interface (off by default; see docs/CAPTURE.md)
  SENTINEL_LIVE_CAPTURE=1 HONEYPOT_API_KEY=... python -m capture.service --live --iface eth0 \
      --i-understand-live-capture --backend http://127.0.0.1:5000

Health: every --heartbeat-seconds the service POSTs {mode, interface, counters} to
/api/honeypot/ingest/capture-heartbeat (same honeypot key) and writes it to --health-file. The dashboard shows "Capture unavailable" when heartbeats stop.
Resource limits: --max-flows, --max-packets, --max-seconds, --max-flows-per-second (excess flows are counted and
dropped, never queued without bound).
"""
import argparse
import json
import os
import sys
import time
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from capture.flows import FlowExtractor, to_ingest_payload  # noqa: E402
from capture.sources import CaptureUnavailable, LivePassiveSource, PcapReplaySource  # noqa: E402


class Health:
    def __init__(self, mode, interface, path=None):
        self.mode, self.interface, self.path = mode, interface, path
        self.started = datetime.now(timezone.utc).isoformat()
        self.counters = {"packets": 0, "flows": 0, "posted": 0, "post_errors": 0, "rate_limited": 0, "dropped_packets": 0}
        self.last_packet_at = None
        self.last_error = None

    def snapshot(self, status="running"):
        return {"mode": self.mode, "interface": self.interface, "status": status, "startedAt": self.started,
                "lastPacketAt": self.last_packet_at, "at": datetime.now(timezone.utc).isoformat(),
                "counters": dict(self.counters), "lastError": self.last_error}

    def write(self, status="running"):
        if self.path:
            tmp = Path(self.path).with_suffix(".tmp")
            tmp.write_text(json.dumps(self.snapshot(status), indent=1), encoding="utf-8")
            os.replace(tmp, self.path)


def _post(url, key, body, timeout=10):
    req = urllib.request.Request(url, data=json.dumps(body).encode(), method="POST",
                                 headers={"Content-Type": "application/json", "x-api-key": key})
    with urllib.request.urlopen(req, timeout=timeout) as r:  # noqa: S310 — URL is the operator's backend
        return r.status


def run(source, extractor, sink, health, heartbeat=None, heartbeat_seconds=15.0, max_flows_per_second=200.0,
        max_seconds=None):
    """Drive one source to completion. sink(payload) delivers a flow; heartbeat(snapshot) reports health."""
    window_start, in_window = time.monotonic(), 0
    last_beat = 0.0
    started = time.monotonic()

    def beat(status="running"):
        health.write(status)
        if heartbeat:
            try:
                heartbeat(health.snapshot(status))
            except Exception as e:  # noqa: BLE001
                health.last_error = f"heartbeat: {type(e).__name__}"

    def deliver(rec):
        nonlocal window_start, in_window
        health.counters["flows"] += 1
        now = time.monotonic()
        if now - window_start >= 1.0:
            window_start, in_window = now, 0
        if in_window >= max_flows_per_second:
            health.counters["rate_limited"] += 1
            return
        in_window += 1
        try:
            sink(to_ingest_payload(rec, source.kind))
            health.counters["posted"] += 1
        except Exception as e:  # noqa: BLE001 — one failed post must not stop the capture
            health.counters["post_errors"] += 1
            health.last_error = f"post: {type(e).__name__}"

    beat("starting")
    try:
        for pkt in source.packets():
            health.counters["packets"] += 1
            health.last_packet_at = datetime.fromtimestamp(pkt.ts, tz=timezone.utc).isoformat()
            for rec in extractor.add(pkt):
                deliver(rec)
            if time.monotonic() - last_beat >= heartbeat_seconds:
                health.counters["dropped_packets"] = getattr(source, "dropped", 0)
                beat()
                last_beat = time.monotonic()
            if max_seconds and time.monotonic() - started > max_seconds:
                break
        for rec in extractor.flush():
            deliver(rec)
        health.counters["dropped_packets"] = getattr(source, "dropped", 0)
        beat("finished")
    except CaptureUnavailable as e:
        health.last_error = e.reason
        beat("unavailable")
        raise


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    src = ap.add_mutually_exclusive_group(required=True)
    src.add_argument("--pcap", help="replay a recorded classic pcap file")
    src.add_argument("--live", action="store_true", help="live passive capture (needs SENTINEL_LIVE_CAPTURE=1)")
    ap.add_argument("--iface", help="the ONE interface to capture (live mode)")
    ap.add_argument("--bpf", help="optional BPF filter, e.g. 'tcp port 2222'")
    ap.add_argument("--i-understand-live-capture", dest="confirm", action="store_true")
    ap.add_argument("--backend", default=os.getenv("SENTINEL_BACKEND_URL", "http://127.0.0.1:5000"))
    ap.add_argument("--dry-run", action="store_true", help="print flow payloads instead of posting them")
    ap.add_argument("--health-file", default=None)
    ap.add_argument("--heartbeat-seconds", type=float, default=15.0)
    ap.add_argument("--max-flows", type=int, default=50_000)
    ap.add_argument("--max-packets", type=int, default=None, help="pcap mode: stop after this many records")
    ap.add_argument("--max-seconds", type=float, default=None)
    ap.add_argument("--max-flows-per-second", type=float, default=200.0)
    a = ap.parse_args(argv)
    try:
        source = (PcapReplaySource(a.pcap, a.max_packets) if a.pcap else
                  LivePassiveSource(a.iface or "", confirm=a.confirm, bpf=a.bpf, max_seconds=a.max_seconds))
    except CaptureUnavailable as e:
        print(json.dumps({"mode": "unavailable", "reason": e.reason}))
        return 3
    health = Health(source.kind, a.iface if a.live else None, a.health_file)
    if a.dry_run:
        sink, heartbeat = (lambda p: print(json.dumps(p))), None
    else:
        key = os.getenv("HONEYPOT_API_KEY")
        if not key:
            print("HONEYPOT_API_KEY is required unless --dry-run", file=sys.stderr)
            return 2
        base = a.backend.rstrip("/")
        sink = lambda p: _post(f"{base}/api/honeypot/ingest/flow", key, p)  # noqa: E731
        heartbeat = lambda s: _post(f"{base}/api/honeypot/ingest/capture-heartbeat", key, s)  # noqa: E731
    try:
        run(source, FlowExtractor(max_flows=a.max_flows), sink, health, heartbeat, a.heartbeat_seconds,
            a.max_flows_per_second, a.max_seconds)
    except CaptureUnavailable as e:
        print(json.dumps({"mode": "unavailable", "reason": e.reason}))
        return 3
    print(json.dumps(health.snapshot("finished")), file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
