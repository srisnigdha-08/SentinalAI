"""
Bidirectional flow assembly and the 53-feature record (utils.features.FEATURE_NAMES), following CICFlowMeter's
definitions as used for CICIDS2017:
  * the first packet of a flow sets the forward direction;
  * packet lengths are L4 payload bytes; header lengths are L4 header bytes;
  * durations and inter-arrival times are in MICROSECONDS; rates are per second;
  * a flow ends on FIN in both directions or RST, after FLOW_TIMEOUT_S idle, or after ACTIVE_LIMIT_S total;
  * active/idle periods use a 5 s activity timeout;
  * init_win_bytes_* is the TCP window of the first packet in that direction, -1 if there is none;
  * bulk features are 0 (they are constant 0 in the training pool);
  * payload_entropy and time_of_day_* are NOT produced here: the engine derives them exactly as in training
    (utils.features.extract_features_from_record), so capture and training cannot disagree on them.
Resource limits: at most max_flows concurrent flows (the oldest idle flow is exported early when full) and at most
max_packets_per_flow packets per flow (the flow is exported and restarted).
"""
import math
from dataclasses import dataclass, field
from typing import Dict, Iterable, Iterator, List, Optional, Tuple

from capture.packets import ACK, FIN, PSH, RST, SYN, URG, PacketMeta

FLOW_TIMEOUT_S = 120.0
ACTIVE_LIMIT_S = 3600.0
ACTIVITY_TIMEOUT_US = 5_000_000.0
# Fields the extractor emits; payload_entropy / time_of_day_* are derived by the engine from these and `timestamp`.
EMITTED_FEATURES = (
    "flow_duration", "total_fwd_packets", "total_bwd_packets", "total_len_fwd_packets", "total_len_bwd_packets",
    "fwd_packet_len_max", "fwd_packet_len_min", "fwd_packet_len_mean", "fwd_packet_len_std",
    "bwd_packet_len_max", "bwd_packet_len_min", "bwd_packet_len_mean", "bwd_packet_len_std",
    "flow_bytes_per_sec", "flow_packets_per_sec", "flow_iat_mean", "flow_iat_std", "flow_iat_max", "flow_iat_min",
    "fwd_iat_total", "fwd_iat_mean", "fwd_iat_std", "fwd_iat_max", "fwd_iat_min",
    "bwd_iat_total", "bwd_iat_mean", "bwd_iat_std", "bwd_iat_max", "bwd_iat_min",
    "fwd_psh_flags", "bwd_psh_flags", "fwd_urg_flags", "bwd_urg_flags",
    "fin_flag_count", "syn_flag_count", "rst_flag_count", "psh_flag_count", "ack_flag_count", "urg_flag_count",
    "fwd_header_len", "bwd_header_len", "fwd_avg_bytes_per_bulk", "bwd_avg_bytes_per_bulk",
    "init_win_bytes_forward", "init_win_bytes_backward", "active_mean", "active_std", "idle_mean", "idle_std",
    "down_up_ratio",
)
ENGINE_DERIVED = ("payload_entropy", "time_of_day_sin", "time_of_day_cos")


def _stats(xs: List[float]) -> Tuple[float, float, float, float]:
    """(mean, sample std, max, min); zeros for an empty list (CICFlowMeter convention)."""
    if not xs:
        return 0.0, 0.0, 0.0, 0.0
    n = len(xs)
    mean = sum(xs) / n
    std = math.sqrt(sum((x - mean) ** 2 for x in xs) / (n - 1)) if n > 1 else 0.0
    return mean, std, max(xs), min(xs)


@dataclass
class _Flow:
    key: tuple
    src: str
    dst: str
    sport: int
    dport: int
    proto: int
    start: float
    last: float
    fwd_len: List[int] = field(default_factory=list)
    bwd_len: List[int] = field(default_factory=list)
    fwd_ts: List[float] = field(default_factory=list)
    bwd_ts: List[float] = field(default_factory=list)
    all_ts: List[float] = field(default_factory=list)
    flags: Dict[str, int] = field(default_factory=lambda: dict.fromkeys(("fin", "syn", "rst", "psh", "ack", "urg"), 0))
    fwd_psh: int = 0
    bwd_psh: int = 0
    fwd_urg: int = 0
    bwd_urg: int = 0
    fwd_hdr: int = 0
    bwd_hdr: int = 0
    init_win_fwd: int = -1
    init_win_bwd: int = -1
    fin_fwd: bool = False
    fin_bwd: bool = False
    active: List[float] = field(default_factory=list)
    idle: List[float] = field(default_factory=list)
    _active_start: float = 0.0
    _active_last: float = 0.0

    def add(self, p: PacketMeta, forward: bool):
        ts_us = p.ts * 1e6
        if not self.all_ts:
            self._active_start = self._active_last = ts_us
        elif ts_us - self._active_last > ACTIVITY_TIMEOUT_US:
            if self._active_last > self._active_start:
                self.active.append(self._active_last - self._active_start)
            self.idle.append(ts_us - self._active_last)
            self._active_start = ts_us
        self._active_last = ts_us
        self.all_ts.append(ts_us)
        self.last = p.ts
        f = p.flags
        for name, bit in (("fin", FIN), ("syn", SYN), ("rst", RST), ("psh", PSH), ("ack", ACK), ("urg", URG)):
            if f & bit:
                self.flags[name] += 1
        if forward:
            self.fwd_len.append(p.payload_len); self.fwd_ts.append(ts_us); self.fwd_hdr += p.header_len
            self.fwd_psh += bool(f & PSH); self.fwd_urg += bool(f & URG)
            if self.init_win_fwd < 0 and p.window >= 0:
                self.init_win_fwd = p.window
            self.fin_fwd |= bool(f & FIN)
        else:
            self.bwd_len.append(p.payload_len); self.bwd_ts.append(ts_us); self.bwd_hdr += p.header_len
            self.bwd_psh += bool(f & PSH); self.bwd_urg += bool(f & URG)
            if self.init_win_bwd < 0 and p.window >= 0:
                self.init_win_bwd = p.window
            self.fin_bwd |= bool(f & FIN)

    @property
    def packets(self):
        return len(self.all_ts)

    def finished_by_tcp(self, p: PacketMeta) -> bool:
        return self.proto == 6 and (bool(p.flags & RST) or (self.fin_fwd and self.fin_bwd))

    def record(self) -> dict:
        dur_us = (self.all_ts[-1] - self.all_ts[0]) if self.all_ts else 0.0
        dur_s = dur_us / 1e6
        iat = [b - a for a, b in zip(self.all_ts, self.all_ts[1:])]
        fiat = [b - a for a, b in zip(self.fwd_ts, self.fwd_ts[1:])]
        biat = [b - a for a, b in zip(self.bwd_ts, self.bwd_ts[1:])]
        fm, fs, fx, fn = _stats([float(x) for x in self.fwd_len])
        bm, bs, bx, bn = _stats([float(x) for x in self.bwd_len])
        im, is_, ix, in_ = _stats(iat)
        fim, fis, fix, fin_ = _stats(fiat)
        bim, bis, bix, bin_ = _stats(biat)
        active = self.active + ([self._active_last - self._active_start] if self._active_last > self._active_start else [])
        am, asd, _, _ = _stats(active)
        idm, ids, _, _ = _stats(self.idle)
        total_bytes = sum(self.fwd_len) + sum(self.bwd_len)
        rec = {
            "flow_duration": dur_us, "total_fwd_packets": len(self.fwd_len), "total_bwd_packets": len(self.bwd_len),
            "total_len_fwd_packets": float(sum(self.fwd_len)), "total_len_bwd_packets": float(sum(self.bwd_len)),
            "fwd_packet_len_max": fx, "fwd_packet_len_min": fn, "fwd_packet_len_mean": fm, "fwd_packet_len_std": fs,
            "bwd_packet_len_max": bx, "bwd_packet_len_min": bn, "bwd_packet_len_mean": bm, "bwd_packet_len_std": bs,
            "flow_bytes_per_sec": total_bytes / dur_s if dur_s > 0 else 0.0,
            "flow_packets_per_sec": self.packets / dur_s if dur_s > 0 else 0.0,
            "flow_iat_mean": im, "flow_iat_std": is_, "flow_iat_max": ix, "flow_iat_min": in_,
            "fwd_iat_total": float(sum(fiat)), "fwd_iat_mean": fim, "fwd_iat_std": fis, "fwd_iat_max": fix, "fwd_iat_min": fin_,
            "bwd_iat_total": float(sum(biat)), "bwd_iat_mean": bim, "bwd_iat_std": bis, "bwd_iat_max": bix, "bwd_iat_min": bin_,
            "fwd_psh_flags": self.fwd_psh, "bwd_psh_flags": self.bwd_psh, "fwd_urg_flags": self.fwd_urg, "bwd_urg_flags": self.bwd_urg,
            "fin_flag_count": self.flags["fin"], "syn_flag_count": self.flags["syn"], "rst_flag_count": self.flags["rst"],
            "psh_flag_count": self.flags["psh"], "ack_flag_count": self.flags["ack"], "urg_flag_count": self.flags["urg"],
            "fwd_header_len": self.fwd_hdr, "bwd_header_len": self.bwd_hdr,
            "fwd_avg_bytes_per_bulk": 0.0, "bwd_avg_bytes_per_bulk": 0.0,
            "init_win_bytes_forward": self.init_win_fwd, "init_win_bytes_backward": self.init_win_bwd,
            "active_mean": am, "active_std": asd, "idle_mean": idm, "idle_std": ids,
            "down_up_ratio": float(len(self.bwd_len) // len(self.fwd_len)) if self.fwd_len else 0.0,
        }
        return {"sourceIP": self.src, "destinationIP": self.dst, "sourcePort": self.sport, "destinationPort": self.dport,
                "protocol": self.proto, "timestamp": _iso(self.start), "features": {k: round(float(v), 6) for k, v in rec.items()}}


def _iso(ts: float) -> str:
    from datetime import datetime, timezone
    return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat().replace("+00:00", "Z")


class FlowExtractor:
    def __init__(self, max_flows: int = 50_000, max_packets_per_flow: int = 100_000,
                 flow_timeout_s: float = FLOW_TIMEOUT_S, active_limit_s: float = ACTIVE_LIMIT_S):
        if max_flows < 1 or max_packets_per_flow < 2:
            raise ValueError("max_flows must be >= 1 and max_packets_per_flow >= 2")
        self.max_flows, self.max_ppf = max_flows, max_packets_per_flow
        self.timeout, self.active_limit = flow_timeout_s, active_limit_s
        self.flows: Dict[tuple, _Flow] = {}
        self.stats = {"packets": 0, "flows_exported": 0, "evicted_capacity": 0, "split_packet_limit": 0, "timed_out": 0}
        self._now = 0.0

    @staticmethod
    def _key(p: PacketMeta):
        a, b = (p.src, p.sport), (p.dst, p.dport)
        return (p.proto,) + ((a, b) if a <= b else (b, a))

    def add(self, p: PacketMeta) -> Iterator[dict]:
        """Feed one packet; yields any flow records that completed."""
        self.stats["packets"] += 1
        self._now = max(self._now, p.ts)
        yield from self._expire(p.ts)
        key = self._key(p)
        flow = self.flows.get(key)
        if flow is not None and (p.ts - flow.last > self.timeout or p.ts - flow.start > self.active_limit):
            self.stats["timed_out"] += 1
            yield self._export(key)
            flow = None
        if flow is None:
            if len(self.flows) >= self.max_flows:
                oldest = min(self.flows.values(), key=lambda f: f.last).key
                self.stats["evicted_capacity"] += 1
                yield self._export(oldest)
            flow = _Flow(key, p.src, p.dst, p.sport, p.dport, p.proto, p.ts, p.ts)
            self.flows[key] = flow
        flow.add(p, forward=(p.src, p.sport) == (flow.src, flow.sport))
        if flow.finished_by_tcp(p):
            yield self._export(key)
        elif flow.packets >= self.max_ppf:
            self.stats["split_packet_limit"] += 1
            yield self._export(key)

    def _expire(self, now: float) -> Iterator[dict]:
        stale = [k for k, f in self.flows.items() if now - f.last > self.timeout]
        for k in stale:
            self.stats["timed_out"] += 1
            yield self._export(k)

    def _export(self, key) -> dict:
        flow = self.flows.pop(key)
        self.stats["flows_exported"] += 1
        return flow.record()

    def flush(self) -> Iterator[dict]:
        for k in list(self.flows):
            yield self._export(k)

    def run(self, packets: Iterable[PacketMeta]) -> Iterator[dict]:
        for p in packets:
            yield from self.add(p)
        yield from self.flush()


def to_ingest_payload(record: dict, capture_source: str) -> dict:
    """The body for POST /api/honeypot/ingest/flow: identifiers, timestamp, the emitted features, the source label."""
    if capture_source not in ("pcap_replay", "live_passive"):
        raise ValueError("capture_source must be pcap_replay or live_passive")
    return {"sourceIP": record["sourceIP"], "destinationIP": record["destinationIP"], "timestamp": record["timestamp"],
            "captureSource": capture_source, **record["features"]}
