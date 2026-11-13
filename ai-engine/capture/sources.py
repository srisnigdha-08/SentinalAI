"""
Packet sources. Both yield capture.packets.PacketMeta (headers only).

PcapReplaySource  a recorded classic-pcap file; never touches a network interface.
LivePassiveSource one explicitly named interface, receive-only. Guarded three ways:
                    1. SENTINEL_LIVE_CAPTURE=1 in the environment,
                    2. confirm=True (the CLI's --i-understand-live-capture),
                    3. the interface must exist and be in SENTINEL_CAPTURE_INTERFACES when that list is set.
                  "any", wildcards and empty names are refused: unrelated interfaces are never captured.
                  scapy's sniffer runs with store=False; no packet is ever sent (no injection, no scanning).
"""
import os
import queue
import threading
import time
from typing import Iterator, List, Optional

from capture.packets import LINKTYPE_ETHERNET, LINKTYPE_RAW, PacketMeta, parse_frame, read_pcap


class CaptureUnavailable(RuntimeError):
    """Live capture cannot run here; .reason says why (shown on the dashboard as 'Capture unavailable')."""
    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


class PcapReplaySource:
    kind = "pcap_replay"

    def __init__(self, path: str, max_packets: Optional[int] = None):
        self.path, self.max_packets = path, max_packets
        self.description = f"pcap file {os.path.basename(path)}"

    def packets(self) -> Iterator[PacketMeta]:
        with open(self.path, "rb") as f:
            yield from read_pcap(f, self.max_packets)


def list_interfaces() -> List[str]:
    try:
        from scapy.all import get_if_list
    except Exception as e:  # noqa: BLE001 — scapy missing or failing to load its capture backend
        raise CaptureUnavailable(f"scapy unavailable: {type(e).__name__}")
    try:
        return list(get_if_list())
    except Exception as e:  # noqa: BLE001
        raise CaptureUnavailable(f"cannot list interfaces: {type(e).__name__}")


def check_live_capture(iface: str, confirm: bool, env=None, interfaces: Optional[List[str]] = None) -> None:
    """Raise CaptureUnavailable unless every guard passes. Pure apart from list_interfaces() (injectable)."""
    env = os.environ if env is None else env
    if env.get("SENTINEL_LIVE_CAPTURE", "") != "1":
        raise CaptureUnavailable("live capture is disabled (set SENTINEL_LIVE_CAPTURE=1 to allow it)")
    if not confirm:
        raise CaptureUnavailable("live capture needs explicit confirmation (--i-understand-live-capture)")
    name = (iface or "").strip()
    if not name or name.lower() in ("any", "all", "*") or any(ch in name for ch in "*?"):
        raise CaptureUnavailable("name exactly one interface; 'any' and wildcards are refused")
    allowed = [s.strip() for s in env.get("SENTINEL_CAPTURE_INTERFACES", "").split(",") if s.strip()]
    if allowed and name not in allowed:
        raise CaptureUnavailable(f"interface {name!r} is not in SENTINEL_CAPTURE_INTERFACES")
    present = interfaces if interfaces is not None else list_interfaces()
    if name not in present:
        raise CaptureUnavailable(f"interface {name!r} not found on this host")


class LivePassiveSource:
    kind = "live_passive"

    def __init__(self, iface: str, confirm: bool = False, bpf: Optional[str] = None, max_queue: int = 10_000,
                 max_seconds: Optional[float] = None):
        check_live_capture(iface, confirm)
        self.iface, self.bpf, self.max_seconds = iface, bpf, max_seconds
        self.description = f"live passive capture on {iface}"
        self.q: "queue.Queue" = queue.Queue(maxsize=max_queue)
        self.dropped = 0
        self._stop = threading.Event()

    def _on_packet(self, pkt):
        try:
            raw = bytes(pkt)
            link = LINKTYPE_ETHERNET if pkt.__class__.__name__ == "Ether" else LINKTYPE_RAW
            meta = parse_frame(raw, link, float(pkt.time))
            del raw
        except Exception:  # noqa: BLE001 — a malformed frame must not stop the capture
            return
        if meta is None:
            return
        try:
            self.q.put_nowait(meta)
        except queue.Full:
            self.dropped += 1  # back-pressure: drop rather than grow memory without bound

    def stop(self):
        self._stop.set()

    def packets(self) -> Iterator[PacketMeta]:
        try:
            from scapy.all import AsyncSniffer
        except Exception as e:  # noqa: BLE001
            raise CaptureUnavailable(f"scapy unavailable: {type(e).__name__}")
        sniffer = AsyncSniffer(iface=self.iface, filter=self.bpf, prn=self._on_packet, store=False)
        try:
            sniffer.start()
        except Exception as e:  # noqa: BLE001 — no Npcap / no CAP_NET_RAW
            raise CaptureUnavailable(f"cannot open {self.iface}: {type(e).__name__}: {e}")
        started = time.monotonic()
        try:
            while not self._stop.is_set():
                if self.max_seconds and time.monotonic() - started > self.max_seconds:
                    break
                try:
                    yield self.q.get(timeout=0.5)
                except queue.Empty:
                    continue
        finally:
            try:
                sniffer.stop()
            except Exception:  # noqa: BLE001
                pass
