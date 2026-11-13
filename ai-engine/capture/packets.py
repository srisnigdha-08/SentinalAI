"""
Header-only packet parsing and a classic-PCAP reader, in pure Python (no capture driver needed for replay).

parse_frame() returns a PacketMeta built from the link, IP and TCP/UDP headers. The payload is measured (its
length) and then discarded: PacketMeta has no field that could hold payload bytes.
"""
import ipaddress
import struct
from dataclasses import dataclass
from typing import BinaryIO, Iterator, Optional

# Link types (tcpdump.org/linktypes.html)
LINKTYPE_NULL, LINKTYPE_ETHERNET, LINKTYPE_RAW, LINKTYPE_LOOP, LINKTYPE_LINUX_SLL = 0, 1, 101, 108, 113
SUPPORTED_LINKTYPES = (LINKTYPE_NULL, LINKTYPE_ETHERNET, LINKTYPE_RAW, LINKTYPE_LOOP, LINKTYPE_LINUX_SLL)
PROTO_TCP, PROTO_UDP = 6, 17
FIN, SYN, RST, PSH, ACK, URG = 0x01, 0x02, 0x04, 0x08, 0x10, 0x20
MAX_SNAPLEN = 262_144


class PcapError(ValueError):
    pass


@dataclass(frozen=True)
class PacketMeta:
    ts: float              # seconds since the epoch (float, microsecond resolution)
    src: str
    dst: str
    sport: int
    dport: int
    proto: int             # 6 TCP, 17 UDP
    payload_len: int       # L4 payload bytes (CICFlowMeter "packet length")
    header_len: int        # L4 header bytes (TCP data offset * 4, UDP 8)
    flags: int             # TCP flags byte (0 for UDP)
    window: int            # TCP window (-1 for UDP)


def _ip_layer(buf: bytes, off: int):
    """(src, dst, proto, l4_offset, l4_end) or None for anything that is not IPv4/IPv6."""
    if len(buf) < off + 1:
        return None
    version = buf[off] >> 4
    if version == 4:
        if len(buf) < off + 20:
            return None
        ihl = (buf[off] & 0x0F) * 4
        total = struct.unpack_from("!H", buf, off + 2)[0]
        frag = struct.unpack_from("!H", buf, off + 6)[0]
        if ihl < 20 or frag & 0x1FFF:  # malformed header, or a non-first fragment (no L4 header)
            return None
        src = str(ipaddress.IPv4Address(buf[off + 12:off + 16]))
        dst = str(ipaddress.IPv4Address(buf[off + 16:off + 20]))
        return src, dst, buf[off + 9], off + ihl, min(len(buf), off + total) if total else len(buf)
    if version == 6:
        if len(buf) < off + 40:
            return None
        plen = struct.unpack_from("!H", buf, off + 4)[0]
        src = str(ipaddress.IPv6Address(buf[off + 8:off + 24]))
        dst = str(ipaddress.IPv6Address(buf[off + 24:off + 40]))
        return src, dst, buf[off + 6], off + 40, min(len(buf), off + 40 + plen)  # extension headers: not followed
    return None


def parse_frame(buf: bytes, linktype: int, ts: float) -> Optional[PacketMeta]:
    """Parse one captured frame. Returns None for frames that are not TCP/UDP over IP (ARP, ICMP, ...)."""
    if linktype == LINKTYPE_ETHERNET:
        if len(buf) < 14:
            return None
        etype, off = struct.unpack_from("!H", buf, 12)[0], 14
        while etype in (0x8100, 0x88A8) and len(buf) >= off + 4:  # VLAN tags
            etype, off = struct.unpack_from("!H", buf, off + 2)[0], off + 4
        if etype not in (0x0800, 0x86DD):
            return None
    elif linktype == LINKTYPE_LINUX_SLL:
        if len(buf) < 16 or struct.unpack_from("!H", buf, 14)[0] not in (0x0800, 0x86DD):
            return None
        off = 16
    elif linktype in (LINKTYPE_NULL, LINKTYPE_LOOP):
        off = 4
    elif linktype == LINKTYPE_RAW:
        off = 0
    else:
        raise PcapError(f"unsupported link type {linktype}")
    ip = _ip_layer(buf, off)
    if ip is None:
        return None
    src, dst, proto, l4, end = ip
    if proto == PROTO_TCP:
        if end < l4 + 20:
            return None
        sport, dport = struct.unpack_from("!HH", buf, l4)
        hlen = (buf[l4 + 12] >> 4) * 4
        if hlen < 20:
            return None
        flags, window = buf[l4 + 13] & 0x3F, struct.unpack_from("!H", buf, l4 + 14)[0]
        return PacketMeta(ts, src, dst, sport, dport, proto, max(0, end - l4 - hlen), hlen, flags, window)
    if proto == PROTO_UDP:
        if end < l4 + 8:
            return None
        sport, dport = struct.unpack_from("!HH", buf, l4)
        return PacketMeta(ts, src, dst, sport, dport, proto, max(0, end - l4 - 8), 8, 0, -1)
    return None


def read_pcap(stream: BinaryIO, max_packets: Optional[int] = None) -> Iterator[PacketMeta]:
    """Classic libpcap files (both byte orders, micro- and nanosecond). pcapng is refused with a clear error."""
    head = stream.read(24)
    if len(head) < 24:
        raise PcapError("file too short for a pcap header")
    magic = head[:4]
    if magic == b"\x0a\x0d\x0d\x0a":
        raise PcapError("pcapng is not supported; convert with: editcap -F pcap in.pcapng out.pcap")
    table = {b"\xd4\xc3\xb2\xa1": ("<", 1e-6), b"\xa1\xb2\xc3\xd4": (">", 1e-6),
             b"\x4d\x3c\xb2\xa1": ("<", 1e-9), b"\xa1\xb2\x3c\x4d": (">", 1e-9)}
    if magic not in table:
        raise PcapError("not a pcap file (bad magic number)")
    endian, unit = table[magic]
    linktype = struct.unpack(endian + "I", head[20:24])[0] & 0x0FFFFFFF
    if linktype not in SUPPORTED_LINKTYPES:
        raise PcapError(f"unsupported link type {linktype}")
    n = 0
    while max_packets is None or n < max_packets:
        rec = stream.read(16)
        if len(rec) < 16:
            return
        sec, frac, incl, _orig = struct.unpack(endian + "IIII", rec)
        if incl > MAX_SNAPLEN:
            raise PcapError(f"record length {incl} exceeds {MAX_SNAPLEN}: corrupt file")
        data = stream.read(incl)
        if len(data) < incl:
            return
        n += 1
        meta = parse_frame(data, linktype, sec + frac * unit)
        del data  # the frame (and any payload in it) is not kept
        if meta is not None:
            yield meta


def write_pcap(path, frames, linktype=LINKTYPE_ETHERNET):
    """Write (ts, frame_bytes) pairs as a classic little-endian microsecond pcap. Used by tests and fixtures."""
    with open(path, "wb") as f:
        f.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, linktype))
        for ts, frame in frames:
            sec = int(ts)
            usec = int(round((ts - sec) * 1e6))
            f.write(struct.pack("<IIII", sec, usec, len(frame), len(frame)))
            f.write(frame)


def build_tcp_frame(src, dst, sport, dport, flags, window=29200, payload_len=0, options_len=0):
    """An Ethernet/IPv4/TCP frame with `payload_len` zero bytes (synthetic, for tests and fixtures)."""
    hlen = 20 + options_len
    tcp = struct.pack("!HHIIBBHHH", sport, dport, 0, 0, (hlen // 4) << 4, flags, window, 0, 0) + b"\x01" * options_len
    total = 20 + len(tcp) + payload_len
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, total, 0, 0, 64, PROTO_TCP, 0,
                     ipaddress.IPv4Address(src).packed, ipaddress.IPv4Address(dst).packed)
    return b"\x00" * 12 + b"\x08\x00" + ip + tcp + b"\x00" * payload_len


def build_udp_frame(src, dst, sport, dport, payload_len=0):
    udp = struct.pack("!HHHH", sport, dport, 8 + payload_len, 0)
    total = 20 + 8 + payload_len
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, total, 0, 0, 64, PROTO_UDP, 0,
                     ipaddress.IPv4Address(src).packed, ipaddress.IPv4Address(dst).packed)
    return b"\x00" * 12 + b"\x08\x00" + ip + udp + b"\x00" * payload_len
