"""Decode captured packets without reading beyond the captured or declared IP length."""

from __future__ import annotations

import ipaddress
import re
import time
from dataclasses import dataclass
from typing import List, Optional, Tuple

DLT_NULL = 0
DLT_EN10MB = 1
DLT_LOOP = 108
DLT_RAW_CANDIDATES = {12, 101}
DLT_IPV4 = 228
DLT_IPV6 = 229
DLT_LINUX_SLL = 113
DLT_LINUX_SLL2 = 276
HTTP_START = re.compile(
    rb'(?:HTTP/1\.[01] [1-5][0-9]{2}(?: [ -~]*)?|'
    rb'(?:GET|POST|HEAD|PUT|DELETE|OPTIONS|PATCH|CONNECT|TRACE) [!-~]+ HTTP/1\.[01])'
)


@dataclass(frozen=True)
class TcpSegment:
    source_port: int
    destination_port: int
    sequence: int
    flags: int
    payload_length: int


@dataclass
class Packet:
    number: int
    timestamp_us: int
    captured_length: int
    wire_length: int
    source: str
    destination: str
    protocol: str
    info: str
    detail: List[Tuple[str, str]]
    raw: bytes
    tcp: Optional[TcpSegment] = None


def _u16(data: bytes, pos: int) -> int:
    return int.from_bytes(data[pos:pos + 2], "big")


def _u32(data: bytes, pos: int) -> int:
    return int.from_bytes(data[pos:pos + 4], "big")


def _ip_text(raw: bytes) -> str:
    try:
        return str(ipaddress.ip_address(raw))
    except ValueError:
        return "?"


def _parse_packet(raw: bytes, linktype: int, number: int, timestamp_us: int,
                  wire_length: int) -> Packet:
    seconds, micros = divmod(timestamp_us, 1_000_000)
    detail: List[Tuple[str, str]] = [
        ("Capture", f"Frame {number}"),
        ("Timestamp", time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(seconds))
         + f".{micros:06d}"),
        ("Captured length", f"{len(raw)} bytes"),
        ("Wire length", f"{wire_length} bytes"),
        ("Link type", str(linktype)),
    ]
    src = dst = "?"
    protocol = "Other"
    info = "Unrecognized or truncated packet"
    offset = 0
    tcp = None
    ethertype: Optional[int] = None

    if linktype == DLT_EN10MB:
        if len(raw) < 14:
            return Packet(number, timestamp_us, len(raw), wire_length, src, dst,
                          "Other", "Truncated Ethernet header", detail, raw)
        dst_mac = ":".join(f"{b:02x}" for b in raw[0:6])
        src_mac = ":".join(f"{b:02x}" for b in raw[6:12])
        ethertype = _u16(raw, 12)
        offset = 14
        detail.extend([("Ethernet", ""), ("  Source MAC", src_mac),
                       ("  Destination MAC", dst_mac), ("  EtherType", f"0x{ethertype:04x}")])
        vlan_count = 0
        while ethertype in (0x8100, 0x88A8, 0x9100) and len(raw) >= offset + 4 and vlan_count < 2:
            tci = _u16(raw, offset)
            ethertype = _u16(raw, offset + 2)
            detail.append(("  VLAN", f"ID {tci & 0x0fff}, priority {(tci >> 13) & 7}"))
            offset += 4
            vlan_count += 1
    elif linktype in (DLT_NULL, DLT_LOOP):
        if len(raw) < 4:
            return Packet(number, timestamp_us, len(raw), wire_length, src, dst,
                          "Other", "Truncated loopback header", detail, raw)
        family = int.from_bytes(raw[:4], 'big' if linktype == DLT_LOOP else 'little')
        if linktype == DLT_NULL and family > 65535:
            family = int.from_bytes(raw[:4], 'big')
        # macOS, BSD, and Linux use different AF_INET6 values; the IP version nibble is authoritative.
        version = raw[4] >> 4 if len(raw) > 4 else 0
        ethertype = 0x0800 if version == 4 else 0x86DD if version == 6 else None
        offset = 4
        detail.extend([("Loopback", ""), ("  Address family", str(family))])
    elif linktype in (DLT_LINUX_SLL, DLT_LINUX_SLL2):
        offset = 16 if linktype == DLT_LINUX_SLL else 20
        if len(raw) < offset:
            return Packet(number, timestamp_us, len(raw), wire_length, src, dst,
                          "Other", "Truncated Linux cooked header", detail, raw)
        ethertype = _u16(raw, 14 if offset == 16 else 0)
        detail.extend([("Linux cooked", ""), ("  Protocol", f"0x{ethertype:04x}")])
    elif linktype in DLT_RAW_CANDIDATES:
        version = raw[0] >> 4 if raw else 0
        ethertype = 0x0800 if version == 4 else 0x86DD if version == 6 else None
    elif linktype == DLT_IPV4:
        ethertype = 0x0800
    elif linktype == DLT_IPV6:
        ethertype = 0x86DD
    else:
        detail.append(("Parser", "This link-layer type is not decoded by the current version."))

    if ethertype == 0x0800:
        if len(raw) < offset + 20:
            return Packet(number, timestamp_us, len(raw), wire_length, src, dst,
                          "IPv4", "Truncated IPv4 header", detail, raw)
        first = raw[offset]
        ihl = (first & 0x0f) * 4
        if first >> 4 != 4 or ihl < 20 or len(raw) < offset + ihl:
            return Packet(number, timestamp_us, len(raw), wire_length, src, dst,
                          "IPv4", "Invalid IPv4 header length", detail, raw)
        total_len = _u16(raw, offset + 2)
        ident = _u16(raw, offset + 4)
        flags_frag = _u16(raw, offset + 6)
        ttl = raw[offset + 8]
        proto_num = raw[offset + 9]
        src = _ip_text(raw[offset + 12:offset + 16])
        dst = _ip_text(raw[offset + 16:offset + 20])
        proto_name = {1: "ICMP", 6: "TCP", 17: "UDP"}.get(proto_num, f"IP protocol {proto_num}")
        detail.extend([("IPv4", ""), ("  Source", src), ("  Destination", dst),
                       ("  Header length", f"{ihl} bytes"), ("  Total length", f"{total_len} bytes"),
                       ("  Identification", f"0x{ident:04x}"), ("  TTL", str(ttl)),
                       ("  Protocol", proto_name),
                       ("  Fragment offset", str(flags_frag & 0x1fff))])
        transport = offset + ihl
        protocol = "IPv4"
        if total_len < ihl:
            info = "IPv4 total length precedes transport header"
        elif flags_frag & 0x1fff:
            info = "IPv4 non-first fragment"
        else:
            ip_end = offset + total_len
            if ip_end > len(raw):
                detail.append(("Capture note", "IPv4 datagram partially captured"))
            protocol, info, tcp = _parse_transport(raw[:ip_end], transport, proto_num, 4, detail)
    elif ethertype == 0x86DD:
        if len(raw) < offset + 40 or raw[offset] >> 4 != 6:
            return Packet(number, timestamp_us, len(raw), wire_length, src, dst,
                          "IPv6", "Truncated or invalid IPv6 header", detail, raw)
        payload_len = _u16(raw, offset + 4)
        next_header = raw[offset + 6]
        hop_limit = raw[offset + 7]
        src = _ip_text(raw[offset + 8:offset + 24])
        dst = _ip_text(raw[offset + 24:offset + 40])
        detail.extend([("IPv6", ""), ("  Source", src), ("  Destination", dst),
                       ("  Payload length", f"{payload_len} bytes"), ("  Hop limit", str(hop_limit))])
        pos = offset + 40
        # Bound transport reads to the IP payload, excluding Ethernet padding.
        ip_end = pos + payload_len
        if ip_end > len(raw):
            detail.append(("Capture note", "IPv6 datagram partially captured"))
        ip = raw[:ip_end]
        extension_headers = {0, 43, 44, 51, 60}
        for _ in range(8):
            if next_header in (0, 43, 60):  # Hop-by-hop, routing, destination options
                if len(ip) < pos + 2:
                    break
                new_next, ext_len = ip[pos], (ip[pos + 1] + 1) * 8
                if ext_len < 8 or len(ip) < pos + ext_len:
                    break
                detail.append(("IPv6 extension", f"next header {new_next}, {ext_len} bytes"))
                next_header, pos = new_next, pos + ext_len
            elif next_header == 44:  # Fragment
                if len(ip) < pos + 8:
                    break
                new_next = ip[pos]
                frag = _u16(ip, pos + 2)
                detail.append(("IPv6 fragment", f"offset {(frag >> 3) & 0x1fff}"))
                next_header, pos = new_next, pos + 8
                if frag & 0xfff8:
                    next_header = -1
                    break
            elif next_header == 51:  # Authentication header
                if len(ip) < pos + 2:
                    break
                new_next, ext_len = ip[pos], (ip[pos + 1] + 2) * 4
                if ext_len < 8 or len(ip) < pos + ext_len:
                    break
                detail.append(("IPv6 AH", f"{ext_len} bytes"))
                next_header, pos = new_next, pos + ext_len
            else:
                break
        if next_header == -1:
            protocol, info = "IPv6", "IPv6 non-first fragment"
        elif next_header in extension_headers:
            protocol, info = "IPv6", "Truncated or too many IPv6 extension headers"
        elif next_header == 59 or payload_len == 0:
            protocol, info = "IPv6", "No decoded IPv6 payload"
        else:
            protocol, info, tcp = _parse_transport(ip, pos, next_header, 6, detail)
    elif ethertype == 0x0806:
        protocol, info = "ARP", "Address resolution"
        if (len(raw) >= offset + 28 and _u16(raw, offset) == 1
                and _u16(raw, offset + 2) == 0x0800 and raw[offset + 4:offset + 6] == b"\x06\x04"):
            src = ":".join(f"{b:02x}" for b in raw[offset + 8:offset + 14])
            dst = ":".join(f"{b:02x}" for b in raw[offset + 18:offset + 24])
            detail.extend([("ARP", ""), ("  Sender MAC", src), ("  Target MAC", dst),
                           ("  Operation", str(_u16(raw, offset + 6)))])
    else:
        info = "Ethernet type not decoded" if ethertype is not None else "No supported network layer found"

    return Packet(number, timestamp_us, len(raw), wire_length, src, dst, protocol, info, detail, raw, tcp)


def _parse_transport(raw, pos, proto_num, version, detail):
    names = {6: "TCP", 17: "UDP", 1: "ICMP", 58: "ICMPv6"}
    if proto_num not in names:
        return f"IPv{version}", f"IP protocol {proto_num}", None
    name = names[proto_num]
    if proto_num == 6:
        if len(raw) < pos + 20:
            return "TCP", "Truncated TCP header", None
        sport, dport = _u16(raw, pos), _u16(raw, pos + 2)
        seq, ack = _u32(raw, pos + 4), _u32(raw, pos + 8)
        header_len = ((raw[pos + 12] >> 4) & 0xf) * 4
        flags = raw[pos + 13]
        if header_len < 20 or len(raw) < pos + header_len:
            return "TCP", "Invalid TCP header length", None
        detail.extend([("TCP", ""), ("  Source port", str(sport)), ("  Destination port", str(dport)),
                       ("  Sequence", str(seq)), ("  Acknowledgment", str(ack)),
                       ("  Header length", f"{header_len} bytes"),
                       ("  Flags", ", ".join(n for bit, n in [(0x02, "SYN"), (0x10, "ACK"),
                           (0x01, "FIN"), (0x04, "RST"), (0x08, "PSH"), (0x20, "URG")]
                           if flags & bit) or "none"), ("  Window", str(_u16(raw, pos + 14)))])
        payload = raw[pos + header_len:]
        summary = f"{sport} → {dport}"
        if flags & 0x02:
            summary += " [SYN, ACK]" if flags & 0x10 else " [SYN]"
        if flags & 0x01:
            summary += " [FIN]"
        if flags & 0x04:
            summary += " [RST]"
        segment = TcpSegment(sport, dport, seq, flags, len(payload))
        first, separator, _ = payload[:512].partition(b"\r\n")
        if separator and HTTP_START.fullmatch(first):
            text = first.decode("ascii")
            detail.append(("HTTP/1.x start line", text))
            return "HTTP", f"{summary} | {text[:100]}", segment
        return "TCP", summary, segment
    if proto_num == 17:
        if len(raw) < pos + 8:
            return "UDP", "Truncated UDP header", None
        sport, dport, length = _u16(raw, pos), _u16(raw, pos + 2), _u16(raw, pos + 4)
        if length < 8:
            return "UDP", "Invalid UDP length", None
        detail.extend([("UDP", ""), ("  Source port", str(sport)), ("  Destination port", str(dport)),
                       ("  Length", f"{length} bytes"), ("  Checksum", f"0x{_u16(raw, pos + 6):04x}")])
        return "UDP", f"{sport} → {dport}", None
    if len(raw) < pos + 4:
        return name, f"Truncated {name} header", None
    kind, code = raw[pos], raw[pos + 1]
    detail.extend([(name, ""), ("  Type", str(kind)), ("  Code", str(code))])
    return name, f"type {kind}, code {code}", None


