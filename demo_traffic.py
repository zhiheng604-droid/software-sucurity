"""Generate private demo fixtures and exercise only the local loopback interface."""

import argparse
from collections import Counter
import http.client
from http.server import BaseHTTPRequestHandler, HTTPServer
from ipaddress import ip_address
from pathlib import Path
import socket
import struct
import threading
import time

PORT = 18765
STAMP = 1795406400
HERE = Path(__file__).resolve().parent


def checksum(data):
    if len(data) % 2:
        data += b'\0'
    total = sum(value for (value,) in struct.iter_unpack('!H', data))
    while total >> 16:
        total = (total & 65535) + (total >> 16)
    return (~total) & 65535


def ethernet(payload, kind):
    return bytes.fromhex('020000000002020000000001') + struct.pack('!H', kind) + payload


def ip4(payload, protocol, source, target):
    header = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(payload), 23,
                         0x4000, 64, protocol, 0, source, target)
    return header[:10] + struct.pack('!H', checksum(header)) + header[12:] + payload


def ip6(payload, protocol, source, target):
    return struct.pack('!IHBB', 0x60000000, len(payload), protocol, 64) + source + target + payload


def tcp(source, target, sport, dport, seq, ack, flags, data):
    header = struct.pack('!HHIIBBHHH', sport, dport, seq, ack, 0x50, flags, 32768, 0, 0)
    pseudo = source + target + struct.pack('!BBH', 0, 6, len(header) + len(data))
    return header[:16] + struct.pack('!H', checksum(pseudo + header + data)) + header[18:] + data


def make_fixture(path):
    a = ip_address('192.0.2.10').packed
    b = ip_address('198.51.100.20').packed
    c = ip_address('2001:db8::10').packed
    d = ip_address('2001:db8::20').packed
    message = b'GET /netlens-demo HTTP/1.1\r\nHost: demo.invalid\r\n\r\n'
    response = b'HTTP/1.1 200 OK\r\nContent-Length: 8\r\n\r\nNetLens\n'
    stream = [
        (False, 100, 0, 2, b''), (True, 200, 101, 0x12, b''),
        (False, 101, 201, 0x10, b''), (False, 101, 201, 0x18, message),
        (True, 201, 101 + len(message), 0x18, response),
        (False, 101 + len(message), 201 + len(response), 0x11, b''),
        (True, 201 + len(response), 102 + len(message), 0x11, b''),
        (False, 102 + len(message), 202 + len(response), 0x10, b''),
    ]
    frames = []
    for reverse, seq, ack, flags, data in stream:
        src, dst = (b, a) if reverse else (a, b)
        sport, dport = (PORT, 50000) if reverse else (50000, PORT)
        frames.append(ethernet(ip4(tcp(src, dst, sport, dport, seq, ack, flags, data),
                                   6, src, dst), 0x0800))
    udp = struct.pack('!HHHH', 53001, 9999, 12, 0) + b'DEMO'
    frames.append(ethernet(ip4(udp, 17, a, b), 0x0800))
    udp6 = struct.pack('!HHHH', 53002, 9999, 12, 0) + b'DEMO'
    pseudo6 = c + d + struct.pack('!I3xB', len(udp6), 17)
    udp6 = udp6[:6] + struct.pack('!H', checksum(pseudo6 + udp6) or 65535) + udp6[8:]
    frames.append(ethernet(ip6(bytes([17, 0]) + bytes(6) + udp6, 60, c, d), 0x86dd))
    echo = struct.pack('!BBHHH4s', 8, 0, 0, 42, 1, b'DEMO')
    echo = echo[:2] + struct.pack('!H', checksum(echo)) + echo[4:]
    frames.append(ethernet(ip4(echo, 1, a, b), 0x0800))
    echo6 = struct.pack('!BBHHH4s', 128, 0, 0, 42, 1, b'DEMO')
    pseudo6 = c + d + struct.pack('!I3xB', len(echo6), 58)
    echo6 = echo6[:2] + struct.pack('!H', checksum(pseudo6 + echo6)) + echo6[4:]
    frames.append(ethernet(ip6(echo6, 58, c, d), 0x86dd))
    arp = struct.pack('!HHBBH6s4s6s4s', 1, 0x0800, 6, 4, 1,
                      bytes.fromhex('020000000001'), a, bytes(6), b)
    frames.append(ethernet(arp, 0x0806))
    frames.append(ethernet(struct.pack('!HH', 7, 0x0800) + ip4(udp, 17, a, b), 0x8100))
    frames.append(frames[3])  # Separately truncate this copy at capture time.
    write_fixture(path, frames, truncate_last=True)


def write_fixture(path, frames, truncate_last=False):
    with path.open('wb') as file:
        file.write(struct.pack('<IHHIIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        for index, frame in enumerate(frames):
            captured = frame[:32] if truncate_last and index == len(frames) - 1 else frame
            seconds, micros = divmod(1000 + index * 20000, 1_000_000)
            file.write(struct.pack('<IIII', STAMP + seconds, micros, len(captured), len(frame)))
            file.write(captured)


def make_split_fixture(path, omit_middle=False):
    """Capture order deliberately differs from stream order in the request."""
    a = ip_address('192.0.2.10').packed
    b = ip_address('198.51.100.20').packed
    isn = 0xfffffffc
    start = isn + 1
    head, mid, tail = b'GE', b'T /split HTTP/1.1\r', b'\n'
    server = 201
    end = (start + len(head + mid + tail)) & 0xffffffff
    rows = [
        (False, isn, 0, 0x02, b''),
        (True, server - 1, start, 0x12, b''),
        (False, start + len(head + mid), server, 0x18, tail),
        (False, start, server, 0x18, head),
        (False, start, server, 0x18, head),  # Exact retransmission.
    ]
    if not omit_middle:
        rows.append((False, start + len(head), server, 0x18, mid))
    rows.extend([
        (True, server, end, 0x18, b'HTTP/'),
        (True, server + 5, end, 0x18, b'1.1 200 OK\r\n'),
        (False, start, server, 0x18, head),
    ])
    frames = []
    for reverse, seq, ack, flags, payload in rows:
        source, target = (b, a) if reverse else (a, b)
        sport, dport = (PORT, 50000) if reverse else (50000, PORT)
        segment = tcp(source, target, sport, dport, seq & 0xffffffff, ack, flags, payload)
        frames.append(ethernet(ip4(segment, 6, source, target), 0x0800))
    write_fixture(path, frames)


def make_reuse_fixture(path):
    """Two observed TCP handshakes reuse the same endpoints. The first SYN is retried."""
    a = ip_address('192.0.2.10').packed
    b = ip_address('198.51.100.20').packed
    observations = [
        (False, 100, 0, 0x02), (False, 100, 0, 0x02),
        (True, 200, 101, 0x12), (False, 101, 201, 0x10),
        (False, 800, 0, 0x02), (True, 950, 801, 0x12),
        (False, 801, 951, 0x10),
    ]
    frames = []
    for reverse, seq, ack, flags in observations:
        source, target = (b, a) if reverse else (a, b)
        sport, dport = (PORT, 50000) if reverse else (50000, PORT)
        segment = tcp(source, target, sport, dport, seq, ack, flags, b'')
        frames.append(ethernet(ip4(segment, 6, source, target), 0x0800))
    write_fixture(path, frames)


class DemoHandler(BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'

    def do_GET(self):
        payload = b'NetLens loopback demo\n'
        self.send_response(200)
        self.send_header('Content-Length', str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, *_args):
        pass


def generate(hold=0):
    """Produce ordinary HTTP and UDP requests, addressed solely to 127.0.0.1."""
    with HTTPServer(('127.0.0.1', PORT), DemoHandler) as server:
        worker = threading.Thread(target=server.serve_forever, daemon=True)
        worker.start()
        try:
            conn = http.client.HTTPConnection('127.0.0.1', PORT, timeout=3)
            try:
                conn.request('GET', '/netlens-demo')
                response = conn.getresponse()
                response.read()
                if response.status != 200:
                    raise RuntimeError(f'HTTP status {response.status}')
                from flows import find_local_processes
                process_map, _ = find_local_processes()
                matched = any(('127.0.0.1', PORT) in key for key in process_map)
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as receiver:
                    receiver.bind(('127.0.0.1', 0))
                    receiver.settimeout(2)
                    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sender:
                        sender.sendto(b'NetLens UDP demo', receiver.getsockname())
                    receiver.recvfrom(1024)
                if hold:
                    print(f'HTTP 200、UDP 已发送。HTTP 连接保留 {hold} 秒，可回到 NetLens 查看进程。', flush=True)
                    time.sleep(hold)
            finally:
                conn.close()
        finally:
            server.shutdown()
            worker.join()
    return matched


def verify_live(output):
    """Run the underlying real capture engine and verify its results."""
    from capture import Pcap, CaptureRequest, CaptureResult, run_capture
    from flows import summarize_flows
    pcap = Pcap()
    devices = pcap.interfaces()
    interface = next((name for name, _, flags in devices if flags & 1), None)
    if not interface:
        raise SystemExit('找不到回环接口')
    stop, ready = threading.Event(), threading.Event()
    packets, state = [], CaptureResult()

    def append(packet):
        packets.append(packet)
        return True

    request = CaptureRequest(interface=interface,
                             expression=f'(tcp port {PORT}) or (udp and host 127.0.0.1)')
    loader = threading.Thread(target=run_capture,
                              args=(pcap, request, stop, lambda _: ready.set(), append, state),
                              daemon=True)
    loader.start()
    try:
        if not ready.wait(2):
            raise RuntimeError(state.error or '等待抓包句柄超时')
        matched = generate()
        time.sleep(0.35)
    finally:
        stopped = time.monotonic()
        stop.set()
        loader.join(2)
        latency = round((time.monotonic() - stopped) * 1000, 1)
    from json import dumps
    counts = Counter(packet.protocol for packet in packets)
    flows = summarize_flows(packets)
    http = any(packet.protocol == 'HTTP' and 'GET /netlens-demo' in packet.info for packet in packets)
    bidirectional = any(all(flow.counts) and all(flow.bytes) for flow in flows)
    passed = bool(http and counts['UDP'] and bidirectional and not loader.is_alive() and not state.error)
    report = {
        'passed': passed, 'version': pcap.version(), 'interface': interface.decode(),
        'counts': counts, 'bidirectional_http': bidirectional, 'http_request': http,
        'process_match': matched, 'stop_latency_ms': latency,
        'driver_drops': state.kernel_dropped, 'error': state.error,
    }
    rendered = dumps(report, indent=2)
    print(rendered)
    if output:
        Path(output).write_text(rendered + '\n')
    return 0 if passed else 1


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('mode', choices=['fixture', 'split-fixture', 'reuse-fixture',
                                         'talk', 'live-check'])
    parser.add_argument('--output', help='Output path for the fixture or live-check JSON')
    parser.add_argument('--hold', type=int, default=0, metavar='SECONDS',
                        help='Keep the loopback HTTP connection open for the recording')
    args = parser.parse_args()
    if not 0 <= args.hold <= 120 or (args.hold and args.mode != 'talk'):
        parser.error('--hold takes 0–120 seconds and applies only to talk')
    if args.mode == 'fixture':
        make_fixture(Path(args.output) if args.output else HERE / 'netlens_demo.pcap')
    elif args.mode == 'split-fixture':
        make_split_fixture(Path(args.output) if args.output else HERE / 'netlens_http_split.pcap')
    elif args.mode == 'reuse-fixture':
        make_reuse_fixture(Path(args.output) if args.output else HERE / 'netlens_tcp_reuse.pcap')
    elif args.mode == 'talk':
        print('HTTP and UDP loopback complete. Local process match:', generate(args.hold))
    else:
        raise SystemExit(verify_live(args.output))
