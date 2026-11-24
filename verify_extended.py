"""Reproduce the HTTP, process and performance checks on the local loopback."""

import argparse
from contextlib import ExitStack, contextmanager
import json
import os
import platform
import selectors
import socket
from socketserver import StreamRequestHandler, ThreadingTCPServer
import struct
import subprocess
import sys
from pathlib import Path
import threading
import time

from capture import CaptureRequest, CaptureResult, Pcap, run_capture
from flows import find_local_processes, flow_process_options, flows_for_process, summarize_flows

LOOPBACK = '127.0.0.1'
PAYLOAD_SIZE = 128
MAGIC = b'NETLTEST'


class Session:
    def __init__(self, pcap, interface, expression, on_packet):
        self.linktype = None
        self.result = CaptureResult()
        self.ready = threading.Event()
        self.stop = threading.Event()
        self.cpu_seconds = 0.0
        request = CaptureRequest(interface=interface, expression=expression)

        def ready(linktype):
            self.linktype = linktype
            self.ready.set()

        def run():
            started = time.thread_time()
            run_capture(pcap, request, self.stop, ready, on_packet, self.result)
            self.cpu_seconds = time.thread_time() - started

        self.thread = threading.Thread(target=run, daemon=True)

    def __enter__(self):
        self.thread.start()
        if not self.ready.wait(2):
            self.stop.set()
            self.thread.join(2)
            raise RuntimeError(self.result.error or '抓包未在 2 秒内启动')
        return self

    def __exit__(self, *_exc):
        started = time.monotonic()
        self.stop.set()
        self.thread.join(2)
        self.stop_ms = round((time.monotonic() - started) * 1000, 3)
        if self.thread.is_alive() or self.result.error:
            raise RuntimeError(self.result.error or '抓包线程未正常结束')


def split_send(sock, fragments):
    for index, fragment in enumerate(fragments):
        if index:
            time.sleep(0.04)
        sock.sendall(fragment)


class SplitHandler(StreamRequestHandler):
    def handle(self):
        self.request.settimeout(10)
        self.request.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        while True:
            line = self.rfile.readline(2048)
            if line == b'\r\n':
                break
            if not line:
                return
        split_send(self.request, (b'HT', b'TP/1.1 200 ', b'OK\r', b'\nContent-Length: 0\r\n\r\n'))
        # Keep the server's endpoint open until the client releases it.
        try:
            self.request.recv(1)
        except socket.timeout:
            pass


def connected_client(port, label, count):
    with ExitStack() as sockets:
        local_ports = []
        for index in range(count):
            sock = sockets.enter_context(socket.create_connection((LOOPBACK, port), timeout=5))
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            target = f'/split-{label}-{index + 1}'.encode('ascii')
            split_send(sock, (b'G', b'ET ' + target + b' HTTP/1.1\r', b'\nHost: localhost\r\n\r\n'))
            response = bytearray()
            while b'\r\n\r\n' not in response:
                batch = sock.recv(4096)
                if not batch:
                    raise ConnectionError('响应提前结束')
                response.extend(batch)
            if not response.startswith(b'HTTP/1.1 200 OK\r\n'):
                raise RuntimeError('响应首行异常')
            local_ports.append(sock.getsockname()[1])
        print(json.dumps({'pid': os.getpid(), 'ports': local_ports}), flush=True)
        sys.stdin.read(1)


@contextmanager
def client(port, label, count):
    process = subprocess.Popen([sys.executable, '-B', str(Path(__file__).resolve()),
                                'client', str(port), label, str(count)],
                               stdin=subprocess.PIPE, stdout=subprocess.PIPE)
    try:
        with selectors.DefaultSelector() as ready:
            ready.register(process.stdout, selectors.EVENT_READ)
            if not ready.select(10):
                raise TimeoutError('等待本机客户端超时')
            line = process.stdout.readline()
        if not line:
            raise RuntimeError('本机客户端提前退出')
        yield json.loads(line)
    finally:
        process.stdin.close()
        try:
            process.wait(timeout=4)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()
        process.stdout.close()


def http_and_processes(pcap, interface):
    packets = []

    def retain(packet):
        packets.append(packet)
        return True

    with ThreadingTCPServer((LOOPBACK, 0), SplitHandler) as server:
        port = server.server_address[1]
        serving = threading.Thread(target=server.serve_forever, daemon=True)
        serving.start()
        try:
            with Session(pcap, interface, f'tcp port {port}', retain) as capture:
                with ExitStack() as workers:
                    clients = [workers.enter_context(client(port, 'a', 2)),
                               workers.enter_context(client(port, 'b', 1))]
                    snapshot, reason = find_local_processes()
                    time.sleep(0.2)
                    flows = summarize_flows(packets)
                    visible = flow_process_options(flows, snapshot)
                    selected = []
                    for proc in clients:
                        matching = flows_for_process(flows, snapshot, proc['pid'])
                        ports = sorted(p for flow in matching for _a, p in flow.key if p != port)
                        selected.append({'pid': proc['pid'], 'expected_ports': sorted(proc['ports']),
                                         'actual_ports': ports, 'flow_count': len(matching)})
                    lines = [{'frame': p.number, 'segments': p.http_frames, 'summary': p.info}
                             for p in packets if len(p.http_frames) > 1]
        finally:
            server.shutdown()
            serving.join()
    requests = [entry for entry in lines if 'GET /split-' in entry['summary']]
    responses = [entry for entry in lines if 'HTTP/1.1 200 OK' in entry['summary']]
    passed = (len(flows) == 3 and len(requests) == len(responses) == 3
              and all(len(x['segments']) == 3 for x in requests)
              and all(len(x['segments']) == 4 for x in responses)
              and all(rec['expected_ports'] == rec['actual_ports'] for rec in selected)
              and all(rec['pid'] in visible.values() for rec in selected))
    return {'passed': passed, 'server_port': port, 'flow_count': len(flows),
            'split_requests': requests, 'split_responses': responses,
            'clients': selected, 'snapshot_note': reason,
            'packet_count': capture.result.received, 'stop_ms': capture.stop_ms}


def pace_udp(sender, destinations, rate, duration):
    goal = round(rate * duration)
    counts = [0, 0]
    begin = time.monotonic()
    for index in range(goal):
        deadline = begin + index / rate
        remaining = deadline - time.monotonic()
        if remaining > 0:
            time.sleep(remaining)
        target = index % 2
        data = MAGIC + struct.pack('!I', index) + bytes(PAYLOAD_SIZE - len(MAGIC) - 4)
        if sender.sendto(data, destinations[target]) == len(data):
            counts[target] += 1
    return counts, time.monotonic() - begin


def measure(pcap, interface, rate, duration, mode):
    seen = set()
    duplicates = 0
    ports = []

    def observe(packet):
        nonlocal duplicates
        if packet.protocol != 'UDP':
            return True
        data = packet.raw[-PAYLOAD_SIZE:]
        if data[:len(MAGIC)] == MAGIC:
            index, = struct.unpack_from('!I', data, len(MAGIC))
            if index in seen:
                duplicates += 1
            seen.add(index)
        return True

    with ExitStack() as resources:
        receiver = []
        for _ in range(2):
            sock = resources.enter_context(socket.socket(socket.AF_INET, socket.SOCK_DGRAM))
            sock.bind((LOOPBACK, 0))
            sock.setblocking(False)
            receiver.append(sock)
        ports = [sock.getsockname() for sock in receiver]
        sender = resources.enter_context(socket.socket(socket.AF_INET, socket.SOCK_DGRAM))
        sender.bind((LOOPBACK, 0))
        expression = f'udp and src port {sender.getsockname()[1]}'
        if mode == 'target':
            expression += f' and dst port {ports[0][1]}'

        drain_stop = threading.Event()

        def drain():
            with selectors.DefaultSelector() as poll:
                for sock in receiver:
                    poll.register(sock, selectors.EVENT_READ)
                while not drain_stop.is_set():
                    for key, _ in poll.select(0.05):
                        sock = key.fileobj
                        for _ in range(256):
                            try:
                                sock.recv(2048)
                            except BlockingIOError:
                                break

        worker = threading.Thread(target=drain, daemon=True)
        worker.start()
        try:
            with Session(pcap, interface, expression, observe) as capture:
                sent, elapsed = pace_udp(sender, ports, rate, duration)
                time.sleep(0.35)  # Allow the read buffer to deliver its final batch.
        finally:
            drain_stop.set()
            worker.join()
    expected = sum(sent) if mode == 'all' else sent[0]
    matched = sum(0 <= n < sum(sent) and (mode == 'all' or n % 2 == 0) for n in seen)
    if not expected or matched > expected:
        raise RuntimeError('性能测量没有有效的发送基数')
    return {'configured_pps': rate, 'mode': mode, 'sent_total': sum(sent), 'expected': expected,
            'seen_unique': matched, 'unexpected_index': len(seen) - matched, 'duplicates': duplicates,
            'missing': expected - matched, 'kernel_dropped': capture.result.kernel_dropped,
            'pcap_reads': capture.result.received, 'send_seconds': round(elapsed, 4),
            'seen_pps': round(matched / elapsed, 1), 'capture_cpu_ms': round(capture.cpu_seconds * 1000, 2),
            'stop_ms': capture.stop_ms}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('mode', choices=['live', 'bench', 'all', 'client'])
    parser.add_argument('worker_args', nargs='*')
    parser.add_argument('--duration', type=float, default=2.0)
    parser.add_argument('--trials', type=int, default=3)
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    if args.mode == 'client':
        port, label, count = args.worker_args
        connected_client(int(port), label, int(count))
        return 0
    if args.worker_args or not 0.2 <= args.duration <= 5 or not 1 <= args.trials <= 5:
        parser.error('duration must be 0.2–5 seconds and trials 1–5')
    pcap = Pcap()
    interface = next((name for name, _, flags in pcap.interfaces() if flags & 1), None)
    if not interface:
        raise SystemExit('找不到回环接口')
    result = {'interface': interface.decode(), 'pcap': pcap.version(),
              'python': platform.python_version(), 'platform': platform.platform()}
    if args.mode != 'bench':
        result['live'] = http_and_processes(pcap, interface)
    if args.mode != 'live':
        result['bench'] = [dict(trial=index + 1, **measure(pcap, interface, rate, args.duration, kind))
                           for index in range(args.trials)
                           for rate, kind in ((1000, 'all'), (4000, 'all'), (8000, 'all'), (8000, 'target'))]
    rendered = json.dumps(result, ensure_ascii=False, indent=2)
    print(rendered)
    if args.output:
        args.output.write_text(rendered + '\n', encoding='utf-8')
    return 0 if result.get('live', {}).get('passed', True) else 1


if __name__ == '__main__':
    raise SystemExit(main())
