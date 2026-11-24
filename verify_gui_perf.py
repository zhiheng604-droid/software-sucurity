"""Measure the real Tk packet list while NetLens captures local UDP traffic."""

import argparse
import json
import math
import os
from pathlib import Path
import socket
import struct
import sys
from tempfile import TemporaryDirectory
import threading
import time

from capture import CaptureRequest, run_capture
from demo_traffic import ethernet, ip4, write_fixture
from verify_extended import LOOPBACK, MAGIC, PAYLOAD_SIZE, pace_udp


def make_replay(path, count):
    addr = socket.inet_aton(LOOPBACK)
    frames = []
    for i in range(count):
        payload = MAGIC + struct.pack('!I', i) + bytes(PAYLOAD_SIZE - len(MAGIC) - 4)
        udp = struct.pack('!HHHH', 19000, 19001, 8 + len(payload), 0) + payload
        frames.append(ethernet(ip4(udp, 17, addr, addr), 0x0800))
    write_fixture(path, frames)


class GuiPerformance:
    def __init__(self, app, rate, duration, replay=None):
        self.app = app
        self.root = app.root
        self.rate, self.duration = rate, duration
        self.replay = replay
        self.stop_sockets = threading.Event()
        if replay is None:
            self.receiver = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.sender = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.receiver.bind((LOOPBACK, 0))
            self.receiver.settimeout(0.1)
            self.sender.bind((LOOPBACK, 0))
        self.participants = []
        self.sent, self.elapsed = None, None
        self.problem = None
        self.finished = False
        self.pending = False
        self.active_sender = False
        self.probe_delay = []
        self.delivered = set()
        self.window_mapped = False
        self.last = None
        self.deadline = time.monotonic() + duration + 12
        self.append = app._append_packet

    def replay_capture(self, pcap, _request, stop, on_ready, on_packet, state):
        start = None
        offered = 0

        def paced(packet):
            nonlocal start, offered
            if start is None:
                start = time.monotonic()
                self.active_sender = True
            deadline = start + offered / self.rate
            delay = deadline - time.monotonic()
            if delay > 0 and stop.wait(delay):
                return False
            offered += 1
            return on_packet(packet)

        # Exercise the normal parser and live queue policy with an offline PCAP.
        run_capture(pcap, CaptureRequest(path=str(self.replay)), stop, on_ready, paced, state)
        if start is not None:
            self.elapsed = time.monotonic() - start
            self.sent = (offered,)

    def drain_socket(self):
        while not self.stop_sockets.is_set():
            try:
                self.receiver.recv(2048)
            except socket.timeout:
                continue

    def datagrams(self):
        try:
            destination = self.receiver.getsockname()
            self.sent, self.elapsed = pace_udp(self.sender, (destination, destination),
                                               self.rate, self.duration)
        except OSError as exc:
            self.problem = str(exc)

    def observe(self, packet):
        self.append(packet)
        data = packet.raw[-PAYLOAD_SIZE:]
        if data.startswith(MAGIC):
            self.delivered.add(int.from_bytes(data[len(MAGIC):len(MAGIC) + 4], 'big'))

    def record_lag(self, due):
        if self.finished:
            return
        now = time.monotonic()
        if self.active_sender and self.sent is None and self.problem is None:
            self.probe_delay.append(max(0, (now - due) * 1000))
        self.root.after(20, lambda: self.record_lag(now + 0.020))

    def execute(self):
        import main as netlens
        app = self.app
        self.window_mapped = bool(self.root.winfo_ismapped() and app.packet_tree.winfo_ismapped())
        if not self.window_mapped:
            raise RuntimeError('Tk packet list is not mapped')
        self.pending = True
        app._append_packet = self.observe
        if self.replay is None:
            interface = next((name for name, _, flags in app.devices if flags & 1), None)
            if interface is None:
                raise RuntimeError('No loopback interface')
            self.source = interface.decode()
            sink = threading.Thread(target=self.drain_socket, daemon=True)
            sink.start()
            self.participants.append(sink)
            port = self.sender.getsockname()[1]
            app.start_source(CaptureRequest(interface=interface, expression=f'udp and src port {port}'),
                             self.source)
        else:
            self.source = 'paced PCAP replay'
            netlens.run_capture = self.replay_capture
            app.start_source(CaptureRequest(interface=b'replay'), self.source)
        self.root.after(20, lambda: self.record_lag(time.monotonic()))
        self.poll()

    def poll(self):
        app = self.app
        if time.monotonic() >= self.deadline:
            raise RuntimeError('Timed out waiting for Tk capture')
        if self.problem:
            raise RuntimeError(self.problem)
        if self.pending:
            if not app.running:
                raise RuntimeError(app.status_var.get())
            if app.opening is None:
                self.pending = False
                if self.replay is None:
                    self.active_sender = True
                    thread = threading.Thread(target=self.datagrams, daemon=True)
                    thread.start()
                    self.participants.append(thread)
        elif self.sent is not None:
            if self.last is None:
                self.last = time.monotonic() + 0.35
            elif time.monotonic() >= self.last:
                if not app.running:
                    self.finished = True
                    return
                if not app.stop_event.is_set():
                    app.stop_capture()
        self.root.after(20, self.poll)

    def results(self):
        if self.app.result.error:
            raise RuntimeError(self.app.result.error)
        if not self.probe_delay or self.sent is None or self.elapsed is None:
            raise RuntimeError('No valid GUI samples')
        sent = sum(self.sent)
        if not self.delivered <= set(range(sent)):
            raise RuntimeError('Unexpected sequence numbers received')
        lag = sorted(self.probe_delay)
        return {
            'interface': self.source,
            'window_mapped': self.window_mapped,
            'configured_pps': self.rate,
            'sent': sent,
            'send_seconds': round(self.elapsed, 4),
            'pcap_reads': self.app.result.received,
            'kernel_dropped': self.app.result.kernel_dropped,
            'queue_dropped': self.app.result.queue_dropped,
            'list_received_unique': len(self.delivered),
            'retained': len(self.app.packets),
            'evicted': self.app.evicted,
            'ui_samples': len(lag),
            'ui_p95_ms': round(lag[math.ceil(0.95 * len(lag)) - 1], 2),
            'ui_max_ms': round(lag[-1], 2),
        }

    def close(self):
        import main as netlens
        self.app._append_packet = self.append
        self.stop_sockets.set()
        for thread in self.participants:
            thread.join(timeout=2)
        if self.replay is None:
            self.sender.close()
            self.receiver.close()
        else:
            netlens.run_capture = run_capture


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--trials', type=int, default=3)
    parser.add_argument('--duration', type=float, default=2)
    parser.add_argument('--output', type=Path)
    parser.add_argument('--replay', action='store_true', help='pace a PCAP through the GUI without capture privileges')
    args = parser.parse_args()
    if not 1 <= args.trials <= 5 or not 0.3 <= args.duration <= 5:
        parser.error('trials 1–5, duration 0.3–5 seconds')
    os.environ.setdefault('TK_SILENCE_DEPRECATION', '1')
    from main import SnifferApp, tk
    root = tk.Tk()
    app = SnifferApp(root)
    settings = iter((trial, rate) for trial in range(1, args.trials + 1)
                    for rate in (1000, 4000, 8000))
    results = []
    workspace = TemporaryDirectory()
    fixtures = {}
    if args.replay:
        for rate in (1000, 4000, 8000):
            fixtures[rate] = Path(workspace.name)/f'{rate}.pcap'
            make_replay(fixtures[rate], round(rate * args.duration))
    case = None
    failure = None

    def start():
        nonlocal case
        try:
            trial, rate = next(settings)
        except StopIteration:
            root.destroy()
            return
        case = GuiPerformance(app, rate, args.duration, replay=fixtures.get(rate))
        case.execute()
        root.after(25, lambda: wait(trial))

    def wait(trial):
        nonlocal case
        if not case.finished:
            root.after(25, lambda: wait(trial))
            return
        results.append(dict(trial=trial, **case.results()))
        case.close()
        case = None
        root.after(120, start)

    def fail(_kind, exception, _trace):
        nonlocal failure
        failure = exception
        app.stop_event.set()
        root.destroy()

    root.report_callback_exception = fail
    tk_version = root.tk.call('info', 'patchlevel')
    root.after(200, start)
    try:
        root.mainloop()
    finally:
        if case is not None:
            case.close()
        workspace.cleanup()
    if failure:
        print(failure, file=sys.stderr)
        return 1
    report = {'python':sys.version.split()[0], 'tk':tk_version, 'pcap':app.pcap.version(),
              'seconds_per_trial':args.duration,
              'mode':'replay' if args.replay else 'live','gui':results}
    output = json.dumps(report, indent=2)
    if args.output:
        args.output.write_text(output + '\n')
    print(output)
    return 0


if __name__ == '__main__':
    sys.exit(main())
