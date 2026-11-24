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
from verify_extended import LOOPBACK, MAGIC, PAYLOAD_SIZE, pace_udp, udp_payload

PROBE_FIELDS = struct.Struct('!IQ')


def timed_payload(index):
    data = bytearray(udp_payload(index))
    PROBE_FIELDS.pack_into(data, len(MAGIC), index, time.monotonic_ns())
    return data


def latency_summary(samples):
    ordered = sorted(samples)
    if not ordered:
        return None
    result = {'samples': len(ordered)}
    for label, fraction in (('p50_ms', .50), ('p95_ms', .95), ('p99_ms', .99), ('max_ms', 1)):
        result[label] = round(ordered[math.ceil(fraction * len(ordered)) - 1] / 1_000_000, 2)
    return result


def make_replay(path, count):
    addr = socket.inet_aton(LOOPBACK)
    frames = []
    for i in range(count):
        payload = MAGIC + struct.pack('!I', i) + bytes(PAYLOAD_SIZE - len(MAGIC) - 4)
        udp = struct.pack('!HHHH', 19000, 19001, 8 + len(payload), 0) + payload
        frames.append(ethernet(ip4(udp, 17, addr, addr), 0x0800))
    write_fixture(path, frames)


class GuiPerformance:
    def __init__(self, app, rate, duration, replay=None, display_filter=False):
        self.app = app
        self.root = app.root
        self.rate, self.duration = rate, duration
        self.replay = replay
        self.display_filter = display_filter
        self.stop_sockets = threading.Event()
        if replay is None:
            self.receivers = [socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                              for _ in range(2 if display_filter else 1)]
            self.sender = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            for receiver in self.receivers:
                receiver.bind((LOOPBACK, 0))
                receiver.settimeout(0.1)
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
        self.insert = app._insert_packet
        self.read = {}
        self.shown = {}
        self.cpu_at_start = None

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

    def drain_socket(self, receiver):
        while not self.stop_sockets.is_set():
            try:
                receiver.recv(2048)
            except socket.timeout:
                continue

    def datagrams(self):
        try:
            first = self.receivers[0].getsockname()
            second = self.receivers[-1].getsockname()
            payload = timed_payload if self.display_filter else udp_payload
            self.sent, self.elapsed = pace_udp(self.sender, (first, second),
                                               self.rate, self.duration, payload)
        except OSError as exc:
            self.problem = str(exc)

    def record_reads(self, pcap, request, stop, on_ready, on_packet, state):
        def observed(packet):
            timestamp = time.monotonic_ns()
            data = packet.raw[-PAYLOAD_SIZE:]
            if data.startswith(MAGIC):
                index, sent = PROBE_FIELDS.unpack_from(data, len(MAGIC))
                self.read.setdefault(index, (sent, timestamp))
            return on_packet(packet)

        run_capture(pcap, request, stop, on_ready, observed, state)

    def observe(self, packet):
        self.append(packet)
        data = packet.raw[-PAYLOAD_SIZE:]
        if data.startswith(MAGIC):
            self.delivered.add(int.from_bytes(data[len(MAGIC):len(MAGIC) + 4], 'big'))

    def observe_insert(self, packet):
        self.insert(packet)
        timestamp = time.monotonic_ns()
        data = packet.raw[-PAYLOAD_SIZE:]
        if data.startswith(MAGIC):
            index, _ = PROBE_FIELDS.unpack_from(data, len(MAGIC))
            self.shown.setdefault(index, timestamp)

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
        self.cpu_at_start = time.process_time_ns()
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
            for receiver in self.receivers:
                sink = threading.Thread(target=self.drain_socket, args=(receiver,), daemon=True)
                sink.start()
                self.participants.append(sink)
            port = self.sender.getsockname()[1]
            self.bpf = f'udp and src port {port}'
            if self.display_filter:
                netlens.run_capture = self.record_reads
                app._insert_packet = self.observe_insert
            app.start_source(CaptureRequest(interface=interface, expression=self.bpf), self.source)
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
                    if self.display_filter:
                        port = self.receivers[0].getsockname()[1]
                        self.expression = f'udp and ip.src = {LOOPBACK} and dst.port = {port} and caplen >= 128'
                        app.display_var.set(self.expression)
                        app.display_apply_button.invoke()
                        if app.display_predicate is None:
                            raise RuntimeError(app.display_status.get())
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
        report = {
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
        if self.display_filter:
            report.update(self.display_results())
        return report

    def display_results(self):
        goal = round(self.rate * self.duration)
        if sum(self.sent) != goal:
            raise RuntimeError('Incomplete probe stream')
        expected = set(range(goal))
        matching = set(range(0, goal, 2))
        reads, dequeued, shown = set(self.read), self.delivered, set(self.shown)
        if self.sent[0] != len(matching) or not shown <= dequeued <= reads <= expected:
            raise RuntimeError('Inconsistent probe stream across capture stages')
        displayed = matching & shown
        return {
            'capture_bpf': self.bpf,
            'expression': self.expression,
            'expected_to_show': len(matching),
            'capture_unique': len(reads),
            'capture_duplicates': self.app.result.received - len(reads),
            'missing_at_capture': len(expected - reads),
            'missing_between_capture_and_gui': len(reads - dequeued),
            'intentionally_hidden_at_gui': len(dequeued - matching - shown),
            'matched_missing_at_capture': len(matching - reads),
            'matched_missing_between_capture_and_gui': len(matching & (reads - dequeued)),
            'matched_missing_at_display': len(matching & (dequeued - shown)),
            'matched_displayed_unique': len(displayed),
            'unexpected_displayed_unique': len(shown - matching),
            'visible_at_end': self.app.visible,
            'process_cpu_ms': round((time.process_time_ns() - self.cpu_at_start) / 1_000_000, 2),
            'send_to_list': latency_summary([self.shown[i] - self.read[i][0] for i in displayed]),
            'send_to_read': latency_summary([self.read[i][1] - self.read[i][0] for i in displayed]),
            'read_to_list': latency_summary([self.shown[i] - self.read[i][1] for i in displayed]),
        }

    def close(self):
        import main as netlens
        self.app._append_packet = self.append
        self.app._insert_packet = self.insert
        self.stop_sockets.set()
        for thread in self.participants:
            thread.join(timeout=2)
        if self.replay is None:
            self.sender.close()
            for receiver in self.receivers:
                receiver.close()
        netlens.run_capture = run_capture


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--trials', type=int, default=3)
    parser.add_argument('--duration', type=float, default=2)
    parser.add_argument('--output', type=Path)
    parser.add_argument('--replay', action='store_true', help='pace a PCAP through the GUI without capture privileges')
    parser.add_argument('--display-filter', action='store_true',
                        help='measure live loopback with a combination filter matching half the UDP probes')
    args = parser.parse_args()
    if not 1 <= args.trials <= 5 or not 0.3 <= args.duration <= 5:
        parser.error('trials 1–5, duration 0.3–5 seconds')
    if args.replay and args.display_filter:
        parser.error('--display-filter requires live loopback')
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
        case = GuiPerformance(app, rate, args.duration, replay=fixtures.get(rate),
                              display_filter=args.display_filter)
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
    if args.display_filter:
        report['mode'] = 'live_with_display_filter'
    output = json.dumps(report, indent=2)
    if args.output:
        args.output.write_text(output + '\n')
    print(output)
    return 0


if __name__ == '__main__':
    sys.exit(main())
