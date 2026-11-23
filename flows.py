"""Group both directions of a TCP conversation in the retained capture window."""

from dataclasses import dataclass, field
import ipaddress
import shutil
import subprocess


def flow_key(packet):
    if packet.tcp is None:
        return None
    source = (packet.source, packet.tcp.source_port)
    target = (packet.destination, packet.tcp.destination_port)
    return tuple(sorted((source, target)))


@dataclass
class Flow:
    key: tuple
    earliest: float
    latest: float
    counts: list = field(default_factory=lambda: [0, 0])
    bytes: list = field(default_factory=lambda: [0, 0])
    syn: bool = False
    syn_ack: bool = False
    fin: set = field(default_factory=set)
    reset: bool = False

    def observe(self, packet):
        segment = packet.tcp
        direction = int((packet.source, segment.source_port) != self.key[0])
        self.earliest = min(self.earliest, packet.timestamp)
        self.latest = max(self.latest, packet.timestamp)
        self.counts[direction] += 1
        self.bytes[direction] += segment.payload_length
        self.syn |= segment.flags & 0x12 == 0x02
        self.syn_ack |= segment.flags & 0x12 == 0x12
        self.reset |= bool(segment.flags & 0x04)
        if segment.flags & 1:
            self.fin.add(direction)

    @property
    def state(self):
        if self.reset:
            return '观察到 RST'
        if len(self.fin) == 2:
            return '双向 FIN'
        if self.fin:
            return '单向 FIN'
        if self.syn and self.syn_ack:
            return '观察到 SYN / SYN-ACK'
        if self.syn:
            return '观察到 SYN'
        return '未观察到连接起始'


def summarize_flows(packets):
    flows = {}
    for packet in packets:
        key = flow_key(packet)
        if key is None:
            continue
        if key not in flows:
            flows[key] = Flow(key, packet.timestamp, packet.timestamp)
        flows[key].observe(packet)
    return sorted(flows.values(), key=lambda flow: flow.latest, reverse=True)


def _endpoint(value):
    address, port = value.rsplit(':', 1)
    address = address.strip('[]').split('%', 1)[0]
    return (str(ipaddress.ip_address(address)), int(port))


def find_local_processes():
    """Return a best-effort snapshot of visible local TCP sockets using lsof."""
    executable = shutil.which('lsof')
    if not executable:
        return {}, '当前系统没有 lsof，无法读取本机 TCP 进程快照。'
    try:
        result = subprocess.run([executable, '-nP', '-iTCP', '-Fpcn'],
                                capture_output=True, text=True, errors='replace', timeout=4)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {}, f'无法读取本机 TCP 进程快照 · {exc}'
    sockets = {}
    pid, command = '', ''
    for line in result.stdout.splitlines():
        if line.startswith('p'):
            pid, command = line[1:], ''
        elif line.startswith('c'):
            command = line[1:]
        elif line.startswith('n') and '->' in line and pid:
            left, right = line[1:].split('->', 1)
            try:
                key = tuple(sorted((_endpoint(left), _endpoint(right))))
            except ValueError:
                continue
            sockets.setdefault(key, set()).add(f'{command} ({pid})')
    return sockets, '' if sockets else '当前快照没有可关联的已连接 TCP 套接字。'
