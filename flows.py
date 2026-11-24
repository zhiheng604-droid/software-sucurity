"""Group both directions of a TCP conversation in the retained capture window."""

from collections import OrderedDict
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


def flow_identity(packet):
    endpoints = flow_key(packet)
    return (endpoints, packet.connection_id) if endpoints is not None else None


class ConnectionTracker:
    """Keep a bounded map from endpoint pair to its most recently observed connection."""

    def __init__(self, capacity=4096):
        self.capacity = capacity
        self.current = OrderedDict()

    def observe(self, packet):
        endpoints = flow_key(packet)
        segment = packet.tcp
        signature = None
        if segment.flags & 0x12 == 0x02:  # SYN without ACK
            signature = (packet.source, segment.source_port, segment.sequence)
        record = self.current.get(endpoints)
        if record is None or (signature is not None and signature != record[1]):
            record = (packet.number, signature)
            self.current[endpoints] = record
        self.current.move_to_end(endpoints)
        if len(self.current) > self.capacity:
            self.current.popitem(last=False)
        packet.connection_id, opener = record
        packet.connection_has_syn = opener is not None


@dataclass
class Flow:
    key: tuple
    earliest: int
    latest: int
    connection_id: int = 0
    start_observed: bool = False
    counts: list = field(default_factory=lambda: [0, 0])
    bytes: list = field(default_factory=lambda: [0, 0])
    syn: bool = False
    syn_ack: bool = False
    fin: set = field(default_factory=set)
    reset: bool = False

    def observe(self, packet):
        segment = packet.tcp
        direction = int((packet.source, segment.source_port) != self.key[0])
        self.earliest = min(self.earliest, packet.timestamp_us)
        self.latest = max(self.latest, packet.timestamp_us)
        self.counts[direction] += 1
        self.bytes[direction] += segment.payload_length
        self.syn |= segment.flags & 0x12 == 0x02
        self.syn_ack |= segment.flags & 0x12 == 0x12
        self.start_observed |= packet.connection_has_syn
        self.reset |= bool(segment.flags & 0x04)
        if segment.flags & 1:
            self.fin.add(direction)

    @property
    def identity(self):
        return self.key, self.connection_id

    @property
    def closed(self):
        return self.reset or len(self.fin) == 2

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
        if self.start_observed:
            return '起始帧已不在保留窗内'
        return '未观察到连接起始'


def summarize_flows(packets):
    flows = {}
    for packet in packets:
        identity = flow_identity(packet)
        if identity is None:
            continue
        if identity not in flows:
            endpoints, connection_id = identity
            flows[identity] = Flow(endpoints, packet.timestamp_us, packet.timestamp_us,
                                   connection_id)
        flows[identity].observe(packet)
    return sorted(flows.values(), key=lambda flow: flow.latest, reverse=True)


@dataclass(frozen=True, order=True)
class SocketOwner:
    pid: int
    command: str

    @property
    def label(self):
        return f'{self.command} ({self.pid})'


def bind_processes(flows, sockets):
    """Bind a current socket snapshot to the latest observed connection only."""
    latest = {}
    for flow in flows:
        previous = latest.get(flow.key)
        if previous is None or flow.connection_id > previous.connection_id:
            latest[flow.key] = flow
    return {flow.identity: sockets[flow.key] for flow in latest.values()
            if not flow.closed and flow.key in sockets}


def flows_for_process(flows, owners, pid=None):
    """Apply the same PID filter in the flow window and in verification."""
    return [flow for flow in flows
            if pid is None or any(owner.pid == pid for owner in owners.get(flow.identity, ()))]


def flow_process_options(flows, owners):
    visible = {owner for flow in flows for owner in owners.get(flow.identity, ())}
    return {owner.label: owner.pid for owner in sorted(visible)}


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
    pid, command = None, ''
    for line in result.stdout.splitlines():
        if line.startswith('p'):
            value = line[1:]
            pid, command = (int(value) if value.isdecimal() else None), ''
        elif line.startswith('c'):
            command = line[1:]
        elif line.startswith('n') and '->' in line and pid:
            left, right = line[1:].split('->', 1)
            try:
                key = tuple(sorted((_endpoint(left), _endpoint(right))))
            except ValueError:
                continue
            sockets.setdefault(key, set()).add(SocketOwner(pid, command or 'PID'))
    return sockets, '' if sockets else '当前快照没有可关联的已连接 TCP 套接字。'
