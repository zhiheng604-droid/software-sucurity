"""Identify a bounded HTTP/1.x start line using TCP sequence numbers."""

from __future__ import annotations

from array import array
from collections import OrderedDict
from dataclasses import dataclass
import re

LIMIT = 512
MAX_DIRECTIONS = 1024
IDLE_US = 30_000_000
MASK = (1 << 32) - 1
METHODS = (b'GET', b'POST', b'HEAD', b'PUT', b'DELETE', b'OPTIONS',
           b'PATCH', b'CONNECT', b'TRACE')
PREFIXES = tuple(method + b' ' for method in METHODS) + (b'HTTP/',)
HTTP_START = re.compile(
    rb'(?:HTTP/1\.[01] [1-5][0-9]{2}(?: [ -~]*)?|(?:'
    + b'|'.join(METHODS) + rb') [!-~]+ HTTP/1\.[01])'
)


def sequence_offset(sequence, origin):
    return ((sequence - origin + (1 << 31)) & MASK) - (1 << 31)


def plausible_prefix(data):
    return any(prefix.startswith(data) or data.startswith(prefix) for prefix in PREFIXES)


@dataclass
class Direction:
    origin: int
    last_seen: int
    from_syn: bool
    data: bytearray | None = None
    owners: array | None = None
    continuous: int = 0
    finished: bool = False
    reported_offset: int = -1

    def add(self, offset, payload, frame):
        end = min(LIMIT, offset + len(payload))
        start = max(0, offset)
        if start >= end:
            return None
        if self.data is None:
            self.data = bytearray(LIMIT)
            self.owners = array('Q', [0]) * LIMIT
        for position in range(start, end):
            if not self.owners[position]:
                self.data[position] = payload[position - offset]
                self.owners[position] = frame
        previous = self.continuous
        while self.continuous < LIMIT and self.owners[self.continuous]:
            self.continuous += 1
        if self.continuous == previous:
            return None
        line, separator, _ = self.data[:self.continuous].partition(b'\r\n')
        if separator:
            self.finished = True
            frames = tuple(dict.fromkeys(self.owners[:len(line) + 2]))
            self.data = self.owners = None
            if HTTP_START.fullmatch(line):
                self.reported_offset = 0
                return bytes(line), frames
        elif self.continuous == LIMIT or not plausible_prefix(bytes(line[:8])):
            self.finished = True
            self.data = self.owners = None
        return None


class HttpInspector:
    def __init__(self):
        self.directions = OrderedDict()
        self.clock = 0

    def observe(self, packet):
        segment = packet.tcp
        if segment is None:
            return
        self.clock = max(self.clock, packet.timestamp_us)
        while self.directions:
            oldest = next(iter(self.directions.values()))
            if self.clock - oldest.last_seen <= IDLE_US:
                break
            self.directions.popitem(last=False)
        key = ((packet.source, segment.source_port), (packet.destination, segment.destination_port))
        reverse = key[::-1]
        if segment.flags & 0x04:  # RST
            self.directions.pop(key, None)
            self.directions.pop(reverse, None)
            return
        syn = bool(segment.flags & 0x02)
        sequence = (segment.sequence + syn) & MASK
        state = self.directions.get(key)
        if syn and (state is None or not state.from_syn or state.origin != sequence):
            if not segment.flags & 0x10:
                self.directions.pop(reverse, None)
            state = self.keep(key, sequence, True)
        if state is not None:
            state.last_seen = self.clock
            self.directions.move_to_end(key)
        if not segment.payload_length:
            return
        start = segment.payload_offset
        payload = packet.raw[start:start + min(LIMIT, segment.payload_length)]
        if state is None:
            if not plausible_prefix(payload[:8]):
                return
            state = self.keep(key, sequence, False)

        offset = sequence_offset(sequence, state.origin)
        if not state.finished and offset < LIMIT:
            result = state.add(offset, payload, packet.number)
            if result:
                self.mark(packet, *result)
            return
        # Keep single-segment detection for later requests on persistent connections.
        # Do not report retransmissions of a previously emitted start line.
        if offset <= max(0, state.reported_offset) or offset < state.continuous:
            return
        first, separator, _ = payload.partition(b'\r\n')
        if separator and HTTP_START.fullmatch(first):
            state.reported_offset = offset
            self.mark(packet, first, (packet.number,))

    def keep(self, key, sequence, from_syn):
        state = Direction(sequence, self.clock, from_syn)
        self.directions[key] = state
        self.directions.move_to_end(key)
        if len(self.directions) > MAX_DIRECTIONS:
            self.directions.popitem(last=False)
        return state

    @staticmethod
    def mark(packet, line, frames):
        text = line.decode('ascii')
        packet.protocol = 'HTTP'
        packet.http_frames = frames
        packet.info += ' | ' + text[:100]
        packet.detail.append(('HTTP/1.x start line', text))
        if len(frames) > 1:
            packet.info += f' [跨 {len(frames)} 段]'
            packet.detail.append(('HTTP 首行来源帧（序号顺序）', ', '.join(map(str, frames))))
