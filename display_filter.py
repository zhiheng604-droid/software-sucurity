"""Compile a bounded display expression into predicates over retained packets."""

import ipaddress
import operator
import re


class DisplayFilterError(ValueError):
    pass


def has_layer(packet, kind):
    return any(key == kind for key, _ in packet.detail)


PROTOCOLS = {
    'tcp': lambda p: p.protocol in ('TCP', 'HTTP'),
    'udp': lambda p: p.protocol == 'UDP',
    'ipv4': lambda p: has_layer(p, 'IPv4'),
    'ipv6': lambda p: has_layer(p, 'IPv6'),
    'icmp': lambda p: p.protocol in ('ICMP', 'ICMPv6'),
    'icmpv6': lambda p: p.protocol == 'ICMPv6',
    'http': lambda p: p.protocol == 'HTTP',
    'arp': lambda p: p.protocol == 'ARP',
}
OPERATORS = {'=': operator.eq, '==': operator.eq, '!=': operator.ne,
             '<': operator.lt, '<=': operator.le, '>': operator.gt, '>=': operator.ge}
PORT_FIELDS = {'port': (0, 1), 'src.port': (0,), 'dst.port': (1,)}
ADDRESS_FIELDS = {'ip.addr': (0, 1), 'ip.src': (0,), 'ip.dst': (1,)}
LENGTH_FIELDS = {'len': 'wire_length', 'caplen': 'captured_length'}
TOKEN = re.compile(r'\s+|==|!=|<=|>=|[()=<>]|[A-Za-z0-9_.:+-]+|[^\s]')


def compile_display_filter(source):
    if not source.strip():
        return None
    parser = Parser(source)
    predicate = parser.disjunction()
    if parser.peek() is not None:
        parser.error('多余的条件或符号')
    return predicate


class Parser:
    def __init__(self, source):
        if len(source) > 300:
            raise DisplayFilterError('表达式最多 300 个字符')
        self.tokens = [(m.group().lower(), m.start()) for m in TOKEN.finditer(source)
                       if not m.group().isspace()]
        if len(self.tokens) > 80:
            raise DisplayFilterError('表达式最多 80 个词和符号')
        self.end = len(source)
        self.index = 0

    def peek(self):
        return self.tokens[self.index][0] if self.index < len(self.tokens) else None

    def error(self, message, index=None):
        index = self.index if index is None else index
        position = self.tokens[index][1] if index < len(self.tokens) else self.end
        raise DisplayFilterError(f'第 {position + 1} 字符：{message}')

    def accept(self, word):
        if self.peek() != word:
            return False
        self.index += 1
        return True

    def disjunction(self):
        predicates = [self.conjunction()]
        while self.accept('or'):
            predicates.append(self.conjunction())
        return predicates[0] if len(predicates) == 1 else lambda packet: any(
            predicate(packet) for predicate in predicates)

    def conjunction(self):
        predicates = [self.factor()]
        while self.accept('and'):
            predicates.append(self.factor())
        return predicates[0] if len(predicates) == 1 else lambda packet: all(
            predicate(packet) for predicate in predicates)

    def factor(self):
        if self.accept('not'):
            predicate = self.factor()
            return lambda packet: not predicate(packet)
        if self.accept('('):
            predicate = self.disjunction()
            if not self.accept(')'):
                self.error('缺少右括号')
            return predicate
        field = self.peek()
        if field in PROTOCOLS:
            self.index += 1
            return PROTOCOLS[field]
        if field in PORT_FIELDS or field in ADDRESS_FIELDS or field in LENGTH_FIELDS:
            self.index += 1
            return self.comparison(field)
        self.error('预期协议、字段或左括号')

    def comparison(self, field):
        symbol = self.peek()
        if symbol not in OPERATORS:
            self.error('缺少比较符')
        if field not in LENGTH_FIELDS and symbol not in ('=', '==', '!='):
            self.error('地址和端口只支持 = 或 !=')
        self.index += 1
        value = self.peek()
        if field in ADDRESS_FIELDS:
            try:
                expected = str(ipaddress.ip_address(value))
            except ValueError:
                self.error('需要 IPv4 或 IPv6 地址')
            positions = ADDRESS_FIELDS[field]
            unequal = symbol == '!='

            def predicate(packet):
                if not (has_layer(packet, 'IPv4') or has_layer(packet, 'IPv6')):
                    return False
                pair = (packet.source, packet.destination)
                match = any(pair[i] == expected for i in positions)
                return not match if unequal else match
        else:
            if value is None or not value.isascii() or not value.isdecimal():
                self.error('需要非负整数')
            expected = int(value)
            if field in PORT_FIELDS:
                if expected > 65535:
                    self.error('端口范围是 0 到 65535')
                positions = PORT_FIELDS[field]
                unequal = symbol == '!='

                def predicate(packet):
                    header = packet.tcp or packet.udp
                    if header is None:
                        return False
                    pair = (header.source_port, header.destination_port)
                    match = any(pair[i] == expected for i in positions)
                    return not match if unequal else match
            else:
                if expected > 0xffffffff:
                    self.error('长度超出 PCAP 字段范围')
                compare = OPERATORS[symbol]
                attribute = LENGTH_FIELDS[field]

                def predicate(packet):
                    return compare(getattr(packet, attribute), expected)
        self.index += 1
        return predicate
