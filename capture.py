"""Minimal ctypes adapter for a single libpcap capture handle."""

from __future__ import annotations

import ctypes as C
from ctypes.util import find_library
import os
from dataclasses import dataclass
from pathlib import Path
import sys

from packet import _parse_packet


class Interface(C.Structure):
    pass


InterfacePtr = C.POINTER(Interface)
Interface._fields_ = [
    ('next', InterfacePtr), ('name', C.c_char_p),
    ('description', C.c_char_p), ('addresses', C.c_void_p), ('flags', C.c_uint),
]


class BpfProgram(C.Structure):
    _fields_ = [('length', C.c_uint), ('instructions', C.c_void_p)]


class PcapTime(C.Structure):
    # Darwin suseconds_t is int32 even though time_t is a long.
    _fields_ = [('seconds', C.c_long),
                ('microseconds', C.c_int if sys.platform == 'darwin' else C.c_long)]


class Header(C.Structure):
    _fields_ = [('time', PcapTime), ('captured', C.c_uint32), ('wire', C.c_uint32)]


class Stats(C.Structure):
    # Windows Npcap exposes additional statistics after the common first three fields.
    _fields_ = [(name, C.c_uint) for name in
                ('received', 'dropped', 'interface_dropped', 'captured', 'sent', 'network_dropped')]


@dataclass(frozen=True)
class CaptureRequest:
    interface: bytes = b''
    path: str = ''
    expression: str = ''


@dataclass
class CaptureResult:
    received: int = 0
    queue_dropped: int = 0
    kernel_dropped: int | None = None
    error: str = ''
    ended: bool = False


def decode(value):
    return (value or b'').decode('utf-8', 'replace')


class Pcap:
    def __init__(self):
        self.dll_directory = None
        if sys.platform == 'win32':
            windows = Path(os.environ.get('SystemRoot', r'C:\Windows'))
            directory = windows / 'System32' / 'Npcap'
            if directory.is_dir():
                self.dll_directory = os.add_dll_directory(str(directory))
            candidates = [str(directory / 'wpcap.dll'), str(windows / 'System32' / 'wpcap.dll')]
        else:
            candidates = [find_library('pcap'), '/usr/lib/libpcap.dylib',
                          'libpcap.so.1', 'libpcap.so']
        for name in filter(None, candidates):
            try:
                self.lib = C.CDLL(name)
                break
            except OSError:
                continue
        else:
            raise RuntimeError('找不到 libpcap/Npcap。请安装对应的系统运行库。')

        p, s, i, bpf = C.c_void_p, C.c_char_p, C.c_int, C.POINTER(BpfProgram)
        signatures = {
            'pcap_init': (i, (C.c_uint, s)),
            'pcap_findalldevs': (i, (C.POINTER(InterfacePtr), s)),
            'pcap_freealldevs': (None, (InterfacePtr,)),
            'pcap_open_live': (p, (s, i, i, i, s)),
            'pcap_open_offline': (p, (s, s)),
            'pcap_datalink': (i, (p,)),
            'pcap_compile': (i, (p, bpf, s, i, C.c_uint32)),
            'pcap_setfilter': (i, (p, bpf)),
            'pcap_freecode': (None, (bpf,)),
            'pcap_setnonblock': (i, (p, i, s)),
            'pcap_next_ex': (i, (p, C.POINTER(C.POINTER(Header)), C.POINTER(p))),
            'pcap_geterr': (s, (p,)),
            'pcap_stats': (i, (p, C.POINTER(Stats))),
            'pcap_close': (None, (p,)),
            'pcap_lib_version': (s, ()),
        }
        for name, (result, args) in signatures.items():
            if name == 'pcap_init' and not hasattr(self.lib, name):
                continue
            function = getattr(self.lib, name)
            function.restype, function.argtypes = result, args
        self.utf8 = hasattr(self.lib, 'pcap_init')
        if self.utf8:
            error = C.create_string_buffer(256)
            if self.lib.pcap_init(1, error) != 0:  # PCAP_CHAR_ENC_UTF_8
                raise RuntimeError(decode(error.value))

    def interfaces(self):
        head = InterfacePtr()
        error = C.create_string_buffer(256)
        if self.lib.pcap_findalldevs(C.byref(head), error) < 0:
            raise RuntimeError(decode(error.value))
        devices = []
        try:
            item = head
            while item:
                record = item.contents
                if record.name:
                    devices.append((record.name, decode(record.description), record.flags))
                item = record.next
        finally:
            if head:
                self.lib.pcap_freealldevs(head)
        return devices

    def version(self):
        return decode(self.lib.pcap_lib_version())

    def error(self, handle):
        return decode(self.lib.pcap_geterr(handle)) or 'libpcap 读取失败'

    def apply_filter(self, handle, expression):
        if not expression.strip():
            return
        program = BpfProgram()
        if self.lib.pcap_compile(handle, C.byref(program), expression.encode('utf-8'),
                                 1, 0xffffffff) < 0:
            raise ValueError('BPF 编译失败 · ' + self.error(handle))
        try:
            if self.lib.pcap_setfilter(handle, C.byref(program)) < 0:
                raise RuntimeError('BPF 应用失败 · ' + self.error(handle))
        finally:
            self.lib.pcap_freecode(C.byref(program))


def run_capture(pcap, request, stop, on_ready, on_packet, result):
    """Read until EOF or stop. Callbacks never access GUI controls directly."""
    lib = pcap.lib
    offline = bool(request.path)
    handle = None
    err = C.create_string_buffer(256)
    try:
        if offline:
            path = request.path.encode('utf-8') if sys.platform == 'win32' and pcap.utf8 else os.fsencode(request.path)
            handle = lib.pcap_open_offline(path, err)
        else:
            handle = lib.pcap_open_live(request.interface, 65535, 0, 100, err)
        if not handle:
            raise RuntimeError(decode(err.value) or '无法打开来源')
        linktype = lib.pcap_datalink(handle)
        if linktype < 0:
            raise RuntimeError(pcap.error(handle))
        pcap.apply_filter(handle, request.expression)
        if not offline and lib.pcap_setnonblock(handle, 1, err) < 0:
            raise RuntimeError(decode(err.value))
        on_ready(linktype)

        header, data = C.POINTER(Header)(), C.c_void_p()
        while not stop.is_set():
            status = lib.pcap_next_ex(handle, C.byref(header), C.byref(data))
            if status == -2:
                result.ended = True
                break
            if status < 0:
                raise RuntimeError(pcap.error(handle))
            if status == 0:
                stop.wait(0.015)
                continue
            record = header.contents
            result.received += 1
            if record.captured > 262144 or record.captured > record.wire:
                raise ValueError('捕获记录长度无效或超过 256 KiB')
            raw = C.string_at(data, record.captured)
            stamp = record.time.seconds + record.time.microseconds / 1_000_000
            packet = _parse_packet(raw, linktype, result.received, stamp, record.wire)
            if not on_packet(packet):
                result.queue_dropped += 1

        if not offline:
            stats = Stats()
            if lib.pcap_stats(handle, C.byref(stats)) == 0:
                result.kernel_dropped = stats.dropped
    except (RuntimeError, ValueError, OSError, OverflowError) as exc:
        result.error = str(exc)
    finally:
        if handle:
            lib.pcap_close(handle)
