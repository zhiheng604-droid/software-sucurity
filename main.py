#!/usr/bin/env python3
"""NetLens desktop interface."""

from __future__ import annotations

import argparse
import os
import queue
import sys
import threading
import time
import tkinter as tk
from collections import OrderedDict
from dataclasses import dataclass
from pathlib import Path
from tkinter import filedialog, messagebox, ttk

from capture import Pcap, CaptureRequest, CaptureResult, decode, run_capture, write_pcap
from display_filter import DisplayFilterError, PROTOCOLS, compile_display_filter
from flows import (bind_processes, find_local_processes, flow_identity, flow_process_options,
                   flows_for_process, summarize_flows)

FILTERS = {
    "全部": None,
    **{name: PROTOCOLS[name.lower()] for name in ("TCP", "UDP", "IPv4", "IPv6", "ICMP", "HTTP", "ARP")},
}

QUEUE_CAPACITY = 2048
GUI_BATCH_LIMIT = 512
GUI_BATCH_SECONDS = 0.006

@dataclass
class OpeningSource:
    request: CaptureRequest
    label: str
    result: CaptureResult


class SnifferApp:
    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        self.root.title("NetLens - 网络嗅探器")
        self.root.geometry("1120x720")
        self.root.minsize(850, 560)
        self.pcap = Pcap()
        self.devices = []
        self.packets = OrderedDict()
        self.buffer_bytes = 0
        self.evicted = 0
        self.incoming = queue.Queue(maxsize=QUEUE_CAPACITY)
        self.control = queue.SimpleQueue()
        self.worker_done = False
        self.last_summary_at = 0.0
        self.stop_event = threading.Event()
        self.result = CaptureResult()
        self.opening = None
        self.running = False
        self.closing = False
        self.stream = None
        self.source_label = ''
        self.source_path = ''
        self.linktype = None
        self.offline = False
        self.visible = 0
        self.display_predicate = None
        self.processes = {}
        self.flow_windows = set()
        self.source_rows = {}
        self.pinned_frame = None
        self.pinned_spans = ()
        self.return_frame = None
        self._build_ui()
        self.refresh_interfaces()
        self.root.after(100, self._drain_packets)
        self.root.protocol("WM_DELETE_WINDOW", self.close)

    def _build_ui(self) -> None:
        self.root.configure(bg="#f3f5f7")
        style = ttk.Style()
        try:
            style.theme_use("clam")
        except tk.TclError:
            pass
        style.configure("TFrame", background="#f3f5f7")
        style.configure("TLabel", background="#f3f5f7", foreground="#1b303d")
        style.configure("TButton", padding=(9, 6), background="#e8eff4",
                        foreground="#1b303d", bordercolor="#c0ced9")
        style.map("TButton", background=[("disabled", "#f3f5f7"), ("active", "#d6e9f6")])
        style.configure("Treeview", rowheight=24, font=("Arial", 10))
        style.map("Treeview", background=[("selected", "#385d76")])
        style.configure("Treeview.Heading", background="#e8eff4", foreground="#1b303d")
        style.configure("Treeview.Heading", font=("Arial", 10, "bold"))

        toolbar = ttk.Frame(self.root, padding=(12, 10))
        toolbar.pack(fill="x")
        ttk.Label(toolbar, text="网卡").pack(side="left", padx=(0, 6))
        self.interface_var = tk.StringVar()
        self.interface_box = ttk.Combobox(toolbar, textvariable=self.interface_var,
                                          state="readonly", width=20)
        self.interface_box.pack(side="left", padx=(0, 6))
        self.refresh_button = ttk.Button(toolbar, text="刷新", width=-1, command=self.refresh_interfaces)
        self.refresh_button.pack(side="left", padx=(0, 8))
        self.start_button = ttk.Button(toolbar, text="▶ 开始抓包", width=-1, command=self.start_capture)
        self.start_button.pack(side="left", padx=(0, 6))
        self.stop_button = ttk.Button(toolbar, text="停止", width=-1, command=self.stop_capture, state="disabled")
        self.stop_button.pack(side="left", padx=(0, 12))
        self.open_button = ttk.Button(toolbar, text="打开 PCAP…", width=-1, command=self.open_file)
        self.open_button.pack(side="left", padx=(0, 6))
        self.demo_button = ttk.Button(toolbar, text="加载课程样本", width=-1, command=self.open_demo)
        self.demo_button.pack(side="left")
        self.clear_button = ttk.Button(toolbar, text="清空", width=-1, command=self.clear_packets)
        self.clear_button.pack(side="right")
        self.export_button = ttk.Button(toolbar, text="导出 PCAP…", width=-1, state="disabled",
                                        command=self.export_file)
        self.export_button.pack(side="right", padx=(6, 6))

        filters = ttk.Frame(self.root, padding=(12, 0, 12, 9))
        filters.pack(fill="x")
        ttk.Label(filters, text="BPF 抓包 / 读取过滤").pack(side="left", padx=(0, 5))
        self.bpf_var = tk.StringVar()
        self.bpf_entry = ttk.Entry(filters, textvariable=self.bpf_var, width=29)
        self.bpf_entry.pack(side="left", padx=(0, 12))
        ttk.Label(filters, text="显示协议").pack(side="left", padx=(0, 5))
        self.filter_var = tk.StringVar(value="全部")
        self.filter_box = ttk.Combobox(filters, textvariable=self.filter_var,
                                       values=list(FILTERS), state="readonly", width=7)
        self.filter_box.pack(side="left", padx=(0, 12))
        self.filter_box.bind("<<ComboboxSelected>>", lambda _event: self._refresh_rows())
        ttk.Button(filters, text="TCP 流…", command=self.open_flows).pack(side="left", padx=(0, 5))
        ttk.Button(filters, text="跟踪所选包", command=self.follow_selected).pack(side="left", padx=(0, 5))
        ttk.Button(filters, text="取消跟踪", command=lambda: self.set_stream(None)).pack(side="left")

        display = ttk.Frame(self.root, padding=(12, 0, 12, 9))
        display.pack(fill="x")
        ttk.Label(display, text="组合显示过滤").pack(side="left", padx=(0, 5))
        self.display_var = tk.StringVar()
        self.display_entry = ttk.Entry(display, textvariable=self.display_var, width=34)
        self.display_entry.pack(side="left", fill="x", padx=(0, 6))
        self.display_entry.bind("<Return>", self.apply_display_filter)
        self.display_apply_button = ttk.Button(display, text="应用", command=self.apply_display_filter)
        self.display_apply_button.pack(side="left", padx=(0, 5))
        self.display_clear_button = ttk.Button(display, text="清除表达式", command=self.clear_display_filter)
        self.display_clear_button.pack(side="left", padx=(0, 8))
        self.display_status = tk.StringVar()
        ttk.Label(display, textvariable=self.display_status).pack(side="left")

        self.status_var = tk.StringVar(value="就绪")
        status = ttk.Label(self.root, textvariable=self.status_var, padding=(12, 4), anchor="w")
        status.pack(fill="x", side="bottom")

        panes = ttk.Panedwindow(self.root, orient="vertical")
        panes.pack(fill="both", expand=True, padx=12, pady=(0, 8))
        list_frame = ttk.Frame(panes)
        details_frame = ttk.Frame(panes)
        panes.add(list_frame, weight=3)
        panes.add(details_frame, weight=2)

        cols = ("no", "time", "source", "destination", "protocol", "length", "info")
        self.packet_tree = ttk.Treeview(list_frame, columns=cols, show="headings", selectmode="browse")
        headings = {"no": "No.", "time": "时间", "source": "源地址", "destination": "目的地址",
                    "protocol": "协议", "length": "长度", "info": "摘要"}
        widths = {"no": 64, "time": 145, "source": 160, "destination": 160,
                  "protocol": 90, "length": 80, "info": 390}
        for col in cols:
            self.packet_tree.heading(col, text=headings[col])
            self.packet_tree.column(col, width=widths[col], minwidth=55,
                                    stretch=(col in ("source", "destination", "info")),
                                    anchor="w" if col == "info" else "center")
        ybar = ttk.Scrollbar(list_frame, orient="vertical", command=self.packet_tree.yview)
        xbar = ttk.Scrollbar(list_frame, orient="horizontal", command=self.packet_tree.xview)
        self.packet_tree.configure(yscrollcommand=ybar.set, xscrollcommand=xbar.set)
        self.packet_tree.grid(row=0, column=0, sticky="nsew")
        ybar.grid(row=0, column=1, sticky="ns")
        xbar.grid(row=1, column=0, sticky="ew")
        list_frame.rowconfigure(0, weight=1)
        list_frame.columnconfigure(0, weight=1)
        for tag, color in {'TCP': '#edf4fc', 'HTTP': '#e6f4ed', 'UDP': '#fcf5e5',
                           'ICMP': '#f1ecfa', 'ICMPv6': '#f1ecfa', 'ARP': '#faede8'}.items():
            self.packet_tree.tag_configure(tag, background=color)
        self.packet_tree.bind("<<TreeviewSelect>>", self._show_selected)

        detail_actions = ttk.Frame(details_frame)
        detail_actions.pack(fill="x")
        self.return_button = ttk.Button(detail_actions, text="回到重组帧", state="disabled",
                                        command=self.return_to_http)
        self.return_button.pack(side="right", padx=(4, 0))
        self.reference_var = tk.StringVar()
        ttk.Label(detail_actions, textvariable=self.reference_var).pack(side="left", padx=(4, 0))
        detail_tabs = self.detail_tabs = ttk.Notebook(details_frame)
        detail_tabs.pack(fill="both", expand=True)
        field_tab = ttk.Frame(detail_tabs)
        hex_tab = self.hex_tab = ttk.Frame(detail_tabs)
        detail_tabs.add(field_tab, text="协议详情")
        detail_tabs.add(hex_tab, text="原始数据")
        self.detail_tree = ttk.Treeview(field_tab, columns=("value",), show="tree headings")
        self.detail_tree.heading("#0", text="字段")
        self.detail_tree.heading("value", text="值")
        self.detail_tree.column("#0", width=220, minwidth=100)
        self.detail_tree.column("value", width=665, minwidth=200)
        detail_y = ttk.Scrollbar(field_tab, orient="vertical", command=self.detail_tree.yview)
        self.detail_tree.configure(yscrollcommand=detail_y.set)
        self.detail_tree.pack(side="left", fill="both", expand=True)
        detail_y.pack(side="right", fill="y")
        self.detail_tree.tag_configure('frame-link', foreground='#07588a')
        self.detail_tree.tag_configure('frame-missing', foreground='#747474')
        self.detail_tree.bind('<ButtonRelease-1>', self.open_http_reference)
        self.detail_tree.bind('<Return>', self.open_http_reference)
        self.hex_text = tk.Text(hex_tab, wrap="none", font=("Menlo", 10), state="disabled")
        self.hex_text.tag_configure('http-source', background='#ffe18c', foreground='#17352a')
        hex_y = ttk.Scrollbar(hex_tab, orient="vertical", command=self.hex_text.yview)
        hex_x = ttk.Scrollbar(hex_tab, orient="horizontal", command=self.hex_text.xview)
        self.hex_text.configure(yscrollcommand=hex_y.set, xscrollcommand=hex_x.set)
        self.hex_text.grid(row=0, column=0, sticky="nsew")
        hex_y.grid(row=0, column=1, sticky="ns")
        hex_x.grid(row=1, column=0, sticky="ew")
        hex_tab.rowconfigure(0, weight=1)
        hex_tab.columnconfigure(0, weight=1)

    def refresh_interfaces(self):
        if self.running:
            return
        current = self.interface_var.get()
        try:
            self.devices = self.pcap.interfaces()
        except RuntimeError as exc:
            self.status_var.set(f'接口枚举失败 · {exc}')
            return
        labels = [f'{desc} [{decode(name)}]' if desc else decode(name)
                  for name, desc, _flags in self.devices]
        self.interface_box['values'] = labels
        if labels:
            self.interface_box.current(labels.index(current) if current in labels else 0)
        self.status_var.set(f'{len(labels)} 个接口 · {self.pcap.version()}')

    def start_capture(self):
        index = self.interface_box.current()
        if index < 0:
            self.status_var.set('请先选择抓包接口。')
            return
        name = self.devices[index][0]
        self.start_source(CaptureRequest(interface=name, expression=self.bpf_var.get()), decode(name))

    def open_file(self):
        path = filedialog.askopenfilename(
            parent=self.root, title='打开捕获文件',
            filetypes=[('捕获文件', '*.pcap *.pcapng *.cap'), ('所有文件', '*')])
        if path:
            self.start_source(CaptureRequest(path=path, expression=self.bpf_var.get()), Path(path).name)

    def open_demo(self):
        path = Path(__file__).resolve().parent / 'netlens_demo.pcap'
        self.start_source(CaptureRequest(path=str(path), expression=self.bpf_var.get()), 'netlens_demo.pcap')

    def start_source(self, request, label):
        if self.running:
            return
        pending = self.opening = OpeningSource(request, label, CaptureResult())
        self.worker_done = False
        self.last_summary_at = 0.0
        self.stop_event.clear()
        self.set_running(True)
        self.status_var.set(f'正在打开 {label}…')
        worker = threading.Thread(target=self._capture_worker, args=(pending,), daemon=True)
        worker.start()

    def _accept_source(self, linktype):
        pending = self.opening
        self.opening = None
        self.source_label = pending.label
        self.source_path = pending.request.path
        self.offline = bool(self.source_path)
        self.result = pending.result
        self.linktype = linktype
        self.filter_box.current(0)
        self._reset_display_filter()
        self._reset_view()
        self.status_var.set(f'{self.source_label} · 链路类型 {linktype} · 正在读取')

    def set_running(self, running):
        self.running = running
        state = 'disabled' if running else 'normal'
        for widget in (self.start_button, self.refresh_button, self.open_button,
                       self.demo_button, self.clear_button, self.bpf_entry):
            widget.configure(state=state)
        self.stop_button.configure(state='normal' if running else 'disabled')
        self.interface_box.configure(state='disabled' if running else 'readonly')
        self._update_export_button()

    def _capture_worker(self, pending):
        offline = bool(pending.request.path)

        def publish(packet):
            if offline:
                while not self.stop_event.is_set():
                    try:
                        self.incoming.put(packet, timeout=0.04)
                        return True
                    except queue.Full:
                        pass
                return False
            try:
                self.incoming.put_nowait(packet)
                return True
            except queue.Full:
                return False
        try:
            run_capture(self.pcap, pending.request, self.stop_event,
                        lambda link: self.control.put(('ready', link)), publish, pending.result)
        except Exception as exc:
            pending.result.error = str(exc)
        finally:
            self.control.put(('done', None))

    def stop_capture(self):
        if self.running:
            self.stop_event.set()
            self.stop_button.configure(state='disabled')
            self.status_var.set('正在停止…')

    def _drain_packets(self):
        while not self.control.empty():
            status, value = self.control.get_nowait()
            if status == 'ready':
                if self.opening is not None and not self.stop_event.is_set():
                    self._accept_source(value)
            elif status == 'done':
                self.worker_done = True
        added = False
        # The worker may enqueue its first packet just after this tick checked
        # the control queue. Hold those packets until the ready event is read.
        if self.opening is None or self.worker_done:
            deadline = time.perf_counter() + GUI_BATCH_SECONDS
            for index in range(GUI_BATCH_LIMIT):
                if index and index % 16 == 0 and time.perf_counter() >= deadline:
                    break
                try:
                    packet = self.incoming.get_nowait()
                except queue.Empty:
                    break
                if self.opening is None:
                    self._append_packet(packet)
                    added = True
        backlog = not self.incoming.empty()
        if self.worker_done and not backlog:
            self.worker_done = False
            pending = self.opening
            self.opening = None
            self.set_running(False)
            if self.closing:
                self.root.destroy()
                return
            if pending is not None:
                reason = (f'打开失败 · {pending.result.error}' if pending.result.error and
                          not self.stop_event.is_set() else '已取消打开')
                suffix = f' · 已保留上一来源的 {len(self.packets)} 条记录' if self.packets else ''
                self.status_var.set(reason + suffix)
            elif self.result.error:
                self.status_var.set(f'读取失败 · {self.result.error}')
            else:
                prefix = '离线读取完成' if self.result.ended and self.offline else '已停止'
                self._set_summary(prefix)
        elif added and self.running and not self.stop_event.is_set():
            now = time.monotonic()
            if now - self.last_summary_at >= 0.1:
                self.last_summary_at = now
                self._set_summary('离线读取中' if self.offline else '实时抓包中')
        # Yield to Tk between slices. Do not wait a full timer interval while
        # packets are already queued, or mark the capture finished before drain.
        self.root.after(1 if backlog else 16, self._drain_packets)

    def _update_export_button(self):
        enabled = not self.running and self.linktype is not None and bool(self.packets)
        self.export_button.configure(state='normal' if enabled else 'disabled')

    def export_file(self):
        if self.running or self.linktype is None or not self.packets:
            return
        path = filedialog.asksaveasfilename(
            parent=self.root, title='导出全部保留包', defaultextension='.pcap',
            initialfile='netlens-capture.pcap', filetypes=[('PCAP', '*.pcap')])
        if not path:
            return
        try:
            if self.source_path and Path(path).resolve() == Path(self.source_path).resolve():
                raise ValueError('请另存为新的文件，避免覆盖打开的捕获文件。')
            count = write_pcap(self.pcap, path, self.linktype, self.packets.values())
        except (OSError, RuntimeError, ValueError) as exc:
            self.status_var.set(f'导出失败 · {exc}')
            return
        self.status_var.set(f'已导出 {count} 条保留记录 · {Path(path).name}')

    def _set_summary(self, state):
        result = self.result
        counts = (f'已读 {result.received} / 保留 {len(self.packets)} / '
                  f'显示 {self.visible} / 队列丢弃 {result.queue_dropped} / 淘汰 {self.evicted}')
        if result.kernel_dropped is not None:
            counts += f' / 驱动报告丢弃 {result.kernel_dropped}'
        self.status_var.set(f'{state} · {self.source_label} · {counts}')

    def apply_display_filter(self, _event=None):
        try:
            predicate = compile_display_filter(self.display_var.get())
        except DisplayFilterError as error:
            self.display_status.set(f'{error}；保留上一筛选')
            return
        self.display_predicate = predicate
        self.display_status.set('已应用' if predicate is not None else '')
        self._refresh_rows()

    def _reset_display_filter(self):
        self.display_var.set('')
        self.display_status.set('')
        self.display_predicate = None

    def clear_display_filter(self):
        self._reset_display_filter()
        self._refresh_rows()

    def _matches(self, packet):
        if packet.number == self.pinned_frame:
            return True
        predicate = FILTERS[self.filter_var.get()]
        return ((predicate is None or predicate(packet)) and
                (self.display_predicate is None or self.display_predicate(packet)) and
                (self.stream is None or flow_identity(packet) == self.stream))

    def _append_packet(self, packet):
        self.packets[packet.number] = packet
        self.buffer_bytes += len(packet.raw)
        while len(self.packets) > 4096 or self.buffer_bytes > 16 * 1024 * 1024:
            number, old = self.packets.popitem(last=False)
            self.buffer_bytes -= len(old.raw)
            self.evicted += 1
            if number == self.pinned_frame:
                self.pinned_frame = None
                self.pinned_spans = ()
                self.reference_var.set(f'来源帧 #{number} 已从缓存淘汰')
            iid = str(number)
            if self.packet_tree.exists(iid):
                self.packet_tree.delete(iid)
                self.visible -= 1
        if self._matches(packet):
            self._insert_packet(packet)

    def _insert_packet(self, packet):
        seconds, micros = divmod(packet.timestamp_us, 1_000_000)
        stamp = time.strftime('%H:%M:%S', time.localtime(seconds)) + f'.{micros // 1000:03d}'
        length = (packet.captured_length if packet.captured_length == packet.wire_length
                  else f'{packet.captured_length}/{packet.wire_length}')
        info = f'来源帧 · {packet.info}' if packet.number == self.pinned_frame else packet.info
        self.packet_tree.insert('', 'end', iid=str(packet.number), tags=(packet.protocol,), values=(
            packet.number, stamp, packet.source, packet.destination,
            packet.protocol, length, info))
        self.visible += 1

    def _refresh_rows(self):
        selected = self.packet_tree.selection()
        self.packet_tree.delete(*self.packet_tree.get_children())
        self.visible = 0
        for packet in self.packets.values():
            if self._matches(packet):
                self._insert_packet(packet)
        if selected and self.packet_tree.exists(selected[0]):
            self.packet_tree.selection_set(selected[0])
            self.packet_tree.see(selected[0])
        self._show_selected()
        if self.source_label and not self.running and not self.result.error:
            self._set_summary('离线样本' if self.offline else '已停止')

    def _selected_packet(self):
        selected = self.packet_tree.selection()
        return self.packets.get(int(selected[0])) if selected else None

    def _show_selected(self, _event=None):
        packet = self._selected_packet()
        self.source_rows.clear()
        self.detail_tree.delete(*self.detail_tree.get_children())
        self.hex_text.configure(state='normal')
        self.hex_text.delete('1.0', 'end')
        if packet is not None:
            parent = ''
            details = sorted(packet.detail, key=lambda item: not item[0].startswith(
                ('HTTP/1.x start line', 'HTTP 首行来源帧')))
            for key, value in details:
                if key.startswith('HTTP 首行来源帧') and packet.http_spans:
                    group = self.detail_tree.insert('', 'end', text=key, values=(value,), open=True)
                    ranges_by_frame = {}
                    for span in packet.http_spans:
                        ranges_by_frame.setdefault(span.frame, []).append(
                            f'0x{span.start:x}–0x{span.stop - 1:x}')
                    for number, ranges in ranges_by_frame.items():
                        retained = number in self.packets
                        offsets = '、'.join(ranges)
                        detail = (f'{offsets} · 点击高亮原始字节' if retained else
                                  f'{offsets} · 已淘汰或未进入界面缓存')
                        tag = 'frame-link' if retained else 'frame-missing'
                        row = self.detail_tree.insert(group, 'end', text=f'帧 #{number}',
                                                      values=(detail,), tags=(tag,))
                        self.source_rows[row] = number
                elif value == '':
                    parent = self.detail_tree.insert('', 'end', text=key, open=True)
                else:
                    self.detail_tree.insert(parent if key.startswith('  ') else '',
                                            'end', text=key.strip(), values=(value,))
            lines = []
            for offset in range(0, len(packet.raw), 16):
                chunk = packet.raw[offset:offset + 16]
                hex_part = ' '.join(f'{byte:02x}' for byte in chunk)
                ascii_part = ''.join(chr(byte) if 32 <= byte < 127 else '.' for byte in chunk)
                lines.append(f'{offset:08x}  {hex_part:<47}  {ascii_part}')
            self.hex_text.insert('1.0', '\n'.join(lines))
            if packet.number == self.pinned_frame:
                self._highlight_source_bytes()
        self.hex_text.configure(state='disabled')

    def _highlight_source_bytes(self):
        for span in self.pinned_spans:
            offset = span.start
            while offset < span.stop:
                row, column = divmod(offset, 16)
                line = row + 1
                count = min(span.stop - offset, 16 - column)
                hex_start = 10 + 3 * column
                ascii_start = 59 + column
                self.hex_text.tag_add('http-source', f'{line}.{hex_start}',
                                      f'{line}.{hex_start + 3 * count - 1}')
                self.hex_text.tag_add('http-source', f'{line}.{ascii_start}',
                                      f'{line}.{ascii_start + count}')
                offset += count
        if self.pinned_spans:
            self.hex_text.see(f'{self.pinned_spans[0].start // 16 + 1}.0')

    def _select_frame(self, number):
        row = str(number)
        if not self.packet_tree.exists(row):
            return False
        self.packet_tree.selection_set(row)
        self.packet_tree.focus(row)
        self.packet_tree.see(row)
        self._show_selected()
        return True

    def open_http_reference(self, event):
        row = (self.detail_tree.identify_row(event.y) if event.num == 1
               else self.detail_tree.focus())
        number = self.source_rows.get(row)
        origin = self._selected_packet()
        if number is None or origin is None:
            return
        if number not in self.packets:
            self.reference_var.set(f'来源帧 #{number} 已淘汰或未进入界面缓存')
            self._show_selected()
            return 'break'
        self.return_frame = origin.number
        self.pinned_frame = number
        self.pinned_spans = tuple(span for span in origin.http_spans if span.frame == number)
        self._refresh_rows()
        self.detail_tabs.select(self.hex_tab)
        self._select_frame(number)
        highlighted = sum(span.stop - span.start for span in self.pinned_spans)
        self.reference_var.set(
            f'来源帧 #{number} · 来自重组帧 #{origin.number} · 高亮 {highlighted} 字节')
        self.return_button.configure(state='normal')
        return 'break'

    def return_to_http(self):
        number = self.return_frame
        self.return_frame = self.pinned_frame = None
        self.pinned_spans = ()
        self.return_button.configure(state='disabled')
        self.reference_var.set('')
        self._refresh_rows()
        self.detail_tabs.select(0)
        if number is not None and not self._select_frame(number):
            message = ('在当前筛选下不可见' if number in self.packets else '已从缓存淘汰')
            self.reference_var.set(f'重组帧 #{number} {message}')

    def clear_packets(self):
        if self.running:
            return
        self._reset_view()

    def _reset_view(self):
        self.packets.clear()
        self.buffer_bytes = self.evicted = 0
        self.stream = None
        self.processes = {}
        self.pinned_frame = self.return_frame = None
        self.pinned_spans = ()
        self.reference_var.set('')
        self.return_button.configure(state='disabled')
        for window in tuple(self.flow_windows):
            window.destroy()
        self._refresh_rows()
        self._update_export_button()

    def follow_selected(self):
        packet = self._selected_packet()
        key = flow_identity(packet) if packet else None
        if key is None:
            self.status_var.set('选中包含完整 TCP 头的包后可跟踪双向流。')
        else:
            self.set_stream(key)

    def set_stream(self, key):
        self.stream = key
        self._refresh_rows()
        if key is not None:
            pair, instance = key
            self.status_var.set(f'跟踪 TCP 流 #{instance} · {endpoint(pair[0])} ↔ '
                                f'{endpoint(pair[1])} · {self.visible} 包')

    def open_flows(self):
        window = tk.Toplevel(self.root)
        self.flow_windows.add(window)

        def forget(event):
            if event.widget is window:
                self.flow_windows.discard(window)

        window.bind('<Destroy>', forget)
        window.title('NetLens · TCP 双向流')
        window.geometry('1040x380')
        frame = ttk.Frame(window, padding=10)
        frame.pack(fill='both', expand=True)
        columns = ('a', 'b', 'connection', 'packets', 'bytes', 'duration', 'state', 'process')
        table = ttk.Treeview(frame, columns=columns, show='headings', selectmode='browse')
        headings = ('端点 A', '端点 B', '连接编号', '双向包数', '双向载荷字节',
                    '时长 s', '观察状态', '本机进程快照')
        widths = (145, 145, 73, 94, 128, 60, 148, 170)
        for key, title, width in zip(columns, headings, widths):
            table.heading(key, text=title)
            table.column(key, width=width, minwidth=54)
        table_scroll = ttk.Scrollbar(frame, orient='vertical', command=table.yview)
        table.configure(yscrollcommand=table_scroll.set)
        actions = ttk.Frame(frame, padding=(0, 8, 0, 0))
        actions.pack(fill='x', side='bottom')
        table_scroll.pack(side='right', fill='y')
        table.pack(fill='both', expand=True)
        note = tk.StringVar(value='统计当前保留包，双向栏顺序为 A→B / B→A。')
        keys = {}
        outcome = queue.SimpleQueue()
        process_name = tk.StringVar(value='全部进程')
        process_picker = ttk.Combobox(actions, textvariable=process_name, width=16,
                                      values=['全部进程'], state='readonly')

        def refresh():
            table.delete(*table.get_children())
            keys.clear()
            flows = summarize_flows(self.packets.values())
            owners = {flow.identity: self.processes[flow.identity] for flow in flows
                      if not flow.closed and flow.identity in self.processes}
            options = flow_process_options(flows, owners)
            current = process_name.get()
            process_picker.configure(values=['全部进程', *options])
            if current not in options:
                process_picker.current(0)
            selected_pid = options.get(process_name.get())
            for i, flow in enumerate(flows_for_process(flows, owners, selected_pid)):
                processes = owners.get(flow.identity, ())
                a, b = flow.key
                iid = str(i)
                keys[iid] = flow.identity
                table.insert('', 'end', iid=iid, values=(
                    endpoint(a), endpoint(b), f'#{flow.connection_id}', ' / '.join(map(str, flow.counts)),
                    ' / '.join(map(str, flow.bytes)), f'{(flow.latest - flow.earliest) / 1_000_000:.3f}',
                    flow.state, ', '.join(owner.label for owner in sorted(processes))))
        def follow(_event=None):
            selected = table.selection()
            if selected:
                self.set_stream(keys[selected[0]])
                window.destroy()
        def snapshot():
            snapshot_button.configure(state='disabled')
            note.set('正在读取本机套接字快照…')
            flows_at_request = summarize_flows(self.packets.values())
            threading.Thread(target=lambda: outcome.put(find_local_processes()), daemon=True).start()
            self.root.after(60, lambda: receive_snapshot(flows_at_request))
        def receive_snapshot(flows_at_request):
            if not window.winfo_exists():
                return
            if outcome.empty():
                self.root.after(60, lambda: receive_snapshot(flows_at_request))
                return
            sockets, reason = outcome.get()
            before = bind_processes(flows_at_request, sockets)
            now = bind_processes(summarize_flows(self.packets.values()), sockets)
            self.processes = {identity: owners for identity, owners in now.items()
                              if identity in before}
            note.set(reason or '进程快照已更新，仅匹配仍存在且当前账号可见的连接。')
            snapshot_button.configure(state='normal')
            refresh()
        ttk.Button(actions, text='刷新统计', command=refresh).pack(side='left', padx=(0, 6))
        ttk.Button(actions, text='跟踪此流', command=follow).pack(side='left', padx=(0, 6))
        snapshot_button = ttk.Button(actions, text='读取本机进程', command=snapshot)
        snapshot_button.pack(side='left', padx=(0, 8))
        process_picker.pack(side='left', padx=(0, 8))
        process_picker.bind('<<ComboboxSelected>>', lambda _event: refresh())
        if self.offline:
            snapshot_button.configure(state='disabled')
        ttk.Label(actions, textvariable=note).pack(side='left')
        table.bind('<Double-1>', follow)
        refresh()

    def close(self):
        self.closing = True
        if self.running:
            self.stop_capture()
        else:
            self.root.destroy()


def endpoint(pair):
    address, port = pair
    return f'[{address}]:{port}' if ':' in address else f'{address}:{port}'


def main():
    parser = argparse.ArgumentParser(description='NetLens · 网络嗅探器')
    parser.add_argument('--demo', action='store_true', help='打开课程样本')
    parser.add_argument('--list', action='store_true', help='在终端列出抓包接口')
    args = parser.parse_args()
    if args.list:
        pcap = Pcap()
        for name, description, _flags in pcap.interfaces():
            print(decode(name), description)
        return 0
    os.environ.setdefault('TK_SILENCE_DEPRECATION', '1')
    root = tk.Tk()
    try:
        app = SnifferApp(root)
    except (RuntimeError, OSError, AttributeError) as exc:
        print(exc, file=sys.stderr)
        messagebox.showerror('启动失败', str(exc), parent=root)
        root.destroy()
        return 1
    if args.demo:
        root.after(250, app.open_demo)
    root.mainloop()
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
