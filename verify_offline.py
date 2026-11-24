"""Check the bundled PCAP fixtures and exported records with libpcap."""

from collections import Counter
from pathlib import Path
from tempfile import TemporaryDirectory
from threading import Event
import unittest

from capture import CaptureRequest, CaptureResult, Pcap, run_capture, write_pcap
from demo_traffic import make_split_fixture
from flows import SocketOwner, bind_processes, flows_for_process, summarize_flows

SAMPLE = Path(__file__).resolve().with_name('netlens_demo.pcap')
SPLIT_SAMPLE = SAMPLE.with_name('netlens_http_split.pcap')
REUSE_SAMPLE = SAMPLE.with_name('netlens_tcp_reuse.pcap')


class OfflineCaptureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.pcap = Pcap()

    def read(self, expression='', path=SAMPLE):
        result, packets = CaptureResult(), []

        def retain(packet):
            packets.append(packet)
            return True

        run_capture(self.pcap, CaptureRequest(path=str(path), expression=expression),
                    Event(), lambda _: None, retain, result)
        return result, packets

    def test_packet_counts_and_timestamps(self):
        result, packets = self.read()
        self.assertTrue(result.ended, result.error)
        self.assertEqual(result.received, 15)
        self.assertEqual(Counter(p.protocol for p in packets),
                         {'TCP': 6, 'HTTP': 2, 'UDP': 3, 'ICMP': 1,
                          'ICMPv6': 1, 'ARP': 1, 'IPv4': 1})
        self.assertEqual(packets[0].timestamp_us % 1_000_000, 1000)
        self.assertIn('GET /netlens-demo HTTP/1.1', packets[3].info)
        self.assertIn('HTTP/1.1 200 OK', packets[4].info)

    def test_bidirectional_flow(self):
        _, packets = self.read()
        flow, = summarize_flows(packets)
        self.assertEqual(flow.counts, [5, 3])
        self.assertEqual(flow.bytes, [50, 46])
        self.assertEqual(flow.latest - flow.earliest, 140000)
        self.assertEqual(flow.fin, {0, 1})

    def test_capture_filter_accepts_and_rejects(self):
        result, packets = self.read('tcp port 18765')
        self.assertEqual(result.received, 8, result.error)
        self.assertTrue(all(p.tcp is not None for p in packets))
        rejected, packets = self.read('tcp and and')
        self.assertIn('BPF 编译失败', rejected.error)
        self.assertEqual(packets, [])

    def test_captured_length_and_layer_offsets(self):
        _, packets = self.read()
        self.assertTrue(any('IPv6 extension' == k for k, _ in packets[9].detail))
        self.assertEqual(packets[9].protocol, 'UDP')
        self.assertTrue(any('VLAN' in k for k, _ in packets[13].detail))
        self.assertEqual(packets[13].protocol, 'UDP')
        self.assertEqual((packets[14].captured_length, packets[14].wire_length), (32, 104))
        self.assertIn('Truncated IPv4', packets[14].info)

    def test_http_across_segments_with_reordering_retransmission_and_wrap(self):
        state, packets = self.read(path=SPLIT_SAMPLE)
        self.assertTrue(state.ended, state.error)
        http = [packet for packet in packets if packet.protocol == 'HTTP']
        self.assertEqual([p.number for p in http], [6, 8])
        self.assertEqual([p.http_frames for p in http], [(4, 6, 3), (7, 8)])
        self.assertIn('GET /split HTTP/1.1', http[0].info)
        self.assertIn('HTTP/1.1 200 OK', http[1].info)

    def test_http_gap_is_not_filled_by_unrelated_bytes(self):
        with TemporaryDirectory() as folder:
            path = Path(folder) / 'missing.pcap'
            make_split_fixture(path, omit_middle=True)
            _, packets = self.read(path=path)
        http = [packet for packet in packets if packet.protocol == 'HTTP']
        self.assertEqual(len(http), 1)
        self.assertIn('HTTP/1.1 200 OK', http[0].info)

    def test_export_round_trip_preserves_link_type_lengths_timestamp_and_bytes(self):
        def read_capture(path):
            linktypes, packets = [], []
            result = CaptureResult()

            def retain(packet):
                packets.append(packet)
                return True

            run_capture(self.pcap, CaptureRequest(path=str(path)), Event(),
                        linktypes.append, retain, result)
            self.assertTrue(result.ended, result.error)
            self.assertEqual(len(linktypes), 1)
            return linktypes[0], packets

        with TemporaryDirectory() as folder:
            for sample in (SAMPLE, SPLIT_SAMPLE):
                with self.subTest(sample=sample.name):
                    linktype, packets = read_capture(sample)
                    destination = Path(folder) / '新导出 测试.pcap'
                    self.assertEqual(write_pcap(self.pcap, destination, linktype, packets),
                                     len(packets))
                    reopened_linktype, reopened = read_capture(destination)
                    self.assertEqual(linktype, reopened_linktype)

                    def record(p):
                        return p.timestamp_us, p.captured_length, p.wire_length, p.raw, p.http_frames

                    self.assertEqual(list(map(record, reopened)), list(map(record, packets)))

    def test_invalid_first_record_is_rejected_before_source_is_ready(self):
        with TemporaryDirectory() as folder:
            path = Path(folder) / 'incomplete.pcap'
            path.write_bytes(SAMPLE.read_bytes()[:30])
            ready = []
            result = CaptureResult()
            run_capture(self.pcap, CaptureRequest(path=str(path)), Event(), ready.append,
                        lambda _: self.fail('unexpected packet'), result)
        self.assertTrue(result.error)
        self.assertFalse(ready)

    def test_reused_endpoints_keep_connections_and_pid_separate(self):
        result, packets = self.read(path=REUSE_SAMPLE)
        self.assertTrue(result.ended, result.error)
        self.assertEqual([packet.connection_id for packet in packets], [1, 1, 1, 1, 5, 5, 5])
        newer, older = summarize_flows(packets)
        self.assertEqual(newer.key, older.key)
        self.assertEqual([newer.counts, older.counts], [[2, 1], [3, 1]])
        snapshot = {newer.key: {SocketOwner(1234, 'example')}}
        owners = bind_processes([newer, older], snapshot)
        self.assertNotIn(older.identity, owners)
        self.assertEqual(flows_for_process([newer, older], owners, 1234), [newer])


if __name__ == '__main__':
    unittest.main(verbosity=2)
