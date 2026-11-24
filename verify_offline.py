"""Reproduce the checks for the bundled 15-record fixture with libpcap."""

from collections import Counter
from pathlib import Path
from tempfile import TemporaryDirectory
from threading import Event
import unittest

from capture import CaptureRequest, CaptureResult, Pcap, run_capture
from demo_traffic import make_split_fixture
from flows import summarize_flows

SAMPLE = Path(__file__).resolve().with_name('netlens_demo.pcap')
SPLIT_SAMPLE = SAMPLE.with_name('netlens_http_split.pcap')


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


if __name__ == '__main__':
    unittest.main(verbosity=2)
