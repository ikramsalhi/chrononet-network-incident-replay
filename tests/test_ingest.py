import json
import struct
import unittest

from chrononet.ingest import IngestError, parse_upload


def build_dns_pcap():
    global_header = struct.pack('<IHHIIII', 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    ethernet = bytes.fromhex('00112233445566778899aabb0800')
    source_ip = bytes([192, 168, 1, 10])
    target_ip = bytes([8, 8, 8, 8])
    dns = struct.pack('!HHHHHH', 0x1234, 0x0100, 1, 0, 0, 0) + b'\x00'
    udp = struct.pack('!HHHH', 53000, 53, 8 + len(dns), 0) + dns
    total = 20 + len(udp)
    ipv4 = struct.pack('!BBHHHBBH4s4s', 0x45, 0, total, 1, 0, 64, 17, 0, source_ip, target_ip)
    packet = ethernet + ipv4 + udp
    record = struct.pack('<IIII', 1700000000, 0, len(packet), len(packet)) + packet
    return global_header + record


class IngestTests(unittest.TestCase):
    def test_classic_pcap_decodes_dns(self):
        result = parse_upload(build_dns_pcap(), 'dns-test.pcap')
        self.assertEqual(result['capture']['packets_total'], 1)
        self.assertEqual(result['capture']['packets_decoded'], 1)
        self.assertEqual(result['events'][0]['service'], 'DNS')
        self.assertEqual(result['events'][0]['source_ip'], '192.168.1.10')
        self.assertEqual(result['events'][0]['target_ip'], '8.8.8.8')

    def test_json_event_import(self):
        raw = json.dumps({'events': [{'timestamp': '2026-01-01T00:00:00Z', 'type': 'DNS', 'source': 'host-a', 'target': 'resolver'}]}).encode()
        result = parse_upload(raw, 'events.json')
        self.assertEqual(result['capture']['event_records'], 1)
        self.assertEqual(result['events'][0]['status'], 'observed')

    def test_rejects_unknown_extension(self):
        with self.assertRaises(IngestError):
            parse_upload(b'hello', 'capture.exe')

    def test_pcapng_gives_clear_error(self):
        with self.assertRaises(IngestError):
            parse_upload(b'\x0a\x0d\x0d\x0a' + b'0' * 40, 'capture.pcapng')


if __name__ == '__main__':
    unittest.main()
