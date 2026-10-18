"""Tests for the capture analysis backend. Run: python -m unittest discover -s tests -v"""

import io
import os
import struct
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import analyzer_backend as t  # noqa: E402


def ip4(s):
    return bytes(map(int, s.split(".")))


def eth(payload, et=0x0800):
    return b"\x00" * 12 + struct.pack(">H", et) + payload


def ipv4(src, dst, proto, l4, ttl=64, flags=0x4000):
    return struct.pack(">BBHHHBBH4s4s", 0x45, 0, 20 + len(l4), 0, flags, ttl, proto, 0, ip4(src), ip4(dst)) + l4


def tcp(sp, dp, seq, ack, fl, payload=b"", opts=b""):
    hl = 20 + len(opts)
    return struct.pack(">HHIIBBHHH", sp, dp, seq, ack, (hl // 4) << 4, fl, 1000, 0, 0) + opts + payload


def udp(sp, dp, payload):
    return struct.pack(">HHHH", sp, dp, 8 + len(payload), 0) + payload


def tcp_pkt(src, dst, *a, **k):
    return eth(ipv4(src, dst, 6, tcp(*a, **k)))


def udp_pkt(src, dst, sp, dp, payload):
    return eth(ipv4(src, dst, 17, udp(sp, dp, payload)))


def icmp_pkt(src, dst, typ, code, rest=b"\x00\x01\x00\x01", body=b""):
    return eth(ipv4(src, dst, 1, struct.pack(">BBH", typ, code, 0) + rest + body))


def arp_pkt(op, smac, sip, tmac, tip):
    body = struct.pack(">HHBBH", 1, 0x0800, 6, 4, op) + smac + ip4(sip) + tmac + ip4(tip)
    return eth(body, 0x0806)


def dns_msg(ident, name, qr=0, rcode=0, qtype=1):
    q = b"".join(bytes([len(x)]) + x.encode() for x in name.split(".")) + b"\x00" + struct.pack(">HH", qtype, 1)
    return struct.pack(">HHHHHH", ident, (qr << 15) | rcode, 1, 0, 0, 0) + q


def pcap(packets):
    out = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    for ts, p in packets:
        out += struct.pack("<IIII", int(ts), int((ts % 1) * 1e6), len(p), len(p)) + p
    return out


def pcapng(packets):
    def block(btype, body):
        body += b"\x00" * (-len(body) % 4)
        return struct.pack("<II", btype, len(body) + 12) + body + struct.pack("<I", len(body) + 12)
    out = block(0x0A0D0D0A, struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1))
    out += block(1, struct.pack("<HHI", 1, 0, 65535))
    for ts, p in packets:
        us = int(ts * 1e6)
        out += block(6, struct.pack("<IIIII", 0, us >> 32, us & 0xFFFFFFFF, len(p), len(p)) + p)
    return out


def run(raw):
    return t.analyze_capture(io.BytesIO(raw))


class BackendTests(unittest.TestCase):
    def test_pcapng_matches_pcap(self):
        pk = [(0.0, tcp_pkt("10.0.0.1", "10.0.0.2", 5000, 80, 100, 0, 2)),
              (0.01, tcp_pkt("10.0.0.2", "10.0.0.1", 80, 5000, 500, 101, 0x12))]
        a, b = run(pcap(pk)), run(pcapng(pk))
        self.assertEqual(a["tcp_packets"], b["tcp_packets"])
        self.assertAlmostEqual(b["flows"][0]["handshake_rtt_ms"], 10.0, places=1)

    def test_rejects_garbage(self):
        with self.assertRaises(t.CaptureError):
            run(b"not a capture at all")

    def test_tcp_refused_on_any_port(self):
        r = run(pcap([(0, tcp_pkt("10.0.0.1", "10.0.0.2", 40000, 31337, 1, 0, 2)),
                      (0.001, tcp_pkt("10.0.0.2", "10.0.0.1", 31337, 40000, 0, 2, 0x14))]))
        f = r["flows"][0]
        self.assertEqual(f["state"], "reset")
        self.assertTrue(any("refused" in x for x in f["findings"]))
        self.assertEqual(r["ports"][0]["port"], 31337)

    def test_tls_sni_and_http(self):
        sni = b"example.com"
        ext = struct.pack(">HHHBH", 0, len(sni) + 5, len(sni) + 3, 0, len(sni)) + sni
        hello = (b"\x03\x03" + b"\x00" * 32 + b"\x00" + struct.pack(">H", 2) + b"\x13\x01" + b"\x01\x00"
                 + struct.pack(">H", len(ext)) + ext)
        hs = b"\x01" + struct.pack(">I", len(hello))[1:] + hello
        rec = b"\x16\x03\x01" + struct.pack(">H", len(hs)) + hs
        r = run(pcap([(0, tcp_pkt("10.0.0.1", "10.0.0.2", 5000, 443, 1, 0, 0x18, rec)),
                      (0.1, tcp_pkt("10.0.0.1", "10.0.0.3", 5001, 80, 1, 0, 0x18, b"GET /x HTTP/1.1\r\nHost: a.b\r\n\r\n")),
                      (0.2, tcp_pkt("10.0.0.3", "10.0.0.1", 80, 5001, 1, 30, 0x18, b"HTTP/1.1 503 Busy\r\n\r\n"))]))
        by = {f["server"]: f for f in r["flows"]}
        self.assertEqual(by["10.0.0.2:443"]["app_detail"], "example.com")
        self.assertEqual(by["10.0.0.2:443"]["application"], "TLS")
        self.assertTrue(any("503" in x for x in by["10.0.0.3:80"]["findings"]))

    def test_dns_latency_nxdomain_and_unanswered(self):
        r = run(pcap([
            (0, udp_pkt("10.0.0.1", "8.8.8.8", 5555, 53, dns_msg(1, "a.test"))),
            (0.05, udp_pkt("8.8.8.8", "10.0.0.1", 53, 5555, dns_msg(1, "a.test", 1, 3))),
            (1, udp_pkt("10.0.0.1", "8.8.8.8", 5556, 53, dns_msg(2, "b.test"))),
        ]))
        d = r["dns"]
        self.assertEqual((d["queries"], d["responses"], d["unanswered"]), (2, 1, 1))
        self.assertEqual(d["rcodes"], {"NXDOMAIN": 1})
        self.assertAlmostEqual(d["latency_ms"]["avg"], 50, delta=1)
        self.assertEqual(r["udp"]["count"], 2)

    def test_udp_one_way(self):
        r = run(pcap([(i, udp_pkt("10.0.0.1", "10.0.0.9", 6000, 9999, b"hi")) for i in range(3)]))
        self.assertTrue(r["udp"]["flows"][0]["findings"])
        self.assertTrue(any("UDP" in a for a in r["alerts"]))

    def test_icmp_echo_and_unreachable(self):
        inner = ipv4("10.0.0.1", "10.0.0.2", 17, udp(6000, 161, b"x"))[:28]
        r = run(pcap([
            (0, icmp_pkt("10.0.0.1", "10.0.0.2", 8, 0)),
            (0.02, icmp_pkt("10.0.0.2", "10.0.0.1", 0, 0)),
            (1, icmp_pkt("10.0.0.1", "10.0.0.5", 8, 0, b"\x00\x01\x00\x02")),
            (2, icmp_pkt("10.0.0.2", "10.0.0.1", 3, 3, b"\x00\x00\x00\x00", inner)),
        ]))
        i = r["icmp"]
        self.assertEqual((i["echo"]["requests"], i["echo"]["replies"], i["echo"]["unanswered"]), (2, 1, 1))
        self.assertAlmostEqual(i["echo"]["rtt_ms"]["avg"], 20, delta=1)
        self.assertEqual(i["errors"][0]["original_port"], 161)
        self.assertIn("port unreachable", i["errors"][0]["description"])

    def test_arp_unanswered_and_conflict(self):
        m1, m2, bc = b"\xaa" * 6, b"\xbb" * 6, b"\x00" * 6
        r = run(pcap([
            (0, arp_pkt(1, m1, "10.0.0.1", bc, "10.0.0.50")),
            (1, arp_pkt(2, m1, "10.0.0.7", m2, "10.0.0.1")),
            (2, arp_pkt(2, m2, "10.0.0.7", m1, "10.0.0.1")),
        ]))
        a = r["arp"]
        self.assertEqual(a["unanswered"][0]["ip"], "10.0.0.50")
        self.assertEqual(a["conflicts"][0]["ip"], "10.0.0.7")

    def test_protocol_breakdown_includes_other_ip(self):
        r = run(pcap([(0, eth(ipv4("10.0.0.1", "10.0.0.2", 47, b"\x00" * 8))),
                      (1, udp_pkt("10.0.0.1", "10.0.0.2", 1234, 5000, b"x"))]))
        names = {p["name"] for p in r["protocols"]}
        self.assertTrue({"GRE", "UDP"} <= names)


def tls_server_hello(version_ext=True):
    exts = struct.pack(">HHH", 43, 2, 0x0304) if version_ext else b""
    body = (b"\x03\x03" + b"\x01" * 32 + b"\x00" + b"\x13\x01" + b"\x00" + struct.pack(">H", len(exts)) + exts)
    hs = b"\x02" + struct.pack(">I", len(body))[1:] + body
    return b"\x16\x03\x03" + struct.pack(">H", len(hs)) + hs


def tls_client_hello(alpn=b"h2"):
    ext = struct.pack(">HH", 16, len(alpn) + 3) + struct.pack(">HB", len(alpn) + 1, len(alpn)) + alpn
    ext += struct.pack(">HH", 43, 3) + b"\x02\x03\x04"
    body = (b"\x03\x03" + b"\x00" * 32 + b"\x00" + struct.pack(">H", 2) + b"\x13\x01" + b"\x01\x00"
            + struct.pack(">H", len(ext)) + ext)
    hs = b"\x01" + struct.pack(">I", len(body))[1:] + body
    return b"\x16\x03\x01" + struct.pack(">H", len(hs)) + hs


class V2Tests(unittest.TestCase):
    def test_dns_over_tcp(self):
        q, a = dns_msg(7, "big.test"), dns_msg(7, "big.test", 1, 0)
        r = run(pcap([
            (0, udp_pkt("10.0.0.1", "10.0.0.9", 5000, 53, dns_msg(3, "big.test"))),
            (0.01, tcp_pkt("10.0.0.1", "10.0.0.9", 6000, 53, 1, 0, 0x18, struct.pack(">H", len(q)) + q)),
            (0.03, tcp_pkt("10.0.0.9", "10.0.0.1", 53, 6000, 1, 20, 0x18, struct.pack(">H", len(a)) + a)),
        ]))
        d = r["dns"]
        self.assertEqual(d["tcp_messages"], 2)
        self.assertEqual(d["responses"], 1)
        self.assertAlmostEqual(d["latency_ms"]["avg"], 20, delta=1)

    def test_tls13_server_hello_and_alpn(self):
        r = run(pcap([
            (0, tcp_pkt("10.0.0.1", "10.0.0.2", 5000, 443, 1, 0, 0x18, tls_client_hello())),
            (0.05, tcp_pkt("10.0.0.2", "10.0.0.1", 443, 5000, 1, 100, 0x18, tls_server_hello())),
        ]))
        f = r["flows"][0]
        self.assertEqual(f["tls_version"], "TLS 1.3")
        self.assertEqual(f["tls_alpn"], ["h2"])
        self.assertFalse(any("ServerHello" in x for x in f["findings"]))

    def test_tls_clienthello_without_serverhello(self):
        r = run(pcap([
            (0, tcp_pkt("10.0.0.1", "10.0.0.2", 5000, 443, 0, 0, 2)),
            (0.01, tcp_pkt("10.0.0.2", "10.0.0.1", 443, 5000, 0, 1, 0x12)),
            (0.02, tcp_pkt("10.0.0.1", "10.0.0.2", 5000, 443, 1, 1, 0x10)),
            (0.03, tcp_pkt("10.0.0.1", "10.0.0.2", 5000, 443, 1, 1, 0x18, tls_client_hello())),
        ]))
        self.assertTrue(any("no ServerHello" in x for x in r["flows"][0]["findings"]))
        self.assertTrue(any(i["category"] == "TLS" for i in r["summary"]["issues"]))

    def test_merge_interleaves_and_drops_duplicates(self):
        syn = tcp_pkt("10.0.0.1", "10.0.0.2", 5000, 80, 100, 0, 2)
        synack = tcp_pkt("10.0.0.2", "10.0.0.1", 80, 5000, 500, 101, 0x12)
        a = pcap([(0.0, syn)])
        b = pcap([(0.0, syn), (0.01, synack)])  # first packet duplicated across captures
        r = t.analyze_packets(t.merge_captures([io.BytesIO(a), io.BytesIO(b)]), 2)
        self.assertEqual(r["total_packets"], 2)
        self.assertEqual(r["flow_count"], 1)
        self.assertEqual(r["sources"], 2)
        self.assertAlmostEqual(r["flows"][0]["handshake_rtt_ms"], 10, delta=1)

    def test_summary_ranks_refused_connection(self):
        r = run(pcap([(0, tcp_pkt("10.0.0.1", "10.0.0.2", 40000, 31337, 1, 0, 2)),
                      (0.001, tcp_pkt("10.0.0.2", "10.0.0.1", 31337, 40000, 0, 2, 0x14))]))
        s = r["summary"]
        self.assertEqual(s["issues"][0]["severity"], "high")
        self.assertIn("refused", s["issues"][0]["title"])
        self.assertLess(s["score"], 100)

    def test_summary_healthy_when_clean(self):
        r = run(pcap([(0, tcp_pkt("10.0.0.1", "10.0.0.2", 5000, 80, 100, 0, 2)),
                      (0.01, tcp_pkt("10.0.0.2", "10.0.0.1", 80, 5000, 500, 101, 0x12)),
                      (0.02, tcp_pkt("10.0.0.1", "10.0.0.2", 5000, 80, 101, 501, 0x10))]))
        self.assertEqual(r["summary"]["health"], "healthy")


if __name__ == "__main__":
    unittest.main()
