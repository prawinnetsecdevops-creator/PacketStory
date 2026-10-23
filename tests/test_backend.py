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

    def test_dns_matching_uses_resolver_and_question(self):
        c = "10.0.0.1"
        # same client port and ID, two different resolvers: two outstanding queries, not a retry
        r = run(pcap([
            (0.0, udp_pkt(c, "8.8.8.8", 5555, 53, dns_msg(7, "a.test"))),
            (0.01, udp_pkt(c, "1.1.1.1", 5555, 53, dns_msg(7, "a.test"))),
            (0.05, udp_pkt("8.8.8.8", c, 53, 5555, dns_msg(7, "a.test", 1))),
        ]))["dns"]
        self.assertEqual((r["queries"], r["responses"], r["unanswered"], r["retries"]), (2, 1, 1, 0))
        # same resolver/port/ID but a different question: not a retry, and a mismatched answer does not clear it
        r = run(pcap([
            (0.0, udp_pkt(c, "8.8.8.8", 5555, 53, dns_msg(7, "a.test"))),
            (0.01, udp_pkt(c, "8.8.8.8", 5555, 53, dns_msg(7, "b.test"))),
            (0.05, udp_pkt("8.8.8.8", c, 53, 5555, dns_msg(7, "b.test", 1))),
        ]))["dns"]
        self.assertEqual((r["retries"], r["unanswered"]), (0, 1))
        # a true retry (identical query) is still a retry
        r = run(pcap([
            (0.0, udp_pkt(c, "8.8.8.8", 5555, 53, dns_msg(7, "a.test"))),
            (1.0, udp_pkt(c, "8.8.8.8", 5555, 53, dns_msg(7, "a.test"))),
            (1.05, udp_pkt("8.8.8.8", c, 53, 5555, dns_msg(7, "a.test", 1))),
        ]))["dns"]
        self.assertEqual((r["retries"], r["unanswered"]), (1, 0))
        # a response from a resolver that was never queried does not match
        r = run(pcap([
            (0.0, udp_pkt(c, "8.8.8.8", 5555, 53, dns_msg(7, "a.test"))),
            (0.05, udp_pkt("9.9.9.9", c, 53, 5555, dns_msg(7, "a.test", 1))),
        ]))["dns"]
        self.assertEqual(r["unanswered"], 1)

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


def client_hello_record(sni=b"example.com", pad=0):
    ext = struct.pack(">HHHBH", 0, len(sni) + 5, len(sni) + 3, 0, len(sni)) + sni
    if pad:
        ext += struct.pack(">HH", 21, pad) + b"\x00" * pad
    body = (b"\x03\x03" + b"\x00" * 32 + b"\x00" + struct.pack(">H", 2) + b"\x13\x01" + b"\x01\x00"
            + struct.pack(">H", len(ext)) + ext)
    hs = b"\x01" + struct.pack(">I", len(body))[1:] + body
    return b"\x16\x03\x01" + struct.pack(">H", len(hs)) + hs


def pcap_truncated(packets, snaplen):
    out = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, snaplen, 1)
    for ts, p in packets:
        out += struct.pack("<IIII", int(ts), int((ts % 1) * 1e6), min(len(p), snaplen), len(p)) + p[:snaplen]
    return out


class ReassemblyTests(unittest.TestCase):
    C, S = "10.0.0.1", "10.0.0.2"

    def c2s(self, sport, dport, seq, payload, t=0.0):
        return (t, tcp_pkt(self.C, self.S, sport, dport, seq, 1, 0x18, payload))

    def s2c(self, sport, dport, seq, payload, t=0.0):
        return (t, tcp_pkt(self.S, self.C, sport, dport, seq, 1, 0x18, payload))

    def syn(self, sport, dport, t=0.0):
        return (t, tcp_pkt(self.C, self.S, sport, dport, 0, 0, 2))

    def test_dns_query_split_across_segments(self):
        q = struct.pack(">H", len(dns_msg(9, "split.test"))) + dns_msg(9, "split.test")
        a = struct.pack(">H", len(dns_msg(9, "split.test", 1))) + dns_msg(9, "split.test", 1)
        d = run(pcap([self.c2s(6000, 53, 1, q[:5], 0.0), self.c2s(6000, 53, 6, q[5:], 0.001),
                      self.s2c(53, 6000, 1, a[:20], 0.02), self.s2c(53, 6000, 21, a[20:], 0.03)]))["dns"]
        self.assertEqual((d["queries"], d["responses"], d["unanswered"], d["tcp_messages"]), (1, 1, 0, 2))

    def test_dns_multiple_messages_in_one_segment_and_out_of_order(self):
        m = lambda i, n: struct.pack(">H", len(dns_msg(i, n))) + dns_msg(i, n)
        both = m(1, "a.test") + m(2, "b.test")
        d = run(pcap([self.c2s(6000, 53, 1, both)]))["dns"]
        self.assertEqual(d["queries"], 2)
        q = m(3, "c.test")
        d = run(pcap([self.syn(6001, 53), self.c2s(6001, 53, 6, q[5:], 0.001),
                      self.c2s(6001, 53, 1, q[:5], 0.002)]))["dns"]
        self.assertEqual(d["queries"], 1)

    def test_dns_retransmitted_segment_not_double_counted(self):
        q = struct.pack(">H", len(dns_msg(9, "r.test"))) + dns_msg(9, "r.test")
        d = run(pcap([self.c2s(6000, 53, 1, q, 0.0), self.c2s(6000, 53, 1, q, 1.0)]))["dns"]
        self.assertEqual((d["queries"], d["retries"]), (1, 0))

    def test_tls_client_hello_larger_than_one_segment(self):
        rec = client_hello_record(sni=b"big.example.com", pad=3000)
        f = run(pcap([self.c2s(5000, 443, 1, rec[:1000], 0.0), self.c2s(5000, 443, 1001, rec[1000:2000], 0.001),
                      self.c2s(5000, 443, 2001, rec[2000:], 0.002)]))["flows"][0]
        self.assertEqual((f["application"], f["app_detail"]), ("TLS", "big.example.com"))

    def test_tls_hello_with_sni_after_first_kilobyte_and_reordered(self):
        rec = client_hello_record(sni=b"late.example.com", pad=0)
        # a 1.2 KB extension before SNI would have pushed it past the old 1024-byte cap
        ext = struct.pack(">HH", 21, 1200) + b"\x00" * 1200
        sni = b"late.example.com"
        sni_ext = struct.pack(">HHHBH", 0, len(sni) + 5, len(sni) + 3, 0, len(sni)) + sni
        exts = ext + sni_ext
        body = (b"\x03\x03" + b"\x00" * 32 + b"\x00" + struct.pack(">H", 2) + b"\x13\x01" + b"\x01\x00"
                + struct.pack(">H", len(exts)) + exts)
        hs = b"\x01" + struct.pack(">I", len(body))[1:] + body
        rec = b"\x16\x03\x01" + struct.pack(">H", len(hs)) + hs
        cut = 700
        f = run(pcap([self.syn(5001, 443), self.c2s(5001, 443, 1 + cut, rec[cut:], 0.001),
                      self.c2s(5001, 443, 1, rec[:cut], 0.002)]))["flows"][0]
        self.assertEqual(f["app_detail"], "late.example.com")

    def test_tls_server_hello_split_and_alert(self):
        sh = tls_server_hello()
        f = run(pcap([self.c2s(5000, 443, 1, tls_client_hello(), 0.0), self.s2c(443, 5000, 1, sh[:7], 0.01),
                      self.s2c(443, 5000, 8, sh[7:], 0.02)]))["flows"][0]
        self.assertEqual(f["tls_version"], "TLS 1.3")
        self.assertFalse(any("ServerHello" in x for x in f["findings"]))
        alert = b"\x15\x03\x03\x00\x02\x02\x28"
        f = run(pcap([self.c2s(5002, 443, 1, tls_client_hello(), 0.0), self.s2c(443, 5002, 1, alert[:3], 0.01),
                      self.s2c(443, 5002, 4, alert[3:], 0.02)]))["flows"][0]
        self.assertTrue(any("handshake_failure" in x for x in f["findings"]))

    def test_http_split_head_keepalive_and_bodies(self):
        req = (b"POST /a HTTP/1.1\r\nHost: h.test\r\nContent-Length: 5\r\n\r\nhello"
               b"GET /b HTTP/1.1\r\nHost: h.test\r\n\r\n")
        resp = (b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nabcd\r\n0\r\n\r\n"
                b"HTTP/1.1 503 Busy\r\nContent-Length: 0\r\n\r\n")
        f = run(pcap([self.c2s(5000, 80, 1, req[:20], 0.0), self.c2s(5000, 80, 21, req[20:], 0.001),
                      self.s2c(80, 5000, 1, resp[:60], 0.01), self.s2c(80, 5000, 61, resp[60:], 0.02)]))["flows"][0]
        self.assertEqual(f["http_requests"], 2)
        self.assertEqual(f["http_status"], {"200": 1, "503": 1})
        self.assertEqual(f["app_detail"], "POST /a [h.test]")

    def test_snaplen_truncated_hello_still_parsed(self):
        pkt = tcp_pkt(self.C, self.S, 5000, 443, 1, 1, 0x18, client_hello_record(sni=b"cut.example.com", pad=1000))
        f = run(pcap_truncated([(0.0, pkt)], 54 + 100))["flows"][0]
        self.assertEqual(f["app_detail"], "cut.example.com")

    def test_garbage_stream_is_ignored(self):
        f = run(pcap([self.c2s(5000, 9999, 1, b"\x00\x01binary-ish data that is no known protocol")]))["flows"][0]
        self.assertIsNone(f["app_detail"])


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

    def test_merge_keeps_repeats_within_one_source(self):
        syn = tcp_pkt("10.0.0.1", "10.0.0.2", 5000, 80, 100, 0, 2)
        def count(*caps):
            return sum(1 for _ in t.merge_captures([io.BytesIO(c) for c in caps]))
        a = pcap([(0.0, syn), (0.0005, syn)])
        self.assertEqual(count(a), 2)
        self.assertEqual(count(a, pcap([(0.0, syn)])), 2)           # B pairs with one A copy
        self.assertEqual(count(a, a), 2)                            # full overlap collapses to 2
        self.assertEqual(count(a, pcap([(0.0, syn), (0.0004, syn), (0.0008, syn)])), 3)
        self.assertEqual(count(a, pcap([(5.0, syn)])), 3)           # outside window: distinct

    def test_malformed_pcapng_is_rejected(self):
        good = pcapng([(0, tcp_pkt("10.0.0.1", "10.0.0.2", 5000, 80, 1, 0, 2))])
        shb_len = struct.unpack("<I", good[4:8])[0]
        self.assertGreater(len(run(good)["flows"]), 0)
        bad = {
            "truncated section header": good[:20],
            "section trailer mismatch": good[:shb_len - 4] + struct.pack("<I", 99) + good[shb_len:],
            "block trailer mismatch": good[:-4] + struct.pack("<I", 12),
            "truncated block": good[:-6],
        }
        # captured length larger than the block body
        epb = good.rfind(struct.pack("<I", 6))
        cap_off = epb + 8 + 12
        bad["cap exceeds block"] = good[:cap_off] + struct.pack("<I", 5000) + good[cap_off + 4:]
        bad["cap exceeds orig"] = (good[:cap_off] + struct.pack("<I", 70) + struct.pack("<I", 60)
                                   + good[cap_off + 8:])
        for name, raw in bad.items():
            with self.subTest(name), self.assertRaises(t.CaptureError):
                run(raw)

    def test_no_decodable_packets_is_not_healthy(self):
        for raw in (pcap([]), pcap([(0, b"\x00" * 20)]), pcapng([(0, b"\x00" * 20)])):
            r = run(raw)
            self.assertEqual(r["summary"]["health"], "no data")
            self.assertIsNone(r["summary"]["score"])
            self.assertEqual(r["analyzable_packets"], 0)

    def test_summary_ranks_refused_connection(self):
        r = run(pcap([(0, tcp_pkt("10.0.0.1", "10.0.0.2", 40000, 31337, 1, 0, 2)),
                      (0.001, tcp_pkt("10.0.0.2", "10.0.0.1", 31337, 40000, 0, 2, 0x14))]))
        s = r["summary"]
        self.assertEqual(s["issues"][0]["severity"], "high")
        self.assertIn("refused", s["issues"][0]["title"])
        self.assertLess(s["score"], 100)

    def test_reordering_is_not_retransmission(self):
        c, s = "10.0.0.1", "10.0.0.2"
        seg = lambda t, seq: (t, tcp_pkt(c, s, 40000, 80, seq, 1, 0x10, payload=b"x" * 100))
        r = run(pcap([seg(0.000, 100), seg(0.001, 300), seg(0.002, 200)]))
        f = r["flows"][0]
        self.assertEqual((f["retransmissions"], f["reordered"]), (0, 1))

    def test_late_hole_fill_duplicate_and_overlap_are_retransmissions(self):
        c, s = "10.0.0.1", "10.0.0.2"
        seg = lambda t, seq, n=100: (t, tcp_pkt(c, s, 40000, 80, seq, 1, 0x10, payload=b"x" * n))
        late = run(pcap([seg(0.0, 100), seg(0.001, 300), seg(1.0, 200)]))["flows"][0]
        self.assertEqual((late["retransmissions"], late["reordered"]), (1, 0))
        dup = run(pcap([seg(0.0, 100), seg(0.001, 200), seg(0.002, 100)]))["flows"][0]
        self.assertEqual((dup["retransmissions"], dup["reordered"]), (1, 0))
        part = run(pcap([seg(0.0, 100), seg(0.001, 150, 100)]))["flows"][0]
        self.assertEqual(part["retransmissions"], 1)

    def test_sequence_wraparound_is_not_retransmission(self):
        c, s = "10.0.0.1", "10.0.0.2"
        seg = lambda t, seq: (t, tcp_pkt(c, s, 40000, 80, seq, 1, 0x10, payload=b"x" * 100))
        r = run(pcap([seg(0.0, 0xFFFFFFC0), seg(0.001, 0x24), seg(0.002, 0x88)]))
        self.assertEqual(r["flows"][0]["retransmissions"], 0)

    def test_pmtu_requires_evidence_of_small_packets_passing(self):
        c, s = "10.0.0.1", "10.0.0.2"
        big = lambda t: (t, tcp_pkt(c, s, 40000, 80, 101, 501, 0x10, payload=b"x" * 1400))
        # large segment repeated, but no handshake and no small traffic: not a black hole
        f = run(pcap([big(0.0), big(1.0), big(3.0)]))["flows"][0]
        self.assertFalse(any("black hole: " in x for x in f["findings"]))
        self.assertTrue(any("low confidence" in x for x in f["findings"]))
        # same, but the handshake completed first: black hole is reported
        hs = [(0.0, tcp_pkt(c, s, 40000, 80, 100, 0, 2)),
              (0.01, tcp_pkt(s, c, 80, 40000, 500, 101, 0x12)),
              (0.02, tcp_pkt(c, s, 40000, 80, 101, 501, 0x10))]
        r = run(pcap(hs + [big(0.03), big(1.0), big(3.0)]))
        self.assertTrue(any("black hole: " in x for x in r["flows"][0]["findings"]))
        self.assertEqual(r["summary"]["issues"][0]["severity"], "critical")
        # large segment eventually acknowledged: no black hole
        ok = run(pcap(hs + [big(0.03), big(1.0), big(3.0),
                            (3.1, tcp_pkt(s, c, 80, 40000, 501, 1501, 0x10))]))["flows"][0]
        self.assertFalse(any("PMTU" in x for x in ok["findings"]))

    def test_summary_healthy_when_clean(self):
        r = run(pcap([(0, tcp_pkt("10.0.0.1", "10.0.0.2", 5000, 80, 100, 0, 2)),
                      (0.01, tcp_pkt("10.0.0.2", "10.0.0.1", 80, 5000, 500, 101, 0x12)),
                      (0.02, tcp_pkt("10.0.0.1", "10.0.0.2", 5000, 80, 101, 501, 0x10))]))
        self.assertEqual(r["summary"]["health"], "healthy")

    def test_reset_then_new_syn_is_separate_flows(self):
        c, s = "10.0.0.1", "10.0.0.2"
        r = run(pcap([
            (0.0, tcp_pkt(c, s, 40000, 80, 100, 0, 2)),
            (0.01, tcp_pkt(s, c, 80, 40000, 500, 101, 0x12)),
            (0.02, tcp_pkt(c, s, 40000, 80, 101, 501, 0x10)),
            (0.03, tcp_pkt(s, c, 80, 40000, 501, 101, 0x04)),
            (1.0, tcp_pkt(c, s, 40000, 80, 9000, 0, 2)),
            (1.01, tcp_pkt(s, c, 80, 40000, 7000, 9001, 0x12)),
            (1.02, tcp_pkt(c, s, 40000, 80, 9001, 7001, 0x10)),
        ]))
        self.assertEqual(len(r["flows"]), 2)
        self.assertEqual([f["state"] for f in r["flows"]], ["reset", "established"])
        self.assertEqual(r["flows"][1]["resets"], 0)

    def test_retransmitted_syn_stays_in_one_flow(self):
        c, s = "10.0.0.1", "10.0.0.2"
        r = run(pcap([(0.0, tcp_pkt(c, s, 40000, 80, 100, 0, 2)),
                      (1.0, tcp_pkt(c, s, 40000, 80, 100, 0, 2)),
                      (1.01, tcp_pkt(s, c, 80, 40000, 500, 101, 0x12)),
                      (1.02, tcp_pkt(s, c, 80, 40000, 500, 101, 0x12))]))
        self.assertEqual(len(r["flows"]), 1)
        self.assertEqual(r["flows"][0]["retransmissions"], 2)

    def test_connection_reuse_after_reset_without_new_isn(self):
        C, S = "10.0.0.1", "10.0.0.2"
        c = lambda seq, ack, fl, d=b"": tcp_pkt(C, S, 5000, 80, seq, ack, fl, d)
        s = lambda seq, ack, fl, d=b"": tcp_pkt(S, C, 80, 5000, seq, ack, fl, d)

        def flows(pk, gap=0.01):
            return run(pcap([(i * gap, p) for i, p in enumerate(pk)]))["flow_count"]

        # refused, then retried with the same ISN
        self.assertEqual(flows([c(100, 0, 2), s(0, 101, 0x14), c(100, 0, 2), s(0, 101, 0x14)]), 2)
        # established, reset, same ISN again
        self.assertEqual(flows([c(100, 0, 2), s(500, 101, 0x12), c(101, 501, 0x10),
                                s(501, 101, 0x14), c(100, 0, 2)]), 2)
        # midstream captures (no SYN): data long after a RST, or data from the side that sent it
        self.assertEqual(flows([c(1000, 1, 0x18, b"a" * 10), s(1, 1010, 0x14),
                                c(5000, 1, 0x18, b"b" * 10)], gap=2), 2)
        self.assertEqual(flows([c(1000, 1, 0x18, b"a" * 10), s(1, 1010, 0x14),
                                s(1, 1010, 0x18, b"b" * 5)]), 2)
        # in-flight data right behind a RST, and retransmitted SYN/SYN-ACK, stay in one flow
        self.assertEqual(flows([c(1000, 1, 0x18, b"a" * 10), s(1, 1010, 0x14),
                                c(1010, 1, 0x18, b"b" * 10)]), 1)
        self.assertEqual(flows([c(100, 0, 2), c(100, 0, 2), s(500, 101, 0x12), s(500, 101, 0x12)]), 1)

    def test_fin_close_then_port_reuse(self):
        c, s = "10.0.0.1", "10.0.0.2"
        r = run(pcap([
            (0.0, tcp_pkt(c, s, 40000, 80, 100, 0, 2)),
            (0.01, tcp_pkt(s, c, 80, 40000, 500, 101, 0x12)),
            (0.02, tcp_pkt(c, s, 40000, 80, 101, 501, 0x10)),
            (0.03, tcp_pkt(c, s, 40000, 80, 101, 501, 0x11)),
            (2.0, tcp_pkt(c, s, 40000, 80, 777, 0, 2)),
            (2.01, tcp_pkt(s, c, 80, 40000, 888, 778, 0x12)),
        ]))
        self.assertEqual(len(r["flows"]), 2)


if __name__ == "__main__":
    unittest.main()
