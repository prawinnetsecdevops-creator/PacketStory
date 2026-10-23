"""Packet capture analysis backend (stdlib only).

Reads classic PCAP and PCAPNG captures (Ethernet/VLAN/Linux SLL/raw IP, IPv4 + IPv6)
and analyzes every port and protocol:
  * TCP   - flows, handshake, resets, retransmissions, windows, MTU/MSS, RTT, TLS/HTTP hints
  * UDP   - flows, one-way traffic, DNS and DHCP diagnostics
  * ICMP / ICMPv6 - echo RTT/loss, unreachable, time exceeded, neighbor discovery
  * ARP   - unanswered requests, duplicate IPs
  * other IP protocols (GRE, ESP, OSPF, SCTP, ...) counted in the protocol breakdown

Run:   python analyzer_backend.py [--host 127.0.0.1] [--port 8000]
API:   POST /api/analyze        raw capture bytes as body                      -> JSON
       POST /api/analyze/merge  several captures concatenated; header
                                X-File-Sizes: n1,n2,...  gives each length     -> one merged JSON
       GET  /api/health
CLI:   python analyzer_backend.py capture.pcap [more.pcap ...]   (several files are merged)
"""

from __future__ import annotations

import argparse
import hashlib
import heapq
import io
import ipaddress
import json
import os
import struct
import sys
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import BinaryIO

from protocols import CaptureError, Extras, parse_other, read_capture, service_for
from streams import AppStream
from summary import build_summary

MAX_UPLOAD = 200 * 1024 * 1024
MAX_PACKET_ROWS = 5_000

DLT_NULL, DLT_EN10MB, DLT_RAW, DLT_LINUX_SLL, DLT_IPV4, DLT_IPV6 = 0, 1, 101, 113, 228, 229
VLAN_TYPES = {0x8100, 0x88A8, 0x9100}
IPV6_EXT = {0, 43, 60, 135, 139, 140}  # hop-by-hop, routing, dest opts, ...

FIN, SYN, RST, PSH, ACK, URG = 0x01, 0x02, 0x04, 0x08, 0x10, 0x20
FLAG_NAMES = [(SYN, "SYN"), (FIN, "FIN"), (RST, "RST"), (PSH, "PSH"), (ACK, "ACK"), (URG, "URG")]


@dataclass
class TcpPacket:
    number: int
    time: float
    src: str
    dst: str
    sport: int
    dport: int
    seq: int
    ack: int
    flags: int
    window: int
    payload_len: int
    ip_version: int
    frame_len: int = 0
    ip_len: int = 0
    ttl: int = 0
    df: bool = False
    mss: int | None = None
    wscale: int | None = None
    sack_perm: bool = False
    has_sack: bool = False
    payload: bytes = b""
    lost: int = 0  # payload bytes cut off by the capture snaplen

    @property
    def flag_str(self) -> str:
        return ",".join(n for b, n in FLAG_NAMES if self.flags & b) or "none"

    def to_dict(self) -> dict:
        return {
            "no": self.number, "time": self.time,
            "src": self.src, "sport": self.sport,
            "dst": self.dst, "dport": self.dport,
            "seq": self.seq, "ack": self.ack, "flags": self.flag_str,
            "window": self.window, "len": self.payload_len,
            "frame": self.frame_len, "ip_len": self.ip_len, "ttl": self.ttl, "df": self.df,
        }


def _l3_offset(data: bytes, link: int) -> tuple[int, int] | None:
    """Return (offset, ethertype-like 4/6) of the IP header, or None."""
    if link == DLT_EN10MB:
        if len(data) < 14:
            return None
        off, et = 14, struct.unpack(">H", data[12:14])[0]
        while et in VLAN_TYPES and len(data) >= off + 4:
            et = struct.unpack(">H", data[off + 2:off + 4])[0]
            off += 4
        return (off, 4) if et == 0x0800 else (off, 6) if et == 0x86DD else None
    if link == DLT_LINUX_SLL:
        if len(data) < 16:
            return None
        et = struct.unpack(">H", data[14:16])[0]
        return (16, 4) if et == 0x0800 else (16, 6) if et == 0x86DD else None
    if link == DLT_NULL:
        if len(data) < 4:
            return None
        fam = struct.unpack("<I", data[:4])[0]
        if fam > 0xFFFF:
            fam = struct.unpack(">I", data[:4])[0]
        return (4, 4) if fam == 2 else (4, 6) if fam in (10, 24, 28, 30) else None
    if link in (DLT_RAW, DLT_IPV4, DLT_IPV6) and data:
        ver = data[0] >> 4
        return (0, ver) if ver in (4, 6) else None
    return None


def _tcp_options(opts: bytes) -> tuple[int | None, int | None, bool, bool]:
    mss = wscale = None
    sack_perm = has_sack = False
    i = 0
    while i < len(opts):
        kind = opts[i]
        if kind == 0:
            break
        if kind == 1:
            i += 1
            continue
        if i + 1 >= len(opts) or opts[i + 1] < 2:
            break
        ln = opts[i + 1]
        body = opts[i + 2:i + ln]
        if kind == 2 and len(body) == 2:
            mss = struct.unpack(">H", body)[0]
        elif kind == 3 and len(body) == 1:
            wscale = body[0]
        elif kind == 4:
            sack_perm = True
        elif kind == 5:
            has_sack = True
        i += ln
    return mss, wscale, sack_perm, has_sack


def parse_icmp_ptb(ts: float, data: bytes, link: int) -> dict | None:
    """Detect ICMP 'fragmentation needed' (v4) / 'packet too big' (v6) messages."""
    loc = _l3_offset(data, link)
    if not loc:
        return None
    off, ver = loc
    if ver == 4:
        if len(data) < off + 28 or data[off + 9] != 1:
            return None
        icmp = off + (data[off] & 0x0F) * 4
        if len(data) < icmp + 8 or data[icmp] != 3 or data[icmp + 1] != 4:
            return None
        src = str(ipaddress.IPv4Address(data[off + 12:off + 16]))
        mtu = struct.unpack(">H", data[icmp + 6:icmp + 8])[0]
        inner = icmp + 8
        target = None
        if len(data) >= inner + 20:
            target = str(ipaddress.IPv4Address(data[inner + 16:inner + 20]))
    else:
        if len(data) < off + 48 or data[off + 6] != 58:
            return None
        icmp = off + 40
        if data[icmp] != 2:
            return None
        src = str(ipaddress.IPv6Address(data[off + 8:off + 24]))
        mtu = struct.unpack(">I", data[icmp + 4:icmp + 8])[0]
        inner = icmp + 8
        target = None
        if len(data) >= inner + 40:
            target = str(ipaddress.IPv6Address(data[inner + 24:inner + 40]))
    return {"time": ts, "reporter": src, "next_hop_mtu": mtu, "original_destination": target}


def parse_tcp(number: int, ts: float, data: bytes, link: int, orig_len: int = 0) -> TcpPacket | None:
    loc = _l3_offset(data, link)
    if not loc:
        return None
    off, ver = loc
    df = False
    if ver == 4:
        if len(data) < off + 20:
            return None
        ihl = (data[off] & 0x0F) * 4
        total = struct.unpack(">H", data[off + 2:off + 4])[0]
        frag = struct.unpack(">H", data[off + 6:off + 8])[0] & 0x1FFF
        if data[off + 9] != 6 or frag or ihl < 20:
            return None
        df = bool(data[off + 6] & 0x40)
        ttl = data[off + 8]
        ip_len = total
        src = str(ipaddress.IPv4Address(data[off + 12:off + 16]))
        dst = str(ipaddress.IPv4Address(data[off + 16:off + 20]))
        tcp_off = off + ihl
        want_end = off + total if total >= ihl else len(data)
        ip_end = min(len(data), want_end)
    else:
        if len(data) < off + 40:
            return None
        plen = struct.unpack(">H", data[off + 4:off + 6])[0]
        nxt = data[off + 6]
        ttl = data[off + 7]
        ip_len = plen + 40
        src = str(ipaddress.IPv6Address(data[off + 8:off + 24]))
        dst = str(ipaddress.IPv6Address(data[off + 24:off + 40]))
        tcp_off = off + 40
        while nxt in IPV6_EXT:
            if len(data) < tcp_off + 8:
                return None
            nxt, ext_len = data[tcp_off], data[tcp_off + 1]
            tcp_off += (ext_len + 1) * 8
        if nxt != 6:
            return None
        want_end = off + 40 + plen if plen else len(data)
        ip_end = min(len(data), want_end)
    if len(data) < tcp_off + 20:
        return None
    sport, dport, seq, ack, doff, flags, win = struct.unpack(">HHIIBBH", data[tcp_off:tcp_off + 16])
    hlen = (doff >> 4) * 4
    if hlen < 20:
        return None
    mss, wscale, sack_perm, has_sack = _tcp_options(data[tcp_off + 20:tcp_off + hlen])
    payload_len = max(0, ip_end - tcp_off - hlen)
    return TcpPacket(number, ts, src, dst, sport, dport, seq, ack, flags & 0x3F, win,
                     payload_len, ver,
                     orig_len or len(data), ip_len, ttl, df, mss, wscale, sack_perm, has_sack,
                     data[tcp_off + hlen:ip_end], max(0, want_end - ip_end))


@dataclass
class Flow:
    id: int
    client: tuple[str, int]
    server: tuple[str, int]
    packets: list[TcpPacket] = field(default_factory=list)
    bytes_c2s: int = 0
    bytes_s2c: int = 0
    resets: int = 0
    retransmissions: int = 0
    zero_windows: int = 0
    dup_acks: int = 0
    syn_time: float | None = None
    syn_seq: int | None = None
    synack_seq: int | None = None
    synack_time: float | None = None
    ack_time: float | None = None
    fin_seen: bool = False
    _ranges: dict = field(default_factory=dict)
    _seq_base: dict = field(default_factory=dict)
    _high_time: dict = field(default_factory=dict)
    reordered: int = 0
    _last_ack: dict = field(default_factory=dict)
    max_ip_len: int = 0
    max_frame: int = 0
    max_payload: int = 0
    frame_sum: int = 0
    ttl: dict = field(default_factory=dict)
    mss: dict = field(default_factory=dict)
    wscale: dict = field(default_factory=dict)
    sack_perm: dict = field(default_factory=dict)
    sack_blocks: int = 0
    min_win: dict = field(default_factory=dict)
    max_win: dict = field(default_factory=dict)
    df_seen: bool = False
    retrans_payloads: list = field(default_factory=list)
    max_gap: float = 0.0
    max_gap_at: float = 0.0
    rtt_samples: list = field(default_factory=list)
    _pending: dict = field(default_factory=dict)
    _bh_first: dict = field(default_factory=dict)
    _bh_unacked: dict = field(default_factory=dict)
    small_ok: int = 0
    first_data_c2s: float | None = None
    first_data_s2c: float | None = None
    ptb_mtu: int | None = None
    app: str | None = None
    app_detail: str | None = None
    tls_version: str | None = None
    http_requests: int = 0
    http_status: dict = field(default_factory=dict)
    tls_alert: tuple | None = None
    tls_alpn: list = field(default_factory=list)
    server_hello: bool = False
    tls_hrr: bool = False

    _streams: dict = field(default_factory=dict)
    dns_msgs: list = field(default_factory=list)

    def _app_data(self, p: TcpPacket, c2s: bool) -> None:
        """Feed the segment to this direction's reassembling application parser."""
        st = self._streams.get(c2s)
        if st is None:
            st = self._streams[c2s] = AppStream(server_side=not c2s, dns=53 in (p.sport, p.dport))
        if p.flags & SYN:
            st.syn(p.seq)
        if p.payload or p.lost:
            for kind, value in st.feed(p.seq, p.payload, p.lost):
                self._app_event(kind, value, p)

    def _app_event(self, kind: str, v, p: TcpPacket) -> None:
        if kind == "dns":
            self.dns_msgs.append((p.time, p.src, p.sport, p.dst, p.dport, v))
        elif kind == "tls_alert":
            self.tls_alert = self.tls_alert or v
        elif kind == "http_req":
            self.http_requests += 1
            self.app = "HTTP"
            self.app_detail = self.app_detail or v
        elif kind == "http_resp":
            self.http_status[v] = self.http_status.get(v, 0) + 1
            self.app = self.app or "HTTP"
        elif kind == "tls_client_hello":
            if self.app is None:
                self.app, self.app_detail, self.tls_version, self.tls_alpn = "TLS", v[0], v[1], v[2]
        elif kind == "tls_server_hello":
            if self.app == "TLS":
                self.server_hello = True
                self.tls_version = v[0] or self.tls_version
                self.tls_hrr = self.tls_hrr or v[1]
        elif kind == "ssh":
            if self.app is None:
                self.app, self.app_detail = "SSH", v

    def state(self) -> str:
        if self.resets:
            return "reset"
        if self.fin_seen:
            return "closed"
        if self.ack_time is not None:
            return "established"
        if self.synack_time is not None:
            return "handshake-incomplete"
        if self.syn_time is not None:
            return "syn-unanswered"
        return "midstream"

    def _track(self, p: TcpPacket, c2s: bool) -> None:
        if len(self.packets) > 1:
            gap = p.time - self.packets[-2].time
            if gap > self.max_gap:
                self.max_gap, self.max_gap_at = gap, p.time
        self.max_ip_len = max(self.max_ip_len, p.ip_len)
        self.max_frame = max(self.max_frame, p.frame_len)
        self.max_payload = max(self.max_payload, p.payload_len)
        self.frame_sum += p.frame_len
        self.df_seen = self.df_seen or p.df
        self.ttl.setdefault(c2s, [p.ttl, p.ttl])
        self.ttl[c2s] = [min(self.ttl[c2s][0], p.ttl), max(self.ttl[c2s][1], p.ttl)]
        if p.mss is not None:
            self.mss[c2s] = p.mss
        if p.wscale is not None:
            self.wscale[c2s] = p.wscale
        if p.flags & SYN:
            self.sack_perm[c2s] = p.sack_perm
        elif not p.flags & RST:
            scaled = p.window << self.wscale.get(c2s, 0)
            self.min_win[c2s] = min(self.min_win.get(c2s, scaled), scaled)
            self.max_win[c2s] = max(self.max_win.get(c2s, scaled), scaled)
        if p.has_sack:
            self.sack_blocks += 1
        if p.payload_len:
            if c2s and self.first_data_c2s is None:
                self.first_data_c2s = p.time
            elif not c2s and self.first_data_s2c is None and self.first_data_c2s is not None:
                self.first_data_s2c = p.time
        if p.flags & ACK:
            sent = self._pending.get(not c2s)
            if sent and p.ack in sent:
                t0, size = sent.pop(p.ack)
                self.rtt_samples.append((p.time - t0) * 1000)
                if size <= 0.5 * self.max_payload:
                    self.small_ok += 1  # a small data segment was delivered and acknowledged
            stuck = self._bh_unacked.get(not c2s)
            if stuck:
                for end in [e for e in stuck if ((p.ack - e) & 0xFFFFFFFF) < 0x7FFFFFFF]:
                    del stuck[end]  # the peer eventually acknowledged this large segment

    def _classify_segment(self, c2s: bool, seq: int, span: int, t: float) -> tuple[str, int]:
        """Return ("new" | "reorder" | "retrans", end_seq) for a segment and record its byte range.

        retrans: bytes already seen (full or partial overlap), or a hole filled long after the
                 higher data arrived (original was likely lost before the capture point).
        reorder: previously unseen bytes that fill a hole shortly after higher data arrived.
        """
        end32 = (seq + span) & 0xFFFFFFFF
        base = self._seq_base.setdefault(c2s, seq)
        s = ((seq - base + 0x80000000) & 0xFFFFFFFF) - 0x80000000  # signed offset handles wraparound
        e = s + span
        ranges = self._ranges.setdefault(c2s, [])
        high = ranges[-1][1] if ranges else None

        overlap = any(a < e and s < b for a, b in ranges)
        if overlap:
            kind = "retrans"
        elif high is None or s >= high:
            kind = "new"
        else:
            window = max(0.003, min(self.rtt_samples) / 1000 if self.rtt_samples else 0.0)
            kind = "reorder" if t - self._high_time.get(c2s, t) <= window else "retrans"

        # merge [s, e) into the sorted range list
        merged, placed = [], False
        for a, b in ranges:
            if b < s:
                merged.append([a, b])
            elif e < a:
                if not placed:
                    merged.append([s, e])
                    placed = True
                merged.append([a, b])
            else:
                s, e = min(s, a), max(e, b)
        if not placed:
            merged.append([s, e])
        self._ranges[c2s] = merged[-256:]  # bound memory on long, lossy flows
        if high is None or merged[-1][1] > high:
            self._high_time[c2s] = t
        return kind, end32

    def add(self, p: TcpPacket) -> None:
        c2s = (p.src, p.sport) == self.client
        self.packets.append(p)
        self._track(p, c2s)
        self._app_data(p, c2s)
        if c2s:
            self.bytes_c2s += p.payload_len
        else:
            self.bytes_s2c += p.payload_len
        if p.flags & RST:
            self.resets += 1
        if p.flags & FIN:
            self.fin_seen = True
        if p.window == 0 and not p.flags & (SYN | RST):
            self.zero_windows += 1
        if p.flags & SYN and not p.flags & ACK and self.syn_time is None:
            self.syn_time, self.syn_seq = p.time, p.seq
        elif p.flags & SYN and p.flags & ACK and self.synack_time is None:
            self.synack_time, self.synack_seq = p.time, p.seq
        elif (p.flags & ACK and c2s and self.synack_time is not None and self.ack_time is None
              and not p.flags & SYN):
            self.ack_time = p.time

        # Track received sequence ranges per direction to tell retransmission from reordering.
        span = p.payload_len + (1 if p.flags & (SYN | FIN) else 0)
        if span:
            kind, end = self._classify_segment(c2s, p.seq, span, p.time)
            if kind == "retrans":
                self.retransmissions += 1
                if p.payload_len:
                    self.retrans_payloads.append((p.payload_len, p.df))
                    if p.df and p.payload_len >= max(1000, 0.8 * self.max_payload):
                        self._bh_first.setdefault(c2s, p.time)
                        stuck = self._bh_unacked.setdefault(c2s, {})
                        stuck[end] = stuck.get(end, 0) + 1
                self._pending.get(c2s, {}).pop(end, None)
            elif kind == "reorder":
                self.reordered += 1
            elif p.payload_len:
                pend = self._pending.setdefault(c2s, {})
                if len(pend) < 2000:
                    pend[end] = (p.time, p.payload_len)
        elif p.flags & ACK and not p.flags & (SYN | FIN | RST):
            key = (c2s, p.ack)
            if self._last_ack.get(c2s) == key and p.window != 0:
                self.dup_acks += 1
            self._last_ack[c2s] = key

    def findings(self) -> list[str]:
        out = []
        if self.state() == "syn-unanswered":
            out.append("SYN got no reply (filtered, dropped, or host down).")
        if self.state() == "handshake-incomplete":
            out.append("SYN/ACK seen but handshake never completed.")
        if self.resets and self.syn_time is not None and self.synack_time is None:
            out.append("SYN answered with RST: connection refused (nothing listening, or a firewall is rejecting).")
        elif self.resets:
            out.append(f"{self.resets} RST packet(s): connection aborted.")
        bad = {c: n for c, n in self.http_status.items() if c >= 400}
        if bad:
            out.append("HTTP error responses: " + ", ".join(f"{c}Ã—{n}" for c, n in sorted(bad.items())) + ".")
        if self.tls_alert and not (self.tls_alert[0] == 1 and self.tls_alert[1] == "close_notify"):
            out.append(f"TLS alert: {self.tls_alert[1]}" + (" (fatal)." if self.tls_alert[0] == 2 else "."))
        if self.app == "TLS" and not self.server_hello and self.state() in ("established", "closed", "reset") \
                and self.bytes_s2c == 0:
            out.append("TLS ClientHello got no ServerHello: server or middlebox is not completing the handshake "
                       "(SNI filtering, TLS inspection, or server overloaded).")
        if self.tls_version in ("SSL 3.0", "TLS 1.0", "TLS 1.1"):
            out.append(f"Deprecated {self.tls_version} negotiated: modern clients/servers may refuse it.")
        if self.tls_hrr:
            out.append("TLS HelloRetryRequest: server rejected the client's key share (extra round trip).")
        if self.retransmissions:
            out.append(f"{self.retransmissions} retransmission(s): possible packet loss.")
        if self.reordered:
            out.append(f"{self.reordered} out-of-order segment(s): packets arrived reordered (no data was resent).")
        if self.dup_acks >= 3:
            out.append(f"{self.dup_acks} duplicate ACKs: likely loss or reordering.")
        if self.zero_windows:
            out.append(f"{self.zero_windows} zero-window packet(s): receiver is overloaded.")
        if self.ptb_mtu:
            out.append(f"ICMP 'fragmentation needed / packet too big' received: path MTU is {self.ptb_mtu}.")
        stuck = sum(n for d in self._bh_unacked.values() for n in d.values())
        # small packets passing: the handshake completed, or small data segments were acknowledged
        small_ok = self.small_ok or (self.syn_time is not None and self.ack_time is not None)
        if stuck >= 2 and small_ok:
            out.append("Possible PMTU black hole: full-size DF segments were retransmitted and never acknowledged, "
                       "while smaller packets (handshake / small segments) got through. "
                       "Try lowering MTU / clamping MSS.")
        elif stuck >= 2:
            out.append("Full-size DF segments were retransmitted without acknowledgement, but no smaller traffic "
                       "succeeded to confirm a size problem: more likely ordinary loss or a stalled peer "
                       "(PMTU issue is possible, low confidence).")
        if self.retransmissions and self.sack_perm and not all(self.sack_perm.get(k) for k in (True, False)):
            out.append("SACK not negotiated by both sides: loss recovery will be slower.")
        for c2s, name, peer_bytes in ((False, "server", self.bytes_c2s), (True, "client", self.bytes_s2c)):
            win = self.max_win.get(c2s)
            if win is not None and peer_bytes > 100_000 and win < 16_384:
                out.append(f"{name} receive window peaked at {win} bytes: throughput is window-limited.")
        resp = self.server_response_ms()
        if resp is not None and resp > 1000:
            out.append(f"Slow server response: {resp:.0f} ms from first request data to first reply data.")
        if self.rtt_samples and sum(self.rtt_samples) / len(self.rtt_samples) > 150:
            out.append("High average round-trip time (>150 ms).")
        if self.max_gap > 5:
            out.append(f"Idle gap of {self.max_gap:.1f} s in the flow (stall or keepalive timeout).")
        return out

    def notes(self) -> list[str]:
        out = []
        mss = self.mss_negotiated()
        if mss is not None:
            v6 = self.packets[0].ip_version == 6
            mtu = mss + (60 if v6 else 40)
            if mss < (1440 if v6 else 1460):
                out.append(f"MSS {mss} implies path MTU of about {mtu} (<1500): tunnel/VPN/PPPoE overhead or MSS clamping.")
        if self.max_ip_len > 1500:
            out.append(f"IP packets up to {self.max_ip_len} bytes: capture-host offload (TSO/GRO) or jumbo frames; "
                       "not the real on-wire size.")
        return out

    def mss_negotiated(self) -> int | None:
        vals = list(self.mss.values())
        return min(vals) if vals else None

    def server_response_ms(self) -> float | None:
        if self.first_data_c2s is None or self.first_data_s2c is None:
            return None
        return (self.first_data_s2c - self.first_data_c2s) * 1000

    @staticmethod
    def _hops(ttl: int) -> int:
        initial = next((i for i in (32, 64, 128, 255) if ttl <= i), 255)
        return initial - ttl

    def summary(self) -> dict:
        rtt = (self.synack_time - self.syn_time) * 1000 if self.syn_time is not None and self.synack_time is not None else None
        n = len(self.packets)
        duration = self.packets[-1].time - self.packets[0].time
        data_pkts = sum(1 for p in self.packets if p.payload_len)
        mss = self.mss_negotiated()
        v6 = self.packets[0].ip_version == 6
        samples = self.rtt_samples
        resp = self.server_response_ms()
        return {
            "id": self.id,
            "client": f"{self.client[0]}:{self.client[1]}",
            "server": f"{self.server[0]}:{self.server[1]}",
            "state": self.state(),
            "packets": n,
            "bytes_client_to_server": self.bytes_c2s,
            "bytes_server_to_client": self.bytes_s2c,
            "start": self.packets[0].time,
            "duration": duration,
            "handshake_rtt_ms": round(rtt, 3) if rtt is not None else None,
            "resets": self.resets,
            "retransmissions": self.retransmissions,
            "retransmission_pct": round(100 * self.retransmissions / data_pkts, 2) if data_pkts else 0,
            "reordered": self.reordered,
            "dup_acks": self.dup_acks,
            "zero_windows": self.zero_windows,
            "ip_version": 6 if v6 else 4,
            "avg_frame_size": round(self.frame_sum / n),
            "max_frame_size": self.max_frame,
            "max_ip_packet": self.max_ip_len,
            "max_payload": self.max_payload,
            "df_set": self.df_seen,
            "mss_client": self.mss.get(True),
            "mss_server": self.mss.get(False),
            "mtu_from_mss": mss + (60 if v6 else 40) if mss is not None else None,
            "icmp_mtu": self.ptb_mtu,
            "wscale_client": self.wscale.get(True),
            "wscale_server": self.wscale.get(False),
            "sack_client": self.sack_perm.get(True),
            "sack_server": self.sack_perm.get(False),
            "sack_blocks": self.sack_blocks,
            "min_window_client": self.min_win.get(True),
            "min_window_server": self.min_win.get(False),
            "max_window_client": self.max_win.get(True),
            "max_window_server": self.max_win.get(False),
            "ttl_client": self.ttl.get(True),
            "ttl_server": self.ttl.get(False),
            "hops_client": self._hops(self.ttl[True][1]) if True in self.ttl else None,
            "hops_server": self._hops(self.ttl[False][1]) if False in self.ttl else None,
            "rtt_min_ms": round(min(samples), 3) if samples else None,
            "rtt_avg_ms": round(sum(samples) / len(samples), 3) if samples else None,
            "rtt_max_ms": round(max(samples), 3) if samples else None,
            "server_response_ms": round(resp, 3) if resp is not None else None,
            "max_idle_gap": round(self.max_gap, 6),
            "throughput_kbps": round((self.bytes_c2s + self.bytes_s2c) * 8 / 1000 / duration, 2) if duration > 0 else None,
            "findings": self.findings(),
            "notes": self.notes(),
            "application": self.app or service_for(self.client[1], self.server[1]),
            "app_detail": self.app_detail,
            "tls_version": self.tls_version,
            "tls_alpn": self.tls_alpn,
            "tls13_encrypted": self.tls_version == "TLS 1.3",
            "http_requests": self.http_requests,
            "http_status": {str(k): v for k, v in self.http_status.items()},
        }


def _orient(p: TcpPacket) -> tuple[tuple[str, int], tuple[str, int]]:
    """Pick (client, server): SYN sender is client; else lower port is server."""
    a, b = (p.src, p.sport), (p.dst, p.dport)
    if p.flags & SYN:
        return (b, a) if p.flags & ACK else (a, b)
    return (a, b) if p.dport < p.sport else (b, a)


IDLE_NEW_CONNECTION_S = 300.0  # a closed/reset flow silent this long is considered finished


def starts_new_connection(flow: Flow, p: TcpPacket) -> bool:
    """True if p begins a new connection on a 4-tuple that `flow` already used.

    A retransmitted SYN/SYN-ACK carries the same initial sequence number and stays in the flow.
    """
    if p.flags & SYN:
        if p.flags & ACK:
            return flow.synack_seq is not None and p.seq != flow.synack_seq
        if flow.syn_seq is None:
            return True  # flow was picked up midstream, so a SYN is a fresh handshake
        return p.seq != flow.syn_seq or bool((flow.resets or flow.fin_seen) and flow.ack_time is not None)
    ended = bool(flow.resets or flow.fin_seen)
    return ended and not p.flags & RST and (p.time - flow.packets[-1].time) > IDLE_NEW_CONNECTION_S


SIZE_BINS = [(64, "â‰¤64"), (127, "65â€“127"), (255, "128â€“255"), (511, "256â€“511"),
             (1023, "512â€“1023"), (1399, "1024â€“1399"), (1500, "1400â€“1500"), (10**9, ">1500")]


DEDUP_WINDOW_S = 0.001


def merge_captures(streams: list[BinaryIO]):
    """Interleave several captures by timestamp and drop packets seen by another capture.

    A packet is a duplicate only when an identical packet from a *different* source is within
    DEDUP_WINDOW_S and not already paired, so repeats inside one capture are all kept.
    """
    def tagged(i: int, s: BinaryIO):
        for _, ts, data, link, orig in read_capture(s):
            yield ts, i, data, link, orig

    recent: dict[bytes, list[list]] = {}  # key -> [[ts, source, paired], ...]
    n = 0
    for ts, src, data, link, orig in heapq.merge(*(tagged(i, s) for i, s in enumerate(streams)),
                                                 key=lambda x: x[0]):
        key = hashlib.blake2b(data, digest_size=16).digest()
        entries = [e for e in recent.get(key, ()) if ts - e[0] < DEDUP_WINDOW_S]
        match = next((e for e in entries if e[1] != src and not e[2]), None)
        if match is not None:
            match[2] = True
            recent[key] = entries
            continue
        entries.append([ts, src, False])
        recent[key] = entries
        if len(recent) > 200_000:
            recent.clear()
        n += 1
        yield n, ts, data, link, orig


def analyze_capture(stream: BinaryIO) -> dict:
    return analyze_packets(read_capture(stream))


def analyze_packets(packets, sources: int = 1) -> dict:
    current: dict[frozenset, Flow] = {}  # 4-tuple -> its latest connection
    all_flows: list[Flow] = []
    total = tcp_count = truncated = 0
    first = last = None
    rows: list[dict] = []
    sizes = [0] * len(SIZE_BINS)
    frame_sum = max_frame = tcp_bytes = 0
    talkers: dict[str, list[int]] = {}
    icmp_ptb: list[dict] = []
    links: set[int] = set()
    extras = Extras()

    def talk(src: str, dst: str, flen: int) -> None:
        for ip in (src, dst):
            t = talkers.setdefault(ip, [0, 0])
            t[0] += 1
            t[1] += flen

    for number, ts, data, link, orig in packets:
        total += 1
        links.add(link)
        first = ts if first is None else first
        last = ts
        flen = orig or len(data)
        if orig > len(data):
            truncated += 1
        frame_sum += flen
        max_frame = max(max_frame, flen)
        for i, (limit, _) in enumerate(SIZE_BINS):
            if flen <= limit:
                sizes[i] += 1
                break
        p = parse_tcp(number, ts, data, link, orig)
        if p is None:
            dec = parse_other(data, link)
            if dec is None:
                extras.count("Other / non-IP", flen)
                continue
            extras.feed(ts, flen, dec)
            if dec.kind == "ip":
                talk(dec.src, dec.dst, flen)
                if dec.proto in (1, 58):
                    ptb = parse_icmp_ptb(ts, data, link)
                    if ptb:
                        icmp_ptb.append(ptb)
            continue
        tcp_count += 1
        tcp_bytes += p.payload_len
        extras.count("TCP", flen, service_for(p.sport, p.dport) or "Other TCP")
        talk(p.src, p.dst, flen)
        key = frozenset([(p.src, p.sport), (p.dst, p.dport)])
        flow = current.get(key)
        if flow is None or starts_new_connection(flow, p):
            client, server = _orient(p)
            flow = current[key] = Flow(len(all_flows) + 1, client, server)
            all_flows.append(flow)
        flow.add(p)
        for ts_, src_, sport_, dst_, dport_, msg in flow.dns_msgs:
            extras.dns.feed_tcp(ts_, src_, sport_, dst_, dport_, msg)
        flow.dns_msgs.clear()
        p.payload = b""
        if len(rows) < MAX_PACKET_ROWS:
            d = p.to_dict()
            d["flow"] = flow.id
            rows.append(d)

    for ptb in icmp_ptb:
        for f in all_flows:
            if ptb["original_destination"] in (f.client[0], f.server[0]):
                f.ptb_mtu = ptb["next_hop_mtu"]

    summaries = [f.summary() for f in all_flows]
    for f, s in zip(all_flows, summaries):
        extras.add_port("TCP", f.server[1], len(f.packets), f.frame_sum, bool(s["findings"]), f.resets)
    states: dict[str, int] = {}
    for s in summaries:
        states[s["state"]] = states.get(s["state"], 0) + 1
    duration = (last - first) if first is not None else 0
    total_retrans = sum(s["retransmissions"] for s in summaries)
    mtus = [s["mtu_from_mss"] for s in summaries if s["mtu_from_mss"]]
    notes = []
    if truncated:
        notes.append(f"{truncated} packet(s) were truncated by the capture snaplen; "
                     "sizes use the original on-wire length but payload analysis may be incomplete.")
    if icmp_ptb:
        notes.append(f"{len(icmp_ptb)} ICMP 'fragmentation needed / packet too big' message(s): "
                     f"path MTU is {min(m['next_hop_mtu'] for m in icmp_ptb)} on at least one path.")
    result = {
        "total_packets": total,
        "tcp_packets": tcp_count,
        "duration": duration,
        "flow_count": len(summaries),
        "flow_states": states,
        "flows": summaries,
        "problem_flows": [s["id"] for s in summaries if s["findings"]],
        "packets": rows,
        "packets_truncated": tcp_count > len(rows),
        "overview": {
            "tcp_payload_bytes": tcp_bytes,
            "total_bytes": frame_sum,
            "avg_frame_size": round(frame_sum / total) if total else 0,
            "max_frame_size": max_frame,
            "size_distribution": [{"range": name, "count": c} for (_, name), c in zip(SIZE_BINS, sizes)],
            "throughput_kbps": round(frame_sum * 8 / 1000 / duration, 2) if duration > 0 else None,
            "total_retransmissions": total_retrans,
            "min_mtu_from_mss": min(mtus) if mtus else None,
            "icmp_mtu_messages": icmp_ptb,
            "truncated_packets": truncated,
            "link_types": sorted(links),
            "top_talkers": [{"ip": ip, "packets": v[0], "bytes": v[1]}
                            for ip, v in sorted(talkers.items(), key=lambda kv: -kv[1][1])[:10]],
            "notes": notes,
        },
    }
    result.update(extras.result())
    result["sources"] = sources
    result["summary"] = build_summary(result)
    return result


analyze_tcp = analyze_capture  # backwards-compatible name


class Handler(BaseHTTPRequestHandler):
    server_version = "PacketStory/2.0"

    def _send(self, code: int, obj: dict) -> None:
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(body)

    def do_OPTIONS(self) -> None:
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()

    def do_GET(self) -> None:
        if self.path == "/api/health":
            self._send(200, {"status": "ok"})
        elif self.path in ("/", "/index.html"):
            try:
                with open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "index.html"), "rb") as fh:
                    body = fh.read()
            except OSError:
                return self._send(404, {"error": "index.html missing"})
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        else:
            self._send(404, {"error": "not found"})

    def do_POST(self) -> None:
        if self.path not in ("/api/analyze", "/api/analyze/tcp", "/api/analyze/merge"):
            return self._send(404, {"error": "not found"})
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            return self._send(400, {"error": "invalid Content-Length"})
        if length <= 0:
            return self._send(400, {"error": "empty body; send raw pcap bytes"})
        if length > MAX_UPLOAD:
            return self._send(413, {"error": "file too large"})
        body = self.rfile.read(length)
        try:
            if self.path.endswith("/merge"):
                try:
                    sizes = [int(x) for x in self.headers.get("X-File-Sizes", "").split(",")]
                except ValueError:
                    sizes = []
                if len(sizes) < 1 or min(sizes) <= 0 or sum(sizes) != length:
                    return self._send(400, {"error": "X-File-Sizes must list each file length and add up to the body"})
                streams, pos = [], 0
                for s in sizes:
                    streams.append(io.BytesIO(body[pos:pos + s]))
                    pos += s
                self._send(200, analyze_packets(merge_captures(streams), len(streams)))
            else:
                self._send(200, analyze_capture(io.BytesIO(body)))
        except CaptureError as exc:
            self._send(400, {"error": str(exc)})

    def log_message(self, fmt, *args) -> None:
        sys.stderr.write("%s - %s\n" % (self.address_string(), fmt % args))


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawTextHelpFormatter)
    ap.add_argument("pcap", nargs="*", help="analyze file(s) and print JSON instead of serving; several are merged")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8000)
    args = ap.parse_args()
    if args.pcap:
        try:
            handles = [open(p, "rb") for p in args.pcap]
            try:
                result = analyze_capture(handles[0]) if len(handles) == 1 else \
                    analyze_packets(merge_captures(handles), len(handles))
            finally:
                for h in handles:
                    h.close()
            print(json.dumps(result, indent=2))
        except (OSError, CaptureError) as exc:
            sys.exit(f"error: {exc}")
        return
    print(f"PacketStory on http://{args.host}:{args.port}")
    ThreadingHTTPServer((args.host, args.port), Handler).serve_forever()


if __name__ == "__main__":
    main()
