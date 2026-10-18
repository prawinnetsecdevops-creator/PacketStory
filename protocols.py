"""Capture readers (pcap + pcapng) and non-TCP protocol analysis.

Covers UDP flows, DNS, DHCP, ICMP/ICMPv6 (incl. echo and neighbor discovery),
ARP, other IP protocols, plus light TLS/HTTP/SSH sniffing helpers used by the
TCP flow tracker.
"""

from __future__ import annotations

import ipaddress
import struct
from dataclasses import dataclass, field
from types import SimpleNamespace
from typing import BinaryIO, Iterator


class CaptureError(ValueError):
    pass


# ---------------------------------------------------------------- readers

PCAP_MAGICS = {
    b"\xa1\xb2\xc3\xd4": (">", 1e6),
    b"\xd4\xc3\xb2\xa1": ("<", 1e6),
    b"\xa1\xb2\x3c\x4d": (">", 1e9),
    b"\x4d\x3c\xb2\xa1": ("<", 1e9),
}
PCAPNG_MAGIC = b"\x0a\x0d\x0d\x0a"
MAX_BLOCK = 64 * 1024 * 1024


def read_capture(stream: BinaryIO) -> Iterator[tuple[int, float, bytes, int, int]]:
    """Yield (number, timestamp, data, link_type, original_length) from pcap or pcapng."""
    head = stream.read(4)
    if len(head) < 4:
        raise CaptureError("File too short to be a capture.")
    if head == PCAPNG_MAGIC:
        yield from _read_pcapng(stream, head)
    elif head in PCAP_MAGICS:
        yield from _read_pcap(stream, head)
    else:
        raise CaptureError("Unrecognized capture format (expected .pcap or .pcapng).")


def _read_pcap(stream: BinaryIO, magic: bytes):
    rest = stream.read(20)
    if len(rest) < 20:
        raise CaptureError("File too short to be a PCAP.")
    order, res = PCAP_MAGICS[magic]
    link = struct.unpack(order + "I", rest[16:20])[0] & 0x0FFFFFFF
    rec = struct.Struct(order + "IIII")
    number = 0
    while True:
        h = stream.read(16)
        if not h:
            return
        if len(h) < 16:
            raise CaptureError("Truncated packet header.")
        sec, frac, incl, orig = rec.unpack(h)
        data = stream.read(incl)
        if len(data) < incl:
            raise CaptureError("Truncated packet data.")
        number += 1
        yield number, sec + frac / res, data, link, orig


def _tsresol(order: str, opts: bytes) -> float:
    res, i = 1e6, 0
    while i + 4 <= len(opts):
        code, ln = struct.unpack(order + "HH", opts[i:i + 4])
        if code == 0:
            break
        if code == 9 and ln >= 1 and i + 4 < len(opts):
            v = opts[i + 4]
            res = 2.0 ** (v & 0x7F) if v & 0x80 else 10.0 ** v
        i += 4 + ((ln + 3) & ~3)
    return res


def _read_pcapng(stream: BinaryIO, first4: bytes):
    order = "<"
    ifaces: list[tuple[int, float]] = []  # (link_type, ticks per second)
    number = 0
    btype_raw: bytes | None = first4
    while True:
        if btype_raw is None:
            btype_raw = stream.read(4)
            if not btype_raw:
                return
            if len(btype_raw) < 4:
                raise CaptureError("Truncated pcapng block.")
        raw_len = stream.read(4)
        if len(raw_len) < 4:
            raise CaptureError("Truncated pcapng block.")
        if btype_raw == PCAPNG_MAGIC:
            bom = stream.read(4)
            if bom == b"\x4d\x3c\x2b\x1a":
                order = "<"
            elif bom == b"\x1a\x2b\x3c\x4d":
                order = ">"
            else:
                raise CaptureError("Invalid pcapng section header.")
            length = struct.unpack(order + "I", raw_len)[0]
            if length < 12 or length > MAX_BLOCK:
                raise CaptureError("Invalid pcapng section header length.")
            stream.read(length - 12)
            ifaces = []
            btype_raw = None
            continue
        btype = struct.unpack(order + "I", btype_raw)[0]
        length = struct.unpack(order + "I", raw_len)[0]
        if length < 12 or length > MAX_BLOCK or length % 4:
            raise CaptureError("Invalid pcapng block length.")
        body = stream.read(length - 8)
        if len(body) < length - 8:
            raise CaptureError("Truncated pcapng block.")
        body = body[:-4]
        btype_raw = None
        if btype == 1 and len(body) >= 8:
            link = struct.unpack(order + "H", body[0:2])[0]
            ifaces.append((link, _tsresol(order, body[8:])))
        elif btype == 6 and len(body) >= 20:
            iface, hi, lo, cap, orig = struct.unpack(order + "IIIII", body[:20])
            if iface >= len(ifaces):
                raise CaptureError("pcapng packet references an unknown interface.")
            link, units = ifaces[iface]
            number += 1
            yield number, ((hi << 32) | lo) / units, body[20:20 + cap], link, orig
        elif btype == 3 and len(body) >= 4 and ifaces:
            orig = struct.unpack(order + "I", body[:4])[0]
            number += 1
            yield number, 0.0, body[4:4 + orig], ifaces[0][0], orig


# ---------------------------------------------------------------- names

SERVICES = {
    20: "FTP-data", 21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 67: "DHCP", 68: "DHCP",
    69: "TFTP", 80: "HTTP", 88: "Kerberos", 110: "POP3", 111: "RPC", 119: "NNTP", 123: "NTP",
    135: "MS-RPC", 137: "NetBIOS-NS", 138: "NetBIOS-DGM", 139: "NetBIOS-SSN", 143: "IMAP", 161: "SNMP",
    162: "SNMP-trap", 179: "BGP", 389: "LDAP", 443: "HTTPS", 445: "SMB", 465: "SMTPS", 500: "IKE",
    514: "Syslog", 515: "LPD", 520: "RIP", 546: "DHCPv6", 547: "DHCPv6", 587: "SMTP-submission",
    631: "IPP", 636: "LDAPS", 853: "DNS-over-TLS", 873: "rsync", 993: "IMAPS", 995: "POP3S",
    1080: "SOCKS", 1194: "OpenVPN", 1433: "MSSQL", 1521: "Oracle", 1701: "L2TP", 1723: "PPTP",
    1812: "RADIUS", 1813: "RADIUS-acct", 1883: "MQTT", 1900: "SSDP", 2049: "NFS", 2181: "ZooKeeper",
    2375: "Docker", 3128: "Proxy", 3306: "MySQL", 3389: "RDP", 3478: "STUN", 4500: "IPsec-NAT-T",
    5060: "SIP", 5061: "SIPS", 5353: "mDNS", 5355: "LLMNR", 5432: "PostgreSQL", 5671: "AMQPS",
    5672: "AMQP", 5900: "VNC", 5985: "WinRM", 5986: "WinRM-S", 6379: "Redis", 6443: "Kubernetes-API",
    8080: "HTTP-alt", 8443: "HTTPS-alt", 8883: "MQTT-TLS", 9092: "Kafka", 9200: "Elasticsearch",
    11211: "Memcached", 27017: "MongoDB", 51820: "WireGuard",
}

IP_PROTOS = {
    1: "ICMP", 2: "IGMP", 4: "IPv4-in-IP", 6: "TCP", 17: "UDP", 41: "IPv6-in-IP", 47: "GRE", 50: "ESP",
    51: "AH", 58: "ICMPv6", 89: "OSPF", 103: "PIM", 112: "VRRP", 115: "L2TP", 132: "SCTP", 136: "UDPLite",
}


def service_for(a: int, b: int) -> str | None:
    for p in sorted((a, b)):
        if p in SERVICES:
            return SERVICES[p]
    return None


# ---------------------------------------------------------------- decoding

VLAN = {0x8100, 0x88A8, 0x9100}
IPV6_EXT = {0, 43, 60, 135, 139, 140}


@dataclass
class Decoded:
    kind: str  # "ip" | "arp"
    ver: int = 0
    src: str = ""
    dst: str = ""
    proto: int = 0
    ttl: int = 0
    l4: bytes = b""
    ip_len: int = 0
    frag: bool = False
    op: int = 0
    smac: str = ""
    sip: str = ""
    tmac: str = ""
    tip: str = ""


def _locate(data: bytes, link: int) -> tuple[int, int] | None:
    if link == 1:
        if len(data) < 14:
            return None
        off, et = 14, struct.unpack(">H", data[12:14])[0]
        while et in VLAN and len(data) >= off + 4:
            et = struct.unpack(">H", data[off + 2:off + 4])[0]
            off += 4
        return off, et
    if link == 113:
        return (16, struct.unpack(">H", data[14:16])[0]) if len(data) >= 16 else None
    if link == 0:
        if len(data) < 4:
            return None
        fam = struct.unpack("<I", data[:4])[0]
        if fam > 0xFFFF:
            fam = struct.unpack(">I", data[:4])[0]
        return (4, 0x0800) if fam == 2 else (4, 0x86DD) if fam in (10, 24, 28, 30) else None
    if link in (101, 228, 229) and data:
        v = data[0] >> 4
        return (0, 0x0800) if v == 4 else (0, 0x86DD) if v == 6 else None
    return None


def _mac(b: bytes) -> str:
    return b.hex(":")


def parse_other(data: bytes, link: int) -> Decoded | None:
    """Decode ARP and IP packets (any protocol). TCP is also decoded here at L3 level."""
    loc = _locate(data, link)
    if not loc:
        return None
    off, et = loc
    if et == 0x0806:
        if len(data) < off + 28 or data[off + 4] != 6 or data[off + 5] != 4:
            return None
        return Decoded("arp", op=struct.unpack(">H", data[off + 6:off + 8])[0],
                       smac=_mac(data[off + 8:off + 14]), sip=str(ipaddress.IPv4Address(data[off + 14:off + 18])),
                       tmac=_mac(data[off + 18:off + 24]), tip=str(ipaddress.IPv4Address(data[off + 24:off + 28])))
    if et == 0x0800:
        if len(data) < off + 20:
            return None
        ihl = (data[off] & 0x0F) * 4
        if ihl < 20:
            return None
        total = struct.unpack(">H", data[off + 2:off + 4])[0]
        fo = struct.unpack(">H", data[off + 6:off + 8])[0]
        end = min(len(data), off + total) if total >= ihl else len(data)
        return Decoded("ip", 4, str(ipaddress.IPv4Address(data[off + 12:off + 16])),
                       str(ipaddress.IPv4Address(data[off + 16:off + 20])), data[off + 9], data[off + 8],
                       b"" if fo & 0x1FFF else data[off + ihl:end], total, bool(fo & 0x3FFF))
    if et == 0x86DD:
        if len(data) < off + 40:
            return None
        plen = struct.unpack(">H", data[off + 4:off + 6])[0]
        nxt, ptr, frag, nonfirst = data[off + 6], off + 40, False, False
        while nxt in IPV6_EXT or nxt == 44:
            if len(data) < ptr + 8:
                return None
            if nxt == 44:
                fo = struct.unpack(">H", data[ptr + 2:ptr + 4])[0]
                frag, nonfirst = True, bool(fo >> 3)
                nxt, ptr = data[ptr], ptr + 8
            else:
                nxt, ptr = data[ptr], ptr + (data[ptr + 1] + 1) * 8
        end = min(len(data), off + 40 + plen) if plen else len(data)
        return Decoded("ip", 6, str(ipaddress.IPv6Address(data[off + 8:off + 24])),
                       str(ipaddress.IPv6Address(data[off + 24:off + 40])), nxt, data[off + 7],
                       b"" if nonfirst else data[ptr:end], plen + 40, frag)
    return None


def _is_multi(ip: str) -> bool:
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return a.is_multicast or ip.endswith(".255") or ip == "255.255.255.255"


# ---------------------------------------------------------------- DNS

DNS_RCODES = {0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN", 4: "NOTIMP", 5: "REFUSED"}
DNS_TYPES = {1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR", 15: "MX", 16: "TXT", 28: "AAAA",
             33: "SRV", 43: "DS", 48: "DNSKEY", 64: "SVCB", 65: "HTTPS", 255: "ANY"}


def _dns_name(buf: bytes, off: int) -> tuple[str, int] | None:
    labels, end, hops = [], None, 0
    while True:
        if off >= len(buf):
            return None
        ln = buf[off]
        if ln == 0:
            off += 1
            break
        if ln & 0xC0 == 0xC0:
            if off + 1 >= len(buf):
                return None
            if end is None:
                end = off + 2
            off = ((ln & 0x3F) << 8) | buf[off + 1]
            hops += 1
            if hops > 10:
                return None
            continue
        if ln & 0xC0:
            return None
        off += 1
        labels.append(buf[off:off + ln].decode("ascii", "replace"))
        off += ln
    return (".".join(labels) or "."), (end if end is not None else off)


def parse_dns(p: bytes) -> dict | None:
    if len(p) < 12:
        return None
    ident, flags, qd, an = struct.unpack(">HHHH", p[:8])
    if not 1 <= qd <= 10 or (flags >> 11) & 0xF > 5:
        return None
    r = _dns_name(p, 12)
    if not r or r[1] + 4 > len(p):
        return None
    name, off = r
    return {"id": ident, "qr": flags >> 15, "tc": (flags >> 9) & 1, "rcode": flags & 0xF,
            "name": name, "qtype": struct.unpack(">H", p[off:off + 2])[0], "answers": an}


def _pct(vals: list[float], q: float) -> float:
    s = sorted(vals)
    return s[min(len(s) - 1, int(q * len(s)))]


def _lat(vals: list[float]) -> dict | None:
    if not vals:
        return None
    return {"min": round(min(vals), 2), "avg": round(sum(vals) / len(vals), 2),
            "p95": round(_pct(vals, 0.95), 2), "max": round(max(vals), 2)}


class DnsTracker:
    def __init__(self) -> None:
        self.pending: dict = {}
        self.queries = self.responses = self.retries = self.truncated = 0
        self.rcodes: dict[str, int] = {}
        self.qtypes: dict[str, int] = {}
        self.names: dict[str, int] = {}
        self.lat: list[float] = []
        self.servers: dict[str, dict] = {}
        self.failures: list[dict] = []
        self.tcp_msgs = 0

    def feed_tcp(self, ts: float, src: str, sport: int, dst: str, dport: int, payload: bytes) -> None:
        """DNS over TCP: each message carries a 2-byte length prefix."""
        if len(payload) < 14 or struct.unpack(">H", payload[:2])[0] < 12:
            return
        before = self.queries + self.responses
        self.feed(ts, SimpleNamespace(src=src, dst=dst), sport, dport, payload[2:])
        self.tcp_msgs += (self.queries + self.responses) - before

    def feed(self, ts: float, dec, sport: int, dport: int, payload: bytes) -> None:
        d = parse_dns(payload)
        if not d:
            return
        if d["qr"] == 0 and dport == 53:
            self.queries += 1
            key = (dec.src, sport, d["id"])
            if key in self.pending:
                self.retries += 1
            elif len(self.pending) < 50_000:
                self.pending[key] = (ts, d["name"], d["qtype"], dec.dst)
            qt = DNS_TYPES.get(d["qtype"], str(d["qtype"]))
            self.qtypes[qt] = self.qtypes.get(qt, 0) + 1
            self.names[d["name"]] = self.names.get(d["name"], 0) + 1
            self.servers.setdefault(dec.dst, {"q": 0, "r": 0, "lat": []})["q"] += 1
        elif d["qr"] == 1 and sport == 53:
            self.responses += 1
            rc = DNS_RCODES.get(d["rcode"], f"RCODE{d['rcode']}")
            self.rcodes[rc] = self.rcodes.get(rc, 0) + 1
            if d["tc"]:
                self.truncated += 1
            srv = self.servers.setdefault(dec.src, {"q": 0, "r": 0, "lat": []})
            srv["r"] += 1
            sent = self.pending.pop((dec.dst, dport, d["id"]), None)
            if sent:
                ms = (ts - sent[0]) * 1000
                self.lat.append(ms)
                srv["lat"].append(ms)
            if d["rcode"] in (1, 2, 3, 5) and len(self.failures) < 100:
                self.failures.append({"time": ts, "client": dec.dst, "server": dec.src, "name": d["name"],
                                      "type": DNS_TYPES.get(d["qtype"], str(d["qtype"])), "rcode": rc})

    def result(self) -> dict:
        unanswered = len(self.pending)
        f: list[str] = []
        if unanswered:
            f.append(f"{unanswered} DNS quer{'y' if unanswered == 1 else 'ies'} never got a response: "
                     "resolver unreachable, filtered, or overloaded.")
        if self.retries:
            f.append(f"{self.retries} DNS retransmitted quer{'y' if self.retries == 1 else 'ies'}: slow or lossy resolver path.")
        for rc, hint in (("SERVFAIL", "upstream/resolver failure"), ("REFUSED", "resolver rejects these clients"),
                         ("FORMERR", "malformed query or EDNS issue")):
            if self.rcodes.get(rc):
                f.append(f"{self.rcodes[rc]} {rc} response(s): {hint}.")
        nx = self.rcodes.get("NXDOMAIN", 0)
        if nx and (nx >= 10 or nx > 0.2 * max(1, self.responses)):
            f.append(f"{nx} NXDOMAIN response(s): clients are querying names that do not exist (typos, search-domain suffixes, stale config).")
        if self.truncated and self.tcp_msgs:
            f.append(f"{self.truncated} truncated (TC) response(s): clients fell back to TCP/53 "
                     f"({self.tcp_msgs} TCP DNS message(s) seen), so check that EDNS size fits the path MTU.")
        elif self.truncated:
            f.append(f"{self.truncated} truncated (TC) response(s) and no DNS over TCP seen: clients must retry over TCP/53; "
                     "ensure TCP 53 is allowed and EDNS size fits the path MTU.")
        lat = _lat(self.lat)
        if lat and lat["avg"] > 100:
            f.append(f"High average DNS latency ({lat['avg']} ms).")
        elif lat and lat["max"] > 1000:
            f.append(f"Slowest DNS response took {lat['max']} ms.")
        servers = [{"server": s, "queries": v["q"], "responses": v["r"],
                    "avg_ms": round(sum(v["lat"]) / len(v["lat"]), 2) if v["lat"] else None,
                    "max_ms": round(max(v["lat"]), 2) if v["lat"] else None}
                   for s, v in sorted(self.servers.items(), key=lambda kv: -kv[1]["q"])[:20]]
        for s in servers:
            if s["queries"] >= 3 and s["responses"] == 0:
                f.append(f"DNS server {s['server']} never answered {s['queries']} queries.")
        return {"queries": self.queries, "responses": self.responses, "unanswered": unanswered,
                "retries": self.retries, "truncated": self.truncated, "tcp_messages": self.tcp_msgs,
                "rcodes": self.rcodes,
                "qtypes": self.qtypes, "latency_ms": lat, "servers": servers,
                "top_queries": [{"name": n, "count": c} for n, c in
                                sorted(self.names.items(), key=lambda kv: -kv[1])[:15]],
                "failures": self.failures[:50], "findings": f}


# ---------------------------------------------------------------- DHCP

DHCP_TYPES = {1: "DISCOVER", 2: "OFFER", 3: "REQUEST", 4: "DECLINE", 5: "ACK", 6: "NAK", 7: "RELEASE", 8: "INFORM"}


class DhcpTracker:
    def __init__(self) -> None:
        self.xids: dict[bytes, dict] = {}
        self.counts: dict[str, int] = {}

    def feed(self, ts: float, payload: bytes) -> None:
        if len(payload) < 241 or payload[236:240] != b"\x63\x82\x53\x63":
            return
        mtype, i = None, 240
        while i + 1 < len(payload):
            code = payload[i]
            if code == 255:
                break
            if code == 0:
                i += 1
                continue
            if code == 53 and i + 2 < len(payload):
                mtype = payload[i + 2]
            i += 2 + payload[i + 1]
        if mtype is None:
            return
        name = DHCP_TYPES.get(mtype, str(mtype))
        self.counts[name] = self.counts.get(name, 0) + 1
        x = self.xids.setdefault(payload[4:8], {"mac": _mac(payload[28:34]), "types": set()})
        x["types"].add(mtype)

    def result(self) -> dict:
        f = []
        no_offer = [x["mac"] for x in self.xids.values() if 1 in x["types"] and 2 not in x["types"]]
        no_ack = [x["mac"] for x in self.xids.values() if 3 in x["types"] and not x["types"] & {5, 6}]
        if no_offer:
            f.append(f"{len(no_offer)} DHCP DISCOVER(s) got no OFFER (no reachable DHCP server / relay): {', '.join(no_offer[:3])}")
        if no_ack:
            f.append(f"{len(no_ack)} DHCP REQUEST(s) got no ACK/NAK.")
        if self.counts.get("NAK"):
            f.append(f"{self.counts['NAK']} DHCP NAK(s): client address is invalid for this network.")
        if self.counts.get("DECLINE"):
            f.append(f"{self.counts['DECLINE']} DHCP DECLINE(s): address conflict detected by a client.")
        return {"transactions": len(self.xids), "messages": self.counts, "findings": f}


# ---------------------------------------------------------------- ICMP

ICMP4 = {0: "Echo reply", 3: "Destination unreachable", 4: "Source quench", 5: "Redirect", 8: "Echo request",
         9: "Router advertisement", 10: "Router solicitation", 11: "Time exceeded", 12: "Parameter problem",
         13: "Timestamp request", 14: "Timestamp reply"}
ICMP4_CODES = {3: {0: "net unreachable", 1: "host unreachable", 2: "protocol unreachable", 3: "port unreachable",
                   4: "fragmentation needed (DF set)", 5: "source route failed", 9: "net administratively prohibited",
                   10: "host administratively prohibited", 13: "communication administratively prohibited"},
               11: {0: "TTL exceeded in transit", 1: "fragment reassembly time exceeded"}}
ICMP6 = {1: "Destination unreachable", 2: "Packet too big", 3: "Time exceeded", 4: "Parameter problem",
         128: "Echo request", 129: "Echo reply", 130: "Multicast listener query", 133: "Router solicitation",
         134: "Router advertisement", 135: "Neighbor solicitation", 136: "Neighbor advertisement", 137: "Redirect",
         143: "Multicast listener report v2"}
ICMP6_CODES = {1: {0: "no route", 1: "administratively prohibited", 2: "beyond scope", 3: "address unreachable",
                   4: "port unreachable", 5: "source policy failed", 6: "reject route"},
               3: {0: "hop limit exceeded", 1: "fragment reassembly time exceeded"}}
ICMP_ERRORS4, ICMP_ERRORS6 = {3, 4, 5, 11, 12}, {1, 2, 3, 4}
UNREACH_HINTS = {
    "administratively prohibited": "a firewall/ACL is actively rejecting the traffic",
    "port unreachable": "nothing is listening on that port (or a host firewall rejects it)",
    "host unreachable": "gateway cannot reach the host (ARP/neighbor failure, host down)",
    "net unreachable": "no route to the destination network",
    "no route": "no route to the destination network",
    "address unreachable": "neighbor discovery failed for the destination",
}


def _inner(l4: bytes, v6: bool) -> tuple[str, str, int | None] | None:
    body = l4[8:]
    if v6:
        if len(body) < 40:
            return None
        dst, proto, hl = str(ipaddress.IPv6Address(body[24:40])), body[6], 40
    else:
        if len(body) < 20:
            return None
        hl, proto = (body[0] & 0x0F) * 4, body[9]
        dst = str(ipaddress.IPv4Address(body[16:20]))
    port = struct.unpack(">H", body[hl + 2:hl + 4])[0] if proto in (6, 17) and len(body) >= hl + 4 else None
    return dst, IP_PROTOS.get(proto, str(proto)), port


class IcmpTracker:
    def __init__(self) -> None:
        self.types: dict[str, int] = {}
        self.total = 0
        self.echo_req = self.echo_rep = 0
        self.echo_pending: dict = {}
        self.rtts: list[float] = []
        self.errors: list[dict] = []
        self.error_counts: dict[str, int] = {}
        self.nd_pending: dict = {}

    def feed(self, ts: float, dec: Decoded) -> None:
        l4 = dec.l4
        if len(l4) < 8:
            return
        v6 = dec.ver == 6
        t, c = l4[0], l4[1]
        names, codes = (ICMP6, ICMP6_CODES) if v6 else (ICMP4, ICMP4_CODES)
        name = names.get(t, f"Type {t}")
        self.total += 1
        self.types[name] = self.types.get(name, 0) + 1
        ident, seq = struct.unpack(">HH", l4[4:8])
        if t == (128 if v6 else 8):
            self.echo_req += 1
            if len(self.echo_pending) < 100_000:
                self.echo_pending[(dec.src, dec.dst, ident, seq)] = ts
        elif t == (129 if v6 else 0):
            self.echo_rep += 1
            sent = self.echo_pending.pop((dec.dst, dec.src, ident, seq), None)
            if sent is not None:
                self.rtts.append((ts - sent) * 1000)
        elif v6 and t == 135 and len(l4) >= 24 and len(self.nd_pending) < 50_000:
            self.nd_pending[l4[8:24]] = (ts, dec.src)
        elif v6 and t == 136 and len(l4) >= 24:
            self.nd_pending.pop(l4[8:24], None)
        elif t in (ICMP_ERRORS6 if v6 else ICMP_ERRORS4):
            desc = f"{name}: {codes.get(t, {}).get(c, f'code {c}')}" if t in codes else name
            self.error_counts[desc] = self.error_counts.get(desc, 0) + 1
            if len(self.errors) < 200:
                inner = _inner(l4, v6)
                self.errors.append({"time": ts, "reporter": dec.src, "to": dec.dst, "description": desc,
                                    "original_dst": inner[0] if inner else None,
                                    "original_proto": inner[1] if inner else None,
                                    "original_port": inner[2] if inner else None})

    def result(self) -> dict:
        f = []
        unanswered = len(self.echo_pending)
        if unanswered:
            f.append(f"{unanswered} ICMP echo request(s) got no reply: host down, route problem, or ICMP filtered.")
        for desc, n in sorted(self.error_counts.items(), key=lambda kv: -kv[1]):
            hint = next((h for k, h in UNREACH_HINTS.items() if k in desc), None)
            if "Time exceeded" in desc:
                hint = "traceroute activity or a routing loop"
            elif desc.startswith("Redirect"):
                hint = "suboptimal first-hop routing or a rogue gateway"
            elif "fragmentation needed" in desc or desc.startswith("Packet too big"):
                hint = "path MTU is smaller than the packet being sent"
            f.append(f"{n} × {desc}" + (f": {hint}." if hint else "."))
        if self.nd_pending:
            f.append(f"{len(self.nd_pending)} IPv6 neighbor solicitation(s) never answered: neighbor unreachable.")
        return {"messages": self.total,
                "types": [{"name": n, "count": c} for n, c in sorted(self.types.items(), key=lambda kv: -kv[1])],
                "echo": {"requests": self.echo_req, "replies": self.echo_rep, "unanswered": unanswered,
                         "loss_pct": round(100 * unanswered / self.echo_req, 1) if self.echo_req else 0,
                         "rtt_ms": _lat(self.rtts)},
                "errors": self.errors, "findings": f}


# ---------------------------------------------------------------- ARP

class ArpTracker:
    def __init__(self) -> None:
        self.requests = self.replies = self.gratuitous = 0
        self.pending: dict[str, list] = {}
        self.macs: dict[str, set] = {}

    def feed(self, ts: float, d: Decoded) -> None:
        if d.op == 1:
            self.requests += 1
            if d.sip == d.tip:
                self.gratuitous += 1
            elif d.tip in self.pending:
                self.pending[d.tip][2] += 1
            elif len(self.pending) < 50_000:
                self.pending[d.tip] = [ts, d.sip, 1]
        elif d.op == 2:
            self.replies += 1
            self.pending.pop(d.sip, None)
        if d.op in (1, 2) and d.sip != "0.0.0.0" and d.smac != "ff:ff:ff:ff:ff:ff":
            self.macs.setdefault(d.sip, set()).add(d.smac)

    def result(self) -> dict:
        f = []
        unanswered = [{"ip": ip, "asked_by": v[1], "attempts": v[2], "first_seen": v[0]}
                      for ip, v in sorted(self.pending.items(), key=lambda kv: -kv[1][2])[:50]]
        if self.pending:
            f.append(f"{len(self.pending)} IP address(es) never answered ARP: host down, wrong VLAN/subnet, or bad gateway config.")
        conflicts = [{"ip": ip, "macs": sorted(m)} for ip, m in self.macs.items() if len(m) > 1][:50]
        if conflicts:
            f.append(f"{len(conflicts)} IP address(es) claimed by multiple MACs: duplicate IP, failover/VRRP, or ARP spoofing.")
        return {"requests": self.requests, "replies": self.replies, "gratuitous": self.gratuitous,
                "unanswered": unanswered, "conflicts": conflicts,
                "hosts": [{"ip": ip, "mac": sorted(m)[0]} for ip, m in sorted(self.macs.items())
                          if len(m) == 1][:100],
                "findings": f}


# ---------------------------------------------------------------- UDP + orchestration

MAX_UDP_FLOWS = 20_000
ONE_WAY_OK = {514, 162}  # syslog / SNMP traps are fire-and-forget


@dataclass
class UdpFlow:
    id: int
    client: tuple[str, int]
    server: tuple[str, int]
    multicast: bool
    pkts_c: int = 0
    pkts_s: int = 0
    bytes_c: int = 0
    bytes_s: int = 0
    max_payload: int = 0
    max_frame: int = 0
    first: float = 0.0
    last: float = 0.0

    def findings(self) -> list[str]:
        out = []
        if self.pkts_s == 0 and not self.multicast and self.pkts_c >= 2 and self.server[1] not in ONE_WAY_OK:
            out.append(f"{self.pkts_c} datagram(s) sent, no reply: service down, filtered, or one-way path.")
        if self.max_frame > 1500:
            out.append(f"Datagrams up to {self.max_frame} bytes: likely IP fragmentation or offload artifact.")
        return out

    def summary(self) -> dict:
        return {"id": self.id, "client": f"{self.client[0]}:{self.client[1]}",
                "server": f"{self.server[0]}:{self.server[1]}",
                "application": service_for(self.client[1], self.server[1]) or "Other UDP",
                "packets_c2s": self.pkts_c, "packets_s2c": self.pkts_s,
                "bytes": self.bytes_c + self.bytes_s, "max_payload": self.max_payload,
                "max_frame_size": self.max_frame, "start": self.first, "duration": self.last - self.first,
                "multicast": self.multicast, "findings": self.findings()}


class Extras:
    """Collects everything that is not a TCP flow."""

    def __init__(self) -> None:
        self.proto: dict[str, list[int]] = {}
        self.apps: dict[str, list[int]] = {}
        self.fragments = 0
        self.udp: dict = {}
        self.udp_dropped = 0
        self.dns, self.dhcp = DnsTracker(), DhcpTracker()
        self.icmp, self.arp = IcmpTracker(), ArpTracker()
        self.ports: dict[tuple[str, int], dict] = {}

    def count(self, label: str, frame_len: int, app: str | None = None) -> None:
        for table, key in ((self.proto, label), (self.apps, app or label)):
            e = table.setdefault(key, [0, 0])
            e[0] += 1
            e[1] += frame_len

    def add_port(self, proto: str, port: int, packets: int, nbytes: int, problem: bool, resets: int = 0) -> None:
        e = self.ports.setdefault((proto, port), {"flows": 0, "packets": 0, "bytes": 0, "problem_flows": 0, "resets": 0})
        e["flows"] += 1
        e["packets"] += packets
        e["bytes"] += nbytes
        e["problem_flows"] += int(problem)
        e["resets"] += resets

    def feed(self, ts: float, frame_len: int, dec: Decoded) -> None:
        if dec.kind == "arp":
            self.count("ARP", frame_len)
            self.arp.feed(ts, dec)
            return
        if dec.frag:
            self.fragments += 1
        if dec.proto == 17 and len(dec.l4) >= 8:
            sport, dport = struct.unpack(">HH", dec.l4[:4])
            self.count("UDP", frame_len, service_for(sport, dport) or "Other UDP")
            self._udp(ts, frame_len, dec, sport, dport)
            return
        label = IP_PROTOS.get(dec.proto, f"IP proto {dec.proto}")
        self.count(label, frame_len)
        if dec.proto in (1, 58):
            self.icmp.feed(ts, dec)

    def _udp(self, ts: float, frame_len: int, dec: Decoded, sport: int, dport: int) -> None:
        key = frozenset([(dec.src, sport), (dec.dst, dport)])
        f = self.udp.get(key)
        if f is None:
            if len(self.udp) >= MAX_UDP_FLOWS:
                self.udp_dropped += 1
                return
            a, b = (dec.src, sport), (dec.dst, dport)
            if sport in SERVICES and dport not in SERVICES:
                a, b = b, a
            f = self.udp[key] = UdpFlow(len(self.udp) + 1, a, b, _is_multi(dec.dst), first=ts)
        payload = dec.l4[8:]
        if (dec.src, sport) == f.client:
            f.pkts_c += 1
            f.bytes_c += len(payload)
        else:
            f.pkts_s += 1
            f.bytes_s += len(payload)
        f.max_payload = max(f.max_payload, len(payload))
        f.max_frame = max(f.max_frame, frame_len)
        f.last = ts
        if 53 in (sport, dport):
            self.dns.feed(ts, dec, sport, dport, payload)
        elif {sport, dport} == {67, 68}:
            self.dhcp.feed(ts, payload)

    def result(self) -> dict:
        udp = sorted((f.summary() for f in self.udp.values()), key=lambda s: -s["bytes"])
        for f in self.udp.values():
            self.add_port("UDP", f.server[1], f.pkts_c + f.pkts_s, f.bytes_c + f.bytes_s, bool(f.findings()))
        dns, icmp, arp, dhcp = self.dns.result(), self.icmp.result(), self.arp.result(), self.dhcp.result()
        alerts: list[str] = []
        if self.fragments:
            alerts.append(f"IP: {self.fragments} fragmented packet(s): datagrams exceed the path MTU "
                          "(check MTU, MSS clamping, UDP payload size).")
        for name, sec in (("DNS", dns), ("DHCP", dhcp), ("ICMP", icmp), ("ARP", arp)):
            alerts += [f"{name}: {x}" for x in sec["findings"]]
        bad_udp = [s for s in udp if s["findings"] and any("no reply" in x for x in s["findings"])]
        if bad_udp:
            alerts.append(f"UDP: {len(bad_udp)} flow(s) never received a reply.")

        def rows(t):
            return [{"name": k, "packets": v[0], "bytes": v[1]}
                    for k, v in sorted(t.items(), key=lambda kv: -kv[1][1])]
        ports = [{"proto": p, "port": port, "service": SERVICES.get(port), **v}
                 for (p, port), v in sorted(self.ports.items(), key=lambda kv: -kv[1]["bytes"])[:40]]
        return {"protocols": rows(self.proto), "applications": rows(self.apps)[:25], "ports": ports,
                "fragments": self.fragments,
                "udp": {"count": len(udp), "dropped": self.udp_dropped, "flows": udp[:500]},
                "dns": dns, "dhcp": dhcp, "icmp": icmp, "arp": arp, "alerts": alerts}


# ---------------------------------------------------------------- TCP payload sniffing

HTTP_METHODS = (b"GET ", b"POST ", b"PUT ", b"HEAD ", b"DELETE ", b"OPTIONS ", b"PATCH ", b"CONNECT ")
TLS_ALERTS = {0: "close_notify", 10: "unexpected_message", 20: "bad_record_mac", 40: "handshake_failure",
              42: "bad_certificate", 43: "unsupported_certificate", 44: "certificate_revoked",
              45: "certificate_expired", 46: "certificate_unknown", 47: "illegal_parameter",
              48: "unknown_ca", 49: "access_denied", 50: "decode_error", 51: "decrypt_error",
              70: "protocol_version", 71: "insufficient_security", 80: "internal_error",
              86: "inappropriate_fallback", 90: "user_canceled", 112: "unrecognized_name",
              120: "no_application_protocol"}
TLS_VERSIONS = {0x0300: "SSL 3.0", 0x0301: "TLS 1.0", 0x0302: "TLS 1.1", 0x0303: "TLS 1.2", 0x0304: "TLS 1.3"}
HELLO_RETRY_RANDOM = bytes.fromhex("cf21ad74e59a6111be1d8c021e65b891c2a211167abb8c5e079e09e2c8a8339c")


def parse_http_request(h: bytes) -> str | None:
    if not h.startswith(HTTP_METHODS):
        return None
    head = h.split(b"\r\n\r\n", 1)[0].decode("latin-1", "replace").split("\r\n")
    line = " ".join(head[0].split(" ")[:2])
    host = next((x[5:].strip() for x in head[1:] if x[:5].lower() == "host:"), None)
    return f"{line} [{host}]" if host else line


def parse_http_status(h: bytes) -> int | None:
    if h.startswith(b"HTTP/1.") and len(h) >= 12 and h[9:12].isdigit():
        return int(h[9:12])
    return None


def tls_alert(h: bytes) -> tuple[int, str] | None:
    """Return (level, description) for a plaintext TLS alert record."""
    if len(h) >= 7 and h[0] == 0x15 and h[1] == 3 and h[3] == 0 and h[4] == 2:
        return h[5], TLS_ALERTS.get(h[6], f"alert {h[6]}")
    return None


def _extensions(h: bytes, i: int):
    """Yield (type, body) for TLS hello extensions starting at the extensions length field."""
    end = min(len(h), i + 2 + struct.unpack(">H", h[i:i + 2])[0])
    i += 2
    while i + 4 <= end:
        et, el = struct.unpack(">HH", h[i:i + 4])
        yield et, h[i + 4:i + 4 + el]
        i += 4 + el


def parse_client_hello(h: bytes) -> tuple[str | None, str | None, list[str]] | None:
    """Return (sni, version, alpn) from a TLS ClientHello; tolerates truncation."""
    if len(h) < 11 or h[0] != 0x16 or h[1] != 3 or h[5] != 1:
        return None
    version = TLS_VERSIONS.get(struct.unpack(">H", h[9:11])[0])
    sni, alpn = None, []
    try:
        i = 11 + 32
        i += 1 + h[i]
        i += 2 + struct.unpack(">H", h[i:i + 2])[0]
        i += 1 + h[i]
        for et, body in _extensions(h, i):
            if et == 0 and len(body) >= 5:
                nl = struct.unpack(">H", body[3:5])[0]
                sni = body[5:5 + nl].decode("ascii", "replace")
            elif et == 43 and body and b"\x03\x04" in body[1:]:
                version = "TLS 1.3"
            elif et == 16 and len(body) >= 3:
                j = 2
                while j < len(body):
                    ln = body[j]
                    alpn.append(body[j + 1:j + 1 + ln].decode("ascii", "replace"))
                    j += 1 + ln
    except (IndexError, struct.error):
        pass
    return sni, version, alpn


def parse_server_hello(h: bytes) -> tuple[str | None, bool] | None:
    """Return (negotiated version, is_hello_retry_request) from a TLS ServerHello."""
    if len(h) < 11 or h[0] != 0x16 or h[1] != 3 or h[5] != 2:
        return None
    version = TLS_VERSIONS.get(struct.unpack(">H", h[9:11])[0])
    hrr = False
    try:
        hrr = h[11:43] == HELLO_RETRY_RANDOM
        i = 43
        i += 1 + h[i]
        i += 3  # cipher suite + compression
        for et, body in _extensions(h, i):
            if et == 43 and len(body) == 2:
                version = TLS_VERSIONS.get(struct.unpack(">H", body)[0], version)
    except (IndexError, struct.error):
        pass
    return version, hrr
