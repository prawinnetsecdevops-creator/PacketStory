"""Bounded TCP stream reassembly and application-message framing.

Each TCP direction gets an AppStream that
  1. puts segments back in sequence order (bounded out-of-order buffer, duplicates and overlaps trimmed),
  2. sniffs the protocol from the first bytes (or uses DNS when the flow is on port 53),
  3. frames complete messages: DNS/TCP length-prefixed messages, TLS records and handshake messages,
     HTTP/1.x message heads (bodies are skipped, including chunked), and the SSH banner.

Memory is bounded: parsers drop bytes they do not need, give up on malformed input, and a stream that
loses data (a capture hole or snaplen truncation) stops after one tolerant parse of what it already has.
"""
from __future__ import annotations

import re

from protocols import (
    HTTP_METHODS, parse_client_hello, parse_http_request, parse_http_status, parse_server_hello, tls_alert,
)

MASK = 0xFFFFFFFF
MAX_OOO_BYTES = 64 * 1024
MAX_OOO_SEGMENTS = 64
MAX_HTTP_HEAD = 64 * 1024
MAX_TLS_RECORD = 16384 + 2048
MAX_HELLO = 60_000  # keeps the synthetic record length below 65536
SNIFF_PATTERNS = HTTP_METHODS + (b"HTTP/1.", b"SSH-")

_CONTENT_LENGTH = re.compile(rb"^content-length:\s*(\d+)", re.I | re.M)
_CHUNKED = re.compile(rb"^transfer-encoding:[^\r\n]*chunked", re.I | re.M)


class Reassembler:
    """In-order byte delivery for one TCP direction."""

    def __init__(self) -> None:
        self.next: int | None = None
        self.ooo: dict[int, bytes] = {}
        self.ooo_bytes = 0
        self.broken = False  # unrecoverable hole: later bytes cannot be placed reliably

    def syn(self, seq: int) -> None:
        if self.next is None:
            self.next = (seq + 1) & MASK

    def add(self, seq: int, data: bytes, lost: int = 0) -> bytes:
        if self.broken or (not data and not lost):
            return b""
        if self.next is None:
            self.next = seq
        diff = (seq - self.next) & MASK
        if diff >= 0x80000000:  # starts before what was already delivered
            back = (self.next - seq) & MASK
            if back >= len(data):
                return b""
            data, seq, diff = data[back:], self.next, 0
        if lost:
            # bytes cut off by the snaplen can never be recovered, so nothing after them is usable
            self.broken = True
            self.ooo.clear()
            return data if diff == 0 else b""
        if diff:
            if len(self.ooo) >= MAX_OOO_SEGMENTS or self.ooo_bytes + len(data) > MAX_OOO_BYTES:
                self.broken = True
                self.ooo.clear()
                return b""
            old = self.ooo.get(seq)
            if old is None or len(old) < len(data):
                self.ooo_bytes += len(data) - (len(old) if old else 0)
                self.ooo[seq] = data
            return b""
        out = bytearray(data)
        self.next = (self.next + len(data)) & MASK
        progressed = True
        while progressed and self.ooo:
            progressed = False
            for s in list(self.ooo):
                d = (s - self.next) & MASK
                if d == 0 or d >= 0x80000000:
                    seg = self.ooo.pop(s)
                    self.ooo_bytes -= len(seg)
                    if d:
                        seg = seg[(self.next - s) & MASK:]
                    if seg:
                        out += seg
                        self.next = (self.next + len(seg)) & MASK
                    progressed = True
        return bytes(out)


class DnsStream:
    """DNS over TCP: each message has a 2-byte length prefix; several may share a segment."""

    def __init__(self) -> None:
        self.buf = bytearray()
        self.finished = False

    def feed(self, data: bytes) -> list[tuple]:
        out = []
        self.buf += data
        while len(self.buf) >= 2:
            n = (self.buf[0] << 8) | self.buf[1]
            if n < 12:
                self.finished = True
                self.buf.clear()
                break
            if len(self.buf) < 2 + n:
                break
            out.append(("dns", bytes(self.buf[2:2 + n])))
            del self.buf[:2 + n]
        return out

    def flush_partial(self) -> list[tuple]:
        out = [("dns", bytes(self.buf[2:]))] if len(self.buf) >= 14 else []
        self.finished = True
        return out


class HttpStream:
    """HTTP/1.x message heads; bodies (Content-Length or chunked) are skipped without buffering."""

    def __init__(self, request: bool) -> None:
        self.request = request
        self.buf = bytearray()
        self.skip = 0
        self.mode = "head"  # head | chunk_size | trailer
        self.finished = False

    def _event(self, head: bytes):
        value = parse_http_request(head) if self.request else parse_http_status(head)
        return None if value is None else ("http_req" if self.request else "http_resp", value)

    def _starts_ok(self, b: bytes) -> bool:
        return b.startswith(HTTP_METHODS if self.request else b"HTTP/1.")

    def feed(self, data: bytes) -> list[tuple]:
        out = []
        self.buf += data
        while not self.finished:
            if self.skip:
                n = min(self.skip, len(self.buf))
                del self.buf[:n]
                self.skip -= n
                if self.skip:
                    break
            if self.mode == "head":
                i = self.buf.find(b"\r\n\r\n")
                if i < 0:
                    if len(self.buf) > MAX_HTTP_HEAD:
                        self.finished = True
                    break
                head = bytes(self.buf[:i])
                del self.buf[:i + 4]
                ev = self._event(head) if self._starts_ok(head) else None
                if ev is None:
                    self.finished = True
                    break
                out.append(ev)
                self._body(head)
            elif self.mode == "chunk_size":
                i = self.buf.find(b"\r\n")
                if i < 0:
                    if len(self.buf) > 64:
                        self.finished = True
                    break
                try:
                    size = int(bytes(self.buf[:i]).split(b";")[0].strip(), 16)
                except ValueError:
                    self.finished = True
                    break
                del self.buf[:i + 2]
                if size == 0:
                    self.mode = "trailer"
                else:
                    self.skip = size + 2  # chunk data plus its CRLF
            else:  # trailer lines until a blank line
                i = self.buf.find(b"\r\n")
                if i < 0:
                    if len(self.buf) > MAX_HTTP_HEAD:
                        self.finished = True
                    break
                del self.buf[:i + 2]
                if i == 0:
                    self.mode = "head"
        return out

    def _body(self, head: bytes) -> None:
        if self.request:
            if head.startswith(b"CONNECT "):
                self.finished = True
                return
        else:
            status = int(head[9:12])
            if status == 101:
                self.finished = True
                return
            if status < 200 or status in (204, 304):
                return
        if _CHUNKED.search(head):
            self.mode = "chunk_size"
            return
        m = _CONTENT_LENGTH.search(head)
        if m:
            self.skip = int(m.group(1))
        elif not self.request:
            self.finished = True  # body runs until the connection closes

    def flush_partial(self) -> list[tuple]:
        out = []
        if self.mode == "head" and not self.skip and self._starts_ok(self.buf):
            ev = self._event(bytes(self.buf))
            if ev:
                out.append(ev)
        self.finished = True
        return out


class TlsStream:
    """TLS records and handshake messages; stops at the first encrypted data."""

    def __init__(self, server: bool) -> None:
        self.server = server
        self.buf = bytearray()
        self.hs = bytearray()
        self.skip = 0
        self.hs_skip = 0
        self.hrr_pending = False  # after a HelloRetryRequest the real ServerHello still follows in plaintext
        self.finished = False

    def feed(self, data: bytes) -> list[tuple]:
        out = []
        self.buf += data
        while not self.finished:
            if self.skip:
                n = min(self.skip, len(self.buf))
                del self.buf[:n]
                self.skip -= n
                if self.skip:
                    break
            if len(self.buf) < 5:
                break
            typ, major, ln = self.buf[0], self.buf[1], (self.buf[3] << 8) | self.buf[4]
            if typ not in (20, 21, 22, 23) or major != 3 or ln > MAX_TLS_RECORD:
                self.finished = True
                break
            if typ == 23:  # application data: encrypted from here on
                self.finished = True
                break
            if len(self.buf) < 5 + ln:
                break
            record = bytes(self.buf[:5 + ln])
            del self.buf[:5 + ln]
            if typ == 20:  # ChangeCipherSpec: everything after is encrypted (unless a HelloRetryRequest is pending)
                if not self.hrr_pending:
                    self.finished = True
            elif typ == 21:
                alert = tls_alert(record)
                if alert:
                    out.append(("tls_alert", alert))
            else:
                self.hs += record[5:]
                self._handshake(out)
        return out

    def _handshake(self, out: list) -> None:
        want = 2 if self.server else 1
        while True:
            if self.hs_skip:
                n = min(self.hs_skip, len(self.hs))
                del self.hs[:n]
                self.hs_skip -= n
                if self.hs_skip:
                    return
            if len(self.hs) < 4:
                return
            mt, ml = self.hs[0], int.from_bytes(self.hs[1:4], "big")
            if mt != want:
                del self.hs[:4]  # certificates, key exchange, Finished...: skip without buffering
                self.hs_skip = ml
                continue
            if ml > MAX_HELLO:
                self.finished = True
                return
            if len(self.hs) < 4 + ml:
                return
            msg = bytes(self.hs[:4 + ml])
            del self.hs[:4 + ml]
            self._hello(msg, out)

    def _hello(self, msg: bytes, out: list) -> None:
        # the parsers expect a 5-byte record header before the handshake message
        h = b"\x16\x03\x01" + min(len(msg), 65535).to_bytes(2, "big") + msg
        if self.server:
            r = parse_server_hello(h)
            if r:
                self.hrr_pending = bool(r[1])
                out.append(("tls_server_hello", r))
        else:
            r = parse_client_hello(h)
            if r:
                out.append(("tls_client_hello", r))

    def flush_partial(self) -> list[tuple]:
        out = []
        want = 2 if self.server else 1
        partial = bytes(self.hs) if self.hs else (
            bytes(self.buf[5:]) if len(self.buf) > 5 and self.buf[0] == 22 else b"")
        if len(partial) >= 4 and partial[0] == want and not self.hs_skip:
            self._hello(partial[:MAX_HELLO + 4], out)  # tolerant parse of a hello cut off by the snaplen
        self.finished = True
        return out


class SshStream:
    def __init__(self) -> None:
        self.buf = bytearray()
        self.finished = False

    def _banner(self, end: int) -> list[tuple]:
        self.finished = True
        return [("ssh", bytes(self.buf[:end]).rstrip(b"\r").decode("latin-1")[:80])]

    def feed(self, data: bytes) -> list[tuple]:
        self.buf += data
        i = self.buf.find(b"\n")
        if i >= 0:
            return self._banner(i)
        return self._banner(255) if len(self.buf) >= 255 else []

    def flush_partial(self) -> list[tuple]:
        return self._banner(255) if self.buf and not self.finished else []


def sniff(b: bytes) -> str | None:
    if b.startswith(HTTP_METHODS):
        return "http_req"
    if b.startswith(b"HTTP/1."):
        return "http_resp"
    if len(b) >= 2 and b[0] in (20, 21, 22) and b[1] == 3:
        return "tls"
    if b.startswith(b"SSH-"):
        return "ssh"
    return None


def _could_become_known(b: bytes) -> bool:
    return len(b) < 8 and (b[:1] in (b"\x14", b"\x15", b"\x16") and len(b) < 2
                           or any(p.startswith(b) for p in SNIFF_PATTERNS))


class AppStream:
    """One TCP direction: reassemble, detect the protocol, and emit (kind, value) events."""

    def __init__(self, server_side: bool, dns: bool = False) -> None:
        self.server_side = server_side  # True when this direction is server -> client
        self.re = Reassembler()
        self.parser = DnsStream() if dns else None
        self.pre = bytearray()
        self.off = False

    def syn(self, seq: int) -> None:
        self.re.syn(seq)

    def feed(self, seq: int, data: bytes, lost: int = 0) -> list[tuple]:
        if self.off:
            return []
        chunk = self.re.add(seq, data, lost)
        events = self._deliver(chunk) if chunk else []
        if not self.off and self.re.broken:
            events += self._finish()
        return events

    def _make(self, kind: str):
        if kind == "http_req":
            return HttpStream(True)
        if kind == "http_resp":
            return HttpStream(False)
        if kind == "tls":
            return TlsStream(self.server_side)
        return SshStream()

    def _deliver(self, chunk: bytes) -> list[tuple]:
        if self.parser is None:
            self.pre += chunk
            kind = sniff(bytes(self.pre))
            if kind is None:
                if not _could_become_known(bytes(self.pre)):
                    self._close()
                return []
            self.parser = self._make(kind)
            chunk = bytes(self.pre)
            self.pre.clear()
        events = self.parser.feed(chunk)
        if self.parser.finished:
            self._close()
        return events

    def _finish(self) -> list[tuple]:
        events: list[tuple] = []
        if self.parser is None and self.pre:
            kind = sniff(bytes(self.pre))
            if kind:
                self.parser = self._make(kind)
                events += self.parser.feed(bytes(self.pre))
        if self.parser is not None and not self.parser.finished:
            events += self.parser.flush_partial()
        self._close()
        return events

    def _close(self) -> None:
        self.off = True
        self.parser = None
        self.pre.clear()
        self.re.ooo.clear()
        self.re.ooo_bytes = 0
