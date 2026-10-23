"""Optional TLS decryption from an SSLKEYLOGFILE, plus certificate inspection.

Key derivation uses only the standard library; the AEAD ciphers and X.509 parsing need the optional
`cryptography` package. Without it (or without keys) every function degrades to "not decrypted".

Supported: TLS 1.3 (AES-128/256-GCM, ChaCha20-Poly1305) and TLS 1.2 AEAD suites (AES-GCM, ChaCha20-Poly1305).
Not supported: CBC suites, TLS 1.3 KeyUpdate, 0-RTT early data, QUIC.
"""
from __future__ import annotations

import hashlib
import hmac
import struct
from datetime import datetime, timezone

try:
    from cryptography import x509
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
    from cryptography.x509.oid import NameOID
    HAVE_CRYPTO = True
except Exception:  # missing or broken installation: decryption simply stays off
    HAVE_CRYPTO = False

MAX_CERT_MSG = 200_000
MAX_KEYLOG_LINES = 2_000_000

# suite -> (cipher, key length, PRF/HKDF hash)
SUITES_13 = {0x1301: ("aes", 16, "sha256"), 0x1302: ("aes", 32, "sha384"), 0x1303: ("chacha", 32, "sha256")}
SUITES_12 = {
    0xC02B: ("aes", 16, "sha256"), 0xC02F: ("aes", 16, "sha256"), 0x009C: ("aes", 16, "sha256"),
    0x009E: ("aes", 16, "sha256"),
    0xC02C: ("aes", 32, "sha384"), 0xC030: ("aes", 32, "sha384"), 0x009D: ("aes", 32, "sha384"),
    0x009F: ("aes", 32, "sha384"),
    0xCCA8: ("chacha", 32, "sha256"), 0xCCA9: ("chacha", 32, "sha256"), 0xCCAA: ("chacha", 32, "sha256"),
}


def parse_keylog(text: str) -> dict[bytes, dict[str, bytes]]:
    """Parse NSS key log text into {client_random: {label: secret}}."""
    out: dict[bytes, dict[str, bytes]] = {}
    for n, line in enumerate(text.splitlines()):
        if n >= MAX_KEYLOG_LINES:
            break
        parts = line.split()
        if len(parts) != 3 or parts[0].startswith("#"):
            continue
        try:
            rnd, secret = bytes.fromhex(parts[1]), bytes.fromhex(parts[2])
        except ValueError:
            continue
        if len(rnd) == 32 and secret:
            out.setdefault(rnd, {})[parts[0].upper()] = secret
    return out


def _hkdf_expand_label(secret: bytes, label: bytes, length: int, algo: str) -> bytes:
    full = b"tls13 " + label
    info = struct.pack(">H", length) + bytes([len(full)]) + full + b"\x00"
    out, t, i = b"", b"", 1
    while len(out) < length:
        t = hmac.new(secret, t + info + bytes([i]), algo).digest()
        out += t
        i += 1
    return out[:length]


def _prf(secret: bytes, label: bytes, seed: bytes, length: int, algo: str) -> bytes:
    seed = label + seed
    a, out = seed, b""
    while len(out) < length:
        a = hmac.new(secret, a, algo).digest()
        out += hmac.new(secret, a + seed, algo).digest()
    return out[:length]


class _Keys:
    def __init__(self, cipher: str, key: bytes, iv: bytes) -> None:
        self.cipher, self.iv = cipher, iv
        self.aead = AESGCM(key) if cipher == "aes" else ChaCha20Poly1305(key)
        self.seq = 0


class _Dir:
    def __init__(self, stages: list[_Keys]) -> None:
        self.stages = stages
        self.cur = 0


class TlsContext:
    """Per-connection TLS state shared by both directions' record parsers."""

    def __init__(self, keylog: dict | None = None, dot: bool = False, methods=None) -> None:
        self.keylog = keylog or {}
        self.dot = dot
        self.methods = methods
        self.client_random: bytes | None = None
        self.server_random: bytes | None = None
        self.suite: int | None = None
        self.mode: str | None = None  # "13" | "12"
        self.status: str | None = None  # why decryption is/was not possible
        self.decrypted = False
        self.failures = 0
        self.failed = False
        self._dirs: dict[bool, _Dir | None] = {}

    def set_client_hello(self, random: bytes) -> None:
        if self.client_random is None:
            self.client_random = random

    def set_server_hello(self, random: bytes, suite: int, tls13: bool) -> None:
        self.server_random, self.suite, self.mode = random, suite, "13" if tls13 else "12"

    def can_decrypt(self, server: bool) -> bool:
        if self.failed or not self.keylog or self.client_random is None or self.mode is None:
            return False
        if server not in self._dirs:
            self._dirs[server] = self._build(server)
        return self._dirs[server] is not None

    def _build(self, server: bool) -> _Dir | None:
        if not HAVE_CRYPTO:
            self.status = "cryptography package not installed"
            return None
        secrets = self.keylog.get(self.client_random)
        if not secrets:
            self.status = "no key for this session in the key log"
            return None
        table = SUITES_13 if self.mode == "13" else SUITES_12
        if self.suite not in table:
            self.status = f"unsupported cipher suite 0x{self.suite:04x}" if self.suite is not None else "no ServerHello"
            return None
        cipher, klen, algo = table[self.suite]
        if self.mode == "13":
            side = "SERVER" if server else "CLIENT"
            stages = []
            for label in (f"{side}_HANDSHAKE_TRAFFIC_SECRET", f"{side}_TRAFFIC_SECRET_0"):
                sec = secrets.get(label)
                if sec:
                    stages.append(_Keys(cipher, _hkdf_expand_label(sec, b"key", klen, algo),
                                        _hkdf_expand_label(sec, b"iv", 12, algo)))
            if not stages:
                self.status = "key log has no TLS 1.3 traffic secrets for this session"
                return None
            return _Dir(stages)
        ms = secrets.get("CLIENT_RANDOM")
        if not ms or self.server_random is None:
            self.status = "key log has no master secret for this session"
            return None
        ivlen = 4 if cipher == "aes" else 12
        block = _prf(ms, b"key expansion", self.server_random + self.client_random, 2 * klen + 2 * ivlen, algo)
        ck, sk = block[:klen], block[klen:2 * klen]
        civ, siv = block[2 * klen:2 * klen + ivlen], block[2 * klen + ivlen:]
        return _Dir([_Keys(cipher, sk, siv) if server else _Keys(cipher, ck, civ)])

    def decrypt(self, server: bool, rtype: int, header: bytes, body: bytes) -> tuple[int, bytes] | None:
        """Decrypt one record body; returns (content type, plaintext) or None if it could not be."""
        d = self._dirs.get(server)
        if d is None:
            return None
        res = self._try13(d, header, body) if self.mode == "13" else self._try12(d, rtype, header, body)
        if res is None:
            self.failures += 1
            if self.failures >= 3 and not self.decrypted:
                self.failed, self.status = True, "records did not decrypt with the supplied keys"
            return None
        self.decrypted, self.status = True, "decrypted"
        self.failures = 0
        return res

    @staticmethod
    def _nonce(iv: bytes, seq: int) -> bytes:
        return bytes(a ^ b for a, b in zip(iv, b"\x00" * (len(iv) - 8) + struct.pack(">Q", seq)))

    def _try13(self, d: _Dir, header: bytes, body: bytes):
        for idx in range(d.cur, len(d.stages)):
            k = d.stages[idx]
            seq = k.seq if idx == d.cur else 0
            try:
                plain = k.aead.decrypt(self._nonce(k.iv, seq), body, header)
            except Exception:
                continue
            k.seq = seq + 1
            d.cur = idx
            plain = plain.rstrip(b"\x00")
            return (plain[-1], plain[:-1]) if plain else None
        return None

    def _try12(self, d: _Dir, rtype: int, header: bytes, body: bytes):
        k = d.stages[0]
        if k.cipher == "aes":
            if len(body) < 8 + 16:
                return None
            nonce, ct = k.iv + body[:8], body[8:]
        else:
            if len(body) < 16:
                return None
            nonce, ct = self._nonce(k.iv, k.seq), body
        aad = struct.pack(">Q", k.seq) + bytes([rtype]) + header[1:3] + struct.pack(">H", len(ct) - 16)
        try:
            plain = k.aead.decrypt(nonce, ct, aad)
        except Exception:
            return None
        k.seq += 1
        return rtype, plain


def parse_certificates(body: bytes, tls13: bool) -> list[bytes]:
    """DER certificates from a Certificate handshake message body (without the 4-byte header)."""
    try:
        i = 1 + body[0] if tls13 else 0  # TLS 1.3 starts with certificate_request_context
        end = i + 3 + int.from_bytes(body[i:i + 3], "big")
        i += 3
        out = []
        while i + 3 <= end and len(out) < 10:
            n = int.from_bytes(body[i:i + 3], "big")
            out.append(body[i + 3:i + 3 + n])
            i += 3 + n + (2 + int.from_bytes(body[i + 3 + n:i + 5 + n], "big") if tls13 else 0)
        return out
    except (IndexError, ValueError):
        return []


def describe_certificate(der: bytes) -> dict | None:
    """Subject, issuer, validity and DNS names of a certificate; None when it cannot be parsed."""
    if not HAVE_CRYPTO:
        return None
    try:
        cert = x509.load_der_x509_certificate(der)
        cn = lambda name: next((a.value for a in name.get_attributes_for_oid(NameOID.COMMON_NAME)), None)
        nb = getattr(cert, "not_valid_before_utc", None) or cert.not_valid_before.replace(tzinfo=timezone.utc)
        na = getattr(cert, "not_valid_after_utc", None) or cert.not_valid_after.replace(tzinfo=timezone.utc)
        try:
            san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value.get_values_for_type(
                x509.DNSName)
        except x509.ExtensionNotFound:
            san = []
        return {"subject": cn(cert.subject) or cert.subject.rfc4514_string(),
                "issuer": cn(cert.issuer) or cert.issuer.rfc4514_string(),
                "self_signed": cert.subject == cert.issuer,
                "not_before": nb.timestamp(), "not_after": na.timestamp(), "names": san[:50]}
    except Exception:
        return None


def hostname_matches(host: str, names: list[str]) -> bool:
    host = host.lower().rstrip(".")
    for n in names:
        n = n.lower().rstrip(".")
        if n == host or (n.startswith("*.") and host.split(".", 1)[-1] == n[2:] and "." in host):
            return True
    return False


def fmt_time(ts: float) -> str:
    return datetime.fromtimestamp(ts, timezone.utc).strftime("%Y-%m-%d")
