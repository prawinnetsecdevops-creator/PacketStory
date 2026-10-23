import datetime
import os
import struct
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
import tlscrypt  # noqa: E402
from test_backend import dns_msg, pcap, run, tcp_pkt  # noqa: E402
import analyzer_backend as t  # noqa: E402

if tlscrypt.HAVE_CRYPTO:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.x509.oid import NameOID

C, S = "10.0.0.1", "10.0.0.2"
CR, SR = bytes(range(32)), bytes(range(100, 132))


def rec(ctype, body, ver=b"\x03\x03"):
    return bytes([ctype]) + ver + struct.pack(">H", len(body)) + body


def hs_msg(mtype, body):
    return bytes([mtype]) + len(body).to_bytes(3, "big") + body


def ext(et, body):
    return struct.pack(">HH", et, len(body)) + body


def client_hello(sni=b"good.example.com"):
    sni_ext = ext(0, struct.pack(">HBH", len(sni) + 3, 0, len(sni)) + sni)
    exts = sni_ext + ext(43, b"\x02\x03\x04")
    body = b"\x03\x03" + CR + b"\x00" + struct.pack(">H", 4) + b"\x13\x01\xc0\x2f" + b"\x01\x00" \
        + struct.pack(">H", len(exts)) + exts
    return rec(22, hs_msg(1, body), b"\x03\x01")


def server_hello(suite, tls13=True):
    exts = ext(43, b"\x03\x04") if tls13 else b""
    body = b"\x03\x03" + SR + b"\x00" + struct.pack(">H", suite) + b"\x00" + struct.pack(">H", len(exts)) + exts
    return rec(22, hs_msg(2, body))


def make_cert(cn, expired):
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    start = datetime.datetime(2000, 1, 1) if expired else datetime.datetime(2020, 1, 1)
    end = datetime.datetime(2001, 1, 1) if expired else datetime.datetime(2099, 1, 1)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(1).not_valid_before(start).not_valid_after(end)
            .add_extension(x509.SubjectAlternativeName([x509.DNSName(cn)]), False)
            .sign(key, hashes.SHA256()))
    return cert.public_bytes(serialization.Encoding.DER)


class Enc13:
    """Encrypts TLS 1.3 records the way a real endpoint would."""

    def __init__(self, secret, klen=16):
        self.key = tlscrypt._hkdf_expand_label(secret, b"key", klen, "sha256")
        self.iv = tlscrypt._hkdf_expand_label(secret, b"iv", 12, "sha256")
        self.seq = 0

    def record(self, ctype, plain):
        inner = plain + bytes([ctype])
        header = b"\x17\x03\x03" + struct.pack(">H", len(inner) + 16)
        nonce = tlscrypt.TlsContext._nonce(self.iv, self.seq)
        self.seq += 1
        return header + AESGCM(self.key).encrypt(nonce, inner, header)


class Conn:
    def __init__(self, sport, dport):
        self.sport, self.dport, self.cs, self.ss, self.t, self.pk = sport, dport, 1, 1, 1_700_000_000.0, []

    def c2s(self, data):
        self.pk.append((self.t, tcp_pkt(C, S, self.sport, self.dport, self.cs, self.ss, 0x18, data)))
        self.cs += len(data)
        self.t += 0.01

    def s2c(self, data):
        self.pk.append((self.t, tcp_pkt(S, C, self.dport, self.sport, self.ss, self.cs, 0x18, data)))
        self.ss += len(data)
        self.t += 0.01

    def capture(self):
        return pcap(self.pk)


SECRETS = {"CLIENT_HANDSHAKE_TRAFFIC_SECRET": b"\x11" * 32, "SERVER_HANDSHAKE_TRAFFIC_SECRET": b"\x22" * 32,
           "CLIENT_TRAFFIC_SECRET_0": b"\x33" * 32, "SERVER_TRAFFIC_SECRET_0": b"\x44" * 32}
KEYLOG = {CR: SECRETS}


def tls13_session(port=443, app=(), cert_cn="bad.example.com", expired=True, alert=None):
    """app: list of ('c'|'s', plaintext) application-data records."""
    ch, sh_enc = Enc13(SECRETS["CLIENT_HANDSHAKE_TRAFFIC_SECRET"]), Enc13(SECRETS["SERVER_HANDSHAKE_TRAFFIC_SECRET"])
    c_app, s_app = Enc13(SECRETS["CLIENT_TRAFFIC_SECRET_0"]), Enc13(SECRETS["SERVER_TRAFFIC_SECRET_0"])
    conn = Conn(5000, port)
    conn.c2s(client_hello())
    der = make_cert(cert_cn, expired)
    cert = hs_msg(11, b"\x00" + (len(der) + 5).to_bytes(3, "big") + len(der).to_bytes(3, "big") + der + b"\x00\x00")
    conn.s2c(server_hello(0x1301) + rec(20, b"\x01") + sh_enc.record(22, hs_msg(8, b"\x00\x00") + cert)
             + sh_enc.record(22, hs_msg(20, b"\x00" * 32)))
    conn.c2s(rec(20, b"\x01") + ch.record(22, hs_msg(20, b"\x00" * 32)))
    for side, data in app:
        (conn.c2s if side == "c" else conn.s2c)((c_app if side == "c" else s_app).record(23, data))
    if alert:
        conn.s2c(s_app.record(21, bytes([2, alert])))
    return conn


@unittest.skipUnless(tlscrypt.HAVE_CRYPTO, "cryptography not installed")
class DecryptTests(unittest.TestCase):
    def test_hkdf_matches_rfc8448(self):
        secret = bytes.fromhex("b67b7d690cc16c4e75e54213cb2d37b4e9c912bcded9105d42befd59d391ad38")
        self.assertEqual(tlscrypt._hkdf_expand_label(secret, b"key", 16, "sha256").hex(),
                         "3fce516009c21727d0f2e4e86ee403bc")
        self.assertEqual(tlscrypt._hkdf_expand_label(secret, b"iv", 12, "sha256").hex(), "5d313eb2671276ee13000b30")

    def test_tls13_without_keys_is_opaque(self):
        raw = tls13_session(app=[("c", b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")]).capture()
        f = run(raw)["flows"][0]
        self.assertEqual(f["tls_version"], "TLS 1.3")
        self.assertTrue(f["tls13_encrypted"])
        self.assertFalse(f["tls_decrypted"])
        self.assertEqual(f["tls_certs"], [])

    def test_tls13_certificate_alert_and_http_decrypted(self):
        raw = tls13_session(app=[("c", b"GET /x HTTP/1.1\r\nHost: good.example.com\r\n\r\n"),
                                 ("s", b"HTTP/1.1 503 Busy\r\nContent-Length: 0\r\n\r\n")], alert=48).capture()
        r = t.analyze_capture(__import__("io").BytesIO(raw), KEYLOG)
        f = r["flows"][0]
        self.assertTrue(f["tls_decrypted"])
        self.assertFalse(f["tls13_encrypted"])
        self.assertEqual(f["tls_certs"][0]["subject"], "bad.example.com")
        text = " ".join(f["findings"])
        self.assertIn("had expired", text)
        self.assertIn("does not match the requested name good.example.com", text)
        self.assertIn("unknown_ca", text)
        self.assertEqual(f["http_requests"], 1)
        self.assertEqual(f["http_status"], {"503": 1})
        self.assertTrue(any(i["category"] == "TLS" for i in r["summary"]["issues"]))

    def test_valid_certificate_has_no_findings(self):
        raw = tls13_session(cert_cn="good.example.com", expired=False).capture()
        f = t.analyze_capture(__import__("io").BytesIO(raw), KEYLOG)["flows"][0]
        self.assertTrue(f["tls_decrypted"])
        self.assertFalse(any("certificate" in x for x in f["findings"]))

    def test_wrong_keys_degrade_gracefully(self):
        raw = tls13_session(app=[("c", b"GET / HTTP/1.1\r\n\r\n")] * 4).capture()
        bad = {CR: {k: b"\x99" * 32 for k in SECRETS}}
        r = t.analyze_capture(__import__("io").BytesIO(raw), bad)
        f = r["flows"][0]
        self.assertFalse(f["tls_decrypted"])
        self.assertIn("did not decrypt", f["tls_decryption"])
        self.assertTrue(any("could not be decrypted" in n for n in r["overview"]["notes"]))
        r = t.analyze_capture(__import__("io").BytesIO(raw), {b"\x00" * 32: SECRETS})
        self.assertIn("no key for this session", r["flows"][0]["tls_decryption"])

    def test_dot_without_keys_is_reported_not_decoded(self):
        q = dns_msg(7, "secret.test")
        raw = tls13_session(port=853, app=[("c", struct.pack(">H", len(q)) + q)]).capture()
        r = run(raw)
        f = r["flows"][0]
        self.assertEqual((f["application"], f["dot"], f["tls_decrypted"]), ("DNS-over-TLS", True, False))
        self.assertEqual(r["dns"]["queries"], 0)
        self.assertTrue(any("DNS-over-TLS" in n and "SSLKEYLOGFILE" in n for n in r["overview"]["notes"]))

    def test_dot_with_keys_decodes_dns(self):
        q, a = dns_msg(7, "secret.test"), dns_msg(7, "secret.test", qr=1)
        raw = tls13_session(port=853, app=[("c", struct.pack(">H", len(q)) + q),
                                           ("s", struct.pack(">H", len(a)) + a)]).capture()
        r = t.analyze_capture(__import__("io").BytesIO(raw), KEYLOG)
        d = r["dns"]
        self.assertEqual((d["queries"], d["responses"], d["unanswered"], d["dot_messages"], d["tcp_messages"]),
                         (1, 1, 0, 2, 0))
        self.assertEqual(r["flows"][0]["application"], "DNS-over-TLS")

    def test_tls12_gcm_decrypted(self):
        ms, suite = b"\x55" * 48, 0xC02F
        block = tlscrypt._prf(ms, b"key expansion", SR + CR, 2 * 16 + 2 * 4, "sha256")
        ck, sk, civ, siv = block[:16], block[16:32], block[32:36], block[36:40]

        def enc(key, salt, seq, rtype, plain):
            explicit = struct.pack(">Q", seq)
            aad = struct.pack(">Q", seq) + bytes([rtype]) + b"\x03\x03" + struct.pack(">H", len(plain))
            ct = AESGCM(key).encrypt(salt + explicit, plain, aad)
            return rec(rtype, explicit + ct)
        conn = Conn(5000, 443)
        conn.c2s(client_hello())
        cert = make_cert("good.example.com", False)
        certs = hs_msg(11, (len(cert) + 3).to_bytes(3, "big") + len(cert).to_bytes(3, "big") + cert)
        conn.s2c(server_hello(suite, tls13=False) + rec(22, certs))
        conn.c2s(rec(20, b"\x01") + enc(ck, civ, 0, 22, hs_msg(20, b"\x00" * 12)))
        conn.s2c(rec(20, b"\x01") + enc(sk, siv, 0, 22, hs_msg(20, b"\x00" * 12)))
        conn.c2s(enc(ck, civ, 1, 23, b"GET / HTTP/1.1\r\nHost: good.example.com\r\n\r\n"))
        conn.s2c(enc(sk, siv, 1, 23, b"HTTP/1.1 500 Err\r\nContent-Length: 0\r\n\r\n"))
        keylog = {CR: {"CLIENT_RANDOM": ms}}
        f = t.analyze_capture(__import__("io").BytesIO(conn.capture()), keylog)["flows"][0]
        self.assertEqual(f["tls_version"], "TLS 1.2")
        self.assertTrue(f["tls_decrypted"])
        self.assertEqual((f["http_requests"], f["http_status"]), (1, {"500": 1}))
        # the TLS 1.2 certificate travels in clear text, so it is inspected even without keys
        f = run(conn.capture())["flows"][0]
        self.assertEqual(f["tls_certs"][0]["subject"], "good.example.com")
        self.assertFalse(f["tls_decrypted"])


class KeylogTests(unittest.TestCase):
    @unittest.skipUnless(tlscrypt.HAVE_CRYPTO, "cryptography not installed")
    def test_keylog_upload_then_analyze_over_http(self):
        import http.client, json, threading
        srv = t.ThreadingHTTPServer(("127.0.0.1", 0), t.Handler)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        c = http.client.HTTPConnection("127.0.0.1", srv.server_port)
        try:
            c.request("POST", "/api/keylog", body=b"not a key log")
            r = c.getresponse()
            r.read()
            self.assertEqual(r.status, 400)
            text = "".join(f"{k} {CR.hex()} {v.hex()}\n" for k, v in SECRETS.items())
            c.request("POST", "/api/keylog", body=text.encode())
            r = c.getresponse()
            kid = json.loads(r.read())["id"]
            raw = tls13_session(cert_cn="good.example.com", expired=False).capture()
            c.request("POST", "/api/analyze", body=raw, headers={"X-Keylog-Id": kid})
            body = json.loads(c.getresponse().read())
            self.assertTrue(body["flows"][0]["tls_decrypted"])
            c.request("POST", "/api/analyze", body=raw)
            self.assertFalse(json.loads(c.getresponse().read())["flows"][0]["tls_decrypted"])
        finally:
            c.close()
            srv.shutdown()
            srv.server_close()
    def test_parse_keylog(self):
        text = "# comment\nCLIENT_RANDOM " + "ab" * 32 + " " + "cd" * 48 + "\nbogus line\nX zz yy\n"
        k = tlscrypt.parse_keylog(text)
        self.assertEqual(list(k), [bytes.fromhex("ab" * 32)])
        self.assertEqual(k[bytes.fromhex("ab" * 32)]["CLIENT_RANDOM"], bytes.fromhex("cd" * 48))

    def test_missing_cryptography_is_reported(self):
        saved = tlscrypt.HAVE_CRYPTO
        tlscrypt.HAVE_CRYPTO = False
        try:
            ctx = tlscrypt.TlsContext({CR: SECRETS})
            ctx.set_client_hello(CR)
            ctx.set_server_hello(SR, 0x1301, True)
            self.assertFalse(ctx.can_decrypt(True))
            self.assertIn("not installed", ctx.status)
        finally:
            tlscrypt.HAVE_CRYPTO = saved


if __name__ == "__main__":
    unittest.main()
