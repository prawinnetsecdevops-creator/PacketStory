"""Executive summary: ranks everything the analyzer found and attaches a recommended action."""

from __future__ import annotations

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}
WEIGHTS = {"critical": 25, "high": 12, "medium": 5, "low": 1}

# (keyword in an extras finding, severity, action)
GENERIC_ACTIONS = [
    ("unreachable", "high", "Verify routing, firewall rules and that the destination service is running."),
    ("no reply", "medium", "Check that the target is up and that ICMP/UDP is not filtered along the path."),
    ("loop", "high", "Inspect the routing path (traceroute) for loops or a TTL that is too low."),
    ("duplicate", "high", "Two devices claim the same IP address; find the second MAC and fix addressing."),
    ("NAK", "medium", "Check the DHCP scope and lease database; the client is asking for an address that is not valid here."),
    ("never answered", "medium", "Check that the target host/service is reachable and not rate-limiting."),
]


def _issue(sev: str, category: str, title: str, detail: str, action: str, flows: list[int] | None = None) -> dict:
    return {"severity": sev, "category": category, "title": title, "detail": detail,
            "action": action, "flows": (flows or [])[:20]}


def _tcp_issues(r: dict) -> list[dict]:
    out: list[dict] = []
    flows = r.get("flows", [])
    total = len(flows)

    def ids(pred) -> list[int]:
        return [f["id"] for f in flows if pred(f)]

    def has(f: dict, text: str) -> bool:
        return any(text in x for x in f["findings"])

    refused = ids(lambda f: has(f, "connection refused"))
    if refused:
        out.append(_issue("high", "TCP", f"{len(refused)} connection(s) refused",
                          "SYN was answered with RST: nothing is listening or a firewall is rejecting.",
                          "Confirm the service is running on that port and check firewall reject rules.", refused))
    dropped = ids(lambda f: f["state"] == "syn-unanswered")
    if dropped:
        out.append(_issue("high", "TCP", f"{len(dropped)} connection attempt(s) got no reply",
                          "SYN packets went unanswered: host down, filtered, or dropped en route.",
                          "Check host reachability and any firewall silently dropping this traffic.", dropped))
    half = ids(lambda f: f["state"] == "handshake-incomplete")
    if half:
        out.append(_issue("medium", "TCP", f"{len(half)} handshake(s) never completed",
                          "SYN/ACK was seen but the final ACK was not.",
                          "Look for asymmetric routing or a stateful firewall dropping the ACK.", half))
    aborted = ids(lambda f: f["resets"] and not has(f, "connection refused"))
    if aborted:
        out.append(_issue("medium", "TCP", f"{len(aborted)} connection(s) aborted with RST",
                          "Established connections were reset by one side.",
                          "Check application logs, idle timeouts and load balancer / firewall session limits.", aborted))
    lossy = ids(lambda f: f["retransmission_pct"] >= 2)
    retrans = r.get("overview", {}).get("total_retransmissions", 0)
    if lossy:
        sev = "high" if len(lossy) >= max(3, total // 4) else "medium"
        out.append(_issue(sev, "Packet loss", f"{retrans} retransmission(s) in {len(lossy)} flow(s) above 2%",
                          "Retransmissions point to packet loss or congestion on the path.",
                          "Check interface errors/drops, link duplex, congestion and Wi-Fi quality along the path.", lossy))
    blackhole = ids(lambda f: has(f, "PMTU black hole"))
    if blackhole:
        out.append(_issue("critical", "MTU", f"Possible PMTU black hole in {len(blackhole)} flow(s)",
                          "Full-size DF segments were retransmitted and never acknowledged while smaller segments "
                          "were delivered (or a router reported 'packet too big').",
                          "Allow ICMP 'fragmentation needed', or clamp MSS / lower the interface MTU on the tunnel or VPN.",
                          blackhole))
    suspected = ids(lambda f: has(f, "PMTU suspected"))
    if suspected:
        out.append(_issue("medium", "MTU", f"PMTU problem suspected in {len(suspected)} flow(s) (lower confidence)",
                          "Full-size DF segments went unacknowledged after a working handshake, but nothing proves "
                          "that smaller data would have succeeded.",
                          "Compare with a smaller-MTU or MSS-clamped test; rule out ordinary loss and a stalled peer first.",
                          suspected))
    zero = ids(lambda f: f["zero_windows"])
    if zero:
        out.append(_issue("medium", "TCP", f"Zero-window stalls in {len(zero)} flow(s)",
                          "A receiver advertised a window of 0 and stopped the sender.",
                          "The receiving application or host is too slow; check its CPU and socket buffers.", zero))
    slow = ids(lambda f: has(f, "Slow server response") or has(f, "High average round-trip"))
    if slow:
        out.append(_issue("medium", "Latency", f"High latency in {len(slow)} flow(s)",
                          "Round-trip time above 150 ms or server response above 1 s.",
                          "Separate network delay (RTT) from server processing time; test the path with ping/traceroute.", slow))
    tls_bad = ids(lambda f: has(f, "TLS alert"))
    if tls_bad:
        out.append(_issue("high", "TLS", f"TLS alerts in {len(tls_bad)} flow(s)",
                          "Peers rejected the TLS handshake or session.",
                          "Check certificates, trust chain, SNI and protocol/cipher compatibility.", tls_bad))
    nohello = ids(lambda f: has(f, "no ServerHello"))
    if nohello:
        out.append(_issue("high", "TLS", f"{len(nohello)} TLS handshake(s) got no ServerHello",
                          "The ClientHello was sent but the server never started the handshake.",
                          "Look for SNI filtering, TLS inspection or an overloaded server.", nohello))
    certs = ids(lambda f: has(f, "TLS certificate"))
    if certs:
        out.append(_issue("high", "TLS", f"Certificate problems in {len(certs)} flow(s)",
                          "A server certificate is expired, not yet valid, or does not match the requested name.",
                          "Renew or replace the certificate, and check the name clients use and the system clock.", certs))
    old = ids(lambda f: has(f, "Deprecated"))
    if old:
        out.append(_issue("low", "TLS", f"{len(old)} flow(s) use deprecated TLS/SSL",
                          "SSL 3.0 / TLS 1.0 / TLS 1.1 are obsolete.",
                          "Upgrade the endpoint to TLS 1.2 or newer.", old))
    http_bad = ids(lambda f: has(f, "HTTP error"))
    if http_bad:
        out.append(_issue("medium", "HTTP", f"HTTP error responses in {len(http_bad)} flow(s)",
                          "The server returned 4xx/5xx status codes.",
                          "Check the application/server logs for these requests.", http_bad))
    return out


def _mtu_issues(r: dict) -> list[dict]:
    out: list[dict] = []
    ov = r.get("overview", {})
    frags = r.get("fragments", 0)
    ptb = ov.get("icmp_mtu_messages") or []
    if ptb:
        mtu = min(m["next_hop_mtu"] for m in ptb)
        out.append(_issue("high", "MTU", f"Path MTU is {mtu} on at least one path",
                          f"{len(ptb)} ICMP 'fragmentation needed / packet too big' message(s) received.",
                          "Lower the sender MTU or clamp TCP MSS to match; avoid blocking ICMP type 3 code 4 / ICMPv6 type 2."))
    if frags:
        out.append(_issue("medium", "MTU", f"{frags} fragmented IP packet(s)",
                          "Datagrams larger than the path MTU are being fragmented.",
                          "Reduce UDP payload / EDNS size, fix MTU mismatches, or clamp MSS."))
    low = ov.get("min_mtu_from_mss")
    if low and low < 1500 and not ptb:
        out.append(_issue("low", "MTU", f"MSS implies an MTU of {low} (< 1500)",
                          "Tunnel, VPN or PPPoE overhead is reducing the effective MTU.",
                          "Confirm this is intended; otherwise check MSS clamping settings."))
    return out


def _extras_issues(r: dict) -> list[dict]:
    out: list[dict] = []
    dns = r.get("dns", {})
    if dns.get("unanswered"):
        out.append(_issue("high", "DNS", f"{dns['unanswered']} DNS quer{'y' if dns['unanswered'] == 1 else 'ies'} unanswered",
                          "Resolver is unreachable, filtered or overloaded.",
                          "Check resolver reachability on UDP/TCP 53 and the configured server addresses."))
    rc = dns.get("rcodes", {})
    for name, sev, action in (("SERVFAIL", "high", "Check the upstream resolver and DNSSEC/forwarder health."),
                              ("REFUSED", "medium", "Allow these clients in the resolver ACL / recursion settings.")):
        if rc.get(name):
            out.append(_issue(sev, "DNS", f"{rc[name]} DNS {name} response(s)", "Resolver reported a failure.", action))
    if rc.get("NXDOMAIN", 0) >= 10:
        out.append(_issue("low", "DNS", f"{rc['NXDOMAIN']} NXDOMAIN responses",
                          "Clients query names that do not exist.",
                          "Look for typos, stale configuration or search-domain suffix expansion."))
    lat = dns.get("latency_ms")
    if lat and lat["avg"] > 100:
        out.append(_issue("medium", "DNS", f"Slow DNS (avg {lat['avg']} ms)",
                          "Resolution adds noticeable delay to every connection.",
                          "Use a closer or cached resolver; check upstream latency."))
    if dns.get("truncated") and not dns.get("tcp_messages"):
        out.append(_issue("medium", "DNS", f"{dns['truncated']} truncated DNS responses with no TCP retry",
                          "Large answers need TCP/53 but none was seen.",
                          "Allow TCP/53 through firewalls and review EDNS buffer size."))
    for name in ("icmp", "arp", "dhcp"):
        for text in r.get(name, {}).get("findings", []):
            sev, action = "medium", "Investigate the affected hosts and path."
            for key, s, a in GENERIC_ACTIONS:
                if key.lower() in text.lower():
                    sev, action = s, a
                    break
            if "fragmentation needed" in text:
                continue  # already covered by the MTU issue
            out.append(_issue(sev, name.upper(), text.rstrip("."), "", action))
    bad_udp = [u for u in r.get("udp", {}).get("flows", [])
               if any("no reply" in x for x in u["findings"]) and not u["server"].endswith(":53")]
    if bad_udp:
        out.append(_issue("low", "UDP", f"{len(bad_udp)} UDP flow(s) never received a reply",
                          "One-way UDP traffic.", "Confirm the destination service is listening and not firewalled."))
    return out


def build_summary(result: dict) -> dict:
    if not result.get("analyzable_packets"):
        total = result.get("total_packets", 0)
        headline = ("The capture contains no packets, so nothing could be assessed." if not total else
                    f"None of the {total} packet(s) could be decoded as IP, TCP, UDP or ARP, so nothing could be assessed.")
        return {"health": "no data", "score": None, "headline": headline,
                "counts": {s: 0 for s in SEVERITY_ORDER}, "issues": []}
    issues = _tcp_issues(result) + _mtu_issues(result) + _extras_issues(result)
    issues.sort(key=lambda i: SEVERITY_ORDER[i["severity"]])
    score = max(0, 100 - sum(WEIGHTS[i["severity"]] for i in issues))
    counts = {s: sum(1 for i in issues if i["severity"] == s) for s in SEVERITY_ORDER}
    if counts["critical"] or score < 40:
        health = "critical"
    elif counts["high"] or score < 75:
        health = "degraded"
    elif issues:
        health = "minor issues"
    else:
        health = "healthy"
    if issues:
        top = issues[0]
        headline = (f"{len(issues)} issue(s) found ({counts['critical']} critical, {counts['high']} high). "
                    f"Most important: {top['title']}.")
    else:
        headline = "No problems detected in this capture."
    return {"health": health, "score": score, "headline": headline, "counts": counts, "issues": issues}
