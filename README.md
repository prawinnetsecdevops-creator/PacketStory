# PacketStory

**Every packet tells a story. Understand yours.**

PacketStory turns `.pcap` / `.pcapng` captures into a ranked, plain-English troubleshooting report: what is
broken, why it probably is, and what to do next. It runs entirely on your machine. Captures are never uploaded.

**[Download for Windows](https://github.com/prawinnetsecdevops-creator/PacketStory/releases/latest/download/PacketStory-Portable.zip)**
&middot; [Project page](https://prawinnetsecdevops-creator.github.io/PacketStory/)

## Quick start (Windows, no install)

1. Download `PacketStory-Portable.zip` from the [latest release](https://github.com/prawinnetsecdevops-creator/PacketStory/releases/latest).
2. Extract it anywhere and run `PacketStory\PacketStory.exe` (no Python needed).
3. Drop one or more capture files into the window.

Windows SmartScreen may warn about an unsigned app on first run: choose **More info > Run anyway**.

## Features

- **Executive summary:** a 0-100 health score and issues ranked critical to low, each with a recommended action and the affected flows.
- **Every port and protocol:** TCP flows, UDP, DNS (over UDP and TCP), DHCP, ICMP/ICMPv6, ARP, and other IP protocols.
- **TCP health:** handshake failures, refused connections, resets, retransmissions, zero windows, duplicate ACKs, RTT, server response time.
- **MTU and size:** MSS-implied MTU, ICMP "fragmentation needed", IP fragmentation, PMTU black-hole detection, size distribution.
- **TLS:** SNI, ALPN, TLS 1.3 detection, missing ServerHello, deprecated versions, plaintext alerts.
- **Multiple captures:** analyze several files, compare them side by side, or merge them into one timeline (duplicate packets removed).
- **Export:** findings and TCP flows as CSV.

## Run from source

Requires Python 3.10+. There are no third-party dependencies.

```powershell
python app.py                    # desktop window (Edge or Chrome app mode)
python analyzer_backend.py       # web server at http://127.0.0.1:8000
python analyzer_backend.py a.pcap b.pcap   # CLI: print merged JSON
python -m unittest discover -s tests -v    # tests
```

API: `POST /api/analyze` (raw capture bytes), `POST /api/analyze/merge` (concatenated captures plus an
`X-File-Sizes` header), `GET /api/health`.

## Build the portable zip

```powershell
pip install pyinstaller
build_exe.bat        # produces PacketStory-Portable.zip
```

Pushing a tag such as `v2.0.0` builds the zip on GitHub and attaches it to a release automatically
(see `.github/workflows/release.yml`).

## Limitations

- TLS 1.3 encrypts alerts and certificates, so only the hellos are visible.
- DNS-over-TLS (port 853) is not decoded.
- Captures taken at different points on a path have different TTLs, so merging them can inflate retransmission counts.
- Limits: 200 MB per upload, 5,000 packet rows shown, 20,000 UDP flows tracked.

## License

GNU General Public License v3.0. See [LICENSE](LICENSE).
