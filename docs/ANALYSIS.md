# Mobile Analysis

PocketPCAP's analysis workspace is a deterministic layer above the bundled Wireshark engine. It is designed to answer the first-pass questions in `PocketPCAP Mobile Analysis Expansion.md` without replacing tshark dissectors or modifying source captures.

## Scope and cache

The Summary, Conversations, Endpoints, Protocols, Issues, DNS, TLS, HTTP, Statistics, Timeline, Search entity index, and contextual suggestions describe the **whole capture**. Packet-list display filters do not silently narrow these views.

`DecodeManager.captureAnalysis()` caches one immutable `CaptureAnalysis` using:

- absolute capture path;
- file size;
- modification time;
- complete decryption argument list;
- optional explicit analysis-scope filter.

The cache is replaced when another capture opens and naturally misses when the file or decryption configuration changes. `MainViewModel` explicitly clears it after TLS/Wi-Fi decryption changes. All tshark, parsing, Room, file, and payload-search work runs on background dispatchers.

Opening a file uses this analysis pass to populate both the summary and unfiltered packet list. It does not run separate whole-file packet-list and stream-index scans first.

## Primary tshark command

The command is assembled as an argv list and shell-quoted by `TsharkBundle`:

```text
tshark -r <capture> -n <decryption options> \
  -T fields \
  -e frame.number -e frame.time_epoch -e frame.time_relative \
  ... \
  -E separator=/t -E occurrence=a -E aggregator=| -E quote=n
```

The field list is the `CaptureAnalysisParser.fields` source of truth. Major dependencies are:

| Analysis | tshark/Wireshark fields |
|---|---|
| Evidence identity | `frame.number`, `frame.time_epoch`, `frame.time_relative`, `frame.len`, `frame.encap_type` |
| Link/network endpoints | `eth.src/dst`, `wlan.sa/da`, `ip.src/dst`, `ipv6.src/dst` |
| Packet display | `_ws.col.Protocol`, `_ws.col.Info` |
| Conversations | `tcp.srcport/dstport`, `tcp.stream`, `tcp.len`, `udp.srcport/dstport`, `udp.stream` |
| TCP findings | `tcp.flags.syn/ack/fin/reset`, `tcp.analysis.retransmission`, `fast_retransmission`, `duplicate_ack`, `out_of_order`, `lost_segment`, `ack_lost_segment`, `zero_window` |
| DNS | `dns.id`, `dns.flags.response`, `dns.qry.name/type`, `dns.a`, `dns.aaaa`, `dns.flags.rcode`, `dns.time` |
| HTTP | `http.request.method`, `http.host`, `http.request.uri`, `http.response.code`, `http.content_type`, `http.content_length`, `http.time`, `http.request_in`, `http.response_in` |
| TLS | SNI, ALPN, handshake/supported/record versions, cipher suite, alert description/level, handshake type, X.509 validity and captured string fields |
| General findings | `_ws.malformed`, `icmp.type.error`, `icmpv6.type.error` |

Raw payload fields are intentionally excluded from the persistent analysis export. ASCII/hex payload search runs a bounded, on-demand tshark display-filter query, avoiding a second payload copy in memory.

## Correlation rules

### Conversations

TCP and UDP packets use Wireshark stream indices. Direction A→B is the direction of the first observed packet in that stream. IPv4 and IPv6 conversations use canonical endpoint pairs. Counts, bytes, start, duration, packet references, direction totals, and per-TCP-conversation retransmission totals come directly from captured rows.

### DNS

Queries and responses match on transaction ID, query name, client, and server. `dns.time` is preferred for response latency; capture-relative timestamp difference is the fallback. A pending query at end-of-capture is marked `Unanswered`. Response codes are rendered as success, SERVFAIL, NXDOMAIN, REFUSED, or the numeric RCODE.

### HTTP

Requests originate from `http.request.method`. Responses first use `http.request_in`; only when absent does the parser choose the latest unmatched request in the same TCP stream. Status, content metadata, and `http.time` remain unavailable when tshark does not expose them.

### TLS

TLS sessions group by TCP stream. Client/server orientation prefers a ClientHello. SNI, ALPN, alerts, cipher, certificate strings/validity, and handshake state are retained only when present. A supported version seen without a ServerHello is labelled `offered`; it is not represented as negotiated. Encrypted application content is never implied unless the configured decryption options let tshark dissect it.

## Findings rules

Findings require direct packet evidence and include a Wireshark display filter plus frame references.

- TCP analysis fields produce matching TCP categories.
- TCP reset requires the boolean field to be true; a printed `False` is not evidence.
- Failed TCP connection requires at least two SYN-without-ACK packets and no SYN+ACK in that tshark stream.
- DNS failures use response RCODE; unanswered requests come only from unmatched pending queries; slow DNS is at least 1,000 ms.
- HTTP errors are 400–499 and 500–599.
- TLS alert/handshake-failure and old-version findings require dissected TLS fields. An alert before an observed Finished message is labelled a handshake failure. Certificate expiry requires a captured numeric `notAfter` earlier than capture start.
- Large transfer requires at least 10,000,000 captured bytes in one conversation direction.
- Malformed and ICMP errors require their respective evidence fields.

PocketPCAP does not currently claim self-signed status when the dissector output cannot establish issuer/subject equality confidently.

## Filters and pivots

Generated filters use Wireshark syntax, for example:

```text
tcp.stream == 17
udp.stream == 4
ip.addr == 192.0.2.10 && ip.addr == 198.51.100.8
dns.flags.rcode == 3
http.response.code >= 500 && http.response.code <= 599
frame.time_relative >= 10.000000 && frame.time_relative <= 20.000000
```

PDML field equality/exclusion is built from the raw field name/value. Numeric values remain bare; string values are escaped and quoted. Packet-list columns run a separate `frame.number` plus selected-field export and keep at most three columns.

## Search

The in-memory index groups matching endpoints, conversations, DNS, HTTP, TLS, issues, packets, streams, aliases, and curated Wireshark field names. After a 250 ms debounce, raw payload search uses one of:

```text
frame contains aa:bb:cc:dd
tcp contains "text" || udp contains "text" || data contains "text"
```

The generated expression is validated by tshark before execution and results are capped.

## Follow Stream bytes

Follow Stream uses `tshark -z follow,<protocol>,raw,<stream>` so direction and binary
payload bytes remain exact. The text, ASCII, offset hex, raw hexadecimal, formatted HTTP,
and JSON views are derived from that byte-preserving output. Stream search matches both
decoded text and space/colon-separated hexadecimal input. It never writes to the capture.

## Bookmarks and notes

Room schema v3 adds `analysis_bookmarks`. Each record is scoped by capture path and stores entity type, stable reference ID, label, optional note, evidence filter, optional packet number, and creation timestamp. This data never enters the source PCAP/PCAPNG.

Migration `MIGRATION_2_3` is additive and is covered by `MigrationTest`. Schema JSON is committed under `app/schemas/`.

## Regression fixtures

Run:

```bash
scripts/generate-analysis-fixture.sh
./gradlew :app:testDebugUnitTest
```

The generator uses real `text2pcap`, `mergecap`, and tshark to create `app/src/test/resources/analysis-fixture.pcapng` and its exact fields output. It verifies that the HTTP body is extractable as an object. The combined fixture covers:

- normal TCP handshake/conversation;
- TCP retransmission and reset;
- repeated failed SYN attempts;
- DNS success, NXDOMAIN, and SERVFAIL;
- HTTP request/503 response and extractable JSON object;
- TLS ClientHello/SNI/ALPN/supported version and fatal alert;
- IPv4/MAC and multiple endpoints;
- UDP conversations;
- a deliberately truncated malformed IPv4 packet.

Parser unit tests additionally assert counts, latency, stream correlation, packet references, evidence filters, absent-evidence behavior, contextual suggestion limits, and grouped search.
