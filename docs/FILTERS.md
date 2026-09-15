# Filters, Name Resolution & Smart Suggestions

This document covers the interactive analysis workflow: click-to-filter, endpoint name
resolution, and the autocomplete filter bar.

All display filters are evaluated by the real `tshark -Y` engine, so the full Wireshark
display-filter language is available. Applying a normal display filter refreshes the
packet list and the packet/stream/object workflow reached from it. Summary,
Conversations, Endpoints, Protocols, Issues, DNS, TLS, HTTP, Statistics, Timeline, and
Search explicitly describe the **whole capture** and retain their cached totals.

---

## Protocol click-to-filter

Any protocol shown in the UI is tappable and applies the matching display filter.

- **Where:** the coloured protocol badge in each packet row; protocol names in the
  Protocol Hierarchy; the long-press packet sheet.
- **Mapping:** display names are normalised to filter tokens
  (`FilterBuilders.protocolToFilter`):

  | Shown | Filter |
  |---|---|
  | `DNS` | `dns` |
  | `HTTP` | `http` |
  | `HTTP/2` | `http2` |
  | `TLSv1.2`, `TLS`, `SSL` | `tls` |
  | `ICMPv6` | `icmpv6` |
  | `MDNS` | `mdns` |
  | `TCP` / `UDP` / `ARP` / … | `tcp` / `udp` / `arp` / … |

## Endpoint click-to-filter

Tap any endpoint (a source/destination address in a packet row, or a row in the
Endpoints view) to open an action sheet:

| Action | Filter (IP) | Filter (MAC) |
|---|---|---|
| Show all traffic | `ip.addr == A` | `eth.addr == A` |
| Show source traffic | `ip.src == A` | `eth.src == A` |
| Show destination traffic | `ip.dst == A` | `eth.dst == A` |
| Show conversation with *peer* | `ip.addr == A && ip.addr == B` | `eth.addr == A && eth.addr == B` |
| Show sessions | `ip.addr == A && (tcp \|\| udp)` | — |

The field (`ip.*` vs `eth.*`) is chosen automatically from the address kind
(`FilterBuilders.endpointFilter` + `AddressUtil`).

The same sheet offers **Set / Edit / Remove alias** for the endpoint.

## Name resolution

Endpoints can be displayed with meaningful names. Sources are consulted in priority
order (`NameResolver`):

1. **User alias** (Room) — always wins.
2. **Local device discovery** —
   - **mDNS / DNS-SD** — `NsdManager` browses common service types (`_workstation`,
     `_http`, `_googlecast`, `_airplay`, `_ipp`, `_printer`, `_smb`, `_ssh`) and caches
     discovered hosts by IP.
   - **NetBIOS (NBSTAT)** — a node-status query to UDP/137 yields the SMB/Windows
     machine name (like `nbtstat -A`).
   - **LLMNR (reverse PTR)** — a reverse query to the link-local multicast group
     (`224.0.0.252:5355`) yields the responder's host name. A Wi-Fi multicast lock is
     held for the reply.
3. **Reverse DNS (PTR)** — `InetAddress.canonicalHostName`, e.g. `8.8.8.8 → dns.google`.
4. **OUI vendor** (MAC only) — the **full IEEE registry** bundled as `assets/manuf.bin`
   (Wireshark's `manuf`, ~57k entries) covering **MA-L (24-bit), MA-M (28-bit) and
   MA-S/IAB (36-bit)** blocks; the most-specific block wins, e.g.
   `00:1B:C5:00:0x → Converging Systems Inc.` over the parent /24.

Reverse DNS, mDNS, NetBIOS and LLMNR run off the main thread and populate caches; the
UI reads the cached result and recomposes when a background pass completes (a resolve
"tick"). The OUI table is parsed once off-thread at startup (`prewarm`).

> NetBIOS and LLMNR are **active** link-local queries, so they only fire for private
> IPv4 addresses (RFC 1918 / 169.254) and only when **Settings → Resolve hostnames** is
> enabled (off by default; keeps the tool passive unless you opt in). Each address is
> queried at most once, with short (400 ms) timeouts. Refresh the OUI data with
> `scripts/build-oui.sh`.

## Endpoint location

Tap a remote endpoint → **Look up location & WHOIS** to open the endpoint
location screen (`EndpointLocationScreen`). It shows three sections (`LocationLookup`):

- **Location (GeoIP)** — country, region, city, postal, coordinates, timezone and flag,
  from the imported offline GeoIP CSV when available, otherwise from `ipwho.is`.
- **Network** — ASN, organisation and ISP (also from the GeoIP source).
- **Registration (WHOIS / RDAP)** — network name, CIDR/range, registrant, country, the
  responsible registry (ARIN/RIPE/APNIC/LACNIC/AFRINIC) and the abuse contact, from
  `rdap.org` (RDAP — the structured JSON successor to port-43 WHOIS).

> **Offline first, online & opt-in:** this is a deliberate, per-tap action. If a custom
> GeoIP database is imported in Settings, GeoIP is resolved locally and only RDAP is sent
> to `rdap.org`; otherwise the endpoint's IP is sent to `ipwho.is` and `rdap.org` over
> HTTPS. Private/link-local addresses are reported as local with no network call (RFC
> 1918 / 169.254 / `fe80::`/ULA). Results are cached for the session.

### Custom GeoIP databases

Settings → Name resolution → **Offline GeoIP database** imports a CSV file into app
storage. The parser accepts either `cidr`/`network`/`ip_prefix` or `start_ip` +
`end_ip`, plus optional `country`, `country_code`, `region`, `city`, `postal`,
`latitude`, `longitude`, `timezone`, `asn`, `org` and `isp` columns. Overlapping
networks use the most-specific prefix.

### Display modes

**Settings → Name resolution → Endpoint display** (`ResolveDisplayMode`):

- **Address** — `192.168.1.15`
- **Name + addr** — `Geoff-MacBook` over `192.168.1.15`
- **Name** — `Geoff-MacBook`

## Aliases

User aliases map an address to a name and are stored in Room (`endpoint_aliases`):

- Persist across launches, editable and removable.
- Manage in **Settings → Endpoint aliases** (add via `+`, edit by tap, remove by trash),
  or inline from any endpoint action sheet.
- Addresses are normalised (trimmed, lower-cased) so `AA:BB:…` and `aa:bb:…` resolve to
  the same alias.

## Smart suggestions

The filter bar offers Wireshark-style autocomplete (`FilterSuggestionEngine`). It
completes the **trailing token** of the query, so suggestions work mid-expression
(`ip.addr == 192.` completes the value).

Suggestion sources:

- **Protocols & fields** — a curated, Wireshark-compatible catalog (`FilterFields`),
  available even when the protocol isn't in the current capture. Typing `d` →
  `dns`, `dhcp`, `dns.qry.name`…; `ip.` → `ip.src`, `ip.dst`, `ip.addr`…; `http` →
  `http`, `http.host`, `http.request.method`…
- **Endpoints** — addresses seen in the capture. `192.` → `192.168.1.1`, `192.168.1.15`
  (applies `ip.addr == …`, or completes the value if a field/operator precedes it).
- **Hostnames & aliases** — `goo` → `dns.google`; `home` → `Home Router` (each applies an
  `ip.addr == <resolved address>` filter).
- **Streams** — `tcp` → `tcp.stream eq 5`; `udp` → `udp.stream eq 2`, from the stream
  indices present in the capture.

Suggestions are computed off the UI thread and never block packet rendering.

When a capture opens, the Summary also offers 3–8 evidence-backed contextual actions,
such as retransmissions, DNS failures, HTTP errors, TLS handshakes, the largest
conversation, the top endpoint, resets, malformed traffic, or QUIC. Suggestions appear
only when the associated traffic/evidence exists and apply a valid Wireshark filter.

## Recent & saved

- **Recent filters** — every applied filter is recorded (`recent_filters`, capped at 20,
  newest first) and persists across launches. Available from the filter bar history menu
  and as suggestions when the bar is empty.
- **Saved filters** — name and keep a filter (`saved_filters`). Save via the bookmark
  icon; apply or delete from the history menu.

## Database schema

Room database `pocketpcap.db` (`PocketPcapDatabase`):

| Table | Columns | Added |
|---|---|---|
| `endpoint_aliases` | `address` (PK), `name`, `updatedAt` | v1 |
| `recent_filters` | `filter` (PK), `usedAt` | v1 |
| `saved_filters` | `id` (PK auto), `name`, `filter`, `createdAt` | v2 |
| `analysis_bookmarks` | `id`, capture path, type, stable reference, label, note, evidence filter, packet, timestamp | v3 |

Migrations are additive and non-destructive (`MIGRATION_1_2` creates `saved_filters`;
`MIGRATION_2_3` creates `analysis_bookmarks`).
See [DEVELOPER](DEVELOPER.md#migrations) for the migration/testing process.
