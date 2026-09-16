# PocketPCAP — User Guide

Every screen, every control, and what each one actually does. This is the on-device
Help content in long form; the app carries the same material under
**Settings → Help & Wiki**.

PocketPCAP is **passive and diagnostic**. It reads traffic and explains it. There is no
injection, no spoofing, no deauthentication, no attack tooling of any kind, and there
will not be.

---

## Contents

- [What needs root and what does not](#what-needs-root-and-what-does-not)
- [Where your files go](#where-your-files-go)
- [Sources — capability check](#sources--capability-check)
- [Capture](#capture)
- [Files — capture library](#files--capture-library)
- [Analysis workspace](#analysis-workspace)
- [Packets](#packets)
- [Packet detail](#packet-detail)
- [Follow Stream](#follow-stream)
- [Objects](#objects)
- [Filtering](#filtering)
- [Search, bookmarks and notes](#search-bookmarks-and-notes)
- [Traffic map and GeoIP](#traffic-map-and-geoip)
- [Endpoint names and aliases](#endpoint-names-and-aliases)
- [Decryption](#decryption)
- [Exporting](#exporting)
- [Settings reference](#settings-reference)
- [Troubleshooting](#troubleshooting)
- [Privacy](#privacy)

---

## What needs root and what does not

This is the single most misunderstood thing about the app, so it is first.

| Task | Root? |
|---|---|
| Open a PCAP/PCAPNG from anywhere on the device | **No** |
| Decode, dissect, analyse, follow streams, search | **No** |
| Rootless capture of device traffic (VpnService) | **No** |
| Export anything — PCAPNG, CSV, JSON, KML, GeoJSON | **No** |
| Merge, sanitise, annotate captures | **No** |
| Decrypt TLS or 802.11 | **No** |
| **Live capture from a named interface (`wlan0`, `rmnet0`, …)** | **Yes** |
| Bluetooth HCI snoop collection, RIL/modem logs | **Yes** |

tshark, dumpcap, editcap and mergecap ship as native libraries, so the installer puts
them in the one directory an app is allowed to execute from. That is why decoding needs
nothing special. Only `dumpcap` opening a live interface needs root, because that needs
`CAP_NET_RAW`.

On a device without root the app says so plainly and keeps every other feature working.

## Where your files go

Captures **and** exports are written to **`Documents/pocketpcap`** by default — reachable
from the Files app, from a file manager, and over USB, with no storage permission at all.

An app cannot simply create a directory in shared storage, so PocketPCAP registers each
file with MediaStore first; that is what makes the folder writable and what lets dumpcap
and tshark use an ordinary file path. Consequences worth knowing:

- **Files another app wrote into that folder are not yours to list.** They will not appear
  in the Files screen. Use **Open** (the `+`) and pick them — that works on anything.
- **Uninstalling drops ownership** of what is left behind. Copy captures off the device
  before uninstalling.
- **Captures made before the default moved** still live in app storage under
  `files/captures/`, and the Files screen lists both places. Nothing was moved or lost.
- **Android 10** cannot write shared storage by path at all, so there the default is app
  storage and Settings shows that path.

**Settings → Storage → Choose folder** points output somewhere else. Android only permits
folders under the standard media directories (`Documents`, `Download`, `DCIM`, …) and the
app's own storage; pick anywhere else and the app tells you rather than silently writing
elsewhere.

## Sources — capability check

The first tab. **Refresh** (↻) probes the device and reports what is available.

- **Root banner** — one of *Root available* (Magisk detected), *No root on this device*
  (with a reminder that only live interface capture needs it), or *Root not checked*.
- **Standard** — rootless VPN capture, visible network interfaces, and the bundled
  tshark/Wireshark version.
- **Root** — root access, Wi-Fi capture, cellular interface capture, RIL/modem logs,
  Bluetooth HCI snoop log, and the dumpcap capture backend.

Each row is green (available), amber (conditional — the text says what is missing) or red
(unavailable here). Network interfaces are listed with type, state and address.

The root probe is only run when you ask for it or when something needs root, and a failed
probe is cached so an unrooted device does not re-search on every operation.

## Capture

### Capture mode

- **Root** — bundled `dumpcap` on the interfaces you select. Tap multiple interfaces to
  capture them simultaneously.
- **Rootless VPN** — Android's `VpnService` creates a local TUN, traffic is forwarded
  through an in-process relay and recorded. Device-wide apart from PocketPCAP's own
  traffic, which is excluded so the relay cannot capture itself. Android shows a
  connection-request dialog the first time; capture only starts if you accept.

### Capture filter

Wireshark-compatible syntax, applied while recording, so it limits what is written. Leave
it empty to capture everything. Rootless VPN capture enforces common protocol, host and
port filters locally; full display filters are always available afterwards regardless.

### While running

Live duration, packet count and bytes written, with the output path. **Pause** suspends
the capture and keeps the file and the tunnel open; **Resume** continues into the same
file; **Stop** closes it cleanly.

### Autostop ceilings

**Settings → Storage**: *Stop at size* (default 512 MB) and *Stop after* (default off).
`dumpcap` enforces both itself and closes the PCAPNG cleanly when either is reached, so a
capture left running overnight cannot fill the device.

## Files — capture library

Every capture PocketPCAP can see, newest first, with size, packet count and timestamp.

- **`+`** — open a PCAP/PCAPNG/CAP from anywhere via the system picker. The file is
  detected by magic bytes, not by extension.
- **↻** — rescan.
- **Share** — hand the file to the system share sheet.
- **Delete** — remove the file and its MediaStore entry.
- **Tap** — open it in the analysis workspace.

Select two or more and **Merge** combines them into one timestamp-ordered capture.

## Analysis workspace

Opening a capture runs a single cached tshark pass and builds the whole model from it, so
moving between the pages below costs nothing.

Six pages are on the tab row: **Summary, Conversations, Endpoints, Protocols, Issues,
Objects**. The top bar reaches seven more: **Search** (🔍), **Statistics** and **Timeline**
(📈), and **Bookmarks** (🔖). **DNS**, **TLS** and **HTTP** pages are reached by pivoting
from Summary or Search.

### Summary

Read this first. Capture size, packet count, duration, link layer, first and last
timestamps; IPv4/IPv6 endpoint counts, MAC address count, TCP and UDP conversation counts;
and the dominant protocols with packets, bytes and share. Every row is a pivot into the
packets behind it.

### Conversations

Every TCP, UDP, IPv4 and IPv6 conversation: endpoints and ports, packets, bytes, bytes
each way, start time, duration, stream index and retransmission count. Sort by bytes,
packets, duration, start, sent or received. Tap to filter; long-press for stream actions.

### Endpoints

Every endpoint — IPv4, IPv6 and MAC — with bytes in and out, packet count, and TCP and DNS
counts. Bookmark any of them. How addresses are displayed is set in
**Settings → Name resolution**.

### Protocols

The protocol hierarchy, as `tshark -z io,phs` computes it: nested protocol layers with
packets, bytes and percentage of the capture. Tap any layer to filter to it.

### Issues

Deterministic findings, each with the evidence attached: TCP resets, retransmissions,
duplicate ACKs, zero windows, unanswered DNS, and more. Every finding names its severity,
protocol, the endpoints involved, the conversation where relevant, the first occurrence
time and the exact packet numbers. They are **indications, not verdicts** — the packet
numbers are there so you can check.

### Objects

Files carried in the capture, extracted by tshark: **HTTP, TFTP, SMB, Email (IMF)** and
**DICOM**. Extracted objects go to app storage in a timestamped per-protocol folder and can
be shared individually.

### DNS, TLS, HTTP

Protocol-specific tables — queries and responses, handshakes and versions, requests and
responses — each exportable as CSV or JSON.

### Statistics and Timeline

**Timeline** plots packets/s or bytes/s per time bucket across the capture. Red markers sit
on buckets containing retransmissions or resets. The range control below the chart selects
a window precisely, and **Filter capture to this time range** applies it as a display
filter.

## Packets

The packet list, with number, protocol, relative or absolute time, length, source and
destination and the dissector's summary line.

- **Display filter** field with autocomplete, history (🕘) and saved filters.
- **Tap** a row for packet detail; **long-press** for stream and filter actions.
- **Follow / Refresh / Close** appear when viewing an opened file: *Follow* polls the file
  and reloads whenever it grows, so you can watch a capture another tool is still writing.
- **Overflow (⋮)** — protocol hierarchy and endpoints, export filtered, export objects,
  share headers-only, share with packet notes, and per-table CSV/JSON export.

Very large captures are bounded and the view says so rather than pretending otherwise.

## Packet detail

- **Decode** — the full Wireshark dissection tree, expandable layer by layer, with field
  values shown alongside. Tap or long-press a field to build a filter from it.
- **Raw** — the hex dump, laid out so rows wrap and the ASCII column stays aligned at phone
  width. Selecting a field in Decode highlights its bytes here.

## Follow Stream

Reassembles a conversation.

- **Direction** — Both, Client → Server, or Server → Client.
- **Display** — Text, ASCII, Hex, Raw, HTTP or JSON.

Reachable from a packet long-press, and from conversation, TLS and HTTP actions.

## Filtering

Wireshark display-filter syntax throughout.

- **Autocomplete** suggests fields, values and stream indices from the capture in hand.
- **Recent filters** are kept (most recent 20) and **saved filters** persist by name.
- **Click-to-filter** from any packet field, endpoint, protocol row or conversation.
- **Validation** — an invalid filter is reported before it is applied.

Capture filters limit what is recorded and cannot be changed afterwards. Display filters
only limit what you are looking at and can be changed freely.

## Search, bookmarks and notes

**Search** (🔍) runs across the whole capture and groups results by kind: packets,
endpoints, conversations, DNS, HTTP, TLS, issues, streams and fields. Each result pivots
to its source.

**Bookmarks** (🔖) can be placed on packets, endpoints, conversations, streams, issues,
DNS, HTTP and TLS entries. Each bookmark takes a free-text note. Notes attached to packets
can be written into an exported PCAPNG as real pcapng comments, which Wireshark on the
desktop will display.

## Traffic map and GeoIP

With a GeoIP database imported, external endpoints are placed on a map with routes drawn
from the local endpoint. Export as **KML** or **GeoJSON**.

Import an offline GeoIP CSV in **Settings → GeoIP** with columns `cidr` or
`start_ip`/`end_ip`, plus `country`, `country_code`, `region`, `city`, `latitude`,
`longitude`, `asn`, `org`, `isp`.

> **The Traffic Map is off by default.** It is the only feature that discloses anything
> derived from your capture, so it asks before the first lookup and stays off until you
> allow it, either in that prompt or under **Settings → Online endpoint lookups**. With
> it off, only an imported offline GeoIP database is used and nothing leaves the device.
> Once allowed, opening it sends your public IP to `api.ipify.org`,
> and for up to 40 endpoints it queries `ipwho.is` for geolocation (when your offline
> database has no entry) and `rdap.org` for organisation detail (when geolocation did not
> supply it). Only globally routable unicast addresses are sent — private, loopback,
> link-local, CGNAT, multicast, broadcast and documentation ranges are all excluded, so
> the mDNS and SSDP chatter in a LAN capture never leaves the device. Those services learn
> which public addresses appear in your capture; they never receive the capture itself. If
> you do not want that, do not open the Traffic Map: every other analysis feature is
> entirely offline. See [PRIVACY.md](PRIVACY.md).

## Endpoint names and aliases

**Settings → Name resolution → Endpoint display**: **Address**, **Name + addr**, or
**Name**. Names resolve in priority order:

1. Your own aliases
2. Local discovery — mDNS, NetBIOS, LLMNR
3. Reverse DNS
4. MAC vendor, from the full offline IEEE OUI database including MA-M and MA-S blocks

**Endpoint aliases** manages your own names (`192.168.1.1 → Home Router`). Aliases persist,
appear as filter suggestions, and can be added from any endpoint action sheet.

Reverse DNS is **off by default** — turning it on makes the device send DNS queries.

## Decryption

**Settings → Decryption.**

- **TLS key log** — import an `SSLKEYLOGFILE` to decrypt TLS/HTTPS. Toggle on or off,
  replace, or clear.
- **802.11 keys** — for captures containing raw 802.11 frames. Three key types: **WPA
  passphrase** (`passphrase:SSID`), **WPA PSK** (raw hex), and **WEP**. WPA/WPA2 also needs
  the EAPOL handshake for that session present in the capture.

A stock phone's Wi-Fi driver does not produce raw 802.11 captures; these keys are for
captures brought in from a monitor-mode capable adapter or another tool.

## Exporting

Everything lands in the capture directory (`Documents/pocketpcap` by default).

| Export | Produces |
|---|---|
| Export filtered → file | New PCAPNG of just the packets matching the display filter |
| Merge captures | One timestamp-ordered PCAPNG from two or more captures |
| Share headers only | PCAPNG with payloads truncated — safe to hand over |
| Share with my packet notes | PCAPNG with your notes written in as pcapng comments |
| Export table (per table) | CSV or JSON of Conversations, Endpoints, Protocols, Issues, DNS, TLS or HTTP |
| Traffic map | KML or GeoJSON |
| Export objects | Extracted HTTP/TFTP/SMB/Email/DICOM files |

CSV exports are guarded against spreadsheet formula injection. Exports are always
user-initiated.

## Settings reference

- **Capture** — Resolve hostnames · Relative timestamps · Auto-scroll to latest ·
  Preserve raw logs · Stop at size · Stop after.
- **Name resolution** — Endpoint display · Endpoint aliases.
- **GeoIP** — import or clear an offline GeoIP CSV.
- **Online endpoint lookups** — off by default. Lets the traffic map and endpoint
  location resolve addresses through `ipwho.is`, `rdap.org` and `api.ipify.org`.
- **Storage** — Capture directory (with Choose folder / Reset) · Max capture file size.
- **Help & Wiki** — the on-device version of this guide.
- **Decryption** — TLS key log · 802.11 decryption keys.
- **About** — version, copyright, Licences (GPL-3.0-or-later and third-party notices),
  GitHub, website, and a user-triggered **Check for Updates** that compares the installed
  version with the latest GitHub release. It never downloads or installs anything.

## Troubleshooting

**"No root on this device" but the device is rooted.**
Open your superuser manager and confirm PocketPCAP is allowed. The app's uid changes when
you reinstall a debug build, so a previously granted policy may not apply to the new one.
Then tap Refresh on Sources.

**No interfaces listed in Root capture mode.**
Interfaces come from the root probe. Run Refresh on Sources first.

**A capture appears as 0 bytes in the Files app.**
It is still being written. MediaStore learns the real size when the capture stops.

**A capture made by another app does not appear in Files.**
Ownership is per-app in shared storage. Use **Open** (`+`) and pick it.

**"Android will not let PocketPCAP write to that folder."**
The folder you chose is outside the standard media directories. Pick one under Documents
or Download, or Reset to the default.

**Decryption produced nothing.**
For TLS, the key log must cover the sessions in the capture. For WPA/WPA2, the EAPOL
handshake for that session must be present in the capture — a key alone is not enough.

**The packet list says it is truncated.**
Very large captures are bounded for responsiveness. Narrow it with a display filter.

## Privacy

- No account, no sign-in, no telemetry, no analytics, no ads.
- Three features reach the internet, each only when you invoke it: the **Traffic Map** and
  endpoint location (third-party GeoIP/RDAP lookups of addresses from your capture),
  **Check for Updates**, and **reverse DNS** if you switch it on. Everything else —
  capture, decode, analysis, search, export — is fully offline. Full detail in
  [PRIVACY.md](PRIVACY.md).
- Name resolution is local by default; reverse DNS is off unless you enable it.
- MAC vendor lookup uses a bundled offline OUI database.
- Captures never leave the device unless you export and share them deliberately.
- Captures contain real traffic. Treat a shared capture as sensitive — prefer **Share
  headers only** when the payloads are not the point.
