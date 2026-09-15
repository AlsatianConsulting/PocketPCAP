# Architecture

PocketPCAP is a single-module Android app (Jetpack Compose, manual DI) that drives a
bundled `tshark`/`dumpcap` over `su` for rooted capture and decode, and also offers a
rootless local capture path through Android `VpnService`.

## High level

```
MainActivity → MainViewModel (AndroidViewModel)
                 ├─ SourceManager       root check + interface discovery (root `ip`)
                 ├─ CaptureService       foreground service
                 │    ├─ CaptureManager  su + dumpcap/tshark → pcapng, live packet flow
                 ├─ VpnCaptureService    Android TUN VPN → tun2socks relay → raw-IP pcapng
                 │    └─ DecodeManager    tshark decode: analysis / PDML / hex / streams
                 ├─ CaptureAnalysisParser one fields pass → entities + findings
                 ├─ PcapRepository       Room: aliases, filters + analysis bookmarks
                 ├─ SharedCaptureStore   MediaStore-backed Documents/pocketpcap output
                 ├─ UpdateChecker        explicit GitHub latest-release comparison
                 ├─ NameResolver         alias / mDNS / rDNS / OUI resolution       (new)
                 └─ FilterSuggestionEngine  autocomplete                            (new)
UI: Compose NavHost — Sources / Capture / Packets / Files / Settings (+ Summary-first
    Analysis workspace, Objects, FollowStream, Help, Aliases)
```

## tshark engine

- Termux aarch64 build (`tshark 4.6.8`). The **executables and their shared-object
  closure ship as `jniLibs`**, renamed `lib*.so` because that is the only pattern the
  installer extracts (`scripts/jnilib-name.py`), and land in the app's native library
  directory — the one place an app is allowed to exec from. Android refuses to execute
  anything an app writes into its own storage, so this split is what makes **decode work
  with no root at all**: `tshark`, `editcap` and `mergecap` run as the app uid.
- Wireshark's data files under `share/wireshark` are read, never executed, so they stay
  in `assets/tshark-prefix.zip` and are unpacked to `filesDir/tshark` on first use.
  `TsharkBundle.WIRESHARK_VERSION` is the single source of truth for the version, and
  the data stamp tracks it so a version bump forces re-extraction.
- Only live capture from an interface needs root, because `dumpcap` needs `CAP_NET_RAW`;
  that path goes through `RootShell`, everything that only reads a capture goes through
  `Exec`. The rootless VPN path needs no root at all.
- `RootShell.suPath()` resolves `su` to an absolute path by *executing* candidates
  (SELinux denies `stat` on `su` for `untrusted_app` on this device), and caches a
  failed probe so an unrooted device does not re-search on every operation.

`DecodeManager` operations: `captureAnalysis` (one cached `-T fields` pass),
`packetList` (`-T fields`), `decodeTree` (`-T pdml`,
byte offsets for hex highlight), `rawBytes` (`-x`), `protocolHierarchy` (`-z io,phs`),
`endpoints` (`-z endpoints,<type>`), `followStream` (`-z follow,…`),
`streamIndices` (distinct `tcp.stream`/`udp.stream` for autocomplete),
`packetFieldValues`, bounded payload search, `exportFiltered`, `exportObjects`, and
`validateFilter`.

## Mobile analysis layer

`analysis/` converts the single tshark fields export into an immutable
`CaptureAnalysis`. It retains packet/frame evidence while correlating TCP/UDP/IPv4/IPv6
conversations, DNS transactions, HTTP request/response pairs, TLS sessions, endpoints,
protocol totals, a timeline, contextual filters, and deterministic issues. The Summary,
Conversations, Endpoints, Protocols, Issues, DNS, TLS, HTTP, Statistics, Timeline, Search,
and Bookmarks views all consume this model. See [ANALYSIS.md](ANALYSIS.md) for the exact
fields, correlation rules, evidence thresholds, filters, cache key, and fixtures.

The analysis cache is keyed by capture path, size, modification time, decryption
arguments, and optional explicit analysis filter. Normal packet-list display filters do
not change the whole-capture analysis. Opening a capture uses the same cached result for
the Summary and unfiltered packet list instead of launching multiple full-file scans.
Cache entries are invalidated by capture or decryption-input changes. All execution and
parsing stays off the Compose thread.

`update/UpdateChecker.kt` is isolated from capture analysis. Only an explicit tap in
the About card performs `GET https://api.github.com/repos/AlsatianConsulting/PocketPCAP/releases/latest`.
It compares the returned tag with `BuildConfig.VERSION_NAME`, exposes deterministic
UI states, and never downloads or installs an artifact.

## Rootless VPN capture

`VpnCaptureService` uses Android's `VpnService.Builder` to create a local TUN
interface and route selected app traffic into PocketPCAP without root. The user must
approve Android's VPN permission prompt. The Capture screen defaults to device-wide;
selecting packages calls `addAllowedApplication(...)` for each, and the **Exclude**
switch instead calls `addDisallowedApplication(...)` — Android forbids mixing the two
on one builder, so the scopes are configured on strictly separate paths. PocketPCAP's
own package is always kept out of the tunnel, or the relay would forward its own
forwarded traffic back through the TUN. System apps are included in the picker via
`QUERY_ALL_PACKAGES`.

Pause suspends recording without tearing the tunnel down: traffic keeps flowing for
the apps in scope and only the writer stops, so the pcapng shows a genuine gap. TCP
sequence numbers still advance, so a resumed capture stays consistent with the real
byte stream and Wireshark reports the gap honestly.

The VPN backend runs `tun2socks` against the TUN file descriptor and forwards TCP/UDP
through a local direct SOCKS5 relay. The relay protects its outbound sockets with
`VpnService.protect(...)`, so forwarded traffic leaves through the device's normal
network instead of looping back into the VPN. PocketPCAP records the relayed payloads to
canonical pcapng with `LINKTYPE_RAW`; saved files still decode through
`DecodeManager`/tshark.

Because tun2socks owns the raw TUN stream, rootless pcapng packets are reconstructed
from relay metadata. They preserve real remote endpoints and payload bytes, but use a
synthetic local client address/port (`10.215.0.2` or `fd00:215::2`) for the app side.
Capture filters are enforced locally for common protocol, host, and port expressions,
while full Wireshark display filters remain available after capture.

## Data layer

`data/` — Room.

- `PocketPcapDatabase` (`pocketpcap.db`), version **3**, `exportSchema = true`
  (schemas in `app/schemas/`).
- Entities: `EndpointAliasEntity`, `RecentFilterEntity`, `SavedFilterEntity`, and
  `AnalysisBookmarkEntity`.
- DAOs expose Flows (observed by the ViewModel via `stateIn`) and suspend accessors.
- `PcapRepository` centralises address normalisation, the recent-filter cap (20) and
  the alias/recent/saved APIs.
- Built with KSP (`com.google.devtools.ksp`).

## Shared storage

`storage/SharedCaptureStore` — where captures and exports land.

The default output directory is `Documents/pocketpcap`, so the operator finds their
work in the Files app or over USB rather than under `Android/data`. An app cannot
`mkdir` there: under scoped storage the app uid gets `EACCES` for both the directory
and the write, and the only alternatives are `MANAGE_EXTERNAL_STORAGE` (a Play
restricted permission this app has no case for) and MediaStore, which needs no
permission at all.

So a file is registered with MediaStore *first*. The insert creates the directory and
an empty file and makes the app its owner, and ownership is what buys back ordinary
`File` reads and writes on the real path — which is the point, because `dumpcap` takes
the output path as an argv and cannot write to a `content://` URI, and `tshark`,
`editcap` and `mergecap` all read the same way.

- `available` gates the whole scheme on API 30+. Ownership buying back plain `File`
  access is an Android 11 rule; Android 10 — this app's `minSdk` — blocks direct
  file-path access to shared storage outright, so there the row and its empty file
  would look like success right up until dumpcap got `EACCES`. On API 29 the default
  output directory is app-private storage instead, and Settings shows that path.
- `targetFor(path)` decides per directory whether MediaStore can address it: a standard
  media folder (`Documents`, `Download`, `DCIM`, …) on emulated storage for any user, or
  on a removable volume named by its UUID. App-private storage and an invented top-level
  folder are not addressable and take the ordinary `mkdir` path. Pure string arithmetic,
  so it is unit-tested off-device (`SharedCaptureStoreTargetTest`); the MediaStore half
  is covered by the instrumented `SharedCaptureStoreTest`.
- `newFile` returns a real path or null, and every caller falls back to app-private
  storage rather than failing to capture or losing an export. Before returning a path it
  opens it for append: the version gate is a claim about the platform, not about this
  device and this volume, and a path that cannot actually be written has to be
  discovered now rather than by a capture that runs and produces nothing.
- That probe retries, which is not padding. Recreating a name that had just been deleted
  was measured failing with `EACCES` on a file that existed and that MediaStore already
  reported us as `owner_package_name` of — the FUSE layer caches its per-uid access
  decision per path, and the decision for the deleted file outlives it by a moment. On
  an API 36 emulator the raw probe failed 4 times in 100 delete-then-recreate cycles;
  with four tries 40 ms apart, 240 cycles through `newFile` failed none. One transient
  denial must not divert a capture to the fallback directory for good.
- `canWrite` backs the Settings warning, so picking a folder Android will refuse is
  reported at pick time instead of silently redirecting the next capture.
- `listFiles` goes through MediaStore for shared directories: an app has no read access
  to a shared directory *as a directory*, only to the files in it that it owns, so
  `File.listFiles()` there returns nothing however many captures are sitting in it.
  `CaptureManager.refreshCaptureFiles` scans the app-private directory *and* the chosen
  output directory, which is also the migration story: captures written before the
  default moved stay under `files/captures/` and keep appearing in the Files list, with
  nothing moved behind the operator's back.
- `refresh` re-scans after a direct write. dumpcap, the tunnel recorder and the export
  writers all write behind MediaStore's back, so without it the Files app shows 0 bytes.
- `forget` drops the row on delete; leaving it behind makes MediaStore hand the next
  capture of that name a `(1)` suffix.

Ownership is the limit of all this: files another app wrote into the same folder stay
unreadable without the picker (which is what **Open** is for), and an uninstall drops
ownership of whatever is left behind.

## Name resolution (new)

`resolve/` —

- `NameResolution.kt` (pure, unit-tested): `AddressUtil` (MAC/IP classification,
  private-IPv4 test, field selection), `OuiTable`/`OuiData` (mask-aware parse + lookup
  for MA-L/MA-M/MA-S), `NameFormat` (display-mode formatting), `ResolvedName` /
  `EndpointLabel` / enums.
- `LocalNameQuery.kt` (pure codecs, unit-tested): NetBIOS NBSTAT and LLMNR reverse-PTR
  packet build/parse, plus timeout-bounded UDP helpers.
- `GeoIpDatabase.kt` / `GeoIpManager.kt`: imported custom offline GeoIP CSV, copied into
  app storage and matched by CIDR/range before any online GeoIP request.
- `LocationLookup.kt` / `EndpointLocation.kt`: on-demand online GeoIP fallback
  (ipwho.is) + WHOIS/RDAP (rdap.org) over HTTPS for remote endpoints; pure JSON parsers
  (`parseGeo`/`parseRdap`/`merge`, unit-tested) + `suspend lookup()`. Private addresses
  short-circuit with no network call.
- `NameResolver` (Android): combines aliases, `NsdManager` mDNS discovery, NetBIOS +
  LLMNR (private IPv4 only, multicast-locked LLMNR), reverse DNS and the bundled OUI
  table (`assets/manuf.bin`, the full IEEE registry, parsed off-thread via `prewarm`);
  maintains caches; exposes synchronous `cached(addr)` for rendering and suspend
  `resolve(addr)` for background population. A `resolveTick` StateFlow tells the UI when
  caches changed.

## Filtering (new)

`filter/` (pure, unit-tested) —

- `FilterFields` — curated Wireshark-compatible protocol/field catalog.
- `FilterSuggestionEngine` — trailing-token autocomplete over the catalog plus dynamic
  endpoints/hostnames/streams, and recent/saved when empty. `SuggestionContext` carries
  the dynamic inputs the ViewModel assembles.
- `FilterBuilders` — `protocolToFilter` and `endpointFilter` for click-to-filter.

## UI composition

- `ui/components/FilterComponents.kt` — `FilterBar` (search icon, live autocomplete
  dropdown, clear, save, recent/saved history menu) and `EndpointActionSheet` +
  `AliasDialog`.
- `ui/components/PcapComponents.kt` — `PacketRow` with tappable protocol badge and
  source/destination labels.
- `ui/screens/` — `AnalysisWorkspaceScreen` (Summary, Conversations, Endpoints,
  Protocols, Issues, Objects, and contextual analysis pages), `PacketListScreen`,
  `PacketDetailScreen`, `FollowStreamScreen`, `SettingsScreen`, and `AliasScreen`.

## Threading

- tshark/decode and DB writes run on `Dispatchers.IO`; suggestion computation on
  `Dispatchers.Default`. Suggestions and resolution never block packet rendering.
- Live capture packets flow from `CaptureManager.packets` into the list unless a saved
  file is open or a display filter is active.
