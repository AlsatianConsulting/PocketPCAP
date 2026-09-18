# Developer Guide

## Project layout

```
app/src/main/java/dev/alsatianconsulting/pocketpcap/
  MainActivity.kt, MainViewModel.kt
  capture/      CaptureManager, Vpn pcapng writer/parser helpers
  decode/       DecodeManager, TsharkBundle, Exec, RootShell, Prefs, Decryption…
  analysis/     CaptureAnalysisParser, immutable models, grouped search
  data/         Room: aliases, filters, analysis bookmarks, migrations
  resolve/      NameResolution (pure), NameResolver                        (new)
  filter/       FilterFields, FilterSuggestionEngine, FilterBuilders       (new)
  update/       explicit GitHub release lookup + version comparison
  model/        immutable UI models
  service/      CaptureService, VpnCaptureService
  source/       SourceManager
  ui/           navigation, components, screens, theme
app/src/main/jniLibs/arm64-v8a/  tshark, dumpcap + libraries (git-ignored)
app/src/main/assets/   tshark-prefix.zip — Wireshark data files, manuf.bin
app/schemas/           exported Room schemas (1.json, 2.json, 3.json)
app/src/test/          JVM unit tests                                      (new)
app/src/androidTest/   instrumented tests                                 (new)
```

## Building & running

```bash
./gradlew :app:assembleDebug
adb -s <id> install -r --no-streaming \
  app/build/outputs/apk/debug/PocketPCAP-debug-0.1.0-debug-*.apk
```

Confirm the device first — IDs drift between sessions:

```bash
adb devices -l
adb -s <id> shell getprop ro.product.device   # panther = Pixel 7
```

**Magisk:** the debug package `…pocketpcap.debug` needs its **own** Superuser grant
(Magisk → Superuser → toggle the `.debug` row ON); the release grant doesn't carry over.

**Duplicate-file gotcha:** a cloud-synced tree can create `"<name> 2.<ext>"` copies under
`app/build`, breaking resource/dex merge. Fix:

```bash
find app/build -name "* [0-9].*" -delete
```

## Tests

```bash
./gradlew :app:testDebugUnitTest          # pure logic
./gradlew :app:connectedDebugAndroidTest  # Room migration/persistence + Compose UI (device)
```

- **Unit** (`src/test`): `FilterSuggestionEngineTest`, `FilterBuildersTest`,
  `NameResolutionTest` (suggestions, click-to-filter mapping, OUI parsing, address
  classification, display-mode formatting).
- **Analysis** (`src/test/.../analysis`): `CaptureAnalysisParserTest` consumes the
  checked-in tshark field export for a real generated pcapng and verifies correlations,
  counts, packet references, evidence filters, findings, suggestions, and grouped
  search. Regenerate it with `scripts/generate-analysis-fixture.sh`; the script uses
  `text2pcap`, `mergecap`, and tshark and verifies an HTTP object can be extracted.
- **Updates** (`src/test/.../update`): `UpdateCheckerTest` pins the production
  repository endpoint, release JSON parsing, numeric version ordering, and prerelease
  ordering without making a network request.
- **Monitor** (`src/test/.../monitor`): `IwPhyParserTest` runs against **unmodified
  `iw` output captured from the target radio** (`src/test/resources/iw-phy-redfin.txt`
  + `iw-reg-redfin.txt`), not synthetic text — the parser decides which controls the
  operator may press, so it is pinned to a real PHY. `ChannelTargetTest` covers
  wide-channel geometry and the generated `iw` commands; `HopPlannerTest` covers the
  sweep plan.
- **DIAG** (`src/test/.../diag`): `DiagFramingTest` (CRC-16/X-25 against the published
  `0x906E` check value, escaping, split reads, corrupt-frame rejection),
  **independent Python encoder** so the framing is checked across two
  implementations rather than only round-tripped through our own.

`DiagPcapWriterTest` also writes `app/build/diag-verify/diag-verify.pcapng`. Push it
readable by real Wireshark dissectors, not just by this project:

```bash
P=/data/data/dev.alsatianconsulting.pocketpcap.debug/files/tshark
adb push app/build/diag-verify/diag-verify.pcapng /data/local/tmp/
adb shell su -c "LD_LIBRARY_PATH=$P/lib WIRESHARK_DATA_DIR=$P/share/wireshark \
  $P/bin/tshark -r /data/local/tmp/diag-verify.pcapng -T fields -e frame.protocols"
```
- **Instrumented** (`src/androidTest`): `MigrationTest` (v1→v2→v3 non-destructive),
  `PersistenceTest` (aliases/recent/saved/bookmarks survive reopen; recent-cap trim),
  `ClickToFilterUiTest` (tap protocol/endpoint → callback).

## Analysis development

- Keep `CaptureAnalysisParser.fields` and the `DecodeManager.captureAnalysis()` export
  in lockstep. `docs/ANALYSIS.md` documents every field family and correlation rule.
- Whole-capture analysis is immutable and cached. Do not attach raw payload copies or
  Compose state to it. Payload string/hex search must remain bounded and on demand.
- Every new finding needs direct frame evidence and a valid Wireshark display filter.
  Unknown or ambiguous dissector output must remain unavailable rather than inferred.
- Analysis screens represent the whole capture unless an explicit analysis-scope filter
  is passed. The packet list may independently show a display-filtered subset.
- Add parser regression coverage and, when practical, a tshark-generated fixture for
  every new correlation or finding family.

## Room

### Adding a schema change / migration {#migrations}

1. Bump `@Database(version = …)` in `PocketPcapDatabase`.
2. Add a `Migration(old, new)` object (additive only — **no** `fallbackToDestructive…`)
   and include it in `ALL_MIGRATIONS`.
3. Build once so KSP exports the new `app/schemas/<version>.json`. **Commit it** — it is
   bundled into androidTest assets and is required for `MigrationTestHelper`.
4. Add a migration test seeding the previous version and asserting data survives.

Schemas are exported via the KSP arg in `app/build.gradle.kts`:

```kotlin
ksp { arg("room.schemaLocation", "$projectDir/schemas") }
```

> Note: `1.json` was authored by hand (the DB shipped new at v2 in one sprint) so the
> migration test can create a v1 database. Any later versions are exported by KSP.

## Extending suggestions

- Add protocols/fields to `FilterFields.all` (use the exact Wireshark filter token).
- Dynamic inputs come from `SuggestionContext`, assembled in
  `MainViewModel.recomputeSuggestions`. Endpoints derive from the current packet list +
  endpoints view; streams from `DecodeManager.streamIndices`; names from
  `NameResolver.knownNames()`.
- Keep `FilterSuggestionEngine` pure — it has unit tests; the `splitFragment` boundary
  rules and ranking (startsWith before contains) are covered there.

## Name resolution

- OUI data is the **full IEEE registry** bundled as `assets/manuf.bin` (Wireshark's
  `manuf`: prefix + vendor, with `/28` and `/36` masks for MA-M and MA-S). Refresh it
  with `scripts/build-oui.sh`. `OuiTable.parse` builds three mask-keyed maps and
  `lookup` returns the most-specific match; it tolerates the legacy space-separated form.
  The table is large, so it is parsed once off-thread via `NameResolver.prewarm()`
  (called from the ViewModel's init coroutine) — never on the UI thread.
- `LocalNameQuery` implements the NetBIOS (NBSTAT) and LLMNR (reverse PTR) wire codecs;
  the pure build/parse helpers are unit-tested, the socket helpers do short UDP I/O.
- Active local queries (NetBIOS/LLMNR) only run for **private IPv4** addresses
  (`AddressUtil.isPrivateIpv4`) and only when **Resolve hostnames** is on; each address
  is queried at most once (`triedLocal`). LLMNR holds a `WifiManager.MulticastLock`
  (needs `CHANGE_WIFI_MULTICAST_STATE`, declared in the manifest).
- Reverse DNS + mDNS are likewise gated by **Settings → Resolve hostnames** and run
  off-thread; add new mDNS service types in `NameResolver.SERVICE_TYPES`.

## Rootless VPN capture

- `VpnCaptureService` is an Android `VpnService`, not a bound helper service. Start it
  with `ACTION_START` after `VpnService.prepare(...)` has returned null or the user has
  approved the VPN prompt.
- App scoping uses `Builder.addAllowedApplication(packageName)`. The picker is sourced
  from `SourceManager.installedApps` and includes system apps.
- All-app capture uses the default VPN app set and excludes PocketPCAP itself to avoid
  routing the UI's own lookups into the local VPN.
- The service passes the TUN fd to tun2socks, points tun2socks at a loopback SOCKS5
  listener, and forwards TCP/UDP with protected direct sockets. The binding is
  `app/libs/tun2socks.aar`, built from source by `scripts/build-tun2socks-aar.sh`
  against the pins in `tun2socks-bind/go.{mod,sum}`; it replaced the prebuilt
  `com.ooimi.library:tun2socks:1.0.4`, whose `libgojni.so` records NDK r19c and which
  Play flags as a 16 KB page-size crash risk. Go calls back into the generated `go.*`
  and `engine.*` classes by name through JNI, so both the AAR's own `proguard.txt` and
  `app/proguard-rules.pro` keep them; without that, release builds break at runtime
  only.
- `Engine.start()` may return after starting the native loop on some tun2socks builds;
  `VpnCaptureService` keeps the foreground job alive until explicit Stop so the VPN fd,
  SOCKS relay, and pcapng writer are not closed immediately.
- `RootlessPacketRecorder` writes `LINKTYPE_RAW` pcapng with `PcapNgWriter` and live
  summaries from `RootlessPacketParser`. Detailed decode still comes from tshark after
  the pcapng exists.
- Rootless packets are relay-reconstructed, not bit-exact TUN frames. They preserve
  remote endpoints and payload bytes; the local app-side address/port is synthetic.
- Active captures should continue if the UI task is swiped away. Services stop
  themselves on task removal only when idle.

## Endpoint location (GeoIP + WHOIS)

- `GeoIpManager` imports a custom CSV database from SAF into `filesDir/geoip/` and loads
  it at startup. Supported columns: `cidr` or `start_ip`/`end_ip`, plus `country`,
  `country_code`, `region`, `city`, `postal`, `latitude`, `longitude`, `timezone`,
  `asn`, `org`, `isp`.
- `LocationLookup` uses the offline GeoIP match first when present, then falls back to
  `ipwho.is` for GeoIP. WHOIS/RDAP still comes from `rdap.org` over HTTPS. It is invoked
  only by the explicit per-tap **Look up location & WHOIS** action, caches per session in
  the ViewModel, and short-circuits private/link-local addresses.
- The JSON parsers (`parseGeo`, `parseRdap`, `merge`) are pure and unit-tested with real
  captured API responses. Android's `org.json` is a stub in JVM unit tests, so a real
  impl is on the test classpath: `testImplementation("org.json:json:…")`.
- Cleartext HTTP is blocked on modern Android, so both providers must be HTTPS — don't
  swap in an `http://` GeoIP API without a network-security config.
- The UI recomposes endpoint labels when `MainViewModel.resolveTick` increments; keep the
  `remember(address, resolveTick)` keys when rendering labels.

## Conventions

- Compose, manual DI through `MainViewModel`; no Hilt.
- Theme: Alsatian warm-dark (`AcOrange500` accent, `WarmBg*`/`WarmFg*` palette).
- Keep tshark/DB work on `Dispatchers.IO`; never block the packet list.
