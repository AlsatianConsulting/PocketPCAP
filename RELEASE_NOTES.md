# Release Notes

## v0.1.4 — 15 September 2026

Found by a full clean-install QA pass, including installing the app the way Google Play
actually delivers it — `bundletool` split APKs generated from the AAB rather than the
monolithic APK.

### Stopping a rootless capture crashed the app

`fdsan: double-close of file descriptor` — SIGABRT, process gone. Stopping the capture
cancels the tun2socks job, and `delay()` then throws `CancellationException`, which *is*
an `Exception`; the handler that exists to release the descriptor when the engine never
took ownership therefore ran on the normal stop path and closed a descriptor the engine
had already closed. The handler now only releases the descriptor when `Engine.start()`
never succeeded, and cancellation is no longer treated as a failure.

This is why the app appeared to "go back to the home screen" after stopping a capture: it
was not navigating, it was dying.

### Check for Updates always failed

The About card queried `AlsatianConsulting/PocketPCAP-dev`, which is private and has no
releases, so every check reported "Unable to check for updates" — and the request
disclosed the name of a private repository. It now queries the public release repository,
where the releases actually are. A unit test pins that and fails if it is ever pointed at
a `-dev` repository again.

### Verified from a clean install

Installed as three Play-delivered splits (`base-master`, `base-arm64_v8a`, `base-en`) and
exercised end to end:

- the bundled tshark executes out of the ABI split — the capability check reports it
  available with no root, which is the whole question for an app that ships executables
- rootless VPN capture, with browsing working through the tunnel; pause, resume and stop
- rooted dumpcap capture, start and stop, no stranded processes
- the analysis workspace: Summary, Conversations, Endpoints, Protocols, Issues, Objects
- packet list, full dissection tree and hex
- headers-only PCAPNG export (valid, payloads stripped, headers intact) and CSV export
- traffic map with live GeoIP lookups
- settings, decryption, GeoIP import, licences, and the update check

84 JVM and 13 instrumented tests pass, none skipped; lint reports 0 errors.

---

## v0.1.3 — 15 September 2026

**Rootless capture actually works now.** Three fixes, one of which was breaking the
device's connectivity whenever a rootless capture was running.

### Rootless VPN capture no longer breaks the network

With a rootless capture running, browsing failed across the device: `ERR_CONNECTION_RESET`
on TLS, `ERR_QUIC_PROTOCOL_ERROR` on QUIC. The capture dutifully recorded the attempts, so
it looked like traffic was flowing when nothing was completing.

The cause was IPv6. The tunnel advertised an IPv6 address and a `::/0` route
unconditionally, so apps inside it resolved AAAA records and tried IPv6 first — and the
relay then tried to connect over real IPv6 on a network that has none, getting
`ENETUNREACH` every time. The tunnel now advertises IPv6 only when the underlying network
carries a genuine global address in `2000::/3`. A router handing out `fd00::` ULAs with no
upstream IPv6 is the normal home case, and the kernel calls those "scope global", so the
check tests the prefix rather than trusting `isSiteLocalAddress()`.

Two further relay bugs found alongside it:

- The SOCKS handshake was parsed through a `BufferedInputStream`, and the relay then
  re-read the socket with a fresh stream — discarding anything the buffer had read ahead.
  A client that pipelines its first payload behind the SOCKS request, which is what a TLS
  ClientHello does, had that payload silently dropped.
- `protect()` was called on a socket with no file descriptor yet, making it a no-op and
  sending the relay's own connections back into the tunnel it was serving. The socket is
  now bound first.
- The UDP relay bound to `127.0.0.1` and then tried to send to real hosts from it, which
  cannot work. It binds to the wildcard address now.

Measured on the same device and network, before and after: **95 frames / 115 kB of
unanswered QUIC Initials → 5,056 frames / 5.75 MB** carrying completed TLS sessions and
QUIC handshakes.

`DirectSocksProxy` also logs its failures now instead of swallowing every exception, which
is how the IPv6 cause was found at all.

### Foreground service only while capturing

`CaptureService` went into the foreground when the app launched and stayed there with a
"Ready to capture" notification, whether or not anything was recording — and the rootless
path started it too, so one capture produced two ongoing notifications from two services,
one of them idle. Binding no longer implies the foreground; a capture does. Verified on
device: **0 foreground services at launch, 1 while capturing, 0 after Stop.**

### Verification

84 JVM and 13 instrumented tests pass, none skipped; lint reports 0 errors. Browsing
through a running rootless capture confirmed working for both TLS and QUIC on a Pixel 7
running Android 16.

---

## v0.1.2 — 15 September 2026

**Foreground service type corrected.** Same features as 0.1.1.

Both capture services declared `dataSync`, and that was the wrong type. Google scopes
`dataSync` to upload/download/backup/sync work, and from Android 15 it carries a six-hour
daily cap — which would have silently truncated a long capture, the one failure a capture
tool must not have. Neither service synchronises anything: `CaptureService` runs `dumpcap`
writing packets to a local file, and `VpnCaptureService` records its own local tunnel.

Both now declare `specialUse` with `PROPERTY_SPECIAL_USE_FGS_SUBTYPE` describing exactly
what they do, and the permission is `FOREGROUND_SERVICE_SPECIAL_USE` in place of
`FOREGROUND_SERVICE_DATA_SYNC`.

Verified on a Pixel 7 (Android 16) by running both paths end to end and reading the
service records back from the system:

- `CaptureService` — `isForeground=true types=0x40000000`, dumpcap capturing to
  `Documents/pocketpcap`, 59.9 KB written.
- `VpnCaptureService` — `isForeground=true types=0x40000000`, tunnel established and
  recording; the capture grew from 4.7 KB to 48.4 KB under traffic.

No foreground-service exceptions in the log on either path. 84 JVM and 13 instrumented
tests pass, none skipped; lint reports 0 errors.

---

## v0.1.1 — 15 September 2026

**Google Play compliance release.** Same features as 0.1.0; the packaging changed.

### 16 KB memory page sizes

Android 15 requires 64-bit native libraries to be aligned for 16 KB memory pages, and
Play rejected 0.1.0 for it. The bundled arm64 tshark libraries were never the problem —
all 40 are already built with `p_align` 16384. The violation was `libgojni.so` for
**x86_64**, pulled in transitively with the tun2socks AAR and aligned to 4096.

PocketPCAP is an arm64 application in practice: the entire bundled tshark/dumpcap/
editcap/mergecap closure is an aarch64 build, so on any other ABI the app installed and
then could not decode anything. Those ABIs were never usable — they arrived only as
dependency stubs. The build now sets `abiFilters = ["arm64-v8a"]`, which:

- makes every native library in the APK 16 KB aligned (42 of 42, verified),
- removes 18.2 MB from the APK (83.2 MB → 64.1 MB),
- stops the app installing on devices where it could never have worked.

Verified by reading the ELF program headers of every `.so` in the built APK, and by
clean-installing on a Pixel 7 (Android 16) where the bundled tshark still executes.

### Also in this release

- 84 JVM unit tests and 13 instrumented tests pass, none skipped; lint reports 0 errors.

---

## v0.1.0 — 15 September 2026

First public release of PocketPCAP: Wireshark-grade packet capture and analysis on
Android, built around a bundled `tshark` 4.6.8.

### What it does

**Summary-first analysis.** Opening a capture runs a single cached tshark pass and builds
the whole model from it, so every view is instant afterwards. The Summary reports size,
duration, link layer, endpoint and conversation counts and the dominant protocols, and
every figure is a pivot into the packets behind it.

**Findings with evidence.** The Issues view flags TCP resets, retransmissions, duplicate
ACKs, zero windows and unanswered DNS, and each finding names the endpoints, the
conversation, the first occurrence and the exact packet numbers — so the claim can be
checked rather than trusted.

**Thirteen analysis views.** Summary, Conversations, Endpoints, Protocols, Issues,
Objects, DNS, TLS, HTTP, Statistics, Timeline, grouped Search and Bookmarks. The Timeline
plots packets or bytes per bucket, marks retransmissions and resets, and filters the
capture to a selected range.

**Capture.** Rootless via Android's `VpnService`, device-wide, no root at all. Rooted via
the bundled `dumpcap` on any interface, with capture filters and autostop ceilings for
size and duration.

**Read anything.** Open a PCAP/PCAPNG from anywhere on the device, detected by magic bytes.
Follow a file another tool is still writing. Merge captures. Decrypt TLS with an
`SSLKEYLOGFILE`, or 802.11 with a WEP key, WPA/WPA2 passphrase or raw PSK.

**Export.** Filtered PCAPNG, headers-only PCAPNG with payloads stripped, PCAPNG annotated
with your packet notes as real pcapng comments, analysis tables as CSV/JSON, and the
traffic map as KML/GeoJSON.

### What needs root

Only live capture from a named network interface, because `dumpcap` needs `CAP_NET_RAW`.
Reading, decoding, analysing, decrypting and exporting captures need no root and no
special permissions. The rootless VPN capture path needs no root either. On a device
without root the app says so plainly and keeps everything else working.

### Storage

Captures and exports are written to `Documents/pocketpcap`, reachable from the Files app
and over USB with **no storage permission at all** — the app registers each file with
MediaStore, which is what makes a shared folder writable and still gives `dumpcap` and
`tshark` an ordinary file path to work with. Android 10 cannot write shared storage by
path, so there the default is app storage and Settings shows that path.

### Privacy

No account, no sign-in, no telemetry, no analytics, no ads. Three features reach the
internet, each only when invoked: the Traffic Map and endpoint location (third-party GeoIP
and RDAP lookups of addresses from your capture — only globally routable unicast addresses
are ever sent), Check for Updates, and reverse DNS if you switch it on. Everything else is
entirely offline. Full detail in [PRIVACY.md](PRIVACY.md).

### Requirements

- Android 10 (API 29) or newer, arm64
- Root only for live interface capture

### Artifacts

| File | Purpose |
|---|---|
| `PocketPCAP-release-0.1.0-<DTG>.apk` | Direct install / sideload |
| `PocketPCAP-release-0.1.0-<DTG>.aab` | Google Play upload |

Both are signed with the Alsatian Consulting release key:

```
CN=Alsatian Consulting, OU=Mobile, O=Alsatian Consulting, L=Boston, ST=MA, C=US
SHA-256: aebe540ca2d63a7a47e5adefd3a9be4c064592462e3ea182dd987d1269b8a203
```

Verify before installing:

```bash
apksigner verify --print-certs PocketPCAP-release-0.1.0-<DTG>.apk
shasum -a 256 -c SHA256SUMS.txt
```

### Verification for this build

- 84 JVM unit tests and 13 instrumented tests pass, none skipped
- Android lint: 0 errors
- Built from this tree, signed with the release key, clean-installed and launched on a
  Pixel 7 (Android 16); the bundled tshark executes and reports itself available
- Interoperability checked against Wireshark on the desktop

### Known limitations

- The bundled `tshark` is arm64 only.
- Raw 802.11 capture needs an adapter and driver that support monitor mode; a stock phone
  Wi-Fi driver does not. The 802.11 decryption keys are for captures brought in from such
  a source.
- WEP decryption is accepted by tshark but has not been confirmed end to end against a
  real WEP capture.
- `jniLibs/` and `assets/tshark-prefix.zip` are not in version control. Build them with
  `scripts/build-tshark-bundle.sh` before building the app from a fresh clone.

### Licence

GPL-3.0-or-later. Third-party attribution ships in the app under
**Settings → About → Licences** and in [THIRD-PARTY-NOTICES.md](THIRD-PARTY-NOTICES.md).
