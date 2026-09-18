# Third-Party Notices

PocketPCAP is distributed under the GNU General Public License v3.0 or later
(see [LICENSE](LICENSE)). It ships and links third-party software, listed here
with the licence each component carries.

Two components are why PocketPCAP is GPL-3.0-or-later rather than something more
permissive:

- **tun2socks** is GPL-3.0-only and is linked into the app's own process via JNI.
- **Wireshark** is GPL-2.0-or-later and is distributed inside the APK.

The "or later" in Wireshark's licence is what lets both sit in one work at GPL-3.
Several bundled libraries are LGPL-3.0, which is compatible with GPL-3 but not
with GPL-2 alone, so GPL-3 is also the only version under which the whole set is
internally consistent.

---

## Written offer for source code

The bundled binaries are builds taken from the Termux aarch64 package repository.
`scripts/build-tshark-bundle.sh` downloads published packages and prunes the
dependency closure to what tshark and dumpcap actually load. The executables and
shared libraries are placed in `app/src/main/jniLibs/arm64-v8a/`; Wireshark's data
files are zipped into `app/src/main/assets/tshark-prefix.zip`.

The only modification PocketPCAP makes is mechanical renaming. Android extracts
only files matching `lib*.so` from an APK, and only files in the native library
directory may be executed by an unprivileged app, so `scripts/jnilib-name.py`
renames each file (`libfoo.so.N` becomes `libfoo_N.so`, `tshark` becomes
`libtshark.so`) and rewrites the matching `DT_SONAME` and `DT_NEEDED` entries so
the linkage still resolves. No code is patched and no behaviour is altered; the
upstream sources named below are the corresponding sources for these binaries.

The exact package name, version, SHA-256 and download URL behind every bundled
file is recorded in
[`docs/tshark-bundle-manifest.tsv`](docs/tshark-bundle-manifest.tsv), which that
script regenerates whenever the bundle is rebuilt. The checksum is enforced: each
package is verified against it at build time, and a package that reappears under
the same version with different bytes fails the build rather than being bundled.
Corresponding source for each package is published by Termux and by each upstream
project at the locations below.

For any GPL or LGPL component listed here, Alsatian Consulting will additionally
provide the complete corresponding source code on request, for at least three
years from the date of distribution, at a charge no more than the cost of
performing the distribution. Contact: <geoff@alsatian.consulting>.

---

## Linked into the application process

| Component | Version | Licence | Upstream |
| --- | --- | --- | --- |
| tun2socks (built from source, see `docs/tun2socks-build-manifest.tsv`) | v2.7.0 | **GPL-3.0-only** | https://github.com/xjasonlyu/tun2socks |
| gVisor `netstack` (vendored inside tun2socks) | bundled | Apache-2.0 | https://github.com/google/gvisor |
| AndroidX (core, lifecycle, activity, navigation, Room) | see `gradle/libs.versions.toml` | Apache-2.0 | https://developer.android.com/jetpack/androidx |
| Jetpack Compose + Material 3 | Compose BOM 2024.12.01 | Apache-2.0 | https://developer.android.com/jetpack/compose |
| Kotlin stdlib and kotlinx.coroutines | 2.0.21 / see catalogue | Apache-2.0 | https://github.com/JetBrains/kotlin |

## Bundled executables

Shipped in the APK's native library directory and executed directly. They run as
separate processes and communicate with PocketPCAP only over a command line and
standard streams. Reading a capture needs no privileges; only live capture runs
through `su`, because dumpcap needs CAP_NET_RAW.

| File (as shipped) | Upstream name | Project | Version | Licence |
| --- | --- | --- | --- | --- |
| `libtshark.so` | `tshark` | Wireshark | 4.6.8 | GPL-2.0-or-later |
| `libdumpcap.so` | `dumpcap` | Wireshark | 4.6.8 | GPL-2.0-or-later |
| `libtcpdump.so` | `tcpdump` | tcpdump | as packaged | BSD-3-Clause |

## Bundled shared libraries

| File | Project | Licence |
| --- | --- | --- |
| `libwireshark.so`, `libwiretap.so`, `libwsutil.so` | Wireshark 4.6.8 | GPL-2.0-or-later |
| `libpcap_1.so` | libpcap 1.10.5 | BSD-3-Clause |
| `libglib-2.0.so.0`, `libgmodule-2.0.so.0` | GLib | LGPL-2.1-or-later |
| `libgnutls.so` | GnuTLS 3.8.13 | LGPL-2.1-or-later |
| `libgcrypt.so` | Libgcrypt | LGPL-2.1-or-later |
| `libgpg-error.so` | libgpg-error | LGPL-2.1-or-later |
| `libnettle.so.8`, `libhogweed.so.6` | Nettle | LGPL-3.0-or-later or GPL-2.0-or-later |
| `libgmp.so` | GMP 6.3.0 | LGPL-3.0-or-later or GPL-2.0-or-later |
| `libidn2.so` | libidn2 2.3.8 | LGPL-3.0-or-later or GPL-2.0-or-later |
| `libunistring.so` | GNU libunistring | LGPL-3.0-or-later |
| `libiconv.so` | GNU libiconv | LGPL-2.1-or-later |
| `libcap-ng.so` | libcap-ng | LGPL-2.1-or-later |
| `libcrypto.so.3` | OpenSSL 3.6.2 | Apache-2.0 |
| `libxml2.so.16` | libxml2 | MIT |
| `libpcre2-8.so` | PCRE2 | BSD-3-Clause |
| `libnghttp2.so` | nghttp2 1.69.0 | MIT |
| `libcares.so` | c-ares 1.34.6 | MIT |
| `libbrotlicommon.so`, `libbrotlidec.so` | Brotli | MIT |
| `libsnappy.so` | Snappy | BSD-3-Clause |
| `libzstd.so.1` | Zstandard 1.5.7 | BSD-3-Clause or GPL-2.0 |
| `liblz4.so` | LZ4 | BSD-2-Clause |
| `libz.so.1` | zlib | Zlib |
| `libicuuc.so.78`, `libicudata.so.78` | ICU 78 | Unicode licence (permissive) |
| `libc++_shared.so` | LLVM libc++ | Apache-2.0 with LLVM exception |
| `libandroid-support.so` | Termux android-support | permissive (BSD/Apache); see manifest |

Library file names above are the upstream ones. As shipped they carry the renamed
form described under the written offer, so `libglib-2.0.so.0` appears in the APK as
`libglib-2.0_0.so` and so on; `docs/tshark-bundle-manifest.tsv` records the package
each came from.

Where a component is offered under a choice of licences, PocketPCAP relies on the
option compatible with GPL-3.0-or-later.

## Bundled data

| File | Source | Licence |
| --- | --- | --- |
| `share/wireshark/**` | Wireshark 4.6.8 data files | GPL-2.0-or-later |
| `app/src/main/assets/manuf.bin` | Derived from Wireshark's canonical `manuf` table, which merges IEEE MA-L/MA-M/MA-S registry data. Regenerated by `scripts/build-oui.sh`. | GPL-2.0-or-later |

## Test-only dependencies

Not shipped in the APK.

| Component | Licence |
| --- | --- |
| JUnit 4 | EPL-1.0 |
| AndroidX Test, Espresso, Compose UI test | Apache-2.0 |
| `org.json:json` | JSON.org licence |

---

## Trademarks

Wireshark and the "fin" logo are registered trademarks of the Wireshark
Foundation. PocketPCAP is not affiliated with, endorsed by, or a product of the
Wireshark Foundation; it bundles unmodified upstream Wireshark binaries and says
so. Android and Google Play are trademarks of Google LLC.
