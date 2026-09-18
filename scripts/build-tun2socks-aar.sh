#!/usr/bin/env bash
#
# build-tun2socks-aar.sh
#
# Builds app/libs/tun2socks.aar from tun2socks source with gomobile.
#
# PocketPCAP's rootless capture path forwards packets out of its VpnService TUN
# with tun2socks, bound into the app through JNI. That used to come from the
# prebuilt AAR com.ooimi.library:tun2socks:1.0.4, which Google Play flagged: its
# libgojni.so records NDK r19c in .note.android.ident, and Play rejects anything
# below r28 as a 16 KB page-size crash risk. That artifact was last published in
# November 2023 and has no newer version, so the only way forward is to build it
# here. The result is also better provenance: a pinned upstream tag built with a
# current toolchain, instead of an unmaintained third-party binary.
#
# The build is pinned by tun2socks-bind/go.mod and go.sum, which fix tun2socks
# and its whole module graph - gVisor's netstack and wireguard-go included.
# tun2socks is GPL-3.0-only and is linked into the app's own process, which is
# why PocketPCAP as a whole is GPL-3.0-or-later; that pin is what makes the
# written source offer in THIRD-PARTY-NOTICES.md answerable.
#
# The output is gitignored. Run this once on a fresh checkout before building
# the APK, the same way scripts/build-tshark-bundle.sh is run.
#
# Requires: bash, go, gomobile + gobind on PATH, an Android NDK r28 or newer.
#
#   go install golang.org/x/mobile/cmd/gomobile@latest
#   go install golang.org/x/mobile/cmd/gobind@latest
#
# Environment:
#   ANDROID_HOME      Android SDK (default ~/Library/Android/sdk, ~/Android/Sdk)
#   ANDROID_NDK_HOME  a specific NDK; otherwise the newest r28+ under $ANDROID_HOME/ndk
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIND_DIR="$ROOT/tun2socks-bind"
OUT="$ROOT/app/libs/tun2socks.aar"
MANIFEST="$ROOT/docs/tun2socks-build-manifest.tsv"
PACKAGE="github.com/xjasonlyu/tun2socks/v2/engine"
MODULE="github.com/xjasonlyu/tun2socks/v2"
# Matches minSdk in app/build.gradle.kts. Binding for an older API buys nothing:
# the app cannot install below it.
ANDROID_API=29
# arm64 only, matching the abiFilters in app/build.gradle.kts: the bundled tshark
# toolchain is an aarch64 build, so no other ABI was ever usable.
TARGET=android/arm64
MIN_NDK=28

die() { echo "error: $*" >&2; exit 1; }
note() { echo "==> $*"; }

for tool in go gomobile gobind; do
  command -v "$tool" >/dev/null || die "$tool not found on PATH (see the header of this script)"
done

find_ndk() {
  if [[ -n "${ANDROID_NDK_HOME:-}" ]]; then echo "$ANDROID_NDK_HOME"; return; fi
  local sdk="${ANDROID_HOME:-}"
  if [[ -z "$sdk" ]]; then
    for candidate in "$HOME/Library/Android/sdk" "$HOME/Android/Sdk"; do
      [[ -d "$candidate" ]] && sdk="$candidate" && break
    done
  fi
  [[ -n "$sdk" && -d "$sdk/ndk" ]] || die "no Android SDK found; set ANDROID_HOME or ANDROID_NDK_HOME"
  # Highest installed version wins, and it has to be at least r28: that is the
  # whole point of this script.
  local newest
  newest="$(ls -1 "$sdk/ndk" | sort -t. -k1,1n -k2,2n -k3,3n | tail -1)"
  [[ -n "$newest" ]] || die "no NDK installed under $sdk/ndk"
  echo "$sdk/ndk/$newest"
}

NDK="$(find_ndk)"
[[ -d "$NDK" ]] || die "NDK path does not exist: $NDK"
NDK_MAJOR="$(sed -n 's/^Pkg\.Revision *= *\([0-9]*\).*/\1/p' "$NDK/source.properties" 2>/dev/null)"
[[ -n "$NDK_MAJOR" ]] || die "cannot read Pkg.Revision from $NDK/source.properties"
[[ "$NDK_MAJOR" -ge "$MIN_NDK" ]] ||
  die "NDK $NDK_MAJOR is too old; Play requires r$MIN_NDK or newer for 16 KB page sizes"

READELF="$(echo "$NDK"/toolchains/llvm/prebuilt/*/bin/llvm-readelf)"
[[ -x "$READELF" ]] || die "llvm-readelf not found under $NDK"

TUN2SOCKS_VERSION="$(cd "$BIND_DIR" && go list -m -f '{{.Version}}' "$MODULE")"
GO_VERSION="$(go env GOVERSION)"
note "tun2socks $TUN2SOCKS_VERSION, $GO_VERSION, NDK r$NDK_MAJOR ($(basename "$NDK"))"

mkdir -p "$(dirname "$OUT")"
note "gomobile bind $PACKAGE -> $OUT"
(
  cd "$BIND_DIR"
  # -trimpath keeps absolute build paths out of the shipped library: the AAR this
  # replaces carried its builder's home directory in plain text. -s -w drop the
  # symbol table and DWARF, which is the difference between a 24 MB and a 12 MB
  # libgojni.so and changes nothing at runtime.
  ANDROID_HOME="${ANDROID_HOME:-}" ANDROID_NDK_HOME="$NDK" \
    gomobile bind \
      -trimpath \
      -ldflags="-s -w" \
      -target="$TARGET" \
      -androidapi "$ANDROID_API" \
      -o "$OUT" \
      "$PACKAGE"
)
[[ -f "$OUT" ]] || die "gomobile produced no archive"

note "verifying the archive"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
unzip -q -o "$OUT" -d "$WORK"
SO="$WORK/jni/arm64-v8a/libgojni.so"
[[ -f "$SO" ]] || die "no arm64-v8a/libgojni.so in the archive"

# The reason this script exists: Play reads the NDK revision out of this note.
# 'r' is not a hex digit, so a match can only come from the dump's ASCII column.
BUILT_NDK="$("$READELF" -x .note.android.ident "$SO" | grep -oE 'r[0-9]{2,}[a-z]?' | head -1)"
[[ -n "$BUILT_NDK" ]] || die "no .note.android.ident in libgojni.so"
[[ "${BUILT_NDK//[!0-9]/}" -ge "$MIN_NDK" ]] ||
  die "libgojni.so records NDK $BUILT_NDK, below the r$MIN_NDK Play requires"

# Every LOAD segment has to be aligned to at least 16 KB or the library cannot be
# mapped on a 16 KB page-size device.
while read -r align; do
  [[ $((align)) -ge 16384 ]] || die "a LOAD segment is aligned to $align, below 16384"
done < <("$READELF" -lW "$SO" | awk '/LOAD/ {print $NF}')

# The app calls exactly these. A binding that silently dropped one would compile
# the AAR fine and fail at the Kotlin call site.
CLASSES="$WORK/classes"
mkdir -p "$CLASSES"
unzip -q -o "$WORK/classes.jar" -d "$CLASSES"
for required in engine/Engine.class engine/Key.class go/Seq.class; do
  [[ -f "$CLASSES/$required" ]] || die "generated binding is missing $required"
done
if command -v javap >/dev/null; then
  api="$(javap -classpath "$CLASSES" engine.Engine engine.Key)"
  for member in "insert(engine.Key)" "start()" "stop()" setDevice setProxy setMTU \
                setLogLevel setInterface setTCPModerateReceiveBuffer; do
    grep -qF "$member" <<<"$api" || die "generated binding is missing $member"
  done
fi

SHA="$(shasum -a 256 "$OUT" | awk '{print $1}')"
SO_SHA="$(shasum -a 256 "$SO" | awk '{print $1}')"
mkdir -p "$(dirname "$MANIFEST")"
{
  echo "# Provenance for app/libs/tun2socks.aar, which is gitignored."
  echo "# Regenerated by scripts/build-tun2socks-aar.sh; do not edit by hand."
  echo "# The exact module graph behind this build is tun2socks-bind/go.{mod,sum}."
  echo "# Rebuilding from the same pins and the same toolchain reproduces the"
  echo "# artifact; a differing hash means something in the chain moved."
  printf 'field\tvalue\n'
  printf 'source\t%s %s\n' "https://github.com/xjasonlyu/tun2socks" "$TUN2SOCKS_VERSION"
  printf 'bound_package\t%s\n' "$PACKAGE"
  printf 'licence\tGPL-3.0-only\n'
  printf 'go\t%s\n' "$GO_VERSION"
  printf 'ndk\t%s (%s)\n' "$BUILT_NDK" "$(basename "$NDK")"
  printf 'target\t%s, androidapi %s\n' "$TARGET" "$ANDROID_API"
  printf 'build_flags\t-trimpath -ldflags="-s -w"\n'
  printf 'aar_sha256\t%s\n' "$SHA"
  printf 'libgojni_so_sha256\t%s\n' "$SO_SHA"
  printf 'built\t%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
} > "$MANIFEST"

note "ok: $(basename "$OUT") $(du -h "$OUT" | cut -f1), libgojni.so $(du -h "$SO" | cut -f1), NDK $BUILT_NDK"
note "manifest: ${MANIFEST#"$ROOT"/}"
