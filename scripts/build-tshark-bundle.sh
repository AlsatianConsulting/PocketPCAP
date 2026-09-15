#!/usr/bin/env bash
#
# build-tshark-bundle.sh
#
# Downloads the Termux aarch64 build of tshark (the full Wireshark dissector
# engine — every protocol Wireshark can decode) plus its shared-library
# dependency closure, and splits it into the two places Android needs:
#
#   app/src/main/jniLibs/arm64-v8a/   executables + shared libraries
#   app/src/main/assets/tshark-prefix.zip   Wireshark's data files
#
# The split is what makes decoding work without root. Android will not execute a
# file an app wrote into its own storage, but it will execute files in the app's
# native library directory, which the installer fills from the APK. So the
# binaries ship as jniLibs, renamed to lib*.so — the only pattern the installer
# extracts — by scripts/jnilib-name.py, which also rewrites every DT_SONAME and
# DT_NEEDED reference so the linkage still resolves. Wireshark's data files are
# only read, so they stay in assets.
#
# Both outputs are gitignored because they are large (~180 MB of libraries). Run
# this once on a fresh checkout before building the APK.
# Requires: bash, curl, python3, bsdtar, zip.
#
# The packages are GPL/LGPL licensed, so this script also writes
# docs/tshark-bundle-manifest.tsv recording the exact package name, version,
# SHA-256 and source URL behind every bundled binary. Commit that manifest
# whenever the bundle is regenerated: it is what makes the written source offer
# in THIRD-PARTY-NOTICES.md verifiable.
#
# The manifest is also enforced, not merely recorded. Every downloaded .deb is
# checked against the SHA-256 in the repository index, and any package whose
# version matches the committed manifest but whose hash does not aborts the
# build. Without that, a rebuild silently accepted whatever the mirror served:
# these packages are fetched over plain HTTPS with no apt signature check, and
# they end up as native code executing inside the app. A republished .deb under
# an unchanged version is exactly the case a provenance record alone misses.
#
# At runtime PocketPCAP extracts this zip to its private files dir and runs
# tshark / dumpcap via `su` with LD_LIBRARY_PATH pointing at the bundled libs.
# The binaries use the standard Android dynamic linker (/system/bin/linker64),
# so no Termux installation is required on the device.
#
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORK="${TMPDIR:-/tmp}/pocketpcap-tshark-build"
OUT="$REPO_ROOT/app/src/main/assets/tshark-prefix.zip"

MAIN_URL="https://packages.termux.dev/apt/termux-main"
ROOT_URL="https://packages.termux.dev/apt/termux-root"
MAIN_PKGS="$MAIN_URL/dists/stable/main/binary-aarch64/Packages"
ROOT_PKGS="$ROOT_URL/dists/root/stable/binary-aarch64/Packages"

echo "==> Work dir: $WORK"
rm -rf "$WORK"; mkdir -p "$WORK/debs" "$WORK/prefix" "$WORK/min/bin" "$WORK/min/lib" "$WORK/min/share"

echo "==> Fetching package indexes"
curl -fsSL "$MAIN_PKGS" -o "$WORK/main.Packages"
curl -fsSL "$ROOT_PKGS" -o "$WORK/root.Packages"

echo "==> Resolving dependency closure for tshark + tcpdump"
python3 - "$WORK" "$MAIN_URL" "$ROOT_URL" "$REPO_ROOT/docs/tshark-bundle-manifest.tsv" << 'PY'
import re, sys, os
work, main_url, root_url, committed = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]
def parse(path, base):
    pkgs={}
    for b in open(path).read().split("\n\n"):
        if not b.strip(): continue
        d={}
        for line in b.splitlines():
            m=re.match(r"^([A-Za-z0-9-]+): (.*)", line)
            if m: d[m.group(1)]=m.group(2)
        if "Package" in d:
            d["_base"]=base; pkgs[d["Package"]]=d
    return pkgs
allp={**parse(f"{work}/main.Packages", main_url), **parse(f"{work}/root.Packages", root_url)}
def deps(n):
    d=allp.get(n)
    if not d: return []
    out=[]
    for part in d.get("Depends","").split(","):
        p=part.strip().split(" ")[0].split("|")[0].strip()
        if p: out.append(p)
    return out
seen=set()
def closure(n):
    if n in seen or n not in allp: return
    seen.add(n)
    for dd in deps(n): closure(dd)
closure("tshark"); closure("tcpdump")
# Termux's tshark package under-declares its dependencies: libwireshark links
# libnghttp3 without apt listing it, so the closure alone produced a bundle whose
# tshark could not link. Seed anything found that way explicitly.
for extra in ("libnghttp3",):
    closure(extra)
urls=[f"{allp[p]['_base']}/{allp[p]['Filename']}" for p in sorted(seen) if p in allp]
open(f"{work}/urls.txt","w").write("\n".join(urls))

# A package the index cannot vouch for cannot be verified after download, so it
# must not be bundled silently.
unhashed=[p for p in sorted(seen) if p in allp and not allp[p].get("SHA256")]
if unhashed:
    sys.exit("    no SHA256 in the index for: " + ", ".join(unhashed))

# Checksums to verify the downloads against, keyed by the basename curl -O writes.
open(f"{work}/sha256sums.txt","w").write("".join(
    f"{allp[p]['SHA256']}  {os.path.basename(allp[p]['Filename'])}\n" for p in sorted(seen) if p in allp))

# Enforce the committed manifest. A version that has moved on is ordinary - the
# manifest is about to be rewritten - but the same version resolving to different
# bytes means the published package was replaced underneath us, and that is not
# something to absorb quietly into a bundle of native code.
if os.path.exists(committed):
    prior={}
    for line in open(committed):
        if line.startswith("#") or not line.strip(): continue
        cols=line.rstrip("\n").split("\t")
        if len(cols) >= 4: prior[cols[0]]=(cols[1], cols[2])
    tampered=[]
    for p in sorted(seen):
        if p not in allp or p not in prior: continue
        ver, sha = prior[p]
        if allp[p].get("Version")==ver and allp[p]["SHA256"]!=sha:
            tampered.append(f"      {p} {ver}\n        committed {sha}\n        index     {allp[p]['SHA256']}")
    if tampered:
        sys.exit("    SAME VERSION, DIFFERENT BYTES - refusing to build:\n" + "\n".join(tampered) +
                 "\n    Establish why upstream republished it before regenerating the manifest.")
# Provenance manifest. The bundle ships GPL and LGPL binaries, so the exact
# upstream package and version behind each one has to be recorded to keep the
# written source offer in THIRD-PARTY-NOTICES.md honest.
rows=["# Termux aarch64 packages composing app/src/main/assets/tshark-prefix.zip",
      "# Regenerated by scripts/build-tshark-bundle.sh; do not edit by hand.",
      "# The SHA-256 is the repository index's, verified against the downloaded",
      "# .deb at build time; a later rebuild that sees the same version with a",
      "# different hash fails rather than bundling it.",
      "# package\tversion\tsha256\tsource"]
for p in sorted(seen):
    if p not in allp: continue
    d=allp[p]
    rows.append(f"{d['Package']}\t{d.get('Version','unknown')}\t{d['SHA256']}\t{d['_base']}/{d['Filename']}")
open(f"{work}/manifest.tsv","w").write("\n".join(rows)+"\n")
print(f"    {len(urls)} packages")
PY

echo "==> Downloading .deb packages"
( cd "$WORK/debs" && xargs -P 8 -n 1 curl -fsSLO < "$WORK/urls.txt" )

echo "==> Verifying .deb checksums"
# Whichever the host provides; both read the same "<hash>  <file>" format.
if command -v sha256sum >/dev/null 2>&1; then SHACHECK="sha256sum -c --quiet"
elif command -v shasum    >/dev/null 2>&1; then SHACHECK="shasum -a 256 -c --status"
else echo "    need sha256sum or shasum to verify downloads" >&2; exit 1
fi
if ! ( cd "$WORK/debs" && $SHACHECK "$WORK/sha256sums.txt" ); then
  echo "    CHECKSUM MISMATCH - a downloaded package does not match the index." >&2
  echo "    Not unpacking it. Re-run; if it persists, treat the mirror as suspect." >&2
  ( cd "$WORK/debs" && shasum -a 256 -c "$WORK/sha256sums.txt" 2>&1 | grep -v ': OK$' || true ) >&2
  exit 1
fi
echo "    $(wc -l < "$WORK/sha256sums.txt" | tr -d ' ') packages match the index"

echo "==> Extracting packages into prefix"
for deb in "$WORK"/debs/*.deb; do
  rm -f "$WORK"/data.tar.*
  bsdtar -xf "$deb" -C "$WORK" data.tar.xz data.tar.gz data.tar.zst 2>/dev/null || true
  data=$(ls "$WORK"/data.tar.* 2>/dev/null | head -1 || true)
  [ -n "$data" ] && bsdtar -xf "$data" -C "$WORK/prefix" 2>/dev/null || true
done
PREFIX="$WORK/prefix/data/data/com.termux/files/usr"

echo "==> Computing shared-library closure"
python3 - "$PREFIX/lib" "$WORK/min/lib" "$PREFIX/bin/tshark" "$PREFIX/bin/dumpcap" "$PREFIX/bin/tcpdump" \
  "$PREFIX/bin/editcap" "$PREFIX/bin/mergecap" << 'PY'
import sys, struct, os, glob, shutil
def dt_needed(path):
    with open(path,'rb') as f: data=f.read()
    if data[:4]!=b'\x7fELF' or data[4]!=2: return []
    e_shoff=struct.unpack_from('<Q',data,0x28)[0]
    e_shentsize=struct.unpack_from('<H',data,0x3a)[0]
    e_shnum=struct.unpack_from('<H',data,0x3c)[0]
    secs=[]; dynoff=dynsz=dynlink=None
    for i in range(e_shnum):
        off=e_shoff+i*e_shentsize
        t=struct.unpack_from('<I',data,off+4)[0]
        o=struct.unpack_from('<Q',data,off+0x18)[0]
        s=struct.unpack_from('<Q',data,off+0x20)[0]
        l=struct.unpack_from('<I',data,off+0x28)[0]
        secs.append((t,o,s,l))
        if t==6: dynoff,dynsz,dynlink=o,s,l
    if dynoff is None: return []
    st_off=secs[dynlink][1]; needed=[]
    for i in range(dynsz//16):
        tag,val=struct.unpack_from('<qQ',data,dynoff+i*16)
        if tag==1:
            needed.append(data[st_off+val:data.index(b'\x00',st_off+val)].decode())
        if tag==0: break
    return needed
libdir, outdir = sys.argv[1], sys.argv[2]
roots=sys.argv[3:]
avail={os.path.basename(p):p for p in glob.glob(os.path.join(libdir,'*.so*'))}
seen=set(); need=set()
def walk(p):
    for so in dt_needed(p):
        need.add(so)
        if so in avail and avail[so] not in seen:
            seen.add(avail[so]); walk(avail[so])
for r in roots: walk(r)
n=0
for so in sorted(need):
    if so in avail:
        # dereference: copy real content under the SONAME the linker resolves
        shutil.copy(avail[so], os.path.join(outdir, so)); n+=1
print(f"    {n} libs bundled")
PY

echo "==> Assembling minimal prefix"
# editcap and mergecap come from the same package and cost little: they back
# capture merging, time-range and payload-stripped export, and packet comments.
for tool in tshark dumpcap tcpdump editcap mergecap; do
  cp -L "$PREFIX/bin/$tool" "$WORK/min/bin/"
done
cp -aL "$PREFIX/share/wireshark" "$WORK/min/share/" 2>/dev/null || true
chmod +x "$WORK/min/bin/"*

JNILIBS="$REPO_ROOT/app/src/main/jniLibs/arm64-v8a"
echo "==> Renaming binaries into jniLibs -> $JNILIBS"
python3 "$REPO_ROOT/scripts/jnilib-name.py" "$WORK/min" "$JNILIBS"

echo "==> Zipping data files -> $OUT"
mkdir -p "$(dirname "$OUT")"
rm -f "$OUT"
( cd "$WORK/min" && zip -qr -X "$OUT" share )
echo "==> Verifying every bundled binary links"
python3 - "$JNILIBS" << 'PY'
import os, struct, sys
outdir = sys.argv[1]
# Provided by Android itself; never bundled.
SYSTEM = {"libc.so", "libm.so", "libdl.so", "liblog.so", "libandroid.so", "libz.so"}

def dt_needed(path):
    with open(path, "rb") as f:
        data = f.read()
    if data[:4] != b"\x7fELF" or data[4] != 2:
        return []
    e_phoff = struct.unpack_from("<Q", data, 0x20)[0]
    e_phentsize = struct.unpack_from("<H", data, 0x36)[0]
    e_phnum = struct.unpack_from("<H", data, 0x38)[0]
    loads, dyn = [], None
    for i in range(e_phnum):
        off = e_phoff + i * e_phentsize
        p_type = struct.unpack_from("<I", data, off)[0]
        p_offset, p_vaddr = struct.unpack_from("<QQ", data, off + 0x08)
        p_filesz = struct.unpack_from("<Q", data, off + 0x20)[0]
        if p_type == 1: loads.append((p_offset, p_vaddr, p_filesz))
        elif p_type == 2: dyn = (p_offset, p_filesz)
    if not dyn: return []
    def v2o(v):
        for o, va, sz in loads:
            if va <= v < va + sz: return o + (v - va)
        return None
    entries, strtab = [], None
    for i in range(dyn[1] // 16):
        tag, val = struct.unpack_from("<qQ", data, dyn[0] + i * 16)
        if tag == 0: break
        if tag == 5: strtab = v2o(val)
        entries.append((tag, val))
    if strtab is None: return []
    out = []
    for tag, val in entries:
        if tag == 1:
            end = data.index(b"\0", strtab + val)
            out.append(data[strtab + val:end].decode())
    return out

present = set(os.listdir(outdir))
missing = {}
for name in sorted(present):
    for need in dt_needed(os.path.join(outdir, name)):
        if need in SYSTEM or need in present: continue
        missing.setdefault(need, []).append(name)
if missing:
    print("    UNRESOLVED shared libraries:", file=sys.stderr)
    for need, users in sorted(missing.items()):
        print(f"      {need} <- {', '.join(users)}", file=sys.stderr)
    print("    Add the providing package to the closure seeds in this script.", file=sys.stderr)
    raise SystemExit(1)
print(f"    {len(present)} binaries, all dependencies resolved")
PY

MANIFEST="$REPO_ROOT/docs/tshark-bundle-manifest.tsv"
echo "==> Recording provenance -> $MANIFEST"
mkdir -p "$(dirname "$MANIFEST")"
cp "$WORK/manifest.tsv" "$MANIFEST"

echo "==> Done: $(du -h "$OUT" | cut -f1)  ($(unzip -l "$OUT" | tail -1 | awk '{print $2}') files)"
echo "    Provenance manifest updated; commit it alongside any bundle change so"
echo "    THIRD-PARTY-NOTICES.md keeps matching what actually ships." 
