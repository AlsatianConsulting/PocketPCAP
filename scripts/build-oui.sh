#!/usr/bin/env bash
# Regenerate the bundled IEEE MAC-vendor table (app/src/main/assets/manuf.gz).
#
# Source: Wireshark's canonical `manuf` file, which merges the IEEE MA-L (24-bit),
# MA-M (28-bit) and MA-S / IAB (36-bit) registries with mask notation. We strip the
# header comments and keep two tab-separated columns: <prefix[/bits]> and the full
# vendor name (falling back to Wireshark's short name when no full name is present),
# then gzip it. The Kotlin OuiTable parser reads this format directly.
set -euo pipefail

SRC_URL="https://www.wireshark.org/download/automated/data/manuf"
# Note: a non-".gz" extension is used so the Android build keeps the file gzipped
# (an asset literally named *.gz is transparently decompressed + renamed by AGP).
OUT="$(dirname "$0")/../app/src/main/assets/manuf.bin"
TMP="$(mktemp)"

echo "Downloading $SRC_URL …"
curl -fsSL "$SRC_URL" -o "$TMP"

echo "Processing $(grep -vcE '^#|^$' "$TMP") entries …"
awk -F'\t' '$0 !~ /^#/ && NF>=2 {
  p=$1;    gsub(/^[ \t]+|[ \t]+$/,"",p);
  short=$2; gsub(/^[ \t]+|[ \t]+$/,"",short);
  full=(NF>=3)?$3:""; gsub(/^[ \t]+|[ \t]+$/,"",full);
  name=(full!="")?full:short;
  if (p!="" && name!="") print p"\t"name;
}' "$TMP" | gzip -9 -c > "$OUT"

rm -f "$TMP"
echo "Wrote $OUT ($(du -h "$OUT" | cut -f1))"
