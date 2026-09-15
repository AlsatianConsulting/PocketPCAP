#!/usr/bin/env python3
"""
Rename Termux ELF binaries into Android jniLibs names and repair their linkage.

Android only extracts files matching lib*.so from an APK's lib/<abi>/ directory,
and those extracted files are the only ones an unprivileged app is allowed to
execute. So every executable and shared library in the tshark bundle has to be
renamed, and every reference to a renamed library has to be rewritten inside the
ELF files that depend on it.

The rename is deliberately length-preserving:

    libfoo.so.N  ->  libfoo_N.so        (".so." -> "_", then ".so" appended)

Dropping three characters and adding three back means the new name always occupies
exactly as many bytes as the old one, so DT_SONAME and DT_NEEDED strings can be
overwritten in place inside .dynstr. That avoids rebuilding the string table, and
avoids needing patchelf, which is not in the toolchain.

Executables are renamed to lib<name>.so. Nothing links against them, so only their
own DT_NEEDED entries need rewriting, not their names.
"""
from __future__ import annotations

import os
import shutil
import struct
import sys

DT_NEEDED = 1
DT_SONAME = 14
DT_STRTAB = 5


def jni_name(original: str) -> str:
    """Map a Termux file name onto a name Android will extract and let us exec."""
    if ".so." in original:
        base, _, version = original.partition(".so.")
        return f"{base}_{version.replace('.', '_')}.so"
    if original.endswith(".so"):
        return original
    # A bare executable such as `tshark`.
    return f"lib{original}.so"


class Elf64:
    """Just enough ELF64 to find .dynamic, resolve DT_STRTAB and edit strings."""

    def __init__(self, path: str):
        self.path = path
        with open(path, "rb") as fh:
            self.data = bytearray(fh.read())
        if self.data[:4] != b"\x7fELF" or self.data[4] != 2:
            raise ValueError(f"{path}: not an ELF64 file")
        if self.data[5] != 1:
            raise ValueError(f"{path}: only little-endian is supported")
        self.e_phoff = struct.unpack_from("<Q", self.data, 0x20)[0]
        self.e_phentsize = struct.unpack_from("<H", self.data, 0x36)[0]
        self.e_phnum = struct.unpack_from("<H", self.data, 0x38)[0]

    def _program_headers(self):
        for i in range(self.e_phnum):
            off = self.e_phoff + i * self.e_phentsize
            p_type, _flags = struct.unpack_from("<II", self.data, off)
            p_offset, p_vaddr = struct.unpack_from("<QQ", self.data, off + 0x08)
            p_filesz = struct.unpack_from("<Q", self.data, off + 0x20)[0]
            yield p_type, p_offset, p_vaddr, p_filesz

    def _vaddr_to_offset(self, vaddr: int) -> int | None:
        # PT_LOAD segments are the only ones that map file content.
        for p_type, p_offset, p_vaddr, p_filesz in self._program_headers():
            if p_type == 1 and p_vaddr <= vaddr < p_vaddr + p_filesz:
                return p_offset + (vaddr - p_vaddr)
        return None

    def _dynamic(self):
        for p_type, p_offset, _vaddr, p_filesz in self._program_headers():
            if p_type == 2:  # PT_DYNAMIC
                return p_offset, p_filesz
        raise ValueError(f"{self.path}: no PT_DYNAMIC segment")

    def _entries(self):
        off, size = self._dynamic()
        for i in range(size // 16):
            tag, val = struct.unpack_from("<qQ", self.data, off + i * 16)
            if tag == 0:  # DT_NULL
                break
            yield tag, val

    def _strtab_offset(self) -> int:
        for tag, val in self._entries():
            if tag == DT_STRTAB:
                offset = self._vaddr_to_offset(val)
                if offset is None:
                    raise ValueError(f"{self.path}: DT_STRTAB {val:#x} is unmapped")
                return offset
        raise ValueError(f"{self.path}: no DT_STRTAB")

    def _read_str(self, base: int, index: int) -> str:
        end = self.data.index(b"\0", base + index)
        return self.data[base + index:end].decode()

    def rewrite(self, renames: dict[str, str]) -> list[tuple[str, str]]:
        """Overwrite DT_SONAME/DT_NEEDED names in place. Returns what changed."""
        base = self._strtab_offset()
        changed: list[tuple[str, str]] = []
        for tag, val in self._entries():
            if tag not in (DT_NEEDED, DT_SONAME):
                continue
            current = self._read_str(base, val)
            replacement = renames.get(current)
            if replacement is None or replacement == current:
                continue
            if len(replacement) != len(current):
                raise ValueError(
                    f"{self.path}: {current!r} -> {replacement!r} changes length; "
                    "the in-place rewrite requires equal-length names"
                )
            start = base + val
            self.data[start:start + len(replacement)] = replacement.encode()
            changed.append((current, replacement))
        return changed

    def save(self, path: str) -> None:
        with open(path, "wb") as fh:
            fh.write(self.data)
        os.chmod(path, 0o755)


def main() -> int:
    if len(sys.argv) != 3:
        print(__doc__)
        print("usage: jnilib-name.py <prefix-dir> <jnilibs-out-dir>", file=sys.stderr)
        return 2
    prefix, out = sys.argv[1], sys.argv[2]

    sources: dict[str, str] = {}
    for sub in ("bin", "lib"):
        directory = os.path.join(prefix, sub)
        if not os.path.isdir(directory):
            continue
        for name in sorted(os.listdir(directory)):
            path = os.path.join(directory, name)
            if os.path.isfile(path) and not os.path.islink(path):
                sources[name] = path
    if not sources:
        print(f"no binaries under {prefix}/bin or {prefix}/lib", file=sys.stderr)
        return 1

    renames = {name: jni_name(name) for name in sources}
    collisions = {}
    for original, new in renames.items():
        collisions.setdefault(new, []).append(original)
    for new, originals in collisions.items():
        if len(originals) > 1:
            print(f"name collision: {originals} all map to {new}", file=sys.stderr)
            return 1

    os.makedirs(out, exist_ok=True)
    for stale in os.listdir(out):
        os.remove(os.path.join(out, stale))

    patched = 0
    for original, path in sources.items():
        target = os.path.join(out, renames[original])
        shutil.copy(path, target)
        try:
            elf = Elf64(target)
        except ValueError as exc:
            print(f"  skipping non-ELF {original}: {exc}", file=sys.stderr)
            continue
        changed = elf.rewrite(renames)
        elf.save(target)
        patched += len(changed)
        print(f"  {original} -> {renames[original]} ({len(changed)} refs rewritten)")

    print(f"{len(sources)} files, {patched} linkage references rewritten -> {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
