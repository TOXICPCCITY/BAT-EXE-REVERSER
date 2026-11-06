#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
rex_extract.py - statically unpack "REX AIM OPTI V2.0.exe"

What it does
------------
1. Parses the PE resource directory (pure standard library, no pefile).
2. Dumps every resource (icon, manifest, RCDATA, ...) to an output folder.
3. Tries zlib on every RCDATA block (the password config is zlib).
4. Tries RC4 on every larger RCDATA block with the recovered key and saves
   anything that decrypts to readable text (that is the embedded .bat).

NOTHING IS EXECUTED. The .bat is written as .txt on purpose.

Usage
-----
    python rex_extract.py "REX AIM OPTI V2.0.com"
    python rex_extract.py "EXAMPLE.EXE" -o my_folder
    python rex_extract.py "EXAMPLE.EXE" --key 2ED6C2B522EF7B4390E9F2BF61FD3F1A

By default the output folder is "<exe name>_extracted".
"""

import argparse
import hashlib
import os
import struct
import sys
import zlib

DEFAULT_EXE = "REX AIM OPTI V2.0.com"
NAME_CANDIDATES = [
    "REX AIM OPTI V2.0.exe",
    "REX AIM OPTI V2.0.com",
    "REX AIM OPTI V2.0",
]

# RC4 key recovered from the stub.
# The stub stores it lowercase and calls CharUpperW before using it,
# so the effective key is the uppercase form.
DEFAULT_KEY = "2ED6C2B522EF7B4390E9F2BF61FD3F1A"

RT_NAMES = {
    1: "CURSOR", 2: "BITMAP", 3: "ICON", 4: "MENU", 5: "DIALOG",
    6: "STRING", 7: "FONTDIR", 8: "FONT", 9: "ACCELERATOR", 10: "RCDATA",
    11: "MESSAGETABLE", 12: "GROUP_CURSOR", 14: "GROUP_ICON", 16: "VERSION",
    17: "DLGINCLUDE", 19: "PLUGPLAY", 20: "VXD", 21: "ANICURSOR",
    22: "ANIICON", 23: "HTML", 24: "MANIFEST",
}


def u16(b, o):
    return struct.unpack_from("<H", b, o)[0]


def u32(b, o):
    return struct.unpack_from("<I", b, o)[0]


def u64(b, o):
    return struct.unpack_from("<Q", b, o)[0]


class PE(object):
    def __init__(self, data):
        self.data = data
        if data[:2] != b"MZ":
            raise ValueError("not an MZ/PE file")
        e_lfanew = u32(data, 0x3C)
        if data[e_lfanew:e_lfanew + 4] != b"PE\x00\x00":
            raise ValueError("missing PE signature")

        coff = e_lfanew + 4
        (self.machine, self.nsec, _ts, _sym, _nsym, self.opt_size,
         self.characteristics) = struct.unpack_from("<HHIIIHH", data, coff)

        opt = coff + 20
        self.magic = u16(data, opt)
        if self.magic == 0x20B:                     # PE32+
            self.image_base = u64(data, opt + 24)
            ndd_off = opt + 108
            self.dd = opt + 112
        elif self.magic == 0x10B:                   # PE32
            self.image_base = u32(data, opt + 28)
            ndd_off = opt + 92
            self.dd = opt + 96
        else:
            raise ValueError("unknown optional header magic 0x%X" % self.magic)

        self.nrva = u32(data, ndd_off)
        self.size_of_image = u32(data, opt + 56)

        self.sections = []
        sec = opt + self.opt_size
        for i in range(self.nsec):
            o = sec + i * 40
            name = data[o:o + 8].rstrip(b"\x00").decode("latin-1", "replace")
            vsize, va, rawsize, rawptr = struct.unpack_from("<IIII", data, o + 8)
            self.sections.append((name, va, vsize, rawptr, rawsize))

    def rva2off(self, rva):
        for _name, va, vsize, rawptr, rawsize in self.sections:
            if va <= rva < va + max(vsize, rawsize):
                delta = rva - va
                return rawptr + delta if delta < rawsize else None
        return None

    def resource_root(self):
        if self.nrva < 3:
            return 0
        return u32(self.data, self.dd + 2 * 8)


def walk_resources(pe, base, rel, path, out):
    """Recursively collect (path, blob, codepage) from the resource tree."""
    off = pe.rva2off(base + rel)
    if off is None:
        return
    d = pe.data
    n_named = u16(d, off + 12)
    n_id = u16(d, off + 14)

    for i in range(n_named + n_id):
        e = off + 16 + i * 8
        name_field = u32(d, e)
        data_field = u32(d, e + 4)

        if name_field & 0x80000000:
            no = pe.rva2off(base + (name_field & 0x7FFFFFFF))
            if no is None:
                continue
            nlen = u16(d, no)
            name = d[no + 2:no + 2 + nlen * 2].decode("utf-16-le", "replace")
        else:
            name = str(name_field)

        if data_field & 0x80000000:
            walk_resources(pe, base, data_field & 0x7FFFFFFF, path + [name], out)
        else:
            de = pe.rva2off(base + data_field)
            if de is None:
                continue
            rva = u32(d, de)
            size = u32(d, de + 4)
            codepage = u32(d, de + 8)
            do = pe.rva2off(rva)
            blob = d[do:do + size] if do is not None else b""
            out.append((path + [name], blob, codepage))


def rc4(key, data):
    S = list(range(256))
    j = 0
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) & 0xFF
        S[i], S[j] = S[j], S[i]
    i = j = 0
    out = bytearray(len(data))
    for n, byte in enumerate(data):
        i = (i + 1) & 0xFF
        j = (j + S[i]) & 0xFF
        S[i], S[j] = S[j], S[i]
        out[n] = byte ^ S[(S[i] + S[j]) & 0xFF]
    return bytes(out)


def is_text(blob):
    if len(blob) < 32:
        return False
    sample = blob[:4096]
    good = sum(1 for c in sample if c in (9, 10, 13) or 32 <= c < 127)
    return good / float(len(sample)) >= 0.97 and (b"\n" in sample)


def safe_name(s):
    keep = "-_.() []{}!@#$%^&+=,;"
    return "".join(c if (c.isalnum() or c in keep) else "_" for c in str(s))


def find_default_exe():
    for name in NAME_CANDIDATES:
        if os.path.isfile(name):
            return name
    for name in sorted(os.listdir(".")):
        low = name.lower()
        if low.endswith((".exe", ".com")) and "rex" in low and "opti" in low:
            return name
    return DEFAULT_EXE


def main():
    ap = argparse.ArgumentParser(description="Statically unpack REX AIM OPTI V2.0.exe")
    ap.add_argument("exe", nargs="?", default=None)
    ap.add_argument("-o", "--outdir", default=None)
    ap.add_argument("-k", "--key", default=DEFAULT_KEY,
                    help="RC4 key (default: the one recovered from the stub)")
    args = ap.parse_args()

    if args.exe is None:
        args.exe = find_default_exe()

    if not os.path.isfile(args.exe):
        sys.exit("error: file not found: %s" % args.exe)

    if args.outdir is None:
        stem = os.path.splitext(os.path.basename(args.exe))[0]
        args.outdir = stem + "_extracted"

    data = open(args.exe, "rb").read()
    pe = PE(data)

    print("file      : %s" % args.exe)
    print("size      : %d bytes" % len(data))
    print("sha256    : %s" % hashlib.sha256(data).hexdigest())
    print("machine   : 0x%04X  image base: 0x%X" % (pe.machine, pe.image_base))

    root = pe.resource_root()
    if not root:
        sys.exit("no resource directory found")

    resources = []
    walk_resources(pe, root, 0, [], resources)

    os.makedirs(args.outdir, exist_ok=True)
    print("\n%-10s %-42s %-4s %8s" % ("TYPE", "NAME", "LANG", "SIZE"))
    print("-" * 70)

    decrypted_files = []
    for path, blob, _cp in resources:
        rtype, rname, rlang = (path + ["", "", ""])[:3]
        try:
            type_id = int(rtype)
        except ValueError:
            type_id = -1
        type_name = RT_NAMES.get(type_id, rtype)

        fname = "%s__%s__%s.bin" % (safe_name(type_name),
                                     safe_name(rname),
                                     safe_name(rlang))
        with open(os.path.join(args.outdir, fname), "wb") as f:
            f.write(blob)
        print("%-10s %-42s %-4s %8d" % (type_name, rname, rlang, len(blob)))

        # ---- bonus 1: zlib members (password config) ----
        if blob[:1] == b"\x78":
            try:
                inf = zlib.decompress(blob)
                zname = "%s__%s__%s.inflated.bin" % (
                    safe_name(type_name), safe_name(rname), safe_name(rlang))
                open(os.path.join(args.outdir, zname), "wb").write(inf)
                print("    zlib   -> %s (%d bytes)" % (zname, len(inf)))
            except zlib.error:
                pass

        # ---- bonus 2: RC4-encrypted text (the batch) ----
        if type_name == "RCDATA" and len(blob) >= 256:
            keys = [args.key, args.key.upper(), args.key.lower()]
            try:
                keys.append(bytes.fromhex(args.key))
            except ValueError:
                pass
            for k in keys:
                pt = rc4(k.encode() if isinstance(k, str) else k, blob)
                if is_text(pt):
                    tname = "DECRYPTED__%s.txt" % safe_name(rname)
                    outpath = os.path.join(args.outdir, tname)
                    open(outpath, "wb").write(pt)
                    decrypted_files.append((outpath, pt))
                    print("    RC4    -> %s (%d bytes, key %r)"
                          % (tname, len(pt), k if isinstance(k, str) else k.hex()))
                    break

    print("\ndone. resources written to: %s" % os.path.abspath(args.outdir))
    if decrypted_files:
        print("\nrecovered text:")
        for p, pt in decrypted_files:
            first = pt.splitlines()[0][:60] if pt.splitlines() else b""
            print("  %s" % p)
            print("    first line: %r" % first)
            print("    sha256    : %s" % hashlib.sha256(pt).hexdigest())
        print("\nNOTE: the recovered file is saved with a .txt extension so it")
        print("      cannot be run by accident. Review it before renaming.")
    else:
        print("\nNo RC4 text payload found with that key. Try --key <HEX>.")


if __name__ == "__main__":
    main()
