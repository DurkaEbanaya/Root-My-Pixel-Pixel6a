#!/usr/bin/env python3
"""Patch a kernel module .ko: turn SHN_UNDEF imports into SHN_ABS symbols
with runtime kernel addresses, so insmod needs no ksymtab exports.

Usage: patch_ko.py <in.ko> <out.ko> <ksym.tsv> <slide_hex>
ksym.tsv lines: "<linkaddr_hex>\\t<name>"; runtime addr = link + slide.
"""
import sys
from elftools.elf.elffile import ELFFile

def main(inp, outp, ksympath, slide):
    slide = int(slide, 16)
    ksym = {}
    with open(ksympath) as f:
        for line in f:
            line = line.rstrip("\n")
            if not line:
                continue
            addr, name = line.split("\t", 1)
            ksym.setdefault(name, int(addr, 16))
    with open(inp, "rb") as f:
        data = bytearray(f.read())
        e = ELFFile(io_bytes := __import__("io").BytesIO(bytes(data)))
        symtab = e.get_section_by_name(".symtab")
        shdr_off = e.header.e_shoff
        shentsize = e.header.e_shentsize
        patched = 0
        missing = []
        for i, sym in enumerate(symtab.iter_symbols()):
            if sym.name and sym["st_shndx"] == "SHN_UNDEF":
                link = ksym.get(sym.name)
                if link is None:
                    missing.append(sym.name)
                    continue
                runtime = link + slide
                off = symtab.header.sh_offset + i * symtab.header.sh_entsize
                st_name, st_info, st_other, st_shndx, st_value, st_size = __import__("struct").unpack("<IBBHQQ", bytes(data[off:off+24]))
                # SHN_ABS = 0xfff1
                new = __import__("struct").pack("<IBBHQQ", st_name, st_info, st_other, 0xfff1, runtime, st_size)
                data[off:off+24] = new
                patched += 1
        with open(outp, "wb") as g:
            g.write(bytes(data))
        print(f"patched={patched} missing={len(missing)}")
        if missing:
            for m in missing:
                print("MISSING:", m)
        return 0 if not missing else 3

if __name__ == "__main__":
    sys.exit(main(sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]))
