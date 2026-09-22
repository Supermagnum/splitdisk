#!/usr/bin/env python3
"""Inspect GPT + FAT32 ESP of a SplitDisk base image (no mounts)."""
import struct
import sys
import uuid

path = sys.argv[1]
with open(path, "rb") as f:
    f.seek(512)
    hdr = f.read(92)
    print("gpt", hdr[0:8])
    part_lba = int.from_bytes(hdr[72:80], "little")
    f.seek(part_lba * 512)
    for i in range(2):
        e = f.read(128)
        type_guid = uuid.UUID(bytes_le=e[0:16])
        name = e[56:128].decode("utf-16le").rstrip("\x00")
        first = int.from_bytes(e[32:40], "little")
        last = int.from_bytes(e[40:48], "little")
        attrs = int.from_bytes(e[48:56], "little")
        print(f"part{i+1}", type_guid, repr(name), "lba", first, last, "attrs", hex(attrs))
    esp = 2048 * 512
    f.seek(esp)
    bpb = f.read(512)
    bps = int.from_bytes(bpb[11:13], "little")
    spc = bpb[13]
    reserved = int.from_bytes(bpb[14:16], "little")
    nfats = bpb[16]
    fatsz = int.from_bytes(bpb[36:40], "little")
    root = int.from_bytes(bpb[44:48], "little")
    fat0 = esp + reserved * bps
    data = esp + (reserved + nfats * fatsz) * bps
    print("fat32", "bps", bps, "spc", spc, "root", root, "fat0", fat0, "data", data)

    def read_cluster(c):
        f.seek(data + (c - 2) * spc * bps)
        return f.read(spc * bps)

    def fat_next(c):
        f.seek(fat0 + c * 4)
        return int.from_bytes(f.read(4), "little") & 0x0FFFFFFF

    def list_dir(start):
        blob = b""
        c = start
        while 2 <= c < 0x0FFFFFF8:
            blob += read_cluster(c)
            c = fat_next(c)
        ents = []
        i = 0
        lfn = []
        while i + 32 <= len(blob):
            e = blob[i : i + 32]
            i += 32
            if e[0] == 0:
                break
            if e[0] == 0xE5:
                continue
            attr = e[11]
            if attr == 0x0F:
                chars = e[1:11] + e[14:26] + e[28:32]
                s = ""
                for j in range(0, len(chars), 2):
                    code = int.from_bytes(chars[j : j + 2], "little")
                    if code in (0, 0xFFFF):
                        break
                    s += chr(code)
                lfn.append((e[0] & 0x1F, s))
                continue
            name83 = e[0:11].decode("ascii", "replace")
            long = "".join(s for _, s in sorted(lfn, reverse=True)) if lfn else name83
            lfn = []
            cl = int.from_bytes(e[26:28], "little") | (int.from_bytes(e[20:22], "little") << 16)
            sz = int.from_bytes(e[28:32], "little")
            ents.append((long.strip(), name83, attr, cl, sz))
        return ents

    root_ents = list_dir(root)
    print("ROOT", root_ents)
    for long, n83, attr, cl, sz in root_ents:
        if attr & 0x10:
            print("DIR", long, list_dir(cl))
            for long2, n832, attr2, cl2, sz2 in list_dir(cl):
                if attr2 & 0x10:
                    print("  SUB", long2, list_dir(cl2))
