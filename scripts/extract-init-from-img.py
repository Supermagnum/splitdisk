#!/usr/bin/env python3
"""Extract /init from a SplitDisk image ESP initramfs and describe it."""
import gzip
import sys

path = sys.argv[1]
esp = 2048 * 512
with open(path, "rb") as f:
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


def read_cluster(f, c):
    f.seek(data + (c - 2) * spc * bps)
    return f.read(spc * bps)


def fat_next(f, c):
    f.seek(fat0 + c * 4)
    return int.from_bytes(f.read(4), "little") & 0x0FFFFFFF


def list_dir(f, start):
    blob = b""
    c = start
    while 2 <= c < 0x0FFFFFF8:
        blob += read_cluster(f, c)
        c = fat_next(f, c)
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
        ents.append((long.strip(), attr, cl, sz))
    return ents


def read_file(f, start, size):
    out = b""
    c = start
    while 2 <= c < 0x0FFFFFF8 and len(out) < size:
        out += read_cluster(f, c)
        c = fat_next(f, c)
    return out[:size]


with open(path, "rb") as f:
    initrd = None
    for long, attr, cl, sz in list_dir(f, root):
        if attr & 0x10 and long.lower() in ("boot", "boot       ".strip()):
            for long2, attr2, cl2, sz2 in list_dir(f, cl):
                if "initramfs" in long2.lower():
                    initrd = read_file(f, cl2, sz2)
                    print("found initramfs", long2, len(initrd))
    if initrd is None:
        print("ROOT", list_dir(f, root))
        raise SystemExit("no initramfs")

raw = gzip.decompress(initrd)
off = 0
while off + 110 <= len(raw):
    magic = raw[off : off + 6]
    if magic not in (b"070701", b"070702"):
        break
    namesize = int(raw[off + 94 : off + 102], 16)
    filesize = int(raw[off + 54 : off + 62], 16)
    mode = int(raw[off + 14 : off + 22], 16)
    name_off = off + 110
    name = raw[name_off : name_off + namesize - 1].decode()
    data_off = (name_off + namesize + 3) // 4 * 4
    if name in ("init", "TRAILER!!!"):
        print("CPIO", repr(name), "mode", oct(mode), "size", filesize)
        if name == "init":
            data = raw[data_off : data_off + filesize]
            open("/tmp/init.bin", "wb").write(data)
            print("init magic", data[:4], "banner?", data[:40])
            print("matches stub", open("/usr/local/share/splitdisk/init-stub", "rb").read() == data)
            print("synthetic banner", data.startswith(b"SPLITDISK-SYNTHETIC"))
    if name == "TRAILER!!!":
        break
    off = (data_off + filesize + 3) // 4 * 4
