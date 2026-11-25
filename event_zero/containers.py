"""Container interiors for coverage wave 1: disk images, virtual
disks, firmware filesystems, and OS package formats.

Design law (the same accounting law as verdict.py): a container the
engine accepts is enumerated to the bottom, or it is refused by
name. Every function here either returns the complete member map
({member name: bytes}) or raises ValueError with the unenumerated
interior named in the message. Nothing here mounts or executes a
member: members are written out by the caller under the same
path-traversal and size guards as zip and tar members, and each
member then receives its own verdict as a loose file.

Parsers are pure Python and read-only: ISO 9660 (Joliet names where
a supplementary descriptor is present), FAT12/16/32, ext2/3/4, MBR
and GPT partition tables, fixed and dynamic VHD, dynamic VHDX,
QCOW2 (uncompressed clusters, no backing file), DMG (raw, zerofill
and zlib chunks), SquashFS (zlib and xz blocks, fragments included),
CRAMFS, JFFS2 (none, zero and zlib node compression), deb (ar plus
tar control and data members, maintainer scripts included), RPM
(lead and header structures plus a cpio payload, scriptlets
included), and Alpine APK (concatenated gzip-stream tar format).
Interiors with no parser here (NTFS partitions, UBIFS indexes,
differencing disks, compressed QCOW2 clusters, data-carrying DMG
chunk types other than raw and zlib) raise, naming the interior,
so the verdict caps the unit instead of passing it.
"""
import gzip, io, lzma, plistlib, struct, tarfile, uuid, zlib

MAX_MEMBERS = 10000
MAX_TOTAL_BYTES = 512 * 1024 * 1024


def _check_total(members):
    if len(members) > MAX_MEMBERS:
        raise ValueError(f"container has {len(members)} members, past the enumeration limit of {MAX_MEMBERS}: the members past the limit cannot be enumerated, so this container is unaccounted")
    total = sum(len(b) for b in members.values())
    if total > MAX_TOTAL_BYTES:
        raise ValueError("container expands past the size limit, so its interior cannot be fully enumerated")
    return members


def _u16(b, o): return struct.unpack_from("<H", b, o)[0]
def _u32(b, o): return struct.unpack_from("<I", b, o)[0]
def _u64(b, o): return struct.unpack_from("<Q", b, o)[0]
def _be32(b, o): return struct.unpack_from(">I", b, o)[0]
def _be64(b, o): return struct.unpack_from(">Q", b, o)[0]


# ---------------------------------------------------------------- ISO 9660

def _iso_dir_records(data, lba, size, sector):
    out = []
    end = lba * sector + size
    pos = lba * sector
    while pos < end:
        ln = data[pos] if pos < len(data) else 0
        if ln == 0:
            pos = (pos // sector + 1) * sector
            continue
        if ln < 34 or pos + ln > len(data):
            raise ValueError("ISO 9660 directory record is malformed, so the disc directory cannot be fully enumerated")
        rec = data[pos:pos + ln]
        if rec[26] or rec[27]:
            raise ValueError("ISO 9660 file is interleaved, which this build cannot enumerate")
        flags = rec[25]
        if flags & 0x80:
            raise ValueError("ISO 9660 file spans multiple extents, which this build cannot enumerate")
        nlen = rec[32]
        out.append((rec[33:33 + nlen], _u32(rec, 2), _u32(rec, 10), flags))
        pos += ln
    return out


def _iso_walk(data, lba, size, sector, prefix, members, depth):
    if depth > 32:
        raise ValueError("ISO 9660 directory nesting is past the enumeration depth limit")
    for name, extent, dlen, flags in _iso_dir_records(data, lba, size, sector):
        if name in (b"\x00", b"\x01"):
            continue
        if len(name) >= 2 and name[1:2] == b"\x00":
            text = name.decode("utf-16-be", "replace")
        else:
            text = name.decode("latin-1")
        if ";" in text and not (flags & 2):
            text = text.split(";")[0]
        rel = prefix + text
        if flags & 2:
            _iso_walk(data, extent, dlen, sector, rel + "/", members, depth + 1)
        else:
            start = extent * sector
            if start + dlen > len(data):
                raise ValueError(f"ISO 9660 member {rel} extends past the end of the image, so the disc cannot be fully enumerated")
            members[rel] = data[start:start + dlen]
    return members


def parse_iso(data):
    sector = 2048
    pvd = None
    joliet = None
    has_udf = False
    for i in range(16, 512):
        off = i * sector
        if off + 7 > len(data):
            break
        desc = data[off:off + sector]
        if desc[1:6] != b"CD001":
            break
        if desc[0] == 255:
            break
        if desc[0] == 0 and desc[40:45] == b"BEA01":
            has_udf = True
        if desc[0] == 2 and desc[40:45] == b"NSR02":
            has_udf = True
        if desc[0] == 1 and pvd is None:
            pvd = desc
        if desc[0] == 2 and desc[88:91] in (b"%/@", b"%/C", b"%/E"):
            joliet = desc
    if pvd is None:
        if has_udf:
            raise ValueError("this disc carries a UDF filesystem and no ISO 9660 volume this build can read: the UDF interior is unenumerated, so the disc is unaccounted")
        raise ValueError("no ISO 9660 primary volume descriptor found, so the disc interior cannot be enumerated")
    use = joliet or pvd
    root = use[156:156 + 34]
    members = _iso_walk(data, _u32(root, 2), _u32(root, 10), sector, "", {}, 0)
    return _check_total(members)


# ---------------------------------------------------------------- filesystems

def _fat_members(img):
    bps = _u16(img, 11)
    spc = img[13]
    reserved = _u16(img, 14)
    nfats = img[16]
    root_entries = _u16(img, 17)
    fatsz16 = _u16(img, 22)
    fatsz32 = _u32(img, 36)
    fatsz = fatsz16 or fatsz32
    if bps < 128 or bps > 4096 or spc == 0 or nfats == 0 or fatsz == 0:
        raise ValueError("FAT boot sector fields are implausible, so the filesystem cannot be enumerated")
    fat_off = reserved * bps
    root_dir_off = fat_off + nfats * fatsz * bps
    root_dir_bytes = root_entries * 32
    data_off = root_dir_off + root_dir_bytes
    if fatsz16:
        total_clusters = (len(img) - data_off) // (spc * bps)
        fat_bits = 12 if total_clusters < 4085 else 16
    else:
        fat_bits = 32
    fat = img[fat_off:fat_off + fatsz * bps]

    def next_cluster(c):
        if fat_bits == 12:
            o = c + c // 2
            if o + 2 > len(fat):
                return 0xFFF
            v = _u16(fat, o)
            return (v >> 4) & 0xFFF if c & 1 else v & 0xFFF
        if fat_bits == 16:
            return _u16(fat, c * 2) if c * 2 + 2 <= len(fat) else 0xFFFF
        return _u32(fat, c * 4) & 0x0FFFFFFF if c * 4 + 4 <= len(fat) else 0x0FFFFFFF

    def eoc(c):
        return c >= (0xFF8 if fat_bits == 12 else 0xFFF8 if fat_bits == 16 else 0x0FFFFFF8)

    def read_chain(first, size):
        out = bytearray()
        c = first
        seen = set()
        while 2 <= c and not eoc(c) and c not in seen:
            seen.add(c)
            start = data_off + (c - 2) * spc * bps
            out += img[start:start + spc * bps]
            c = next_cluster(c)
        return bytes(out[:size])

    members = {}

    def walk(dir_bytes, prefix, depth):
        if depth > 32:
            raise ValueError("FAT directory nesting is past the enumeration depth limit")
        i = 0
        lfn = ""
        while i + 32 <= len(dir_bytes):
            ent = dir_bytes[i:i + 32]
            i += 32
            if ent[0] == 0x00:
                return
            if ent[0] == 0xE5:
                lfn = ""
                continue
            attr = ent[11]
            if attr == 0x0F:
                chars = ent[1:11] + ent[14:26] + ent[28:32]
                lfn = chars.decode("utf-16-le", "ignore").split("\x00")[0] + lfn
                continue
            raw = ent[0:8].decode("latin-1").rstrip()
            ext = ent[8:11].decode("latin-1").rstrip()
            name = lfn or (raw + ("." + ext if ext else ""))
            lfn = ""
            if name in (".", ".."):
                continue
            size = _u32(ent, 28)
            first = _u16(ent, 26)
            if fat_bits == 32:
                first |= _u16(ent, 20) << 16
            rel = prefix + name
            if attr & 0x10:
                walk(read_chain(first, 1 << 31), rel + "/", depth + 1)
            else:
                members[rel] = read_chain(first, size) if first >= 2 else b""

    if fat_bits == 32:
        walk(read_chain(_u32(img, 44), 1 << 31), "", 0)
    else:
        walk(img[root_dir_off:root_dir_off + root_dir_bytes], "", 0)
    return members


def _ext_members(img):
    if len(img) < 2048 or img[1080:1082] != b"\x53\xef":
        raise ValueError("ext superblock magic not found, so the filesystem cannot be enumerated")
    sb = img[1024:2048]
    inodes_count = _u32(sb, 0)
    block = 1024 << _u32(sb, 24)
    inodes_per_group = _u32(sb, 40)
    rev = _u32(sb, 76)
    inode_size = _u16(sb, 88) if rev >= 1 else 128
    incompat = _u32(sb, 96)
    desc_size = _u16(sb, 254) if rev >= 1 else 32
    if desc_size < 32:
        desc_size = 32
    gdt_off = 2048 if block == 1024 else block
    use_64 = bool(incompat & 0x80)

    def block_bytes(n):
        return img[n * block:(n + 1) * block]

    def inode_table_block(group):
        off = gdt_off + group * desc_size
        lo = _u32(img, off + 8)
        hi = _u32(img, off + 40) if use_64 and desc_size >= 64 else 0
        return lo | (hi << 32)

    cache = {}

    def read_inode(num):
        if num in cache:
            return cache[num]
        if num < 1 or num > inodes_count:
            raise ValueError(f"ext inode {num} is out of range, so the filesystem cannot be fully enumerated")
        group = (num - 1) // inodes_per_group
        idx = (num - 1) % inodes_per_group
        off = inode_table_block(group) * block + idx * inode_size
        raw = img[off:off + inode_size]
        if len(raw) < 128:
            raise ValueError("ext inode table is truncated, so the filesystem cannot be fully enumerated")
        mode = _u16(raw, 0)
        size = _u32(raw, 4)
        if (mode & 0xF000) == 0x8000 and _u32(raw, 108):
            size |= _u32(raw, 108) << 32
        cache[num] = (mode, size, _u32(raw, 32), raw[40:100])
        return cache[num]

    def file_data(num):
        mode, size, flags, bf = read_inode(num)
        out = bytearray()
        if flags & 0x80000:
            magic, _max, _depth_entries, depth = struct.unpack_from("<HHHH", bf, 0)
            if magic != 0xF30A:
                raise ValueError("ext extent header is malformed, so the filesystem cannot be fully enumerated")
            entries = struct.unpack_from("<H", bf, 2)[0]
            nodes = [(bf, entries, depth)]
            leaf = []
            while nodes:
                buf, cnt, d = nodes.pop(0)
                if d == 0:
                    for i in range(cnt):
                        eb, elen, ehi, elo = struct.unpack_from("<IHHI", buf, 12 + i * 12)
                        leaf.append((eb, elen & 0x7FFF, elo | (ehi << 32)))
                else:
                    for i in range(cnt):
                        _ib, lo, hi = struct.unpack_from("<IIH", buf, 12 + i * 12)
                        child = block_bytes(lo | (hi << 32))
                        chdr = struct.unpack_from("<HHH", child, 0)
                        nodes.append((child, chdr[2], d - 1))
            leaf.sort()
            for _eb, elen, start in leaf:
                for k in range(elen):
                    out += block_bytes(start + k)
            return bytes(out[:size])
        ptrs = list(struct.unpack_from("<15I", bf, 0))
        logical = list(ptrs[:12])

        def add_indirect(blk, level):
            if not blk:
                return
            per = block // 4
            for v in struct.unpack_from(f"<{per}I", block_bytes(blk), 0):
                if level == 1:
                    logical.append(v)
                elif v:
                    add_indirect(v, level - 1)

        if ptrs[12]:
            add_indirect(ptrs[12], 1)
        if ptrs[13]:
            add_indirect(ptrs[13], 2)
        if ptrs[14]:
            add_indirect(ptrs[14], 3)
        need = (size + block - 1) // block
        for n in logical[:need]:
            out += block_bytes(n) if n else b"\x00" * block
        return bytes(out[:size])

    members = {}

    def walk(dir_ino, prefix, depth):
        if depth > 32:
            raise ValueError("ext directory nesting is past the enumeration depth limit")
        data = file_data(dir_ino)
        pos = 0
        while pos + 8 <= len(data):
            ino, rec_len, name_len, _ftype = struct.unpack_from("<IHBB", data, pos)
            if rec_len < 8:
                break
            name = data[pos + 8:pos + 8 + name_len].decode("utf-8", "surrogateescape")
            if ino and name not in (".", ".."):
                mode = read_inode(ino)[0]
                rel = prefix + name
                if (mode & 0xF000) == 0x4000:
                    walk(ino, rel + "/", depth + 1)
                elif (mode & 0xF000) == 0x8000:
                    members[rel] = file_data(ino)
            pos += rec_len

    walk(2, "", 0)
    return members


def _fs_members(img, what):
    if len(img) >= 1082 and img[1080:1082] == b"\x53\xef":
        return _ext_members(img)
    if len(img) > 512 and img[3:11] == b"NTFS    ":
        raise ValueError(f"the {what} carries an NTFS filesystem, which this build cannot enumerate: the NTFS interior is unenumerated, so the unit is unaccounted")
    if len(img) > 512 and (img[54:59] in (b"FAT12", b"FAT16") or img[82:87] == b"FAT32"):
        return _fat_members(img)
    raise ValueError(f"the {what} carries a filesystem this build cannot identify or enumerate, so its interior is unenumerated and the unit is unaccounted")


def _disk_members(data):
    if len(data) > 1024 and data[512:520] == b"EFI PART":
        entries_lba = _u64(data, 72)
        entry_count = _u32(data, 80)
        entry_size = _u32(data, 84)
        members = {}
        found = False
        for i in range(entry_count):
            off = entries_lba * 512 + i * entry_size
            ent = data[off:off + entry_size]
            if len(ent) < 48 or ent[:16] == b"\x00" * 16:
                continue
            first, last = _u64(ent, 32), _u64(ent, 40)
            sub = _fs_members(data[first * 512:(last + 1) * 512], f"GPT partition {i + 1}")
            found = True
            for k, v in sub.items():
                members[f"partition{i + 1}/{k}"] = v
        if not found:
            raise ValueError("GPT partition table lists no partitions, so the disk interior cannot be enumerated")
        return _check_total(members)
    if len(data) > 512 and data[510:512] == b"\x55\xaa":
        parts = []
        for i in range(4):
            ent = data[446 + i * 16:446 + i * 16 + 16]
            if ent[4] and _u32(ent, 12):
                parts.append((i, ent[4], _u32(ent, 8), _u32(ent, 12)))
        plausible = [p for p in parts if (p[2] + p[3]) * 512 <= len(data) + 512]
        if plausible:
            members = {}
            for i, ptype, lba, count in plausible:
                sub = _fs_members(data[lba * 512:(lba + count) * 512], f"MBR partition {i + 1} (type 0x{ptype:02x})")
                for k, v in sub.items():
                    members[f"partition{i + 1}/{k}"] = v
            return _check_total(members)
    return _check_total(_fs_members(data, "disk image"))


# ---------------------------------------------------------------- virtual disks

def _vhd_members(data):
    footer = data[-512:]
    if footer[:8] != b"conectix":
        raise ValueError("VHD footer not found, so the virtual disk cannot be enumerated")
    # VHD footer and dynamic header fields are big-endian.
    disk_type = _be32(footer, 60)
    if disk_type == 4:
        raise ValueError("this VHD is a differencing disk whose parent is not in evidence: the merged interior is unenumerated, so the unit is unaccounted")
    if disk_type == 2:
        return _disk_members(data[:-512])
    if disk_type != 3:
        raise ValueError(f"VHD disk type {disk_type} is not one this build can enumerate")
    dyn = data[512:1536]
    if dyn[:8] != b"cxsparse":
        raise ValueError("VHD dynamic header not found, so the virtual disk cannot be enumerated")
    # Dynamic header layout: cookie 0, data offset 8, table (BAT)
    # offset 16, header version 24, max table entries 28, block
    # size 32.
    bat_off = _be64(dyn, 16)
    max_entries = _be32(dyn, 28)
    block_size = _be32(dyn, 32)
    if block_size == 0:
        raise ValueError("VHD dynamic header declares a zero block size, so the virtual disk cannot be enumerated")
    bitmap_bytes = ((block_size // 512) // 8 + 511) // 512 * 512
    disk = bytearray()
    for i in range(max_entries):
        entry = _be32(data, bat_off + i * 4)
        if entry == 0xFFFFFFFF:
            disk += b"\x00" * block_size
            continue
        start = entry * 512 + bitmap_bytes
        disk += data[start:start + block_size]
    return _disk_members(bytes(disk))


_VHDX_BAT_GUID = uuid.UUID("2dc27766-f623-4200-9d64-115e9bfd4a08").bytes_le
_VHDX_META_GUID = uuid.UUID("8b7ca206-4790-4b9a-b8fe-575f050f886e").bytes_le
_VHDX_VSIZE_GUID = uuid.UUID("2fa54224-cd1b-4876-b211-6d9bed83bf4d").bytes_le


def _vhdx_members(data):
    regions = {}
    for table_off in (192 * 1024, 256 * 1024):
        if data[table_off:table_off + 4] != b"regi":
            continue
        count = _u32(data, table_off + 4)
        for i in range(count):
            eoff = table_off + 16 + i * 32
            regions[data[eoff:eoff + 16]] = (_u64(data, eoff + 16), _u32(data, eoff + 24))
        if regions:
            break
    if _VHDX_BAT_GUID not in regions or _VHDX_META_GUID not in regions:
        raise ValueError("VHDX region table lacks a block allocation table or metadata region, so the virtual disk cannot be enumerated")
    meta_off, _mlen = regions[_VHDX_META_GUID]
    if data[meta_off:meta_off + 8] != b"metadata":
        raise ValueError("VHDX metadata region is malformed, so the virtual disk cannot be enumerated")
    # Metadata header: signature 8, reserved u16 at 8, entry count
    # u16 at 10, reserved 20 bytes, entries from offset 32.
    count = _u16(data, meta_off + 10)
    vsize = None
    block_size = 32 * 1024 * 1024
    logical_sector = 512
    four_byte = []
    for i in range(count):
        eoff = meta_off + 32 + i * 32
        guid = data[eoff:eoff + 16]
        off = _u32(data, eoff + 16)
        length = _u32(data, eoff + 20)
        val = data[meta_off + off:meta_off + off + length]
        if length >= 256:
            # Long metadata entries are parent locators: this is a
            # differencing disk and the parent is not in evidence.
            raise ValueError("this VHDX is a differencing disk whose parent is not in evidence (a parent locator is present in its metadata): the merged interior is unenumerated, so the unit is unaccounted")
        if guid == _VHDX_VSIZE_GUID and length == 8:
            vsize = _u64(val, 0)
        elif length == 4:
            four_byte.append(_u32(val, 0))
    # Block size and the sector sizes are all four-byte metadata
    # items. They are told apart by value, which is unambiguous in
    # practice: a block size is a power of two of at least 1 MiB,
    # and a sector size is 512 or 4096.
    for v in four_byte:
        if v in (512, 4096):
            logical_sector = v
        elif v >= 1024 * 1024 and (v & (v - 1)) == 0:
            block_size = v
    if vsize is None:
        raise ValueError("VHDX metadata carries no virtual disk size, so the virtual disk cannot be enumerated")
    bat_off, _blen = regions[_VHDX_BAT_GUID]
    chunk_ratio = (8 * 1024 * 1024 * logical_sector) // block_size
    nblocks = (vsize + block_size - 1) // block_size
    disk = bytearray()
    for i in range(nblocks):
        bat_index = i + (i // chunk_ratio if chunk_ratio else 0)
        entry = _u64(data, bat_off + bat_index * 8)
        state = entry & 0x7
        if state == 0:
            disk += b"\x00" * block_size
            continue
        if state != 6:
            raise ValueError(f"VHDX block {i} is in state {state}, which this build cannot enumerate")
        start = (entry >> 20) << 20
        disk += data[start:start + block_size]
    return _disk_members(bytes(disk[:vsize]))


def _qcow2_members(data):
    backing_off = _be64(data, 8)
    backing_size = _be32(data, 16)
    if backing_off or backing_size:
        raise ValueError("this QCOW2 has a backing file that is not in evidence: the merged interior is unenumerated, so the unit is unaccounted")
    cluster_bits = _be32(data, 20)
    size = _be64(data, 24)
    if _be32(data, 32):
        raise ValueError("this QCOW2 is encrypted, so its interior is unenumerated and the unit is unaccounted")
    l1_size = _be32(data, 36)
    l1_off = _be64(data, 40)
    cluster = 1 << cluster_bits
    l2_entries = cluster // 8
    disk = bytearray()
    remaining = size
    for i in range(l1_size):
        if remaining <= 0:
            break
        l1e = _be64(data, l1_off + i * 8)
        l2_off = l1e & 0x00FFFFFFFFFFFE00
        for j in range(l2_entries):
            if remaining <= 0:
                break
            take = min(cluster, remaining)
            if l2_off == 0:
                disk += b"\x00" * take
                remaining -= take
                continue
            l2e = _be64(data, l2_off + j * 8)
            if l2e & (1 << 62):
                raise ValueError("this QCOW2 uses compressed clusters, which this build cannot enumerate: the interior is unenumerated, so the unit is unaccounted")
            coff = l2e & 0x00FFFFFFFFFFFE00
            disk += data[coff:coff + take] if coff else b"\x00" * take
            remaining -= take
    return _disk_members(bytes(disk))


def _dmg_members(data):
    trailer = data[-512:]
    if trailer[:4] != b"koly":
        raise ValueError("DMG koly trailer not found, so the disk image cannot be enumerated")
    # Koly trailer fields are big-endian.
    xml_off = _be64(trailer, 216)
    xml_len = _be64(trailer, 224)
    if not xml_len or xml_off + xml_len > len(data):
        raise ValueError("DMG carries no readable blkx plist, so the disk image cannot be enumerated")
    try:
        plist = plistlib.loads(data[xml_off:xml_off + xml_len])
        blkx = plist["resource-fork"]["blkx"]
    except Exception as e:
        raise ValueError(f"DMG blkx plist could not be parsed ({e}), so the disk image cannot be enumerated")
    disk = bytearray()
    for entry in blkx:
        blob = entry.get("Data", b"")
        # A blkx data blob is a mish block: a 204-byte header (the
        # block checksum occupies bytes 60 to 196, and the chunk
        # count sits at byte 200) followed by 40-byte chunk records.
        if len(blob) < 204 or blob[:4] != b"mish":
            raise ValueError("DMG blkx entry is malformed, so the disk image cannot be enumerated")
        nchunks = _be32(blob, 200)
        for i in range(nchunks):
            ctype, _comment, sector_no, sector_count, comp_off, comp_len = struct.unpack_from(">IIQQQQ", blob, 204 + i * 40)
            if ctype in (0x00000002, 0x7FFFFFFE, 0xFFFFFFFF):
                continue
            start = sector_no * 512
            raw = data[comp_off:comp_off + comp_len]
            if ctype == 0x00000000:
                out = b"\x00" * (sector_count * 512)
            elif ctype == 0x00000001:
                out = raw
            elif ctype == 0x80000005:
                try:
                    out = zlib.decompress(raw)
                except Exception as e:
                    raise ValueError(f"DMG zlib chunk could not be decompressed ({e}), so the disk image cannot be enumerated")
            else:
                raise ValueError(f"DMG chunk type 0x{ctype:08x} carries data this build cannot decode, so the disk image interior is unenumerated and the unit is unaccounted")
            end = start + len(out)
            if len(disk) < end:
                disk += b"\x00" * (end - len(disk))
            disk[start:end] = out
    return _disk_members(bytes(disk))


# ---------------------------------------------------------------- firmware filesystems

def _meta_stream(data, start, end_limit=None):
    """Read a SquashFS metadata block sequence into one byte stream.
    Returns (stream, end_offset)."""
    out = bytearray()
    pos = start
    limit = end_limit if end_limit is not None else len(data)
    while pos + 2 <= limit:
        hdr = _u16(data, pos)
        pos += 2
        ln = hdr & 0x7FFF
        if ln == 0:
            break
        chunk = data[pos:pos + ln]
        pos += ln
        if hdr & 0x8000:
            out += chunk
        else:
            try:
                out += zlib.decompress(chunk)
            except Exception:
                try:
                    out += lzma.decompress(chunk, format=lzma.FORMAT_ALONE)
                except Exception as e:
                    raise ValueError(f"SquashFS metadata block could not be decompressed ({e}), so the filesystem interior is unenumerated")
    return bytes(out), pos


def _squashfs_members(data, base=0):
    d = data[base:]
    if d[:4] != b"hsqs":
        raise ValueError("SquashFS superblock not found, so the filesystem interior is unenumerated")
    block_size = _u32(d, 12)
    fragments = _u32(d, 16)
    compression = _u16(d, 20)
    # Superblock field offsets (bytes): root_inode 32, bytes_used
    # 40, id_table_start 48, xattr_table_start 56, inode_table_start
    # 64, directory_table_start 72, fragment_table_start 80.
    root_ref = _u64(d, 32)
    inode_start = _u64(d, 64)
    dir_start = _u64(d, 72)
    frag_start = _u64(d, 80)
    if compression not in (1, 2, 4):
        raise ValueError(f"SquashFS compression id {compression} is not one this build can decompress (zlib and xz are): the filesystem interior is unenumerated")

    def decompress_block(chunk, stored_flag):
        if stored_flag:
            return chunk
        if compression in (1, 2):
            return zlib.decompress(chunk)
        return lzma.decompress(chunk, format=lzma.FORMAT_ALONE)

    # The fragment table is an array of 16-byte entries (start
    # block u64, size u32 with a not-compressed flag in bit 24,
    # unused u32) stored in metadata blocks; the table start in the
    # superblock points at an index array of u64 file offsets, one
    # per metadata block of 256 entries.
    frag_entries = []
    if fragments:
        nindex = (fragments + 255) // 256
        index = [_u64(d, frag_start + i * 8) for i in range(nindex)]
        for blk_start in index:
            # Each index entry points at exactly one metadata
            # block holding up to 256 fragment entries.
            hdr = _u16(d, blk_start)
            ln = hdr & 0x7FFF
            chunk = d[blk_start + 2:blk_start + 2 + ln]
            if hdr & 0x8000:
                stream = chunk
            elif compression in (1, 2):
                stream = zlib.decompress(chunk)
            else:
                stream = lzma.decompress(chunk, format=lzma.FORMAT_ALONE)
            for i in range(min(256, len(stream) // 16)):
                frag_entries.append(struct.unpack_from("<QI", stream, i * 16))
        frag_entries = frag_entries[:fragments]

    def fragment_bytes(idx):
        start, size = frag_entries[idx]
        ln = size & 0xFFFFFF
        return decompress_block(d[start:start + ln], bool(size & 0x1000000))

    inode_memo = {}

    def read_inode(ref):
        if ref in inode_memo:
            return inode_memo[ref]
        blk_off = (ref >> 16)
        inner = ref & 0xFFFF
        # An inode reference is (compressed block offset from the
        # inode table start) << 16 | offset inside the decompressed
        # block. Walk the compressed blocks to the referenced one.
        pos = inode_start
        acc = 0
        target = None
        while pos + 2 <= len(d):
            hdr = _u16(d, pos)
            ln = hdr & 0x7FFF
            if acc == blk_off:
                # decompress this block alone
                chunk = d[pos + 2:pos + 2 + ln]
                block_bytes = chunk if (hdr & 0x8000) else zlib.decompress(chunk) if compression in (1, 2) else lzma.decompress(chunk, format=lzma.FORMAT_ALONE)
                target = block_bytes[inner:]
                break
            acc += 2 + ln
            pos += 2 + ln
        if target is None:
            raise ValueError("SquashFS inode reference points outside the inode table, so the filesystem interior cannot be fully enumerated")
        itype = _u16(target, 0)
        inode_memo[ref] = (itype, target)
        return inode_memo[ref]

    def dir_children(ref):
        itype, raw = read_inode(ref)
        if itype in (1, 3):
            # Directory inodes (basic and extended) share the first
            # fields: start_block u32 at 16, file_size u32 at 20,
            # offset u16 at 24.
            start_block = _u32(raw, 16)
            fsize = _u32(raw, 20)
            off = _u16(raw, 24)
        else:
            raise ValueError("SquashFS directory inode has an unexpected type, so the filesystem interior cannot be fully enumerated")
        # Fetch the decompressed directory byte range.
        stream = bytearray()
        pos = dir_start
        acc = 0
        started = False
        need = fsize - 3
        while pos + 2 <= len(d):
            hdr = _u16(d, pos)
            ln = hdr & 0x7FFF
            chunk = d[pos + 2:pos + 2 + ln]
            if acc == start_block:
                started = True
            if started:
                block = chunk if (hdr & 0x8000) else zlib.decompress(chunk) if compression in (1, 2) else lzma.decompress(chunk, format=lzma.FORMAT_ALONE)
                stream += block[off:] if acc == start_block else block
                if len(stream) >= need:
                    break
            acc += 2 + ln
            pos += 2 + ln
        if not started:
            raise ValueError("SquashFS directory reference is outside the directory table, so the filesystem interior cannot be fully enumerated")
        db = bytes(stream[:need])
        out = []
        p = 0
        while p + 12 <= len(db):
            count, gstart, _ino_base = struct.unpack_from("<III", db, p)
            p += 12
            for _ in range(count + 1):
                if p + 8 > len(db):
                    break
                eoff, _delta, etype, esize = struct.unpack_from("<HhHH", db, p)
                p += 8
                name = db[p:p + esize + 1].decode("utf-8", "surrogateescape")
                p += esize + 1
                out.append((name, (gstart << 16) | eoff))
        return out

    def file_bytes(ref):
        itype, raw = read_inode(ref)
        if itype == 2:
            # Basic file inode: start_block u64 at 16, fragment u32
            # at 24, offset u32 at 28, file_size u32 at 32, then the
            # block list at 36.
            start_block, frag, foff, fsize = struct.unpack_from("<QIII", raw, 16)
            nblocks = fsize // block_size
            block_sizes = [struct.unpack_from("<I", raw, 36 + i * 4)[0] for i in range(nblocks)]
        elif itype == 4:
            # Extended file inode: start_block u64 at 16, file_size
            # u64 at 24, sparse u64 at 32, inode_number u32 at 40,
            # fragment u32 at 44, offset u32 at 48, xattr u32 at 52,
            # then the block list at 56.
            start_block = _u64(raw, 16)
            fsize = _u64(raw, 24)
            nblocks = fsize // block_size
            frag = _u32(raw, 44)
            foff = _u32(raw, 48)
            block_sizes = [struct.unpack_from("<I", raw, 56 + i * 4)[0] for i in range(nblocks)]
        else:
            raise ValueError("SquashFS file inode has an unexpected type, so the filesystem interior cannot be fully enumerated")
        out = bytearray()
        pos = start_block
        for sz in block_sizes:
            ln = sz & 0xFFFFFF
            out += decompress_block(d[pos:pos + ln], bool(sz & 0x1000000))
            pos += ln
        if frag != 0xFFFFFFFF:
            tail = fsize - nblocks * block_size
            if tail:
                fb = fragment_bytes(frag)
                out += fb[foff:foff + tail]
        return bytes(out[:fsize])

    members = {}

    def walk(ref, prefix, depth):
        if depth > 32:
            raise ValueError("SquashFS directory nesting is past the enumeration depth limit")
        for name, child_ref in dir_children(ref):
            if name in (".", ".."):
                continue
            itype, _raw = read_inode(child_ref)
            rel = prefix + name
            if itype in (1, 3):
                walk(child_ref, rel + "/", depth + 1)
            elif itype in (2, 4):
                members[rel] = file_bytes(child_ref)
            else:
                raise ValueError(f"SquashFS member {rel} is a special file (inode type {itype}) whose contents cannot be enumerated as a file, so the filesystem is unaccounted")

    walk(root_ref, "", 0)
    return _check_total(members)


def _cramfs_members(data, base=0):
    d = data[base:]
    if _u32(d, 0) != 0x28CD3D45:
        raise ValueError("CRAMFS superblock not found, so the filesystem interior is unenumerated")

    def read_inode(off):
        mode, uid = struct.unpack_from("<HH", d, off)
        packed1 = _u32(d, off + 4)
        size = packed1 & 0xFFFFFF
        packed2 = _u32(d, off + 8)
        namelen = (packed2 & 0x3F) * 4
        data_off = (packed2 >> 6) * 4
        name = d[off + 12:off + 12 + namelen].split(b"\x00")[0].decode("utf-8", "surrogateescape")
        return mode, size, data_off, name, namelen

    def file_bytes(off, size):
        nblocks = (size + 4095) // 4096
        ptrs = [_u32(d, off + i * 4) for i in range(nblocks)]
        out = bytearray()
        start = off + nblocks * 4
        prev = start
        for ptr in ptrs:
            chunk = d[prev:ptr]
            try:
                out += zlib.decompress(chunk)
            except Exception as e:
                raise ValueError(f"CRAMFS data block could not be decompressed ({e}), so the filesystem interior is unenumerated")
            prev = ptr
        return bytes(out[:size])

    members = {}

    def walk(off, size, prefix, depth):
        if depth > 32:
            raise ValueError("CRAMFS directory nesting is past the enumeration depth limit")
        end = off + size
        p = off
        while p + 12 <= end:
            mode, fsize, data_off, name, namelen = read_inode(p)
            p += 12 + namelen
            if not name:
                continue
            rel = prefix + name
            if (mode & 0xF000) == 0x4000:
                walk(data_off, fsize, rel + "/", depth + 1)
            elif (mode & 0xF000) == 0x8000:
                members[rel] = file_bytes(data_off, fsize)
            else:
                raise ValueError(f"CRAMFS member {rel} is a special file whose contents cannot be enumerated as a file, so the filesystem is unaccounted")

    # The root inode sits in the superblock at offset 64 (after
    # magic, size, flags, future, signature, fsid and name).
    root_mode, root_size, root_off, _rn, _nl = read_inode(64)
    walk(root_off, root_size, "", 0)
    return _check_total(members)


def _jffs2_members(data, base=0):
    d = data[base:]
    inodes = {}
    dirents = []
    pos = 0
    while pos + 8 <= len(d):
        magic, ntype, totlen = struct.unpack_from("<HHI", d, pos)
        if magic != 0x1985 or totlen < 8 or pos + totlen > len(d) + 4096:
            pos += 4
            continue
        node = d[pos:pos + totlen]
        if ntype == 0xE002 and len(node) >= 68:  # INODE
            # Node common header is 12 bytes; the inode body runs:
            # ino 12, version 16, mode 20, uid 24, gid 26, isize 28,
            # times 32/36/40, offset 44, csize 48, dsize 52, compr
            # 56, data at 68.
            ino = _u32(node, 12)
            version = _u32(node, 16)
            off = _u32(node, 44)
            csize = _u32(node, 48)
            dsize = _u32(node, 52)
            compr = node[56]
            raw = node[68:68 + csize]
            if compr == 0:
                payload = raw
            elif compr == 1:
                payload = b"\x00" * dsize
            elif compr == 6:
                try:
                    payload = zlib.decompress(raw)
                except Exception:
                    payload = b""
            else:
                raise ValueError(f"JFFS2 inode {ino} uses compression type {compr}, which this build cannot decompress: the filesystem interior is unenumerated")
            key = (ino, off)
            if key not in inodes or version > inodes[key][0]:
                inodes[key] = (version, payload)
        elif ntype == 0xE001 and len(node) >= 40:  # DIRENT
            # Dirent body: pino 12, version 16, ino 20, mctime 24,
            # nsize 28, type 29, name at 40.
            pino = _u32(node, 12)
            ino = _u32(node, 20)
            nsize = node[28]
            name = node[40:40 + nsize].decode("utf-8", "surrogateescape")
            dirents.append((pino, ino, name))
        pos += (totlen + 3) & ~3
    if not dirents and not inodes:
        raise ValueError("no JFFS2 nodes could be parsed, so the filesystem interior is unenumerated")
    files = {}
    for (ino, off), (_ver, payload) in inodes.items():
        buf = files.setdefault(ino, bytearray())
        if len(buf) < off + len(payload):
            buf += b"\x00" * (off + len(payload) - len(buf))
        buf[off:off + len(payload)] = payload
    names = {}
    children = {}
    for pino, ino, name in dirents:
        if ino == 0 or name in (".", ".."):
            continue
        children.setdefault(pino, []).append((ino, name))
    members = {}

    def walk(ino, prefix, depth):
        if depth > 32:
            raise ValueError("JFFS2 directory nesting is past the enumeration depth limit")
        for child, name in children.get(ino, []):
            rel = prefix + name
            if child in children:
                walk(child, rel + "/", depth + 1)
            elif child in files:
                members[rel] = bytes(files[child])
            else:
                raise ValueError(f"JFFS2 member {rel} has a directory entry but no readable content, so the filesystem interior is unenumerated")

    walk(1, "", 0)
    return _check_total(members)


def firmware_regions(data):
    """Locate filesystem regions inside a firmware image. Returns a
    list of {kind, offset, length, label}; length None means the
    region runs to the next region or the end of the image."""
    regions = []
    for magic, kind, label in ((b"hsqs", "squashfs", "SquashFS filesystem"),
                               (b"sqsh", "squashfs-be", "SquashFS filesystem (big-endian)")):
        start = 0
        while True:
            i = data.find(magic, start)
            if i < 0:
                break
            ln = _u64(data, i + 40) if kind == "squashfs" and i + 48 <= len(data) else None
            regions.append({"kind": kind, "offset": i, "length": ln, "label": label})
            start = i + 4
    start = 0
    while True:
        i = data.find(struct.pack("<I", 0x28CD3D45), start)
        if i < 0:
            break
        ln = _u32(data, i + 4) if i + 8 <= len(data) else None
        regions.append({"kind": "cramfs", "offset": i, "length": ln, "label": "CRAMFS filesystem"})
        start = i + 4
    if b"UBI#" in data:
        i = data.find(b"UBI#")
        regions.append({"kind": "ubi", "offset": i, "length": None, "label": "UBI flash image (UBIFS)"})
    start = 0
    jffs_found = False
    while True:
        i = data.find(b"\x85\x19", start)
        if i < 0 or i + 8 > len(data):
            break
        ntype, totlen = struct.unpack_from("<HI", data, i + 2)
        if ntype in (0xE001, 0xE002, 0x2003, 0x2004, 0x2006) and 8 <= totlen <= len(data):
            jffs_found = True
            break
        start = i + 2
    if jffs_found:
        regions.append({"kind": "jffs2", "offset": i, "length": None, "label": "JFFS2 filesystem"})
    regions.sort(key=lambda r: r["offset"])
    return regions


def carve_pe_images(data):
    """Carve valid PE images (UEFI DXE, PEI and SMM drivers) with
    their computed file sizes. Returns [(offset, bytes)]."""
    out = []
    start = 0
    while True:
        i = data.find(b"MZ", start)
        if i < 0:
            break
        start = i + 2
        if i + 0x40 > len(data):
            continue
        peoff = _u32(data, i + 0x3C)
        if not (0 < peoff < 4096) or data[i + peoff:i + peoff + 4] != b"PE\x00\x00":
            continue
        coff = i + peoff + 4
        if coff + 20 > len(data):
            continue
        nsec = _u16(data, coff + 2)
        opt_size = _u16(data, coff + 16)
        sec_off = coff + 20 + opt_size
        size = sec_off - i
        ok = True
        for s in range(nsec):
            so = sec_off + s * 40
            if so + 40 > len(data):
                ok = False
                break
            raw_size = _u32(data, so + 16)
            raw_ptr = _u32(data, so + 20)
            size = max(size, raw_ptr + raw_size)
        if ok and size > 0 and i + size <= len(data):
            out.append((i, data[i:i + size]))
    return out


# ---------------------------------------------------------------- OS packages

def _tar_members(tf, prefix=""):
    members = {}
    for m in tf.getmembers():
        if m.isdir():
            continue
        if not m.isfile():
            raise ValueError(f"package member {m.name} is not a regular file, so the package interior cannot be fully enumerated")
        src = tf.extractfile(m)
        if src is None:
            raise ValueError(f"package member {m.name} could not be read, so the package interior cannot be fully enumerated")
        name = m.name
        while name.startswith("./"):
            name = name[2:]
        members[prefix + name] = src.read()
    return members


def _deb_members(data):
    if data[:8] != b"!<arch>\n":
        raise ValueError("deb ar header not found, so the package interior cannot be enumerated")
    pos = 8
    control = None
    payload = None
    while pos + 60 <= len(data):
        hdr = data[pos:pos + 60]
        if hdr[58:60] != b"`\n":
            break
        name = hdr[0:16].decode("latin-1").strip()
        try:
            size = int(hdr[48:58].decode("latin-1").strip())
        except Exception:
            raise ValueError("deb ar member header is malformed, so the package interior cannot be enumerated")
        body = data[pos + 60:pos + 60 + size]
        base = name.rstrip("/")
        if base.startswith("control.tar"):
            control = (base, body)
        elif base.startswith("data.tar"):
            payload = (base, body)
        pos += 60 + size + (size & 1)
    if payload is None:
        raise ValueError("deb carries no data.tar member, so the package interior cannot be enumerated")
    members = {}
    for label, item in (("control", control), ("data", payload)):
        if item is None:
            continue
        base, body = item
        if ".zst" in base:
            raise ValueError(f"deb {label} archive {base} is zstd compressed, which this build cannot enumerate: the package interior is unenumerated")
        try:
            with tarfile.open(fileobj=io.BytesIO(body), mode="r:*") as tf:
                prefix = "DEBIAN/" if label == "control" else ""
                members.update(_tar_members(tf, prefix))
        except ValueError:
            raise
        except Exception as e:
            raise ValueError(f"deb {label} archive {base} could not be enumerated ({e}), so the package interior is unaccounted")
    return _check_total(members)


def _rpm_header(data, pos):
    if data[pos:pos + 8] != b"\x8e\xad\xe8\x01\x00\x00\x00\x00":
        raise ValueError("RPM header structure is malformed, so the package interior cannot be enumerated")
    count = _be32(data, pos + 8)
    store_bytes = _be32(data, pos + 12)
    entries = []
    for i in range(count):
        tag, typ, off, cnt = struct.unpack_from(">IIII", data, pos + 16 + i * 16)
        entries.append((tag, typ, off, cnt))
    store = data[pos + 16 + count * 16:pos + 16 + count * 16 + store_bytes]
    return entries, store, pos + 16 + count * 16 + store_bytes


def _rpm_string(store, typ, off, cnt):
    if typ == 6:
        end = store.find(b"\x00", off)
        return store[off:end].decode("utf-8", "replace")
    if typ in (8, 9):
        out = []
        p = off
        for _ in range(cnt):
            end = store.find(b"\x00", p)
            out.append(store[p:end].decode("utf-8", "replace"))
            p = end + 1
        return out[0] if out else ""
    return None


_RPM_SCRIPT_TAGS = {1023: "RPMSCRIPT/PREIN", 1024: "RPMSCRIPT/POSTIN", 1025: "RPMSCRIPT/PREUN", 1026: "RPMSCRIPT/POSTUN", 1085: "RPMSCRIPT/PREINPROG", 1086: "RPMSCRIPT/POSTINPROG"}


def _cpio_members(blob):
    members = {}
    pos = 0
    while pos + 110 <= len(blob):
        if blob[pos:pos + 6] != b"070701":
            raise ValueError("RPM payload is not a newc cpio archive this build can enumerate")
        fields = [int(blob[pos + 6 + i * 8:pos + 14 + i * 8], 16) for i in range(13)]
        mode = fields[1]
        filesize = fields[6]
        namesize = fields[11]
        name = blob[pos + 110:pos + 110 + namesize - 1].decode("utf-8", "surrogateescape")
        data_off = pos + 110 + ((namesize + 3) & ~3) if False else pos + ((110 + namesize + 3) & ~3)
        if name == "TRAILER!!!":
            break
        payload = blob[data_off:data_off + filesize]
        if (mode & 0xF000) == 0x8000:
            while name.startswith("./"):
                name = name[2:]
            members[name] = payload
        elif (mode & 0xF000) not in (0x4000, 0xA000, 0):
            raise ValueError(f"RPM payload member {name} is a special file whose contents cannot be enumerated as a file, so the package is unaccounted")
        pos = data_off + ((filesize + 3) & ~3)
    return members


def _rpm_members(data):
    if data[:4] != b"\xed\xab\xee\xdb":
        raise ValueError("RPM lead magic not found, so the package interior cannot be enumerated")
    pos = 96
    _e, _s, pos = _rpm_header(data, pos)
    pos = (pos + 7) & ~7
    entries, store, pos = _rpm_header(data, pos)
    members = {}
    compressor = None
    for tag, typ, off, cnt in entries:
        if tag in _RPM_SCRIPT_TAGS:
            text = _rpm_string(store, typ, off, cnt)
            if text:
                members[_RPM_SCRIPT_TAGS[tag]] = text.encode()
        if tag == 1125:
            compressor = _rpm_string(store, typ, off, cnt)
    payload = data[pos:]
    try:
        if compressor in (None, "none"):
            blob = payload
        elif compressor == "gzip":
            blob = gzip.decompress(payload)
        elif compressor == "xz":
            blob = lzma.decompress(payload, format=lzma.FORMAT_XZ)
        elif compressor == "bzip2":
            import bz2
            blob = bz2.decompress(payload)
        else:
            raise ValueError(f"RPM payload compressor {compressor} is not one this build can enumerate: the package interior is unenumerated")
    except ValueError:
        raise
    except Exception as e:
        raise ValueError(f"RPM payload could not be decompressed ({e}), so the package interior is unenumerated")
    members.update(_cpio_members(blob))
    return _check_total(members)


def _apk_members(data):
    # An Alpine APK is three concatenated gzip streams, each holding
    # one tar archive: signature, control (with .PKGINFO and the
    # maintainer scripts as .pre-install and kin), and data.
    streams = []
    rest = data
    while rest:
        dobj = zlib.decompressobj(31)
        try:
            out = dobj.decompress(rest)
        except Exception as e:
            raise ValueError(f"APK gzip stream could not be decompressed ({e}), so the package interior is unenumerated")
        streams.append(out)
        rest = dobj.unused_data
        if not dobj.eof:
            raise ValueError("APK gzip stream is truncated, so the package interior is unenumerated")
    members = {}
    saw_pkginfo = False
    for blob in streams:
        try:
            with tarfile.open(fileobj=io.BytesIO(blob), mode="r:") as tf:
                for name, content in _tar_members(tf).items():
                    if name == ".PKGINFO":
                        saw_pkginfo = True
                    members[name] = content
        except ValueError:
            raise
        except Exception as e:
            raise ValueError(f"APK tar stream could not be enumerated ({e}), so the package interior is unaccounted")
    if not saw_pkginfo:
        raise ValueError("this gzip-stream package carries no .PKGINFO, so it is not an Alpine APK this build can account")
    return _check_total(members)


# ---------------------------------------------------------------- detection and dispatch

EXTRA_CONTAINER_KINDS = {"iso", "vhd", "vhdx", "qcow2", "dmg", "diskimg",
                         "squashfs", "cramfs", "jffs2", "ubi",
                         "deb", "rpm", "apk"}


def detect_extra_kind(path, data):
    name = str(path).lower()
    if len(data) > 32769 + 6 and data[32769:32774] == b"CD001":
        return "iso"
    if data[:4] == b"QFI\xfb":
        return "qcow2"
    if data[:8] == b"vhdxfile":
        return "vhdx"
    if len(data) >= 512 and data[-512:-504] == b"conectix":
        return "vhd"
    if len(data) >= 512 and data[-512:-508] == b"koly":
        return "dmg"
    if data[:4] == b"hsqs":
        return "squashfs"
    if data[:4] == struct.pack("<I", 0x28CD3D45):
        return "cramfs"
    if data[:8] == b"!<arch>\n" and b"debian-binary" in data[:4096]:
        return "deb"
    if data[:4] == b"\xed\xab\xee\xdb":
        return "rpm"
    if name.endswith(".apk") and data[:2] == b"\x1f\x8b":
        return "apk"
    if b"UBI#" in data[:8192]:
        return "ubi"
    if len(data) > 4 and data[:2] == b"\x85\x19":
        ntype, totlen = struct.unpack_from("<HI", data, 2)
        if ntype in (0xE001, 0xE002) and 8 <= totlen <= len(data):
            return "jffs2"
    # Raw disk images: only on strong evidence (a partition table
    # whose partitions carry a recognisable filesystem, a GPT
    # header, or a bare filesystem signature), never on the MBR
    # boot signature alone.
    if len(data) > 1024 and data[512:520] == b"EFI PART":
        return "diskimg"
    if len(data) >= 1082 and data[1080:1082] == b"\x53\xef":
        return "diskimg"
    if len(data) > 512 and (data[54:59] in (b"FAT12", b"FAT16") or data[82:87] == b"FAT32"):
        return "diskimg"
    if len(data) > 512 and data[510:512] == b"\x55\xaa":
        for i in range(4):
            ent = data[446 + i * 16:446 + i * 16 + 16]
            if ent[4] and _u32(ent, 12):
                part = data[_u32(ent, 8) * 512:(_u32(ent, 8) + _u32(ent, 12)) * 512]
                if len(part) >= 1082 and (part[1080:1082] == b"\x53\xef" or part[54:59] in (b"FAT12", b"FAT16")
                                          or part[82:87] == b"FAT32" or part[3:11] == b"NTFS    "):
                    return "diskimg"
    for suf, kind in ((".iso", "iso"), (".vhd", "vhd"), (".vhdx", "vhdx"),
                      (".qcow2", "qcow2"), (".dmg", "dmg"), (".img", "diskimg"),
                      (".deb", "deb"), (".rpm", "rpm"),
                      (".squashfs", "squashfs"), (".cramfs", "cramfs")):
        if name.endswith(suf):
            return kind
    return None


def extract_members(data, kind):
    """Return {member name: bytes} for one extra container kind, or
    raise ValueError naming the unenumerated interior."""
    if kind == "iso":
        return parse_iso(data)
    if kind == "vhd":
        return _vhd_members(data)
    if kind == "vhdx":
        return _vhdx_members(data)
    if kind == "qcow2":
        return _qcow2_members(data)
    if kind == "dmg":
        return _dmg_members(data)
    if kind == "diskimg":
        return _disk_members(data)
    if kind == "squashfs":
        return _squashfs_members(data)
    if kind == "cramfs":
        return _cramfs_members(data)
    if kind == "jffs2":
        return _jffs2_members(data)
    if kind == "squashfs-be":
        raise ValueError("this SquashFS filesystem is big-endian, which this build cannot decompress: the filesystem interior is unenumerated")
    if kind == "ubi":
        raise ValueError("this is a UBI flash image: its UBIFS interior is organised as a B-tree index (the TNC) that this build cannot walk, so the UBIFS interior is unenumerated and the unit is unaccounted")
    if kind == "deb":
        return _deb_members(data)
    if kind == "rpm":
        return _rpm_members(data)
    if kind == "apk":
        return _apk_members(data)
    raise ValueError(f"container kind {kind} has no extractor in this build, so its interior is unenumerated")


def extract_to(data, kind, dest):
    """Write members under dest with the zip path's safety rules
    and return the member names."""
    import os
    members = extract_members(data, kind)
    names = []
    total = 0
    for name, blob in members.items():
        total += len(blob)
        if total > MAX_TOTAL_BYTES:
            raise ValueError("container expands past the size limit, so its interior cannot be fully enumerated")
        target = os.path.realpath(os.path.join(dest, name))
        if not target.startswith(os.path.realpath(dest) + os.sep):
            raise ValueError(f"container member escapes the extraction folder: {name}")
        os.makedirs(os.path.dirname(target), exist_ok=True)
        with open(target, "wb") as out:
            out.write(blob)
        names.append(name)
    return names
