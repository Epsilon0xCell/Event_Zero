"""Coverage wave 3: byte ownership, dual-parser differentials,
polyglot accounting and the BYOVD driver carve-out.

Design law (total coverage programme, build wave 3): a verdict of
NO certifies that two independent parsers agree on the file's
structure and that every byte range has an accounted owner. This
module supplies the three readings that law needs, plus the
driver capability extraction the BYOVD carve-out judges:

- byte_ownership: for the formats where a byte-range ledger is
  tractable today (PE, ELF, ZIP, TAR, DEX, Mach-O thin and fat),
  the ranges each analysis owns (headers, section and segment
  content, container member data, certificate records) and the
  ranges no analysis owns (overlay and appended data, section
  slack past the declared virtual size, gaps between structures,
  trailing data past a container's end). Verified-zero ranges are
  owned as padding; a small named tolerance covers alignment
  residue. Any other unowned range is material and is returned
  for the verdict to cap on, with its offset and size. The PE
  certificate table is owned by content, not only as a record
  (coverage wave 5): the WIN_CERTIFICATE chain is walked entry
  by entry, each X.509 or PKCS#7 entry is sized by its DER
  structure, and any bytes inside the table past the accounted
  certificate content (an inflated entry length, a malformed
  chain, nonzero padding, content past the chain) are unowned
  with the offset named, because the table of a signed file is
  a documented payload staging place.
- dual_parser: PE and ELF files are parsed by the engine's own
  structural parser, by pefile, and by LIEF, and the three views
  are compared on the security-relevant fields (entry point,
  machine, section table, imports), together with a loader-model
  sanity check and pefile's structural warnings. Any material
  disagreement is returned for the verdict to cap on (Nisi et
  al., RAID 2021: there is no single correct parse, so a verdict
  must not rest on one parser).
- polyglot_identities: every format the bytes satisfy at once,
  so a second identity cannot stay invisible merely because the
  first one was recognised.
- driver_capabilities: the dangerous primitive set of a Windows
  kernel driver (physical and virtual memory access, MSR and
  port IO, process termination, driver-load and DSE surfaces),
  judged on capability, never on provenance: a genuine signed
  driver carrying this set is the BYOVD exploit primitive, so
  byte identity and a verifying signature cannot acquit it.

Everything here is a pure read-only parse. Nothing is executed.
"""
import io
import struct
import zipfile

# A nonzero unowned range at or below this size is alignment
# residue and is recorded, not capped on. Anything larger, and
# any unowned range past a container's logical end, is material.
TOLERANCE_BYTES = 16


def _entropy(data):
    if not data:
        return 0.0
    import math
    from collections import Counter
    c = Counter(data)
    n = len(data)
    return round(-sum((v / n) * math.log2(v / n) for v in c.values()), 3)


def _merge(intervals):
    out = []
    for s, e, owner in sorted(intervals):
        if e <= s:
            continue
        if out and s <= out[-1][1]:
            if e > out[-1][1]:
                out[-1] = (out[-1][0], e, out[-1][2])
        else:
            out.append((s, e, owner))
    return out


def _finish_ownership(data, fmt, basis, owned, notes, reason_map=()):
    """Merge owned ranges, compute the complement, and classify
    each unowned range: verified zero is owned padding, a range
    at or below the tolerance is recorded residue, and anything
    else is material, with a reason from reason_map (a list of
    (start, end, reason) hints) or a generic one."""
    owned = _merge(owned)
    unowned = []
    cursor = 0
    for s, e, _o in owned:
        if s > cursor:
            unowned.append((cursor, s))
        cursor = max(cursor, e)
    if cursor < len(data):
        unowned.append((cursor, len(data)))
    final_owned = list(owned)
    classified = []
    for s, e in unowned:
        blob = data[s:e]
        if not any(blob):
            final_owned.append((s, e, "verified zero padding"))
            continue
        reason = "no analysis owns this range"
        for rs, re_, why in reason_map:
            if s >= rs and e <= re_:
                reason = why
                break
        item = {"start": s, "end": e, "size": e - s,
                "offset_hex": hex(s), "entropy": _entropy(blob),
                "reason": reason}
        if e - s <= TOLERANCE_BYTES:
            item["material"] = False
            item["note"] = (f"at or below the {TOLERANCE_BYTES}-byte "
                            "alignment tolerance; recorded, not capped on")
        else:
            item["material"] = True
        classified.append(item)
    material = [c for c in classified if c["material"]]
    return {"format": fmt, "basis": basis,
            "owned": [{"start": s, "end": e, "owner": o}
                      for s, e, o in _merge(final_owned)],
            "unowned": classified,
            "material_unowned": material,
            "complete": not material,
            "notes": notes}


# ======================================================================
# PE: detailed structural parse (internal parser, loader-model view)
# ======================================================================

def parse_pe_detailed(data):
    out = {"parsed": False, "error": None}
    if len(data) < 0x40 or data[:2] != b"MZ":
        out["error"] = "not a PE (no MZ header)"
        return out
    try:
        peoff = struct.unpack_from("<I", data, 0x3c)[0]
        if peoff + 24 > len(data) or data[peoff:peoff + 4] != b"PE\x00\x00":
            out["error"] = "no PE signature at e_lfanew"
            return out
        machine, nsec, _ts, _symtab, _nsyms, opt_size, chars = \
            struct.unpack_from("<HHIIIHH", data, peoff + 4)
        opt = peoff + 24
        magic = struct.unpack_from("<H", data, opt)[0]
        if magic not in (0x10b, 0x20b):
            out["error"] = f"unknown optional header magic {hex(magic)}"
            return out
        is64 = magic == 0x20b
        entry = struct.unpack_from("<I", data, opt + 16)[0]
        subsystem = struct.unpack_from("<H", data, opt + 68)[0] if opt_size >= 70 else None
        dd_base = opt + (112 if is64 else 96)
        dirs = {}
        dir_names = ["export", "import", "resource", "exception",
                     "certificate", "relocation", "debug", "architecture",
                     "globalptr", "tls", "loadconfig", "boundiat",
                     "iat", "delayimport", "clr", "reserved"]
        ndirs = struct.unpack_from("<I", data, opt + (108 if is64 else 92))[0] \
            if opt_size >= (112 if is64 else 96) else 0
        for i in range(min(ndirs, 16)):
            rva, size = struct.unpack_from("<II", data, dd_base + 8 * i)
            if rva or size:
                dirs[dir_names[i]] = (rva, size)
        sections = []
        soff = opt + opt_size
        for i in range(nsec):
            off = soff + 40 * i
            if off + 40 > len(data):
                out["error"] = (f"section table declares {nsec} sections but "
                                f"header {i} runs past the end of the file")
                return out
            name = data[off:off + 8].rstrip(b"\x00").decode("ascii", "replace")
            vsize, vaddr, rsize, rptr = struct.unpack_from("<IIII", data, off + 8)
            sections.append({"name": name, "virtual_size": vsize,
                             "virtual_address": vaddr, "raw_size": rsize,
                             "raw_pointer": rptr})

        def rva_to_off(rva):
            for s in sections:
                span = max(s["virtual_size"], s["raw_size"])
                if s["virtual_address"] <= rva < s["virtual_address"] + span:
                    return s["raw_pointer"] + (rva - s["virtual_address"])
            return rva if rva < len(data) else None

        imports = {}
        if "import" in dirs:
            irva, _isize = dirs["import"]
            ioff = rva_to_off(irva)
            if ioff is not None:
                for d in range(4096):
                    doff = ioff + 20 * d
                    if doff + 20 > len(data):
                        break
                    ilt_rva, _t, _f, name_rva, iat_rva = \
                        struct.unpack_from("<IIIII", data, doff)
                    if not any((ilt_rva, name_rva, iat_rva)):
                        break
                    noff = rva_to_off(name_rva)
                    dll = ""
                    if noff is not None:
                        dll = data[noff:noff + 256].split(b"\x00")[0].decode("ascii", "replace")
                    funcs = []
                    t_rva = ilt_rva or iat_rva
                    toff = rva_to_off(t_rva) if t_rva else None
                    if toff is not None:
                        step = 8 if is64 else 4
                        ordflag = 0x8000000000000000 if is64 else 0x80000000
                        for j in range(65536):
                            eoff = toff + step * j
                            if eoff + step > len(data):
                                break
                            val = struct.unpack_from("<Q" if is64 else "<I",
                                                     data, eoff)[0]
                            if val == 0:
                                break
                            if val & ordflag:
                                funcs.append(f"ord{val & 0xffff}")
                            else:
                                hnoff = rva_to_off(val & 0x7fffffff)
                                if hnoff is not None and hnoff + 2 < len(data):
                                    funcs.append(data[hnoff + 2:hnoff + 258]
                                                 .split(b"\x00")[0].decode("ascii", "replace"))
                    imports[dll] = funcs
        cert = None
        if "certificate" in dirs:
            coff_, csize = dirs["certificate"]
            rec_len = None
            if 0 < coff_ and coff_ + 8 <= len(data):
                rec_len = struct.unpack_from("<I", data, coff_)[0]
            cert = {"offset": coff_, "size": csize, "record_length": rec_len}
        out.update({"parsed": True, "machine": machine, "num_sections": nsec,
                    "entry_rva": entry, "subsystem": subsystem,
                    "is_dll": bool(chars & 0x2000),
                    "headers_end": soff + 40 * nsec,
                    "sections": sections, "directories": dirs,
                    "imports": imports, "certificate": cert})
        return out
    except (struct.error, IndexError) as e:
        out["error"] = f"PE structure could not be read: {e}"
        return out


def _der_total_length(data, pos, end):
    """Total byte length of the DER object starting at pos (a
    SEQUENCE whose declared length bounds the whole object), or
    None when the bytes at pos are not a well-formed definite
    length DER object inside [pos, end)."""
    if pos + 2 > end or data[pos] != 0x30:
        return None
    b = data[pos + 1]
    if b < 0x80:
        total = 2 + b
    elif b == 0x80:
        return None  # indefinite length is BER, not DER
    else:
        n = b & 0x7F
        if n == 0 or n > 4 or pos + 2 + n > end:
            return None
        total = 2 + n + int.from_bytes(data[pos + 2:pos + 2 + n], "big")
    if pos + total > end:
        return None
    return total


def _cert_shape_clause(blob):
    """A content classification clause for unowned bytes inside
    a certificate table, or an empty string: executable-shaped
    content and high-entropy content are named, because the
    documented abuse of this region is an encrypted payload
    staged where a signature-respecting review does not look."""
    if blob[:2] == b"MZ" or b"\xca\xfe\xba\xbe" in blob \
            or b"PE\x00\x00" in blob:
        return ("; the content is executable-shaped (it carries "
                "an executable marker)")
    if len(blob) >= 64 and _entropy(blob) >= 7.0:
        return (f"; the content is high-entropy "
                f"({_entropy(blob)} bits per byte), consistent "
                f"with an encrypted payload staged in the table")
    return ""


def _cert_unowned_reason(blob, where):
    """Reason text for unowned bytes inside a certificate table,
    with the content classified by _cert_shape_clause."""
    return (f"bytes {where} are not part of any declared "
            f"certificate blob: the certificate table of a signed "
            f"file is a documented payload staging place, and "
            f"content there is owned by no analysis"
            + _cert_shape_clause(blob))


def certificate_table_accounting(data, offset, size):
    """Account the contents of a PE certificate table (coverage
    wave 5, extending the wave 3 ledger, which owned the table
    as a record sized by its first entry only).

    Walks the WIN_CERTIFICATE chain: each entry is 8-byte
    aligned from the table start, declares its own length, and
    for the two DER certificate types (X.509, PKCS#7 signed
    data) the entry's certificate content is sized by its DER
    structure. Returns {"entries": [...], "owned": [...],
    "unowned": [...], "notes": [...]} in the shapes
    _finish_ownership consumes: owned (start, end, owner) ranges
    and unowned (start, end, reason) ranges. Everything inside
    the table that is not accounted certificate content or
    verified zero padding is unowned: bytes past an entry's DER
    content inside an inflated entry length, an entry whose
    content is not a readable DER structure, an entry of a type
    this build cannot account, nonzero padding between or after
    entries, bytes past the end of the chain, and the remainder
    of the table after a malformed chain link."""
    table_start = offset
    table_end = min(offset + size, len(data))
    owned, unowned, notes, entries = [], [], [], []

    def push_unowned(s, e, reason):
        if e <= s:
            return
        if unowned and unowned[-1][1] == s:
            ps, _pe, pr = unowned[-1]
            unowned[-1] = (ps, e, pr + "; " + reason)
        else:
            unowned.append((s, e, reason))

    if offset + size > len(data):
        notes.append("the certificate table declares bytes past the "
                     "end of the file; only the bytes present are "
                     "accounted")
    pos = table_start
    idx = 0
    chain_broken = False
    while pos + 8 <= table_end:
        dw_length, _rev, ctype = struct.unpack_from("<IHH", data, pos)
        if dw_length < 8 or pos + dw_length > table_end:
            push_unowned(pos, table_end,
                         f"the certificate chain is malformed at "
                         f"entry {idx} (declared length {dw_length} "
                         f"does not fit the table), so this entry "
                         f"and the rest of the certificate table "
                         f"are unaccounted"
                         + _cert_shape_clause(data[pos:table_end]))
            entries.append({"index": idx, "offset": pos,
                            "declared_length": dw_length,
                            "type": ctype, "accounted": False})
            chain_broken = True
            break
        entry_end = pos + dw_length
        content_start = pos + 8
        if ctype in (0x0001, 0x0002):
            der = _der_total_length(data, content_start, entry_end)
            if der is None:
                push_unowned(pos, entry_end,
                             f"certificate entry {idx} (type "
                             f"{ctype:#06x}) does not hold a readable "
                             f"DER certificate structure at its start, "
                             f"so the entry is unaccounted: bytes "
                             f"inside a certificate table that are not "
                             f"part of the certificate itself are a "
                             f"staging place")
                entries.append({"index": idx, "offset": pos,
                                "declared_length": dw_length,
                                "type": ctype, "accounted": False})
            else:
                der_end = content_start + der
                owned.append((pos, der_end,
                              f"certificate table entry {idx}: "
                              f"WIN_CERTIFICATE header and its "
                              f"{der} bytes of DER certificate "
                              f"content, structure parsed"))
                if der_end < entry_end:
                    tail = data[der_end:entry_end]
                    if any(tail):
                        push_unowned(der_end, entry_end,
                                     _cert_unowned_reason(
                                         tail,
                                         f"inside certificate entry "
                                         f"{idx}, past the end of its "
                                         f"DER certificate content"))
                    else:
                        owned.append((der_end, entry_end,
                                      "verified zero padding inside "
                                      "the certificate entry, past "
                                      "its DER content"))
                entries.append({"index": idx, "offset": pos,
                                "declared_length": dw_length,
                                "type": ctype, "accounted": True,
                                "der_length": der})
        else:
            push_unowned(pos, entry_end,
                         f"certificate entry {idx} has type "
                         f"{ctype:#06x}, which is not a certificate "
                         f"structure this build can account (only "
                         f"X.509 and PKCS#7 signed data entries are "
                         f"DER-accounted), so the entry is "
                         f"unaccounted")
            entries.append({"index": idx, "offset": pos,
                            "declared_length": dw_length,
                            "type": ctype, "accounted": False})
        rel_end = entry_end - table_start
        next_pos = table_start + ((rel_end + 7) // 8) * 8
        if next_pos > entry_end:
            pad_end = min(next_pos, table_end)
            pad = data[entry_end:pad_end]
            if any(pad):
                push_unowned(entry_end, pad_end,
                             "nonzero padding between certificate "
                             "entries: the Authenticode layout "
                             "leaves only zero bytes in the "
                             "alignment padding between chained "
                             "entries, so nonzero bytes here are "
                             "part of no certificate")
            elif pad:
                owned.append((entry_end, pad_end,
                              "verified zero alignment padding "
                              "between certificate entries"))
        if next_pos <= pos or next_pos >= table_end:
            pos = next_pos
            break
        pos = next_pos
        idx += 1
    if not chain_broken and pos < table_end:
        rest = data[pos:table_end]
        if any(rest):
            push_unowned(pos, table_end,
                         _cert_unowned_reason(
                             rest,
                             "inside the certificate table, past "
                             "the end of the declared certificate "
                             "chain"))
        elif rest:
            owned.append((pos, table_end,
                          "verified zero padding at the end of "
                          "the certificate table"))
    return {"entries": entries, "owned": owned,
            "unowned": unowned, "notes": notes}


def _pe_ownership(data, expanded=False):
    det = parse_pe_detailed(data)
    if not det["parsed"]:
        return None
    notes = []
    owned = [(0, det["headers_end"],
              "PE headers: DOS header and stub, PE signature, COFF and "
              "optional headers and the section table, structure parsed")]
    reasons = []
    sec_end = det["headers_end"]
    for s in det["sections"]:
        rptr, rsize, vsize = s["raw_pointer"], s["raw_size"], s["virtual_size"]
        if rsize == 0 or rptr == 0:
            continue
        end = min(rptr + rsize, len(data))
        if rptr + rsize > len(data):
            notes.append(f"section {s['name']} declares raw bytes past the "
                         "end of the file")
        content = rptr + min(vsize if vsize else rsize, rsize)
        owned.append((rptr, min(content, len(data)),
                      f"section {s['name']}: structure parsed, strings "
                      "extracted, code window disassembled"))
        if content < rptr + rsize:
            reasons.append((content, rptr + rsize,
                            f"section slack past the declared virtual size "
                            f"in section {s['name']}: bytes the loader never "
                            "maps from this section, owned by no analysis"))
        sec_end = max(sec_end, end)
    cert_end = 0
    cert_acct = None
    cert = det.get("certificate")
    if cert and cert["offset"]:
        coff_, csize = cert["offset"], cert["size"]
        # Coverage wave 5: the table is owned by content. The
        # WIN_CERTIFICATE chain is walked and each entry sized
        # by its DER structure; anything inside the table that
        # is not accounted certificate content or verified zero
        # padding is an unowned range with its reason.
        cert_acct = certificate_table_accounting(data, coff_, csize)
        owned.extend(cert_acct["owned"])
        reasons.extend(cert_acct["unowned"])
        notes.extend(cert_acct["notes"])
        cert_end = coff_ + csize
    accounted_end = max(sec_end, cert_end)
    if accounted_end < len(data):
        if expanded:
            # An appended archive in the overlay is a second identity
            # whose members were enumerated as verdict units; that
            # range is owned by the container identity, not unowned.
            tail = data[accounted_end:]
            zstart = tail.find(b"PK\x03\x04")
            if zstart < 0:
                zstart = tail.find(b"PK\x05\x06")
            if zstart >= 0:
                owned.append((accounted_end + zstart, len(data),
                              "appended archive in the overlay: second "
                              "identity, enumerated as members and judged "
                              "as verdict units"))
                reasons.append((accounted_end, accounted_end + zstart,
                                "overlay bytes before the appended archive: "
                                "owned by no analysis"))
            else:
                reasons.append((accounted_end, len(data),
                                "overlay past the last section and the "
                                "certificate table: appended data owned by "
                                "no analysis"))
        else:
            reasons.append((accounted_end, len(data),
                            "overlay past the last section and the "
                            "certificate table: appended data owned by "
                            "no analysis"))
    result = _finish_ownership(
        data, "PE", "structural parse: headers, section content and "
        "slack, data directories, certificate table, overlay", owned,
        notes, reasons)
    if cert_acct is not None:
        result["certificate_table"] = {
            "offset": cert["offset"], "size": cert["size"],
            "entries": cert_acct["entries"],
            "accounted_entries":
                sum(1 for e in cert_acct["entries"] if e["accounted"])}
    return result


# ======================================================================
# ELF ownership and views
# ======================================================================

def parse_elf_detailed(data):
    out = {"parsed": False, "error": None}
    if len(data) < 52 or data[:4] != b"\x7fELF":
        out["error"] = "not an ELF"
        return out
    try:
        is64 = data[4] == 2
        en = "<" if data[5] == 1 else ">"
        machine = struct.unpack_from(en + "H", data, 18)[0]
        entry = struct.unpack_from(en + ("Q" if is64 else "I"), data, 24)[0]
        if is64:
            phoff = struct.unpack_from(en + "Q", data, 0x20)[0]
            shoff = struct.unpack_from(en + "Q", data, 0x28)[0]
            phentsize, phnum = struct.unpack_from(en + "HH", data, 0x36)
            shentsize, shnum, shstrndx = struct.unpack_from(en + "HHH", data, 0x3a)
        else:
            phoff = struct.unpack_from(en + "I", data, 0x1c)[0]
            shoff = struct.unpack_from(en + "I", data, 0x20)[0]
            phentsize, phnum = struct.unpack_from(en + "HH", data, 0x2a)
            shentsize, shnum, shstrndx = struct.unpack_from(en + "HHH", data, 0x2e)
        raw_secs = []
        for i in range(shnum):
            off = shoff + i * shentsize
            if off + shentsize > len(data):
                out["error"] = "section header table runs past the end of the file"
                return out
            if is64:
                nm, typ, _fl, _ad, soff_, ssize = struct.unpack_from(en + "IIQQQQ", data, off)
            else:
                nm, typ, _fl, _ad, soff_, ssize = struct.unpack_from(en + "IIIIII", data, off)
            raw_secs.append({"name_idx": nm, "type": typ, "offset": soff_, "size": ssize})
        names = b""
        if 0 <= shstrndx < len(raw_secs):
            st = raw_secs[shstrndx]
            names = data[st["offset"]:st["offset"] + st["size"]]
        sections = []
        for s in raw_secs:
            nm = ""
            if s["name_idx"] < len(names):
                nm = names[s["name_idx"]:].split(b"\x00")[0].decode("ascii", "replace")
            sections.append({"name": nm, "type": s["type"],
                             "offset": s["offset"], "size": s["size"]})
        out.update({"parsed": True, "machine": machine, "entry": entry,
                    "is64": is64, "endian": en, "shoff": shoff,
                    "shentsize": shentsize, "phoff": phoff,
                    "phentsize": phentsize, "phnum": phnum,
                    "ehsize": 64 if is64 else 52, "sections": sections})
        return out
    except (struct.error, IndexError) as e:
        out["error"] = f"ELF structure could not be read: {e}"
        return out


def _elf_ownership(data):
    det = parse_elf_detailed(data)
    if not det["parsed"]:
        return None
    owned = [(0, det["ehsize"], "ELF header: structure parsed")]
    if det["phoff"] and det["phnum"]:
        owned.append((det["phoff"], det["phoff"] + det["phentsize"] * det["phnum"],
                      "ELF program header table: structure parsed"))
    if det["shoff"]:
        owned.append((det["shoff"], det["shoff"] + det["shentsize"] * len(det["sections"]),
                      "ELF section header table: structure parsed"))
    for s in det["sections"]:
        if s["type"] == 8 or s["size"] == 0:  # SHT_NOBITS occupies no file bytes
            continue
        owned.append((s["offset"], min(s["offset"] + s["size"], len(data)),
                      f"section {s['name'] or '(unnamed)'}: structure parsed, "
                      "strings extracted, code window disassembled"))
    return _finish_ownership(data, "ELF", "structural parse: header, "
                             "program and section header tables, section "
                             "content", owned, [])


# ======================================================================
# ZIP and TAR ownership
# ======================================================================

def _zip_ownership(data, expanded=False):
    if not zipfile.is_zipfile(io.BytesIO(data)):
        return None
    # locate the end-of-central-directory record
    window = data[-min(len(data), 65557):]
    eocd_rel = window.rfind(b"PK\x05\x06")
    if eocd_rel < 0:
        return None
    eocd = len(data) - len(window) + eocd_rel
    if eocd + 22 > len(data):
        return None
    _disk, _cddisk, _n1, _n2, cd_size, cd_off, _clen = \
        struct.unpack_from("<HHHHIIH", data, eocd + 4)
    owned = []
    reasons = []
    notes = []
    try:
        zf = zipfile.ZipFile(io.BytesIO(data))
        infos = zf.infolist()
    except Exception:
        return None
    # zipfile's start_dir is the absolute offset of the central
    # directory, already adjusted for any prepended data, where
    # the EOCD's own cd_off field is relative to the archive start.
    cd_abs = getattr(zf, "start_dir", cd_off)
    # zipfile reports header offsets already adjusted for prepended
    # data; the first member's local header sits after any prepend.
    first_local = None
    scan = data.find(b"PK\x03\x04")
    if scan >= 0:
        first_local = scan
    if first_local:
        pre = data[:first_local]
        if image_identity_accounted(pre):
            owned.append((0, first_local,
                          "polyglot first identity: a complete image file, "
                          "accounted as data under its own identity"))
        else:
            reasons.append((0, first_local,
                            "data prepended before the first zip member: "
                            "owned by no analysis under either identity"))
    for info in infos:
        ho = info.header_offset
        if ho + 30 > len(data) or data[ho:ho + 4] != b"PK\x03\x04":
            # header offset may be relative to the archive start in a
            # prepended archive; zipfile has already adjusted it, so a
            # mismatch here means the local header is not where the
            # central directory claims: record, do not guess.
            notes.append(f"member {info.filename}: local header not found "
                         "at the central directory offset")
            continue
        nl, el = struct.unpack_from("<HH", data, ho + 26)
        dstart = ho + 30 + nl + el
        dend = dstart + info.compress_size
        owned.append((ho, min(dend, len(data)),
                      f"member {info.filename}: local header and data, "
                      "enumerated and judged as a verdict unit"))
        if info.flag_bits & 0x8:
            desc = dend
            if data[desc:desc + 4] == b"PK\x07\x08":
                desc += 4
            owned.append((dend, min(desc + 12, len(data)),
                          f"member {info.filename}: data descriptor"))
    owned.append((cd_abs, min(cd_abs + cd_size, len(data)),
                  "zip central directory: structure parsed"))
    owned.append((eocd, eocd + 22 + _clen,
                  "zip end of central directory: structure parsed"))
    if eocd + 22 + _clen < len(data):
        reasons.append((eocd + 22 + _clen, len(data),
                        "data appended past the end of the central "
                        "directory: part of no member and no zip "
                        "structure, owned by no analysis"))
    return _finish_ownership(data, "ZIP archive", "structural parse: "
                             "local headers and member data, central "
                             "directory, end record, prepended and "
                             "appended ranges", owned, notes, reasons)


def _tar_ownership(data):
    if len(data) < 1024 or data[257:262] != b"ustar":
        return None
    owned = []
    off = 0
    ok = True
    while off + 512 <= len(data):
        block = data[off:off + 512]
        if not any(block):
            # end blocks: two zero blocks end the archive; anything
            # after them is padding or appended data, handled by the
            # generic complement classification.
            owned.append((off, min(off + 1024, len(data)),
                          "tar end-of-archive zero blocks"))
            off += 1024
            break
        name = block[0:100].split(b"\x00")[0].decode("utf-8", "replace")
        size_field = block[124:136].split(b"\x00")[0].strip()
        try:
            if size_field and size_field[0] & 0x80:
                raise ValueError("base-256 size")
            size = int(size_field or b"0", 8)
        except Exception:
            ok = False
            break
        owned.append((off, off + 512, f"tar member header for {name}"))
        dstart = off + 512
        dend = dstart + ((size + 511) // 512) * 512
        owned.append((dstart, min(dend, len(data)),
                      f"tar member {name}: content, enumerated and "
                      "judged as a verdict unit"))
        off = dend
    if not ok:
        return None
    return _finish_ownership(data, "TAR archive", "structural parse: "
                             "member headers and member data blocks, "
                             "end blocks, trailing ranges", owned, [])


def _dex_ownership(data):
    if not (len(data) > 36 and data[:4] == b"dex\n"):
        return None
    file_size = struct.unpack_from("<I", data, 32)[0]
    notes = []
    if file_size > len(data):
        notes.append(f"DEX header declares {file_size} bytes but "
                     f"{len(data)} are present: truncated")
        owned_end = len(data)
    else:
        owned_end = file_size
    owned = [(0, owned_end, "DEX structure: header, id lists, class "
              "data and code items, parsed and accounted at method "
              "level by the bytecode accounting")]
    return _finish_ownership(data, "DEX", "header-declared extent: the "
                             "DEX parser accounts the structure inside "
                             "the declared file size; bytes past it are "
                             "appended data", owned, notes,
                             [(owned_end, len(data),
                               "data appended past the DEX header's "
                               "declared file size: owned by no analysis")]
                             if owned_end < len(data) else [])


def _macho_ownership(data):
    magics = (b"\xcf\xfa\xed\xfe", b"\xfe\xed\xfa\xcf",
              b"\xce\xfa\xed\xfe", b"\xfe\xed\xfa\xce")
    fat_magics = (b"\xca\xfe\xba\xbe", b"\xbe\xba\xfe\xca")
    if data[:4] in fat_magics:
        try:
            nfat = struct.unpack_from(">I", data, 4)[0]
        except struct.error:
            return None
        owned = [(0, 8 + 20 * nfat, "fat Mach-O header: structure parsed")]
        for i in range(nfat):
            off_rec = 8 + 20 * i
            if off_rec + 20 > len(data):
                return None
            _cpu, _sub, soff, ssize, _al = struct.unpack_from(">IIIII", data, off_rec)
            owned.append((soff, min(soff + ssize, len(data)),
                          f"fat slice {i}: expanded and verdicted as "
                          "its own unit"))
        return _finish_ownership(data, "Mach-O (fat)", "fat header and "
                                 "slice ranges: every slice is a verdict "
                                 "unit of its own", owned, [])
    if data[:4] not in magics:
        return None
    en = "<" if data[:4] in (b"\xcf\xfa\xed\xfe", b"\xce\xfa\xed\xfe") else ">"
    is64 = data[:4] in (b"\xcf\xfa\xed\xfe", b"\xfe\xed\xfa\xcf")
    try:
        ncmds = struct.unpack_from(en + "I", data, 16)[0]
        off = 32 if is64 else 28
        owned = [(0, off, "Mach-O header: structure parsed")]
        for _ in range(ncmds):
            cmd, cmdsize = struct.unpack_from(en + "II", data, off)
            if cmdsize < 8 or off + cmdsize > len(data):
                return None
            owned.append((off, off + cmdsize, "Mach-O load command: "
                          "structure parsed"))
            if cmd in (0x01, 0x19):
                segname = data[off + 8:off + 24].rstrip(b"\x00").decode("ascii", "replace")
                if cmd == 0x19:
                    fileoff, filesize = struct.unpack_from(en + "QQ", data, off + 40)
                else:
                    fileoff, filesize = struct.unpack_from(en + "II", data, off + 32)
                if filesize:
                    owned.append((fileoff, min(fileoff + filesize, len(data)),
                                  f"segment {segname}: structure parsed, "
                                  "strings extracted, code window "
                                  "disassembled"))
            if cmd == 0x1d:
                doff, dsize = struct.unpack_from(en + "II", data, off + 8)
                owned.append((doff, min(doff + dsize, len(data)),
                              "code signature superblob: structure parsed"))
            off += cmdsize
    except (struct.error, IndexError):
        return None
    return _finish_ownership(data, "Mach-O", "structural parse: header, "
                             "load commands, segment ranges, code "
                             "signature", owned, [])


def byte_ownership(name, data, expanded=False):
    """The byte-ownership ledger for one file, or None when this
    build computes no byte-range ledger for the format. Formats
    with no ledger here are named in the wave log: ELF, PE, ZIP,
    TAR, DEX and Mach-O are covered; the coverage wave 1 container
    kinds are accounted by member enumeration (their interiors
    are verdict units, and the container's own bytes are not a
    content unit), and the remaining formats record their
    incompleteness through the existing verdict rules."""
    if data[:2] == b"MZ":
        own = _pe_ownership(data, expanded=expanded)
        if own:
            return own
    if data[:4] == b"\x7fELF":
        return _elf_ownership(data)
    if data[:4] in (b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08"):
        return _zip_ownership(data, expanded=expanded)
    tar = _tar_ownership(data)
    if tar:
        return tar
    dex = _dex_ownership(data)
    if dex:
        return dex
    return _macho_ownership(data)


# ======================================================================
# Dual-parser differential gate
# ======================================================================

def _canon_sections(secs):
    """Canonical section list: phantom entries a parser invents
    from a corrupt table (empty name, no raw bytes, no raw
    pointer) are dropped from every view alike, so the comparison
    is about real sections."""
    out = []
    for name, rsize, rptr in secs:
        name = (name or "").rstrip("\x00")
        if not name and not rsize and not rptr:
            continue
        out.append((name, int(rsize), int(rptr)))
    return sorted(out)


def _pe_views(data, path):
    views = {}
    det = parse_pe_detailed(data)
    if det["parsed"]:
        views["internal"] = {
            "entry": det["entry_rva"], "machine": det["machine"],
            "sections": _canon_sections(
                [(s["name"], s["raw_size"], s["raw_pointer"]) for s in det["sections"]]),
            "imports": sorted({f for funcs in det["imports"].values() for f in funcs})}
    else:
        views["internal"] = {"error": det["error"]}
    try:
        import pefile
        pe = pefile.PE(data=data, fast_load=True)
        try:
            pe.parse_data_directories(
                directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"]])
        except Exception:
            pass
        funcs = set()
        for entry in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []) or []:
            for imp in entry.imports:
                if imp.name:
                    funcs.add(imp.name.decode("ascii", "replace"))
        views["pefile"] = {
            "entry": pe.OPTIONAL_HEADER.AddressOfEntryPoint,
            "machine": pe.FILE_HEADER.Machine,
            "sections": _canon_sections(
                [(s.Name.rstrip(b"\x00").decode("ascii", "replace"),
                  s.SizeOfRawData, s.PointerToRawData) for s in pe.sections]),
            "imports": sorted(funcs),
            "warnings": [w for w in pe.get_warnings()
                         if "makes up" not in w]}
    except Exception:
        pass
    try:
        import lief
        b = lief.parse(path) if path else None
        if b is not None and hasattr(b, "sections"):
            funcs = set()
            try:
                for lib in b.imports:
                    for e in lib.entries:
                        if e.name:
                            funcs.add(e.name)
            except Exception:
                pass
            machine = None
            try:
                ms = str(b.header.machine_type)
                machine = {k: v for k, v in
                           (("X86_64", 0x8664), ("I386", 0x14c),
                            ("ARM64", 0xaa64), ("ARM", 0x1c0))}.get(
                                ms.split(".")[-1])
            except Exception:
                pass
            # LIEF reports the entry point as a virtual address
            # (image base plus RVA) where pefile and the internal
            # parser report the RVA; normalise by the image base
            # so the comparison is about the structure, not about
            # each parser's presentation convention.
            lief_entry = b.entrypoint
            try:
                ib = b.imagebase
            except Exception:
                ib = 0
            if ib and lief_entry >= ib:
                lief_entry -= ib
            views["lief"] = {
                "entry": lief_entry, "machine": machine,
                "sections": _canon_sections(
                    [(s.name, s.sizeof_raw_data, s.pointerto_raw_data)
                     for s in b.sections]),
                "imports": sorted(funcs)}
    except Exception:
        pass
    return views, det


def _elf_views(data, path):
    views = {}
    det = parse_elf_detailed(data)
    if det["parsed"]:
        views["internal"] = {
            "entry": det["entry"], "machine": det["machine"],
            "sections": _canon_sections(
                [(s["name"], s["size"], s["offset"]) for s in det["sections"]]),
            "imports": []}
    else:
        views["internal"] = {"error": det["error"]}
    try:
        import lief
        b = lief.parse(path) if path else None
        if b is not None and hasattr(b, "sections"):
            machine = None
            try:
                ms = str(b.header.machine_type).split(".")[-1]
                machine = {"X86_64": 0x3e, "I386": 0x3, "AARCH64": 0xb7,
                           "ARM": 0x28, "MIPS": 0x8, "RISCV": 0xf3}.get(ms)
            except Exception:
                pass
            views["lief"] = {
                "entry": b.entrypoint, "machine": machine,
                "sections": _canon_sections(
                    [(s.name, s.size, s.offset) for s in b.sections]),
                "imports": []}
    except Exception:
        pass
    return views, det


def dual_parser(data, path=None):
    """Parse one PE or ELF with every parser this build has and
    compare the views. Returns {available, parsers, compared,
    disagreements} where each disagreement is {field, detail}
    with the conflicting values named. available is False when
    fewer than two parsers produced a view: a verdict must not
    rest on one parser, so the caller records that as
    incompleteness."""
    if data[:2] == b"MZ":
        views, det = _pe_views(data, path)
        kind = "PE"
    elif data[:4] == b"\x7fELF":
        views, det = _elf_views(data, path)
        kind = "ELF"
    else:
        return {"available": False, "parsers": [], "compared": [],
                "disagreements": [], "kind": None,
                "reason": "not a PE or ELF file"}
    disagreements = []
    compared = []
    names = sorted(views)
    parsed = [n for n in names if "error" not in views[n]]
    errored = [n for n in names if "error" in views[n]]
    if len(parsed) < 2 and not (parsed and errored):
        return {"available": False, "parsers": names, "compared": [],
                "disagreements": [], "kind": kind,
                "reason": "fewer than two parsers produced a view"}
    for n in errored:
        # One parser could not read a structure another parser
        # read: that is a differential in itself, the shape the
        # RAID 2021 shapes take (valid to one reader, malformed
        # to another).
        disagreements.append(
            {"field": "parser-failure",
             "detail": f"the {n} parser could not read this file's "
                       f"structure ({views[n]['error']}) while "
                       f"{' and '.join(parsed)} produced a view"})
    for field in ("entry", "machine", "sections", "imports"):
        vals = {}
        for n in parsed:
            v = views[n].get(field)
            if v is None:
                continue
            if field == "imports" and not v and len(names) > 2:
                # a parser that found no import directory at all
                # abstains; a parser that parsed one and found
                # names is compared against the other that did.
                continue
            vals[n] = v
        if len(vals) < 2:
            continue
        compared.append(field)
        first = next(iter(vals.values()))
        if any(v != first for v in vals.values()):
            shown = "; ".join(
                f"{n}: {v if field != 'imports' else v[:8]}" for n, v in vals.items())
            disagreements.append(
                {"field": field,
                 "detail": f"the parsers disagree on the {field}: {shown}"})
    for w in views.get("pefile", {}).get("warnings", []) or []:
        disagreements.append({"field": "parser-warning",
                              "detail": f"pefile records a structural "
                                        f"warning: {w}"})
    # loader-model sanity, from the internal parse: the entry
    # point must land in a section the loader maps, and every
    # section's raw range must lie inside the file.
    if det.get("parsed") and kind == "PE":
        entry = det["entry_rva"]
        if entry:
            inside = any(s["virtual_address"] <= entry <
                         s["virtual_address"] + max(s["virtual_size"], s["raw_size"])
                         for s in det["sections"])
            if not inside:
                disagreements.append(
                    {"field": "loader-model",
                     "detail": f"the entry point {hex(entry)} lies outside "
                               "every section the loader would map"})
        for s in det["sections"]:
            if s["raw_size"] and s["raw_pointer"] + s["raw_size"] > len(data):
                disagreements.append(
                    {"field": "loader-model",
                     "detail": f"section {s['name']} declares raw bytes "
                               f"[{s['raw_pointer']}, "
                               f"{s['raw_pointer'] + s['raw_size']}) but "
                               f"the file has {len(data)} bytes"})
    return {"available": True, "parsers": names, "compared": compared,
            "disagreements": disagreements, "kind": kind}


# ======================================================================
# Polyglot identities
# ======================================================================

def _pe_sig_at(data, off):
    if data[off:off + 2] != b"MZ" or off + 0x40 > len(data):
        return False
    try:
        peoff = struct.unpack_from("<I", data, off + 0x3c)[0]
    except struct.error:
        return False
    return 0 < peoff < 4096 and data[off + peoff:off + peoff + 4] == b"PE\x00\x00"


def image_identity_accounted(blob):
    """A complete image file under its own identity: the format's
    own terminator is present at the end of the blob, so the
    image is a whole file that can be accounted as data."""
    if blob[:6] in (b"GIF87a", b"GIF89a"):
        return blob.rstrip(b"\x00")[-1:] == b";"
    if blob[:8] == b"\x89PNG\r\n\x1a\n":
        return b"IEND" in blob[-16:]
    if blob[:3] == b"\xff\xd8\xff":
        return blob.rstrip(b"\x00")[-2:] == b"\xff\xd9"
    return False


def polyglot_identities(data):
    """Every format the bytes satisfy simultaneously, as
    {format, offset} in offset order. A single identity is the
    ordinary case; two or more means the file must be accounted
    under each."""
    ids = []

    def add(fmt, off):
        if not any(i["format"] == fmt and i["offset"] == off for i in ids):
            ids.append({"format": fmt, "offset": off})

    if _pe_sig_at(data, 0):
        add("PE", 0)
    if data[:4] == b"\x7fELF":
        add("ELF", 0)
    if data[:6] in (b"GIF87a", b"GIF89a"):
        add("GIF image", 0)
    if data[:8] == b"\x89PNG\r\n\x1a\n":
        add("PNG image", 0)
    if data[:3] == b"\xff\xd8\xff":
        add("JPEG image", 0)
    if data[:5] == b"%PDF-":
        add("PDF", 0)
    if len(data) > 262 and data[257:262] == b"ustar":
        add("TAR archive", 0)
    zoff = data.find(b"PK\x03\x04")
    if zoff < 0:
        zoff = data.find(b"PK\x05\x06")
    if zoff >= 0:
        add("ZIP archive", zoff)
    # appended native binaries past the first identity
    start = 1
    while True:
        off = data.find(b"MZ", start)
        if off < 0:
            break
        if _pe_sig_at(data, off):
            add("PE", off)
            break
        start = off + 1
    eoff = data.find(b"\x7fELF", 1)
    if eoff > 0:
        add("ELF", eoff)
    return sorted(ids, key=lambda i: i["offset"])


# ======================================================================
# BYOVD: driver capability extraction
# ======================================================================

DRIVER_CAPABILITY_APIS = {
    "physical-memory-access": {
        "MmMapIoSpace", "MmMapIoSpaceEx", "MmMapLockedPages",
        "MmMapLockedPagesSpecifyCache",
        "MmMapLockedPagesWithReservedMapping", "MmAllocateContiguousMemory",
    },
    "virtual-memory-access": {
        "MmCopyVirtualMemory", "KeStackAttachProcess", "KeAttachProcess",
        "MmCopyMemory",
    },
    "msr-access": {"__readmsr", "__writemsr"},
    "port-io": {
        "READ_PORT_UCHAR", "READ_PORT_USHORT", "READ_PORT_ULONG",
        "WRITE_PORT_UCHAR", "WRITE_PORT_USHORT", "WRITE_PORT_ULONG",
        "__inbyte", "__inword", "__indword",
        "__outbyte", "__outword", "__outdword",
    },
    "process-termination": {"ZwTerminateProcess", "NtTerminateProcess"},
    "driver-load-and-dse-surface": {"ZwLoadDriver", "NtLoadDriver"},
}

DRIVER_CAPABILITY_STRINGS = {
    "physical-memory-access": ["\\Device\\PhysicalMemory"],
    "msr-access": [],
    "driver-load-and-dse-surface": ["g_CiOptions"],
}


def driver_capabilities(name, data, imports=(), strings=(), is_kernel_driver=False):
    """The dangerous capability set of a Windows kernel driver.
    is_driver is decided by the .sys name, a native subsystem, an
    import from the kernel or HAL, or the caller's rootkit
    identification. Capabilities are matched on imported names
    first (exact, case-insensitive) and on a small set of string
    tokens that name objects no import table carries (the
    physical memory device, the CI options variable)."""
    det = parse_pe_detailed(data) if data[:2] == b"MZ" else {"parsed": False}
    dlls = set()
    funcs = set()
    if det.get("parsed"):
        for dll, fl in det["imports"].items():
            dlls.add(dll.lower())
            funcs.update(f.lower() for f in fl)
    for imp in imports or ():
        funcs.add(str(imp).lower())
    low_name = (name or "").lower()
    is_driver = bool(
        low_name.endswith(".sys")
        or (det.get("parsed") and det.get("subsystem") == 1)
        or dlls & {"ntoskrnl.exe", "hal.dll"}
        or is_kernel_driver)
    if not is_driver:
        return {"is_driver": False, "capabilities": []}
    caps = []
    for cat, apis in DRIVER_CAPABILITY_APIS.items():
        hits = sorted(a for a in apis if a.lower() in funcs)
        if hits:
            caps.append({"category": cat, "evidence": hits,
                         "source": "import table"})
    joined = "\n".join(strings or ())
    for cat, tokens in DRIVER_CAPABILITY_STRINGS.items():
        hits = [t for t in tokens if t in joined]
        if hits and not any(c["category"] == cat for c in caps):
            caps.append({"category": cat, "evidence": hits,
                         "source": "strings"})
    return {"is_driver": True, "capabilities": caps,
            "imports_from": sorted(dlls)}
