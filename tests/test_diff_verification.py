"""Elite-analyst requirement (adopted 2026-11-23): an expected-crack
classification must be machine-verified, never a label. A differing
region earns it only by matching a named crack pattern AND passing
the region capability check on its own bytes. A payload planted
inside a region that looks like a license patch must come back YES
PROVEN or UNACCOUNTED, never NO."""
import os, struct, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from event_zero.verdict import verdict, classify_diff

def write(tmp, name, data, sub=""):
    d = os.path.join(str(tmp), sub) if sub else str(tmp)
    os.makedirs(d, exist_ok=True)
    p = os.path.join(d, name)
    # newline="" for text writes: byte-exact fixtures on every platform
    # (Windows text mode would otherwise write CRLF and change hashes).
    with open(p, "wb" if isinstance(data, bytes) else "w", newline=None if isinstance(data, bytes) else "") as f:
        f.write(data)
    return p

def pe_with_body(body, extra_strings=b"", section=b".text"):
    dos = bytearray(0x80); dos[0:2] = b"MZ"; struct.pack_into("<I", dos, 0x3c, 0x80)
    coff = struct.pack("<HHIIIHH", 0x8664, 1, 0, 0, 0, 240, 0x22)
    opt = bytearray(240); struct.pack_into("<H", opt, 0, 0x20b); struct.pack_into("<I", opt, 16, 0x1000)
    sec = bytearray(40); sec[0:len(section)] = section; struct.pack_into("<IIII", sec, 8, 100, 0x1000, 512, 512)
    b = (body + extra_strings).ljust(512, b"\x00")
    return bytes(dos) + b"PE\x00\x00" + coff + bytes(opt) + bytes(sec) + b

OLD_URL = b"http://vendor.example/upd"
NEW_URL = b"http://evil.invalid/updat"
assert len(OLD_URL) == len(NEW_URL)

def test_url_swap_inside_license_region_never_no(tmp_path):
    """The patch-shaped region swaps the vendor address for an
    attacker address, same length, beside the license string. The
    genuine file already has a network capability, so the file-level
    gate cannot catch it; the region capability check must."""
    genuine = pe_with_body(b"\x90" * 8, b"license check\x00" + OLD_URL + b"\x00")
    planted = pe_with_body(b"\x90" * 8, b"license check\x00" + NEW_URL + b"\x00")
    ref = os.path.join(str(tmp_path), "genuine"); rel = os.path.join(str(tmp_path), "release")
    os.makedirs(ref); os.makedirs(rel)
    write(tmp_path, "game.exe", genuine, "genuine")
    write(tmp_path, "game.exe", planted, "release")
    v = verdict(rel, reference=ref)
    assert v["verdict"] == "YES", v["plain_english"]
    assert v["reason_class"] in ("PROVEN", "UNACCOUNTED")
    failed = [le for le in v["diff_ledger"] if le.get("region_capability_check", {}).get("passed") is False]
    assert failed, v["diff_ledger"]
    assert all(le["classification"] == "unaccounted" for le in failed)

def test_region_adding_capability_atom_never_expected_crack():
    """Unit level: a region whose new bytes carry a capability atom
    the genuine region lacked fails the check, whatever its shape."""
    old = b"license check\x00" + b"A" * 32
    new = b"license check\x00" + b"VirtualAllocEx\x00" + b"A" * 17
    assert len(old) == len(new)
    ledger = classify_diff(old, new, [], [])
    bad = [le for le in ledger if le["classification"] == "expected-crack"]
    assert not bad, ledger
    assert any(le.get("region_capability_check", {}).get("passed") is False for le in ledger), ledger

def test_genuine_branch_patch_still_expected_crack():
    """The verified path still works: a conditional jump flipped to
    an unconditional jump beside the license string, adding nothing,
    classifies expected-crack with the pattern named."""
    old = b"license check\x00" + bytes([0x74, 0x12]) + b"B" * 16
    new = b"license check\x00" + bytes([0xEB, 0x12]) + b"B" * 16
    ledger = classify_diff(old, new, [], [])
    good = [le for le in ledger if le["classification"] == "expected-crack"]
    assert good and good[0]["crack_pattern"] == "conditional-branch-patch", ledger
    assert good[0]["region_capability_check"]["passed"] is True

def test_open_case_carries_residual_pack_and_coverage(tmp_path):
    """Elite-analyst adoptions: every report states environment
    coverage as a number, and an OPEN case's residual pack (unaccounted
    items with ranges, evidence, and the adjudication question) is the
    human handoff format."""
    p = write(tmp_path, "helper.sys", pe_with_body(b"\x90" * 8, b"driver entry\x00"))
    v = verdict(p)
    assert v["case_state"] == "OPEN"
    assert v["residual_pack"], v.keys()
    item = v["residual_pack"][0]
    assert item["evidence"] and item["question"] and "next_rung" in item
    cov = v["environment_coverage"]
    assert cov["files_total"] == 1 and cov["files_statically_analysed"] == 1
    assert cov["environments_not_covered"]  # the uncovered list is stated, not omitted
    assert v["receipt"]["environment_coverage"]["files_total"] == 1

def test_no_case_has_empty_residual_pack(tmp_path):
    p = write(tmp_path, "keygen.py", 'import hashlib\n# keygen\nprint("serial:", hashlib.md5(b"x").hexdigest()[:8])\n')
    v = verdict(p)
    assert v["case_state"] == "NO" and v["residual_pack"] == []
