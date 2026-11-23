import os, struct, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from event_zero.virt import analyze_virtualization, trace_entry_stub
from event_zero.verdict import verdict

def pe_with_body(body, extra_strings=b"", section=b".vmp0"):
    dos = bytearray(0x80); dos[0:2] = b"MZ"; struct.pack_into("<I", dos, 0x3c, 0x80)
    coff = struct.pack("<HHIIIHH", 0x8664, 1, 0, 0, 0, 240, 0x22)
    opt = bytearray(240); struct.pack_into("<H", opt, 0, 0x20b); struct.pack_into("<I", opt, 16, 0x1000)
    sec = bytearray(40); sec[0:len(section)] = section; struct.pack_into("<IIII", sec, 8, len(body), 0x1000, 512, 512)
    b = (body + extra_strings).ljust(512, b"\x00")
    return bytes(dos) + b"PE\x00\x00" + coff + bytes(opt) + bytes(sec) + b

# Synthetic VM-like fixture: dispatcher loop bytes (indirect jumps),
# an entry stub (push imm32; call), and an encrypted payload region
# (deterministic high-entropy bytes).
import random
_rnd = random.Random(1337)
ENCRYPTED = bytes(_rnd.randrange(256) for _ in range(1024))
VM_BODY = (b"\x68\x44\x33\x22\x11\xe8\x10\x00\x00\x00"      # push imm32; call (entry stub)
           + b"\xff\xe3" * 6                                # jmp rbx (dispatcher / handler exits)
           + b"\xff\xd2" * 2                                # call rdx
           + b"\x90" * 16 + ENCRYPTED)
VM_FILE = pe_with_body(VM_BODY, b"VMProtect\x00license\x00")

def write(tmp, name, data):
    p = os.path.join(str(tmp), name)
    with open(p, "wb") as f:
        f.write(data)
    return p

# 1. census: protector identified, handlers counted, encrypted region mapped
def test_virt_census():
    from event_zero.stringsx import extract_all
    sx = extract_all(VM_FILE)
    sections = [{"name": ".vmp0", "size": len(VM_BODY)}]
    v = analyze_virtualization(VM_FILE, sx["all"], sections, "game.exe")
    assert v["detected"] and v["protector"] == "VMProtect"
    assert v["handler_census"]["indirect_jump_sites"] >= 3
    assert v["handler_census"]["dispatcher_region"]
    assert len(v["entry_stubs"]) >= 1
    assert v["encrypted_regions"], "the high-entropy payload region must be mapped"
    assert v["unaccounted_units"] >= 1
    assert v["open_list"], "the disclosed open list must travel with the census"

# 2. verdict integration: virtualized units are UNACCOUNTED (fail closed)
def test_virt_verdict_unaccounted(tmp_path):
    p = write(tmp_path, "game_crack.exe", VM_FILE)
    v = verdict(p)
    assert v["headline"] == "YES: MALWARE FOUND" and v["reason_class"] == "UNACCOUNTED"
    f0 = v["files"][0]
    assert f0["virtualization"]["detected"]
    assert f0["virtualization"]["handler_census"]["indirect_jump_sites"] >= 3
    assert any("unaccounted units" in u for u in v["unaccounted"])

# 3. trace harness: runs in Unicorn, logs crossings, never on the host
def test_virt_trace_harness():
    # mov rax, imm64 ("http://x"); jmp rax  -> control leaves the image
    code = b"\x48\xb8" + b"http://x" + b"\xff\xe0"
    t = trace_entry_stub(code)
    assert t["available"], t["note"]
    assert t["instructions_traced"] >= 1
    assert t["api_crossings"], "the jump out of the mapped image is an API crossing and must be logged"
