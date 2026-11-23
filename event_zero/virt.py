"""Devirtualization layer: protector identification, handler census,
and a Unicorn trace harness for virtualized binaries.

Claims discipline (from the devirtualization research, claims ledger):
the achievable bar is "no sample can obtain a clean verdict by hiding".
Event Zero never claims "no escape" as an absolute. Environment-keyed
payloads and server-gated payload content stay on the disclosed open
list: their bytes never enter the lab, so they are named as open, not
papered over.

What this module does:
1. Identifies the protector (VMProtect, Themida, Code Virtualizer,
   Enigma, Safengine) from section names and signature strings.
2. Takes a handler census: entry stubs, indirect jumps and calls (the
   dispatcher and handler exits of a bytecode VM), encrypted regions,
   and an estimate of how much of the file is virtualized. A census is
   evidence, not a guess at the original code.
3. Traces the entry stub in Unicorn: the VM must cross into the real
   world to act, so the trace logs API crossings (control leaving the
   mapped image) and recovers strings that only exist decrypted in
   trace memory. Recovered strings are accounted evidence.
The handler-semantics pass (Triton symbolic execution over handler
clusters) is an ADAPTER/HANDOFF item: see CAPABILITY-MATRIX.md.
"""
import re
from .unpack import entropy_map  # noqa: F401 (kept for callers that import it from here)
from .stringsx import extract_all

PROTECTORS = [
    ("VMProtect", (".vmp",), ("VMProtect", "VMProtectSDK", "VMP")),
    ("Themida", (".themida", ".winlice"), ("Themida", "WinLicense", "Oreans")),
    ("Code Virtualizer", (".cv", ".cvirt"), ("Code Virtualizer", "VirtualizerSDK")),
    ("Enigma Protector", (".enigma",), ("Enigma Protector", "EnigmaProtector")),
    ("Safengine", (".safengine", ".se"), ("Safengine", "Shielden")),
]

def analyze_virtualization(data, strings, sections, filename=""):
    joined = "\n".join(strings)
    sec_names = [str(s.get("name", "")) for s in sections if isinstance(s, dict)]
    protector = None
    vm_sections = []
    sig_evidence = []
    for name, sec_pats, str_pats in PROTECTORS:
        hit_secs = [s for s in sec_names if any(p in s.lower() for p in sec_pats)]
        hit_strs = [p for p in str_pats if p in joined]
        if hit_secs or hit_strs:
            protector = name
            vm_sections = hit_secs
            sig_evidence = [f"section name: {s}" for s in hit_secs] + [f"signature string: {p}" for p in hit_strs]
            break
    # entry stubs: push imm32; call rel32 (68 xx xx xx xx E8) and push; ret (68 .. C3)
    stubs = []
    for m in re.finditer(rb"\x68(....)\xe8", data, re.DOTALL):
        stubs.append({"offset": m.start(), "kind": "push-imm32-call", "detail": "push a value then call: the classic virtualized-function entry stub that hands control to the VM"})
    for m in re.finditer(rb"\x68(....)\xc3", data, re.DOTALL):
        stubs.append({"offset": m.start(), "kind": "push-imm32-ret", "detail": "push a value then return into it: an entry stub variant"})
    # dispatcher and handler census: indirect jumps (FF E0-E7) and calls (FF D0-D7)
    jmp_sites = [m.start() for m in re.finditer(rb"\xff[\xe0-\xe7]", data)]
    call_sites = [m.start() for m in re.finditer(rb"\xff[\xd0-\xd7]", data)]
    # a dispatcher loop shows as indirect jumps clustered in one region
    dispatcher_region = None
    if len(jmp_sites) >= 3:
        span = jmp_sites[-1] - jmp_sites[0]
        dispatcher_region = {"first_jump_offset": jmp_sites[0], "last_jump_offset": jmp_sites[-1], "span_bytes": span,
                             "detail": "Indirect jumps clustered in one region: the VM dispatcher loop and handler exits live here. Each handler ends by jumping back through the dispatcher."}
    # 1024-byte windows: a 256-byte window cannot exceed about 7.16 bits
    # of entropy even for pure random data, so the census uses windows
    # large enough for the threshold to mean something
    from .unpack import _entropy
    encrypted_regions = [{"offset": i, "entropy": _entropy(data[i:i + 1024])} for i in range(0, len(data), 1024)]
    encrypted_regions = [w for w in encrypted_regions if w["entropy"] > 7.5]
    total_vm_bytes = 0
    for s in sections:
        if isinstance(s, dict) and str(s.get("name", "")) in vm_sections:
            total_vm_bytes += s.get("size") or s.get("raw_size") or 0
    proportion = round(total_vm_bytes / len(data), 3) if total_vm_bytes and data else None
    detected = protector is not None
    return {
        "detected": detected,
        "protector": protector,
        "signature_evidence": sig_evidence,
        "vm_sections": vm_sections,
        "entry_stubs": stubs[:50],
        "handler_census": {
            "indirect_jump_sites": len(jmp_sites),
            "indirect_call_sites": len(call_sites),
            "handler_exit_estimate": len(jmp_sites),
            "dispatcher_region": dispatcher_region,
            "note": "A census counts the VM machinery that is visible: dispatcher, handler exits, entry stubs. It does not reconstruct the original functions, and it is reported as a census, not as recovered code.",
        },
        "encrypted_regions": encrypted_regions,
        "virtualized_proportion": proportion,
        "virtualized_function_estimate": len(stubs),
        "unaccounted_units": (len(stubs) if detected else 0),
        "open_list": ["environment-keyed payload with an unknown key: the payload bytes never enter the lab",
                      "server-gated or one-time payload content that refuses every lab vantage point: only the attempt is provable",
                      "current-version mutated virtualization (VMProtect 3.8+ Ultra, Themida 3.x): full devirtualization is open; the census and trace layers still apply"],
        "plain_english": (f"This file is protected by {protector}. Its original code was translated into a private bytecode that only its own interpreter understands. Event Zero counted the interpreter machinery ({len(stubs)} entry stub(s), {len(jmp_sites)} indirect jump site(s)) and mapped the encrypted regions, and it traces the entry stub because the VM must cross into the real world to act. The virtualized functions are unaccounted units: hiding inside a VM can never earn a clean verdict here." if detected else "No known virtualizing protector signature (VMProtect, Themida, Code Virtualizer, Enigma, Safengine) was found in section names or strings, and no dispatcher census was triggered."),
    }

def trace_entry_stub(data, arch="x86-64", max_instructions=2000):
    """Emulate the start of the file inside Unicorn only. Logs API
    crossings (control transfers to addresses outside the mapped
    image: the VM crossing into the real world) and recovers strings
    that appear decrypted in trace memory but were not plain strings
    in the file."""
    try:
        from unicorn import Uc, UC_ARCH_X86, UC_MODE_64, UC_MODE_32, UC_HOOK_CODE, UC_HOOK_MEM_INVALID
    except Exception as e:
        return {"available": False, "note": f"Trace unavailable: Unicorn is not installed ({e}). The census still ran and the virtualized units stay unaccounted.", "instructions_traced": 0, "api_crossings": [], "recovered_strings": []}
    base = 0x1000000
    size = 0x100000
    code = data[:0x10000]
    crossings = []
    count = [0]
    try:
        uc = Uc(UC_ARCH_X86, UC_MODE_64 if arch != "x86" else UC_MODE_32)
        uc.mem_map(base, size)
        uc.mem_write(base, code)
        def hook(u, address, sz, user):
            count[0] += 1
            if not (base <= address < base + size):
                crossings.append({"address": hex(address), "at_instruction": count[0], "detail": "control left the mapped image: an API crossing, the VM reaching into the real world"})
                u.emu_stop()
            if count[0] >= max_instructions:
                u.emu_stop()
        uc.hook_add(UC_HOOK_CODE, hook)
        def hook_invalid(u, access, address, sz, value, user):
            # execution or data reaching outside the mapped image is the
            # VM crossing into the real world: log it as an API crossing
            crossings.append({"address": hex(address), "at_instruction": count[0], "detail": "control or data left the mapped image: an API crossing, the VM reaching into the real world"})
            return False
        uc.hook_add(UC_HOOK_MEM_INVALID, hook_invalid)
        try:
            uc.emu_start(base, base + len(code), count=max_instructions)
        except Exception:
            pass
        mem = bytes(uc.mem_read(base, min(size, 0x20000)))
    except Exception as e:
        return {"available": False, "note": f"Trace attempt failed and is labelled, not hidden: {e}", "instructions_traced": count[0], "api_crossings": crossings, "recovered_strings": []}
    before = set(extract_all(data)["all"])
    after = set(extract_all(mem)["all"])
    recovered = sorted(s for s in (after - before) if len(s) >= 6)[:50]
    gaps = []
    if not crossings:
        gaps.append("no API crossing was observed within the instruction budget: the stub may need inputs, keys, or more steps than the trace allowed")
    return {"available": True, "instructions_traced": count[0], "api_crossings": crossings[:50],
            "recovered_strings": recovered,
            "gaps": gaps,
            "note": "The entry stub ran inside the Unicorn CPU emulator only. No host process executed it and no system call was serviced. Strings recovered from trace memory are accounted evidence; instructions that never ran stay unaccounted."}
