"""AV evasion decoding: direct syscalls, API hashing, injection chains, anti-debug/VM/sandbox, AMSI/ETW."""
import re, struct
def _f(fid,name,attack,tech,ev,why): return {"id":fid,"name":name,"attack_id":attack,"technique":tech,"evidence":ev,"plain_english":why}
def analyze_evasion(data, imports, strings):
    imp={i.lower().lstrip('_') for i in imports}; joined="\n".join(strings); low=joined.lower(); out=[]
    # direct syscall stubs: 4c 8b d1 b8 <ssn 2 bytes> 00 00 (0f 05 | c3)
    stubs=[]
    for m in re.finditer(rb'\x4c\x8b\xd1\xb8(.)(.)\x00\x00', data):
        ssn=struct.unpack('<H', m.group(1)+m.group(2) if False else data[m.start()+4:m.start()+6])[0]
        stubs.append({"offset": m.start(), "syscall_number": ssn})
    if stubs or b'\x0f\x05' in data:
        out.append(_f("evasion-direct-syscall","Direct syscall use","T1106","Native API",[f"stub at {s['offset']} with syscall number {s['syscall_number']}" for s in stubs] or ["syscall instruction 0f 05 present"],"Calls the kernel directly instead of through the normal Windows library. Security tools that watch the normal library are bypassed, which is why this is a standard AV and EDR evasion move. The syscall numbers are extracted from the stubs so they can be looked up for the exact Windows build."))
    # API hashing: ror edx,13 = c1 ca 0d ; ror eax,13 = c1 c8 0d ; crc32 insn f2 0f 38 f1
    hashing=[]
    if b'\xc1\xca\x0d' in data or b'\xc1\xc8\x0d' in data: hashing.append("rotate right by 13 instruction, the heart of the ROR13 API hash used since classic shellcode")
    if b'\xf2\x0f\x38\xf1' in data: hashing.append("crc32 instruction, used as an API name hash")
    if hashing: out.append(_f("evasion-api-hashing","API hashing (names hidden)","T1027","Obfuscated Files or Information",hashing,"Instead of naming the Windows functions it wants, which antivirus can read, the code stores short fingerprints and compares each library function name against them at run time. The names only exist for a moment in memory."))
    chain=[a for a in ("virtualallocex","writeprocessmemory","createremotethread") if a in imp or a in low]
    if len(chain)>=2: out.append(_f("inject-chain","Process injection API chain","T1055","Process Injection",chain,"These functions together, not alone, are the recipe: reserve memory in another process, write code into it, then start it running there. Malware hides inside a trusted process this way. Event Zero reports the chain as one finding because each step alone has innocent uses."))
    hollow=[s for s in ("NtUnmapViewOfSection","ZwUnmapViewOfSection","NtCreateSection","ResumeThread") if s.lower() in low or s.lower() in imp]
    if hollow: out.append(_f("inject-hollowing","Process hollowing indicators","T1055.012","Process Hollowing",hollow,"Hollowing starts a trusted program, empties its memory, fills it with malware, then resumes it. To the system it still looks like the trusted program."))
    anti=[]
    if "isdebuggerpresent" in imp or "isdebuggerpresent" in low: anti.append("IsDebuggerPresent import or string")
    if "checkremotedebuggerpresent" in low: anti.append("CheckRemoteDebuggerPresent")
    if b'\x64\xa1\x30\x00\x00\x00' in data or b'\x64\x8b\x04\x25\x30\x00\x00\x00' in data: anti.append("direct access to the process environment block (PEB) at fs:[0x30], where the being-debugged flag lives")
    if data.count(b'\x0f\x31')>=1: anti.append("rdtsc timing instruction, used to tell if a debugger slowed the code down")
    if anti: out.append(_f("evasion-anti-debug","Anti-debug checks","T1622","Debugger Evasion",anti,"The code checks whether an analyst is watching it with a debugger, and usually behaves innocently if one is found."))
    vm=[]
    for pat,label in [(r'VMware',"VMware strings"),(r'VirtualBox|VBox',"VirtualBox strings"),(r'QEMU|KVM',"QEMU or KVM strings"),(r'00:0c:29|00:50:56|08:00:27',"a virtual machine network card address prefix (MAC prefix)")]:
        if re.search(pat, joined): vm.append(label)
    if b'\x0f\xa2' in data: vm.append("cpuid instruction, used to ask the processor if it is running inside a virtual machine")
    if vm: out.append(_f("evasion-anti-vm","Anti virtual machine checks","T1497.001","System Checks",vm,"The code checks whether it is running in a researcher's virtual machine. If it thinks it is, it hides its real behaviour."))
    sand=[]
    if "sleep" in imp and re.search(r'sleep|delay|GetTickCount|GetCursorPos|GetUserName|GetComputerName', joined, re.I): sand.append("sleep or timing and environment checks (Sleep, GetTickCount, cursor or identity checks)")
    if sand: out.append(_f("evasion-sandbox","Sandbox evasion","T1497.003","Time Based Evasion",sand,"Sandboxes watch a sample for a short time, so malware waits them out with long sleeps or checks for signs of a real user, like mouse movement."))
    amsi=[s for s in strings if "AmsiScanBuffer" in s or "EtwEventWrite" in s or "amsi.dll" in s.lower() or "EtwEvent" in s]
    if amsi or b'\xb8\x57\x00\x07\x80\xc3' in data: out.append(_f("evasion-amsi-etw","AMSI or ETW patching indicators","T1562.001","Impair Defenses",amsi or ["known AMSI bypass return value byte pattern (0x80070057, invalid argument)"],"AMSI is the Windows scan interface for scripts and ETW is the Windows event tracing system. Patching them blinds the built in scanners and logging, so later stages run unseen."))
    return {"findings": out, "direct_syscall_stubs": stubs,
            "plain_english": ("Evasion findings: "+", ".join(f["name"] for f in out)+"." if out else "No built in evasion pattern matched. That covers direct syscalls, API hashing, injection chains, hollowing, anti-debug, anti-VM, sandbox checks and AMSI or ETW patching only, it is not proof the sample has no evasion.")}
