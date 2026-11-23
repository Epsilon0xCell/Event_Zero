"""Rootkit analysis for Windows .sys drivers and Linux kernel modules / eBPF."""
import re
WIN_APIS={
 "ntoskrnl.exe":"the Windows kernel itself","hal.dll":"the Windows hardware abstraction layer",
 "MmMapIoSpace":"maps physical memory or device memory into the driver","MmCopyVirtualMemory":"copies memory between processes, used to hide or steal data",
 "ZwOpenProcess":"opens another process from kernel mode","PsLookupProcessByProcessId":"finds a process object, a step in hiding a process (DKOM)",
 "KeServiceDescriptorTable":"the kernel service table (SSDT), the classic hooking target","SSDT":"the kernel service table (SSDT)",
 "IoCreateDevice":"creates a device so user programs can talk to the driver","IoCreateSymbolicLink":"names the driver device for user programs",
 "IoCompleteRequest":"finishes a request from a user program (IRP handling)","IRP_MJ_DEVICE_CONTROL":"handles custom control codes (ioctl) from user programs, the usual rootkit command channel",
 "ZwLoadDriver":"loads another driver","ObRegisterCallbacks":"registers callbacks that can strip handles and hide processes",
 "PsSetCreateProcessNotifyRoutine":"gets told when processes start, used to watch or block security tools",
 "CmRegisterCallback":"gets told about registry access, used to hide registry keys",
}
LINUX_PATTERNS=[
 (r'vermagic=', "kernel version lock string (vermagic), this module only loads on the exact kernel it was built for"),
 (r'sys_call_table|kallsyms_lookup_name', "looks up the system call table, the Linux equivalent of SSDT hooking"),
 (r'getdents|readdir', "hooks directory listing, the classic way to hide files and processes"),
 (r'__x64_sys_|sys_read|sys_write', "touches system call handlers"),
 (r'ioctl', "handles custom control codes (ioctl), a common hidden command channel"),
 (r'netfilter|nf_register', "registers a network filter hook, can hide or redirect traffic"),
 (r'ftrace|kprobe', "uses kernel tracing hooks, used legitimately for debugging and by rootkits to intercept functions"),
 (r'/proc|hide.*process|rootkit', "process hiding or rootkit vocabulary in strings"),
]
def analyze_rootkit(data, imports, strings, fmt, filename="", sections=None):
    low=filename.lower(); joined="\n".join(strings); imp_joined=" ".join(imports)
    is_sys = low.endswith(".sys") or "ntoskrnl.exe" in joined or "ntoskrnl" in imp_joined
    is_ko = low.endswith(".ko") or "vermagic=" in joined
    findings=[]
    for api, why in WIN_APIS.items():
        if api.lower() in joined.lower() or api.lower() in imp_joined.lower():
            findings.append({"indicator": api, "plain_english": why, "attack_id": "T1014", "technique": "Rootkit"})
    linux=[]
    for pat, why in LINUX_PATTERNS:
        if re.search(pat, joined, re.I): linux.append({"pattern": pat, "plain_english": why, "attack_id": "T1014", "technique": "Rootkit"})
    # eBPF in ELF
    bpf=[]
    secnames=[str(s.get("name","")) for s in (sections or []) if isinstance(s,dict)]
    if any("bpf" in s.lower() for s in secnames) or re.search(rb'linux/bpf\.h|BPF_PROG|bpf_map|tracepoint/', data):
        bpf.append({"evidence": [s for s in secnames if "bpf" in s.lower()] or ["bpf strings"], "plain_english": "This ELF carries eBPF programs. eBPF runs inside the kernel and is used by modern security tools and by modern rootkits (for example the public Bvp47 and TripleCross research) to hide processes and traffic.", "attack_id": "T1014"})
    hidden=[]
    for pat, label in [(r'rootkit',"rootkit vocabulary"),(r'hide|hidden|unhook',"hiding vocabulary"),(r'beep\.sys|\\\\Device\\\\|\\\\DosDevices\\\\',"driver device naming")]:
        if re.search(pat, joined, re.I): hidden.append(label)
    kind = "Windows kernel driver (.sys)" if is_sys else "Linux kernel module (.ko)" if is_ko else "not identified as a kernel driver"
    return {"is_kernel_driver": bool(is_sys or is_ko), "driver_kind": kind, "windows_kernel_indicators": findings, "linux_kernel_indicators": linux, "ebpf": bpf, "hiding_indicators": sorted(set(hidden)),
            "volatility_handoff": "Confirmation requires a memory dump analysed with Volatility 3 cross-view plugins: windows.ssdt, windows.driverirp, windows.pslist versus windows.psscan, linux.check_syscall, linux.check_idt, linux.hidden_modules. Static file analysis alone cannot confirm a rootkit.",
            "plain_english": (f"Indicators consistent with a {kind} with rootkit potential were found. That phrasing is deliberate: these are indicators consistent with rootkit behaviour, not a confirmed rootkit. Kernel code runs with the highest privilege, below antivirus. Event Zero lists the exact kernel functions used so each claim can be checked, and confirmation needs the Volatility cross-view handoff below." if (is_sys or is_ko) else "No kernel driver structure was identified, so rootkit specific checks found no driver to judge. User mode hiding patterns, if any, are covered by the evasion section.")}
