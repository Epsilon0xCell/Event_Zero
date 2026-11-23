"""Optional Unicorn emulation of carved shellcode. Never executes the sample on the host:
the sample bytes run inside the Unicorn CPU emulator only, with no syscalls serviced."""
def emulate_shellcode(code, arch="x86-64", max_instructions=500):
    try:
        from unicorn import Uc, UC_ARCH_X86, UC_MODE_64, UC_MODE_32, UC_HOOK_CODE
        from unicorn.x86_const import UC_X86_REG_RAX, UC_X86_REG_RBX, UC_X86_REG_RCX, UC_X86_REG_RDX
    except Exception as e:
        return {"available": False, "note": f"Emulation unavailable: Unicorn engine is not installed in this environment ({e}). The static decoder still ran. Install unicorn in the virtual environment to enable sandboxed emulation.", "instructions_emulated": 0}
    try:
        mode=UC_MODE_64 if arch!="x86" else UC_MODE_32
        uc=Uc(UC_ARCH_X86, mode); base=0x1000000
        uc.mem_map(base, 0x100000); uc.mem_write(base, code[:0x10000])
        count=[0]; regs={}
        def hook(u, address, size, user):
            count[0]+=1
            if count[0]>=max_instructions: u.emu_stop()
        uc.hook_add(UC_HOOK_CODE, hook)
        try: uc.emu_start(base, base+len(code[:0x10000]), count=max_instructions)
        except Exception: pass
        try: regs={"rax": hex(uc.reg_read(UC_X86_REG_RAX)), "rbx": hex(uc.reg_read(UC_X86_REG_RBX)), "rcx": hex(uc.reg_read(UC_X86_REG_RCX)), "rdx": hex(uc.reg_read(UC_X86_REG_RDX))}
        except Exception: pass
        mem=bytes(uc.mem_read(base, min(len(code),4096)))
        return {"available": True, "instructions_emulated": count[0], "final_registers": regs, "memory_after_start_hex": mem[:128].hex(), "note": "Shellcode bytes were emulated inside Unicorn only. No host process ran them and no system call was serviced, so this reveals decoder behaviour, not full runtime behaviour."}
    except Exception as e:
        return {"available": False, "note": f"Emulation attempt failed and is labelled, not hidden: {e}", "instructions_emulated": 0}
