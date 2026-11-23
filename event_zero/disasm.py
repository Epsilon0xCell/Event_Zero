"""Capstone disassembly with graceful degradation."""
try:
    import capstone
    HAVE=True
except Exception:
    HAVE=False
ARCHMAP={"x86":("CS_ARCH_X86","CS_MODE_32"),"x86-64":("CS_ARCH_X86","CS_MODE_64"),"ARM":("CS_ARCH_ARM","CS_MODE_ARM"),"ARM64":("CS_ARCH_ARM64","CS_MODE_LITTLE_ENDIAN"),"MIPS":("CS_ARCH_MIPS","CS_MODE_MIPS32")}
def disassemble(code, arch, base=0, max_insns=4000):
    if not HAVE or arch not in ARCHMAP or not code:
        return {"available":HAVE,"instructions":[],"mnemonics":[],"note":"Capstone not installed" if not HAVE else f"No disassembly for architecture {arch}"}
    a,m=ARCHMAP[arch]
    md=capstone.Cs(getattr(capstone,a), getattr(capstone,m))
    md.detail=False
    ins=[]; mn=[]
    for i in md.disasm(code, base):
        ins.append({"address":hex(i.address),"mnemonic":i.mnemonic,"op_str":i.op_str,"text":f"{i.mnemonic} {i.op_str}".strip()})
        mn.append(i.mnemonic)
        if len(ins)>=max_insns: break
    return {"available":True,"instructions":ins,"mnemonics":mn,"note":f"Disassembled {len(ins)} instructions (cap {max_insns}) from executable section bytes"}
def function_summaries(instructions, imports):
    """Group by call targets; produce plain-English per call-site summary."""
    imp_lower={i.lower():i for i in imports}
    out=[]
    for ins in instructions:
        if ins["mnemonic"] in ("call","bl","blr","jmp"):
            tgt=ins["op_str"].strip()
            for k,v in imp_lower.items():
                if k in tgt.lower():
                    out.append({"address":ins["address"],"calls":v,"plain":f"At {ins['address']} the code calls {v}."})
    return out[:200]
