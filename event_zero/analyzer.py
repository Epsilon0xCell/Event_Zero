import ast, base64, hashlib, json, math, os, re, struct
from collections import Counter
from .stringsx import extract_all
from .capabilities import match_capabilities
from . import disasm as dismod
from .unpack import analyze_unpack
from .firmware import analyze_firmware
from .rootkit import analyze_rootkit
from .exploit import analyze_exploit
from .evasion import analyze_evasion
from .emulation import emulate_shellcode
from .eli5 import generate_eli5
from . import llm as llmmod
from .formats_extra import analyze_dotnet, analyze_apk, analyze_office, analyze_pdf, analyze_email
from .exports import yara_rule
from .timeline import build_timeline
from .pcap import analyze_pcap
try:
    import lief
    HAVE_LIEF=True
except Exception:
    HAVE_LIEF=False
EICAR_SHA256="275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
def entropy(data):
    if not data: return 0.0
    c=Counter(data); n=len(data)
    return round(-sum((v/n)*math.log2(v/n) for v in c.values()),3)
def hashes(data):
    return {"md5":hashlib.md5(data).hexdigest(),"sha1":hashlib.sha1(data).hexdigest(),"sha256":hashlib.sha256(data).hexdigest(),"sha512":hashlib.sha512(data).hexdigest()}

# ---------- stdlib format parsers (fallback + cross-check) ----------
def parse_elf(data):
    cls=data[4]; endian='< ' if data[5]==1 else '>'
    endian='<' if data[5]==1 else '>'
    machine=struct.unpack(endian+'H', data[18:20])[0]
    etype=struct.unpack(endian+'H', data[16:18])[0]
    arch={0x3e:'x86-64',0x03:'x86',0xb7:'ARM64',0x28:'ARM',0x08:'MIPS',0xf3:'RISC-V'}.get(machine, f'machine-{machine}')
    entry=struct.unpack(endian+'Q' if cls==2 else endian+'I', data[24:32] if cls==2 else data[24:28])[0]
    return {"format":"ELF","variant":"64-bit" if cls==2 else "32-bit","architecture":arch,
            "object_type":{1:"relocatable",2:"executable",3:"shared object / PIE",4:"core"}.get(etype,str(etype)),
            "entry_point":hex(entry),"sections":[],"imports":[],"symbols":[],"libraries":[]}
def parse_pe(data):
    peoff=struct.unpack('<I', data[0x3c:0x40])[0]
    machine, nsec = struct.unpack('<HH', data[peoff+4:peoff+8])
    arch={0x8664:'x86-64',0x14c:'x86',0xaa64:'ARM64',0x1c0:'ARM'}.get(machine, hex(machine))
    opt=peoff+24; magic=struct.unpack('<H', data[opt:opt+2])[0]
    entry=struct.unpack('<I', data[opt+16:opt+20])[0]
    sections=[]
    soff=opt+(224 if magic==0x20b else 96)
    for i in range(nsec):
        off=soff+i*40; name=data[off:off+8].rstrip(b'\x00').decode('ascii','replace')
        vsize, vaddr, rsize, rptr = struct.unpack('<IIII', data[off+8:off+24])
        raw=data[rptr:rptr+rsize] if rptr+rsize<=len(data) else b''
        sections.append({"name":name,"virtual_size":vsize,"raw_size":rsize,"entropy":entropy(raw)})
    return {"format":"PE","variant":"PE32+" if magic==0x20b else "PE32","architecture":arch,"entry_point":hex(entry),"sections":sections,"imports":[],"symbols":[],"libraries":[]}
def parse_macho(data):
    magic=data[:4]
    is64=magic in (b'\xcf\xfa\xed\xfe', b'\xfe\xed\xfa\xcf'); fat=magic in (b'\xca\xfe\xba\xbe', b'\xbe\xba\xfe\xca')
    if fat: return {"format":"Mach-O","variant":"fat (multi-architecture)","architecture":"multiple (see strings/symbols)","sections":[],"segments":[],"imports":[],"symbols":[],"libraries":[],"entry_point":"unknown, labelled: fat header lists slices, entry is per-slice"}
    endian='< ' if magic==b'\xcf\xfa\xed\xfe' else '>'
    endian='<' if magic in (b'\xcf\xfa\xed\xfe', b'\xce\xfa\xed\xfe') else '>'
    cputype=struct.unpack(endian+'I', data[4:8])[0] & 0xffffff
    arch={0x0c:'ARM64',0x07:'x86',0x01000007:'x86-64'}.get(struct.unpack(endian+'I', data[4:8])[0], {12:'ARM64',7:'x86'}.get(cputype,'unknown'))
    ncmds=struct.unpack(endian+'I', data[16:20])[0]
    segs=[]; secs=[]; libs=[]; symbols=[]
    off=32 if is64 else 28
    for _ in range(ncmds):
        if off+8>len(data): break
        cmd, size = struct.unpack(endian+'II', data[off:off+8])
        if cmd in (0x19,0x1) and size>=72:
            segname=data[off+8:off+24].rstrip(b'\x00').decode('ascii','replace'); segs.append(segname)
            nsects=struct.unpack(endian+'I', data[off+64:off+68])[0] if cmd==0x19 else struct.unpack(endian+'I', data[off+60:off+64])[0]
            soff=off+72 if cmd==0x19 else off+56
            for i in range(min(nsects,64)):
                s=data[soff+i*80:soff+i*80+16].rstrip(b'\x00').decode('ascii','replace') if cmd==0x19 else data[soff+i*68:soff+i*68+16].rstrip(b'\x00').decode('ascii','replace')
                if s: secs.append(s)
        if cmd in (0xc,0x1c,0x8000001c,0x18):
            try:
                noff=struct.unpack(endian+'I', data[off+8:off+12])[0]
                libs.append(data[off+noff:off+size].split(b'\x00')[0].decode('ascii','replace'))
            except Exception: pass
        off+= size if size else 8
    return {"format":"Mach-O","variant":"64-bit" if is64 else "32-bit","architecture":arch,"load_commands":ncmds,"segments":segs,"sections":[{"name":s} for s in secs],"linked_libraries":libs,"libraries":libs,"imports":[],"symbols":[],"entry_point":"unknown, labelled: Mach-O entry is in LC_MAIN/LC_THREAD, not decoded by the fallback parser"}
def detect_format(data):
    if data[:4]==b'\x7fELF': return parse_elf(data)
    if data[:2]==b'MZ':
        try: return parse_pe(data)
        except Exception: return {"format":"PE","architecture":"unknown"}
    # Coverage wave 2: a Java class file shares its first four bytes
    # (CAFEBABE) with the fat Mach-O magic, so the class check must
    # run first: a class file is identified by a plausible class-file
    # major version in bytes 6..8, which a fat header's slice count
    # never carries in practice (45..99 against a slice count that
    # would have to be 0x002d0000 or more).
    if data[:4]==b'\xca\xfe\xba\xbe' and len(data)>=8 and 45<=struct.unpack('>H',data[6:8])[0]<=99: return {"format":"Java class","architecture":"JVM","sections":[],"imports":[],"symbols":[]}
    if data[:4]==b'dex\n': return {"format":"DEX","architecture":"Dalvik/ART","sections":[],"imports":[],"symbols":[]}
    if len(data)>=8 and data[:2]==b'\x03\x00' and data[2:4]==b'\x08\x00' and 8<=struct.unpack('<I',data[4:8])[0]<=len(data): return {"format":"Android binary XML","architecture":"n/a","sections":[],"imports":[],"symbols":[]}
    if data[:4] in (b'\xcf\xfa\xed\xfe',b'\xfe\xed\xfa\xcf',b'\xce\xfa\xed\xfe',b'\xfe\xed\xfa\xce',b'\xca\xfe\xba\xbe',b'\xbe\xba\xfe\xca'): return parse_macho(data)
    if data[:4]==b'PK\x03\x04': return {"format":"ZIP archive","architecture":"n/a","sections":[],"imports":[],"symbols":[]}
    # Coverage wave 1 container kinds get their own labels, for the
    # same reason tar does (2026-11-24 accuracy audit, defect 9): a
    # container recognised by the verdict must not fall through to
    # the text heuristic and be judged as script content from its
    # raw bytes.
    _container_stub = {"architecture":"n/a","sections":[],"imports":[],"symbols":[]}
    if len(data)>32774 and data[32769:32774]==b'CD001': return {"format":"ISO 9660 disk image",**_container_stub}
    if data[:4]==b'QFI\xfb': return {"format":"QCOW2 virtual disk",**_container_stub}
    if data[:8]==b'vhdxfile': return {"format":"VHDX virtual disk",**_container_stub}
    if len(data)>=512 and data[-512:-504]==b'conectix': return {"format":"VHD virtual disk",**_container_stub}
    if len(data)>=512 and data[-512:-508]==b'koly': return {"format":"DMG disk image",**_container_stub}
    if data[:4]==b'hsqs': return {"format":"SquashFS filesystem",**_container_stub}
    if data[:4]==b'\x45\x3d\xcd\x28': return {"format":"CRAMFS filesystem",**_container_stub}
    if data[:8]==b'!<arch>\n' and b'debian-binary' in data[:4096]: return {"format":"Debian package",**_container_stub}
    if data[:4]==b'\xed\xab\xee\xdb': return {"format":"RPM package",**_container_stub}
    if len(data)>520 and data[512:520]==b'EFI PART': return {"format":"raw disk image",**_container_stub}
    if len(data)>=1082 and data[1080:1082]==b'\x53\xef': return {"format":"raw disk image",**_container_stub}
    if len(data)>512 and (data[54:59] in (b'FAT12',b'FAT16') or data[82:87]==b'FAT32'): return {"format":"raw disk image",**_container_stub}
    if len(data)>262 and data[257:262]==b'ustar': return {"format":"TAR archive","architecture":"n/a","sections":[],"imports":[],"symbols":[]}
    if data[:5]==b'%PDF-': return {"format":"PDF","architecture":"n/a","sections":[],"imports":[],"symbols":[]}
    if data[:6] in (b'#!/bin',) or data[:3]==b'#!/': return {"format":"script","architecture":"n/a","sections":[],"imports":[],"symbols":[]}
    # Coverage wave 7 model labels, before the text heuristic:
    # a binary pickle is ASCII-adjacent code for a stack machine
    # and a safetensors header is JSON text, so both would fall
    # into the text branch and be acquitted as readable content
    # if the heuristic reached them first.
    if len(data)>=2 and data[0]==0x80 and 2<=data[1]<=5: return {"format":"Python pickle","architecture":"n/a","sections":[],"imports":[],"symbols":[]}
    try:
        from .coverage7 import is_safetensors as _is_st
        if _is_st(data): return {"format":"safetensors model","architecture":"n/a","sections":[],"imports":[],"symbols":[]}
    except Exception: pass
    # text heuristic
    try:
        data[:4096].decode('utf-8'); return {"format":"text / script","architecture":"n/a","sections":[],"imports":[],"symbols":[]}
    except Exception: return {"format":"unknown binary data","architecture":"unknown","sections":[],"imports":[],"symbols":[]}

def lief_parse(path, fallback):
    if not HAVE_LIEF: return fallback, "stdlib fallback parser (lief not installed)"
    try:
        b=lief.parse(path)
        if b is None: return fallback, "stdlib fallback parser (lief could not parse)"
        fmt=str(b.format).split('.')[-1]
        out=dict(fallback)
        out["lief_format"]=fmt
        try: out["entry_point"]=hex(b.entrypoint)
        except Exception: pass
        try: out["libraries"]=[str(getattr(x,"name",x)) for x in b.libraries]
        except Exception: pass
        secs=[]
        try:
            for s in b.sections:
                content=bytes(s.content) if s.content else b''
                secs.append({"name":s.name,"size":s.size,"entropy":entropy(content)})
            if secs: out["sections"]=secs
        except Exception: pass
        imps=[]
        try:
            for lib in b.imports:
                for e in lib.entries:
                    if e.name: imps.append(e.name)
        except Exception: pass
        # ELF dynamic symbols as imports fallback
        if not imps:
            try: imps=[s.name for s in b.dynamic_symbols if s.name]
            except Exception: pass
        syms=[]
        try:
            syms_all=[s.name for s in b.symbols if getattr(s,'name','')]
            if len(syms_all)>500: out["symbols_truncated"]=True
            syms=syms_all[:500]
        except Exception: pass
        if imps: out["imports"]=sorted(set(imps))
        if syms: out["symbols"]=syms
        if getattr(b,'header',None):
            try:
                _a=str(b.header.machine_type).split(".")[-1]
                out["architecture"]={"X86_64":"x86-64","AARCH64":"ARM64","ARM64":"ARM64","I386":"x86","ARM":"ARM"}.get(_a,_a)
            except Exception: pass
        return out, "lief"
    except Exception as e:
        return fallback, f"stdlib fallback parser (lief failed: {e})"

SCRIPT_EXTS={'.py':'Python','.sh':'shell','.bash':'shell','.ps1':'PowerShell','.js':'JavaScript','.bat':'batch','.pl':'Perl','.rb':'Ruby'}
def script_analysis(path, data):
    ext=os.path.splitext(path)[1].lower()
    try: text=data.decode('utf-8')
    except Exception: return None
    kind=SCRIPT_EXTS.get(ext)
    if not kind:
        if text.startswith('#!') and 'python' in text.splitlines()[0]: kind='Python'
        elif text.startswith('#!'): kind='shell'
        elif ext in ('.txt','.com') and len(data)<200: kind=None
        else: return None if '\x00' in text[:2000] else None
    # The full decoded source is kept for judgement: capability
    # matching and the per-line ledger must see every line, so no
    # length cap is applied here. Display excerpts are capped where
    # they are produced (script_source_excerpt), never the source
    # the verdict relies on.
    info={"language":kind,"lines":len(text.splitlines()),"imports":[],"calls":[],"source":text,"source_chars":len(text)}
    if kind=='Python':
        try:
            tree=ast.parse(text)
            for n in ast.walk(tree):
                if isinstance(n, ast.Import):
                    for a in n.names: info["imports"].append(a.name)
                elif isinstance(n, ast.ImportFrom):
                    if n.module: info["imports"].append(n.module)
                elif isinstance(n, ast.Call):
                    try: info["calls"].append(ast.unparse(n.func))
                    except Exception: pass
        except SyntaxError as e: info["parse_error"]=str(e)
    else:
        info["calls"]=re.findall(r'\b(curl|wget|chmod|rm|systemctl|crontab|schtasks|powershell|certutil|nc|ncat|bash|sh)\b', text)
    return info

IMPORT_PLAIN={
 'socket':"creates a network socket",'connect':"connects to a remote address",'send':"sends data over a network or file",'recv':"receives data",'bind':"binds a socket to a local port (listening backdoor pattern)",'listen':"listens for incoming connections",'accept':"accepts an incoming connection",
 'fopen':"opens a file",'fclose':"closes a file",'fwrite':"writes to a file",'fprintf':"writes formatted text to a file or stream",'remove':"deletes a file",'unlink':"deletes a file",'chmod':"changes file permissions",
 'system':"runs a shell command",'popen':"runs a command and reads its output",'execve':"replaces itself with another program",'fork':"creates a child process",
 'sleep':"pauses execution",'usleep':"pauses execution briefly",'malloc':"allocates memory",'free':"frees memory",'memcpy':"copies memory",'strlen':"measures a string",'strcmp':"compares strings",'printf':"prints text",'puts':"prints a line of text",
 'inet_pton':"converts a written IP address into binary form for a connection",'htons':"converts a port number into network byte order",'getaddrinfo':"looks up a hostname or address",
 'ptrace':"traces or debugs a process (also used to detect analysts)",'isdebuggerpresent':"checks whether a debugger is attached",
 'virtualalloc':"allocates memory, often executable memory for injected code",'writeprocessmemory':"writes into another process memory",'createremotethread':"starts a thread in another process",
 'regsetvalueex':"writes a registry value (classic persistence)",'createprocess':"starts a new process",'shellexecute':"opens or runs a file or command",
}
def explain_import(name):
    key=name.lstrip('_').lower()
    for k,v in IMPORT_PLAIN.items():
        if key==k or key.startswith(k): return v
    return "is a library function used by the program, with no specific note in the built-in table, so it is listed by name only"

def analyze(path, use_llm=False, llm_client=None, sandbox_report=None, enrich=False):
    if not os.path.isfile(path): raise FileNotFoundError(path)
    with open(path,'rb') as f: data=f.read()
    h=hashes(data)
    fmt_fallback=detect_format(data)
    fmt, backend = lief_parse(path, fmt_fallback)
    # imports: lief first, else symbols-looking strings / ELF dyn handled in fallback empty -> derive from strings
    imports=list(fmt.get("imports") or [])
    sx=extract_all(data)
    all_strings=sx["all"]
    if not imports:
        cand=set()
        for s in all_strings:
            base=s.lstrip('_').split('@')[0]
            if base.lower() in IMPORT_PLAIN or base in ('socket','connect','send','recv','fopen','system','popen','printf','puts','malloc','free','strlen','close','read','write','open','chmod','remove','unlink','fork','execve','sleep','getaddrinfo','inet_pton','htons'):
                cand.add(base)
        imports=sorted(cand)
    script=script_analysis(path, data)
    # executable bytes for disassembly: ELF/Mach-O/PE first section raw approx: use whole file code heuristic = bytes after header; better: lief section content
    code=b''; code_base=0; code_from_window=False
    if HAVE_LIEF:
        try:
            b=lief.parse(path)
            for s in b.sections:
                if s.name in ('.text','__text') or (hasattr(s,'has_characteristic') and False):
                    code=bytes(s.content); code_base=int(s.virtual_address); break
            if not code and b.sections:
                # largest executable-looking section fallback: first section with size>0 named text-ish
                pass
        except Exception: pass
    if not code and fmt.get("format")=="ELF":
        code=data[64:64+200000]; code_from_window=True
    elif not code and fmt.get("format") in ("Mach-O","PE"):
        code=data[:200000]; code_from_window=True
    arch_raw=str(fmt.get("architecture",""))
    arch_map={'X86_64':'x86-64','x86-64':'x86-64','AMD64':'x86-64','I386':'x86','x86':'x86','ARM64':'ARM64','AARCH64':'ARM64','ARM':'ARM'}
    arch=arch_map.get(arch_raw, arch_raw if arch_raw in ('x86','x86-64','ARM','ARM64') else 'x86-64' if fmt.get("format") in ('ELF','PE') else arch_raw)
    dis=disassemble_wrap(code, arch, code_base)
    caps=match_capabilities(imports+list(fmt.get("symbols") or []), all_strings+(["xor-encoded strings decoded by Event Zero"] if sx["xor_decoded"] else []), dis["mnemonics"], script["source"] if script else "")
    # IOCs
    urls=sorted(set(re.findall(r'https?://[^\s"\'<>\)]+', '\n'.join(all_strings))))
    ips=sorted(set(re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', '\n'.join(all_strings))))
    ips=[i for i in ips if all(int(p)<=255 for p in i.split('.'))]
    domains=sorted(set(re.findall(r'\b(?:[a-z0-9-]+\.)+(?:com|net|org|io|ru|cn|info|top|xyz|onion)\b', '\n'.join(all_strings).lower())))
    files_mentioned=sorted(set(re.findall(r'/(?:tmp|etc|var|usr|home)/[^\s"\'<>]+', '\n'.join(all_strings))))
    # sections entropy + packing
    secs=fmt.get("sections") or []
    for s in secs:
        if isinstance(s, dict) and "entropy" not in s: s["entropy"]="not computed by fallback parser for this section"
    overall=entropy(data)
    packing=[]
    if overall>7.2: packing.append(f"Whole-file entropy is high ({overall}/8.0), consistent with packing or encryption.")
    if any(x in '\n'.join(all_strings) for x in ('UPX!','UPX0','UPX1')): packing.append("UPX packer markers found in strings.")
    if any(isinstance(s,dict) and isinstance(s.get("entropy"),(int,float)) and s["entropy"]>7.2 for s in secs): packing.append("At least one section has entropy above 7.2, consistent with packed or encrypted content in that section.")
    if not packing: packing.append(f"No strong packing signal: whole-file entropy is {overall}/8.0 and no UPX markers were found. Low whole-file entropy can be pulled down by zero padding in Mach-O and ELF files, so this is not proof of no packing.")
    # risk
    cap_ids={c["id"] for c in caps}
    score=0; reasons=[]
    weights={'exec-shell':25,'exec-download-run':30,'inject-process':30,'cred-access':20,'net-connect':15,'net-listen':20,'persist-runkey':20,'persist-file':15,'persist-schtask':15,'anti-debug':15,'mining':15,'keylog':25,'crypto-aes':10,'file-delete':10}
    for cid,w in weights.items():
        if cid in cap_ids: score+=w; reasons.append(f"Capability detected: {cid}")
    if h["sha256"]==EICAR_SHA256: verdict="TEST FILE (EICAR, harmless)"; score=0
    elif score>=50: verdict="HIGH RISK"
    elif score>=25: verdict="SUSPICIOUS"
    elif score>0: verdict="LOW TO MEDIUM RISK, review the capabilities listed"
    else: verdict="NO MALICIOUS CAPABILITY DETECTED by static rules. This is not proof the file is safe."
    unknowns=[]
    unknowns.append("Runtime behaviour was not observed: the sample was never executed, so network traffic, timing, and environment checks it performs can only be inferred from static evidence.")
    if 'anti-debug' in cap_ids or 'anti-sleep' in cap_ids: unknowns.append("Anti-analysis behaviour was detected, so the sample may behave differently under analysis than on a real machine.")
    if packing and 'high' in packing[0]: unknowns.append("Packing or encryption is suspected, so some code and strings may only appear after the sample unpacks itself at runtime.")
    if not dis["available"]: unknowns.append("Disassembly was not available (Capstone missing or unsupported architecture), so function-level conclusions rest on imports, symbols, and strings.")
    if fmt.get("format")=="unknown binary data": unknowns.append("File format was not recognised, so format-specific fields could not be filled.")
    if script: unknowns.append("Script was analysed as source text. Obfuscated or dynamically generated code in it (eval, exec of decoded strings) is flagged as a capability when seen, but its final payload cannot be known without running it in a sandbox.")
    # ---- v3 advanced modules ----
    unpack_r=analyze_unpack(data, all_strings, secs, os.path.basename(path))
    firmware_r=analyze_firmware(data, all_strings)
    rootkit_r=analyze_rootkit(data, imports, all_strings, fmt, os.path.basename(path), secs)
    code_for_exploit=code if code else data[:200000]
    exploit_r=analyze_exploit(data, all_strings, imports, code_for_exploit, arch!="x86")
    evasion_r=analyze_evasion(data, imports, all_strings)
    emu={"available": False, "note": "No shellcode region was identified for emulation.", "instructions_emulated": 0}
    if exploit_r["nop_sleds_and_spray"] or exploit_r["egghunter_detected"]:
        sled_off=exploit_r["nop_sleds_and_spray"][0]["offset"] if exploit_r["nop_sleds_and_spray"] else 0
        emu=emulate_shellcode(data[sled_off:sled_off+4096], arch if arch in ("x86","x86-64") else "x86-64")
    # re-run capability rules over multi-layer decoded content
    decoded_texts=[d.get("result","") for d in unpack_r.get("decoded_layers",[])]
    if decoded_texts:
        extra=match_capabilities([], decoded_texts, [], " ".join(decoded_texts))
        seen={c["id"] for c in caps}
        for c in extra:
            if c["id"] not in seen: caps.append(c); seen.add(c["id"])
        cap_ids={c["id"] for c in caps}
    # ---- capa-backed capability evidence (coverage wave 9) ----
    # A second, independent capability source behind the same
    # interface: capa entries carry ids under the capa: prefix
    # that cannot collide with the authored ids the risk score
    # weights and every verdict chain are keyed on, and they are
    # merged after scoring, so capa evidence can neither convict
    # nor acquit here; it is evidence for the accounting. Any
    # capa failure degrades to the own-matcher evidence with the
    # failure named in the report's capa field.
    capa_info={"status":"skipped","note":"capa evidence applies to PE and ELF inputs only."}
    if fmt.get("format") in ("PE","ELF"):
        from .capa_evidence import capa_capabilities, merge_capabilities
        capa_entries, capa_info = capa_capabilities(path, fmt.get("format"), data)
        if capa_entries:
            caps=merge_capabilities(caps, capa_entries)
            cap_ids={c["id"] for c in caps}
    adv_score=0; adv_reasons=[]
    if evasion_r["findings"]: adv_score+=10*len(evasion_r["findings"]); adv_reasons.append(f"Evasion findings: {len(evasion_r['findings'])}")
    if rootkit_r["is_kernel_driver"]: adv_score+=25; adv_reasons.append("Kernel driver (rootkit surface)")
    if firmware_r["red_flags"]: adv_score+=10*len(firmware_r["red_flags"]); adv_reasons.append("Firmware red flags")
    if exploit_r["egghunter_detected"]: adv_score+=15; adv_reasons.append("Egghunter shellcode pattern")
    if unpack_r["carved"]: adv_score+=5; adv_reasons.append("Embedded binaries carved")
    score=min(score+adv_score,100); reasons=reasons+adv_reasons
    if h["sha256"]==EICAR_SHA256: verdict="TEST FILE (EICAR, harmless)"; score=0
    elif score>=50: verdict="HIGH RISK"
    elif score>=25: verdict="SUSPICIOUS"
    elif score>0 and verdict.startswith("NO MALICIOUS"): verdict="LOW TO MEDIUM RISK, review the capabilities listed"
    if h["sha256"]!=EICAR_SHA256:
        if score>=50: verdict="HIGH RISK"
        elif score>=25: verdict="SUSPICIOUS"
    # ---- truncations: every cap that cut material a judgement can
    # depend on is recorded explicitly. The verdict turns each entry
    # into an unaccounted marker for NO purposes (a file accounted by
    # byte identity, hash match or a strong manifest hash, does not
    # depend on the truncated analysis and is exempt there). Silence
    # about a cap is how truncated evidence once passed as complete.
    truncs=[]
    if code_from_window and len(data)>200000:
        truncs.append("the disassembly code window covers only the first 200000 bytes of the file, so code past that window was not disassembled")
    if len(dis["instructions"])>=4000:
        truncs.append("disassembly stopped at the 4000-instruction cap, so instructions past the cap were not examined")
    if fmt.get("symbols_truncated"):
        truncs.append("the symbol list stopped at 500 entries, so symbols past that cap were not examined")
    if len(data)>16384:
        truncs.append("the entropy map covers only the first 16384 bytes, so high-entropy regions past that point were not mapped")
    if emu.get("instructions_emulated",0)>=500:
        truncs.append("shellcode emulation stopped at the 500-instruction budget, so behaviour past that budget was not emulated")
    if script is None and (os.path.splitext(path)[1].lower() in SCRIPT_EXTS or data[:3]==b'#!/'):
        truncs.append("the file looks like a script but its source could not be fully decoded as UTF-8, so script behaviour accounting is incomplete")
    if unpack_r["virtualization"]["detected"]: unknowns.append("Virtualizing packer detected: original code is private bytecode run by an interpreter, so static analysis can map the protector and entry, not the original logic. That remainder needs dynamic analysis in a sandbox.")
    if firmware_r["is_firmware_image"]: unknowns.append("Firmware was analysed statically. Whether each carved driver is signed and loaded at boot can only be confirmed against the platform firmware configuration.")
    report={
      "tool":"Event Zero","version":"3.0.0","file":path,"filename":os.path.basename(path),"size_bytes":len(data),
      "hashes":h,"eicar_test_file":h["sha256"]==EICAR_SHA256,
      "format":fmt,"parser_backend":backend,"overall_entropy":overall,
      "sections":secs,"packing_assessment":packing,
      "imports":[{"name":i,"plain_english":explain_import(i)} for i in imports],
      "symbols":(fmt.get("symbols") or [])[:200],
      "strings":{"count":len(all_strings),"ascii_count":len(sx["ascii"]),"utf16_count":len(sx["utf16"]),"all":all_strings,"base64_decoded":sx["base64_decoded"],"xor_decoded":sx["xor_decoded"]},
      "disassembly":{"available":dis["available"],"note":dis["note"],"instruction_count":len(dis["instructions"]),"instructions":dis["instructions"][:500],"call_sites":dis.get("call_sites",[])},
      "capabilities":caps,
      "capa":capa_info,
      "script_analysis":({k:v for k,v in script.items() if k!='source'} if script else None),
      "script_source_excerpt":(script["source"][:4000] if script else None),
      "script_source_full":(script["source"] if script else None),
      "truncations":truncs,
      "iocs":{"urls":urls,"ip_addresses":ips,"domains":domains,"file_paths":files_mentioned},
      "unpack":unpack_r,"firmware":firmware_r,"rootkit":rootkit_r,"exploit":exploit_r,"evasion":evasion_r,"emulation":emu,
      "risk":{"score":min(score,100),"verdict":verdict,"reasons":reasons},
      "unknowns":unknowns,
    }
    report["plain_english"]=plain_english(report)
    report["llm"]={"status":"not_configured","provider":"gemini","model":llmmod.DEFAULT_MODEL,"note":"LLM layer not configured: run with --gemini and a GEMINI_API_KEY or GOOGLE_API_KEY in the environment to enable the evidence-gated Gemini narrative. The deterministic report is complete without it."}
    from .tools_registry import registry as _reg
    from .services import browser_links as _links, not_configured_enrichment as _nce, enrich as _enrich
    report["dotnet"]=analyze_dotnet(data, all_strings)
    report["apk"]=analyze_apk(data, path)
    report["office"]=analyze_office(data, all_strings)
    report["pdf"]=analyze_pdf(data, all_strings)
    report["email"]=(analyze_email(data) if data[:100].lstrip().lower().startswith((b"from:",b"from ",b"subject:",b"return-path:",b"received:",b"mime-version:")) or os.path.splitext(path)[1].lower()==".eml" else {"is_email": False})
    report["pcap"]=analyze_pcap(data)
    report["timeline"]=build_timeline(report)
    report["generated_yara"]=yara_rule(report)
    report["tools_available"]=[x for x in _reg() if x["installed"]]
    report["browser_links"]=_links(h["sha256"])
    report["enrichment"]=_enrich(h["sha256"]) if enrich else _nce(h["sha256"])
    if sandbox_report:
        from .hybrid import ingest_sandbox_report as _ing
        report["sandbox"]=_ing(sandbox_report)
    else: report["sandbox"]=None
    report["eli5"]=generate_eli5(report)
    from .readability import scores as _rs; report["eli5_metrics"]=_rs(report["eli5"])
    if use_llm or llm_client is not None:
        narrative, status = llmmod.enhance_report(report, client=llm_client)
        report["llm"]=status
        if narrative: report["llm_narrative"]=narrative
        # Gemini may polish ELI5 only through the same gate
        if narrative:
            clean, dropped = llmmod.verify_narrative(narrative, report)
            report["llm"]["eli5_polish_gate_dropped"]=dropped
    return report

def disassemble_wrap(code, arch, base):
    d=disassemble_real(code, arch, base)
    return d
def disassemble_real(code, arch, base):
    from .disasm import disassemble, function_summaries
    # function_summaries needs imports; filled by caller via empty here, call sites computed in analyze is skipped; keep simple
    d=disassemble(code, arch, base)
    d["call_sites"]=[]
    return d

def plain_english(r):
    lines=[]
    lines.append(f"This file is called {r['filename']} and it is {r['size_bytes']} bytes in size.")
    f=r['format']; lines.append(f"It is a {f.get('format','unknown')} file for {f.get('architecture','unknown architecture')}" + (f", variant {f.get('variant')}" if f.get('variant') else "") + ".")
    if r['eicar_test_file']: lines.append("It is the EICAR antivirus test file. It is harmless and exists only so people can check that security tools are working.")
    lines.append(f"Its fingerprint (SHA-256) is {r['hashes']['sha256']}. If anyone else reports this exact fingerprint, they are talking about the exact same file, byte for byte.")
    if r['imports']: lines.append("It borrows these ready-made functions from the operating system and libraries: " + ", ".join(i['name'] for i in r['imports'][:40]) + ". In plain terms: " + "; ".join(f"{i['name']} means it {i['plain_english']}" for i in r['imports'][:12]) + ".")
    else: lines.append("No imported functions could be listed. That can happen with scripts, stripped files, or formats the parser could not read in detail, and it is recorded as a gap rather than hidden.")
    if r['capabilities']:
        lines.append("Here is what the evidence says it can do:")
        for c in r['capabilities']: lines.append(f"- {c['name']} (MITRE ATT&CK {c['attack_id']}, {c['technique']}): {c['explanation']} Evidence: {', '.join(c['evidence'])}.")
    else:
        lines.append("No capability from the built-in rule set matched. That means none of the checked behaviours (networking, shell commands, persistence, injection, credential access, and the rest) were found in the imports, strings, or instructions that were examined.")
    lines.append("Packing check: " + " ".join(r['packing_assessment']))
    if r['iocs']['urls'] or r['iocs']['ip_addresses']: lines.append(f"Network names and addresses written inside the file: URLs {r['iocs']['urls'] or 'none'}, IP addresses {r['iocs']['ip_addresses'] or 'none'}, domains {r['iocs']['domains'] or 'none'}. A name written in a file is a lead, not proof the program contacts it.")
    if r['strings']['base64_decoded']: lines.append(f"Some text was hidden with Base64 and has been decoded in this report: {r['strings']['base64_decoded'][:5]}.")
    if r['strings']['xor_decoded']: lines.append(f"Some text appears to be hidden with a single-byte XOR key and has been decoded in this report: keys {[x['key_hex'] for x in r['strings']['xor_decoded']]}.")
    lines.append(f"Verdict: {r['risk']['verdict']} (rule score {r['risk']['score']}/100).")
    lines.append("What is not known: " + " ".join(r['unknowns']))
    return lines
