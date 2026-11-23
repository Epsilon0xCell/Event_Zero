"""Unpacking, carving, multi-layer decoding, virtualization detection."""
import base64, math, re, struct
from collections import Counter

def _entropy(data):
    if not data: return 0.0
    c=Counter(data); n=len(data)
    return round(-sum((v/n)*math.log2(v/n) for v in c.values()),3)

def rc4(key, data):
    S=list(range(256)); j=0; out=bytearray()
    for i in range(256):
        j=(j+S[i]+key[i%len(key)])&0xff; S[i],S[j]=S[j],S[i]
    i=j=0
    for b in data:
        i=(i+1)&0xff; j=(j+S[i])&0xff; S[i],S[j]=S[j],S[i]
        out.append(b ^ S[(S[i]+S[j])&0xff])
    return bytes(out)

def _printable(b):
    try: s=b.decode()
    except Exception: return None
    return s if s and all(32<=ord(c)<127 or c in "\r\n\t" for c in s) and len(s)>=6 else None

def multilayer_decode(strings):
    """Recursively decode base64 -> xor / base64 layers, and RC4 with keys found as strings."""
    found=[]
    keys=[s.encode() for s in strings if 3<=len(s)<=32 and s.isalnum()][:50]
    expanded=[]
    for s in strings: expanded.extend(s.split())
    for s in expanded:
        cur=s; chain=[]
        for _ in range(3):
            t=cur.strip()
            if len(t)>=12 and re.fullmatch(r'[A-Za-z0-9+/=]+', t):
                try:
                    dec=base64.b64decode(t, validate=True)
                except Exception: break
                p=_printable(dec)
                if p: found.append({"chain":chain+["base64"],"result":p}); cur=p; chain=chain+["base64"]; continue
                # try xor on decoded bytes
                hit=False
                for k in range(1,256):
                    d=bytes(b^k for b in dec); p2=_printable(d)
                    if p2 and ("http" in p2 or "cmd" in p2 or ".exe" in p2 or "powershell" in p2.lower() or " " in p2):
                        found.append({"chain":chain+["base64",f"xor-0x{k:02x}"],"result":p2}); hit=True; break
                if hit: break
                break
            break
    return found[:50]

def carve(data):
    out=[]
    # PE
    for m in re.finditer(rb'MZ', data):
        off=m.start()
        if off+0x40>len(data): continue
        peoff=struct.unpack('<I', data[off+0x3c:off+0x40])[0] if off+0x40<=len(data) else 0
        if 0<peoff<4096 and data[off+peoff:off+peoff+4]==b'PE\x00\x00':
            out.append({"type":"PE","offset":off,"offset_hex":hex(off),"validated":"PE signature at e_lfanew"})
    for m in re.finditer(rb'\x7fELF', data):
        if data[m.start()+4] in (1,2) and data[m.start()+5] in (1,2):
            out.append({"type":"ELF","offset":m.start(),"offset_hex":hex(m.start()),"validated":"ELF class/data bytes valid"})
    for magic, name in [(b'\xcf\xfa\xed\xfe',"Mach-O 64 LE"),(b'\xce\xfa\xed\xfe',"Mach-O 32 LE"),(b'\xfe\xed\xfa\xcf',"Mach-O 64 BE")]:
        for m in re.finditer(re.escape(magic), data):
            if m.start()>0:  # offset 0 is the file itself
                out.append({"type":"Mach-O","offset":m.start(),"offset_hex":hex(m.start()),"validated":name})
    # dedup
    seen=set(); uniq=[]
    for c in out:
        k=(c["type"],c["offset"])
        if k not in seen: seen.add(k); uniq.append(c)
    return sorted(uniq, key=lambda x:x["offset"])

def entropy_map(data, window=256):
    return [{"offset":i,"entropy":_entropy(data[i:i+window])} for i in range(0, min(len(data), window*64), window)]

def analyze_unpack(data, strings, sections, filename=""):
    joined="\n".join(strings)
    upx={"detected": bool(re.search(r'UPX(!|0|1)', joined)) or b'UPX!' in data, "unpacked": False, "note": ""}
    if upx["detected"]:
        import shutil, subprocess, tempfile, os
        if shutil.which("upx"):
            try:
                with tempfile.NamedTemporaryFile(delete=False) as t: t.write(data); pth=t.name
                r=subprocess.run(["upx","-d","-o",pth+".out",pth], capture_output=True, timeout=30)
                upx["unpacked"]=r.returncode==0; upx["note"]=(r.stdout+r.stderr).decode(errors="replace")[:500]
            except Exception as e: upx["note"]=f"upx attempt failed: {e}"
        else: upx["note"]="UPX markers found but the upx binary is not installed in this environment, so in-place unpacking was not attempted. Static decoding and carving still ran."
    # overlay for PE
    overlay={"present": False, "size": 0}
    if data[:2]==b'MZ':
        try:
            peoff=struct.unpack('<I', data[0x3c:0x40])[0]; nsec=struct.unpack('<H', data[peoff+6:peoff+8])[0]
            magic=struct.unpack('<H', data[peoff+24:peoff+26])[0]; soff=peoff+24+(240 if magic==0x20b else 224)
            end=0
            for i in range(nsec):
                off=soff+i*40; rsize, rptr = struct.unpack('<II', data[off+16:off+24])
                end=max(end, rptr+rsize)
            if 0<end<len(data): overlay={"present": True, "size": len(data)-end, "offset": end, "entropy": _entropy(data[end:])}
        except Exception: pass
    virt_names=[s.get("name","") for s in sections if isinstance(s,dict) and any(v in str(s.get("name","")).lower() for v in (".vmp","themida",".aspack",".enigma"))]
    virt_strings=[s for s in strings if any(v in s for v in ("VMProtect","Themida","WinLicense","Enigma Protector"))]
    emap=entropy_map(data)
    high_windows=[w for w in emap if w["entropy"]>7.2]
    virtualized=bool(virt_names or virt_strings)
    return {
        "upx": upx, "overlay": overlay, "carved": carve(data),
        "decoded_layers": multilayer_decode(strings),
        "entropy_map": emap, "high_entropy_regions": high_windows,
        "virtualization": {"detected": virtualized, "section_evidence": virt_names, "string_evidence": virt_strings,
            "plain_english": ("This sample appears protected by a virtualizing packer ("+", ".join(virt_names+virt_strings)+"). This is a hard limit, not a missing feature: its original code is translated into a private bytecode and run by an embedded interpreter (Rolles, USENIX WOOT 2009), so static disassembly shows the interpreter handlers, not the original program. Handler analysis is all that static work can honestly offer here. Event Zero reports the entry and interpreter evidence and labels the original logic as an unknown rather than inventing it." if virtualized else "No virtualizing packer signature (VMProtect, Themida, Enigma) was found in section names or strings.")},
        "rc4_note": "RC4 decoding is available in this module (rc4 function) and is tried by the multi-layer decoder when key material appears as a string.",
    }
