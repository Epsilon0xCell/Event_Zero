"""Format analyzers: .NET, Android APK, Office, PDF, email."""
import email, io, os, re, struct, zipfile
from email import policy
from email.parser import BytesParser

def analyze_dotnet(data, strings):
    is_dotnet=False; evidence=[]
    # CLR header: PE data directory 14 non-zero. Parse PE header.
    if data[:2]==b'MZ':
        try:
            peoff=struct.unpack('<I', data[0x3c:0x40])[0]
            magic=struct.unpack('<H', data[peoff+24:peoff+26])[0]
            dd_base=peoff+24+(112 if magic==0x20b else 96)
            clr_rva, clr_size=struct.unpack('<II', data[dd_base+14*8:dd_base+14*8+8])
            if clr_rva and clr_size: is_dotnet=True; evidence.append(f"CLR runtime header present (RVA {hex(clr_rva)}, size {clr_size})")
        except Exception: pass
    if b'#~' in data or b'mscorlib' in data or b'System.' in data: 
        if not is_dotnet and (b'mscorlib' in data or b'#Strings' in data): is_dotnet=True
        evidence.append("IL metadata streams or mscorlib reference found")
    meta=[s for s in strings if s.startswith(("System.","Microsoft.","mscorlib"))][:30]
    obf=[]
    for pat,label in [("ConfuserEx","ConfuserEx obfuscator marker"),("Confuser","Confuser obfuscator marker"),("Dotfuscator","Dotfuscator marker"),("SmartAssembly","SmartAssembly marker"),("Eazfuscator","Eazfuscator marker"),("NETGuard","NETGuard marker")]:
        if any(pat in s for s in strings): obf.append(label)
    # nonsense type names are a common obfuscation signal
    weird=[s for s in strings if re.fullmatch(r'[^\x20-\x7e]{2,}|[a-z]{1,2}[A-Z][a-z]{1,2}[A-Z]\w{6,}', s)]
    return {"is_dotnet": is_dotnet, "evidence": evidence, "metadata_strings": meta, "obfuscator_indicators": obf,
            "plain_english": ("This is a .NET program: it runs on the Microsoft runtime, so its middle language (IL) and metadata can usually be read far more completely than native code, unless an obfuscator scrambled the names. Event Zero reports the metadata and any obfuscator markers." if is_dotnet else "No .NET runtime header or metadata was found, so this is not identified as a .NET program.")}

PERMISSIONS_PLAIN={
 "android.permission.INTERNET":"talk to the internet","android.permission.SEND_SMS":"send text messages",
 "android.permission.READ_SMS":"read text messages","android.permission.RECORD_AUDIO":"record sound with the microphone",
 "android.permission.CAMERA":"use the camera","android.permission.ACCESS_FINE_LOCATION":"know exactly where the phone is",
 "android.permission.READ_CONTACTS":"read the address book","android.permission.SYSTEM_ALERT_WINDOW":"draw over other apps",
 "android.permission.REQUEST_INSTALL_PACKAGES":"install other apps","android.permission.BIND_DEVICE_ADMIN":"become a device boss (device admin)",
 "android.permission.RECEIVE_BOOT_COMPLETED":"start when the phone turns on","android.permission.READ_EXTERNAL_STORAGE":"read files on the phone",
}
def analyze_apk(data, path=""):
    if not zipfile.is_zipfile(io.BytesIO(data)): return {"is_apk": False}
    z=zipfile.ZipFile(io.BytesIO(data)); names=z.namelist()
    perms=set()
    manifest=b""
    if "AndroidManifest.xml" in names: manifest=z.read("AndroidManifest.xml")
    # binary XML string pool: UTF-16 strings contain permission names
    txt=manifest.decode('utf-16le', errors='ignore')+" "+manifest.decode(errors='ignore')
    for p in PERMISSIONS_PLAIN:
        if p in txt: perms.add(p)
    dex_strings=[]
    for n in names:
        if n.endswith(".dex"):
            d=z.read(n); dex_strings += re.findall(rb'[\x20-\x7e]{6,}', d)[:0]
            # dex string extraction: printable runs
            dex_strings=[m.decode() for m in re.findall(rb'[\x20-\x7e]{8,}', d)][:500]
    urls=sorted(set(re.findall(r'https?://[^\s"\'<>]+', " ".join(dex_strings))))[:30]
    dex_xor=[]
    for n in names:
        if n.endswith(".dex"):
            d=z.read(n)
            for key in range(1,256):
                dec=bytes(b^key for b in d)
                for m in re.finditer(rb'https?://[\x20-\x7e]{4,80}', dec):
                    cand=m.group().decode()
                    if cand not in " ".join(dex_strings): dex_xor.append({"key_hex": hex(key), "decoded": cand})
    return {"is_apk": "AndroidManifest.xml" in names, "entries": names[:200], "permissions": sorted(perms),
            "permissions_plain": {p: PERMISSIONS_PLAIN[p] for p in sorted(perms)},
            "permissions_eli5": [f"It asks to {PERMISSIONS_PLAIN[p]}." for p in sorted(perms)],
            "dex_files": [n for n in names if n.endswith(".dex")], "dex_xor_decoded": dex_xor, "dex_string_sample": dex_strings[:100], "urls_in_dex": urls,
            "plain_english": "This is an Android app package (APK). Event Zero listed what is inside it, read the app manifest permissions and explained each one, and pulled readable text out of its code files (DEX). It did not install or run the app."}

def analyze_office(data, strings):
    ole=data[:8]==bytes.fromhex('d0cf11e0a1b11ae1')
    joined="\n".join(strings)
    macros=bool(re.search(r'VBA|_VBA_PROJECT|Macros|vbaProject', joined)) or b'vbaProject.bin' in data
    triggers=[t for t in ("AutoOpen","AutoExec","Document_Open","Workbook_Open","AutoClose") if t in joined]
    dde=bool(re.search(r'\bDDE(AUTO)?\b', joined))
    template_urls=re.findall(r'https?://[^\s"\'<>]+', joined) if ("Template" in joined or ".dot" in joined) else []
    streams=[]
    if ole: streams=["OLE compound file header confirmed (D0CF11E0), the container used by old Office documents"]
    if b'vbaProject.bin' in data: streams.append("vbaProject.bin present inside the zip based Office file, that is where macros live")
    risk = macros or triggers or dde
    return {"is_ole_compound": ole, "has_macros": macros, "auto_open_triggers": triggers, "dde": dde,
            "template_injection_urls": sorted(set(template_urls)), "stream_notes": streams,
            "oletools_adapter": "oletools (olevba) is used through the tool registry when installed; the built in checks above run regardless.",
            "plain_english": ("This Office document carries code: macros, an automatic start trigger, or a DDE link. That is the classic way a document infects a machine when it is opened and editing is enabled." if risk else "No macro streams, auto-open triggers or DDE links were found by the built in Office checks.")}

def analyze_pdf(data, strings):
    if not data[:5]==b'%PDF-': return {"is_pdf": False}
    txt=data.decode('latin1', errors='ignore')
    feats={}
    for key in ("/JavaScript","/JS","/OpenAction","/AA","/EmbeddedFile","/Launch","/URI","/SubmitForm","/XFA"):
        feats[key]=txt.count(key)
    obj_streams=txt.count("/ObjStm")
    return {"is_pdf": True, "features": feats, "object_streams": obj_streams,
            "embedded_files": feats.get("/EmbeddedFile",0)>0,
            "plain_english": "This is a PDF. Event Zero counted the active features that make PDFs dangerous: scripts, actions that run when the file opens, embedded files and launch actions. Counts are listed, not guessed."}

def analyze_email(data, analyzer_fn=None):
    try: msg=BytesParser(policy=policy.default).parsebytes(data)
    except Exception as e: return {"is_email": False, "error": str(e)}
    headers={k: str(v) for k,v in msg.items()}
    atts=[]
    for part in msg.walk():
        if part.get_content_disposition()=="attachment":
            payload=part.get_payload(decode=True) or b""
            atts.append({"filename": part.get_filename(), "content_type": part.get_content_type(), "size": len(payload),
                         "sha256": __import__("hashlib").sha256(payload).hexdigest()})
    return {"is_email": True, "headers": headers, "from": headers.get("From"), "subject": headers.get("Subject"),
            "attachments": atts, "attachment_note": "Attachments are hashed and listed. To analyse an attachment, extract it and run Event Zero on it; the analyzer never opens attachments itself.",
            "plain_english": "This is an email file. Event Zero read its headers (who sent it, the subject, the path it took) and listed its attachments with fingerprints, because email is the most common way malware arrives."}
