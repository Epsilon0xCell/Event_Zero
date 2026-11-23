import io, json, os, struct, subprocess, sys, zipfile
import pytest
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from event_zero.analyzer import analyze
from event_zero.formats_extra import analyze_dotnet, analyze_apk, analyze_office, analyze_pdf, analyze_email
from event_zero.exports import yara_rule, sigma_summary, iocs_csv, stix_bundle, navigator_layer
from event_zero.timeline import build_timeline
from event_zero.pcap import analyze_pcap
from event_zero.report import to_text
ROOT=os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
def write(tmp,name,data):
    p=os.path.join(str(tmp),name)
    with open(p,'wb' if isinstance(data,bytes) else 'w') as f: f.write(data)
    return p
def pe_dotnet():
    dos=bytearray(0x80); dos[0:2]=b'MZ'; struct.pack_into('<I',dos,0x3c,0x80)
    coff=struct.pack('<HHIIIHH',0x8664,1,0,0,0,240,0x22)
    opt=bytearray(240); struct.pack_into('<H',opt,0,0x20b); struct.pack_into('<I',opt,16,0x1000)
    # data directories start at opt+112 for PE32+; CLR is #14
    struct.pack_into('<II',opt,112+14*8,0x2000,72)
    sec=bytearray(40); sec[0:5]=b'.text'; struct.pack_into('<IIII',sec,8,100,0x1000,512,512)
    body=(b'\x90'*50+b"mscorlib\x00System.Net.Sockets\x00ConfuserEx\x00#Strings\x00").ljust(512,b'\x00')
    return bytes(dos)+b'PE\x00\x00'+coff+bytes(opt)+bytes(sec)+body

def test_dotnet():
    d=analyze_dotnet(pe_dotnet(), ["mscorlib","System.Net.Sockets","ConfuserEx"])
    assert d["is_dotnet"] and d["obfuscator_indicators"]
def make_apk(tmp):
    buf=io.BytesIO()
    with zipfile.ZipFile(buf,'w') as z:
        # binary-ish manifest: permission as utf-16le
        man="android.permission.INTERNET android.permission.SEND_SMS android.permission.RECORD_AUDIO".encode('utf-16le')
        z.writestr("AndroidManifest.xml", man)
        z.writestr("classes.dex", b"dex\n035\x00"+b"\x00"*20+b"http://apk-c2.example/beacon\x00sendSmsMessage\x00")
        z.writestr("assets/note.txt","hi")
    return write(tmp,"app.apk",buf.getvalue())
def test_apk(tmp_path):
    r=analyze(make_apk(tmp_path))
    assert r["apk"]["is_apk"] and "android.permission.INTERNET" in r["apk"]["permissions"]
    assert r["apk"]["permissions_eli5"] and r["apk"]["urls_in_dex"]
def test_office_macro():
    data=bytes.fromhex('d0cf11e0a1b11ae1')+b'\x00'*100+b"VBA AutoOpen Document_Open DDEAUTO http://tmpl.example/x.dotm Template"
    o=analyze_office(data, [data.decode('latin1')])
    assert o["is_ole_compound"] and o["has_macros"] and o["auto_open_triggers"] and o["dde"]
def test_office_zip_macro():
    buf=io.BytesIO()
    with zipfile.ZipFile(buf,'w') as z: z.writestr("word/vbaProject.bin", b"vba")
    o=analyze_office(buf.getvalue(), ["vbaProject.bin"])
    assert o["has_macros"]
def test_pdf():
    pdf=b"%PDF-1.7\n1 0 obj << /OpenAction 2 0 R /JavaScript (app.alert) /EmbeddedFile >> endobj %%EOF"
    p=analyze_pdf(pdf, [])
    assert p["is_pdf"] and p["features"]["/JavaScript"]>=1 and p["embedded_files"]
def test_email(tmp_path):
    eml=b"From: Bad <bad@example.com>\r\nSubject: Invoice\r\nMIME-Version: 1.0\r\nContent-Type: text/plain\r\n\r\nsee attached\r\n"
    e=analyze_email(eml); assert e["is_email"] and e["subject"]=="Invoice"
    r=analyze(write(tmp_path,"mail.eml",eml)); assert r["email"]["is_email"]
def test_exports(tmp_path):
    r=analyze(os.path.join(ROOT,"fake_malware"))
    assert yara_rule(r).startswith("rule EZ_fake_malware")
    assert sigma_summary(r)["behaviours"]
    assert "ipv4-addr" in iocs_csv(r)
    b=stix_bundle(r); assert b["type"]=="bundle" and any(o["type"]=="malware" for o in b["objects"])
    nav=navigator_layer(r); assert nav["techniques"]
def test_timeline(tmp_path):
    r=analyze(os.path.join(ROOT,"fake_malware")); tl=build_timeline(r)
    stages=[s["stage"] for s in tl["timeline"]]
    assert "c2" in stages and "persistence" in stages
    assert "not observed timing" in tl["note"]
def test_pcap():
    # build one UDP DNS packet for example.com and one IP packet
    def pkt(payload, proto=17):
        ip=bytearray(20); ip[0]=0x45; ip[9]=proto; ip[12:16]=bytes([10,0,0,1]); ip[16:20]=bytes([8,8,8,8])
        eth=b'\x00'*12+b'\x08\x00'
        return eth+bytes(ip)+payload
    dnsq=b'\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01'
    udp=struct.pack('>HHHH',12345,53,len(dnsq)+8,0)+dnsq
    frame=pkt(udp)
    hdr=struct.pack('<IHHiIII',0xa1b2c3d4,2,4,0,0,65535,1)
    rec=struct.pack('<IIII',0,0,len(frame),len(frame))+frame
    out=analyze_pcap(hdr+rec)
    assert out["is_pcap"] and "example.com" in out["dns_queries"] and "8.8.8.8" in out["ip_endpoints"]
def test_export_cli(tmp_path):
    f=os.path.join(ROOT,"fake_malware")
    r=subprocess.run([sys.executable,"-m","event_zero","export-iocs",f],capture_output=True,text=True,cwd=ROOT)
    assert r.returncode==0, r.stderr
    assert os.path.isfile(f+".stix.json")
    for suf in (".iocs.csv",".stix.json",".navigator.json"): os.remove(f+suf)
def test_report_has_timeline_and_yara():
    r=analyze(os.path.join(ROOT,"fake_malware")); t=to_text(r)
    assert "21. KILL CHAIN TIMELINE" in t and "22. GENERATED YARA" in t and "20. EXTRA FORMATS" in t
