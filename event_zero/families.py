"""Per-family proof logic for The Verdict.

Source: the per-family evidence table in the deep research report
event-zero-every-malware-type-in-cracks (2026-11-23). Each family has
a stated proof standard and a false-positive (FP) twin: the legitimate
crack behaviour that merely resembles it. A family chain fires only
when the proof standard is met under the FP discriminator. Atoms alone
are never a verdict: the capability rules in capabilities.py fire on
single atoms, and this module combines them.

Circumvention itself is not malware. A patched licence check, a keygen
algorithm, a KMS emulator and a disclosed, consensual tool are the
expected crack or a disclosed potentially unwanted program (PUP),
flagged separately, never silently converted into a malware YES.

Items flagged unverified in the research (a crack-borne Cobalt Strike
campaign, a standalone crack wiper campaign, an upstream patcher
framework compromise) are detection rules only. Nothing in this module
or the project documentation claims them as real-world cases.

family_findings returns:
  chains: proven family chains, same shape as verdict.malicious_chains
  blockers: items that make bytes unaccounted (fail closed)
  conditional_blockers: blockers the caller applies only when the
    file is not otherwise proven and not accounted by a reference diff
  notes: family notes, including disclosed-PUP and family-unaccounted
    lines (a proven loader whose final family stays unaccounted)
  family_unaccounted: payload families that remain unaccounted even
    when a loader chain is proven (server-keyed delivery)
  script_ledger: per-line accounting for scripts, or None
  beacon_config: a parsed Cobalt Strike style TLV config, or None
"""
import ast, base64, builtins, re, struct

NET_CAPS = {"net-socket", "net-connect", "net-send-recv", "net-http", "net-dns", "net-listen"}
PERSIST_CAPS = {"persist-runkey", "persist-file", "persist-schtask", "persistence-service"}
CAPTURE_CAPS = {"keylog", "screenshot", "clipboard"}


def _blob(report):
    parts = list(report.get("strings", {}).get("all", []))
    # Judgement consumes the FULL script source, never the display
    # excerpt: evidence past the excerpt cap must still count.
    src = report.get("script_source_full") or report.get("script_source_excerpt")
    if src:
        parts.append(src)
    return "\n".join(parts)


def _caps(report):
    return {c["id"]: c for c in report.get("capabilities", [])}


def _ev(caps, *ids):
    out = []
    for i in ids:
        if i in caps:
            out.extend(caps[i]["evidence"])
    return sorted(set(out))


def _hits(blob_low, atoms):
    return [a for a in atoms if a.lower() in blob_low]


# ---------------------------------------------------------------- stealer
STEALER_CLASSES = {
    "browser credential and session stores": ["login data", "web data", "local state", "logins.json"],
    "cryptocurrency wallets": ["wallet.dat", "exodus", "electrum", "metamask", "atomic wallet", "phantom wallet"],
    "Telegram sessions": ["telegram desktop", "tdata"],
    "Discord sessions": ["discord", "local storage\\leveldb", "local storage/leveldb"],
    "FTP, VPN and Steam credentials": ["recentservers.xml", "filezilla", "ssfn", "openvpn", "nordvpn"],
}


def _stealer(caps, blob, low):
    classes = {name: _hits(low, atoms) for name, atoms in STEALER_CLASSES.items()}
    classes = {k: v for k, v in classes.items() if v}
    net = sorted(set(caps) & NET_CAPS)
    staging = "file-write" in caps and any(x in low for x in (".zip", "archive", "%temp%", "appdata"))
    sink = bool(net) or staging
    ev = []
    for v in classes.values():
        ev.extend(f"theft target: {a}" for a in v)
    if "stealer-config" in caps:
        return {"family": "stealer", "chain": "family-stealer-config",
                "name": "Information stealer: carries a stealer scanning configuration (RedLine type atoms: switches enumerating browsers, wallets, Telegram, VPN, Steam and Discord). A family config is proof on its own: no licensing function enumerates unrelated apps' secrets",
                "evidence": _ev(caps, "stealer-config") + ev}
    if len(classes) >= 2 and sink:
        return {"family": "stealer", "chain": "family-stealer",
                "name": f"Information stealer: enumerates {len(classes)} unrelated theft target classes ({', '.join(classes)}) and has a staging or exfiltration sink. The FP twin, a crack reading only the target app's own licence data, touches one class and no sink",
                "evidence": ev + _ev(caps, *net, "file-write")}
    if "dpapi-access" in caps and "sqlite-access" in caps and classes and net:
        return {"family": "stealer", "chain": "family-stealer-dpapi",
                "name": "Information stealer: DPAPI unprotection plus SQLite reading aimed at a credential store, with a network channel. DPAPI and SQLite are how browser saved passwords are unlocked and read",
                "evidence": _ev(caps, "dpapi-access", "sqlite-access", *net) + ev}
    return None


# ---------------------------------------------------------------- RAT
RAT_COMMANDS = ["remote_shell", "remote shell", "file_manager", "file manager", "screen_stream",
                "screen stream", "webcam_stream", "keylog_start", "plugin_load", "load plugin",
                "hvnc", "remote_desktop", "remote desktop", "download_file", "upload_file",
                "open_shell", "exec_command", "shell_exec",
                "\"shell\"", "\"download\"", "\"upload\"", "\"screenshot\"", "\"keylog\"", "\"persist\""]


def _rat(caps, blob, low):
    cmds = sorted(set(_hits(low, RAT_COMMANDS)))
    config = ("rat-config" in caps
              or re.search(r"(serverhost|serverport|c2_host|c2_port|rat_host|operator_host)", low)
              or ("host=" in low and "port=" in low)
              # a decoded operator config in source form: an IP literal
              # together with a port assignment on the same line
              or bool(re.search(r"\d{1,3}(?:\.\d{1,3}){3}", low) and re.search(r"port.{0,24}\d{2,5}", low)))
    if config and len(cmds) >= 3:
        return {"family": "rat", "chain": "family-rat-dispatcher",
                "name": f"Remote access trojan: a decoded operator configuration (host, port or key) plus a command dispatcher with {len(cmds)} operator commands ({', '.join(cmds[:6])}). A vendor updater has a signed endpoint and no shell, file or screen dispatcher",
                "evidence": _ev(caps, "rat-config") + [f"dispatcher command: {c}" for c in cmds]}
    return None


# ---------------------------------------------------------------- ransomware
USER_EXTS = [".docx", ".xlsx", ".pptx", ".pdf", ".jpg", ".png", ".zip", ".db", ".sql", ".pst", ".bak"]
KEY_ATOMS = ["begin public key", "public key pem", "offline key", "per-file key", "victim key", "rsa public key"]


def _ransomware(caps, blob, low):
    crypto = "crypto-aes" in caps or "aes-256" in low or "chacha20" in low
    ext_hits = _hits(low, USER_EXTS)
    traversal = "file-write" in caps and (len(ext_hits) >= 4 or "encrypt files" in low or "encrypting" in low)
    corro = []
    if "ransom-note" in caps:
        corro.append("ransom note")
    if "shadow-delete" in caps:
        corro.append("shadow copy deletion or recovery disabling")
    if _hits(low, KEY_ATOMS):
        corro.append("key material")
    if crypto and traversal and len(corro) >= 2:
        return {"family": "ransomware", "chain": "family-ransomware",
                "name": f"Ransomware: an encryption capability over user file types ({', '.join(ext_hits[:6])}) plus {len(corro)} corroborators ({', '.join(corro)}). The FP twin, a tool encrypting its own data only, has no user-file scope and no corroborator",
                "evidence": _ev(caps, "crypto-aes", "file-write", "ransom-note", "shadow-delete") + [f"key material: {k}" for k in _hits(low, KEY_ATOMS)]}
    if "shadow-delete" in caps and ("file-delete" in caps or "exec-shell" in caps or crypto or traversal):
        return {"family": "ransomware", "chain": "family-ransomware-anti-recovery",
                "name": "Ransomware pattern, anti-recovery first: shadow copy deletion or recovery disabling reachable from this file. Anti-recovery is near-dispositive on its own: no crack encrypts user files or deletes shadow copies, ever, and no legitimate activation step disables recovery",
                "evidence": _ev(caps, "shadow-delete", "file-delete", "exec-shell", "crypto-aes")}
    return None


# ---------------------------------------------------------------- miner
XMR_RE = re.compile(r"4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}")
ETH_RE = re.compile(r"0x[0-9a-fA-F]{40}")
POOL_ATOMS = ["pool.minexmr", "supportxmr", "nanopool", "2miners", "kryptex", "xmrpool", "pool.hashvault"]
HIDDEN_ATOMS = ["windowstyle hidden", "-windowstyle hidden", "hidden window", "watchdog",
                "taskmgr", "process hacker", "getforegroundwindow", "pause when", "fullscreen"]
DISCLOSED_ATOMS = ["your wallet", "your earnings", "your account", "your payout", "miner is running", "dashboard"]


def miner_disclosed(report):
    """True when a miner presents as the user's own: pool plus wallet,
    at least two own-account or visibility markers, and no concealment
    and no persistence. Used by the verdict's generic miner chain so a
    disclosed own miner is not converted into a proven crack miner."""
    caps = _caps(report)
    blob = _blob(report)
    low = blob.lower()
    wallet = XMR_RE.search(blob) or ETH_RE.search(blob)
    pool = "pool-connect" in caps or _hits(low, POOL_ATOMS) or re.search(r"pool[^\s\"']*:\d{2,5}", low)
    if not (wallet and pool):
        return False
    hidden = _hits(low, HIDDEN_ATOMS) or set(caps) & PERSIST_CAPS
    return len(_hits(low, DISCLOSED_ATOMS)) >= 2 and not hidden


def _miner(caps, blob, low, notes):
    wallet = XMR_RE.search(blob) or ETH_RE.search(blob)
    pool = "pool-connect" in caps or _hits(low, POOL_ATOMS) or re.search(r"pool[^\s\"']*:\d{2,5}", low)
    if not (wallet and pool):
        return None
    hidden = _hits(low, HIDDEN_ATOMS) or sorted(set(caps) & PERSIST_CAPS)
    disclosed = _hits(low, DISCLOSED_ATOMS)
    if len(disclosed) >= 2 and not hidden:
        notes.append("Miner present with a pool and a wallet, but it presents as the user's own miner (own-account and visibility markers, no concealment and no persistence). A user's own visible miner is not a proven crack-borne miner; XMRig presence alone is never proof.")
        return None
    if hidden:
        return {"family": "miner", "chain": "family-miner-hidden-wallet",
                "name": "Cryptocurrency miner: a pool endpoint plus a wallet that is not the user's, with concealment (hidden window, watchdog, pause watchlist or persistence). Hidden plus foreign wallet is proven; the FP twin is a visible miner running for the user's own account",
                "evidence": _ev(caps, "pool-connect", "mining") + [f"wallet: {wallet.group(0)[:20]}..."] + [f"concealment: {h}" for h in (_hits(low, HIDDEN_ATOMS) or list(set(caps) & PERSIST_CAPS))]}
    notes.append("Miner atoms present (pool plus wallet) but neither concealment nor clear own-account disclosure was proven, so the miner family is not proven on this evidence alone.")
    return None


# ---------------------------------------------------------------- loader and server-keyed
SERVER_KEY_ATOMS = ["server key", "fetch key", "request key", "getkey", "payload_url", "payload url",
                    "stage2", "stage 2", "second stage", "download config", "remote config", "key from server"]


def _loader(caps, blob, low, ev_ids, family_unaccounted):
    out = None
    if "exec-download-run" in caps and "dead-drop" in caps:
        # the dead-drop branch is the more specific family trait and is
        # checked first: a loader that also injects is still the
        # dead-drop loader the research names
        out = {"family": "loader", "chain": "family-loader-dead-drop",
               "name": "Loader: resolves its real download address through a public dead drop (Telegram, Discord webhook or paste page) and downloads and runs what it finds. Dead drops hide the operator; vendor updaters fetch from their own vendor",
               "evidence": _ev(caps, "exec-download-run", "dead-drop")}
    elif "exec-download-run" in caps and ("inject-process" in caps or "mem-exec" in caps or "inject-chain" in ev_ids):
        out = {"family": "loader", "chain": "family-loader-inject",
               "name": "Loader: downloads external code and injects or executes it from memory. The FP twin, a legitimate updater, downloads a signed update of the same product and never injects it",
               "evidence": _ev(caps, "exec-download-run", "inject-process", "mem-exec")}
    sk = _hits(low, SERVER_KEY_ATOMS)
    if sk and ("exec-download-run" in caps or set(caps) & NET_CAPS):
        family_unaccounted.append(
            "Server-keyed payload: this file requests a key or payload from an operator server and executes what returns, which makes it a loader by construction. The loader is proven; the final payload family is UNACCOUNTED, because the decisive code never leaves the server during analysis. This is never a NO.")
        if out is None and "exec-download-run" in caps:
            out = {"family": "loader", "chain": "family-loader-server-keyed",
                   "name": "Loader (server-keyed): requests a key or payload from an operator server and executes what returns. The loader is proven by construction; the payload family it fetches is unaccounted, never clean",
                   "evidence": _ev(caps, "exec-download-run") + [f"server-keyed atom: {s}" for s in sk]}
    return out


# ---------------------------------------------------------------- botnet
BOT_GRAMMAR = ["attack_start", "start_attack", "flood_start", "bot_id", "botid", "privmsg", "join #",
               "\"flood\"", "'flood'"]


def _botnet(caps, blob, low):
    grammar = _hits(low, BOT_GRAMMAR)
    if "flood-routine" in caps and (grammar or set(caps) & {"net-connect", "net-listen", "net-socket"}):
        return {"family": "botnet", "chain": "family-botnet-ddos",
                "name": "Botnet or DDoS agent: a flooding routine reachable from a command and control dispatch. The FP twin, a game or torrent client, sends only user-directed traffic to user-chosen peers and has no target, rate and duration command grammar",
                "evidence": _ev(caps, "flood-routine", "net-connect", "net-listen") + [f"command grammar: {g}" for g in grammar]}
    return None


# ---------------------------------------------------------------- rootkit and bootkit
ESP_ATOMS = ["bootmgfw.efi", "\\efi\\microsoft\\boot", "mountvol", "/efi/boot/"]
BOOT_TAMPER_ATOMS = ["nointegritychecks", "testsigning", "disable hvci", "hypervisorlaunchtype off", "hvci disabled",
                     "disable secureboot", "secureboot disabled", "secure boot disabled", "integrity checks", "unsigned driver"]


def _rootkit_bootkit(report, filename, signature_valid, caps, low, blockers,
                     reference_accounted=False):
    rk = report.get("rootkit") or {}
    name = (filename or "").lower()
    is_sys = name.endswith(".sys") or rk.get("is_kernel_driver")
    # Coverage wave 8 provenance exclusion: this blocker used to be
    # suppressed when the driver's signature verified. A signature is
    # provenance, not accounting: it vouches for who signed the bytes,
    # never for what an unexplained driver beside a crack is for, and
    # the 2025 to 2026 record (Azure Trusted Signing enrolled by a
    # crimeware operator, intercepted DigiCert token activation) is
    # that signing identities themselves are obtainable by attackers.
    # The blocker is now suppressed only by accounting: byte identity
    # against the genuine reference (reference_accounted), the same
    # basis on which every other stage exempts a hash-matched file.
    if is_sys and not rk.get("hiding_indicators") and not reference_accounted:
        blockers.append(
            f"{filename}: an unexplained kernel driver (.sys) sits in or beside a crack. A crack needs no kernel driver at all, so this driver is at minimum UNACCOUNTED. The FP twin, a named vendor anti-cheat or hardware driver that hides nothing, accounts itself by byte identity against the genuine reference or by proven function; a signature on this driver is recorded in the report as provenance and does not account for it. Next step: supply the genuine reference so the driver can be matched byte for byte, or prove its function.")
    esp = _hits(low, ESP_ATOMS)
    tamper = _hits(low, BOOT_TAMPER_ATOMS)
    if esp and tamper:
        return {"family": "bootkit", "chain": "family-bootkit-staging",
                "name": "Bootkit staging: writes toward the EFI System Partition or boot loader while disabling integrity checks or hypervisor-protected code integrity. A dual-boot tool writes the ESP openly and disables nothing",
                "evidence": [f"ESP target: {e}" for e in esp] + [f"integrity tampering: {t}" for t in tamper]}
    return None


# ---------------------------------------------------------------- keylogger stash
HIDDEN_STASH_ATOMS = ["%appdata%", "\\temp\\", "/tmp/", "\\logs\\", "hidden log", "keylog.txt", "logs\\",
                      "\\.hidden", "/.hidden", ".hidden\\"]


def _keylogger(caps, blob, low):
    capture = sorted(set(caps) & CAPTURE_CAPS)
    if not capture:
        return None
    if set(caps) & NET_CAPS:
        return None  # capture plus network is the stealer-collection chain
    stash = _hits(low, HIDDEN_STASH_ATOMS)
    titling = "getforegroundwindow" in low
    if "file-write" in caps and (stash or (titling and "keylog" in caps)):
        return {"family": "keylogger", "chain": "family-keylogger-stash",
                "name": "Keylogger or screen spyware with a local stash: capture code writes hidden logs on this machine. Capture APIs alone are not proof (recorders and overlays use them); capture plus a hidden log store, or logs titled by the foreground window, is. The FP twin saves visibly, where the user chose, and never exfiltrates",
                "evidence": _ev(caps, *capture, "file-write") + [f"hidden stash: {s}" for s in stash] + (["window titling: GetForegroundWindow"] if titling else [])}
    return None


# ---------------------------------------------------------------- banking
BANK_ATOMS = ["bankofamerica", "chase.com", "wells fargo", "wellsfargo", "citibank", "hsbc",
              "barclays", "santander", "commerzbank", "paypal", "fidelity.com", "vanguard.com"]
INJECT_ATOMS = ["webinject", "inject config", "form grabber", "automatic transfer system", "man-in-the-browser", "mitb"]


def _banking(caps, blob, low, filename="", notes=None):
    banks = sorted(set(_hits(low, BANK_ATOMS)))
    injects = _hits(low, INJECT_ATOMS)
    if banks and (filename or "").lower().endswith((".txt", ".md", ".rst", ".html", ".htm", ".csv", ".log", ".json", ".xml")):
        # Discriminator found by the surprise verification corpus: bank
        # names in a non-executable document (a news article, a report)
        # are content about banking, not code that targets banks. The
        # dispositive target-list rule applies to code-bearing files.
        if notes is not None:
            notes.append("bank target strings appear in a non-executable document file: content about banking is not banking malware, so the target-list rule does not fire here")
        return None
    if len(banks) >= 3:
        return {"family": "banking", "chain": "family-banking-targets",
                "name": f"Banking trojan: the binary carries a target list of {len(banks)} banks or payment services ({', '.join(banks[:6])}). A bank target list in a crack binary is dispositive: no licensing function enumerates banks",
                "evidence": [f"bank target: {b}" for b in banks] + _ev(caps, "bank-targets")}
    if injects and banks:
        return {"family": "banking", "chain": "family-banking-inject",
                "name": "Banking trojan: web-inject machinery (inject configuration, form grabbing or an automatic transfer system) aimed at named banks. The FP twin, a password manager or security extension, is branded, signed, store-distributed and targets no bank list in a hidden binary config",
                "evidence": [f"inject atom: {i}" for i in injects] + [f"bank target: {b}" for b in banks]}
    return None


# ---------------------------------------------------------------- proxy
PROXY_SYSTEM_ATOMS = ["nt authority\\system", "run as system", "system scheduled task", "sc create"]
PROXY_UI_ATOMS = ["tray icon", "pause sharing", "pause proxy", "pause sharing", "dashboard"]
PROXY_ACCOUNT_ATOMS = ["your account", "your earnings", "your payout", "sign in to your"]
FIREWALL_ATOMS = ["netsh advfirewall", "new-netfirewallrule", "firewall add rule", "add firewall rule"]


def _proxy(caps, blob, low, notes):
    atoms = []
    if "proxy-server" in caps:
        atoms.append("proxy-server")
    if "proxy-network-sdk" in caps:
        atoms.append("proxy-network-sdk")
    if "honeygain" in low:
        atoms.append("honeygain client")
    if not atoms:
        return None
    system_atoms = _hits(low, PROXY_SYSTEM_ATOMS)
    system_persist = bool(system_atoms) or ("persistence-service" in caps and "hidden" in low)
    disclosed = _hits(low, PROXY_ACCOUNT_ATOMS) and _hits(low, PROXY_UI_ATOMS) and not system_persist and "hidden" not in low
    if disclosed:
        notes.append("Proxyware present but disclosed under the consent, beneficiary and visibility test: the user's own account and payout, a visible interface with a pause control, no SYSTEM persistence and no concealment. Consensual proxyware is flagged as disclosed PUP, not as malware.")
        return None
    enrol = _hits(low, ["enrolment token", "enrollment token", "network token", "operator token", "reseller id"])
    fw = _hits(low, FIREWALL_ATOMS)
    if "proxy-network-sdk" in caps or enrol or fw or ("net-listen" in caps and set(caps) & PERSIST_CAPS) or system_persist:
        return {"family": "proxy", "chain": "family-proxy-traffic-selling",
                "name": "Residential proxy or traffic-selling malware: a proxy listener or proxy network client with an operator enrolment, a firewall opening, or SYSTEM persistence, and no proof the enrolment account is the user's. The test is consent, beneficiary and visibility: a consensual client is branded, visible, pausable and pays the user; this one works for a third party in silence",
                "evidence": _ev(caps, "proxy-server", "proxy-network-sdk", "net-listen") + [f"enrolment: {e}" for e in enrol] + [f"firewall: {f}" for f in fw] + [f"SYSTEM persistence: {s}" for s in system_atoms]}
    notes.append("Proxy atoms present, but enrolment, firewall opening and third-party beneficiary were not proven, so the proxy family is not proven on this evidence alone.")
    return None


# ---------------------------------------------------------------- adware and PPI
OFFER_ID_RE = re.compile(r"(affiliate|offer|campaign)[_-]?id\s*[=:]\s*[\"']?[a-z0-9_-]{3,}", re.I)
CALLBACK_ATOMS = ["install callback", "offer_execution", "postback", "install_success", "install success ping", "/callback"]
HIJACK_ATOMS = ["default_search_provider", "homepage override", "new tab override", "search provider hijack", "browser hijack", "hijack homepage",
                "set homepage", "homepage =", "default search provider", "search provider =", "new tab page"]
PUP_DISCLOSURE_ATOMS = ["optional offer", "you can decline", "you may decline", "opt out", "untick", "uninstaller", "add or remove programs"]


def _ppi(caps, blob, low):
    m = OFFER_ID_RE.search(blob)
    cb = _hits(low, CALLBACK_ATOMS)
    if (m or "offer-engine" in caps) and cb:
        return {"family": "ppi-downloader", "chain": "family-ppi-callback",
                "name": "Pay-per-install downloader: an affiliate or offer identifier plus an install callback. That pair proves a paid distribution deal the user never saw, and a server that can serve different payloads to different visitors, which alone defeats any NO. There is no legitimate reason for a keygen to phone home an install-success callback",
                "evidence": ([f"offer identifier: {m.group(0)[:80]}"] if m else _ev(caps, "offer-engine")) + [f"install callback: {c}" for c in cb]}
    return None


def _adware(caps, blob, low, notes):
    hijack = _hits(low, HIJACK_ATOMS)
    if hijack and ("watchdog" in low or set(caps) & PERSIST_CAPS):
        return {"family": "adware-hijacker", "chain": "family-browser-hijacker",
                "name": "Browser hijacker, malware side of the grey zone: it changes homepage or search settings and re-applies the change through a watchdog or persistence, so the hijack resists reversal. A disclosed PUP changes settings as disclosed and reverses in one step",
                "evidence": [f"hijack atom: {h}" for h in hijack] + _ev(caps, *sorted(set(caps) & PERSIST_CAPS))}
    disclosure = _hits(low, PUP_DISCLOSURE_ATOMS)
    if hijack and len(disclosure) >= 2:
        notes.append("Disclosed PUP assessment (the 5-row grey-zone table): the bundle is named before install with a real opt-out, states an uninstaller, and shows no right-column behaviour (no installs beyond disclosure, no reversal resistance, no undisclosed data sale, no SYSTEM persistence, no Defender exclusion). Flagged separately as PUP, not a malware YES.")
    return None


# ---------------------------------------------------------------- beacon config
CS_TYPES = {1: ("beacon_type", {2}), 2: ("port", {2}), 3: ("sleep_ms", {4}), 4: ("maxget", {4}),
            5: ("jitter", {2}), 6: ("maxdns", {2}), 7: ("public_key", {256}), 8: ("c2_host", "str"),
            9: ("user_agent", "str"), 10: ("post_uri", "str"), 13: ("killdate", {4, 8}),
            26: ("spawnto", "str"), 36: ("watermark", {4}), 37: ("watermark", {4})}


def parse_beacon_config(data):
    """Parse a Cobalt Strike style beacon configuration: TLV records
    XOR-encoded with a single byte (0x69 for v3, 0x2e for v4). Returns
    the decoded settings dict, or None. A successfully parsed config is
    an indicator set: C2 host, port, sleep, jitter, watermark."""
    if not data or len(data) < 32:
        return None
    for key in (0x69, 0x2e):
        dec = bytes(b ^ key for b in data)
        for start in range(len(dec) - 8):
            t0 = struct.unpack(">H", dec[start:start + 2])[0]
            if t0 not in CS_TYPES:
                continue
            settings = {}
            i = start
            while i + 4 <= len(dec):
                t, ln = struct.unpack(">HH", dec[i:i + 4])
                if t not in CS_TYPES:
                    # tolerate inter-record zero padding: some builders
                    # align each value. Probe each offset up to 8 bytes
                    # ahead for the next valid header (skipping zeros
                    # wholesale would eat the header's own high byte,
                    # which is itself zero for every type below 256).
                    nxt = None
                    for j in range(i + 1, min(i + 9, len(dec) - 4)):
                        if dec[j] != 0:
                            break
                        if struct.unpack(">H", dec[j:j + 2])[0] in CS_TYPES:
                            nxt = j
                            break
                    if nxt is not None:
                        i = nxt
                        continue
                    break
                kind = CS_TYPES[t][1]
                val = dec[i + 4:i + 4 + ln]
                if len(val) < ln:
                    break
                if kind == "str":
                    sval = val[:-1] if val.endswith(b"\x00") else val  # strings are NUL-terminated in the real format
                    if not (1 <= len(sval) <= 1024) or not all(32 <= c < 127 for c in sval):
                        break
                    settings[CS_TYPES[t][0]] = sval.decode("ascii")
                else:
                    if ln not in kind:
                        break
                    settings[CS_TYPES[t][0]] = int.from_bytes(val, "big")
                i += 4 + ln
                if len(settings) >= 4 and ("c2_host" in settings or "public_key" in settings):
                    break
            if len(settings) >= 4 and ("c2_host" in settings or "public_key" in settings):
                settings["xor_key"] = hex(key)
                settings["offset"] = start
                if "public_key" in settings:
                    settings["public_key"] = "256-byte RSA public key present"
                return settings
    return None


def _beacon(data):
    cfg = parse_beacon_config(data) if data else None
    if not cfg:
        return None, None
    ev = [f"beacon config TLV (XOR {cfg['xor_key']}) at offset {cfg['offset']}"]
    for k in ("c2_host", "port", "sleep_ms", "jitter", "watermark", "user_agent", "post_uri", "killdate"):
        if k in cfg:
            ev.append(f"{k}: {cfg[k]}")
    return {"family": "beacon", "chain": "family-beacon-config",
            "name": "Beacon implant configuration parsed (Cobalt Strike TLV format): C2 host, timing and operator watermark recovered from the file itself. In a software crack there is no legitimate beacon at all; the FP twin, a licensed red-team beacon, belongs to an engagement, not to a crack",
            "evidence": ev}, cfg


# ---------------------------------------------------------------- wiper
WIPE_ATOMS = ["overwrite", "zero fill", "random fill", "wipe files", "shred"]
MBR_ATOMS = ["mbr", "master boot record", "gpt header", "boot sector"]


def _wiper(caps, blob, low, notes):
    raw = "raw-disk" in caps or "physicaldrive" in low
    if not raw:
        return None
    if "secure erase" in low and ("you selected" in low or "chosen files" in low):
        notes.append("Raw disk access present but presented as a consented secure-erase of user-chosen files, with no concealment. Scope and consent separate a disk tool from a wiper; this file is not proven as a wiper on this evidence.")
        return None
    wipe = _hits(low, WIPE_ATOMS)
    mbr = _hits(low, MBR_ATOMS)
    if wipe or mbr:
        return {"family": "wiper", "chain": "family-wiper",
                "name": "Destructive wiper: raw physical disk access plus an overwrite routine or boot-structure target, with no recovery mechanism. The FP twin, a secure-erase utility, works on files the user chose, with consent and a visible interface; a crack has no disk-erase function",
                "evidence": _ev(caps, "raw-disk") + [f"overwrite: {w}" for w in wipe] + [f"boot target: {m}" for m in mbr]}
    return None


# ---------------------------------------------------------------- logic bomb
TRIGGER_WORDS = ["arm on", "target date", "deadline date", "activation date", "getsystemtime",
                 "startup count", "launch count", "boot count", "runs remaining", "if date",
                 "datetime.date.today", "date.today()"]
DATE_RE = re.compile(r"\b20\d{2}-(0[1-9]|1[0-2])-(0[1-9]|[12]\d|3[01])\b|date\(\s*20\d{2}\s*,\s*\d{1,2}\s*,\s*\d{1,2}\s*\)")


def _logic_bomb(report, caps, blob, low, conditional_blockers, notes):
    words = _hits(low, TRIGGER_WORDS)
    date = DATE_RE.search(blob)
    if not words or not (date or "count" in " ".join(words)):
        return
    opaque = bool(report.get("unpack", {}).get("high_entropy_regions")) or "encrypted payload" in low or "payload blob" in low \
        or "opaque" in low or bool(re.search(r"(subprocess|os\.system|popen|exec)\b[^\n]{0,80}\.(bin|dat|enc)\b", low))
    gated_caps = sorted(set(caps) & (NET_CAPS | PERSIST_CAPS | CAPTURE_CAPS | {"crypto-aes", "exec-download-run"}))
    if opaque:
        conditional_blockers.append(
            "Logic bomb pattern: a date or counter trigger guards an opaque or encrypted payload arm. The fact that an analysis run did not take the branch is the expected behaviour of a bomb, not exculpation, so the gated arm is UNACCOUNTED until it is decoded. The FP twin, the genuine app's own trial logic, accounts itself by hash match against the genuine reference.")
    elif gated_caps:
        notes.append(f"Logic bomb pattern: a date or counter trigger sits in front of capabilities ({', '.join(gated_caps)}). The trigger condition is recorded as evidence; the gated capabilities are judged by their own chains.")
    else:
        notes.append("A date or counter trigger is present with no opaque arm and no gated malicious capability: consistent with trial or version-expiry logic, recorded and not a finding on its own.")


# ---------------------------------------------------------------- fileless
EXECUTOR_ATOMS = ["powershell -enc", "powershell.exe -encodedcommand", "-encodedcommand", "mshta", "regsvr32", "wscript.exe", "cscript.exe"]
REGISTRY_PERSIST_ATOMS = ["currentversion\\run", "runonce", "__eventfilter", "commandlineeventconsumer", "image file execution options"]
B64_TOKEN_RE = re.compile(r"[A-Za-z0-9+/]{200,}={0,2}")


def _fileless(report, caps, blob, low, blockers):
    text = (report.get("script_source_excerpt") or "") + "\n" + blob
    executors = _hits(low, EXECUTOR_ATOMS)
    reg = _hits(low, REGISTRY_PERSIST_ATOMS)
    m = B64_TOKEN_RE.search(text)
    if not (executors and reg and m):
        return None
    token = m.group(0)
    decoded = None
    try:
        decoded = base64.b64decode(token + "=" * (-len(token) % 4), validate=False)
    except Exception:
        decoded = None
    if decoded and (decoded[:2] == b"MZ" or b"http" in decoded.lower() or b"invoke" in decoded.lower() or b"download" in decoded.lower()):
        return {"family": "fileless", "chain": "family-fileless-registry-blob",
                "name": "Fileless registry malware: a persistence entry whose only content is a large encoded executable blob, run by a living-off-the-land executor, and the blob decodes to code. The FP twin, a licence blob, is small, structured, data for the app, and has no interpreter executor",
                "evidence": [f"executor: {e}" for e in executors] + [f"persistence: {r}" for r in reg] + [f"encoded blob: {len(token)} chars, decodes to {decoded[:2]!r} code"]}
    blockers.append(
        "Fileless pattern: a persistence entry holds a large encoded blob with a living-off-the-land executor, and the blob could not be decoded to accounted code here. An undecodable executable blob is UNACCOUNTED, never clean. Next step: decode the blob (the script ledger and decoding layers name the encoding) and re-run the verdict.")
    return None


# ---------------------------------------------------------------- scripts: per-line ledger vs the KMS allowlist
KMS_ALLOW_RES = [re.compile(p, re.I) for p in (
    r"slmgr(\.vbs)?\s+/(ipk|skms|ato|dli|dlv|xpr|upk|ckms|rearm)",
    r"(ospp|osp)\.vbs\s+/(inpkey|sethst|setprt|act|dstatus|inslic)",
    r"cscript[^\n]*(ospp|slmgr)",
    r"keymanagementservice(machine|lookupdomain)?",
    r"\bgvlk\b", r"generic volume license key",
    r"schtasks[^\n]*(kms|ospp|reactivat)",
    r"reg\s+add[^\n]*(licensing|ospp|slmgr)",
    r"set\s+.*kms[^\n]*=",
)]
TAMPER_LINE_RES = [re.compile(p, re.I) for p in (
    r"set-mppreference[^\n]*-disable", r"disableantispyware|disableantivirus",
    r"(net|sc)\s+(stop|config)\s+\S*(windefend|sense|wdnissvc)",
    r"vssadmin[^\n]*delete\s+shadows", r"bcdedit[^\n]*safeboot",
    r"add-mppreference\s+-exclusion(path|process)\s+[\"']?[a-z]:\\($|[^\\]*$|users|programdata)",
)]
DOWNLOAD_LINE_RES = [re.compile(p, re.I) for p in (
    r"downloadstring", r"downloadfile", r"invoke-expression", r"\biex\s*\(", r"net\.webclient",
    r"curl\s+https?://", r"wget\s+https?://", r"start-bitstransfer", r"invoke-webrequest[^\n]*-outfile",
    r"urlopen\([^\n]*https?://", r"requests\.(get|post)\([^\n]*https?://",
)]
PERSIST_LINE_RES = [re.compile(p, re.I) for p in (
    r"schtasks\s+/create", r"currentversion\\run", r"crontab", r"launchagents|launchdaemons",
    r"systemctl\s+enable", r"new-service|sc\s+create",
)]
EXFIL_LINE_RES = [re.compile(p, re.I) for p in (
    r"\.connect\(\(", r"socket\.socket", r"sendall?\(", r"requests\.post", r"telegra\.ph|api\.telegram\.org",
)]
# The third pattern is the phrase-key declaration (a config or
# data line whose key contains spaces, "app name = BandwidthShare"):
# never valid code in any dialect the ledger serves, and its value
# is constrained to data characters (no call, substitution or
# second assignment), so the pattern cannot account a command.
STRUCT_RES = [re.compile(p, re.I) for p in (
    r"^\s*(import\s|from\s+\S+\s+import|#|//|rem\s|@echo|echo[\s\.]|set\s+\w+=|def\s|class\s|return\b|if\b|elif\b|else\b|for\b|while\b|try\b|except\b|finally\b|with\b|print\s*\(|pass\b|break\b|continue\b|raise\b|assert\b|del\b|global\b|nonlocal\b|yield\b|await\b|async\b)",
    r"^\s*[\w\.\[\]\"']+\s*=[^=]",
    r"^\s*[A-Za-z][\w\-]*(?:[ \t]+[\w\-]+)+[ \t]*=[^=()$`]*$",
    r"^\s*[\)\]\}]+[;:,]?\s*$",
    r"^\s*(end|fi|done|esac)\s*$",
)]

# Statement keywords that open a compound statement: a line led by
# one of these is code structure, never a data line, and a parse
# failure on such a line is unexamined structure.
COMPOUND_LEADS = {"def", "class", "if", "elif", "else", "for",
                  "while", "try", "except", "finally", "with",
                  "async", "match", "case"}
_EXPR_CHARS = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
                  "0123456789_.,()[]{}:+-*/%<>=!&|^~ \t")
_DATA_TOKEN_RE = re.compile(
    r"^(?:[A-Za-z0-9_][\w\.\-\+:/\\@%~,]*|-{1,2}[A-Za-z][\w\-]*)$")
_DATA_FORBIDDEN = set("()[]{}\"'`$&|;<>=#*?!")


def _strip_literals(line):
    """Remove string literals from one line, returning the
    remaining text, or None when a literal is unterminated on
    this line (its shape cannot be read from one line alone)."""
    out = []
    i, n = 0, len(line)
    while i < n:
        c = line[i]
        if c in ("'", '"'):
            if line.startswith(c * 3, i):
                j = line.find(c * 3, i + 3)
                if j < 0:
                    return None
                i = j + 3
            else:
                j = i + 1
                closed = False
                while j < n:
                    if line[j] == "\\":
                        j += 2
                        continue
                    if line[j] == c:
                        closed = True
                        break
                    j += 1
                if not closed:
                    return None
                i = j + 1
            out.append(" ")
        else:
            out.append(c)
            i += 1
    return "".join(out)


# Builtins whose effective callee is chosen by data rather than
# fixed by the name on the line: a call to one of these executes
# or reaches code the line does not show, so it can never be
# accounted from the line.
_DYNAMIC_BUILTINS = {"eval", "exec", "compile", "__import__",
                     "getattr", "setattr", "delattr"}
_SAFE_BUILTINS = set(dir(builtins)) - _DYNAMIC_BUILTINS


def _expression_statement(line, known_names):
    """True when the line is a single expression statement the
    ledger can fully read: with string literals removed, the
    remainder is names, attribute and index access, calls and
    operators, with balanced delimiters, at least one call, no
    top-level assignment and no compound header; and every call
    it makes resolves to a name whose behaviour is fixed by
    what the file shows: a function or class defined in this
    file, a name this file imports, an attribute of a visible
    receiver chain, or a builtin whose behaviour is fixed by
    its name (the dynamic-execution builtins are excluded: what
    they run is chosen by data). A bare call to any other name
    stays unaccounted, as it always has: what that name does
    cannot be known from this file. The same expression is
    already accounted when it follows return or an assignment
    target; standing alone as a statement (a method-call chain
    such as open(...).write(...) or os.remove(...)) it is the
    same ordinary structure."""
    body = _strip_literals(line)
    if body is None:
        return False
    body = body.split("#", 1)[0].strip()
    if not body or "(" not in body or body.endswith(":"):
        return False
    first = re.match(r"[A-Za-z_]\w*", body)
    if not first or first.group(0).lower() in COMPOUND_LEADS:
        return False
    depth = 0
    for ch in body:
        if ch not in _EXPR_CHARS:
            return False
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth -= 1
            if depth < 0:
                return False
        elif ch == "=" and depth == 0:
            return False
    if depth != 0:
        return False
    for m in re.finditer(r"([A-Za-z_]\w*)\s*\(", body):
        if m.start() > 0 and body[m.start() - 1] == ".":
            continue
        callee = m.group(1)
        if callee in COMPOUND_LEADS or callee in ("lambda",):
            return False
        if callee not in known_names and callee not in _SAFE_BUILTINS:
            return False
    return True


def _data_line(line):
    """True when the line is a data line: whitespace-separated
    literal tokens (bare words, numbers, versions, URLs, paths,
    flag tokens) with no call, quote, operator, substitution,
    glob or chaining character. Such a line can only name
    things: read as data it declares exactly those tokens, and
    read as a command its program and arguments are the same
    literal tokens, so nothing it can do is hidden from the
    ledger. Hostile atoms are flagged before this rule is
    reached, and interpreter-proxy invocations are capped by
    the verdict's own proxy rule, not by legibility."""
    if any(c in _DATA_FORBIDDEN for c in line):
        return False
    toks = line.split()
    if not toks:
        return False
    return all(_DATA_TOKEN_RE.match(t) for t in toks)


def _inner_command(line):
    m = re.search(r"(?:os\.system|os\.popen|subprocess\.(?:run|call|Popen)|system|popen)\s*\(\s*[\"']([^\"']+)[\"']", line)
    return m.group(1) if m else line


def script_line_ledger(text):
    """Per-line accounting of a script against the KMS allowlist.
    Every line ends up: blank or comment, KMS-allowlisted (slmgr and
    ospp.vbs licence lines, GVLK installation, KMS reactivation task),
    structural (imports, assignments, prints, control flow, ordinary
    statement keywords, expression statements), data (a semicolon
    comment, or a line of literal data tokens that can only name
    things), flagged (download, tamper, non-licensing persistence,
    exfiltration), or unaccounted. One flagged download, tamper or
    exfiltration line is proof; the allowlist defines the whole
    legitimate job of an activation script, so unaccounted lines
    block its NO."""
    out = {"lines": 0, "allowlisted": 0, "structural": 0, "data": 0, "flagged": [], "unaccounted": []}
    # A call to a function defined in this same script is accounted
    # by transitivity: the body's own lines are ledgered individually
    # below, so the call line adds no behaviour the ledger has not
    # already classified. The same holds for a class defined here
    # and for a name this file imports: the import line names the
    # module it comes from, so the callee's identity is fixed by
    # what the file shows. A call to any other bare name stays
    # unaccounted: what it does cannot be known from this file.
    known = set(re.findall(r"^\s*def\s+([A-Za-z_]\w*)\s*\(", text, re.M))
    known |= set(re.findall(r"^\s*class\s+([A-Za-z_]\w*)", text, re.M))
    for mimp in re.finditer(r"^\s*(?:from\s+\S+\s+)?import\s+(.+)$", text, re.M):
        for item in mimp.group(1).strip().strip("()").split(","):
            item = item.strip()
            if not item:
                continue
            malias = re.match(r"([A-Za-z_][\w\.]*)\s+as\s+([A-Za-z_]\w*)$", item)
            if malias:
                known.add(malias.group(2))
            else:
                mname = re.match(r"([A-Za-z_]\w*)", item)
                if mname:
                    known.add(mname.group(1))
    for n, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        if not line:
            continue
        out["lines"] += 1
        low = line.lower()
        if low.startswith(("#", "//", "rem ", "::")):
            out["structural"] += 1
            continue
        inner = _inner_command(line)
        ilow = inner.lower()
        if any(r.search(inner) or r.search(line) for r in KMS_ALLOW_RES):
            out["allowlisted"] += 1
            continue
        kind = None
        if any(r.search(inner) or r.search(line) for r in TAMPER_LINE_RES):
            kind = "tamper"
        elif any(r.search(inner) or r.search(line) for r in DOWNLOAD_LINE_RES):
            kind = "download-execute"
        elif any(r.search(inner) or r.search(line) for r in PERSIST_LINE_RES):
            kind = "persistence-nonlicensing"
        elif any(r.search(inner) for r in EXFIL_LINE_RES):
            kind = "network-exfiltration"
        if kind:
            out["flagged"].append({"line": n, "kind": kind, "text": line[:160]})
            continue
        if line.startswith(";"):
            # A leading semicolon is a comment in the INI, registry
            # and assembler dialects. The flagged scan above has
            # already run over the whole line, so a hostile atom
            # after the semicolon is flagged, never commented away;
            # what remains is a comment when the rest of the line
            # is itself accounted as data or structure.
            rest = line[1:].strip()
            if not rest or _data_line(rest) or _expression_statement(rest, known) \
                    or any(r.match(rest) for r in STRUCT_RES):
                out["data"] += 1
                continue
        if any(r.match(line) for r in STRUCT_RES):
            out["structural"] += 1
            continue
        mcall = re.match(r"([A-Za-z_]\w*)\s*\(.*\)\s*;?$", line)
        if mcall and mcall.group(1) in known:
            out["structural"] += 1
            continue
        if _expression_statement(line, known):
            out["structural"] += 1
            continue
        if _data_line(line):
            out["data"] += 1
            continue
        out["unaccounted"].append({"line": n, "text": line[:160]})
    return out


# Errors that mean content was swallowed or structure is missing:
# no per-line classification can account for what the parser never
# saw, so a failure of one of these classes is never attributable
# to data lines.
_PARSE_HARD_ERRORS = ("unterminated", "was never closed", "eof",
                      "indented block")


def script_parse_failure_attribution(text):
    """Decide whether a Python parse failure is fully explained
    by non-code lines. Returns (explained, neutralised), where
    neutralised is the list of 1-based line numbers that had to
    be replaced by a bare pass at the same indentation for the
    source to compile. A failure is explained only when every
    line that must be neutralised is a plain statement line: not
    a compound-statement header and not a decorator, and no
    error is of the unterminated-string, unclosed-delimiter, EOF
    or indented-block class. A malformed code line (a broken def
    header, a swallowed string) is genuinely unexamined
    structure and is never explained away."""
    lines = text.split("\n")
    neutralised = []
    seen = set()
    cur = text
    for _ in range(128):
        try:
            ast.parse(cur)
            return True, neutralised
        except SyntaxError as e:
            msg = (e.msg or "").lower()
            if any(h in msg for h in _PARSE_HARD_ERRORS):
                return False, neutralised
            ln = e.lineno
            if ln is None or ln < 1 or ln > len(lines) or ln in seen:
                return False, neutralised
            seen.add(ln)
            raw = lines[ln - 1]
            stripped = raw.strip()
            if not stripped or stripped.startswith("@"):
                return False, neutralised
            lead = re.match(r"[A-Za-z_]\w*", stripped)
            if lead and lead.group(0).lower() in COMPOUND_LEADS:
                return False, neutralised
            indent = raw[:len(raw) - len(raw.lstrip())]
            lines[ln - 1] = indent + "pass"
            neutralised.append(ln)
            cur = "\n".join(lines)
        except Exception:
            return False, neutralised
    return False, neutralised


def _scripts(report, caps, blob, low):
    # The ledger runs over the full decoded source, never the capped
    # display excerpt: a NO may not claim the whole source was read
    # when only the first excerpt was.
    text = report.get("script_source_full") or report.get("script_source_excerpt")
    if not text:
        return None, None
    ledger = script_line_ledger(text)
    chain = None
    kinds = sorted({f["kind"] for f in ledger["flagged"]})
    if kinds:
        chain = {"family": "malicious-script", "chain": "family-malicious-script",
                 "name": f"Malicious script lines: a line-by-line ledger of this script against the activation allowlist (slmgr and ospp.vbs licence lines) flags {len(ledger['flagged'])} line(s): {', '.join(kinds)}. A legitimate activation script does only licence lines, in readable plaintext; one download, tamper or exfiltration line is proof",
                 "evidence": [f"line {f['line']} [{f['kind']}]: {f['text']}" for f in ledger["flagged"][:6]]}
    return ledger, chain


# ---------------------------------------------------------------- DLL sideload (per-file part)
SIDECAR_ATOMS = ["decrypt payload", "payload file", "sidecar", "encrypted blob", "decrypts the .dat", "load payload"]


def _sideload_file(report, filename, caps, low):
    name = (filename or "").lower()
    if not name.endswith((".dll", ".dylib", ".so")):
        return None
    risky = sorted(set(caps) & (NET_CAPS | {"inject-process", "mem-exec", "exec-download-run"}))
    sidecar = _hits(low, SIDECAR_ATOMS) or bool(report.get("unpack", {}).get("high_entropy_regions"))
    if risky and sidecar:
        return {"family": "dll-sideload", "chain": "family-dll-sideload-payload",
                "name": "Malicious DLL sideload (per-file proof): this replacement DLL carries a non-library capability plus an encrypted sidecar payload. A legitimate scene emulator DLL implements the platform API and nothing else: no network loader, no sidecar decryption, no persistence. The folder-level triad (signed EXE, unsigned same-name DLL, encrypted sidecar) is judged in the verdict itself",
                "evidence": _ev(caps, *risky) + [f"sidecar atom: {s}" for s in _hits(low, SIDECAR_ATOMS)] + (["high entropy regions (encrypted sidecar)"] if report.get("unpack", {}).get("high_entropy_regions") else [])}
    return None


# ---------------------------------------------------------------- main
def family_findings(report, filename="", data=None, signature_valid=None,
                    reference_accounted=False):
    # signature_valid is accepted for call compatibility and is
    # deliberately not consumed toward any finding (coverage wave 8
    # provenance exclusion: signature state is report context, never
    # character evidence). reference_accounted is the accounting fact
    # that may suppress the unexplained-driver blocker: the file is
    # byte-identical to the genuine reference (hash match or a strong
    # manifest hash), so its bytes are accounted by identity.
    report = report or {}
    caps = _caps(report)
    blob = _blob(report)
    low = blob.lower()
    ev_ids = {f["id"] for f in report.get("evasion", {}).get("findings", [])}
    chains, blockers, conditional, notes, family_unaccounted = [], [], [], [], []

    for fn in (_stealer(caps, blob, low),
               _rat(caps, blob, low),
               _ransomware(caps, blob, low),
               _miner(caps, blob, low, notes),
               _loader(caps, blob, low, ev_ids, family_unaccounted),
               _botnet(caps, blob, low),
               _rootkit_bootkit(report, filename, signature_valid, caps, low, blockers,
                                reference_accounted=reference_accounted),
               _keylogger(caps, blob, low),
               _banking(caps, blob, low, filename, notes),
               _proxy(caps, blob, low, notes),
               _ppi(caps, blob, low),
               _adware(caps, blob, low, notes),
               _wiper(caps, blob, low, notes),
               _fileless(report, caps, blob, low, blockers),
               _sideload_file(report, filename, caps, low)):
        if fn:
            chains.append(fn)
    _logic_bomb(report, caps, blob, low, conditional, notes)
    beacon_chain, beacon_cfg = _beacon(data)
    if beacon_chain:
        chains.append(beacon_chain)
    ledger, script_chain = _scripts(report, caps, blob, low)
    if script_chain:
        chains.append(script_chain)
    return {"chains": chains, "blockers": blockers, "conditional_blockers": conditional,
            "notes": notes, "family_unaccounted": family_unaccounted,
            "script_ledger": ledger, "beacon_config": beacon_cfg}


def family_chains(report, filename="", data=None, signature_valid=None,
                  reference_accounted=False):
    """Chain-only view, used by verdict.malicious_chains."""
    return family_findings(report, filename, data, signature_valid,
                           reference_accounted=reference_accounted)["chains"]
