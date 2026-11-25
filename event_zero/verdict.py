"""Event Zero flagship: the YES / NO verdict for pirated and cracked software.

Design law (accuracy over comfort): this is an ACCOUNTING verdict, and
it fails closed. There are exactly two headlines:
    "YES: MALWARE FOUND"
    "NO: NO MALWARE"
YES carries a reason class:
  - PROVEN: malicious capability or behaviour is proven, with evidence.
  - UNACCOUNTED: some byte, file, script, archive layer or behaviour
    could not be accounted for as genuine or as the explained crack.
    UNACCOUNTED is stated plainly as unaccounted. It is not proven
    malware, and the report never calls it that. It is a refusal to
    certify, printed as YES because the only other headline is NO and
    NO must be earned.
NO is issued only when every file is byte-identical to a genuine
signature-valid original, or a fully reverse-engineered difference
classified expected-crack or benign-repack, with every archive layer
unpacked to the bottom. The NO claim is phrased exactly as the
accounting claim it is: every byte accounted for as genuine or
explained crack, and no behaviour beyond the genuine program plus the
explained crack observed in the evidence.

Circumvention itself is not malware: a patched license check, a keygen
algorithm, a KMS emulator and hosts-file activation blocks are the
expected crack. Antivirus HackTool or CrackTool labels alone never
trigger YES. An unneeded remote download-and-execute capability is
itself malicious class, because the payload it fetches tomorrow cannot
be accounted for today.

NSRL and CIRCL hashlookup presence, and antivirus non-detection, are
corroboration only: they identify known files, they never form the
basis of a NO.

Never a score, never a percentage, never a probability word.

Pipeline order matters: unpacking, multi-layer decoding, carving and
evasion analysis run BEFORE capability chains are judged, so hidden
layers are decoded first and only then scored.

The sample is never executed on the host. Archives and installers are
opened with parsers only, never run. Installer extraction adapters
(innoextract, 7z for NSIS, MSI table readers) are parser adapters;
.torrent file lists and .sfv files are enumeration aids only, and an
.sfv match proves self-consistency of the release, nothing more.
"""
import difflib, hashlib, io, ipaddress, json, os, re, shutil, struct, subprocess, tarfile, tempfile, time, zipfile
from .analyzer import analyze, hashes
from .unpack import analyze_unpack, carve
from .evasion import analyze_evasion
from .stringsx import extract_all
from .virt import analyze_virtualization, trace_entry_stub
from .capabilities import match_capabilities
from .families import family_findings, miner_disclosed
from .containers import EXTRA_CONTAINER_KINDS, detect_extra_kind, extract_to as _extract_extra_to, firmware_regions, carve_pe_images
from .bytecode import bytecode_report, split_macho_fat, is_jar_signature_member
from .coverage3 import byte_ownership, dual_parser, polyglot_identities, image_identity_accounted, driver_capabilities
from .coverage5 import member_semantics
from .coverage6 import SYSTEM_DLLS, autoexec_units, pe_imports
from .coverage7 import analyze_pickle, safetensors_accounting, is_safetensors, onnx_accounting, keras_lambda_findings, clipboard_units, scan_embedded_pickles

HEADLINE_YES = "YES: MALWARE FOUND"
HEADLINE_NO = "NO: NO MALWARE"
REASON_PROVEN = "PROVEN"
REASON_UNACCOUNTED = "UNACCOUNTED"
REASON_ACCOUNTED = "ACCOUNTED"
NO_CLAIM = "Every byte is accounted for as genuine or explained crack, and no behaviour beyond the genuine program plus the explained crack was observed in the evidence. This verdict is linked to the evidence manifest in this report."

# Built-in known-bad SHA-256 set. Deliberately small and curated: a hash
# only enters this set from a published, named source. Online known-bad
# hits (MalwareBazaar, VirusTotal) arrive through services.enrich when
# the user has configured keys, and are cited per file when they fire.
KNOWN_BAD_SHA256 = {}

NET_CAPS = {"net-socket", "net-connect", "net-send-recv", "net-http", "net-dns", "net-listen"}
PERSIST_CAPS = {"persist-runkey", "persist-file", "persist-schtask", "persistence-service"}
STEAL_CAPS = {"cred-access", "keylog", "screenshot", "clipboard"}
LICENSE_WORDS = ("license", "licence", "serial", "activation", "activate", "trial",
                 "register", "registration", "key check", "check_key", "verify_key",
                 "valid key", "license check", "product key")
EXECUTABLE_FORMATS = {"PE", "ELF", "Mach-O", "script", "text / script"}
ARCHIVE_SUFFIXES = (".zip", ".tar", ".tar.gz", ".tgz", ".tar.bz2", ".tbz2", ".tar.xz", ".txz")
MAX_MEMBERS = 10000
MAX_TOTAL_BYTES = 512 * 1024 * 1024


# ---------------------------------------------------------------- chains
def malicious_chains(report, data=None, filename=""):
    """Return a list of proven malicious chains for one analysed file.
    Each chain: {chain, name, evidence}. Dual-use APIs alone never form
    a chain: every chain needs the combination that makes it malicious
    in context, which is what keeps a crack itself from a false YES."""
    caps = {c["id"]: c for c in report.get("capabilities", [])}
    ev_ids = {f["id"] for f in report.get("evasion", {}).get("findings", [])}
    strings_blob = "\n".join(report.get("strings", {}).get("all", [])).lower()
    _src = report.get("script_source_full") or report.get("script_source_excerpt")
    if _src:
        strings_blob += "\n" + _src.lower()
    out = []

    def ev(*ids):
        e = []
        for i in ids:
            if i in caps:
                e.extend(caps[i]["evidence"])
        return sorted(set(e))

    net = [i for i in NET_CAPS if i in caps]
    if "cred-access" in caps and net:
        out.append({"chain": "stealer", "name": "Credential stealer: touches credential stores and has a network channel to send what it finds",
                    "evidence": ev("cred-access", *net)})
    steal2 = [i for i in ("keylog", "screenshot", "clipboard") if i in caps]
    if steal2 and net:
        out.append({"chain": "stealer-collection", "name": "Collects keystrokes, screen or clipboard and has a network channel to send it out",
                    "evidence": ev(*steal2, *net)})
    if "exec-download-run" in caps:
        out.append({"chain": "download-and-execute", "name": "Downloads code from the internet and runs it",
                    "evidence": ev("exec-download-run")})
    persist = [i for i in PERSIST_CAPS if i in caps]
    c2 = [i for i in ("net-connect", "net-http", "net-listen", "net-send-recv") if i in caps]
    if persist and c2:
        out.append({"chain": "persistence-plus-c2", "name": "Installs persistence and talks to a remote host: it stays on the machine and takes orders or sends data",
                    "evidence": ev(*persist, *c2)})
    # Miner proof standard (aligned with families._miner by the
    # verification corpus): pool plus wallet plus concealment or
    # persistence. A pool string or the miner binary alone is NOT
    # proof, and a disclosed own miner is not a finding at all.
    miner_concealed = bool(set(caps) & PERSIST_CAPS) or any(
        h in strings_blob for h in ("hidden", "windowstyle", "stealth", "hideconsole", "daemonize"))
    miner_wallet = "wallet" in strings_blob or bool(re.search(
        r"\b4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}\b|\b0x[0-9a-fA-F]{40}\b", strings_blob))
    if "mining" in caps and (net or "stratum" in strings_blob or "pool" in strings_blob) \
            and miner_concealed and miner_wallet and not miner_disclosed(report):
        out.append({"chain": "miner", "name": "Cryptocurrency miner with a pool or network channel: it mines for someone else on this machine",
                    "evidence": ev("mining", *net)})
    # Ransomware proof standard (aligned with families._ransomware by
    # the verification corpus): encryption plus file handling plus a
    # demand or anti-recovery element. Encryption plus delete alone is
    # also the shape of a backup tool, so it is not proof here.
    if "crypto-aes" in caps and "file-write" in caps and ("file-delete" in caps or "ransom" in strings_blob or "bitcoin" in strings_blob) \
            and any(d in strings_blob for d in ("ransom", "bitcoin", "shadow", "vssadmin", "your files are encrypted", "pay")):
        out.append({"chain": "ransomware", "name": "Ransomware pattern: encrypts files and deletes or demands payment over the originals",
                    "evidence": ev("crypto-aes", "file-write", "file-delete")})
    if "net-listen" in caps and "exec-shell" in caps:
        out.append({"chain": "backdoor", "name": "Backdoor: listens for incoming connections and runs shell commands for whoever connects",
                    "evidence": ev("net-listen", "exec-shell")})
    if "inject-chain" in ev_ids and ("mem-exec" in caps or "exec-download-run" in caps or persist or net):
        evf = [f for f in report["evasion"]["findings"] if f["id"] == "inject-chain"][0]
        out.append({"chain": "injection-plus-payload", "name": "Injects code into another process as part of a larger malicious chain",
                    "evidence": list(evf["evidence"]) + ev("mem-exec", "exec-download-run", *persist, *net)})
    rk = report.get("rootkit", {})
    if rk.get("is_kernel_driver") and rk.get("hiding_indicators"):
        out.append({"chain": "rootkit-hiding", "name": "Kernel driver with hiding indicators: rootkit behaviour",
                    "evidence": list(rk["hiding_indicators"])})
    # Per-family proof chains (The Verdict family expansion): each
    # family in families.py has a stated proof standard and a
    # false-positive twin discriminator. Family chains are appended
    # after the generic chains so generic names win display order.
    seen = {c["chain"] for c in out}
    for fc in family_findings(report, filename, data)["chains"]:
        if fc["chain"] not in seen:
            out.append(fc)
            seen.add(fc["chain"])
    return out


TAMPER_PATTERNS = [
    ("av-disable", r"Set-MpPreference[^\n]*-Disable(RealtimeMonitoring|BehaviorMonitoring|IOAVProtection)", "Disables Windows Defender protection through Set-MpPreference"),
    ("av-disable", r"DisableAntiSpyware|DisableAntiVirus", "Registry policy that disables antivirus"),
    ("av-stop", r"(net|sc)\s+(stop|config)\s+\S*(WinDefend|Sense|WdNisSvc|SecurityHealthService)", "Stops an antivirus service"),
    ("av-delete", r"(del|rm|Remove-Item)[^\n]*(Windows Defender|MpCmdRun|MsMpEng|antivirus)", "Deletes antivirus components"),
    ("av-exclusion-broad", r"Add-MpPreference\s+-Exclusion(Path|Process)[^\n]*", "Adds a Defender exclusion (scope judged in the scope test)"),
    ("safe-mode", r"SafeBoot|bcdedit[^\n]*safeboot|HKLM[^\n]*SafeBoot", "Safe Mode boot configuration manipulation, the Crackonosh route to deleting antivirus where it cannot defend itself"),
    ("reboot-gating", r"(?i)reboot[_\s-]*(count|counter|number)|boot[_\s-]*count|NumberOfReboots|RebootCount", "Reboot-count gating: the sample counts restarts and acts only after many of them, the Crackonosh delay pattern"),
]

def tampering_findings(report):
    """Crackonosh-class indicators: AV tampering, Safe Mode registry
    manipulation, reboot-count gating. Each is PROVEN class: none of
    them is ever part of a crack's claimed function."""
    blob = "\n".join(report.get("strings", {}).get("all", []))
    _src = report.get("script_source_full") or report.get("script_source_excerpt")
    if _src:
        blob += "\n" + _src
    out = []
    seen = set()
    for kind, pat, why in TAMPER_PATTERNS:
        m = re.search(pat, blob)
        if m and kind not in seen or (m and kind == "av-exclusion-broad"):
            if kind in seen and kind != "av-exclusion-broad":
                continue
            seen.add(kind)
            out.append({"kind": kind, "evidence": m.group(0)[:160], "why": why})
    return out

# KMS evidence must live in behaviour-bearing content: tool names and
# protocol vocabulary in the file's own strings. The file NAME never
# qualifies (a name is chosen by whoever ships the file, so a baseline
# keyed on it acquits by filename), and neither does a bare "1688"
# substring (the KMS port number appears inside unrelated digit
# strings, filler text and counters, and tripped this test on filler
# during the 2026-11-24 accuracy audit).
KMS_MARKERS = ("kmspico", "kmsauto", "autokms", "gvlk", "slmgr",
               "keymanagementservice", "key management service",
               "kms emulator", "kms server", "kms host", "kms client")
def kms_baseline(report):
    """True when the file presents as a KMS activator. The expected
    baseline for a KMS activator is exactly: a local emulator service,
    a renewal scheduled task, and GVLK key installation. Everything
    outside that baseline is judged normally."""
    blob = "\n".join(report.get("strings", {}).get("all", [])).lower()
    src = report.get("script_source_full") or report.get("script_source_excerpt")
    if src:
        blob += "\n" + src.lower()
    return any(m in blob for m in KMS_MARKERS)

def _ip_is_local(ip):
    """Real private-range test. A prefix test is wrong: "172." covers
    all of 172.0.0.0/8, but only 172.16.0.0/12 is private, so public
    addresses such as 172.217.14.206 (Google) were classified local."""
    try:
        a = ipaddress.ip_address(ip)
    except Exception:
        return False
    return a.is_loopback or a.is_private or a.is_link_local or a.is_unspecified

_INTERNAL_DOMAIN_SUFFIXES = (".local", ".lan", ".home", ".internal", ".intranet", ".corp")
def external_contacts(report):
    """Every contact in the file that reaches outside this machine:
    any URL, any non-local IP address, and any bare domain that is
    not a provably internal name. A bare domain counts as external:
    a name is resolved by an external resolver to an external host
    unless its suffix marks it as an internal name."""
    iocs = report.get("iocs", {})
    ext = list(iocs.get("urls", []))
    ext += [ip for ip in iocs.get("ip_addresses", []) if not _ip_is_local(ip)]
    ext += [d for d in iocs.get("domains", [])
            if d != "localhost" and not d.endswith(_INTERNAL_DOMAIN_SUFFIXES)]
    return ext

def claimed_function(name, report):
    n = name.lower()
    blob = "\n".join(report.get("strings", {}).get("all", [])).lower()
    if "keygen" in n or "keygen" in blob or "key generator" in blob:
        return "keygen"
    if kms_baseline(report):
        return "activator"
    if "patch" in n or "patcher" in blob:
        return "patcher"
    return "program"

def scope_test(report, name):
    """THE SCOPE TEST (named rule): the first behaviour that is
    unnecessary for the file's claimed function decides YES.
    Circumvention itself is never a scope violation: patched checks,
    key algorithms and KMS emulation are the claimed function of a
    crack. Network access for a keygen, wallet or browser credential
    access, antivirus deletion or disabling, Defender exclusions
    outside the program folder, and undisclosed mining are."""
    claimed = claimed_function(name, report)
    caps = {c["id"]: c for c in report.get("capabilities", [])}
    out = []
    def ev(*ids):
        e = []
        for i in ids:
            if i in caps:
                e.extend(caps[i]["evidence"])
        return sorted(set(e))
    if claimed in ("keygen", "patcher", "activator"):
        net = [i for i in NET_CAPS if i in caps]
        if claimed == "activator" and kms_baseline(report):
            # KMS baseline: a local emulator listener on the KMS port is
            # the claimed function. Only network reach beyond that
            # baseline is a scope violation.
            if not external_contacts(report):
                net = []
        if net:
            out.append({"behaviour": f"network access for a {claimed}", "evidence": ev(*net),
                        "why": f"A {claimed} does its whole job on this machine. Network access is unnecessary for the claimed function, so under the scope test it decides the verdict on its own."})
        steal = [i for i in STEAL_CAPS if i in caps]
        if steal:
            out.append({"behaviour": f"wallet or browser credential access by a {claimed}", "evidence": ev(*steal),
                        "why": "Touching credential stores, keystrokes, screen or clipboard is unnecessary for the claimed function and is the core behaviour of a stealer."})
        if "exec-download-run" in caps:
            out.append({"behaviour": f"remote download and execute by a {claimed}", "evidence": ev("exec-download-run"),
                        "why": "An unneeded remote download-and-execute capability is itself malicious class: the payload it fetches tomorrow cannot be accounted for today."})
    if "mining" in caps and claimed != "program":
        out.append({"behaviour": "undisclosed mining", "evidence": ev("mining"),
                    "why": "Mining for someone else is never part of a crack's claimed function and is never disclosed by the releases that bundle it."})
    for t in tampering_findings(report):
        if t["kind"] == "av-exclusion-broad":
            path_txt = t["evidence"]
            broad = any(x in path_txt for x in ("C:\\", "%USERPROFILE%", "C:/Users", " -ExclusionPath C:", "ProgramData")) and name.lower().split(".")[0] not in path_txt.lower()
            if broad:
                out.append({"behaviour": "Defender exclusion outside the program folder", "evidence": [path_txt],
                            "why": "An exclusion that covers folders outside the program's own folder blinds Defender to far more than the crack. That is AV tampering, not circumvention."})
            continue
        out.append({"behaviour": t["why"], "evidence": [t["evidence"]],
                    "why": "Antivirus tampering, Safe Mode manipulation and reboot-count gating are PROVEN class (the Crackonosh pattern: wait through many reboots, then delete the antivirus in Safe Mode where it cannot defend itself). None is ever part of a crack's claimed function."})
    return out, claimed

SCENE_GROUPS = ("codex", "skidrow", "flt", "fairlight", "plaza", "rune", "empress", "goldberg", "hoodlum", "tenoke", "flt", "razor1911", "cpy", "steam underground")
def provenance_findings(text_blobs):
    """Provenance checks. Scene groups have no websites: a release
    claiming a group site is fraudulent by construction. Impersonator
    signals are recorded as evidence entries."""
    out = []
    for blob in text_blobs:
        low = blob.lower()
        for m in re.finditer(r"https?://[^\s\"'<>\)]+", blob):
            url = m.group(0)
            ctx = low[max(0, m.start() - 120):m.start()]
            if any(g in ctx for g in SCENE_GROUPS) or "official site" in ctx or "our website" in ctx or "homepage" in ctx:
                if any(g in url.lower() or g in ctx for g in SCENE_GROUPS):
                    out.append({"signal": "scene-group-site-claim", "url": url,
                                "detail": "Scene groups have no websites. A release claiming a scene group site is fraudulent by construction: the provenance it claims cannot exist, so the release cannot be accounted for as that group's release."})
    return out

def parse_manifest(text, kind):
    """Parse an .sfv (CRC32) or checksum manifest (md5/sha1/sha256).
    Returns {filename: expected_hex}."""
    out = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith(";") or line.startswith("#"):
            continue
        if kind == "sfv":
            parts = line.rsplit(None, 1)
            if len(parts) == 2 and re.fullmatch(r"[0-9a-fA-F]{8}", parts[1]):
                out[parts[0]] = parts[1].lower()
        else:
            m = re.match(r"^([0-9a-fA-F]{32,64})\s+\*?(.+)$", line)
            if m:
                out[m.group(2).strip()] = m.group(1).lower()
    return out

def manifest_kind(name):
    n = name.lower()
    if n.endswith(".sfv"):
        return "sfv"
    if n.endswith((".md5", ".sha1", ".sha256", ".sha256sum", ".sums")):
        return "checksum"
    if "checksums" in n or "hashes" in n:
        return "checksum"
    return None


SHORTENER_HOSTS = {"bit.ly", "tinyurl.com", "is.gd", "t.co", "rb.gy", "cutt.ly", "shorturl.at", "tiny.cc", "ow.ly", "rebrand.ly", "s.id", "v.gd"}
FILEHOST_HOSTS = {"mega.nz", "mediafire.com", "anonfiles.com", "sendspace.com", "rapidgator.net", "uploaded.net", "turbobit.net", "pixeldrain.com", "gofile.io", "raw.githubusercontent.com", "gist.githubusercontent.com"}
VENDOR_DOMAINS = {"microsoft.com", "windows.com", "google.com", "steampowered.com", "steamcommunity.com", "discord.com", "telegram.org", "github.com", "mozilla.org", "apple.com", "adobe.com", "nvidia.com", "amd.com", "intel.com"}
LOLBINS = ("powershell", "mshta", "rundll32", "certutil", "bitsadmin", "wscript", "cscript", "curl", "wget")
DOWNLOAD_CRADLE = ("downloadstring", "invoke-expression", "iex(", "iex ", "-enc", "urlcache", "/transfer", "downloadfile", "net.webclient", "start-bitstransfer")

def _edit_distance(a, b):
    if abs(len(a) - len(b)) > 2:
        return 99
    dp = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        prev, dp[0] = dp[0], i
        for j, cb in enumerate(b, 1):
            prev, dp[j] = dp[j], min(dp[j] + 1, dp[j - 1] + 1, prev + (ca != cb))
    return dp[-1]

def classify_link(dest, baseline_domains=()):
    """Classify one ledger destination. Returns (classification, tag)."""
    host = (dest.get("domain") or "").lower()
    ip = dest.get("ip") or ""
    if ip:
        if ip.startswith(("127.", "0.", "10.", "192.168.", "172.16.", "172.17.", "172.18.", "172.19.", "172.2", "172.30.", "172.31.", "::1")):
            return "local", "crack-only"
        return "unknown", "needs-more-evidence"
    if not host:
        return "unknown", "needs-more-evidence"
    if host in baseline_domains or any(host == d or host.endswith("." + d) for d in baseline_domains):
        return "genuine-vendor", "crack-only"
    if host in SHORTENER_HOSTS or any(host.endswith("." + d) for d in SHORTENER_HOSTS):
        return "shortener", "needs-more-evidence"
    if host in FILEHOST_HOSTS or any(host.endswith("." + d) for d in FILEHOST_HOSTS):
        return "file-host", "needs-more-evidence"
    for vd in VENDOR_DOMAINS:
        if host == vd or host.endswith("." + vd):
            return "genuine-vendor", "crack-only"
        if vd in host and host != vd and not host.endswith("." + vd):
            return "lookalike", "needs-more-evidence"
        registrable = ".".join(host.split(".")[-2:])
        if registrable != vd and _edit_distance(registrable, vd) in (1, 2):
            return "lookalike", "needs-more-evidence"
    return "unknown", "needs-more-evidence"

def parse_url_file(data):
    text = data.decode("utf-8", "replace")
    out = []
    for line in text.splitlines():
        if line.strip().lower().startswith("url="):
            out.append(line.strip()[4:])
    return out

# ------------------------------------------------------------------
# Script-class and shortcut-class shapes (accuracy fix wave 2,
# 2026-11-24). The classes below reach the verdict as plain text:
# detect_format has no branch for them, and script_analysis does not
# claim their extensions (.cmd, .hta and .url are absent from
# SCRIPT_EXTS in analyzer.py), so no script source is recorded, the
# per-line ledger never runs on them, and the text NO branch could
# acquit them on a full read that never happened in ledger terms.
# These findings close that path fail-closed, in the verdict, the
# same place wave 1 wired the document and firmware findings in.
# A finding here is a blocker, never a proof chain: it makes NO
# unreachable for the shape, it does not convict the file.
SCRIPT_CLASS_EXTS = {".bat", ".cmd", ".ps1", ".vbs", ".vbe", ".js", ".jse",
                     ".wsf", ".wsh", ".hta", ".sh", ".bash", ".py", ".pl", ".rb"}
EXEC_PAYLOAD_EXTS = (".exe", ".dll", ".scr", ".com", ".bat", ".cmd", ".ps1",
                     ".vbs", ".vbe", ".js", ".jse", ".wsf", ".wsh", ".hta",
                     ".msi", ".jar", ".cpl")
FETCH_PATTERNS = [
    ("bitsadmin transfer", r"bitsadmin[^\n]{0,240}?(/transfer|https?://)"),
    ("certutil URL cache download", r"certutil[^\n]{0,160}?-urlcache|-urlcache[^\n]{0,160}?certutil"),
    ("Start-BitsTransfer", r"start-bitstransfer"),
    ("curl or wget fetch", r"\b(?:curl|wget)\b[^\n]{0,240}?(?:https?://|ftp://|\d{1,3}(?:\.\d{1,3}){3})"),
    ("PowerShell web download", r"(?:downloadstring|downloadfile|invoke-webrequest|invoke-restmethod)[^\n]{0,240}?(?:https?://|\d{1,3}(?:\.\d{1,3}){3})"),
    ("Python web fetch", r"(?:urlopen|requests\.(?:get|post)|urllib\.request)[^\n]{0,200}?https?://"),
    ("remote script include", r"<script[^>]+src\s*=\s*[\"']?https?://"),
    ("XMLHTTP or WinHttp fetch", r"(?:xmlhttp|winhttp)[^\n]{0,240}?https?://"),
    ("mshta remote content", r"mshta(?:\.exe)?\s+[\"']?https?://"),
    ("rundll32 remote content", r"rundll32[^\n]{0,200}?https?://"),
]
EXEC_PATTERNS = [
    ("pipe to a shell", r"\|\s*(?:sh|bash|powershell|cmd)\b"),
    ("Invoke-Expression", r"invoke-expression|\biex\s*\("),
    ("Start-Process", r"start-process"),
    ("batch start command", r"(?m)^\s*start\s+(?:\"[^\"]*\"\s+)?\S"),
    ("script host Run call", r"\.run\s*\("),
    ("ShellExecute", r"shellexecute"),
    ("shell command execution", r"os\.system|subprocess\.|popen\s*\("),
]
DOWNLOAD_LINE_WORDS = ("bitsadmin", "certutil", "start-bitstransfer", "curl ", "wget ",
                       "invoke-webrequest", "downloadfile", "downloadstring")
DOUBLE_EXT_DOC = ("pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "rtf",
                  "txt", "jpg", "jpeg", "png", "gif", "zip")
DOUBLE_EXT_EXEC = ("exe", "scr", "com", "bat", "cmd", "ps1", "vbs", "vbe",
                   "js", "jse", "wsf", "wsh", "hta", "msi", "jar")

def _download_line_payload(low):
    """An executable-extension file named on a download line, as the
    fetched URL or as the local destination: the staged payload. A
    URL token is judged on its path only, never on its host: the
    .com in a domain name is a top-level domain, not the DOS
    executable extension, and matching it would convict every
    download from a .com host."""
    for line in low.splitlines():
        if not any(w in line for w in DOWNLOAD_LINE_WORDS):
            continue
        for tok in re.findall(r"[^\s\"'<>]+", line):
            t = tok.rstrip(".,;:")
            if "://" in t:
                rest = t.split("://", 1)[1]
                upath = rest.split("/", 1)[1] if "/" in rest else ""
                upath = upath.split("?")[0].split("#")[0]
                if upath.endswith(EXEC_PAYLOAD_EXTS):
                    return t
            elif t.endswith(EXEC_PAYLOAD_EXTS):
                return t
    return None

def script_class_findings(name, data):
    """Findings for script-class and shortcut-class files: a remote
    fetch-and-execute chain, a .url shortcut whose target is a remote
    executable payload, and a disguised double extension. Returns a
    list of {kind, evidence}. The principle is accounting, not
    suspicion: what a fetch-and-execute file does is decided by
    content that is not in the file, so no reading of the file alone
    can account for its behaviour, and a NO built on that reading
    would be false. A fetch with no execution side and no executable
    payload (downloading data, a URL mentioned in a comment) is not a
    finding: the chain, not the atom, is what blocks."""
    base = os.path.basename(str(name).split("!")[-1]).lower()
    ext = os.path.splitext(base)[1]
    out = []
    m = re.match(r".*\.(" + "|".join(DOUBLE_EXT_DOC) + r")\.(" + "|".join(DOUBLE_EXT_EXEC) + r")$", base)
    if m:
        out.append({"kind": "disguised-double-extension",
                    "evidence": [f"file name: {base}",
                                 f"document extension presented first: .{m.group(1)}",
                                 f"executable extension that actually governs: .{m.group(2)}"]})
    if ext == ".url":
        for u in parse_url_file(data):
            mu = re.match(r"(?:https?|ftp)://([^/:\s]+)(?::\d+)?(/[^\s]*)?", u)
            if not mu:
                continue
            host = mu.group(1).lower()
            upath = (mu.group(2) or "/").split("?")[0].split("#")[0].lower()
            is_ip = bool(re.fullmatch(r"(?:\d{1,3}\.){3}\d{1,3}", host))
            page = upath in ("", "/") or upath.endswith((".htm", ".html", ".php", ".asp", ".aspx", ".jsp", ".cfm"))
            if upath.endswith(EXEC_PAYLOAD_EXTS) or (is_ip and not page):
                out.append({"kind": "url-shortcut-remote-payload",
                            "evidence": [f"shortcut target: {u}",
                                         "the target is a remote executable payload" if upath.endswith(EXEC_PAYLOAD_EXTS)
                                         else "the target is a payload path on a bare IP host, with no page extension"]})
        return out
    text = _decode_script_bytes(data)
    if ext not in SCRIPT_CLASS_EXTS:
        # Wave 4: the class is keyed on content where the name
        # carries no class at all. Identical dropper bytes under a
        # bare hash name (the form in which samples and renamed
        # deliveries circulate) were judged as plain text, because
        # every script treatment in the engine keyed on the
        # extension. A strong dialect signature in the content
        # assigns the class the name failed to.
        sniffed = _sniff_script_ext(text) if ext == "" else None
        if not sniffed:
            return out
        ext = sniffed
    if "\x00" in text[:2000]:
        return out
    # The scan runs over the raw source and over the resolved
    # source (wave 4: variable substitution, character-code
    # decoding, literal de-concatenation), and takes the union:
    # these dialects execute the resolved text, so a literal-only
    # scan judges a text the host never runs.
    seen = set()
    for cand in (text, _resolved_script_text(ext, text)):
        for f in _script_text_findings(ext, cand):
            key = (f["kind"], tuple(f["evidence"]))
            if key not in seen:
                seen.add(key)
                out.append(f)
    return out

def _script_text_findings(ext, text):
    """The wave 2 chain scan over one version of a script-class
    file's source (raw or resolved), plus the wave 4 composition
    rule: a network-fetch object composed with an executable staged
    to disk is a fetch-and-execute chain even when no single line
    holds both halves, which is the object model's normal shape
    (the fetch object is created on one line, opened on another,
    and its response body written out by a stream object on a
    third)."""
    out = []
    low = text.lower()
    fetch = [label for label, pat in FETCH_PATTERNS if re.search(pat, low)]
    execs = [label for label, pat in EXEC_PATTERNS if re.search(pat, low)]
    if _BARE_EXEC_RE.search(text):
        execs.append("downloaded file invoked by name")
    payload = _download_line_payload(low)
    intrinsic = [f for f in fetch if f in ("mshta remote content", "rundll32 remote content", "remote script include")]
    # An HTA is executed by mshta the moment it opens, so a remote
    # fetch inside one is a fetch-and-execute chain by construction:
    # the file itself is the executor.
    if intrinsic or (ext == ".hta" and fetch) or (fetch and (execs or payload)):
        ev = [f"fetch: {f}" for f in fetch] + [f"execution: {e}" for e in execs]
        if payload:
            ev.append(f"executable payload staged: {payload}")
        if ext == ".hta" and fetch and not execs and not payload:
            ev.append("the HTA itself is the executor: mshta runs its script on open")
        out.append({"kind": "remote-fetch-and-execute", "evidence": ev})
        return out
    netobj = [label for label, pat in NETOBJ_PATTERNS if re.search(pat, low)]
    staged = _staged_executable(low)
    if netobj and staged:
        # The staged executable is the unaccounted content, the
        # same basis on which wave 3 caps a download-only proxy
        # aimed at an executable: what the file does next is
        # decided by bytes that are not in this file.
        ev = [f"fetch object: {n}" for n in netobj]
        ev.append(f"executable payload staged: {staged}")
        ev += [f"execution: {e}" for e in execs]
        if ext == ".hta" and not execs:
            ev.append("the HTA itself is the executor: mshta runs its script on open")
        out.append({"kind": "remote-fetch-and-execute", "evidence": ev})
    return out

# ------------------------------------------------------------------
# Resolved script source (accuracy fix wave 4, 2026-11-24). Waves 2
# and 3 read the raw text of script-class files, but the dialects
# these delivery files use execute a resolved text: batch expands
# %VAR% and !VAR! from set assignments, VBScript and JScript pass
# URLs and paths through variables, strings are assembled from
# fragments and concatenations, and a URL can be built from Chr()
# character codes with no literal form anywhere. None of that is
# obfuscation; it is the ordinary mechanics of the dialect, and an
# idiomatically written lure file is invisible to a literal scan.
# The helpers below produce, at the same static limit as wave 3's
# de-concatenation, the source the host would execute: decoding
# that never silently empties, character-code construction
# decoded, literal concatenation collapsed, and simple
# literal-valued variables substituted. Consumers run their
# existing checks over the raw text and the resolved text and
# take the union, so nothing the raw scan caught is lost.
NETOBJ_PATTERNS = [
    ("XMLHTTP or WinHttp object", r"(?:createobject|activexobject)\s*\(\s*[\"'](?:msxml2\.xmlhttp|microsoft\.xmlhttp|msxml2\.serverxmlhttp|winhttp\.winhttprequest)"),
    ("WebClient download object", r"net\.webclient|webclient\s*\("),
]
STAGE_WRITE_PATTERNS = [
    r"savetofile\s+([^,\n]+)",
    r"createtextfile\s*\(\s*([^,\n]+)",
]
_BARE_EXEC_RE = re.compile(r"^\s*(?:call\s+)?[\"']?[^\s\"']+\.(?:exe|com|scr|bat|cmd|msi)[\"']?\s*$", re.I | re.M)
_CHR_RUN_RE = re.compile(r"(?:ChrW?\(\s*\d+\s*\)\s*[&+]\s*)+ChrW?\(\s*\d+\s*\)|ChrW?\(\s*\d+\s*\)", re.I)
_CHR_ONE_RE = re.compile(r"ChrW?\(\s*(\d+)\s*\)", re.I)
_FROMCHARCODE_RE = re.compile(r"String\.fromCharCode\(([\d\s,]+)\)", re.I)
_BATCH_DIALECT_EXTS = {".bat", ".cmd"}
_WORD_DIALECT_EXTS = {".vbs", ".vbe", ".js", ".jse", ".wsf", ".wsh", ".hta"}
_PS_DIALECT_EXTS = {".ps1"}
_SHELL_DIALECT_EXTS = {".sh", ".bash"}

def _decode_script_bytes(data):
    """Decode script-class bytes the way the host reads them:
    BOM-marked UTF-16 and UTF-8, BOM-less UTF-16 (NUL-interleaved),
    strict UTF-8, and a cp1252 fallback for the legacy code page
    these lure files are written in. Never returns an empty string
    for non-empty input. Wave 3's reference extractor decoded
    strict UTF-8 and returned "" on any error, while the format
    heuristic reads only the first 4,096 bytes: one cp1252 byte
    past that window in an 8 KB Italian lure batch file silently
    emptied the file's entire external-reference list."""
    if not data:
        return ""
    if data[:2] in (b"\xff\xfe", b"\xfe\xff"):
        return data.decode("utf-16", "replace")
    if data[:3] == b"\xef\xbb\xbf":
        return data.decode("utf-8-sig", "replace")
    head = data[:512]
    if len(head) >= 8:
        pairs = max(1, len(head) // 2)
        nul_at_odd = sum(1 for i in range(1, len(head), 2) if head[i] == 0)
        nul_at_even = sum(1 for i in range(0, len(head), 2) if head[i] == 0)
        if nul_at_odd > pairs * 0.6:
            return data.decode("utf-16-le", "replace")
        if nul_at_even > pairs * 0.6:
            return data.decode("utf-16-be", "replace")
    try:
        return data.decode("utf-8")
    except Exception:
        return data.decode("cp1252", "replace")

def _decode_chr_constructions(text):
    """Decode Chr()/ChrW() character construction and JScript
    String.fromCharCode into the characters they build, as a
    quoted literal the de-concatenation pass can then join with
    its neighbours. A URL assembled from character codes has no
    literal form anywhere in the raw text; after this pass it is
    an ordinary string the existing scans can read. Replacement
    happens in the analysis copy only."""
    def _run(m):
        try:
            chars = [int(n) for n in _CHR_ONE_RE.findall(m.group(0))]
            if not chars or not all(0 < c < 0x110000 for c in chars):
                return m.group(0)
            return '"' + "".join(chr(c) for c in chars).replace('"', "'") + '"'
        except Exception:
            return m.group(0)
    t = _CHR_RUN_RE.sub(_run, text)
    def _fcc(m):
        try:
            return '"' + "".join(chr(int(n)) for n in m.group(1).split(",")).replace('"', "'") + '"'
        except Exception:
            return m.group(0)
    return _FROMCHARCODE_RE.sub(_fcc, t)

def _sniff_script_ext(text):
    """Content-keyed script class for a file whose name carries no
    extension. Every script treatment in the engine keys on the
    extension, so identical dropper bytes under a bare hash name
    were judged as plain text and acquitted. The signatures are
    the dialects' own structural markers, not keywords: an
    HTA:APPLICATION element, a script element naming VBScript or
    JScript together with an ActiveX object, a batch file's @echo
    opening with set and expansion structure, a VBScript object
    script outside markup. Returns the sniffed extension or
    None."""
    low = text.lower()
    if "<hta:application" in low:
        return ".hta"
    if "<script" in low and ("vbscript" in low or "jscript" in low) \
            and ("createobject" in low or "activexobject" in low):
        return ".hta"
    head = "\n".join(text.splitlines()[:60]).lower()
    batch_marks = sum([
        "@echo" in head,
        bool(re.search(r"(?m)^\s*set\s+[a-z_]\w*=", head)),
        bool(re.search(r"(?m)^\s*(?:goto|call)\s+[:\w]", head)),
        bool(re.search(r"%\w+%\\", head)),
    ])
    if batch_marks >= 3:
        return ".cmd"
    if "createobject(" in low and re.search(r"(?m)^\s*set\s+\w+\s*=", low) \
            and re.search(r"(?m)^\s*dim\s+\w+", low):
        return ".vbs"
    return None

def _batch_expand(s, env):
    for _ in range(6):
        n = re.sub(r"%([A-Za-z_]\w*)%", lambda m: env.get(m.group(1).lower(), m.group(0)), s, flags=re.I)
        n = re.sub(r"!([A-Za-z_]\w*)!", lambda m: env.get(m.group(1).lower(), m.group(0)), n, flags=re.I)
        # a batch-set variable is part of the environment a child
        # PowerShell process inherits, read there as $env:NAME
        n = re.sub(r"\$env:([A-Za-z_]\w*)", lambda m: env.get(m.group(1).lower(), m.group(0)), n, flags=re.I)
        if n == s:
            break
        s = n
    return s

def _batch_resolve(lines):
    env = {}
    for ln in lines:
        m = re.match(r"\s*set\s+(.+)$", ln, re.I)
        if not m or _is_comment_line(ln):
            continue
        rest = m.group(1).strip()
        if rest.startswith("/") or "=" not in rest:
            continue
        if rest.startswith('"') and rest.endswith('"'):
            rest = rest[1:-1]
        k, v = rest.split("=", 1)
        k = k.strip()
        if re.fullmatch(r"[A-Za-z_]\w*", k):
            env[k.lower()] = _batch_expand(v.strip(), env)
    # Assignment lines are emitted as written: their values built
    # the environment, and re-expanding a self-referential
    # assignment (set u=%u%.exe) against the final environment
    # would double-apply it. Every other line is expanded with
    # the final environment, which is the text the host runs.
    return [ln if (_is_comment_line(ln) or re.match(r"\s*set\s+", ln, re.I))
            else _batch_expand(ln, env) for ln in lines]

_LIT_ASSIGN_RE = re.compile(r"(?<![\w$.])([A-Za-z_]\w*)\s*=\s*(\"([^\"]*)\"|'([^']*)')")

def _word_env(lines):
    env = {}
    for ln in lines:
        if _is_comment_line(ln):
            continue
        for m in _LIT_ASSIGN_RE.finditer(ln):
            if m.start() > 0 and ln[m.start() - 1] == "=":
                continue
            env[m.group(1).lower()] = m.group(3) if m.group(3) is not None else m.group(4)
    return env

def _substitute_outside_quotes(line, subs, quote_chars):
    parts = re.split("(" + "|".join(re.escape(q) + "[^" + re.escape(q) + "]*" + re.escape(q) for q in quote_chars) + ")", line)
    for i in range(0, len(parts), 2):
        seg = parts[i]
        for pat, val in subs:
            seg = pat.sub(lambda _m, v=val: v, seg)
        parts[i] = seg
    return "".join(parts)

def _word_resolve(lines, ext):
    env = _word_env(lines)
    if not env:
        return lines
    subs = []
    for k, v in env.items():
        pat = re.compile(r"(?<![\w$.])" + re.escape(k) + r"(?![\w])", re.I)
        subs.append((pat, '"' + v.replace('"', "'") + '"'))
    quotes = ('"',) if ext in (".vbs", ".vbe", ".wsf", ".wsh") else ('"', "'")
    return [ln if _is_comment_line(ln) else _substitute_outside_quotes(ln, subs, quotes)
            for ln in lines]

def _ps_resolve(lines):
    env = {}
    for ln in lines:
        if _is_comment_line(ln):
            continue
        for m in re.finditer(r"\$([A-Za-z_]\w*)\s*=\s*(\"([^\"]*)\"|'([^']*)')", ln):
            env[m.group(1).lower()] = m.group(3) if m.group(3) is not None else m.group(4)
    if not env:
        return lines
    out = []
    for ln in lines:
        if _is_comment_line(ln):
            out.append(ln)
            continue
        for k, v in env.items():
            ln = re.sub(r"\$" + re.escape(k) + r"(?![\w:])", lambda _m, v=v: '"' + v.replace('"', "'") + '"', ln, flags=re.I)
        out.append(ln)
    return out

def _shell_resolve(lines):
    env = {}
    for ln in lines:
        m = re.match(r"\s*(?:export\s+)?([A-Za-z_]\w*)=(\"([^\"]*)\"|'([^']*)'|([^\s]+))", ln)
        if m and not _is_comment_line(ln):
            env[m.group(1)] = next(g for g in m.groups()[1:] if g is not None)
    if not env:
        return lines
    out = []
    for ln in lines:
        if _is_comment_line(ln):
            out.append(ln)
            continue
        for k, v in env.items():
            ln = ln.replace("${" + k + "}", v)
            ln = re.sub(r"\$" + re.escape(k) + r"(?![\w])", lambda _m, v=v: v, ln)
        out.append(ln)
    return out

def _resolved_script_text(ext, text):
    """The source the host would execute, resolved at the static
    limit: character-code construction decoded, adjacent literal
    concatenation collapsed, and simple literal-valued variables
    substituted in the dialect's own syntax (batch %VAR% and
    !VAR! from set assignments, VBScript and JScript identifiers,
    PowerShell $VAR, shell $VAR). Substitution runs on
    non-comment lines only, so a mention in a comment stays a
    mention (the wave 2 comment control). Anything the static
    limit cannot resolve (function results, registry or
    environment reads, substring arithmetic on non-literals)
    stays visibly unresolved in the output rather than being
    guessed."""
    t = _deconcatenate(_decode_chr_constructions(text))
    lines = t.splitlines()
    if ext in _BATCH_DIALECT_EXTS:
        lines = _batch_resolve(lines)
    elif ext in _WORD_DIALECT_EXTS:
        lines = _word_resolve(lines, ext)
    elif ext in _PS_DIALECT_EXTS:
        lines = _ps_resolve(lines)
    elif ext in _SHELL_DIALECT_EXTS:
        lines = _shell_resolve(lines)
    return "\n".join(lines)

def _staged_executable(low):
    """An executable-class path handed to a stream write in the
    (lowercased) source: the staged payload of the object model,
    where the download line of the command model is an Open call
    and a SaveToFile three lines apart."""
    for pat in STAGE_WRITE_PATTERNS:
        for m in re.finditer(pat, low):
            tgt = m.group(1).strip().strip("\"'").rstrip(")\"' ")
            if tgt.endswith(EXEC_PAYLOAD_EXTS):
                return tgt
    return None

_ECHO_STAGE_RE = re.compile(r"^\s*@?echo\s+(.*?)\s*(>>?)\s*(\S+)\s*$", re.I)

def _echo_stages(text):
    """Files a batch file writes with echo redirection, as
    {target token: reconstructed content}. A single > starts the
    file over; >> appends. The reconstruction is exact for the
    lines the writer carries: echo is a literal transcription in
    this dialect."""
    stages = {}
    for ln in text.splitlines():
        if _is_comment_line(ln):
            continue
        m = _ECHO_STAGE_RE.match(ln)
        if not m:
            continue
        content, op, target = m.group(1), m.group(2), m.group(3).strip("\"'")
        if op == ">":
            stages[target] = [content]
        else:
            stages.setdefault(target, []).append(content)
    return {t: "\r\n".join(ls) for t, ls in stages.items()}

def written_stage_findings(name, data, local_basenames=()):
    """Wave 4, written-stage accounting. A batch file that writes
    a second script with echo redirection and runs it moves its
    behaviour into a file that is not in the submission: the
    stage exists only when the writer runs. The stage's content
    is nevertheless fully determined by the writer's own lines,
    so it is reconstructed here and judged with the same
    functions as a submitted file. A stage that fails its own
    accounting makes the writer unaccounted; a stage that is
    reconstructed and judged is returned in the judged set, so
    an invocation of it by name is an invocation of examined
    content, not of an absent file. Returns (findings,
    judged_basenames)."""
    base = os.path.basename(str(name).split("!")[-1]).lower()
    ext = os.path.splitext(base)[1]
    text = _decode_script_bytes(data)
    if ext == "":
        ext = _sniff_script_ext(text) or ext
    if ext not in _BATCH_DIALECT_EXTS:
        return [], set()
    stages = _echo_stages(_resolved_script_text(ext, text))
    findings, judged = [], set()
    for target, content in stages.items():
        tbase = os.path.basename(target.replace("\\", "/")).lower()
        text_ext = os.path.splitext(tbase)[1]
        stage_ext = text_ext if text_ext in SCRIPT_CLASS_EXTS else _sniff_script_ext(content)
        if stage_ext not in SCRIPT_CLASS_EXTS:
            continue
        judged.add(tbase)
        locals_ = set(local_basenames) | judged
        cdata = content.encode()
        inner = []
        for f in script_class_findings(tbase, cdata):
            inner.append(f["kind"])
        for f in proxy_invocation_findings(tbase, cdata, locals_):
            inner.append(f["kind"])
        refs, _complete, _note = external_references(tbase, cdata)
        for r in refs:
            d, _why = _reference_disposition(r, locals_)
            if d == "unresolved":
                inner.append("external-reference-unresolved")
        if inner:
            findings.append({"kind": "written-stage-unaccounted",
                             "evidence": [f"stage written by this file at runtime: {target}",
                                          "the stage's own accounting fails on: " + ", ".join(sorted(set(inner))),
                                          "the stage is not part of this submission; it exists only when this file runs, so its content was reconstructed from this file's write lines and judged as written"]})
    return findings, judged

# ------------------------------------------------------------------
# External references, interpreter proxies (accuracy fix wave 3,
# 2026-11-24). The closure rule from the deep research report
# event-zero-no-clean-for-remote-payload-20261124: a file may
# receive NO only if its behaviour set is closed under the evidence
# examined, meaning every reference the file makes to content
# outside itself resolves to content examined in this run or to a
# provably inert target. Wave 2 closed three named shapes; this
# wave implements the general rules behind them: R1 (the
# external-reference list itself, produced and resolved before any
# NO), R3 (engine incompleteness as a verdict-layer invariant,
# wired in the per-file loop below and in enumerate_subject), and
# R5 (interpreter-proxy invocation: a signed system binary's
# signature vouches for the binary, never for the data file that
# aims it at remote, encoded or unexamined content).
REF_ACTIVE_EXTS = EXEC_PAYLOAD_EXTS + (".zip", ".7z", ".rar", ".tar", ".gz", ".tgz",
                                       ".dot", ".dotm", ".xltm", ".potm", ".inf",
                                       ".reg", ".sct", ".application", ".appref-ms")
REF_PAGE_EXTS = (".htm", ".html", ".php", ".asp", ".aspx", ".jsp", ".cfm")
REF_DATA_EXTS = (".json", ".txt", ".xml", ".csv", ".md", ".log", ".ini", ".yaml", ".yml")
REF_IMAGE_EXTS = (".png", ".jpg", ".jpeg", ".gif", ".bmp", ".svg", ".webp", ".ico", ".tif", ".tiff")
PROTOCOL_URI_SCHEMES = ("search-ms", "ms-msdt")
_REF_URL_RE = re.compile(r"(?:https?|ftp)://[^\s\"'<>\)\]]+")
_REF_UNC_RE = re.compile(r"\\\\[A-Za-z0-9._\-]+\\[^\s\"'<>|]+")
_REF_PROTO_RE = re.compile(r"\b(?:search-ms|ms-msdt):[^\s\"'<>]+", re.I)
_CONCAT_RE = re.compile(r"""(["'])((?:(?!\1).)*)\1\s*[+&]\s*(["'])((?:(?!\3).)*)\3""")

def _is_comment_line(line):
    """A comment line in the script classes the verdict reads:
    batch rem and ::, shell, PowerShell and Python #, VBScript '.
    Mentions on comment lines are documentation, not invocation;
    wave 2's comment control established that boundary and wave 3
    keeps it for reference extraction and proxy invocation alike."""
    s = line.strip().lower()
    return (s == "rem" or s.startswith(("rem ", "rem\t", "::", "#", "'"))
            or s.startswith("<!--"))

def _deconcatenate(text):
    """Static-limit deobfuscation for reference extraction: remove
    PowerShell backtick escapes and collapse adjacent string
    literals joined by + or & ("http" + "://host/x.exe",
    "http" & "://host/x.exe") until no more collapse. This recovers
    references that split-string construction hides from literal
    scanning. It is deliberately narrow: it runs only over
    script-class carriers and only feeds reference extraction,
    never the accounting itself."""
    t = text.replace("`", "")
    for _ in range(8):
        n = _CONCAT_RE.sub(lambda m: m.group(1) + m.group(2) + m.group(4) + m.group(1), t)
        if n == t:
            break
        t = n
    return t

def _ref_url_parts(target):
    m = re.match(r"(?:https?|ftp)://([^/:\s]+)(?::\d+)?(/[^\s]*)?", target)
    if not m:
        return None, ""
    return m.group(1).lower(), (m.group(2) or "/").split("?")[0].split("#")[0].lower()

def _classify_ref_target(target):
    """Classify an external reference target by what a host program
    would do with it: protocol (a handler URI that fetches remote
    content by design), unc (a network path), local-file (a file:
    URI), local (a plain machine path), or for http(s)/ftp targets
    active (executable, script, template, package or configuration
    content), image, page, data, or other."""
    t = str(target).strip()
    low = t.lower()
    for scheme in PROTOCOL_URI_SCHEMES:
        if low.startswith(scheme + ":"):
            return "protocol"
    if t.startswith("\\\\"):
        return "unc"
    if low.startswith("file:"):
        return "local-file"
    host, path = _ref_url_parts(t)
    if host is not None:
        if path.endswith(REF_ACTIVE_EXTS):
            return "active"
        if path.endswith(REF_IMAGE_EXTS):
            return "image"
        if path.endswith(REF_PAGE_EXTS) or path in ("", "/"):
            return "page"
        if path.endswith(REF_DATA_EXTS):
            return "data"
        if "." not in path.rsplit("/", 1)[-1]:
            # an extensionless path is a page or an endpoint a
            # browser or client renders or reads as data; it names
            # no executable content by itself
            return "page"
        return "other"
    return "local"

_REL_TAG_RE = re.compile(r"<Relationship\b[^>]*>", re.I)

def _rels_references(xml_text, source):
    out = []
    for tag in _REL_TAG_RE.findall(xml_text):
        low = tag.lower()
        if "targetmode" not in low or "external" not in low:
            continue
        tm = re.search(r'Target\s*=\s*"([^"]+)"', tag) or re.search(r"Target\s*=\s*'([^']+)'", tag)
        ym = re.search(r'Type\s*=\s*"([^"]+)"', tag) or re.search(r"Type\s*=\s*'([^']+)'", tag)
        if tm:
            out.append({"kind": "ooxml-external-relationship", "target": tm.group(1),
                        "rel_type": (ym.group(1).rsplit("/", 1)[-1] if ym else ""),
                        "source": source})
    return out

def external_references(name, data):
    """The external-reference list for one file: every reference
    the file makes to content outside itself, taken from the
    structures this build already parses (OOXML relationship
    parts, shortcut fields, shortcut string carving, ClickOnce
    manifests, HTML resource references, script source). Returns
    (references, complete, note). Where a format's references
    cannot be enumerated by the current analyzers, complete is
    False and the note names the gap, rather than a new parser
    being built for it; the verdict records that as the cap
    reason where the file is not already capped on other grounds.
    Ordinary links in prose are not operative references and are
    not extracted, except protocol handler URIs, which are
    operative wherever they appear because a host program acts
    on them by design."""
    base = os.path.basename(str(name).split("!")[-1]).lower()
    ext = os.path.splitext(base)[1]
    if data[:4] == b"PK\x03\x04" and zipfile.is_zipfile(io.BytesIO(data)):
        refs = []
        try:
            with zipfile.ZipFile(io.BytesIO(data)) as z:
                for n in z.namelist():
                    if n.lower().endswith(".rels"):
                        refs.extend(_rels_references(z.read(n).decode("utf-8", "replace"),
                                                      f"relationship part {n}"))
        except Exception:
            pass
        if refs or ext in (".docx", ".xlsx", ".pptx", ".docm", ".xlsm", ".pptm", ".dotx", ".dotm"):
            return refs, True, "OOXML relationship parts enumerated from the package"
    if base.endswith(".rels"):
        return (_rels_references(data.decode("utf-8", "replace"), "relationship part"),
                True, "OOXML relationship part")
    if ext == ".msi" or data[:8] == b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1":
        return ([], False,
                "MSI table and custom-action targets are not enumerated by this build; "
                "the installer accounting caps this file on that basis")
    _cache = [None]
    def _text():
        if _cache[0] is None:
            # Wave 4: dialect-faithful decoding. The strict
            # UTF-8 decode this replaces returned "" on any
            # error, silently emptying the reference list of
            # any file with a byte outside UTF-8 (a cp1252
            # Italian lure line past the format heuristic's
            # 4 KB window was enough).
            _cache[0] = _decode_script_bytes(data)
        return _cache[0]
    if ext == "":
        # Wave 4: an extensionless file is routed by its
        # content's dialect signature, like every other
        # script treatment (see _sniff_script_ext).
        _sniffed = _sniff_script_ext(_text())
        if _sniffed:
            ext = _sniffed
    if ext == ".url":
        refs = []
        for line in _text().splitlines():
            s = line.strip()
            if s.lower().startswith("url="):
                refs.append({"kind": "shortcut-target", "target": s[4:].strip(),
                             "source": ".url URL field"})
            elif s.lower().startswith("iconfile="):
                refs.append({"kind": "shortcut-icon", "target": s[9:].strip(),
                             "source": ".url IconFile field"})
        return refs, True, "Internet Shortcut fields"
    if ext == ".scf":
        refs = []
        for line in _text().splitlines():
            s = line.strip()
            if s.lower().startswith("iconfile="):
                refs.append({"kind": "scf-icon", "target": s[9:].strip(),
                             "source": ".scf IconFile field"})
        return refs, True, "Shell Command File fields"
    if ext == ".lnk":
        lnk = parse_lnk(data)
        refs = [{"kind": "lnk-target", "target": u, "source": "shortcut strings"}
                for u in lnk["urls"]]
        for u in sorted(set(_REF_UNC_RE.findall(lnk["blob"]))):
            refs.append({"kind": "lnk-target", "target": u, "source": "shortcut strings"})
        return (refs, True,
                "shortcut reference fields recovered by string carving (the format "
                "stores its target, arguments and icon location as strings)")
    if ext in (".application", ".appref-ms"):
        refs = [{"kind": "clickonce-codebase", "target": t,
                 "source": "ClickOnce manifest codebase"}
                for t in re.findall(r'codebase\s*=\s*"([^"]+)"', _text(), re.I)]
        if ext == ".appref-ms":
            for u in _REF_URL_RE.findall(_text()):
                refs.append({"kind": "clickonce-codebase", "target": u,
                             "source": "ClickOnce shortcut target"})
        return refs, True, "ClickOnce manifest"
    if ext in (".htm", ".html", ".hta"):
        t = _text()
        refs = [{"kind": "html-resource", "target": u, "source": "script element source"}
                for u in re.findall(r"<script[^>]+src\s*=\s*[\"']?([^\s\"'>]+)", t, re.I)]
        refs += [{"kind": "html-resource", "target": u, "source": "meta refresh target"}
                 for u in re.findall(r"http-equiv\s*=\s*[\"']?refresh[\"']?[^>]*url\s*=\s*([^\s\"'>]+)", t, re.I)]
        refs += [{"kind": "protocol-uri", "target": u, "source": "protocol handler URI in markup"}
                 for u in sorted(set(_REF_PROTO_RE.findall(t)))]
        if ext == ".hta":
            # Wave 4: an HTA's script body is script source in
            # every sense the closure rule cares about (mshta
            # executes it on open), but this branch returned
            # before the script branch below, so URLs in the
            # body were never extracted as references at all:
            # the .hta was the one script class whose own URLs
            # were invisible to R1. They are extracted now, raw
            # and resolved, with the ordinary dispositions.
            seen = {r["target"] for r in refs}
            for cand in (t, _resolved_script_text(ext, t)):
                body = "\n".join(ln for ln in cand.splitlines()
                                 if not _is_comment_line(ln))
                for u in _REF_URL_RE.findall(body):
                    u = u.rstrip(".,;:")
                    if u not in seen:
                        seen.add(u)
                        refs.append({"kind": "script-url", "target": u,
                                     "source": "HTA script body"})
            return refs, True, "HTML resource references and HTA script body references"
        return refs, True, "HTML resource references"
    if ext in SCRIPT_CLASS_EXTS:
        # Wave 4: references are extracted from the raw source
        # and from the resolved source (variables substituted,
        # character codes decoded), because the dialect executes
        # the resolved text: a URL held in a variable, assembled
        # from fragments, or grown by a second assignment is a
        # reference the file makes, in the only form that matters.
        refs = []
        seen = set()
        for cand in (_deconcatenate(_text()), _resolved_script_text(ext, _text())):
            body = "\n".join(ln for ln in cand.splitlines()
                             if not _is_comment_line(ln))
            for u in _REF_URL_RE.findall(body):
                u = u.rstrip(".,;:")
                if u not in seen:
                    seen.add(u)
                    refs.append({"kind": "script-url", "target": u, "source": "script source"})
            for u in sorted(set(_REF_UNC_RE.findall(body))):
                if ("script-unc", u) not in seen:
                    seen.add(("script-unc", u))
                    refs.append({"kind": "script-unc", "target": u, "source": "script source"})
            for u in sorted(set(_REF_PROTO_RE.findall(body))):
                if ("protocol-uri", u) not in seen:
                    seen.add(("protocol-uri", u))
                    refs.append({"kind": "protocol-uri", "target": u, "source": "script source"})
        return (refs, True,
                "script source references, after static de-concatenation of "
                "split string literals and resolution of literal-valued variables")
    if ext in (".eml", ".txt", ".md", ".nfo"):
        refs = [{"kind": "protocol-uri", "target": u, "source": "protocol handler URI in text"}
                for u in sorted(set(_REF_PROTO_RE.findall(_text())))]
        return refs, True, "protocol handler URIs in text"
    return [], True, ""

def _reference_disposition(ref, entry_basenames):
    """Decide whether one external reference is resolved. Resolved
    means: examined (the referenced file is part of this submission
    and was judged in this run), inert (a target whose nature makes
    the reference itself the whole behaviour: a hyperlink to a page,
    a display-only image relationship, a local icon path), or
    remote-data (recorded, not capping: a reference no host fetches
    and executes automatically and whose target class could not be
    confirmed executable). Anything else is unresolved, and an
    unresolved reference to executable or active content caps the
    verdict under R1. Returns (disposition, basis)."""
    kind = ref["kind"]
    target = ref["target"]
    cls = _classify_ref_target(target)
    if kind == "ooxml-external-relationship":
        rt = (ref.get("rel_type") or "").lower()
        if rt == "attachedtemplate":
            return ("unresolved",
                    "a remote template is fetched and loaded by the host program when "
                    "the document opens; the template's content was not examined")
        if rt in ("oleobject", "package"):
            return ("unresolved",
                    "an external OLE object or package is fetched and acted on by the "
                    "host program; its content was not examined")
        if rt == "image":
            if cls == "image":
                return ("inert",
                        "an external image relationship over http(s): display-only "
                        "content the host renders as data; it cannot carry code or "
                        "credentials, so the fetch itself is the whole behaviour")
            return ("unresolved",
                    "an external image relationship to a non-http target can carry "
                    "forced authentication or local file access")
        if rt == "hyperlink":
            if cls in ("page", "image", "data"):
                return ("inert",
                        "a hyperlink to a page, image or data target: no host program "
                        "fetches and executes it automatically")
            return ("unresolved",
                    "a hyperlink to executable, package or handler content is not a "
                    "provably inert reference")
        if cls in ("active", "protocol", "unc"):
            return ("unresolved",
                    "the relationship target is executable, package or remote content "
                    "that was not examined")
        if cls in ("page", "image", "data"):
            return ("inert",
                    "the relationship target is a page, image or data target that no "
                    "host program executes automatically")
        return ("unresolved",
                "the relationship target's nature could not be classified as inert")
    if kind in ("shortcut-icon", "scf-icon"):
        if cls in ("unc", "protocol"):
            return ("unresolved",
                    "a remote icon reference makes the host contact a remote server, "
                    "and authenticate to it, when the file is merely displayed; the "
                    "remote content was not examined")
        if _ref_url_parts(target)[0] is not None:
            return ("unresolved",
                    "an icon loaded from a remote host is content fetched from "
                    "outside this file and was not examined")
        return ("inert",
                "a local icon path: the host loads a file already on the machine, "
                "which is outside this file's own behaviour")
    if kind == "clickonce-codebase":
        return ("unresolved",
                "a ClickOnce manifest is a subscription to code the runtime "
                "downloads at install time and on every update check; the current "
                "bytes at the target were not examined and can change under the "
                "same signed manifest")
    if kind == "protocol-uri":
        return ("unresolved",
                "a protocol handler URI makes a host program fetch remote content "
                "by design; that content was not examined")
    if kind == "office-remote-template":
        return ("unresolved",
                "the Office analyzer found a remote template reference; the "
                "template's content was not examined")
    if kind == "html-resource" and ref.get("source") == "script element source":
        if _ref_url_parts(target)[0] is not None or cls in ("unc", "protocol"):
            return ("unresolved",
                    "a remote script element is code the host fetches and runs; "
                    "it was not examined")
        # a local script element falls through to the generic
        # local-target resolution below
    elif kind == "html-resource":
        if cls in ("active", "protocol", "unc"):
            return ("unresolved",
                    "the refresh target is executable, package or remote content "
                    "that was not examined")
        return ("inert", "a refresh to a page target is a navigation, not an execution")
    if cls == "protocol":
        return ("unresolved",
                "a protocol handler URI makes a host program fetch remote content "
                "by design; that content was not examined")
    if cls == "active":
        return ("unresolved",
                "the target is executable, script, template, package or "
                "configuration content that was not examined in this run")
    if cls == "unc":
        if target.lower().rstrip("/\\").endswith(REF_ACTIVE_EXTS):
            return ("unresolved",
                    "the target is executable or package content on a network "
                    "path; it was not examined in this run")
        return ("remote-data",
                "a network path to data content: recorded as a reference; the "
                "content is not executed by the reference itself")
    if cls in ("local-file", "local"):
        bn = os.path.basename(str(target).replace("\\", "/")).lower()
        if bn and bn in entry_basenames:
            return ("resolved",
                    "the referenced file is part of this submission and was "
                    "examined in this run")
        if cls == "local":
            return ("remote-data",
                    "a path on the user's own machine: recorded as a reference; "
                    "machine-local content is outside the submission boundary")
        return ("unresolved",
                "the reference names a file outside this submission that was "
                "not examined")
    if cls in ("page", "image", "data"):
        return ("inert",
                "the target is a page, image or data target that no host program "
                "fetches and executes automatically")
    return ("remote-data",
            "the target's class could not be confirmed as executable or as "
            "inert; recorded as a reference without capping")

def _pdf_uri_targets(data):
    """Literal /URI action targets in a PDF, from the raw bytes the
    analyzer already decodes as latin-1. Targets inside compressed
    object streams are not enumerated by this build; that limit is
    recorded on the file's reference list, and the PDF features
    that execute (JavaScript, OpenAction, Launch, embedded files)
    are already verdict blockers in their own right."""
    txt = data.decode("latin1", "ignore")
    out = [m.group(1).strip() for m in re.finditer(r"/URI\s*\(([^)]{1,300})\)", txt)]
    for m in re.finditer(r"/URI\s*<([0-9A-Fa-f\s]{16,})>", txt):
        try:
            out.append(bytes.fromhex(re.sub(r"\s+", "", m.group(1))).decode("utf-8", "replace"))
        except Exception:
            pass
    return out

PROXY_BINARIES = ("mshta", "rundll32", "regsvr32", "msiexec", "wscript", "cscript",
                  "powershell", "pwsh", "msbuild", "bitsadmin", "certutil")
PROXY_EXECUTOR_BINARIES = {"mshta", "rundll32", "regsvr32", "msiexec", "wscript",
                           "cscript", "powershell", "pwsh", "msbuild"}
PROXY_TARGET_EXTS = (".ps1", ".vbs", ".vbe", ".js", ".jse", ".wsf", ".wsh", ".sct",
                     ".msi", ".hta", ".bat", ".cmd", ".inf", ".dll")
# Scripts that ship with the platform itself: slmgr.vbs is part of
# the Windows image (System32) and ospp.vbs ships with Microsoft
# Office. Invoking one by bare name aims the interpreter at content
# the platform image accounts for, the same basis on which system
# DLLs on system paths are exempt below, and it is the documented
# activation path the KMS baseline exists for: the engine's own
# false-positive twin (a KMS helper running cscript ospp.vbs) must
# keep its NO. The set is named and closed, never a pattern.
PLATFORM_SCRIPTS = {"slmgr.vbs", "ospp.vbs"}
_B64_TOKEN_RE = re.compile(r"[A-Za-z0-9+/]{40,}={0,2}")

def proxy_invocation_findings(name, data, local_basenames=()):
    """R5, interpreter-proxy invocation: a file that aims a signed
    system proxy or interpreter (mshta, rundll32, regsvr32, msiexec,
    wscript, cscript, powershell, msbuild, bitsadmin, certutil) at
    content that is remote, encoded, or not itself accounted in
    this run. The proxy's own signature is never entered as
    accounting for the invoking file: it vouches for the proxy's
    publisher, not for the data file's instructions. Scope is
    invocation evidence only: a proxy named on a non-comment line
    together with its operative argument. A mere mention (a
    comment, a sentence in an echo) carries no argument of the
    capped classes and does not fire. Download-only proxies
    (bitsadmin, certutil) fire on remote content only when the
    fetched target is itself executable-class, because their
    download shape is wave 2's fetch atom: the chain there needs
    an execution side, while here the staged executable is the
    unaccounted content. System library DLLs on system paths are
    the proxy's normal library surface and do not fire; a DLL in a
    user-writable or relative location does."""
    base = os.path.basename(str(name).split("!")[-1]).lower()
    ext = os.path.splitext(base)[1]
    if ext == ".lnk":
        lines = [" ".join(parse_lnk(data)["strings"])]
    elif ext in SCRIPT_CLASS_EXTS or ext == "":
        text = _decode_script_bytes(data)
        if "\x00" in text[:2000]:
            return []
        if ext == "":
            ext = _sniff_script_ext(text)
            if ext not in SCRIPT_CLASS_EXTS:
                return []
        # Wave 4: the invocation is scanned in the raw lines and
        # in the resolved lines (variable substitution applied),
        # because the proxy is aimed by the resolved text: a
        # wscript invocation of a variable-held path names its
        # target only after substitution.
        lines = [ln for ln in text.splitlines() if not _is_comment_line(ln)]
        lines += [ln for ln in _resolved_script_text(ext, text).splitlines()
                  if not _is_comment_line(ln)]
    else:
        return []
    out = []
    seen_ev = set()
    for line in lines:
        low = line.lower()
        proxies = [p for p in PROXY_BINARIES
                   if re.search(r"\b" + p + r"(?:\.exe)?\b", low)]
        if not proxies:
            continue
        ev = []
        m = _REF_URL_RE.search(line) or _REF_UNC_RE.search(line)
        remote_target = m.group(0) if m else ("file://" if "file://" in low else None)
        if remote_target:
            cls = _classify_ref_target(remote_target)
            for p in proxies:
                if p in PROXY_EXECUTOR_BINARIES or cls == "active":
                    ev.append(f"{p} invoked on remote content: {remote_target}")
                    break
        if (re.search(r"-enc\b|encodedcommand|frombase64string", low)
                or "javascript:" in low or "vbscript:" in low):
            ev.append(f"{proxies[0]} invoked on encoded or script-URI content: "
                      "the invoked content is not in this file in readable form "
                      "and was not accounted")
        else:
            bm = _B64_TOKEN_RE.search(line)
            if bm and any(p in PROXY_EXECUTOR_BINARIES for p in proxies):
                ev.append(f"{proxies[0]} invoked with a long base64 argument "
                          f"({len(bm.group(0))} characters): the invoked content "
                          "is encoded and was not decoded or accounted in this run")
        for tok in re.findall(r"[^\s\"'<>]+", line):
            t = tok.rstrip(".,;:").lower()
            if not t.endswith(PROXY_TARGET_EXTS):
                continue
            bn = os.path.basename(t.replace("\\", "/"))
            if bn in local_basenames or bn in PLATFORM_SCRIPTS:
                continue
            if t.endswith(".dll") and ("system32" in t or "syswow64" in t
                                       or "\\windows\\" in t):
                continue
            ev.append(f"{proxies[0]} invoked on a file that is not part of this "
                      f"submission and was not examined: {tok}")
            break
        if ev:
            key = tuple(ev)
            if key not in seen_ev:
                seen_ev.add(key)
                out.append({"kind": "interpreter-proxy-invocation", "evidence": ev})
    return out

def parse_lnk(data):
    """Parse a Windows .lnk as pure bytes. Never via a shell, never
    executed. Returns {strings, target_guess, lolbin, cradle, urls}."""
    strs = []
    try:
        strs.extend(s.decode("ascii", "ignore") for s in re.findall(rb"[\x20-\x7e]{4,}", data))
    except Exception:
        pass
    try:
        strs.extend(s.decode("utf-16-le", "ignore") for s in re.findall(rb"(?:[\x20-\x7e]\x00){4,}", data))
    except Exception:
        pass
    blob = "\n".join(strs)
    low = blob.lower()
    lolbin = [b for b in LOLBINS if b in low]
    cradle = [c for c in DOWNLOAD_CRADLE if c in low]
    urls = re.findall(r"https?://[^\s\"'<>]+", blob)
    return {"strings": strs[:50], "lolbin": lolbin, "cradle": cradle, "urls": urls, "blob": blob[:2000]}

def bdecode(data, i=0):
    c = data[i:i + 1]
    if c == b"i":
        j = data.index(b"e", i)
        return int(data[i + 1:j]), j + 1
    if c == b"l":
        out = []; i += 1
        while data[i:i + 1] != b"e":
            v, i = bdecode(data, i); out.append(v)
        return out, i + 1
    if c == b"d":
        out = {}; i += 1
        while data[i:i + 1] != b"e":
            k, i = bdecode(data, i); v, i = bdecode(data, i); out[k] = v
        return out, i + 1
    j = data.index(b":", i)
    n = int(data[i:j])
    return data[j + 1:j + 1 + n], j + 1 + n

def parse_torrent(data):
    """Parse a .torrent locally with a bencode reader. Event Zero never
    joins a swarm, never announces, never fetches metadata from peers:
    joining would expose the user's IP to the swarm."""
    out = {"trackers": [], "web_seeds": [], "files": [], "parsed": False}
    try:
        meta, _ = bdecode(data)
        if not isinstance(meta, dict):
            return out
        out["parsed"] = True
        def dec(x):
            return x.decode("utf-8", "replace") if isinstance(x, bytes) else x
        if b"announce" in meta:
            out["trackers"].append(dec(meta[b"announce"]))
        for tier in meta.get(b"announce-list", []) or []:
            if isinstance(tier, list):
                out["trackers"].extend(dec(t) for t in tier)
            elif isinstance(tier, bytes):
                out["trackers"].append(dec(tier))
        for u in meta.get(b"url-list", []) or []:
            if isinstance(u, bytes):
                out["web_seeds"].append(dec(u))
            elif isinstance(u, list):
                out["web_seeds"].extend(dec(x) for x in u if isinstance(x, bytes))
        info = meta.get(b"info", {})
        if isinstance(info, dict):
            if b"files" in info:
                for f in info[b"files"]:
                    parts = [dec(p) for p in f.get(b"path", [])]
                    out["files"].append("/".join(parts))
            elif b"name" in info:
                out["files"].append(dec(info[b"name"]))
    except Exception:
        pass
    out["trackers"] = sorted(set(out["trackers"]))
    out["web_seeds"] = sorted(set(out["web_seeds"]))
    return out

EFFECT_MAP = [
    ("net-connect", "network", "connects out to a remote host"),
    ("net-http", "network", "makes web requests"),
    ("net-listen", "network", "listens for incoming connections"),
    ("net-socket", "network", "opens network sockets"),
    ("exec-shell", "process", "runs shell commands"),
    ("exec-download-run", "network", "downloads and runs remote code"),
    ("file-write", "files", "writes files to disk"),
    ("file-delete", "files", "deletes files"),
    ("persist-runkey", "persistence", "adds a registry Run key"),
    ("persist-file", "persistence", "writes a persistence script or autostart file"),
    ("persist-schtask", "persistence", "creates a scheduled task"),
    ("persistence-service", "persistence", "installs a service"),
    ("inject-process", "process", "injects code into another process"),
    ("cred-access", "collection", "accesses credential stores"),
    ("keylog", "collection", "captures keystrokes"),
    ("mining", "system", "mines cryptocurrency"),
    ("anti-debug", "defence-evasion", "checks for a debugger or analysis tools"),
]
def predicted_effects(report):
    caps = {c["id"] for c in report.get("capabilities", [])}
    out = []
    for cid, cat, effect in EFFECT_MAP:
        if cid in caps:
            out.append({"category": cat, "effect": effect, "basis": f"capability {cid}", "provenance": "static-predicted"})
    for f in report.get("evasion", {}).get("findings", []):
        out.append({"category": "defence-evasion", "effect": f["name"], "basis": f"evasion finding {f['id']}", "provenance": "static-predicted"})
    return out

def build_manifest_jsonl(v):
    """The folder manifest as JSON Lines: header, one entry record per
    file with its container parent chain, footer with the tree hash.
    Verdict inheritance is exact: any PROVEN entry makes the folder
    YES-PROVEN, else any UNACCOUNTED entry makes it YES-UNACCOUNTED,
    else NO."""
    import datetime
    lines = []
    header = {"type": "header", "schema": "eventzero.manifest/1", "root_name": os.path.basename(str(v["subject"]).rstrip("/")) or str(v["subject"]),
              "created": datetime.datetime.now(datetime.timezone.utc).isoformat(), "scanner": f"Event Zero {v['version']}",
              "cache_used": False, "limits": {"max_depth": 3, "max_entries_per_container": MAX_MEMBERS, "max_total_extracted_bytes": MAX_TOTAL_BYTES}}
    lines.append(json.dumps(header))
    ids = {}
    entries = []
    for i, f in enumerate(v["files"], 1):
        eid = f"e{i:06d}"
        ids[f["path_in_release"]] = eid
        entries.append((eid, f))
    def parent_of(f):
        p = f["path_in_release"]
        if "!" in p:
            parent_path = p.rsplit("!", 1)[0]
            if parent_path in ids:
                return ids[parent_path]
            for cand, cid in ids.items():
                if p.startswith(cand + "!"):
                    return cid
        return None
    total_bytes = 0
    for eid, f in entries:
        total_bytes += f["size_bytes"]
        coverage = "full" if f["verdict"] in ("NO: ACCOUNTED", "YES: MALWARE (PROVEN)") else "partial"
        rec = {"type": "entry", "id": eid, "parent_id": parent_of(f), "path": f["path_in_release"],
               "kind": "archive-member" if f["origin"] == "archive" else "file",
               "size": f["size_bytes"], "sha256": f["sha256"],
               "streams": [{"name": "$DATA", "size": f["size_bytes"], "sha256": f["sha256"]}] + f.get("extra_streams", []),
               "magic": f.get("format"), "exec": (f.get("format") in ("PE", "ELF", "Mach-O", "script")),
               "signature": {"status": "valid" if f.get("signature_valid") else "present-unverified" if f.get("signed") else "unsigned" if f.get("signed") is not None else "n/a"},
               "coverage": coverage, "verdict": f["verdict"], "tags": f.get("chains", [])}
        lines.append(json.dumps(rec))
    tree = hashlib.sha256("".join(sorted(f["sha256"] for _, f in entries)).encode()).hexdigest()
    footer = {"type": "footer", "entries": len(entries), "bytes": total_bytes, "tree_sha256": tree,
              "verdict": v["verdict"], "reason_class": v.get("reason_class"),
              "proof_entries": [eid for eid, f in entries if f["verdict"].startswith("YES: MALWARE")],
              "unaccounted_entries": [eid for eid, f in entries if f["verdict"] == "YES: UNACCOUNTED"]}
    lines.append(json.dumps(footer))
    return "\n".join(lines) + "\n", tree


# ---------------------------------------------------------------- helpers
def pe_signature(data):
    """Return (signed, valid). valid is True/False only when a real
    verifier (osslsigncode) is installed; otherwise None: present but
    not verified here, which is stated, never guessed."""
    if data[:2] != b"MZ":
        return (None, None)
    try:
        peoff = struct.unpack("<I", data[0x3c:0x40])[0]
        magic = struct.unpack("<H", data[peoff + 24:peoff + 26])[0]
        dd_base = peoff + 24 + (112 if magic == 0x20b else 96)
        cert_off, cert_size = struct.unpack("<II", data[dd_base + 4 * 8:dd_base + 4 * 8 + 8])
    except Exception:
        return (None, None)
    if not cert_off or cert_size <= 8:
        return (False, None)
    tool = shutil.which("osslsigncode")
    if not tool:
        return (True, None)
    try:
        with tempfile.NamedTemporaryFile(delete=False, suffix=".exe") as t:
            t.write(data); path = t.name
        r = subprocess.run([tool, "verify", "-in", path], capture_output=True, timeout=60)
        os.unlink(path)
        return (True, r.returncode == 0)
    except Exception:
        return (True, None)


def find_patch_evidence(data, report):
    """Collect patch-like signals in a single binary with no reference:
    patched-out code (a run of NOP bytes where a check used to be, in
    a code-bearing file) and crack or license markers in the file's
    own strings. Returns a list of findings. These signals ANNOTATE a
    report only: a NOP run is also ordinary alignment padding, and a
    license string appears in every licensed program, so neither is
    an accounting. A compiled binary with no reference and no
    verifying signature is unaccounted by definition, however many of
    these signals it carries (2026-11-24 accuracy audit, defect 1)."""
    out = []
    fmt = (report.get("format") or {}).get("format", "")
    if fmt in ("PE", "ELF", "Mach-O"):
        for m in re.finditer(rb"\x90{5,}", data):
            out.append({"kind": "patched-out-code",
                        "offset": m.start(), "offset_hex": hex(m.start()),
                        "detail": f"{len(m.group(0))} NOP bytes in a row at offset {hex(m.start())}: a run of no-operation bytes where working code used to be, the classic shape of a check that was patched out so it can never fail"})
    low_strings = [s for s in report.get("strings", {}).get("all", [])]
    for s in low_strings:
        sl = s.lower()
        if any(w in sl for w in LICENSE_WORDS) or "cracked" in sl or "crack" in sl:
            out.append({"kind": "license-or-crack-marker", "string": s[:160],
                        "detail": f"The file itself names the thing that was patched: '{s[:120]}'"})
    return out[:20]


def is_keygen_like(name, report):
    n = name.lower()
    blob = "\n".join(report.get("strings", {}).get("all", [])).lower()
    return ("keygen" in n or "keygen" in blob or "key generator" in blob
            or ("serial" in blob and "generate" in blob))


def keygen_behaviour(report):
    """For a keygen or patcher: list the behaviours beyond generating
    keys. An empty list means it only generates keys."""
    caps = {c["id"] for c in report.get("capabilities", [])}
    bad = []
    mapping = [(NET_CAPS, "network access"), (PERSIST_CAPS, "persistence"),
               ({"inject-process"}, "process injection"), ({"exec-download-run"}, "downloading and running code"),
               ({"exec-shell"}, "running shell commands"), (STEAL_CAPS, "touching credentials or user input")]
    for ids, label in mapping:
        hit = sorted(caps & ids)
        if hit:
            bad.append({"behaviour": label, "capability_ids": hit})
    ev_ids = {f["id"] for f in report.get("evasion", {}).get("findings", [])}
    if "inject-chain" in ev_ids:
        bad.append({"behaviour": "process injection chain", "capability_ids": ["inject-chain"]})
    return bad


CONTAINER_SUFFIX_KIND = ((".tar.gz", "tar"), (".tar.bz2", "tar"), (".tar.xz", "tar"),
                         (".tgz", "tar"), (".tbz2", "tar"), (".txz", "tar"),
                         (".zip", "zip"), (".tar", "tar"), (".7z", "7z"),
                         (".rar", "rar"), (".cab", "cab"))
# Container kinds this build has no parser for. A container of one of
# these kinds cannot be enumerated at all here, so it is unaccounted
# by construction, never plain data.
UNSUPPORTED_CONTAINER_KINDS = {"7z", "rar", "cab"}

def container_kind(path, data):
    """Detect a container by content first, then by declared name.
    Content detection deliberately does NOT require the container to
    parse: a truncated zip still begins with a zip local-file header,
    and a container that cannot be enumerated is exactly the case that
    must fall to unaccounted. The previous detection used
    zipfile.is_zipfile, which answers False for a truncated zip (the
    end-of-central-directory record is gone), so truncated archives
    were waved through as ordinary data files and could be certified
    NO. That fail-open shape is what this function exists to close."""
    if zipfile.is_zipfile(io.BytesIO(data)):
        return "zip"
    if data[:4] in (b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08"):
        return "zip"
    # Coverage wave 1 kinds are detected before tar on purpose:
    # tarfile.is_tarfile answers True for any file whose first block
    # is zeros (an ISO 9660 image opens with sixteen zero sectors),
    # so a disk image would otherwise be claimed as an empty tar
    # and its interior never enumerated.
    extra = detect_extra_kind(path, data)
    if extra:
        return extra
    try:
        if tarfile.is_tarfile(path):
            return "tar"
    except Exception:
        pass
    if len(data) > 262 and data[257:262] == b"ustar":
        return "tar"
    if data[:6] == b"7z\xbc\xaf'\x1c":
        return "7z"
    if data[:7] == b"Rar!\x1a\x07\x00" or data[:8] == b"Rar!\x1a\x07\x01\x00":
        return "rar"
    if data[:4] == b"MSCF":
        return "cab"
    name = str(path).lower()
    for suf, kind in CONTAINER_SUFFIX_KIND:
        if name.endswith(suf):
            return kind
    return None

def is_archive(path, data):
    kind = container_kind(path, data)
    return kind if kind in ("zip", "tar") else None


def installer_kind(name, data):
    n = name.lower()
    if data[:8] == b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" or n.endswith(".msi"):
        return "MSI installer"
    blob = data[:2000000]
    for marker, kind in [(b"Inno Setup", "Inno Setup installer"), (b"Nullsoft", "NSIS installer"),
                         (b"InstallShield", "InstallShield installer"), (b"7zS.sfx", "7-Zip self-extracting archive")]:
        if marker in blob:
            return kind
    if n.endswith((".exe", ".com")) and any(w in n for w in ("setup", "install")):
        return "executable installer (type not identified)"
    return None


def _safe_extract_zip(zf, dest):
    """Extract a zip, failing loudly on anything that prevents full
    enumeration. Every failure raises, and the caller turns the raise
    into an unaccounted blocker: a partially enumerated archive is
    never a complete ledger. Failures raised here include a member
    count past the enumeration cap (previously the member list was
    silently truncated at the cap), an encrypted member, an
    unsupported compression method, a CRC failure, and a member whose
    extracted bytes do not match its declared size (truncation)."""
    infos = zf.infolist()
    if len(infos) > MAX_MEMBERS:
        raise ValueError(f"archive has {len(infos)} members, past the enumeration limit of {MAX_MEMBERS}: the members past the limit cannot be enumerated, so this archive is unaccounted")
    names = []
    total = 0
    for info in infos:
        total += info.file_size
        if total > MAX_TOTAL_BYTES:
            raise ValueError("archive expands past the size limit")
        target = os.path.realpath(os.path.join(dest, info.filename))
        if not target.startswith(os.path.realpath(dest) + os.sep):
            raise ValueError(f"archive member escapes the extraction folder: {info.filename}")
        if info.is_dir():
            continue
        os.makedirs(os.path.dirname(target), exist_ok=True)
        written = 0
        with zf.open(info) as src, open(target, "wb") as out:
            while True:
                chunk = src.read(65536)
                if not chunk:
                    break
                written += len(chunk)
                out.write(chunk)
        if written != info.file_size:
            raise ValueError(f"archive member {info.filename} extracted {written} of {info.file_size} declared bytes: the member is truncated, so this archive cannot be fully enumerated")
        names.append(info.filename)
    return names


def _safe_extract_tar(tf, dest):
    """Extract a tar with the same fail-closed contract as the zip
    path: member count past the cap raises instead of silently
    truncating the member list, a member that is not a regular file
    or directory (symlink, hardlink, device, fifo) raises instead of
    being silently skipped, an unreadable member raises, and a member
    whose extracted bytes do not match its declared size raises."""
    members = tf.getmembers()
    if len(members) > MAX_MEMBERS:
        raise ValueError(f"archive has {len(members)} members, past the enumeration limit of {MAX_MEMBERS}: the members past the limit cannot be enumerated, so this archive is unaccounted")
    names = []
    total = 0
    for m in members:
        total += max(m.size, 0)
        if total > MAX_TOTAL_BYTES:
            raise ValueError("archive expands past the size limit")
        if m.isdir():
            continue
        if not m.isfile():
            raise ValueError(f"archive member {m.name} is not a regular file (tar type {m.type!r}): its contents cannot be enumerated as a file, so this archive is unaccounted")
        target = os.path.realpath(os.path.join(dest, m.name))
        if not target.startswith(os.path.realpath(dest) + os.sep):
            raise ValueError(f"archive member escapes the extraction folder: {m.name}")
        os.makedirs(os.path.dirname(target), exist_ok=True)
        src = tf.extractfile(m)
        if src is None:
            raise ValueError(f"archive member {m.name} could not be read, so this archive cannot be fully enumerated")
        written = 0
        with src, open(target, "wb") as out:
            while True:
                chunk = src.read(65536)
                if not chunk:
                    break
                written += len(chunk)
                out.write(chunk)
        if written != m.size:
            raise ValueError(f"archive member {m.name} extracted {written} of {m.size} declared bytes: the member is truncated, so this archive cannot be fully enumerated")
        names.append(m.name)
    return names


def enumerate_subject(path, workdir):
    """Return (entries, installer_info, blockers, unexpanded,
    failed_containers, expanded_containers, entry_blockers).
    entries: [{rel, abspath, origin}] with origin in file/dir/archive/installer.
    Nested archives are expanded up to depth 3 and also listed.
    failed_containers holds the rel path of every detected container
    whose full contents could not be enumerated (corrupt, truncated,
    encrypted, unsupported kind or compression, cap hit): each one is
    an unaccounted unit by construction. expanded_containers holds the
    rel path of every container that was fully enumerated, so the
    verdict can judge its members as the content units and not
    re-judge the container's own raw bytes as if they were code.
    entry_blockers maps a rel path to blocker text that belongs to
    that file's own record (an installer subject, an installer file
    inside a folder): the per-file table is the accounting, so a
    blocker that decides a file's verdict must be attached to the
    file, not only to the release-level list."""
    entries = []
    blockers = []
    unexpanded = []
    failed_containers = []
    expanded_containers = []
    entry_blockers = {}
    installer = {"is_installer_or_archive": False, "kind": None, "contents": [], "drop_list": [], "extracted": False}

    def add_tree(base, origin, prefix=""):
        for root, _dirs, files in os.walk(base):
            for fn in sorted(files):
                ap = os.path.join(root, fn)
                rel = os.path.relpath(ap, base)
                entries.append({"rel": (prefix + rel).replace(os.sep, "/"), "abspath": ap, "origin": origin})

    def expand_email(ap, rel, origin, depth):
        """Enumerate an email file's attachments as entries, exactly
        like archive members: an attachment that is never listed is
        never judged, and email is the most common delivery route
        there is (2026-11-24 accuracy audit, defect 5). The email
        file itself stays a content entry and is judged as well."""
        try:
            with open(ap, "rb") as f:
                data = f.read()
        except Exception:
            return
        head = data[:4096].lstrip().lower()
        if not (head.startswith((b"from:", b"from ", b"subject:", b"return-path:", b"received:", b"mime-version:", b"content-type:"))
                or str(ap).lower().endswith(".eml")):
            return
        try:
            from email import policy as _email_policy
            from email.parser import BytesParser as _BytesParser
            msg = _BytesParser(policy=_email_policy.default).parsebytes(data)
            atts = []
            skipped = []
            for part in msg.walk():
                if part.get_content_disposition() == "attachment":
                    payload = part.get_payload(decode=True)
                    if payload is None:
                        skipped.append(part.get_filename() or "attachment")
                    else:
                        atts.append((part.get_filename() or "attachment", payload))
        except Exception as ex:
            # A message that looked like email but could not be
            # parsed has attachments nobody enumerated: that is an
            # engine-incompleteness cap (wave 3, R3), recorded on the
            # message's own record, never a silent return.
            entry_blockers.setdefault(rel, []).append(
                f"{rel}: this email file could not be parsed ({ex}), so its attachments could not be enumerated. An email whose attachments were never listed is an unaccounted unit and blocks any NO. Next step: open the message with a mail parser and run the verdict on the extracted attachments.")
            return
        for fn in skipped:
            entry_blockers.setdefault(rel, []).append(
                f"{rel}: email attachment {fn} could not be decoded, so it was not enumerated or judged. An unenumerated attachment is unaccounted and blocks any NO. Next step: extract the attachment with a mail tool and run the verdict on it.")
        if not atts:
            return
        dest = os.path.join(workdir, f"extract_email_{hashlib.sha256(rel.encode('utf-8')).hexdigest()[:16]}")
        os.makedirs(dest, exist_ok=True)
        for i, (fn, payload) in enumerate(atts):
            safe = os.path.basename(str(fn).replace("\\", "/")) or f"attachment_{i}"
            target = os.path.join(dest, f"{i}_{safe}")
            with open(target, "wb") as out:
                out.write(payload)
            arel = rel + "!" + safe
            entries.append({"rel": arel, "abspath": target, "origin": "archive"})
            if depth < 3:
                expand(target, arel, "archive", depth + 1)

    def _register_members(dest, rel, origin, depth, before_mark=None):
        """Shared tail of every container expansion: record the
        extracted members as entries, note them in the installer
        contents ledger, and recurse into nested containers."""
        expanded_containers.append(rel)
        installer["is_installer_or_archive"] = True
        installer["extracted"] = True
        before = len(entries)
        add_tree(dest, "archive", prefix=rel + "!")
        for e in list(entries[before:]):
            installer["contents"].append(e["rel"])
            installer["drop_list"].append(e["rel"])
        if depth < 3:
            for e in list(entries[before:]):
                expand(e["abspath"], e["rel"], "archive", depth + 1)
        else:
            for e in list(entries[before:]):
                try:
                    with open(e["abspath"], "rb") as fh:
                        edata = fh.read()
                    if container_kind(e["abspath"], edata) is not None:
                        unexpanded.append(e["rel"])
                except Exception:
                    pass
        return True

    def expand_extra(ap, rel, origin, depth, data, kind):
        """Coverage wave 1 containers (disk images, virtual disks,
        firmware filesystems standing alone, OS packages): the same
        contract as zip and tar. Full enumeration registers the
        members as verdict units; any failure is a failed container,
        unaccounted by construction, never judged from raw bytes."""
        installer["is_installer_or_archive"] = True
        installer["kind"] = installer["kind"] or f"{kind} container"
        dest = os.path.join(workdir, f"extract_{depth}_{hashlib.sha256(rel.encode('utf-8')).hexdigest()[:16]}")
        os.makedirs(dest, exist_ok=True)
        try:
            _extract_extra_to(data, kind, dest)
        except Exception as e:
            blockers.append(f"Container {rel} ({kind}) could not be fully enumerated: {e}. Its contents are unaccounted, so no NO verdict can cover them.")
            failed_containers.append(rel)
            return True
        return _register_members(dest, rel, origin, depth)

    def expand_firmware(ap, rel, data, depth):
        """Firmware images: filesystem regions (SquashFS, CRAMFS,
        JFFS2, UBI) are extracted as members and carved PE images
        (DXE, PEI and SMM drivers) are re-submitted as entries with
        verdicts of their own. A region this build cannot extract
        is named on the firmware unit's own record as a failed
        container: unaccounted, never silently inert."""
        regions = firmware_regions(data)
        has_fv = b"_FVH" in data
        if not regions and not has_fv:
            return False
        dest = os.path.join(workdir, f"extract_fw_{hashlib.sha256(rel.encode('utf-8')).hexdigest()[:16]}")
        os.makedirs(dest, exist_ok=True)
        wrote = False
        failures = []
        if has_fv:
            for off, blob in carve_pe_images(data):
                target = os.path.join(dest, f"dxe_{off}.efi")
                with open(target, "wb") as out:
                    out.write(blob)
                wrote = True
        ordered = sorted(regions, key=lambda r: r["offset"])
        for idx, r in enumerate(ordered):
            start = r["offset"]
            if r["length"]:
                end = start + r["length"]
            elif idx + 1 < len(ordered):
                end = ordered[idx + 1]["offset"]
            else:
                end = len(data)
            blob = data[start:end]
            sub = os.path.join(dest, f"fs{idx}_{r['kind']}")
            os.makedirs(sub, exist_ok=True)
            try:
                _extract_extra_to(blob, r["kind"], sub)
                wrote = True
            except Exception as e:
                failures.append(f"{rel}: the {r['label']} at offset {start} could not be extracted: {e}. That filesystem interior is unenumerated and unaccounted, and it blocks any NO for this firmware image. Next step: extract that filesystem region with a firmware tool (unsquashfs, unblob, or a UBIFS reader) and run the verdict on the extracted folder.")
        if failures:
            for f in failures:
                entry_blockers.setdefault(rel, []).append(f)
            failed_containers.append(rel)
            if wrote:
                before = len(entries)
                add_tree(dest, "archive", prefix=rel + "!")
                if depth < 3:
                    for e in list(entries[before:]):
                        expand(e["abspath"], e["rel"], "archive", depth + 1)
            return True
        if wrote:
            return _register_members(dest, rel, "archive", depth)
        return False

    def expand_macho_fat(ap, rel, origin, depth, data):
        """Fat Mach-O binaries (coverage wave 2): each architecture
        slice is cut out and registered as an entry of its own, so
        every slice is analysed and verdicted as its own unit, the
        same contract the firmware expander gives carved PE images.
        A slice that cannot be cut (declared out of bounds or
        truncated) fails the bundle by name: the bundle is a failed
        container and no slice accounting can cover it."""
        slices, err = split_macho_fat(data)
        if slices is None and err is None:
            return False
        if err:
            blockers.append(f"Container {rel} (fat Mach-O) could not be fully enumerated: {err}. Its slices are unaccounted, so no NO verdict can cover them.")
            failed_containers.append(rel)
            return True
        dest = os.path.join(workdir, f"extract_fat_{hashlib.sha256(rel.encode('utf-8')).hexdigest()[:16]}")
        os.makedirs(dest, exist_ok=True)
        for s in slices:
            target = os.path.join(dest, f"slice_{s['arch']}")
            with open(target, "wb") as out:
                out.write(s["data"])
        return _register_members(dest, rel, "archive", depth)

    def expand(ap, rel, origin, depth):
        with open(ap, "rb") as f:
            data = f.read()
        kind = container_kind(ap, data)
        if kind is None:
            expand_email(ap, rel, origin, depth)
            if expand_macho_fat(ap, rel, origin, depth, data):
                return True
            return expand_firmware(ap, rel, data, depth)
        if kind in EXTRA_CONTAINER_KINDS:
            return expand_extra(ap, rel, origin, depth, data, kind)
        installer["is_installer_or_archive"] = True
        installer["kind"] = installer["kind"] or f"{kind} archive"
        if kind in UNSUPPORTED_CONTAINER_KINDS:
            blockers.append(f"Archive {rel} is a {kind} container, and this build has no parser that can enumerate {kind} containers. Its contents cannot be enumerated, so they are unaccounted and no NO verdict can cover them. Next step: open it with a {kind} parser and run the verdict on the extracted folder.")
            failed_containers.append(rel)
            return True
        # Deterministic, collision-free extraction directory: the
        # SHA-256 of the archive's release path plus the depth. The
        # previous name used Python's hash() of the path, which is
        # randomised per process (the same archive extracted to a
        # different directory on every run) and had only 99,999
        # buckets (two archives in one release could collide into
        # one directory and be judged on each other's bytes).
        dest = os.path.join(workdir, f"extract_{depth}_{hashlib.sha256(rel.encode('utf-8')).hexdigest()[:16]}")
        os.makedirs(dest, exist_ok=True)
        try:
            if kind == "zip":
                with zipfile.ZipFile(ap) as zf:
                    names = _safe_extract_zip(zf, dest)
            else:
                with tarfile.open(ap) as tf:
                    names = _safe_extract_tar(tf, dest)
        except Exception as e:
            blockers.append(f"Archive {rel} could not be fully enumerated: {e}. Its contents are unaccounted, so no NO verdict can cover them.")
            failed_containers.append(rel)
            return True
        expanded_containers.append(rel)
        installer["extracted"] = True
        for n in names:
            installer["contents"].append((rel + "!" + n) if origin != "file" else n)
            installer["drop_list"].append((rel + "!" + n) if origin != "file" else n)
        before = len(entries)
        add_tree(dest, "archive", prefix=rel + "!")
        if depth < 3:
            for e in list(entries[before:]):
                expand(e["abspath"], e["rel"], "archive", depth + 1)
        else:
            # depth limit hit: any archive at this depth stays unopened,
            # and an unopened layer is UNACCOUNTED, never clean
            for e in list(entries[before:]):
                try:
                    with open(e["abspath"], "rb") as fh:
                        edata = fh.read()
                    if container_kind(e["abspath"], edata) is not None:
                        unexpanded.append(e["rel"])
                except Exception:
                    pass
        return True

    if os.path.isdir(path):
        add_tree(path, "dir")
        for e in list(entries):
            expand(e["abspath"], e["rel"], "dir", 0)
    elif os.path.isfile(path):
        with open(path, "rb") as f:
            data = f.read()
        ik = installer_kind(path, data)
        if container_kind(path, data):
            entries.append({"rel": os.path.basename(path), "abspath": path, "origin": "installer"})
            expand(path, os.path.basename(path), "file", 0)
            installer["kind"] = ik or installer["kind"]
        elif ik:
            installer["is_installer_or_archive"] = True
            installer["kind"] = ik
            entries.append({"rel": os.path.basename(path), "abspath": path, "origin": "installer"})
            tool = shutil.which("innoextract") if "Inno" in ik else shutil.which("7z") if "NSIS" in ik or "7-Zip" in ik else shutil.which("msiextract") if "MSI" in ik else None
            if tool:
                msg = f"Installer {os.path.basename(path)} ({ik}): the parser adapter {tool} is present as a handoff, but this build reads installers with parsers only and the adapter step was not run, so the files this installer would drop are unaccounted. Next step: run the parser adapter ({tool}) or extract in a disposable VM and run the verdict on the extracted folder."
            else:
                msg = f"Installer {os.path.basename(path)} ({ik}) could not be opened with any parser installed, so the files it would drop are unaccounted. Next step: open it with a parser adapter (innoextract for Inno Setup, 7z for NSIS script and contents, an MSI table reader for MSI) or extract it in a disposable VM, then run the verdict on the extracted folder."
            # The blocker belongs to the installer's own record, not
            # only to the release list: the per-file table is the
            # accounting, and it previously claimed this same file
            # was ACCOUNTED while the headline said UNACCOUNTED
            # (2026-11-24 accuracy audit, defect 16).
            entry_blockers.setdefault(os.path.basename(path), []).append(msg)
            installer["contents"] = [os.path.basename(path) + " (contents not extracted)"]
            installer["drop_list"] = installer["contents"]
        else:
            entries.append({"rel": os.path.basename(path), "abspath": path, "origin": "file"})
            expand(path, os.path.basename(path), "file", 0)
    else:
        blockers.append(f"Subject not found: {path}")
    # Installer files inside a folder or archive get the installer
    # test too, not only single-file subjects: an installer EXE whose
    # own bytes raise no chain was previously judged as an ordinary
    # file, so its payload was never treated as unaccounted
    # (2026-11-24 accuracy audit, defect 10). Fully enumerated or
    # failed containers are skipped: their contents are the members,
    # judged as units of their own.
    expanded_set = set(expanded_containers)
    failed_set = set(failed_containers)
    for e in list(entries):
        if e["origin"] not in ("dir", "archive"):
            continue
        if e["rel"] in expanded_set or e["rel"] in failed_set:
            continue
        try:
            with open(e["abspath"], "rb") as fh:
                edata = fh.read()
        except Exception:
            continue
        ik = installer_kind(e["abspath"], edata)
        if ik:
            entry_blockers.setdefault(e["rel"], []).append(
                f"{e['rel']}: this file is an installer ({ik}) sitting inside the release. The files it would drop are not in this release listing, so they are unaccounted, and this file blocks any NO for the release. Next step: extract the installer with a parser adapter (innoextract for Inno Setup, 7z for NSIS, an MSI table reader for MSI) and run the verdict on the extracted folder.")
    return entries, installer, blockers, unexpanded, failed_containers, expanded_containers, entry_blockers


def enumerate_reference(reference):
    """Map rel path and basename to {abspath, sha256, data} for a genuine
    reference file or folder. Archives in the reference are expanded."""
    out = {}
    if not reference:
        return out
    with tempfile.TemporaryDirectory(prefix="ezref_") as td:
        entries, _inst, blockers, _un, _fc, _ec, _eb = enumerate_subject(reference, td)
        for e in entries:
            with open(e["abspath"], "rb") as f:
                data = f.read()
            rec = {"abspath": e["abspath"], "data": data, "sha256": hashes(data)["sha256"], "rel": e["rel"]}
            out[e["rel"]] = rec
            out.setdefault("base:" + os.path.basename(e["rel"]), rec)
            out.setdefault("sha:" + rec["sha256"], rec)
        # data must outlive the temp dir for archives: copy bytes only, abspath dropped
        for rec in out.values():
            rec["abspath"] = None
    return out


LICENSE_CTX = 128

# Named crack patterns. An expected-crack classification is a
# machine-verified claim, never a label: a differing region earns it
# only by (a) matching one of these named patterns, AND (b) passing
# the region capability check (the region's own bytes add no
# capability, network indicator, or embedded executable the genuine
# region did not have). Context or nearby strings alone classify
# nothing. This is the elite-analyst requirement adopted 2026-11-23:
# accounting proves every byte is explained, not that every
# explanation is true, so the explanation itself must be verified.
_JCC = {0x74, 0x75, 0x78, 0x79, 0x7C, 0x7D, 0x7E, 0x7F, 0x84, 0x85}

def _diff_positions(a, b):
    return sum(1 for x, y in zip(a, b) if x != y) + abs(len(a) - len(b))

def _crack_pattern(tag, old_seg, new_seg, ctx):
    """Return the name of the crack pattern this region matches, or
    None. Patterns are byte- and shape-based, deliberately narrow."""
    low_new = new_seg.decode("latin-1", "replace").lower()
    low_old = old_seg.decode("latin-1", "replace").lower()
    if tag == "replace" and len(old_seg) == len(new_seg) and 0 < len(new_seg) <= 16:
        if any(b in new_seg for b in (0xEB, 0x90)) or (len(new_seg) >= 1 and new_seg[0] in _JCC and old_seg[0] in _JCC):
            return "conditional-branch-patch"
    if tag == "replace" and len(old_seg) == len(new_seg) and _diff_positions(old_seg, new_seg) <= 4 and len(new_seg) <= 64:
        if any(w in ctx for w in ("checksum", "crc", "integrity", "signature check")):
            return "checksum-or-integrity-fix"
        if any(w in ctx for w in LICENSE_WORDS):
            return "license-flag-flip"
        # A small equal-length change with NO positive license or
        # integrity context names nothing: it is as consistent with a
        # settings change, a counter, or a call-target redirection
        # as with a license flag. Fall through to the remaining
        # patterns; if none matches, the region is unaccounted
        # (2026-11-24 accuracy audit, defect 7).
    if tag in ("replace", "insert") and ("if true" in low_new or "if 1:" in low_new or "return true" in low_new
                                         or ("==" in low_old and "==" not in low_new and any(w in ctx for w in LICENSE_WORDS))):
        return "license-condition-neutralised"
    if tag == "insert" and any(w in ctx for w in LICENSE_WORDS) and (
            re.search(r"\btrue\b", low_new) or low_new.strip().startswith("#")
            or "license" in low_new or "patch" in low_new or "crack" in low_new):
        # an inserted fragment of the same condition rewrite (the diff
        # engine splits one edit into several regions); the region
        # capability check remains the gate on its content
        return "license-condition-neutralised"
    if tag == "delete" and not new_seg and len(old_seg) <= 8192 and any(w in ctx for w in LICENSE_WORDS + ("wrapper", "drm", "protection")):
        low_old_seg = old_seg.decode("latin-1", "replace").lower()
        nonprintable = sum(1 for b in old_seg if b < 0x20 or b > 0x7E) / max(1, len(old_seg))
        if any(w in low_old_seg for w in ("wrapper", "drm", "protection")) or nonprintable > 0.3:
            return "wrapper-removal"
    if tag == "replace" and len(old_seg) == len(new_seg) and any(w in ctx for w in LICENSE_WORDS):
        printable = sum(1 for b in new_seg if 32 <= b < 127)
        if new_seg and printable / len(new_seg) > 0.9:
            return "key-or-serial-substitution"
    return None

_URL_RE = re.compile(r"https?://[^\s\"'<>]+")
_IP_RE = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")
_DOMAIN_RE = re.compile(r"\b[a-z0-9-]+\.(?:com|net|org|io|invalid|example|info|biz|xyz|top|site|online|ru|su|cc)\b")

def _expand_span(data, a, b):
    """Expand a diff region to the enclosing printable string span
    (bounded). The diff engine emits minimal edit fragments, so a
    swapped URL arrives as several tiny regions, none holding the
    whole indicator; the capability check profiles the full string
    the region sits inside, in both files."""
    while a > 0 and 0x20 <= data[a - 1] <= 0x7E and b - a < 2048:
        a -= 1
    while b < len(data) and 0x20 <= data[b] <= 0x7E and b - a < 2048:
        b += 1
    return data[a:b]

def _region_profile(seg):
    """Capability profile of one diff region's bytes: capability
    rule hits over the region's strings and text, network indicators,
    embedded executable headers, and the printable strings found (the
    string count is what proves the profile actually examined
    something)."""
    text = seg.decode("latin-1", "replace")
    strings = re.findall(r"[\x20-\x7e]{4,}", text)
    caps = {c["id"] for c in match_capabilities([], strings, [], text)}
    indicators = set(_URL_RE.findall(text)) | set(_IP_RE.findall(text)) | {"domain:" + d for d in _DOMAIN_RE.findall(text.lower())}
    headers = set()
    if seg.startswith(b"MZ") or b"PE\x00\x00" in seg:
        headers.add("embedded-pe-header")
    for sname in (b".vmp", b".themida", b".enigma"):
        if sname in seg:
            headers.add("protector-section")
    return caps, indicators, headers, len(strings)

def _region_instruction_profile(data, start):
    """Decode the instruction at the region start (both x86 modes).
    Returns (decoded, kind, target): kind classifies the instruction
    as call, jmp, jcc (conditional jump) or other; target is its
    direct branch operand text when it has one. This is what makes
    the capability check non-vacuous for pure code regions, where
    there are no strings to profile (2026-11-24 accuracy audit,
    defect 7)."""
    try:
        from .disasm import disassemble
    except Exception:
        return (False, None, None)
    chunk = data[start:start + 24]
    if not chunk:
        return (False, None, None)
    for arch in ("x86-64", "x86"):
        d = disassemble(chunk, arch, start)
        ins = d.get("instructions") or []
        if d.get("available") and ins:
            first = ins[0]
            mn = first["mnemonic"].lower()
            if mn == "call":
                kind = "call"
            elif mn.startswith("j"):
                kind = "jmp" if mn == "jmp" else "jcc"
            else:
                kind = "other"
            target = first["op_str"] if kind in ("call", "jmp", "jcc") else None
            return (True, kind, target)
    return (False, None, None)

def _region_capability_check(old, new, i1, i2, j1, j2):
    """The verification half of an expected-crack classification:
    the new region must add nothing the genuine region did not have.
    Profiles the enclosing string spans AND the region's own bytes
    AND the instruction decoded at the region start, in both files.
    A region where nothing at all could be profiled (no strings, no
    capability hits, no indicators, no decodable instruction) FAILS
    the check: a check that examined nothing is not a pass.
    Returns (passed, added_capabilities, added_indicators)."""
    oc, oi, oh, os_ = _region_profile(_expand_span(old, i1, i2))
    nc, ni, nh, ns_ = _region_profile(_expand_span(new, j1, j2))
    orc, ori, orh, ors = _region_profile(old[i1:i2])
    nrc, nri, nrh, nrs = _region_profile(new[j1:j2])
    oc, oi, oh = oc | orc, oi | ori, oh | orh
    nc, ni, nh = nc | nrc, ni | nri, nh | nrh
    added_caps = sorted(nc - oc)
    added_ind = sorted((ni - oi) | (nh - oh))
    o_dec, o_kind, o_tgt = _region_instruction_profile(old, i1)
    n_dec, n_kind, n_tgt = _region_instruction_profile(new, j1)
    profiled = bool(oc or oi or oh or nc or ni or nh or os_ or ns_ or ors or nrs or o_dec or n_dec)
    if not profiled:
        added_ind.append("region could not be profiled: no strings, capabilities, indicators or decodable instruction in the region or its enclosing span, so the check examined nothing")
    # Control-flow novelty in a code region: a call whose target the
    # genuine region did not call is added behaviour, however
    # patch-shaped the region looks. A conditional jump flipped to
    # an unconditional jump to the same target is the canonical
    # crack and is not flagged. Text regions (both sides printable)
    # skip this: coincidental decodings of text bytes are not code.
    old_seg, new_seg = old[i1:i2], new[j1:j2]
    def _mostly_printable(seg):
        return bool(seg) and sum(1 for b in seg if 0x20 <= b <= 0x7E or b in (9, 10, 13)) / len(seg) > 0.9
    if o_dec and n_dec and not (_mostly_printable(old_seg) and _mostly_printable(new_seg)):
        if n_kind == "call" and (o_kind != "call" or o_tgt != n_tgt):
            added_ind.append(f"control-flow: the new region calls {n_tgt}, a target the genuine region did not call")
    return (not added_caps and not added_ind), added_caps, added_ind


def classify_diff(old, new, old_caps, new_caps):
    """Binary diff ledger. Every differing region is classified as
    expected-crack, benign-repack, or unaccounted. An expected-crack
    classification is machine-verified: the region must match a named
    crack pattern (license check patch, checksum fix, wrapper
    removal, condition neutralised, flag flip, key substitution) AND
    pass the region capability check on its own bytes. A region that
    adds any capability, network indicator, or embedded executable
    the genuine region did not have fails to unaccounted, however
    much it looks like a license patch. New capabilities anywhere in
    the patched file also make every region unaccounted on their own."""
    ledger = []
    new_cap_ids = {c["id"] for c in new_caps} - {c["id"] for c in old_caps}
    sm = difflib.SequenceMatcher(a=old, b=new, autojunk=False)
    for tag, i1, i2, j1, j2 in sm.get_opcodes():
        if tag == "equal":
            continue
        old_seg, new_seg = old[i1:i2], new[j1:j2]
        ctx = (old[max(0, i1 - LICENSE_CTX):i2 + LICENSE_CTX] + new[max(0, j1 - LICENSE_CTX):j2 + LICENSE_CTX]).decode("latin-1", "replace").lower()
        entry = {"tag": tag, "old_range": [i1, i2], "new_range": [j1, j2],
                 "old_bytes": old_seg[:48].hex(), "new_bytes": new_seg[:48].hex(),
                 "size_change": len(new_seg) - len(old_seg)}
        if new_cap_ids:
            entry["classification"] = "unaccounted"
            entry["reason"] = f"The patched file gained capabilities the genuine file does not have: {sorted(new_cap_ids)}. Any region could carry them, so no region is waved through."
        elif len(new_seg) - len(old_seg) > 64:
            entry["classification"] = "unaccounted"
            entry["reason"] = f"The change inserts {len(new_seg) - len(old_seg)} new bytes, far more than a license patch needs, and nothing in the inserted bytes explains what the new code does. Size is judged before context: a large insertion next to a license string is still a large insertion."
        elif all(b == 0 for b in new_seg) and tag in ("replace", "insert"):
            entry["classification"] = "benign-repack"
            entry["reason"] = "The change writes zero bytes only: padding or a cleared field, not new code. This explanation is byte-verified: every new byte is zero."
        else:
            pattern = _crack_pattern(tag, old_seg, new_seg, ctx)
            passed, added_caps, added_ind = _region_capability_check(old, new, i1, i2, j1, j2)
            entry["crack_pattern"] = pattern
            entry["region_capability_check"] = {"passed": passed, "added_capabilities": added_caps,
                                                 "added_network_indicators": added_ind}
            if pattern and passed:
                entry["classification"] = "expected-crack"
                entry["reason"] = (f"Machine-verified expected crack: the region matches the named crack pattern "
                                   f"'{pattern}', and the region capability check passes: the region's own bytes add no capability, "
                                   f"network indicator, or embedded executable the genuine region did not have.")
            elif pattern and not passed:
                entry["classification"] = "unaccounted"
                entry["reason"] = (f"The region matches the crack pattern '{pattern}' in shape, but it FAILS the region capability check: "
                                   f"it adds capabilities {added_caps} or network indicators {added_ind} the genuine region did not have. "
                                   f"A payload planted inside a patch-shaped region is classified unaccounted, never expected-crack.")
            else:
                entry["classification"] = "unaccounted"
                entry["reason"] = "The change matches no named crack pattern (license check patch, checksum fix, wrapper removal, condition neutralised, flag flip, key substitution), so it is unaccounted. Nearby license strings or small size alone do not classify a region."
        ledger.append(entry)
    return ledger


# ---------------------------------------------------------------- main
def verdict(path, reference=None, known_bad=None, enrich_known_bad=False):
    started = time.perf_counter()
    kb = dict(KNOWN_BAD_SHA256)
    if known_bad:
        kb.update(known_bad)
    known_bad = kb
    ref_map = enumerate_reference(reference)
    # A reference may itself be a manifest (.sfv or checksum file). Then
    # NO requires hash equality with that manifest, per file, on a
    # collision-resistant hash: CRC32 (.sfv) and MD5 entries match as
    # corroboration only and never account for a file on their own.
    ref_manifest = None
    if reference and os.path.isfile(str(reference)) and manifest_kind(str(reference)):
        try:
            with open(str(reference), "r", errors="replace") as mf:
                ref_manifest = parse_manifest(mf.read(), manifest_kind(str(reference)))
            ref_map = {}
        except Exception:
            ref_manifest = None
    files_out = []
    yes_reasons = []
    blockers = []
    emu_stats = {"files_emulated": 0, "instructions_emulated": 0, "entry_stub_traces": 0}
    missing = []
    next_steps = []
    diff_ledger_all = []

    with tempfile.TemporaryDirectory(prefix="ezverdict_") as td:
        entries, installer, enum_blockers, unexpanded, failed_containers, expanded_containers, entry_blockers = enumerate_subject(path, td)
        failed_container_set = set(failed_containers)
        expanded_container_set = set(expanded_containers)
        # Basenames of everything examined in this run: an external
        # reference or a proxy invocation that names one of these
        # files is resolved, because the target was judged here
        # (wave 3, R1 and R5).
        entry_basenames = {os.path.basename(e["rel"].split("!")[-1]).lower() for e in entries}
        # Coverage wave 2: the Java and DEX classes defined anywhere
        # in this submission, collected before the per-file loop, so
        # a class file's dynamic load of a sibling class (or a DEX
        # file's load of a class defined in a second DEX) resolves
        # against the submission itself instead of capping.
        known_class_names = set()
        known_dex_class_names = set()
        from .bytecode import parse_class_file as _parse_class_file, parse_dex as _parse_dex, is_java_class as _is_java_class, is_dex as _is_dex
        for e in entries:
            try:
                with open(e["abspath"], "rb") as _kf:
                    _kdata = _kf.read()
            except Exception:
                continue
            if _is_java_class(_kdata):
                try:
                    _kr = _parse_class_file(_kdata)
                    if _kr.get("this_class"):
                        known_class_names.add(_kr["this_class"])
                except Exception:
                    pass
            elif _is_dex(_kdata):
                try:
                    _kr = _parse_dex(_kdata)
                    for _kc in _kr.get("classes") or []:
                        known_dex_class_names.add(_kc["name"])
                except Exception:
                    pass
        blockers.extend(enum_blockers)
        enumeration_aids = []
        for e in entries:
            bn = os.path.basename(e["rel"])
            if bn.lower().endswith(".torrent"):
                enumeration_aids.append({"file": e["rel"], "kind": "torrent", "note": "The .torrent file list is an enumeration aid: it states what the release claims to contain. Piece hashes prove a copy matches the torrent, not that the torrent is clean."})
            elif manifest_kind(bn):
                enumeration_aids.append({"file": e["rel"], "kind": manifest_kind(bn), "note": "A bundled manifest is an enumeration aid and a self-consistency check only: matching it proves the files match what the release itself claims, never that they are genuine."})
        text_blobs = []
        release_manifests = []
        autoexec_all = []
        connection_ledger = []
        ledger_seq = [0]
        def ledger_add(dest, source_rel, provenance, note=""):
            ledger_seq[0] += 1
            cls, tag = classify_link(dest, baseline_domains)
            connection_ledger.append({"id": f"c{ledger_seq[0]:04d}", "dest": dest, "source_file": source_rel,
                                      "provenance": provenance, "classification": cls, "tag": tag,
                                      "observed": False, "note": note})
            return connection_ledger[-1]
        # genuine baseline (domains and predicted effects) from the reference
        baseline_domains = set()
        baseline_effects = set()
        if reference and ref_manifest is None and os.path.exists(str(reference)):
            try:
                bent, _bi, _bb, _bu, _bfc, _bec, _beb = enumerate_subject(str(reference), os.path.join(td, "baseline"))
                for be in bent[:100]:
                    try:
                        brep = analyze(be["abspath"])
                    except Exception:
                        continue
                    for d in brep.get("iocs", {}).get("domains", []):
                        baseline_domains.add(d)
                    for u in brep.get("iocs", {}).get("urls", []):
                        m = re.match(r"https?://([^/]+)", u)
                        if m:
                            baseline_domains.add(m.group(1).split(":")[0].lower())
                    for ef in predicted_effects(brep):
                        baseline_effects.add((ef["category"], ef["effect"]))
            except Exception:
                pass
        single_file = len(entries) == 1 and entries and entries[0]["origin"] == "file"
        for e in entries:
            rel = e["rel"]
            base = os.path.basename(rel.split("!")[-1])
            with open(e["abspath"], "rb") as f:
                data = f.read()
            h = hashes(data)
            rec = {"name": base, "path_in_release": rel, "size_bytes": len(data),
                   "sha256": h["sha256"], "hashes": h, "origin": e["origin"],
                   "signed": None, "signature_valid": None, "verdict": "YES: UNACCOUNTED",
                   "why": [], "capabilities": [], "chains": [], "reference": None,
                   "patch_evidence": [], "embedded_payloads": []}
            signed, sig_valid = pe_signature(data)
            rec["signed"] = signed
            rec["signature_valid"] = sig_valid
            file_blockers = []
            file_blockers.extend(entry_blockers.get(rel, []))
            import zlib as _zlib
            rec["crc32"] = format(_zlib.crc32(data) & 0xffffffff, "08x")
            if base.lower().endswith((".nfo", ".txt", ".md", ".url", ".diz")) and len(data) < 200000:
                try:
                    text_blobs.append(data.decode("utf-8", "replace"))
                except Exception:
                    pass
            mk = manifest_kind(base)
            if mk and e["origin"] != "installer":
                try:
                    release_manifests.append((rel, mk, parse_manifest(data.decode("utf-8", "replace"), mk)))
                except Exception:
                    pass
            if ref_manifest is not None:
                expected = None
                for key, val in ref_manifest.items():
                    if os.path.basename(key) == base:
                        expected = val
                        break
                if expected is None:
                    file_blockers.append(f"{rel}: this file is not listed in the reference manifest, so it is unaccounted. NO requires hash equality with the manifest for every file.")
                    rec["reference"] = "not-in-reference-manifest"
                else:
                    actual = rec["crc32"] if len(expected) == 8 else h["md5"] if len(expected) == 32 else h["sha1"] if len(expected) == 40 else h["sha256"]
                    if actual == expected:
                        if len(expected) in (8, 32):
                            # CRC32 and MD5 are checksums, not
                            # collision-resistant hashes: a
                            # substituted file can be padded to the
                            # listed value by construction, so the
                            # match is corroboration only and can
                            # never close the accounting on its own
                            # (2026-11-24 accuracy audit, defect 11).
                            rec["reference"] = "manifest-match-weak"
                            rec["why"].append(f"Matches the reference manifest only on a {'CRC32' if len(expected) == 8 else 'MD5'} value ({expected}). That match is corroboration only: CRC32 and MD5 values can be forged onto different bytes, so this file still has to be accounted for on other grounds.")
                        else:
                            rec["reference"] = "manifest-match"
                    else:
                        file_blockers.append(f"{rel}: hash does not equal the reference manifest entry ({actual} vs {expected}), so these bytes are unaccounted.")
                        rec["reference"] = "manifest-mismatch"
            # pipeline order: unpack and evasion first, then full analysis
            sx = extract_all(data)
            pre_unpack = analyze_unpack(data, sx["all"], [], base)
            pre_evasion = analyze_evasion(data, [], sx["all"])
            try:
                rep = analyze(e["abspath"])
            except Exception as ex:
                blockers.append(f"{rel}: analysis failed ({ex}), so this file is unproven.")
                rec["why"].append(f"Analysis failed: {ex}")
                files_out.append(rec)
                continue
            rec["format"] = (rep.get("format") or {}).get("format")
            rec["capabilities"] = [c["id"] for c in rep.get("capabilities", [])]
            rec["capa"] = rep.get("capa")
            rec["analysis_verdict"] = rep.get("risk", {}).get("verdict")
            rec["behaviour_effects"] = predicted_effects(rep)
            # ---- document and firmware analysis feeds the verdict ----
            # The analyzer computes PDF, Office and firmware findings
            # for every file; until now the verdict never read them,
            # so a PDF with auto-run JavaScript and a launch action
            # earned NO "as data" (2026-11-24 accuracy audit,
            # defects 5 and 14). Active document content and the
            # combined firmware flag are unaccounted markers here.
            if rel not in failed_container_set:
                _pdf = rep.get("pdf") or {}
                if _pdf.get("is_pdf"):
                    _feats = _pdf.get("features") or {}
                    _active = sorted(k for k in ("/JavaScript", "/JS", "/OpenAction", "/AA", "/Launch", "/SubmitForm", "/XFA", "/EmbeddedFile") if _feats.get(k))
                    if _active:
                        file_blockers.append(f"{rel}: this PDF carries active content ({', '.join(_active)}): scripts, actions that run when the file opens, launch actions or embedded files are behaviour the data accounting cannot account for, so the document is unaccounted until the active content is extracted and judged. Next step: extract the embedded files and scripts and run the verdict on them.")
                _office = rep.get("office") or {}
                if _office.get("has_macros") or _office.get("auto_open_triggers") or _office.get("dde"):
                    _bits = []
                    if _office.get("has_macros"):
                        _bits.append("macro streams")
                    if _office.get("auto_open_triggers"):
                        _bits.append("auto-open triggers (" + ", ".join(_office["auto_open_triggers"]) + ")")
                    if _office.get("dde"):
                        _bits.append("DDE links")
                    file_blockers.append(f"{rel}: this Office document carries active content ({'; '.join(_bits)}) that the data accounting cannot account for, so the document is unaccounted until the macro code is extracted and judged.")
                _fw = rep.get("firmware") or {}
                if _fw.get("red_flags"):
                    rec["firmware"] = {"is_firmware_image": _fw.get("is_firmware_image"),
                                       "red_flags": [f["name"] for f in _fw["red_flags"]]}
                    for _fl in _fw["red_flags"]:
                        if "SMM" in _fl["name"] and "network" in _fl["name"].lower():
                            file_blockers.append(f"{rel}: firmware analysis flags an SMM driver with network protocol access. System Management Mode code that can reach the network runs below the operating system, outside its view, so those bytes are unaccounted and block any NO. Detail: {_fl['plain_english']}")
            # extra streams where detectable (Linux xattrs here; NTFS
            # alternate data streams are separate manifest streams on
            # Windows hosts and are hashed per stream there)
            extra_streams = []
            try:
                for xa in os.listxattr(e["abspath"]):
                    try:
                        val = os.getxattr(e["abspath"], xa)
                        extra_streams.append({"name": f"xattr:{xa}", "size": len(val), "sha256": hashlib.sha256(val).hexdigest()})
                    except Exception:
                        pass
            except Exception:
                pass
            rec["extra_streams"] = extra_streams
            if rel in unexpanded:
                file_blockers.append(f"{rel}: this archive layer sits at the recursion depth limit and was not opened. An unopened layer is unaccounted, never clean.")
            if rel in failed_container_set:
                file_blockers.append(f"{rel}: this container could not be fully enumerated (the enumeration failure for it is recorded in this report's unaccounted list). A container that cannot be opened to the bottom is an unaccounted unit by construction and can never be certified clean.")
            # A container that was fully enumerated is an enumeration
            # unit, not a content unit: its members are judged as the
            # content, each with the same context discriminators a
            # loose file gets. The container's own raw bytes are NOT
            # judged as code, because stored member bytes inside the
            # container would otherwise be judged a second time under
            # the container's name and extension, which is how a
            # banking article inside a zip was once flagged as a
            # banking trojan: the article discriminator follows the
            # member (.txt), not the container (.zip). The exception
            # is a container that is itself executable (a
            # self-extracting PE, say): that file is judged as code in
            # its own right as well as enumerated.
            container_entry = rel in expanded_container_set and rec["format"] not in EXECUTABLE_FORMATS
            # Coverage wave 2: a fat Mach-O that was fully expanded
            # into slices is an enumeration unit by the same rule,
            # even though its format label (Mach-O) sits in
            # EXECUTABLE_FORMATS: the slices are the judged content,
            # each verdicted as its own unit, and the bundle's own
            # bytes are the slices' bytes read a second time.
            if rel in expanded_container_set and data[:4] in (b"\xca\xfe\xba\xbe", b"\xbe\xba\xfe\xca"):
                container_entry = True
            # A container that FAILED enumeration gets the same
            # judgement exemption, for the opposite reason: its
            # contents could not be enumerated at all, so nothing in
            # it is proven either way. Chains, scope hits and carve
            # verdicts computed from its raw bytes would print a
            # PROVEN token for unreadable content, which breaks the
            # proof contract even when the headline direction happens
            # to match (2026-11-24 accuracy audit, defect 8). The
            # failed-container blocker already recorded above makes
            # the file YES UNACCOUNTED, which is the correct output.
            failed_container = rel in failed_container_set
            judgement_exempt = container_entry or failed_container
            # ---- connection ledger: every link this file contains ----
            seen_dest = set()
            def _add_url(u, provenance, note=""):
                m = re.match(r"(https?)://([^/:\s]+)(?::(\d+))?(/[^\s]*)?", u)
                if not m:
                    return
                host = m.group(2).lower()
                dest = {"url": u, "domain": None if re.fullmatch(r"(?:\d{1,3}\.){3}\d{1,3}", host) else host,
                        "ip": host if re.fullmatch(r"(?:\d{1,3}\.){3}\d{1,3}", host) else None,
                        "port": int(m.group(3)) if m.group(3) else (443 if m.group(1) == "https" else 80),
                        "scheme": m.group(1), "path": m.group(4) or "/"}
                key = (dest["url"], provenance)
                if key in seen_dest:
                    return
                seen_dest.add(key)
                ledger_add(dest, rel, provenance, note)
            for u in rep.get("iocs", {}).get("urls", []):
                _add_url(u, "written-in-file")
            for ip in rep.get("iocs", {}).get("ip_addresses", []):
                key = (ip, "written-in-file")
                if key not in seen_dest:
                    seen_dest.add(key)
                    ledger_add({"url": None, "domain": None, "ip": ip, "port": None, "scheme": None, "path": None}, rel, "written-in-file")
            for d in rep.get("unpack", {}).get("decoded_layers", []):
                for u in re.findall(r"https?://[^\s\"'<>]+", d.get("result", "")):
                    _add_url(u, "decrypted-at-runtime", f"recovered by decoding ({' then '.join(d.get('chain', []))})")
            lowbase = base.lower()
            if lowbase.endswith(".url"):
                for u in parse_url_file(data):
                    _add_url(u, "written-in-file", "target of an Internet Shortcut (.url) file, parsed as data")
            if lowbase.endswith(".lnk"):
                lnk = parse_lnk(data)
                rec["lnk"] = {k: lnk[k] for k in ("lolbin", "cradle", "urls")}
                for u in lnk["urls"]:
                    _add_url(u, "written-in-file", "inside a Windows shortcut (.lnk), parsed as pure bytes, never opened through a shell")
                if lnk["lolbin"]:
                    ledger_add({"url": None, "domain": None, "ip": None, "port": None, "scheme": "lnk-target",
                                "path": ", ".join(lnk["lolbin"])}, rel, "written-in-file",
                               "shortcut target is a living-off-the-land binary: " + ", ".join(lnk["lolbin"]))
                if lnk["lolbin"] and (lnk["urls"] or lnk["cradle"]):
                    yes_reasons.append({"file": rel, "chain": "lnk-download-cradle",
                                        "name": "A Windows shortcut points at a living-off-the-land binary with a download cradle: the shortcut itself is the dropper",
                                        "evidence": [f"lolbin: {', '.join(lnk['lolbin'])}", f"cradle: {', '.join(lnk['cradle']) or 'url present'}", f"urls: {', '.join(lnk['urls'])}"]})
            if lowbase.endswith(".torrent"):
                tor = parse_torrent(data)
                rec["torrent"] = tor
                for t in tor["trackers"]:
                    tu = t if "://" in t else "udp://" + t
                    hm = re.match(r"\w+://([^/:\s]+)(?::(\d+))?", tu)
                    ledger_add({"url": tu, "domain": hm.group(1).lower() if hm else None, "ip": None,
                                "port": int(hm.group(2)) if hm and hm.group(2) else None,
                                "scheme": tu.split("://")[0], "path": None}, rel, "written-in-file",
                               "torrent tracker from the .torrent metainfo, parsed locally. Event Zero never joins a swarm: joining would expose the user's IP address to every peer and tracker. Trackers are shared infrastructure, so a tracker alone is needs-more-evidence, never proof.")
                for w in tor["web_seeds"]:
                    _add_url(w, "written-in-file", "torrent web seed from the .torrent metainfo")
            # needs-more-evidence links inside executable or script files
            # are unaccounted behaviour; the same links in an .nfo or
            # readme are scene boilerplate and are notes only
            if rec["format"] in ("PE", "ELF", "Mach-O", "script"):
                for le in connection_ledger:
                    if le["source_file"] == rel and le["classification"] in ("lookalike", "shortener") and le["tag"] == "needs-more-evidence":
                        file_blockers.append(f"{rel}: connection ledger entry {le['id']} is a {le['classification']} link ({(le['dest'].get('domain') or le['dest'].get('url'))}) inside an executable or script file. An unknown shortener or lookalike link is needs-more-evidence: it cannot be accounted for as genuine or as the explained crack until it is resolved and classified.")
            chains = [] if judgement_exempt else malicious_chains(rep, data, base)
            # embedded payloads carved from this file alone. A fully
            # enumerated container is not carved: its members are
            # already enumerated and analysed as units of their own,
            # so carving the container would judge member bytes twice.
            carved = [] if judgement_exempt else carve(data)
            ends = sorted([c["offset"] for c in carved if c["offset"] > 0] + [len(data)])
            for c in carved:
                if c["offset"] == 0:
                    continue
                start = c["offset"]
                end = min([o for o in ends if o > start] or [len(data)])
                payload = data[start:end]
                if len(payload) < 64:
                    continue
                ppath = os.path.join(td, f"carved_{start}_{base}")
                with open(ppath, "wb") as pf:
                    pf.write(payload)
                try:
                    prep = analyze(ppath)
                except Exception as ex:
                    # The cap belongs to this file's own record
                    # (wave 3, R3): a release-level-only blocker
                    # would leave the unit itself reading ACCOUNTED
                    # while the headline disagreed.
                    file_blockers.append(f"{rel}: embedded {c['type']} payload at offset {hex(start)} could not be analysed ({ex}), so it is unproven.")
                    rec["embedded_payloads"].append({"type": c["type"], "offset": start, "offset_hex": hex(start), "analysed": False})
                    continue
                pchains = malicious_chains(prep, payload, base)
                rec["embedded_payloads"].append({"type": c["type"], "offset": start, "offset_hex": hex(start),
                                                  "analysed": True, "format": (prep.get("format") or {}).get("format"),
                                                  "chains": [p["chain"] for p in pchains]})
                for p in pchains:
                    yes_reasons.append({"file": rel, "chain": "embedded-payload:" + p["chain"],
                                        "name": f"Hidden embedded {c['type']} payload at offset {hex(start)} inside {base}: " + p["name"],
                                        "evidence": p["evidence"]})
                if (prep.get("format") or {}).get("format") == "unknown binary data" and not pchains:
                    file_blockers.append(f"{rel}: embedded {c['type']} payload at offset {hex(start)} could not be decoded to a known format, so what it does is unproven.")
            # known-bad hash
            if h["sha256"] in known_bad:
                yes_reasons.append({"file": rel, "chain": "known-bad-hash",
                                    "name": f"SHA-256 matches a known malware sample ({known_bad[h['sha256']]})",
                                    "evidence": [f"sha256: {h['sha256']}"]})
            if enrich_known_bad:
                # A VirusTotal count alone is never a verdict. Generic
                # HackTool, RiskWare, CrackTool or PUA scatter means the
                # engines see a crack, which is expected: that is the
                # UNACCOUNTED path (more evidence needed), never PROVEN.
                # PROVEN from a service needs a specific family on
                # record (MalwareBazaar signature) or family convergence
                # plus behaviour proven locally.
                try:
                    from .services import enrich as _enrich
                    en = _enrich(h["sha256"])
                    for s in en.get("services", []):
                        if not s.get("found"):
                            continue
                        if s.get("provider") == "MalwareBazaar" and s.get("family"):
                            yes_reasons.append({"file": rel, "chain": "known-bad-hash",
                                                "name": f"MalwareBazaar has this exact hash on record as the malware family {s['family']}",
                                                "evidence": [f"sha256: {h['sha256']}", "provider: MalwareBazaar", f"family: {s['family']}"]})
                        elif s.get("provider") in ("VirusTotal", "MetaDefender"):
                            det = s.get("last_analysis_stats", {}).get("malicious") if s.get("provider") == "VirusTotal" else s.get("detections")
                            if det:
                                file_blockers.append(f"{rel}: {s['provider']} reports {det} detection(s) for this hash, but a detection count alone is never a verdict and the labels available here are generic. This is corroboration that needs behaviour evidence, so the file is unaccounted until the behaviour is proven or the labels resolve to a specific family.")
                                rec.setdefault("corroboration", []).append(f"{s['provider']}: {det} generic detection(s), treated as corroboration only, never as a verdict basis.")
                except Exception:
                    pass
            # KMS baseline: local emulator service, renewal task and GVLK
            # installation are expected crack for an activator. A
            # persistence-plus-C2 chain built only on that baseline is
            # not malware; everything outside the baseline is judged.
            # The baseline is content based (a filename never qualifies,
            # and neither does a bare port-number substring), and the
            # local test is a real address test: 172.0.0.0/8 is not
            # local, only 172.16.0.0/12 is, and a bare domain counts as
            # external (2026-11-24 accuracy audit, defect 6).
            if kms_baseline(rep):
                if not external_contacts(rep):
                    kept = [c for c in chains if c["chain"] != "persistence-plus-c2"]
                    if len(kept) != len(chains):
                        rec["why"].append("KMS baseline applied: the local emulator service, renewal task and GVLK keys are the expected crack for an activator, so the persistence-plus-local-listener pattern was accounted as expected crack. Everything outside that baseline was judged normally.")
                    chains = kept
            for ch in chains:
                yes_reasons.append({"file": rel, "chain": ch["chain"], "name": ch["name"], "evidence": ch["evidence"]})
            rec["chains"] = [c["chain"] for c in chains]
            # THE SCOPE TEST: first behaviour unnecessary for the claimed
            # function decides YES (PROVEN class).
            scope_hits, claimed = scope_test(rep, base)
            if judgement_exempt:
                # the scope test judges content; a fully enumerated
                # container's content is its members, judged above,
                # and a failed container has no judged content at all
                scope_hits = []
            rec["claimed_function"] = claimed
            rec["scope_test"] = scope_hits
            for sh in scope_hits:
                if not any(y["file"] == rel and y["chain"] == "scope-test" and sh["behaviour"] in y["name"] for y in yes_reasons):
                    yes_reasons.append({"file": rel, "chain": "scope-test",
                                        "name": f"Scope test failed: {sh['behaviour']}. {sh['why']}",
                                        "evidence": sh["evidence"]})
            # ---- per-family findings that need the raw bytes or the
            # accounting state (beacon config parsing, unexplained .sys
            # accounting, fileless blobs, script line ledger). The
            # accounting state is computed here from the reference map
            # because the reference section below assigns it to the
            # record only later in this loop; the manifest states are
            # already on the record. Coverage wave 8: the families
            # layer receives the accounting fact, not the signature
            # state, as the thing that can suppress a finding. ----
            _ref_rec = None
            if ref_map:
                _ref_rec = ref_map.get(rel) or ref_map.get("base:" + base) or ref_map.get("sha:" + h["sha256"])
            _reference_accounted = bool(_ref_rec and _ref_rec.get("sha256") == h["sha256"]) or rec["reference"] in ("hash-match", "manifest-match")
            ff = family_findings(rep, base, data, sig_valid, reference_accounted=_reference_accounted)
            rec["family_chains"] = [c["chain"] for c in ff["chains"]]
            rec["family_notes"] = ff["notes"] + ff["family_unaccounted"]
            if ff["beacon_config"]:
                rec["beacon_config"] = {k: v for k, v in ff["beacon_config"].items() if k != "public_key"}
            if ff["script_ledger"]:
                rec["script_ledger"] = ff["script_ledger"]
                # The gate applies to files the engine identifies as
                # scripts (a real script language from a code
                # extension or a shebang). A prose text file also
                # receives a ledger for display, with language None;
                # its lines are prose, not code lines, and an
                # "unaccounted" prose line is not unaccounted
                # behaviour.
                _is_script = bool((rep.get("script_analysis") or {}).get("language"))
                if _is_script and ff["script_ledger"]["unaccounted"]:
                    # The ledger gate applies to every script, not
                    # only to activators: a NO on a script claims its
                    # behaviour is accounted, and a line the ledger
                    # cannot classify is behaviour nobody accounted
                    # for (2026-11-24 accuracy audit, defect 4). The
                    # ledger itself is KMS-allowlist shaped, but its
                    # flagged and unaccounted classes are generic
                    # high-risk classes (download, tamper, exfil,
                    # unknown), so the gate is the same for any
                    # script; allowlisted KMS lines simply do not
                    # occur in non-KMS scripts.
                    file_blockers.append(f"{rel}: this script has {len(ff['script_ledger']['unaccounted'])} line(s) the line ledger cannot account for (outside the licence allowlist and outside ordinary script structure), so those lines are unaccounted: " + "; ".join(f"line {u['line']}: {u['text']}" for u in ff["script_ledger"]["unaccounted"][:4]))
            for fb in ff["blockers"]:
                if fb not in file_blockers:
                    file_blockers.append(fb)
            for fc in ff["chains"]:
                if judgement_exempt:
                    # family proof standards judge content under the
                    # content file's own context; the container entry
                    # carries none of them (see container_entry above)
                    continue
                if fc["chain"] not in rec["chains"] and not any(y["file"] == rel and y["chain"] == fc["chain"] for y in yes_reasons):
                    # a family chain proven only with the raw bytes in
                    # hand (parsed beacon config): record it as proof
                    yes_reasons.append({"file": rel, "chain": fc["chain"], "name": fc["name"], "evidence": fc["evidence"]})
                    rec["chains"] = rec["chains"] + [fc["chain"]]
            for note in ff["notes"] + ff["family_unaccounted"]:
                rec["why"].append(note)
            # keygen and patcher special handling
            kg = is_keygen_like(base, rep)
            kg_bad = keygen_behaviour(rep) if kg else []
            if kg_bad and kms_baseline(rep):
                # the renewal service and task are the KMS baseline, not
                # behaviour beyond key generation
                kg_bad = [b for b in kg_bad if b["behaviour"] != "persistence"]
            if kg and kg_bad and not chains and not judgement_exempt:
                for b in kg_bad:
                    yes_reasons.append({"file": rel, "chain": "keygen-with-malicious-behaviour",
                                        "name": f"This keygen or patcher does more than generate keys: it has {b['behaviour']}, which no key generator needs",
                                        "evidence": [f"capability: {i}" for i in b["capability_ids"]]})
            # ---- devirtualization layer: census, trace, verdict feed ----
            virt = analyze_virtualization(data, rep.get("strings", {}).get("all", []), rep.get("sections", []), base)
            rec["virtualization"] = virt
            _emu = rep.get("emulation", {}) or {}
            if _emu.get("instructions_emulated", 0) or _emu.get("available"):
                emu_stats["files_emulated"] += 1
                emu_stats["instructions_emulated"] += int(_emu.get("instructions_emulated", 0) or 0)
            if virt["detected"]:
                trace = trace_entry_stub(data)
                if trace.get("available"):
                    emu_stats["entry_stub_traces"] += 1
                rec["virt_trace"] = {"available": trace["available"], "instructions_traced": trace["instructions_traced"],
                                     "api_crossings": trace["api_crossings"], "recovered_strings": trace["recovered_strings"],
                                     "gaps": trace.get("gaps", []), "note": trace["note"]}
                if trace["recovered_strings"] and not judgement_exempt:
                    caps2 = match_capabilities([], trace["recovered_strings"], [], " ".join(trace["recovered_strings"]))
                    chains2 = malicious_chains({"capabilities": caps2, "evasion": {"findings": []},
                                                "strings": {"all": trace["recovered_strings"]}, "rootkit": {}})
                    for ch in chains2:
                        yes_reasons.append({"file": rel, "chain": "virtualized-trace:" + ch["chain"],
                                            "name": f"Proven from the Unicorn trace of the virtualized entry stub: strings decrypted in trace memory form a malicious chain. " + ch["name"],
                                            "evidence": ch["evidence"] + [f"recovered in trace memory: {s}" for s in trace["recovered_strings"][:3]]})
            file_ledger = []
            # reference matching and diff
            ref_rec = None
            if ref_map:
                ref_rec = ref_map.get(rel) or ref_map.get("base:" + base) or ref_map.get("sha:" + h["sha256"])
            if ref_rec is not None:
                if ref_rec["sha256"] == h["sha256"]:
                    rec["reference"] = "hash-match"
                    rec["why"].append("Byte for byte identical to the genuine reference (SHA-256 match). Nothing was added, removed or patched.")
                else:
                    rec["reference"] = "differs-from-reference"
                    old_rep = None
                    old_caps = []
                    if ref_rec.get("data") is not None:
                        opath = os.path.join(td, "ref_" + base)
                        with open(opath, "wb") as of:
                            of.write(ref_rec["data"])
                        try:
                            old_rep = analyze(opath)
                            old_caps = old_rep.get("capabilities", [])
                        except Exception:
                            old_caps = []
                    ledger = classify_diff(ref_rec["data"], data, old_caps, rep.get("capabilities", []))
                    file_ledger = ledger
                    for le in ledger:
                        le["file"] = rel
                    diff_ledger_all.extend(ledger)
                    bad = [le for le in ledger if le["classification"] == "unaccounted"]
                    good = [le for le in ledger if le["classification"] != "unaccounted"]
                    rec["why"].append(f"Differs from the genuine reference in {len(ledger)} region(s): {len(good)} classified expected-crack or benign-repack, {len(bad)} unaccounted. Full ledger in this report.")
                    if bad and not chains:
                        file_blockers.append(f"{rel}: {len(bad)} differing region(s) against the genuine reference are unaccounted. A NO verdict needs every differing byte accounted for as expected-crack or benign-repack.")
                    if bad and chains:
                        yes_reasons.append({"file": rel, "chain": "unaccounted-code-with-malicious-chain",
                                            "name": "Unaccounted executable difference from the genuine original, and the file carries a proven malicious capability chain",
                                            "evidence": [f"diff region new_range {le['new_range']}" for le in bad]})
            elif reference and ref_manifest is None:
                # in the release but not in the genuine reference
                if rec["format"] in EXECUTABLE_FORMATS or os.path.splitext(base)[1].lower() in (".exe", ".dll", ".sys", ".so", ".dylib", ".py", ".ps1", ".sh", ".bat", ".js"):
                    if not chains:
                        file_blockers.append(f"{rel}: this executable file is not part of the genuine program and is not the explained crack, so it is unaccounted. Inside an installer or archive this is exactly where hidden payloads sit, so it blocks any NO for the whole release.")
                    rec["reference"] = "not-in-reference"
                else:
                    rec["reference"] = "not-in-reference (data file)"
                    rec["why"].append("Data file that is not in the reference. It was fully read, carries no executable code and no malicious capability, and is accounted for as data.")
            # Accounting for this file: every byte must end up genuine,
            # expected-crack, or benign-repack, or the file is unaccounted.
            patch_ev = find_patch_evidence(data, rep)
            rec["patch_evidence"] = patch_ev
            virt_detected = virt["detected"] or rep.get("unpack", {}).get("virtualization", {}).get("detected")
            # Exception, narrowly: the virtualized region is the known
            # crack patch area itself, fully enumerated as such in the
            # diff ledger against the genuine original (every differing
            # region classified expected-crack or benign-repack). Then
            # the virtualized units are accounted as the explained crack.
            virt_is_patch_area = bool(file_ledger) and all(le["classification"] in ("expected-crack", "benign-repack") for le in file_ledger)
            if virt_detected and virt_is_patch_area:
                rec["why"].append("The virtualized region is the known crack patch area: every differing region against the genuine original is enumerated in the diff ledger and classified expected-crack or benign-repack, so those virtualized units are accounted as the explained crack.")
                _gaps = (rec.get("virt_trace") or {}).get("gaps") or []
                if _gaps:
                    # Entry-stub trace gaps are recorded, never
                    # silent (2026-11-24 accuracy audit, defect 18).
                    # They do not reopen this accounting: the
                    # accounting here rests on the diff ledger against
                    # the genuine reference, not on the trace.
                    rec["why"].append(f"The entry-stub trace of the virtualized region had {len(_gaps)} gap(s) ({'; '.join(str(g) for g in _gaps[:3])}); the trace is coverage evidence only, and this file's accounting rests on the diff ledger above, not on the trace.")
            elif virt_detected:
                file_blockers.append(f"{rel}: a virtualizing protector was detected ({virt.get('protector') or 'unknown VM'}). Census: {virt['handler_census']['indirect_jump_sites']} indirect jump site(s), {len(virt['entry_stubs'])} entry stub(s), {len(virt['encrypted_regions'])} encrypted region(s). The virtualized functions are unaccounted units: the original code is private bytecode that static analysis cannot decode, and hiding inside a VM can never earn a clean verdict here. Next step: run it in a self-hosted sandbox (CAPE) and merge the behaviour report, then re-run the verdict.")
            for cb in ff["conditional_blockers"]:
                if file_ledger and all(le["classification"] in ("expected-crack", "benign-repack") for le in file_ledger):
                    rec["why"].append("A gated trigger (logic bomb pattern) is present, but every differing region against the genuine reference is classified expected-crack or benign-repack, so the trigger is accounted as the genuine program's own logic or the explained crack.")
                elif cb not in file_blockers:
                    file_blockers.append(cb)
            if rec["format"] == "unknown binary data" and not container_entry and not is_jar_signature_member(rel) and not rel.lower().endswith(".onnx"):
                # A fully enumerated container whose own container
                # format has no dedicated label (a tar.gz, say) is an
                # enumeration unit: its members are the judged
                # content, so the container's own format label is not
                # unaccounted content. A JAR signature member is
                # likewise an identified format (DER or digest data),
                # inventoried by the coverage wave 2 JAR accounting
                # on the JAR's own record, not unaccounted content.
                file_blockers.append(f"{rel}: the file format was not recognised, so the file could not be fully decoded. Its bytes are unaccounted.")
            if rep.get("unpack", {}).get("high_entropy_regions") and virt_detected and not virt_is_patch_area:
                file_blockers.append(f"{rel}: high entropy regions sit inside the virtualized protector and cannot be decoded statically. Those bytes are unaccounted.")
            # ---- script-class and shortcut-class shapes (accuracy
            # fix wave 2, 2026-11-24): a remote fetch-and-execute
            # chain, a .url shortcut to a remote executable payload,
            # and a disguised double extension each block NO, because
            # none of them can be accounted from the file alone. The
            # exemption is the same one the truncation markers use: a
            # file accounted by byte identity (hash match against a
            # reference, or a strong manifest hash) does not depend
            # on this reading, so it is not blocked by it. A fully
            # enumerated or failed container is exempt for the usual
            # reason: its content units are its members.
            if not judgement_exempt and rec["reference"] not in ("hash-match", "manifest-match"):
                _scf = script_class_findings(base, data)
                if _scf:
                    rec["script_class_findings"] = _scf
                    for _sf in _scf:
                        _ev = "; ".join(_sf["evidence"])
                        if _sf["kind"] == "remote-fetch-and-execute":
                            _tb = (f"{rel}: remote fetch-and-execute chain in a script-class file ({_ev}). "
                                   "What this file does is decided by content fetched from a remote host, and that content is not in this file, "
                                   "so the file's behaviour is unaccounted by construction and blocks any NO. "
                                   "Next step: fetch the remote content inside a disposable sandbox and run the verdict on it as well, or account for this file by byte identity against a genuine reference.")
                        elif _sf["kind"] == "url-shortcut-remote-payload":
                            _tb = (f"{rel}: this Internet Shortcut (.url) points at a remote executable payload ({_ev}). "
                                   "Opening the shortcut loads content that is not in this file, so the shortcut's effect cannot be accounted from the file alone and blocks any NO. "
                                   "Next step: fetch the target inside a disposable sandbox and run the verdict on what it serves, or account for this file by byte identity against a genuine reference.")
                        else:
                            _tb = (f"{rel}: disguised double extension ({_ev}). "
                                   "The name presents a document first and an executable second, the classic shape for making an executable look like a document. "
                                   "A name is not behaviour, so this is not proof of malware, but a file that disguises what it is cannot be accounted as what it appears to be, and it blocks any NO. "
                                   "Next step: rename the file to its true single extension and re-run the verdict, or account for it by byte identity against a genuine reference.")
                        if _tb not in file_blockers:
                            file_blockers.append(_tb)
            # ---- external references, engine completeness and
            # interpreter proxies (accuracy fix wave 3, 2026-11-24;
            # research rules R1, R3 and R5). R3 generalises the
            # wave 1 truncation markers into an invariant: any
            # recorded cap, parse failure or unenumerated member in
            # a unit's processing caps that unit. The truncation
            # markers are wired just below; the enumeration failures
            # are wired in enumerate_subject and at the top of this
            # loop; the two signals that existed but never reached
            # the verdict were the script parser's own parse error
            # and the binary parser's failure to read a PE section
            # table, and they are wired here. R1 produces the file's
            # external-reference list and resolves every entry
            # before any NO: examined in this run, provably inert,
            # or unresolved, and an unresolved reference to
            # executable or active content caps the verdict. R5 caps
            # a file that aims a signed system proxy at remote,
            # encoded or unexamined content; the proxy's signature
            # is never accounting for the invoking file. Exemptions
            # mirror waves 1 and 2: byte identity (hash match or a
            # strong manifest hash) does not depend on these
            # readings, and a failed container is already capped as
            # a unit. A fully enumerated container is exempt from
            # R5 and the R3 analysis signals (its members are the
            # judged units) but NOT from R1: an OOXML package's
            # relationship parts are the package's own references,
            # and they are read from the package itself.
            if not failed_container and rec["reference"] not in ("hash-match", "manifest-match"):
                _sa = rep.get("script_analysis") or {}
                _inc = []
                if _sa.get("parse_error"):
                    _inc.append(("script-parse-failure",
                                 f"the {_sa.get('language') or 'script'} parser could not parse this source ({_sa['parse_error']}), so the file's structure was not fully examined and the source accounting rests on the line ledger alone"))
                if rec["format"] == "PE" and "sections" not in (rep.get("format") or {}):
                    _inc.append(("binary-parse-failure",
                                 "the PE parser could not read this file's section table, so the binary was not fully decoded"))
                if _inc and not container_entry:
                    rec["incompleteness"] = [k for k, _d in _inc]
                    for _kind, _detail in _inc:
                        _tb = (f"{rel}: engine-incompleteness ({_kind}): {_detail}. "
                               "A verdict of NO claims complete accounting; processing that did not complete cannot support it, so this caps the verdict. "
                               "Next step: repair or convert the file so it parses fully, or account for it by byte identity against a genuine reference.")
                        if _tb not in file_blockers:
                            file_blockers.append(_tb)
                _refs, _refs_complete, _refs_note = external_references(base, data)
                for _tu in (rep.get("office") or {}).get("template_injection_urls") or []:
                    _refs.append({"kind": "office-remote-template", "target": _tu,
                                  "source": "Office analyzer template scan"})
                if (rep.get("pdf") or {}).get("is_pdf"):
                    for _u in _pdf_uri_targets(data):
                        _refs.append({"kind": "pdf-uri", "target": _u,
                                      "source": "PDF /URI action"})
                    if (rep.get("pdf") or {}).get("object_streams"):
                        _refs_note = ((_refs_note + "; ") if _refs_note else "") + \
                            "literal /URI targets only: this PDF carries compressed object streams, whose references this build does not enumerate"
                        _refs_complete = False
                if _refs or _refs_note:
                    _disp = []
                    _unres = []
                    for _r in _refs:
                        _d, _why = _reference_disposition(_r, entry_basenames)
                        _disp.append({**_r, "disposition": _d, "basis": _why})
                        if _d == "unresolved":
                            _unres.append(_r)
                    rec["external_references"] = {"references": _disp,
                                                  "complete": _refs_complete,
                                                  "note": _refs_note}
                    if _unres:
                        _ev = "; ".join(f"{_r['kind']}: {_r['target']}" for _r in _unres[:4])
                        _tb = (f"{rel}: external-reference-unresolved: this file points at content outside itself that was not examined in this run ({_ev}). "
                               "What the file does is decided in part by that content, so its behaviour cannot be accounted from the file alone, and the reference caps any NO. "
                               "Next step: fetch the referenced content inside a disposable sandbox and run the verdict on it as well, or account for this file by byte identity against a genuine reference.")
                        if _tb not in file_blockers:
                            file_blockers.append(_tb)
                # ---- written stages (accuracy fix wave 4,
                # 2026-11-24): a batch file that writes a second
                # script with echo redirection moves its behaviour
                # into a file that is not in the submission. The
                # stage's content is fully determined by the
                # writer's own lines, so it is reconstructed and
                # judged here; a judged stage counts as examined
                # content for the proxy check below, and a stage
                # that fails its own accounting blocks the writer.
                _stage_findings, _stage_locals = [], set()
                if not judgement_exempt:
                    _stage_findings, _stage_locals = written_stage_findings(
                        base, data, entry_basenames)
                if not judgement_exempt:
                    _pf = proxy_invocation_findings(base, data, entry_basenames | _stage_locals)
                    if _pf:
                        rec["proxy_invocation_findings"] = _pf
                        for _f in _pf:
                            _ev = "; ".join(_f["evidence"])
                            _tb = (f"{rel}: interpreter-proxy-invocation: this file aims a signed system binary at content that is remote, encoded, or not part of this submission ({_ev}). "
                                   "The system binary's signature vouches for the binary, never for this file's instructions, so the invoked content is unaccounted and blocks any NO. "
                                   "Next step: include the invoked file in the submission so it is examined in the same run, fetch the remote content inside a disposable sandbox and judge it too, or account for this file by byte identity against a genuine reference.")
                            if _tb not in file_blockers:
                                file_blockers.append(_tb)
                    if _stage_findings:
                        rec["written_stage_findings"] = _stage_findings
                        for _f in _stage_findings:
                            _ev = "; ".join(_f["evidence"])
                            _tb = (f"{rel}: written-stage-unaccounted: this batch file writes a script file at runtime whose content cannot be accounted ({_ev}). "
                                   "The written file is not in this submission; it exists only when this file runs, so what this file does is decided in part by that content, and the content fails its own accounting, which blocks any NO. "
                                   "Next step: include the written script in the submission so it is examined as a file in the same run, or account for this file by byte identity against a genuine reference.")
                            if _tb not in file_blockers:
                                file_blockers.append(_tb)
            # ---- bytecode accounting (coverage wave 2, 2026-11-24):
            # Java class files and JARs, .NET assemblies (IL decoded
            # at method level), DEX files and binary Android
            # manifests, and Mach-O code signature and entitlement
            # extraction. The parsers live in event_zero.bytecode and
            # state their own depth in the wave log; this section
            # wires their findings into the same accounting rules as
            # every other unit: a proven chain is a yes reason, an
            # unresolvable unit is a named blocker on the file's own
            # record, an unresolved external reference caps by the
            # wave 3 R1 rule, and a fully accounted unit earns the
            # bytecode branch of the final decision below. Exemptions
            # mirror waves 2 and 3: byte identity (hash match or a
            # strong manifest hash) does not depend on this reading,
            # and a failed container is already capped as a unit. A
            # fully enumerated container is NOT exempt: a JAR is
            # exactly a container whose manifest, signer and class
            # path accounting belongs to the JAR's own record, and a
            # fat Mach-O bundle's signature accounting belongs to the
            # bundle and its slices.
            if not failed_container and rec["reference"] not in ("hash-match", "manifest-match"):
                try:
                    _bc = bytecode_report(rel, data, known_files=entry_basenames,
                                          known_classes=known_class_names,
                                          known_dex_classes=known_dex_class_names)
                except Exception as _bcex:
                    _bc = {"kind": "bytecode", "accounted": False, "references": [],
                           "chains": [], "notes": [], "rec": {},
                           "blockers": [f"bytecode accounting: the bytecode parser failed on this file ({_bcex}), so its bytecode is unaccounted"]}
                if _bc is not None:
                    rec["bytecode"] = _bc["rec"]
                    rec["bytecode_kind"] = _bc["kind"]
                    rec["bytecode_accounted"] = bool(_bc.get("accounted"))
                    for _note in _bc.get("notes") or []:
                        rec["why"].append(_note)
                    if not judgement_exempt:
                        for _ch in _bc.get("chains") or []:
                            yes_reasons.append({"file": rel, "chain": _ch["chain"],
                                                "name": _ch["name"], "evidence": _ch["evidence"]})
                            if _ch["chain"] not in rec["chains"]:
                                rec["chains"] = rec["chains"] + [_ch["chain"]]
                    for _b in _bc.get("blockers") or []:
                        _tb = f"{rel}: {_b}"
                        if _tb not in file_blockers:
                            file_blockers.append(_tb)
                    for _r in _bc.get("references") or []:
                        _d, _why = _reference_disposition(_r, entry_basenames)
                        if _d == "unresolved":
                            _tb = (f"{rel}: external-reference-unresolved: this file's bytecode points at content outside itself that was not examined in this run ({_r['kind']}: {_r['target']}). "
                                   "What the file does is decided in part by that content, so its behaviour cannot be accounted from the file alone, and the reference caps any NO. "
                                   "Next step: include the referenced content in the submission so it is examined in the same run, or account for this file by byte identity against a genuine reference.")
                            if _tb not in file_blockers:
                                file_blockers.append(_tb)
            # ---- byte ownership, the dual-parser gate, polyglot
            # accounting and the BYOVD carve-out (coverage wave 3,
            # 2026-11-24). A NO now certifies two further things:
            # that every material byte range has an accounted owner,
            # and that independent parsers agree on the file's
            # structure. The ownership and dual-parser readings carry
            # the usual exemptions (byte identity does not depend on
            # them; a failed container is already capped as a unit).
            # The BYOVD carve-out carries NO provenance exemption: a
            # genuine signed driver with a dangerous capability set
            # is the exploit primitive, so it applies even to a
            # hash-matched or signature-verified driver. Polyglot
            # accounting requires every identity the bytes satisfy
            # to be accounted: an enumerated archive identity, an
            # image identity that is complete under its own format,
            # a carved and analysed appended binary, or the primary
            # identity judged in this loop.
            _drv = driver_capabilities(
                base, data,
                [i.get("name", "") for i in rep.get("imports") or []],
                rep.get("strings", {}).get("all", []),
                bool((rep.get("rootkit") or {}).get("is_kernel_driver")))
            if _drv["is_driver"]:
                rec["driver_capabilities"] = _drv
                if _drv["capabilities"] and not failed_container:
                    _ev = "; ".join(f"{c['category']}: {', '.join(c['evidence'])}"
                                    for c in _drv["capabilities"])
                    _tb = (f"{rel}: BYOVD carve-out: this Windows kernel driver carries a dangerous capability set ({_ev}). "
                           "A driver with these primitives is a bring-your-own-vulnerable-driver exploit primitive once a loader issues its IOCTLs, and that is true of the genuine signed original exactly as much as of a copy: provenance and byte identity vouch for where the driver came from, never for what it can be made to do. "
                           "The capability set is therefore refused clean on capability grounds, regardless of signature or hash match, and the capabilities are enumerated here as the reason. "
                           "Next step: judge the driver's deployment context with it (the loader that drives it must be accounted in the same submission), or remove the driver from the release.")
                    if _tb not in file_blockers:
                        file_blockers.append(_tb)
            if not failed_container and rec["reference"] not in ("hash-match", "manifest-match"):
                try:
                    _own = byte_ownership(base, data, expanded=rel in expanded_container_set)
                except Exception:
                    _own = None
                if _own is not None:
                    rec["byte_ownership"] = _own
                    for _u in _own["material_unowned"]:
                        _tb = (f"{rel}: byte-ownership: the range at offset {_u['offset_hex']} ({_u['size']} bytes, entropy {_u['entropy']}) has no accounted owner: {_u['reason']}. "
                               "A verdict of NO certifies that every byte was accounted for; bytes no analysis owns are unaccounted and cap the verdict. "
                               "Next step: account for that range (extract it and run the verdict on it as its own unit, or supply the genuine reference so it can be classified), or remove it.")
                        if _tb not in file_blockers:
                            file_blockers.append(_tb)
                if rec["format"] in ("PE", "ELF"):
                    try:
                        _dual = dual_parser(data, e["abspath"])
                    except Exception as _dex:
                        _dual = {"available": False, "parsers": [],
                                 "compared": [], "disagreements": [],
                                 "kind": rec["format"],
                                 "reason": f"the dual-parser gate itself failed ({_dex})"}
                    rec["dual_parser"] = _dual
                    if not _dual["available"]:
                        _tb = (f"{rel}: dual-parser gate unavailable: {_dual.get('reason') or 'fewer than two parsers produced a view'}. "
                               "A verdict of NO must not rest on one parser's reading of a binary's structure, so this caps the verdict. "
                               "Next step: account for this file by byte identity against a genuine reference, or repair the file so independent parsers can read it.")
                        if _tb not in file_blockers:
                            file_blockers.append(_tb)
                    else:
                        for _d in _dual["disagreements"]:
                            _tb = (f"{rel}: dual-parser differential ({_d['field']}): {_d['detail']}. "
                                   "Independent parsers reading the same bytes differently is exactly how a payload hides from one of them (Nisi et al., RAID 2021), so the disagreement is unaccounted and caps any NO. "
                                   "Next step: account for this file by byte identity against a genuine reference, or repair the malformed structure and re-run.")
                            if _tb not in file_blockers:
                                file_blockers.append(_tb)
                _ids = polyglot_identities(data)
                if len(_ids) >= 2:
                    rec["polyglot"] = _ids
                    _zip_ids = [i for i in _ids if i["format"] == "ZIP archive"]
                    _zip_accounted = bool(_zip_ids) and rel in expanded_container_set
                    _carved_offsets = {c["offset"] for c in carved}
                    for _i in _ids:
                        _tb = None
                        if _i["format"] in ("GIF image", "PNG image", "JPEG image") and _i["offset"] == 0:
                            _end = _zip_ids[0]["offset"] if _zip_ids else len(data)
                            if not (_zip_accounted and image_identity_accounted(data[:_end])):
                                _tb = (f"{rel}: polyglot: this file is a {_i['format']} and a ZIP archive at once, and the image identity is not accounted as a complete image under its own format. "
                                       "A file that satisfies two formats must be accounted under both; the unaccounted identity caps any NO. "
                                       "Next step: split the file into its two identities and run the verdict on each.")
                        elif _i["format"] in ("PE", "ELF") and _i["offset"] > 0:
                            if _i["offset"] not in _carved_offsets:
                                _tb = (f"{rel}: polyglot: an appended {_i['format']} begins at offset {hex(_i['offset'])}, past this file's first identity, and it was not carved and analysed under either identity. "
                                       "Content accounted under neither identity is unaccounted and caps any NO. "
                                       "Next step: extract the appended binary at that offset and run the verdict on it as its own unit.")
                        elif _i["format"] == "TAR archive" and _i["offset"] > 0:
                            _tb = (f"{rel}: polyglot: a TAR archive begins at offset {hex(_i['offset'])} inside this file and was never enumerated as members. "
                                   "A second identity whose interior was never listed is unaccounted and caps any NO. "
                                   "Next step: extract the archive at that offset and run the verdict on its members.")
                        if _tb and _tb not in file_blockers:
                            file_blockers.append(_tb)
            # ---- archive member semantics (coverage wave 5,
            # 2026-11-24). A fully enumerated container is
            # accounted by its member list, but an extractor
            # writes what each member's extraction semantics
            # say: a member whose written form diverges from its
            # listing (an escaping link target, a stream-qualified
            # or backslash name, a duplicate name shadowing an
            # earlier member, a local header that disagrees with
            # the central directory) is an unaccounted member,
            # and the container caps with the member and the
            # divergence named. The gate judges semantics, not
            # intent, and carries the wave 3 exemptions (byte
            # identity does not depend on it; a failed container
            # is already capped as a unit).
            if not failed_container and rel in expanded_container_set \
                    and rec["reference"] not in ("hash-match", "manifest-match"):
                try:
                    _mkind = container_kind(e["abspath"], data)
                except Exception:
                    _mkind = None
                if _mkind in ("zip", "tar", "deb", "rpm", "apk"):
                    try:
                        _divs = member_semantics(data, _mkind)
                    except Exception as _mex:
                        _divs = None
                        _tb = (f"{rel}: archive member semantics: the member-semantics gate could not read this {_mkind} container's member list ({_mex}), so how its members would be written by an extractor is unaccounted. "
                               "A verdict of NO certifies the members as listed; members whose extraction semantics were never checked are unaccounted and cap the verdict. "
                               "Next step: extract the container with a tool that lists its members and their link targets, and run the verdict on the extracted folder.")
                        if _tb not in file_blockers:
                            file_blockers.append(_tb)
                    if _divs is not None:
                        rec["member_semantics"] = {"kind": _mkind,
                                                   "divergences": _divs}
                        for _dv in _divs:
                            _tb = (f"{rel}: archive member semantics: member {_dv['member']!r} diverges from its listing ({_dv['kind']}): {_dv['detail']}. "
                                   "The container is accounted by its member list, but an extractor writes the member's extraction semantics, not the listing; a member whose written form differs from its listed form is unaccounted, so this container caps at unaccounted. This is a semantics finding, not a conviction. "
                                   "Next step: rebuild the container with the member under a name and form whose extraction matches its listing, or extract it with a tool that reports the divergence and run the verdict on the extracted folder.")
                            if _tb not in file_blockers:
                                file_blockers.append(_tb)
            # ---- auto-execution inventory (coverage wave 6,
            # 2026-11-24): every surface that runs code
            # automatically on a named trigger (package install
            # hooks, prepare and native-build steps, interpreter
            # startup files, folder-open and session-start
            # surfaces, workspace and agent configuration) is
            # inventoried as a first-class unit with its trigger
            # named, and judged under the same closure rules as
            # any script: a unit that names remote content, an
            # unaccounted local file, or a fetch-and-execute
            # composition caps; a trigger class the inventory
            # does not recognise caps rather than passing
            # silently. The exemptions mirror waves 1 to 3: byte
            # identity does not depend on the inventory, and a
            # failed container is already capped as a unit.
            if rec["format"] == "PE":
                try:
                    _pi = pe_imports(data)
                except Exception:
                    _pi = None
                if _pi is not None:
                    rec["pe_imports"] = _pi
            if not failed_container and rec["reference"] not in ("hash-match", "manifest-match"):
                try:
                    _units = autoexec_units(rel, data, entry_basenames)
                except Exception:
                    _units = None
                if _units is None:
                    _tb = (f"{rel}: auto-execution inventory: the inventory could not be built for this file, so any surface in it that runs code automatically is unaccounted. "
                           "Next step: run the verdict again; if the failure persists, treat the file as unaccounted and inspect it manually.")
                    if _tb not in file_blockers:
                        file_blockers.append(_tb)
                elif _units:
                    rec["autoexec"] = _units
                    for _u in _units:
                        _trig = _u["trigger"]
                        _capped = False
                        if _u["parse_error"]:
                            _tb = (f"{rel}: auto-execution inventory: this file claims an auto-execution surface ({_u['kind']}) but it could not be inventoried ({_u['parse_error']}). {_u['detail']}. "
                                   "A trigger surface that cannot be inventoried is unaccounted and blocks any NO. "
                                   "Next step: read the file manually and account for every command it runs automatically, or repair it into the standard form of its format and run the verdict again.")
                            if _tb not in file_blockers:
                                file_blockers.append(_tb)
                            _capped = True
                        if not _u["recognised"]:
                            _tb = (f"{rel}: auto-execution inventory: unrecognised trigger ({_trig}) on the {_u['kind']} surface. {_u['detail']}. "
                                   "The trigger catalogue is a maintained list, not a finished one; an unlisted trigger is behaviour nobody accounted, so it blocks any NO. "
                                   "Next step: account for what runs on this trigger manually, and treat the catalogue entry as a coverage item for the next wave.")
                            if _tb not in file_blockers:
                                file_blockers.append(_tb)
                            _capped = True
                        for _rt in _u["remote_targets"]:
                            _tb = (f"{rel}: auto-execution unit (trigger: {_trig}): this unit runs remote content that is not in this submission ({_rt}). {_u['detail']}. "
                                   "What runs is decided by content fetched at trigger time, so the unit is unaccounted and blocks any NO. This is a reference finding, not a conviction: the remote content was never examined. "
                                   "Next step: vendor the content into the submission so it is examined in the same run, or remove the remote reference.")
                            if _tb not in file_blockers:
                                file_blockers.append(_tb)
                            _capped = True
                        for _lt in _u["local_targets"]:
                            if _lt["resolved"]:
                                continue
                            _tb = (f"{rel}: auto-execution unit (trigger: {_trig}): this unit runs a local file that is not part of this submission and was not examined: {_lt['target']}. {_u['detail']}. "
                                   "A configuration whose command is absent cannot be accounted from the configuration alone, so the unit is unaccounted and blocks any NO. This is a reference finding, not a conviction. "
                                   "Next step: include the named file in the submission so it is examined in the same run.")
                            if _tb not in file_blockers:
                                file_blockers.append(_tb)
                            _capped = True
                        for _cmd in _u["commands"]:
                            _synth = f"{os.path.basename(rel)}.{'py' if _u['dialect'] == 'python' else 'sh'}"
                            _cdata = _cmd.encode("utf-8", "replace")
                            for _f in script_class_findings(_synth, _cdata):
                                _tb = (f"{rel}: auto-execution unit (trigger: {_trig}): {_f['kind']} in a command that runs automatically ({'; '.join(_f['evidence'])}). "
                                       "What this unit does is decided by content that is not in this submission, and the command runs on its trigger with no further user action, so the unit is unaccounted and blocks any NO. "
                                       "Next step: remove the automatic command, or replace the remote stage with content included in this submission so it can be examined.")
                                if _tb not in file_blockers:
                                    file_blockers.append(_tb)
                                _capped = True
                            for _pf in proxy_invocation_findings(_synth, _cdata, entry_basenames):
                                _tb = (f"{rel}: auto-execution unit (trigger: {_trig}): interpreter proxy invocation in a command that runs automatically ({'; '.join(_pf['evidence'])}). "
                                       "What runs is decided by content outside this submission, so the unit is unaccounted and blocks any NO. "
                                       "Next step: include the named script in the submission, or remove the automatic command.")
                                if _tb not in file_blockers:
                                    file_blockers.append(_tb)
                                _capped = True
                            _urefs, _ucomplete, _unote = external_references(_synth, _cdata)
                            for _ref in _urefs:
                                _dstate, _dbasis = _reference_disposition(_ref, entry_basenames)
                                if _dstate == "unresolved":
                                    _tb = (f"{rel}: auto-execution unit (trigger: {_trig}): external reference not accounted for: the command names {_ref['target']} ({_ref['kind']}): {_dbasis}. "
                                           "The command runs automatically on its trigger, so the unit is unaccounted and blocks any NO. This is a reference finding, not a conviction: the referenced content was never examined. "
                                           "Next step: include the referenced content in the submission, or remove the reference from the automatic command.")
                                    if _tb not in file_blockers:
                                        file_blockers.append(_tb)
                                    _capped = True
                        _u["accounted"] = not _capped
                        autoexec_all.append(
                            {"file": rel, "kind": _u["kind"],
                             "trigger": _trig,
                             "recognised": _u["recognised"],
                             "accounted": not _capped})
            # ---- model files and clipboard units (coverage
            # wave 7, 2026-11-24): a pickle stream is a program
            # for a stack machine whose opcodes name callables,
            # and it is walked as bytecode here (disassembly
            # only; nothing in the engine ever unpickles). A
            # safetensors header is checked against the file's
            # actual extent. An ONNX model's operator domains
            # and external tensors are external references under
            # the closure rules. A Keras Lambda layer is code by
            # design. A page's clipboard writes and paste-and-run
            # instructions are script units judged under the
            # script rules. The exemptions mirror waves 1 to 6:
            # byte identity does not depend on any of it, and a
            # failed container is already capped as a unit (a
            # failed 7z gets a naming-only scan for stored
            # pickles, below).
            if failed_container and data[:6] == b"7z\xbc\xaf'\x1c":
                try:
                    _labels = scan_embedded_pickles(data)
                except Exception:
                    _labels = []
                if _labels:
                    _tb = (f"{rel}: this container could not be enumerated, and a raw scan of its stored bytes finds pickle stream(s) naming these callables: {', '.join(_labels)}. "
                           "The container is unaccounted as a unit; the scan names what a stored payload would resolve, and changes nothing about the cap.")
                    if _tb not in file_blockers:
                        file_blockers.append(_tb)
            if not failed_container and rec["reference"] not in ("hash-match", "manifest-match"):
                _member = rel.split("!")[-1]
                _mext = os.path.splitext(_member)[1].lower()
                _st = None
                try:
                    _st = safetensors_accounting(data) if is_safetensors(data) else None
                except Exception:
                    _st = None
                if _st is not None:
                    rec["safetensors"] = {"tensors": _st["tensors"], "payload_bytes": _st["payload_bytes"], "accounted": _st["accounted"]}
                    for _cap in _st["caps"]:
                        _tb = (f"{rel}: safetensors accounting: {_cap}. "
                               "A model file is accounted by its header: tensor extents the header cannot account for are unaccounted bytes, and a header that disagrees with the file cannot certify the file. "
                               "Next step: rebuild the model with a header whose tensor extents match the payload, or supply the file's genuine reference.")
                        if _tb not in file_blockers:
                            file_blockers.append(_tb)
                    if _st["accounted"]:
                        rec["model_accounted"] = True
                        rec["model_kind"] = "safetensors"
                else:
                    _claim = "none"
                    if _mext in (".pkl", ".pickle", ".pck"):
                        _claim = "strict"
                    elif _mext in (".pt", ".pth"):
                        _claim = "soft"
                    _pk = None
                    if _claim != "none" or (data[:1] and data[:1] in b"\x80c(VSNILF})P.\x8c\x8f\x88\x89"):
                        try:
                            _pk = analyze_pickle(data, claim=_claim)
                        except Exception:
                            _pk = None
                    if _pk is not None:
                        rec["pickle"] = {"callables": _pk["callables"], "complete": _pk["complete"], "persids": _pk["persids"], "trailing_bytes": _pk["trailing_bytes"], "accounted": _pk["accounted"]}
                        if _pk["chain"]:
                            _danger = [f"{c['module']}.{c['name']}" for c in _pk["callables"] if c["tier"] == "dangerous" and c["invoked"]]
                            if not any(y["file"] == rel and y["chain"] == "pickle-code-execution" for y in yes_reasons):
                                yes_reasons.append({"file": rel, "chain": "pickle-code-execution",
                                                    "name": "pickle stream invokes a code-execution callable on load (" + ", ".join(_danger) + ")",
                                                    "evidence": [f"callable {d} is invoked by a REDUCE, INST, OBJ or NEWOBJ opcode in the stream's disassembly walk" for d in _danger]})
                        for _cap in _pk["caps"]:
                            _tb = (f"{rel}: pickle accounting: {_cap}. "
                                   "A pickle stream is a program: loading it runs the callables its opcodes name, so a stream whose callables cannot all be accounted is unaccounted code, never data. "
                                   "Next step: re-export the model in a data-only format (safetensors), or supply the stream's genuine reference.")
                            if _tb not in file_blockers:
                                file_blockers.append(_tb)
                        if _pk["accounted"]:
                            rec["model_accounted"] = True
                            rec["model_kind"] = "pickle"
                if _mext == ".onnx":
                    try:
                        _ox = onnx_accounting(data, entry_basenames)
                    except Exception:
                        _ox = None
                    if _ox is None:
                        _tb = (f"{rel}: ONNX accounting: the file claims the ONNX format but no model graph could be read from its protobuf structure, so its content is unaccounted. "
                               "Next step: re-export the model so its graph parses, or supply the file's genuine reference.")
                        if _tb not in file_blockers:
                            file_blockers.append(_tb)
                    else:
                        rec["onnx"] = {"nodes": _ox["nodes"], "external_refs": _ox["external_refs"], "accounted": _ox["accounted"]}
                        for _cap in _ox["caps"]:
                            _tb = (f"{rel}: ONNX accounting: {_cap}. "
                                   "A model is accounted when every operator resolves inside the standard set and every tensor's data is present; an operator or tensor that resolves outside the submission is unaccounted. "
                                   "Next step: vendor the named library or tensor file into the submission, or re-export with standard operators and embedded tensors.")
                            if _tb not in file_blockers:
                                file_blockers.append(_tb)
                        if _ox["accounted"]:
                            rec["model_accounted"] = True
                            rec["model_kind"] = "onnx"
                if _mext == ".json":
                    try:
                        _lambdas = keras_lambda_findings(data)
                    except Exception:
                        _lambdas = []
                    for _lp in _lambdas:
                        _tb = (f"{rel}: Keras Lambda layer at {_lp}: a Lambda layer carries a serialised Python function, which is code by design, and configuration accounting cannot account for code. "
                               "The layer is unaccounted and blocks any NO. "
                               "Next step: replace the Lambda layer with a standard layer, or extract the function and submit it as a script unit for judgement.")
                        if _tb not in file_blockers:
                            file_blockers.append(_tb)
                _is_html = _mext in (".html", ".htm") or data[:1024].lower().find(b"<html") >= 0 or data[:1024].lower().find(b"<!doctype html") >= 0
                if _is_html:
                    try:
                        _cb = clipboard_units(data.decode("utf-8", "replace"))
                    except Exception:
                        _cb = None
                    if _cb is not None and (_cb["units"] or _cb["in_text_commands"]):
                        rec["clipboard"] = {"units": [{"kind": u["kind"], "resolution": u["resolution"]} for u in _cb["units"]], "framing": _cb["framing"]}
                        for _u in _cb["units"]:
                            if _u["resolution"] == "remote":
                                _tb = (f"{rel}: clipboard unit ({_u['kind']}): the content written to the reader's clipboard is fetched from a remote source at page time, so what the reader would paste is not in this submission and is unaccounted. "
                                       "A clipboard payload assembled remotely is a script unit whose code was never examined. "
                                       "Next step: inline the exact clipboard content in the page so it is examined in the same run, or remove the clipboard write.")
                                if _tb not in file_blockers:
                                    file_blockers.append(_tb)
                            elif _u["resolution"] == "unresolvable":
                                _tb = (f"{rel}: clipboard unit ({_u['kind']}): the content written to the reader's clipboard could not be resolved from the page's source, so what the reader would paste is unaccounted. "
                                       "Next step: inline the exact clipboard content in the page so it is examined in the same run, or remove the clipboard write.")
                                if _tb not in file_blockers:
                                    file_blockers.append(_tb)
                            elif _u.get("cradle"):
                                if not any(y["file"] == rel and y["chain"] == "clickfix-paste-and-run" for y in yes_reasons):
                                    yes_reasons.append({"file": rel, "chain": "clickfix-paste-and-run",
                                                        "name": "page writes a fetch-and-execute command to the clipboard for the reader to paste and run",
                                                        "evidence": ["clipboard content: " + (_u["content"] or "")[:200]]})
                            elif _cb["framing"] == "strong" and _u.get("content") and re.search(r"\b(powershell|cmd|pwsh|mshta|rundll32|regsvr32|notepad|calc|wscript|cscript|bash|sh|curl|wget)\b|\.(exe|bat|cmd|ps1|vbs|js|sh)\b", _u["content"], re.IGNORECASE):
                                _tb = (f"{rel}: clipboard unit ({_u['kind']}): the page pairs paste-and-run instruction framing with a clipboard command ({(_u['content'] or '')[:120]}). "
                                       "The command itself is fully present and is not a fetch-and-execute cradle, so this is a framing finding, not a conviction: the unit is unaccounted until the instruction framing is removed or the command is accounted as a script. "
                                       "Next step: remove the paste-and-run instructions, or submit the command as a standalone script unit.")
                                if _tb not in file_blockers:
                                    file_blockers.append(_tb)
                        if _cb["framing"] == "strong" and _cb["in_text_cradle"]:
                            if not any(y["file"] == rel and y["chain"] == "clickfix-paste-and-run" for y in yes_reasons):
                                yes_reasons.append({"file": rel, "chain": "clickfix-paste-and-run",
                                                    "name": "page instructs the reader to paste and run a fetch-and-execute command",
                                                    "evidence": ["instruction text: " + _cb["in_text_commands"][0][:200] if _cb["in_text_commands"] else "paste-and-run framing with an in-text cradle"]})
                        elif _cb["framing"] == "strong" and _cb["in_text_commands"] and not any(u["resolution"] == "literal" for u in _cb["units"]):
                            _tb = (f"{rel}: instruction accounting: the page pairs paste-and-run instruction framing (fake verification or Run-dialog instructions) with a command in its visible text ({_cb['in_text_commands'][0][:120]}). "
                                   "The command is fully present and is not a fetch-and-execute cradle, so this is a framing finding, not a conviction: the instruction unit is unaccounted until the framing is removed or the command is accounted as a script. "
                                   "Next step: remove the paste-and-run instructions, or present the command as documentation without run instructions.")
                            if _tb not in file_blockers:
                                file_blockers.append(_tb)
            # ---- truncation markers: analysis caps that cut material
            # a NO would depend on are explicit unaccounted markers.
            # A file accounted by byte identity (hash match against a
            # reference, or a strong manifest hash) does not depend
            # on the truncated analysis, so those files are exempt;
            # every other NO path does depend on it.
            for _t in rep.get("truncations") or []:
                if rec["reference"] in ("hash-match", "manifest-match") or container_entry or failed_container:
                    continue
                tb = f"{rel}: analysis was truncated: {_t}. A verdict of NO would claim this file was fully accounted for; with part of the analysis cut, the unexamined remainder is unaccounted."
                if tb not in file_blockers:
                    file_blockers.append(tb)
            file_yes = [y for y in yes_reasons if y["file"] == rel]
            if file_yes:
                rec["verdict"] = "YES: MALWARE (PROVEN)"
                rec["why"].append("Malicious behaviour proven: " + "; ".join(y["name"] for y in file_yes))
                # A proven chain does not erase the file's named
                # blockers: an unresolved target on the same file
                # (a dynamically loaded class, an assembly loaded
                # from a remote string) is part of the evidence for
                # this file and must stay on its record and in the
                # report's blocker list, not be dropped because the
                # chain already decided the headline.
                if file_blockers:
                    rec["why"].extend(file_blockers)
                    blockers.extend(file_blockers)
            elif file_blockers:
                rec["verdict"] = "YES: UNACCOUNTED"
                rec["why"].extend(file_blockers)
                blockers.extend(file_blockers)
            else:
                # decide whether this file is fully accounted for
                fmt_name = rec["format"] or ""
                if rec["reference"] == "hash-match":
                    rec["verdict"] = "NO: ACCOUNTED"
                    rec["why"].append("Accounted as genuine: byte-identical to the genuine reference.")
                elif rec["reference"] == "manifest-match":
                    rec["verdict"] = "NO: ACCOUNTED"
                    rec["why"].append("Accounted as genuine: hash equality with the reference manifest for this file.")
                elif rec["reference"] == "differs-from-reference":
                    rec["verdict"] = "NO: ACCOUNTED"
                    rec["why"].append("Accounted: every differing region against the genuine reference is classified expected-crack or benign-repack in the diff ledger, and no malicious capability chain exists.")
                elif sig_valid:
                    # Coverage wave 8 provenance rule, formalised.
                    # Provenance (signature state, publisher identity,
                    # attestations, reputation lookups) is report
                    # context and is consumed toward a verdict only as
                    # byte identity for the very file it signs: a
                    # verifying Authenticode signature proves these
                    # bytes are byte-identical to the bytes whose
                    # digest the signature carries, which is an
                    # accounting fact about identity, not character
                    # evidence about the signer. This branch is
                    # reachable only when the file carries no proven
                    # chain and no blocker, so a signature can never
                    # outweigh, soften or skip any finding: chains are
                    # decided first, blockers second, and every
                    # accounting gate (byte ownership, dual parser,
                    # BYOVD capabilities, certificate-table content,
                    # member semantics, sideload composites) speaks as
                    # a blocker on this same file before this branch is
                    # reached. Signer identity is consumed nowhere:
                    # pe_signature returns no publisher name, and the
                    # sideload pass reads signature state only to add
                    # scrutiny (a composite pairing), never to remove
                    # it. The named, bounded exception this retention
                    # carries is recorded in
                    # validation/COVERAGE-WAVE-8-LOG.md.
                    rec["verdict"] = "NO: ACCOUNTED"
                    rec["why"].append("Accounted by byte identity: this file's digest matches the digest carried in its embedded signature and the signature verifies, and no behaviour finding, blocker or capability chain exists for this file. The signature is identity evidence for this file's bytes only: it outweighs no finding, softens no cap, and covers no other file.")
                elif kg and not kg_bad:
                    rec["verdict"] = "NO: ACCOUNTED"
                    rec["why"].append("Accounted as expected crack: a keygen or patcher that only generates keys. No network, no persistence, no injection, no dropper behaviour. The key algorithm is circumvention, not malware.")
                elif rec.get("bytecode_accounted"):
                    rec["verdict"] = "NO: ACCOUNTED"
                    rec["why"].append(f"Accounted: this file's bytecode was parsed and accounted at method level by the coverage wave 2 bytecode accounting ({rec.get('bytecode_kind')}): every method body was decoded, and every reference, dynamic load and embedded unit in it is resolved or enumerated in this report, with no malicious chain.")
                elif rec.get("model_accounted"):
                    rec["verdict"] = "NO: ACCOUNTED"
                    rec["why"].append(f"Accounted: this file's model content was accounted by the coverage wave 7 model accounting ({rec.get('model_kind')}): every callable the stream names, every tensor extent the header declares, and every operator and external reference in it is resolved or enumerated in this report, with no malicious chain.")
                elif fmt_name in ("script", "text / script"):
                    rec["verdict"] = "NO: ACCOUNTED"
                    rec["why"].append("Accounted: this is a script or text file, so it was fully reverse-engineered by reading all of its source. Every behaviour in it is enumerated in this report and classified expected-crack or benign, with no malicious chain.")
                elif fmt_name not in ("PE", "ELF", "Mach-O"):
                    rec["verdict"] = "NO: ACCOUNTED"
                    rec["why"].append("Accounted as data: the file was fully read, it is not executable code, and it carries no malicious capability.")
                elif container_entry:
                    # A fully enumerated container whose own format is
                    # an executable format (a fat Mach-O bundle): the
                    # members or slices are the judged units, each
                    # verdicted on its own record above, so the
                    # bundle is accounted when every unit inside it
                    # is. The compiled-binary rule below judges
                    # content, and this file's content is its slices.
                    rec["verdict"] = "NO: ACCOUNTED"
                    rec["why"].append("Accounted as a fully enumerated container: every slice or member inside it was extracted and verdicted as its own unit in this report, and no unit inside it is unaccounted.")
                else:
                    # A compiled binary with no reference and no
                    # verifying signature is unaccounted, period.
                    # Patch-like signals (a NOP run, license or crack
                    # strings) are recorded in the patch evidence as
                    # annotation, but they are not an accounting: a
                    # NOP run is also ordinary alignment padding, and
                    # a license string appears in every licensed
                    # program. The earlier patch-evidence NO path
                    # acquitted a clean compiler hello-world on
                    # exactly those signals (2026-11-24 accuracy
                    # audit, defect 1).
                    if patch_ev:
                        msg = (f"{rel}: this compiled binary cannot be accounted for. It does not match a genuine reference and its signature does not verify. "
                               "Patch-like signals were found in the file (see patch evidence), but those signals are annotation, not an accounting: a NOP run is also ordinary alignment padding, and license or crack strings appear in ordinary licensed programs. Its bytes are unaccounted. "
                               "Next step: supply the genuine original with --reference so every differing byte can be classified, or a publisher signature that verifies.")
                    else:
                        msg = (f"{rel}: this compiled binary cannot be accounted for. It does not match a genuine reference, its signature does not verify, and no crack patch could be identified in it. "
                               "Its bytes are unaccounted. Next step: supply the genuine original with --reference so every differing byte can be classified, or a publisher signature that verifies.")
                    rec["verdict"] = "YES: UNACCOUNTED"
                    rec["why"].append(msg)
                    blockers.append(msg)
            files_out.append(rec)

    # ---- bytecode reconciliation (coverage wave 2): facts that only
    # exist across units of one package. A JAR's declared Main-Class
    # must be one of the enumerated class members, or the entry point
    # the JAR declares was never examined. An APK manifest's declared
    # components must be declared in the DEX files of the same
    # package, or the component the manifest promises has no examined
    # code behind it. A mismatch is recorded on the JAR's or the
    # manifest's own record with the same force as a per-file
    # blocker, in the same style as the DLL triad pass below.
    _bc_groups = {}
    for f in files_out:
        _rel = f["path_in_release"]
        _key = _rel.split("!")[0] if "!" in _rel else os.path.dirname(_rel)
        _bc_groups.setdefault(_key, []).append(f)
    for _key, _members in _bc_groups.items():
        _dex_classes = set()
        for f in _members:
            if f.get("bytecode_kind") == "dex":
                for _cn in (f.get("bytecode") or {}).get("classes") or []:
                    _dex_classes.add(_cn)
        for f in _members:
            _bc = f.get("bytecode") or {}
            if f.get("bytecode_kind") == "jar" and _bc.get("main_class"):
                _mc = _bc["main_class"]
                # Presence is by member resource path inside this
                # JAR: the launcher resolves Main-Class to the
                # resource com/example/Hello.class, so a class file
                # stored under any other member name does not
                # satisfy the declaration, whatever class its bytes
                # define. (The JAR's own record groups under its
                # directory while its members group under the JAR
                # path, so the members are gathered by path prefix
                # from the whole release, not from _members.)
                _jar_rel = f["path_in_release"]
                _present = any(m["path_in_release"].split("!", 1)[1] in
                               (_mc.replace(".", "/") + ".class", _mc + ".class")
                               for m in files_out
                               if m["path_in_release"].startswith(_jar_rel + "!"))
                if not _present:
                    _msg = (f"{f['path_in_release']}: bytecode accounting (jar): the manifest declares Main-Class {_mc}, "
                            "but no class file for it is among the enumerated members, so the JAR's declared entry point was never examined and is unaccounted.")
                    if f["verdict"].startswith("NO"):
                        f["verdict"] = "YES: UNACCOUNTED"
                    f["why"].append(_msg)
                    if _msg not in blockers:
                        blockers.append(_msg)
            if f.get("bytecode_kind") == "axml" and _dex_classes:
                _pkg = _bc.get("package")
                for _comp in _bc.get("components") or []:
                    _full = _comp["name"]
                    if _full.startswith("."):
                        _full = (_pkg or "") + _full
                    elif "." not in _full:
                        _full = ((_pkg + ".") if _pkg else "") + _full
                    if _full not in _dex_classes:
                        _msg = (f"{f['path_in_release']}: bytecode accounting (apk): the manifest declares component {_comp['kind']} {_full}, "
                                "but no DEX file in this package declares that class, so the component's code was never examined and is unaccounted.")
                        if f["verdict"].startswith("NO"):
                            f["verdict"] = "YES: UNACCOUNTED"
                        f["why"].append(_msg)
                        if _msg not in blockers:
                            blockers.append(_msg)

    # ---- DLL sideload triad, judged at folder level: a signed EXE, an
    # unsigned same-folder DLL that is not the genuine file, and an
    # encrypted sidecar the DLL feeds on. A legitimate scene emulator
    # DLL is functionally accounted API by API and carries no sidecar,
    # so the triad never fires on the emulator pattern. ----
    folders = {}
    for f in files_out:
        folders.setdefault(os.path.dirname(f["path_in_release"]), []).append(f)
    for _folder, members in folders.items():
        signed_exes = [m for m in members if m.get("format") == "PE" and m.get("signed") and not m["name"].lower().endswith((".dll", ".sys"))]
        sidecars = [m for m in members if m.get("format") == "unknown binary data" and m["size_bytes"] >= 64]
        if not signed_exes or not sidecars:
            continue
        for m in members:
            if not m["name"].lower().endswith((".dll", ".dylib")):
                continue
            if m.get("signed") or m.get("reference") == "hash-match":
                continue
            if any(y["file"] == m["path_in_release"] for y in yes_reasons):
                continue
            yes_reasons.append({"file": m["path_in_release"], "chain": "dll-sideload-triad",
                                "name": "DLL sideload triad: a signed executable, an unsigned same-name DLL beside it that is not the genuine file, and an encrypted sidecar data file in one folder. The executable is clean; the planted DLL is the loader. A legitimate emulator DLL is accounted against its known release and carries no encrypted sidecar",
                                "evidence": [f"signed executable: {signed_exes[0]['name']}",
                                             f"unsigned DLL, not hash-matched to the genuine file: {m['name']}",
                                             f"encrypted sidecar (unrecognised format, {sidecars[0]['size_bytes']} bytes): {sidecars[0]['name']}"]})
            m["verdict"] = "YES: MALWARE (PROVEN)"
            m["chains"] = list(m.get("chains", [])) + ["dll-sideload-triad"]
            m["why"].append("DLL sideload triad proven at folder level: signed executable plus unsigned replacement DLL plus encrypted sidecar.")

    # ---- sideload composites (coverage wave 6, 2026-11-24):
    # the general import-resolution case of the triad above.
    # Where a signed host executable resolves an import (or a
    # delay import) to a file in the same folder, the pair is
    # judged as a composite: the loaded unit is judged alone on
    # its own record, the host's signature covers the host only,
    # and an unaccounted loaded unit caps the pair with the
    # loading relationship named. This is the shape of the
    # signed-host cases in the field (a genuine signed host
    # beside a planted library the host loads by name): judged
    # per file, the host is genuinely clean and the library is
    # somebody else's problem; judged as a composite, the pair
    # is the unit that runs. An import that resolves to no file
    # in the folder and is not a known system library is
    # recorded on the host's record as an unresolved import: it
    # resolves outside this submission, and the host alone is
    # not capped for it.
    for _folder, _members in folders.items():
        _by_base = {m["name"].lower(): m for m in _members}
        for host in _members:
            _pi = host.get("pe_imports")
            if not _pi or not host.get("signed"):
                continue
            if host["name"].lower().endswith((".dll", ".sys")):
                continue
            _comp = {"pairs": [], "unresolved_imports": []}
            for _kind, _names in (("import", _pi["imports"]),
                                  ("delay-import", _pi["delay_imports"])):
                for _dll in _names:
                    _tgt = _by_base.get(_dll.lower())
                    if _tgt is None:
                        if _dll.lower() not in SYSTEM_DLLS and not _dll.lower().startswith(("api-ms-", "ext-ms-")):
                            _comp["unresolved_imports"].append(
                                {"library": _dll, "kind": _kind})
                        continue
                    if _tgt is host:
                        continue
                    _status = "accounted" if _tgt["verdict"].startswith("NO") else "unaccounted"
                    _comp["pairs"].append(
                        {"library": _dll, "kind": _kind,
                         "loaded": _tgt["path_in_release"],
                         "status": _status})
                    if _status == "unaccounted":
                        _tb = (f"{host['path_in_release']}: sideload composite: this signed executable {_kind}s {_dll}, which resolves to the same-folder file {_tgt['path_in_release']}; that file is not accounted (its verdict: {_tgt['verdict']}), and this host's signature covers this host only, never the unit it loads. "
                               "The pair is judged as a composite: the loaded unit is judged on its own record, and because it is unaccounted, the pair is unaccounted and blocks any NO. This is a composition finding, not a conviction about either file alone. "
                               "Next step: account for the loaded unit (supply the genuine original so it can be matched, or a signature for it that verifies), or remove it from the folder.")
                        if host["verdict"].startswith("NO"):
                            host["verdict"] = "YES: UNACCOUNTED"
                        host["why"].append(_tb)
                        blockers.append(_tb)
            if _comp["unresolved_imports"]:
                _names = ", ".join(
                    f"{u['library']} ({u['kind']})"
                    for u in _comp["unresolved_imports"])
                host["why"].append(
                    f"Sideload record: this signed executable imports {_names}, which are not in this folder and are not known system libraries: they resolve outside this submission (an installed library or a system copy under a name this build does not catalogue), recorded here because what the host loads is part of its accounting. The host is not capped for an absent import alone.")
            if _comp["pairs"] or _comp["unresolved_imports"]:
                host["sideload"] = _comp

    # Provenance: scene groups have no websites, so a group-site claim
    # makes the claimed provenance impossible and the release
    # unaccounted as that group's release.
    provenance = provenance_findings(text_blobs) if text_blobs else []
    for pf in provenance:
        blockers.append(f"Provenance: {pf['detail']} Claimed site: {pf['url']}")
    # Release-internal manifests: self-consistency only. A mismatch
    # means the bytes do not even match the release's own manifest, so
    # they are unaccounted. A match is noted, never treated as genuine.
    manifest_notes = []
    by_base = {}
    for f in files_out:
        by_base.setdefault(os.path.basename(f["path_in_release"]), f)
    for mrel, mk, entries_map in release_manifests:
        for fname, expected in entries_map.items():
            target = by_base.get(os.path.basename(fname))
            if target is None:
                manifest_notes.append(f"Manifest {mrel} lists {fname}, which is not present in the release.")
                continue
            actual = target["crc32"] if len(expected) == 8 else target["hashes"]["md5"] if len(expected) == 32 else target["hashes"]["sha1"] if len(expected) == 40 else target["sha256"]
            if actual != expected:
                blockers.append(f"Manifest mismatch: {fname} does not match the release's own manifest {mrel} ({actual} vs {expected}), so those bytes are unaccounted.")
            else:
                manifest_notes.append(f"Manifest {mrel}: {fname} matches. Self-consistency only: this proves the file matches what the release claims, not that it is genuine.")

    # files in the reference but missing from the release: note, not a blocker
    notes = []
    notes.extend(manifest_notes)
    if ref_map:
        release_hashes = {f["sha256"] for f in files_out}
        for key, rec in ref_map.items():
            if key.startswith("sha:") or key.startswith("base:"):
                continue
            if rec["sha256"] not in release_hashes and all(f["path_in_release"] != key for f in files_out):
                notes.append(f"Reference file {key} is not present in the release. A missing file cannot carry malware into the release, so this is noted, not blocking.")

    # ---- behaviour ledger: static-predicted effects per file, with the
    # genuine baseline diff applied when a reference was provided ----
    behaviour_ledger = []
    sample_effects = set()
    for f in files_out:
        for ef in f.get("behaviour_effects", []):
            behaviour_ledger.append({"file": f["path_in_release"], **ef})
            sample_effects.add((ef["category"], ef["effect"]))
    behaviour_diff = {
        "sample_only": sorted(({"category": c, "effect": e} for c, e in (sample_effects - baseline_effects)), key=lambda d: (d["category"], d["effect"])) if reference else [],
        "baseline_only": sorted(({"category": c, "effect": e} for c, e in (baseline_effects - sample_effects)), key=lambda d: (d["category"], d["effect"])) if reference else [],
        "note": ("Static-predicted effects, diffed against the genuine reference baseline. Effects the genuine program also has are baseline, not findings. A crack removing the vendor activation call appears in baseline_only and is expected: that removal is the crack. Observed-live behaviour entries come from sandbox ingestion and are marked SERVICE/HANDOFF in CAPABILITY-MATRIX.md." if reference else "No reference provided, so no baseline diff was applied. Observed-live behaviour entries come from sandbox ingestion (SERVICE/HANDOFF)."),
    }
    manifest_tree = hashlib.sha256("".join(sorted(f["sha256"] for f in files_out)).encode()).hexdigest()

    elapsed = round(time.perf_counter() - started, 3)
    if yes_reasons:
        headline = HEADLINE_YES
        verdict_word = "YES"
        reason_class = REASON_PROVEN
    elif blockers:
        headline = HEADLINE_YES
        verdict_word = "YES"
        reason_class = REASON_UNACCOUNTED
        missing = list(blockers)
        for b in blockers:
            if "Next step:" in b:
                next_steps.append(b.split("Next step:", 1)[1].strip())
        if not next_steps:
            next_steps.append("Supply the genuine original with --reference so every differing byte can be classified, open any unopened archive layer (a password-protected inner archive that cannot be opened stays unaccounted), or extract any unopened installer with a parser adapter and run the verdict on the extracted folder.")
    else:
        headline = HEADLINE_NO
        verdict_word = "NO"
        reason_class = REASON_ACCOUNTED

    if reason_class == REASON_PROVEN:
        eli5 = ["Yes, this one has a thief inside.",
                "We took the whole thing apart, piece by piece.",
                "One of the pieces does a bad thing that no honest program needs to do.",
                "The grown up part of this report shows the exact piece and the proof.",
                "Do not run it. Delete it, and get the program from a place you trust."]
        for fn in dict.fromkeys(os.path.basename(y["file"]) for y in yes_reasons):
            eli5.append(f"The bad piece is in {fn}.")
    elif reason_class == REASON_UNACCOUNTED:
        eli5 = ["Yes. We have to say yes, because we cannot account for every piece.",
                "That is not the same as proving a piece is bad. It means a piece is unaccounted for.",
                "We took the whole thing apart, piece by piece.",
                "The grown up part of this report lists each unaccounted piece, and what would account for it.",
                "Do not run it. A piece we cannot read could hide a thief, and we will not guess and say no."]
    else:
        eli5 = ["No, we checked every part and found no thief.",
                "We took the whole thing apart, piece by piece.",
                "Every piece is accounted for. It is a piece of the real program, or a crack piece we can point at and explain.",
                "No piece does a bad thing that no honest program needs to do."]

    plain = [f"Headline: {headline}"]
    plain.append(f"Reason class: {reason_class}")
    plain.append(f"Subject: {path} ({len(files_out)} file(s) enumerated and analysed in {elapsed} seconds).")
    if installer["is_installer_or_archive"]:
        plain.append(f"This subject is an installer or archive ({installer['kind']}). Contents and drop list are in this report.")
    if reason_class == REASON_PROVEN:
        plain.append("Malware was proven, not suspected. Each proof below names the file, the behaviour chain, and the evidence. Circumvention itself was not counted: the patched check, the keygen algorithm and any KMS emulation are the expected crack, and they appear in the accounting, not in the proof.")
    elif reason_class == REASON_UNACCOUNTED:
        plain.append("Reason class UNACCOUNTED: this YES is not proven malware, and this report does not call it that. It means one or more bytes, files, scripts or archive layers could not be accounted for as genuine or as the explained crack. Event Zero fails closed: the only other headline is NO, and NO must be earned by full accounting, so an unaccounted release gets YES with the gaps named.")
        plain.append("Unaccounted items are listed exactly in this report, with the next step that would account for each one.")
    else:
        plain.append(NO_CLAIM)

    # ---- case lifecycle state (certainty research, sections 7 to 9):
    # the verdict tokens are YES and NO only. OPEN is a case lifecycle
    # state, not a verdict and never an in-between answer: when the
    # ledger is incomplete and no proof chain has closed, the case is
    # OPEN, the safety headline stays fail-closed YES (UNACCOUNTED),
    # and the report lists the open items, the rungs tried, and the
    # next rung. OPEN is never rendered as safe and never as a score.
    if reason_class == REASON_PROVEN:
        case_state = "YES"
    elif reason_class == REASON_UNACCOUNTED:
        case_state = "OPEN"
    else:
        case_state = "NO"
    if reference:
        ref_desc = f"reference {reference} (provenance: supplied by the user as the genuine original; per-file reference hashes are recorded in the per-file table)"
    else:
        ref_desc = "no external reference (accounting rests on signature verification, manifest equality, patch identification and full decoding, as recorded per file)"
    if case_state == "NO":
        scope_sentence = (f"Scope: every byte of artefact {os.path.basename(str(path))} (manifest tree SHA-256 {manifest_tree}), and all code accounted under static analysis and emulation traces on this host, is accounted as genuine or explained crack relative to {ref_desc}. The sample was never executed on the host. This NO is certainty about that accounting claim for this artefact and this reference, not a claim about any other build or any other environment.")
    elif case_state == "YES":
        scope_sentence = (f"Scope: this YES asserts that the exhibited proof chain is present in artefact {os.path.basename(str(path))} (manifest tree SHA-256 {manifest_tree}). It does not assert attribution, and it does not assert that no other chains exist.")
    else:
        scope_sentence = (f"Scope: this case is OPEN, with {len(blockers)} open item(s) listed in this report. OPEN is a case lifecycle state, not a verdict: the verdict tokens are YES and NO only, and an OPEN case is never rendered as safe. The headline stays fail-closed YES (UNACCOUNTED) until a proof chain closes or the ledger completes.")
    plain.append(scope_sentence)
    escalation_ladder = []
    next_rung = None
    if case_state == "OPEN":
        joined_blockers = " ".join(blockers).lower()
        if "reference" in joined_blockers:
            next_rung = 6
        elif "virtualiz" in joined_blockers:
            next_rung = 4
        elif "installer" in joined_blockers or "archive" in joined_blockers or "password" in joined_blockers:
            next_rung = 5
        else:
            next_rung = 4
        rung_defs = [
            (0, "Identity and inventory", "Hash, format parse, section and overlay inventory, signature check, reference lookup by hash", "tried"),
            (1, "Static accounting", "Byte diff against the genuine reference, crack-explainer matching, capability scan, strings, imports and entropy map", "tried"),
            (2, "Recursive unpacking and deobfuscation", "Generic and specific unpackers, layer-by-layer re-inventory, each new layer capability scanned", "tried"),
            (3, "Emulation traces", "CPU and OS emulation of unaccounted regions, API tracing, forced branch exploration on guard checks", "partially tried (entry-stub and shellcode emulation where a region was identified)"),
            (4, "Symbolic and handler analysis", "Directed symbolic execution at unresolved branches, C2 dispatchers, config decoders and trigger checks", "not tried"),
            (5, "Sandbox detonation, environment matrix", "Detonation across environments (CAPE ingestion is supported), locale, time and network personalities, downloaded stages recursively ledgered", "not tried"),
            (6, "Reference acquisition and re-diff", "Hunt the genuine reference from vendor, registry or archive sources, verify provenance, re-run the diff", "not tried"),
            (7, "Human analyst and community rules", "Analyst reverse engineering of the residual named items only, new atoms and explainers authored and upstreamed", "not tried"),
        ]
        escalation_ladder = [{"rung": n, "name": name, "action": action,
                              "status": "next" if n == next_rung else status}
                             for n, name, action, status in rung_defs]

    # ---- environment coverage, as a number (elite-analyst adoption):
    # coverage is reported, never implied. Environments and paths not
    # covered are listed, not omitted.
    environment_coverage = {
        "files_total": len(files_out),
        "files_statically_analysed": len(files_out),
        "files_emulated": emu_stats["files_emulated"],
        "instructions_emulated": emu_stats["instructions_emulated"],
        "entry_stub_traces": emu_stats["entry_stub_traces"],
        "environments_covered": [
            "static analysis of every file (parsing, strings, capabilities, diff accounting)",
            "CPU emulation of identified shellcode regions and protector entry stubs (Unicorn; no system calls are serviced, so code that needs an OS is listed as a gap, not guessed)",
        ],
        "environments_not_covered": [
            "full operating system execution on any Windows or macOS version (the sample is never executed on this host)",
            "locale, date and time variations, including future dates that arm time-gated payloads",
            "network personalities: live internet, simulated command and control, or offline",
            "domain-joined state, installed-software states, and user-interaction states",
        ],
        "statement": (f"Coverage: {len(files_out)} of {len(files_out)} files statically analysed; "
                      f"{emu_stats['files_emulated']} file(s) emulated ({emu_stats['instructions_emulated']} instructions, "
                      f"{emu_stats['entry_stub_traces']} entry-stub trace(s)); 0 operating-system environments executed. "
                      f"Behaviour that only appears under an uncovered environment is not guessed: it is what the escalation ladder and the residual pack are for."),
    }

    # ---- residual pack (elite-analyst adoption): for an OPEN case,
    # this is the defined human handoff format. The analyst is handed
    # only the residual: each unaccounted item with its ranges and
    # evidence and the specific question to adjudicate, never the
    # whole file.
    residual_pack = []
    if case_state == "OPEN":
        for b in blockers:
            residual_pack.append({"file": b.split(":", 1)[0] if ":" in b else str(path),
                                  "kind": "unaccounted-item", "ranges": [],
                                  "evidence": [b],
                                  "question": "Adjudicate this item: prove what these bytes do, supply the genuine reference or a verifying signature, or decode the named region, then re-run The Verdict.",
                                  "next_rung": next_rung})
        for le in diff_ledger_all:
            if le.get("classification") == "unaccounted":
                residual_pack.append({"file": le.get("file", str(path)), "kind": "unaccounted-diff-region",
                                      "ranges": [le.get("new_range")],
                                      "evidence": [le.get("reason", ""), f"crack pattern matched: {le.get('crack_pattern')}",
                                                   f"region capability check: {le.get('region_capability_check')}"],
                                      "question": "Adjudicate this differing region: is the change the explained crack, and does it add any capability the genuine region did not have?",
                                      "next_rung": next_rung})

    result = {
        "tool": "Event Zero", "version": "3.0.0", "report_type": "verdict",
        "subject": str(path), "reference": str(reference) if reference else None,
        "headline": headline, "verdict": verdict_word, "reason_class": reason_class,
        "case_state": case_state, "scope": scope_sentence,
        "open_items": list(blockers) if case_state == "OPEN" else [],
        "escalation_ladder": escalation_ladder, "next_rung": next_rung,
        "environment_coverage": environment_coverage,
        "residual_pack": residual_pack,
        "elapsed_seconds": elapsed,
        "pipeline_order": ["enumerate release and extract archives/installers to the bottom",
                           "unpack, multi-layer decode, carve embedded payloads",
                           "evasion analysis", "capability analysis of every file and every carved payload",
                           "malicious chain judgement", "the scope test against each file's claimed function",
                           "reference diff, manifest equality and patch identification",
                           "known-bad hash check", "accounting: every byte genuine, expected-crack, benign-repack, proven malicious, or unaccounted"],
        "files": files_out,
        "installer": installer,
        "manifest": {"schema": "eventzero.manifest/1", "tree_sha256": manifest_tree, "entries": len(files_out),
                     "format": "JSON Lines: header, per-entry records with container parent chain and per-stream hashes, footer with tree hash. Produced by build_manifest_jsonl or the CLI --manifest option.",
                     "inheritance": "Exact: any PROVEN entry makes the release YES-PROVEN, else any UNACCOUNTED entry makes it YES-UNACCOUNTED, else NO."},
        "connection_ledger": connection_ledger,
        "autoexec_inventory": autoexec_all,
        "behaviour_ledger": behaviour_ledger,
        "behaviour_baseline_diff": behaviour_diff,
        "enumeration_aids": enumeration_aids,
        "provenance": provenance,
        "diff_ledger": diff_ledger_all,
        "yes_reasons": yes_reasons,
        "unaccounted": list(blockers),
        "blockers": blockers,
        "missing_proof": missing,
        "next_steps": next_steps,
        "notes": notes,
        "eli5": eli5,
        "plain_english": plain,
        "corroboration": {"note": "NSRL and CIRCL hashlookup presence, antivirus non-detection, and VirusTotal detection counts are corroboration only. They identify known files or generic labels; they never form the basis of a NO, and a generic HackTool or RiskWare count never forms a PROVEN YES. A PROVEN service-based YES needs a specific family on record or family convergence plus locally proven behaviour.",
                          "nsrl_circl": "not queried in this run" if not enrich_known_bad else "queried through the configured enrichment services"},
        "proof_standard": {
            "yes_proven": "Malicious capability or behaviour proven in context: a capability chain (stealer, injection plus payload, download-and-execute, persistence plus command and control, miner, ransomware pattern, backdoor, rootkit hiding), a scope test failure (the first behaviour unnecessary for the claimed function decides it), antivirus tampering, Safe Mode manipulation or reboot-count gating (the Crackonosh pattern), a known-bad family hash hit, or an unaccounted executable difference that carries a proven malicious chain. An unneeded remote download-and-execute capability is itself malicious class.",
            "yes_unaccounted": "Any byte, file, script, archive layer or behaviour that could not be accounted for as genuine or as the explained crack: an unopened or password-protected archive layer, a virtualized region, an unaccounted diff region, an executable that is not part of the genuine program, a compiled binary with no reference, no valid signature and no identified crack patch, or generic-only service detections that need behaviour evidence. UNACCOUNTED is stated plainly as unaccounted, never as proven malware.",
            "no": "Every file byte-identical to a genuine signature-valid original (hash match or reference-manifest hash equality), or a fully reverse-engineered difference classified expected-crack or benign-repack in the diff ledger, with all archive layers unpacked to the bottom. Phrased exactly as the accounting claim: " + NO_CLAIM,
            "circumvention": "Circumvention itself is not malware: patched checks, keygen algorithms, KMS emulation (local emulator service, renewal task, GVLK keys), and hosts-file activation blocks are the expected crack. Antivirus HackTool or CrackTool labels alone never trigger YES.",
        },
    }
    # ---- run receipt: every run emits proof, not just a report. The
    # receipt core is deterministic (no wall-clock durations, no
    # absolute paths) and is signed when EZ_SIGNING_KEY is configured;
    # the LLM narration, when present, is never inside the signed core.
    try:
        from . import signing as _signing
        _ref_hash = None
        if ref_map:
            _ref_hash = hashlib.sha256("".join(sorted({r["sha256"] for r in ref_map.values()})).encode()).hexdigest()
        elif ref_manifest:
            _ref_hash = hashlib.sha256(json.dumps(ref_manifest, sort_keys=True).encode()).hexdigest()
        _receipt = _signing.build_receipt(result,
                                          reference_sha256=_ref_hash,
                                          reference_provenance=("supplied by the user as the genuine original" if reference else None))
        result["receipt"] = _signing.sign_receipt(_receipt)
    except Exception as _e:  # a receipt failure must never change a verdict
        result["receipt"] = {"schema": "eventzero.run-receipt/1", "status": "receipt-error", "note": f"Receipt could not be built: {_e}"}
    # every rendered verdict carries its trust class next to the token
    result["trust_class"] = result["receipt"].get("trust_class", "UNSIGNED")
    return result


def verdict_to_text(v):
    L = []
    L.append("EVENT ZERO: PIRATED SOFTWARE VERDICT")
    L.append("=" * 60)
    L.append(v["headline"])
    L.append(f"Reason class: {v.get('reason_class')}")
    L.append(f"Case state: {v.get('case_state')} (the verdict tokens are YES and NO only; OPEN is a case lifecycle state, not a verdict)")
    _tc = v.get("trust_class", "UNSIGNED")
    try:
        from .signing import TRUST_CLASS_MEANINGS
        _tcm = TRUST_CLASS_MEANINGS.get(_tc, "")
    except Exception:
        _tcm = ""
    L.append(f"Trust class: {_tc}" + (f" ({_tcm})" if _tcm else ""))
    L.append("=" * 60)
    L.append(f"Subject: {v['subject']}")
    if v.get("reference"):
        L.append(f"Genuine reference: {v['reference']}")
    L.append(f"Time taken: {v['elapsed_seconds']} seconds")
    L.append("")
    L.append("0. EXPLAINED LIKE YOU ARE FIVE (ELI5)")
    for s in v["eli5"]:
        L.append(f"  {s}")
    L.append("")
    L.append("1. THE VERDICT IN PLAIN ENGLISH")
    for p in v["plain_english"]:
        L.append(f"  {p}")
    L.append("")
    L.append("2. PER-FILE TABLE")
    for f in v["files"]:
        L.append(f"  {f['path_in_release']}  ({f['size_bytes']} bytes, format: {f.get('format')})")
        L.append(f"    sha256: {f['sha256']}")
        L.append(f"    signed: {f['signed']}  signature valid: {f['signature_valid']}")
        L.append(f"    per-file verdict: {f['verdict']}")
        for w in f["why"]:
            L.append(f"    why: {w}")
        if f["capabilities"]:
            L.append(f"    capabilities: {', '.join(f['capabilities'])}")
        if f["patch_evidence"]:
            L.append("    crack patch evidence:")
            for pe in f["patch_evidence"]:
                L.append(f"      - {pe['detail']}")
        if f["embedded_payloads"]:
            L.append(f"    embedded payloads carved: {f['embedded_payloads']}")
    L.append("")
    L.append("3. INSTALLER AND ARCHIVE DROP LIST")
    inst = v["installer"]
    L.append(f"  Installer or archive: {inst['is_installer_or_archive']}  kind: {inst['kind']}  extracted: {inst['extracted']}")
    for c in inst["drop_list"] or inst["contents"]:
        L.append(f"  - {c}")
    if not (inst["drop_list"] or inst["contents"]):
        L.append("  Not an installer or archive subject.")
    L.append("")
    L.append("4. DIFF LEDGER AGAINST THE GENUINE REFERENCE")
    if v["diff_ledger"]:
        for le in v["diff_ledger"]:
            L.append(f"  {le['file']}: {le['tag']} old bytes {le['old_range']} new bytes {le['new_range']} size change {le['size_change']:+d} => {le['classification']}")
            L.append(f"    {le['reason']}")
    else:
        L.append("  No reference supplied, or every file matched the reference exactly.")
    L.append("")
    L.append("5. PROOF AND ACCOUNTING")
    if v.get("provenance"):
        L.append("  Provenance findings:")
        for pf in v["provenance"]:
            L.append(f"  - [{pf['signal']}] {pf['detail']} Claimed site: {pf['url']}")
    if v["yes_reasons"]:
        L.append("  Malware proof, PROVEN class (any one of these is enough for YES):")
        for y in v["yes_reasons"]:
            L.append(f"  - [{y['chain']}] in {y['file']}: {y['name']}")
            L.append(f"    Evidence: {'; '.join(str(e) for e in y['evidence'])}")
    if v["verdict"] == "NO":
        L.append("  Accounting: " + NO_CLAIM)
        L.append("  Every file in the per-file table carries its own NO: ACCOUNTED line with the reason its bytes are accounted for.")
    if v.get("reason_class") == "UNACCOUNTED":
        L.append("  Unaccounted items (each one blocks NO and is stated plainly as unaccounted, not as proven malware):")
        for m in v["unaccounted"]:
            L.append(f"  - {m}")
        L.append("  Next steps to account for them:")
        for s in v["next_steps"]:
            L.append(f"  - {s}")
    for aid in v.get("enumeration_aids", []):
        L.append(f"  Enumeration aid: {aid['file']} ({aid['kind']}): {aid['note']}")
    for n in v["notes"]:
        L.append(f"  Note: {n}")
    L.append("")
    L.append("6. CONNECTION LEDGER (every link found, classified)")
    if v.get("connection_ledger"):
        for le in v["connection_ledger"]:
            d = le["dest"]
            dest = d.get("url") or d.get("ip") or d.get("domain") or d.get("path")
            L.append(f"  {le['id']}: {dest}  from {le['source_file']}  provenance: {', '.join(le['provenance'])}  class: {le['classification']}  tag: {le['tag']}  observed-live: {le['observed']}")
            if le.get("note"):
                L.append(f"    {le['note']}")
    else:
        L.append("  No links were found in any file.")
    L.append("  Observed-live entries are not produced by this static build: they arrive through sandbox ingestion (CAPE), marked SERVICE/HANDOFF in CAPABILITY-MATRIX.md.")
    L.append("")
    L.append("7. BEHAVIOUR LEDGER (static-predicted effects)")
    if v.get("behaviour_ledger"):
        for be in v["behaviour_ledger"]:
            L.append(f"  {be['file']}: [{be['category']}] {be['effect']} (basis: {be['basis']}, {be['provenance']})")
    else:
        L.append("  No behaviour effects were predicted from the capabilities found.")
    bd = v.get("behaviour_baseline_diff", {})
    if bd.get("sample_only"):
        L.append(f"  Beyond the genuine baseline: {bd['sample_only']}")
    if bd.get("baseline_only"):
        L.append(f"  In the genuine baseline but not the sample (expected crack removals appear here): {bd['baseline_only']}")
    L.append(f"  {bd.get('note', '')}")
    L.append(f"  Manifest tree SHA-256: {v.get('manifest', {}).get('tree_sha256')}")
    L.append("")
    if v.get("escalation_ladder"):
        L.append("8. ESCALATION LADDER FOR THIS OPEN CASE (work list, cheapest applicable rung first)")
        for r in v["escalation_ladder"]:
            marker = "NEXT" if r["rung"] == v.get("next_rung") else r["status"]
            L.append(f"  Rung {r['rung']}: {r['name']} [{marker}]")
            L.append(f"    {r['action']}")
        L.append("  The case is never abandoned and never force-closed: it parks OPEN with a resume condition (a new reference, a new rule pack, a new environment profile, or a reconstructed server) and resumes when the world changes.")
        L.append("")
    if v.get("residual_pack"):
        L.append("8b. RESIDUAL PACK (the human handoff: only the residual, with evidence and the question to adjudicate)")
        for item in v["residual_pack"]:
            L.append(f"  [{item['kind']}] {item['file']} ranges: {item['ranges']}")
            for ev in item["evidence"]:
                L.append(f"    evidence: {ev}")
            L.append(f"    question: {item['question']}")
        L.append("")
    if v.get("environment_coverage"):
        c = v["environment_coverage"]
        L.append("8c. ENVIRONMENT COVERAGE (a number, not an implication)")
        L.append(f"  {c['statement']}")
        L.append(f"  Not covered: {'; '.join(c['environments_not_covered'])}")
        L.append("")
    L.append("9. THE STANDARD THIS VERDICT WAS ISSUED UNDER")
    for k, s in v["proof_standard"].items():
        L.append(f"  {k.upper()}: {s}")
    if v.get("scope"):
        L.append(f"  SCOPE: {v['scope']}")
    L.append("")
    L.append("End of verdict. Nothing was executed on the host. No score and no probability are used anywhere in this verdict, by design.")
    return "\n".join(L) + "\n"


def verdict_to_json(v):
    return json.dumps(v, indent=2, default=str)

def verdict_to_manifest_jsonl(v):
    return build_manifest_jsonl(v)[0]
