"""Capa-style capability rules authored for Event Zero.

Each rule: id, name, attack (id, tactic, technique), evidence sources
(imports, strings, mnemonics, script tokens), plain-English explanation.
Matching is deterministic: a rule fires only on observed evidence, and the
evidence strings are carried into the report.
"""
import re as _re
re = _re

RULES = [
 ("net-socket","Create a network socket","T1071.001","Command and Control","Application Layer Protocol: Web Protocols",["socket","WSASocket","socketpair"],["socket"],["socket"],"Opens a network socket, the first step in talking to another machine."),
 ("net-connect","Connect to a remote host","T1071.001","Command and Control","Application Layer Protocol",["connect","WSAConnect","ConnectEx"],["connect to","connect("],["connect"],"Connects out to an address and port. In malware this is often the command and control channel."),
 ("net-send-recv","Send and receive data over a socket","T1071","Command and Control","Application Layer Protocol",["send","recv","sendto","recvfrom","WSASend","WSARecv"],[],["send","recv"],"Moves data over a network connection, used to receive orders or send stolen data out."),
 ("net-http","Make HTTP requests","T1071.001","Command and Control","Application Layer Protocol: Web Protocols",["InternetOpen","HttpSendRequest","WinHttpSendRequest","curl_easy_perform"],["http://","https://","User-Agent","curl","wget"],[""],"Uses web traffic, which blends in with normal browsing and often passes firewalls."),
 ("net-dns","Resolve hostnames via DNS","T1071.004","Command and Control","Application Layer Protocol: DNS",["gethostbyname","getaddrinfo","DnsQuery"],[],["getaddrinfo"],"Looks up a hostname, typically to find its control server even if the IP changes."),
 ("net-listen","Listen for incoming connections","T1571","Command and Control","Non-Standard Port",["bind","listen","accept"],[],["bind","listen"],"Waits for someone else to connect in. This is backdoor behaviour: the infected machine becomes a server."),
 ("exec-shell","Run shell commands","T1059.004","Execution","Command and Scripting Interpreter: Unix Shell",["system","popen","execl","execve","ShellExecute","CreateProcess","WinExec"],["/bin/sh","/bin/bash","cmd.exe","powershell","os.system","subprocess"],[],"Runs operating system commands, giving the sample the power of a user at a terminal."),
 ("exec-download-run","Download and execute a payload","T1105","Command and Control","Ingress Tool Transfer",[],["curl http","wget http","| sh","| bash","downloadstring","invoke-expression","iex(","urlopen","urllib.request","invoke-webrequest","start-bitstransfer"],[],"Downloads code from the internet and runs it. The file you have is then only a first stage."),
 ("persist-runkey","Persist via registry Run key","T1547.001","Persistence","Boot or Logon Autostart Execution: Registry Run Keys",["RegSetValueEx"],["CurrentVersion\\Run","CurrentVersion/Run"],[],"Adds itself to the Windows Run key so it starts again at every logon."),
 ("persist-file","Create a persistence script or autostart file","T1547","Persistence","Boot or Logon Autostart Execution",[],["persistence.sh","crontab","LaunchAgents","LaunchDaemons","systemd",".bashrc","autostart"],[],"Writes a script or entry whose purpose is to bring the program back after a reboot or logoff."),
 ("persist-schtask","Persist via scheduled task or cron","T1053","Persistence","Scheduled Task/Job",["schtasks"], ["schtasks","crontab","/etc/cron"],[],"Schedules itself to run again on a timer or at logon."),
 ("discovery-identity","Discover user and host identity","T1033","Discovery","System Owner/User Discovery",["getuid","GetUserName","whoami"],["whoami","id;","uname","hostname"],[],"Asks who is logged in and what machine this is. Attackers do this first to value a victim."),
 ("discovery-sysinfo","Gather system information","T1082","Discovery","System Information Discovery",["uname","GetComputerName","GetVersionEx","sysinfo"],["uname -a","system_info","/proc/cpuinfo"],[],"Collects operating system and hardware details, usually sent to the operator or used to pick a payload."),
 ("discovery-process","Enumerate running processes","T1057","Discovery","Process Discovery",["CreateToolhelp32Snapshot","Process32Next","EnumProcesses"],["ps aux","process_list","tasklist"],[],"Lists running processes. Used to find antivirus tools, targets to inject into, or to check it is not already running."),
 ("file-write","Write files to disk","T1105","Impact","Ingress Tool Transfer (file creation evidence)",["fopen","fwrite","CreateFile","WriteFile","open"],[],["fopen","CreateFile"],"Creates or writes files: dropped payloads, logs of stolen data, or persistence scripts."),
 ("file-delete","Delete files (anti-forensics)","T1070.004","Defense Evasion","Indicator Removal: File Deletion",["remove","unlink","DeleteFile","shred"],["rm -f","rm -rf","del /"],[],"Deletes files. In context this is often cleanup of its own traces after running."),
 ("file-chmod-exec","Make a file executable","T1222.002","Defense Evasion","File and Directory Permissions Modification",["chmod","fchmod"],["chmod +x"],[],"Marks a file as executable, the step that turns a downloaded or written file into a runnable program."),
 ("crypto-xor","Encode or decode data with XOR","T1027","Defense Evasion","Obfuscated Files or Information",[],["xor-encoded strings decoded by Event Zero","^ xor","xor key"],[],"XORs data with a key. Legitimate for tiny transforms, classic for hiding addresses, strings, and payloads."),
 ("crypto-aes","Use AES encryption","T1027","Defense Evasion","Obfuscated Files or Information",["CryptEncrypt","BCryptEncrypt","EVP_EncryptInit","AES"],["AES","rijndael"],[],"Encrypts data with AES. In ransomware this encrypts victim files; in loaders it hides the payload or traffic."),
 ("crypto-base64","Encode data with Base64","T1140","Defense Evasion","Deobfuscate/Decode Files or Information",[],["base64","b64decode","FromBase64String"],[],"Base64 encodes or decodes data, a standard way to smuggle payloads and addresses past text filters."),
 ("anti-debug","Check for a debugger or analysis tools","T1622","Defense Evasion","Debugger Evasion",["IsDebuggerPresent","ptrace","CheckRemoteDebuggerPresent"],["ptrace","debugger","vmware","virtualbox","sandbox","wireshark","x64dbg"],[],"Looks for analysts tools or a debugger and may refuse to run or change behaviour when watched."),
 ("anti-sleep","Delay execution with sleeps","T1497.003","Defense Evasion","Virtualization/Sandbox Evasion: Time Based Evasion",["Sleep","sleep","nanosleep","usleep"],[],["sleep"],"Waits before acting. Sandboxes often only watch for a few minutes, so sleeping outlasts them."),
 ("inject-process","Inject code into another process","T1055","Defense Evasion","Process Injection",["VirtualAllocEx","WriteProcessMemory","CreateRemoteThread","OpenProcess"],[],[],"Puts its code inside a legitimate process so the activity looks like it came from that process."),
 ("mem-exec","Allocate executable memory","T1055","Defense Evasion","Process Injection",["VirtualAlloc","VirtualProtect","mmap"],["rwx"],[],"Reserves memory that can be executed. Required to run unpacked or downloaded code from memory."),
 ("cred-access","Access credentials","T1003","Credential Access","OS Credential Dumping",[],["password","credential","/etc/shadow","lsass","mimikatz","Login Data","keychain"],[],"Touches passwords or credential stores. Treat any machine this ran on as having exposed credentials."),
 ("privesc","Attempt privilege escalation","T1068","Privilege Escalation","Exploitation for Privilege Escalation",["setuid","setgid","AdjustTokenPrivileges"],["sudo ","setuid"],[],"Tries to gain higher privileges than the account it started with."),
 ("mining","Cryptocurrency mining behaviour","T1496","Impact","Resource Hijacking",[],["crypto mining","stratum","minerd","xmrig","monero","mining pool"],[],"Uses the victims CPU to mine cryptocurrency for the operator. Expect heat, fan noise, and slowdowns."),
 ("recon-files","Read or search files on disk","T1083","Discovery","File and Directory Discovery",["FindFirstFile","FindNextFile","opendir","readdir"],["/etc/passwd","document","wallet"],[],"Searches the disk, typically looking for documents, wallets, or data worth stealing."),
 ("persistence-service","Install a service or daemon","T1543.002","Persistence","Create or Modify System Process: Systemd Service",["CreateService","StartServiceCtrlDispatcher"],["systemctl","service "],[],"Installs itself as a background service so it runs with system privileges and restarts automatically."),
 ("keylog","Capture keystrokes or input","T1056.001","Collection","Input Capture: Keylogging",["GetAsyncKeyState","SetWindowsHookEx","GetKeyState"],[],[],"Records what the user types, including passwords and private messages."),
 ("screenshot","Capture the screen","T1113","Collection","Screen Capture",["BitBlt","GetDC"],[],[],"Takes screenshots of the victims screen."),
 ("clipboard","Read the clipboard","T1115","Collection","Clipboard Data",["OpenClipboard","GetClipboardData"],[],[],"Reads copied data, a known route to stealing copied passwords and crypto wallet addresses."),
 # ---- per-family proof atoms (The Verdict family expansion) ----
 # These rules fire on single atoms. An atom alone is never a verdict:
 # the family chains in families.py combine atoms under each family's
 # stated proof standard and its false-positive twin discriminator.
 ("dpapi-access","Unprotect DPAPI-protected data","T1003.002","Credential Access","OS Credential Dumping: DPAPI",["CryptUnprotectData"],["CryptUnprotectData","DPAPI"],[],"Decrypts data Windows protected with DPAPI, the mechanism browsers use to store saved passwords. A stealer atom: meaningful only combined with the stores it unlocks."),
 ("sqlite-access","Read SQLite databases","T1003","Credential Access","OS Credential Dumping",["sqlite3_open"],["sqlite3","SELECT * FROM logins","FROM logins","moz_logins"],[],"Reads SQLite databases. Browser credential and cookie stores are SQLite files, so this is a stealer atom when combined with browser store paths."),
 ("browser-store-paths","Reference browser credential and session stores","T1555.003","Credential Access","Credentials from Web Browsers",[],["Login Data","Web Data","Local State","logins.json","Cookies-journal","Telegram Desktop","leveldb","recentservers.xml"],[],"Names the files where browsers, Telegram, Discord and FTP clients keep saved logins and sessions. One path can be innocent; a list spanning unrelated apps is a theft target list."),
 ("wallet-paths","Reference cryptocurrency wallet stores","T1555.001","Credential Access","Credentials In Password Stores",[],["wallet.dat","Exodus","Electrum","MetaMask","Atomic Wallet","phantom.app","WasabiWallet"],[],"Names cryptocurrency wallet files and browser wallet extensions. Combined with DPAPI or SQLite access and a network sink, this is the stealer pattern."),
 ("stealer-config","Carry a stealer scanning configuration","T1005","Collection","Data from Local System",[],["ScanningArgs","ScanBrowsers","ScanFiles","ScanFTP","ScanWallets","ScanScreen","ScanTelegram","ScanVPN","ScanSteam","ScanDiscord","BlockedCountry","BlockedIP"],[],"Carries a server-supplied stealer configuration of the RedLine type: switches that enumerate browsers, wallets, Telegram, VPN, Steam and Discord in one pass. No licensing function has such a list."),
 ("rat-config","Carry a remote-access configuration","T1105","Command and Control","Ingress Tool Transfer (operator configuration evidence)",[],["ServerHost","ServerPort","HVNC","hidden VNC","command dispatcher","operator commands"],[],"Carries a remote-access tool configuration: an operator host, port or key plus the shape of a command dispatcher. Proof requires the dispatcher atoms in families.py, not this string alone."),
 ("ransom-note","Carry a ransom note or extortion text","T1491","Impact","Defacement (extortion note evidence)",[],["_readme.txt","decrypt your files","ransom note","your files have been encrypted","victim id","files are encrypted"],[],"Carries the text or filename of a ransom note. One corroborator for ransomware, never proof on its own."),
 ("shadow-delete","Delete shadow copies or disable recovery","T1490","Impact","Inhibit System Recovery",["vssadmin"],["vssadmin delete shadows","wbadmin delete catalog","recoveryenabled no","delete shadows","bcdedit /set recoveryenabled"],[],"Deletes volume shadow copies or disables boot recovery, so the victim cannot restore what was encrypted or destroyed. No crack function ever does this: anti-recovery is near-dispositive when paired with an encryption or overwrite capability."),
 ("pool-connect","Carry a mining pool endpoint","T1496.001","Impact","Resource Hijacking: Compute Hijacking",[],["stratum+tcp","stratum+ssl","stratum://","stratum2"],[],"Carries a Stratum mining pool endpoint. Combined with a wallet and concealment it is a proven miner; a pool string alone is not."),
 ("flood-routine","Carry a flooding or denial-of-service routine","T1498","Impact","Network Denial of Service",[],["syn flood","udp flood","http flood","slowloris","flood attack","attack duration","target_ip","udp_flood","syn_flood","http_flood"],[],"Carries code or command grammar for flooding a third-party target. Combined with a command and control dispatch it is a botnet agent; games and torrent clients direct traffic only where the user chose."),
 ("bank-targets","Carry a bank or payment target list","T1189","Initial Access","Drive-by Compromise (web inject target evidence)",[],["bankofamerica.com","chase.com","wellsfargo.com","citibank.com","hsbc.com","barclays.com","santander.com","commerzbank.com","webinject","inject config","form grabber","automatic transfer system"],[],"Enumerates banks or carries web-inject machinery. A crack binary containing a bank target list is dispositive: no licensing function enumerates banks."),
 ("proxy-server","Run a proxy server","T1090","Command and Control","Proxy",[],["socks5","socks4","socks proxy","3proxy","residential proxy","proxy enrolment","proxy enrollment"],[],"Runs or enrols in a proxy service. Whether it is malware turns on consent, beneficiary and visibility, judged in families.py."),
 ("proxy-network-sdk","Carry a traffic-selling network client","T1090.002","Command and Control","Proxy: External Proxy",[],["pawns.app","api.pawns.app","lum_sdk","clientsdk.brdtnet.com","PacketStream","packetstream.io","proxyrack"],[],"Carries a residential proxy network client or enrolment endpoint, the traffic-selling pattern: other people's traffic relayed through this machine for the network operator."),
 ("raw-disk","Access the raw physical disk","T1561","Impact","Disk Wipe (raw access evidence)",[],["PhysicalDrive0","PhysicalDrive1","\\\\.\\PhysicalDrive","raw disk access"],[],"Opens the physical drive itself rather than files on it. Combined with an overwrite routine and no recovery path, this is the wiper pattern."),
 ("offer-engine","Carry a pay-per-install offer engine","T1105","Command and Control","Ingress Tool Transfer (affiliate distribution evidence)",[],["offer_execution","installbest","installusd","affiliate_id","affiliateid","offer_id","install callback","postback url","per-offer"],[],"Carries affiliate or offer identifiers and install callbacks of a pay-per-install network. In a crack, an affiliate ID plus an install callback is proof of a paid distribution deal the user never saw."),
 ("dead-drop","Resolve addresses through a public dead drop","T1102.001","Command and Control","Web Service: Dead Drop Resolver",[],["api.telegram.org/bot","discord.com/api/webhooks","telegra.ph","rentry.co/","pastebin.com/raw","pastebin.com/api","hastebin.com/raw","ghostbin","dpaste.org"],[],"Uses a public service (Telegram bot API, Discord webhook, paste page) as a dead drop for addresses or payloads. Legitimate updaters fetch from their own vendor; dead drops hide the operator."),
 ("beacon-config-string","Carry beacon configuration strings","T1071.001","Command and Control","Application Layer Protocol: Web Protocols",[],["beacon config"," beacon ","malleable c2","watermark","spawnto","pipe name"],[],"Carries strings associated with a beacon implant configuration. The dispositive evidence is a parsed TLV beacon configuration, implemented in families.py; strings alone are corroboration."),
]

def _atom_in_text(atom, text):
    """Token-boundary search: an API name counts in script text only
    as a whole token, so 'bind' does not fire on 'binding' and 'open'
    does not fire on 'opener'."""
    a = atom.lower()
    pat = r"(?<![a-z0-9_])" + re.escape(a) + r"(?![a-z0-9_])"
    return re.search(pat, text) is not None


def match_capabilities(imports, strings, mnemonics, script_text=""):
    low_strings=[s.lower() for s in strings]
    imp=[i.lower() for i in imports]
    mn=set(m.lower() for m in mnemonics)
    text=(script_text or "").lower()
    out=[]
    for rid,name,aid,tactic,technique,imp_need,str_need,mn_need,explain in RULES:
        ev=[]
        for n in imp_need:
            if any(n.lower() in i for i in imp): ev.append(f"import/symbol: {n}")
            elif text and _atom_in_text(n, text): ev.append(f"api reference in script text: {n}")
        for n in str_need:
            if any(n.lower() in s for s in low_strings) or n.lower() in text: ev.append(f"string/text: {n}")
        for n in mn_need:
            if n and n in mn: ev.append(f"instruction: {n}")
        if ev:
            out.append({"id":rid,"name":name,"attack_id":aid,"tactic":tactic,"technique":technique,"evidence":sorted(set(ev)),"explanation":explain})
    return out
