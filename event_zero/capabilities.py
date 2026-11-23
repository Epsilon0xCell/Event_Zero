"""Capa-style capability rules authored for Event Zero.

Each rule: id, name, attack (id, tactic, technique), evidence sources
(imports, strings, mnemonics, script tokens), plain-English explanation.
Matching is deterministic: a rule fires only on observed evidence, and the
evidence strings are carried into the report.
"""
RULES = [
 ("net-socket","Create a network socket","T1071.001","Command and Control","Application Layer Protocol: Web Protocols",["socket","WSASocket","socketpair"],["socket"],["socket"],"Opens a network socket, the first step in talking to another machine."),
 ("net-connect","Connect to a remote host","T1071.001","Command and Control","Application Layer Protocol",["connect","WSAConnect","ConnectEx"],["connect to","connect("],["connect"],"Connects out to an address and port. In malware this is often the command and control channel."),
 ("net-send-recv","Send and receive data over a socket","T1071","Command and Control","Application Layer Protocol",["send","recv","sendto","recvfrom","WSASend","WSARecv"],[],["send","recv"],"Moves data over a network connection, used to receive orders or send stolen data out."),
 ("net-http","Make HTTP requests","T1071.001","Command and Control","Application Layer Protocol: Web Protocols",["InternetOpen","HttpSendRequest","WinHttpSendRequest","curl_easy_perform"],["http://","https://","User-Agent","curl","wget"],[""],"Uses web traffic, which blends in with normal browsing and often passes firewalls."),
 ("net-dns","Resolve hostnames via DNS","T1071.004","Command and Control","Application Layer Protocol: DNS",["gethostbyname","getaddrinfo","DnsQuery"],[],["getaddrinfo"],"Looks up a hostname, typically to find its control server even if the IP changes."),
 ("net-listen","Listen for incoming connections","T1571","Command and Control","Non-Standard Port",["bind","listen","accept"],[],["bind","listen"],"Waits for someone else to connect in. This is backdoor behaviour: the infected machine becomes a server."),
 ("exec-shell","Run shell commands","T1059.004","Execution","Command and Scripting Interpreter: Unix Shell",["system","popen","execl","execve","ShellExecute","CreateProcess","WinExec"],["/bin/sh","/bin/bash","cmd.exe","powershell","os.system","subprocess"],[],"Runs operating system commands, giving the sample the power of a user at a terminal."),
 ("exec-download-run","Download and execute a payload","T1105","Command and Control","Ingress Tool Transfer",[],["curl http","wget http","| sh","| bash","downloadstring","invoke-expression","iex("],[],"Downloads code from the internet and runs it. The file you have is then only a first stage."),
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
]

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
        for n in str_need:
            if any(n.lower() in s for s in low_strings) or n.lower() in text: ev.append(f"string/text: {n}")
        for n in mn_need:
            if n and n in mn: ev.append(f"instruction: {n}")
        if ev:
            out.append({"id":rid,"name":name,"attack_id":aid,"tactic":tactic,"technique":technique,"evidence":sorted(set(ev)),"explanation":explain})
    return out
