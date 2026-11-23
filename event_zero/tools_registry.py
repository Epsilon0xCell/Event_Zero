"""Tool registry: every free tool Event Zero can use as an optional adapter.
Auto-detects presence, version where cheap, and what it adds. Missing tools
never break analysis: the report lists which tools contributed and which were
missing. BlackArch mapping gives the pacman package name for BlackArch/Arch."""
import shutil, subprocess

# name, binary or python module, category, what it adds, blackarch package, alternatives
TOOLS=[
 ("ghidra","analyzeHeadless","reversing","Decompiles functions to C-like pseudocode","ghidra","Install Ghidra from ghidra-sre.org (needs JDK 21)"),
 ("radare2","r2","reversing","Fast disassembly, function graphs, ROP gadget search (ragg2/rasm2)","radare2","apt/pip: pip install r2pipe, or install rizin"),
 ("rizin","rizin","reversing","Radare2 fork disassembly and analysis","rizin","apt install rizin"),
 ("capa","capa","malware","Mandiant capability rules matched against functions","python-capa","pip install flare-capa"),
 ("floss","floss","malware","Mandiant stack, tight and decoded string extraction","python-floss","pip install flare-floss"),
 ("diec","diec","binary","Detect It Easy compiler, packer and format identification","detect-it-easy","Install Detect It Easy from horsicq.github.io"),
 ("binwalk","binwalk","firmware","Firmware extraction and embedded file carving","binwalk","pip install binwalk, or use unblob"),
 ("unblob","unblob","firmware","Modern firmware extraction for many container formats","unblob","pip install unblob"),
 ("yara","yara","malware","YARA rule matching (binary)","yara","apt install yara, or pip install yara-python"),
 ("strings","strings","binary","Binutils printable string extraction","binutils","apt install binutils"),
 ("objdump","objdump","disassembler","Binutils disassembly and section dumps","binutils","apt install binutils"),
 ("readelf","readelf","binary","ELF header, section and symbol reading","binutils","apt install binutils"),
 ("nm","nm","binary","Symbol listing","binutils","apt install binutils"),
 ("upx","upx","malware","UPX unpacking when a sample is UPX packed","upx","apt install upx"),
 ("speakeasy","speakeasy","malware","Windows API emulation of binaries and shellcode (Python module: speakeasy)","python-speakeasy","pip install speakeasy-emulator"),
 ("unicorn","","malware","CPU emulation engine for shellcode and entry tracing (Python module: unicorn)","python-unicorn","pip install unicorn"),
 ("ssdeep","ssdeep","binary","Fuzzy hashing for near-duplicate samples","ssdeep","apt install ssdeep, or pip install pydeep"),
 ("tlsh","","binary","TLSH fuzzy hash (Python module: tlsh)","python-tlsh","pip install python-tlsh"),
 ("volatility3","vol","reversing","Memory image analysis for rootkit cross-view diffs","volatility3","pip install volatility3"),
 ("uefitool","UEFITool","firmware","UEFI firmware volume inspection and extraction","uefitool","Install UEFITool from LongSoft/UEFITool releases"),
 ("chipsec","chipsec_main","firmware","Platform firmware security checks (CHIPSEC framework)","chipsec","pip install chipsec, run only on hardware you own"),
 ("pestudio-style checks","","binary","Built in: imports, sections, entropy, TLS callbacks and overlay checks in the core, no external tool needed","(built in)","Always available in Event Zero core"),
 ("ghidra-mcp","","reversing","Optional Ghidra MCP bridge when a user runs one","ghidra-mcp","Optional, user configured"),
 ("x64dbg","","reversing","Windows debugger, listed for the analyst workstation, not run by Event Zero","x64dbg","Windows only, manual use"),
 ("cutter","cutter","reversing","Rizin GUI front end, listed for the analyst workstation","cutter","apt install cutter"),
 ("jadx","jadx","reversing","Android DEX decompilation when a sample is an APK","jadx","Install JADX from skylot/jadx releases"),
 ("apktool","apktool","reversing","Android APK resource decoding","apktool","apt install apktool"),
 ("innoextract","innoextract","malware","Inno Setup installer extraction","innoextract","apt install innoextract"),
 ("7z","7z","binary","Archive extraction for droppers and installers","p7zip","apt install p7zip-full"),
 ("jadx2","jadx","reversing","Android DEX decompilation","jadx","Install JADX releases"),
 ("apktool2","apktool","reversing","APK resource decoding","apktool","apt install apktool"),
 ("ilspycmd","ilspycmd","reversing",".NET IL decompilation","ilspycmd","dotnet tool install -g ilspycmd"),
 ("de4dot","de4dot","reversing",".NET deobfuscation (ConfuserEx etc)","de4dot","Install de4dot releases"),
 ("tshark","tshark","firmware","Deep packet capture analysis beyond the built in pcap quick look","wireshark","apt install tshark"),
 ("volatility3b","vol","reversing","Memory forensics","volatility3","pip install volatility3"),
 ("olevba","olevba","malware","Office macro analysis (oletools)","python-oletools","pip install oletools"),
 ("peframe","peframe","malware","PE static analysis helper","peframe","pip install peframe"),
 ("exiftool","exiftool","binary","File metadata extraction","perl-image-exiftool","apt install libimage-exiftool-perl"),
]
PY_MODULES={"unicorn":"unicorn","tlsh":"tlsh","speakeasy":"speakeasy"}

def _version(binary):
    if not binary: return None
    path=shutil.which(binary)
    if not path: return None
    try:
        r=subprocess.run([path,"--version"], capture_output=True, text=True, timeout=5)
        return (r.stdout or r.stderr).splitlines()[0][:120] if (r.stdout or r.stderr) else "installed"
    except Exception: return "installed"

def registry():
    out=[]
    for name, binary, cat, adds, ba, alt in TOOLS:
        installed=False; version=None; how=""
        if name in PY_MODULES:
            try: __import__(PY_MODULES[name]); installed=True; version="python module importable"
            except Exception: installed=False
            how=alt
        elif binary:
            installed=shutil.which(binary) is not None; version=_version(binary) if installed else None; how=alt
        else:
            installed=True; version="built in"; how=alt
        out.append({"tool":name,"category":cat,"installed":installed,"version":version,"adds":adds,"blackarch_package":ba,"install_hint":how})
    return out

def contributed(report_tools=None):
    return [t for t in registry() if t["installed"]]
