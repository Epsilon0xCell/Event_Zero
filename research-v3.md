# Event Zero v3 Research

Design sources, all primary project documentation unless noted. Deep research report: research_notes/event-zero-advanced-malware-plaintext-20261123-0555/report.md in the workspace.

## Chosen stack and why
- capa and FLOSS (Mandiant, github.com/mandiant/capa, github.com/mandiant/flare-floss): capability rules with ATT&CK mapping and decoded string classes. Event Zero ships built-in capa-style rules and uses the real binaries through the tool registry when installed.
- Ghidra headless (ghidra-sre.org, needs JDK 21): decompilation adapter in the registry. Not bundled.
- LIEF and Capstone: parsing and disassembly in the core, verified by tests/test_event_zero.py.
- Unicorn (unicorn-engine.org) and Speakeasy (Mandiant): CPU and Windows API emulation. Unicorn is integrated and test-proven in this environment; Speakeasy is a registry adapter.
- unblob and binwalk (github.com/onekey-sec/unblob): firmware extraction design; Event Zero core implements binwalk-style magic scanning and UEFI carving, unblob is a registry adapter.
- UEFITool (github.com/LongSoft/UEFITool) and CHIPSEC (github.com/chipsec/chipsec): firmware volume model and platform red flags, registry adapters.
- Volatility 3 (volatility3.readthedocs.io): rootkit confirmation is a cross-view memory task. Event Zero reports "indicators consistent with" and hands off the exact plugins. It never confirms a rootkit from a file.
- CAPE Sandbox (github.com/kevoreilly/CAPEv2): the only private-by-default dynamic option, self-hosted. Event Zero ingests its JSON reports.

## Service corrections (2026-11-23, from the deep research)
- abuse.ch (MalwareBazaar, ThreatFox, URLhaus) now requires a free Auth-Key: clients read ABUSECH_API_KEY and report not configured without it. Keyless calls return 401.
- VirusTotal public API: 4 requests per minute, 500 per day, non-commercial, hash lookup only by default in Event Zero.
- Every free public sandbox publishes the sample. Upload paths carry a plain warning. Default is never upload.
- Hybrid Analysis, urlscan.io, AlienVault OTX, MetaDefender, filescan.io, tria.ge: hash-first clients in services.py, each optional, each mocked in tests.

## BlackArch mapping
The registry (event_zero/tools_registry.py, `event_zero tools`) maps each tool to its BlackArch package name across the blackarch-malware, blackarch-reversing, blackarch-disassembler and blackarch-binary categories, with pacman style install hints for BlackArch and Arch and pip or apt alternatives elsewhere. BlackArch itself is not installed in the build VM, by design.

## Free service table
| Service | Free tier | What it adds | Key env |
|---|---|---|---|
| VirusTotal | 4/min, 500/day, non-commercial | multi-engine hash reputation | VIRUSTOTAL_API_KEY |
| Hybrid Analysis | free API key | sandbox verdicts by hash | HYBRID_ANALYSIS_API_KEY |
| MalwareBazaar | free Auth-Key | sample family, first seen, tags | ABUSECH_API_KEY |
| ThreatFox | free Auth-Key | IOC context | ABUSECH_API_KEY |
| URLhaus | free Auth-Key | payload delivery URLs | ABUSECH_API_KEY |
| urlscan.io | search without key | URL and hash search results | URLSCAN_API_KEY optional |
| AlienVault OTX | free key | threat pulses and tags | OTX_API_KEY |
| MetaDefender | free key | multi-engine hash scan counts | METADEFENDER_API_KEY |
| filescan.io | basic hash search | file scan records | none for basic |
| tria.ge | free key | sandbox sample records | TRIAGE_API_KEY |

## Honest limits
- Virtualized code (VMProtect, Themida) is a hard limit: the original code is never restored (Rolles, USENIX WOOT 2009). Event Zero identifies the protector, analyses handlers and entry, and labels the rest unknown.
- Zero-day is a disclosure status, not a property of a binary. Event Zero never certifies it; the exploit section states disclosure status unknown.
- Rootkit confirmation needs a memory dump and Volatility cross-view. Static output is "indicators consistent with" only.
- eBPF rootkits may leave no file artifact at all.
- Firmware verdicts are per component inventories, not one verdict for an image.
- Perfect decompilation of arbitrary packed malware is impossible. The v3 guarantee is maximum extraction, evidence on every claim, and labelled unknowns.
