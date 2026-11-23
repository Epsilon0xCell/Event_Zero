# Event Zero: Deep Research and Rebuild Design

## Sources (primary / official)
- Mandiant capa: https://mandiant.github.io/capa/ and github.com/mandiant/capa (v10.0.0, Oct 2026 per site). capa disassembles PE/ELF/.NET/shellcode, matches 1000+ expert YAML rules, outputs capabilities mapped to MITRE ATT&CK and MBC. Backends: vivisect, IDA, Ghidra, Binary Ninja. Python 3.10+, flare-capa on PyPI, or standalone binary.
- Mandiant FLOSS (flare-floss, github.com/mandiant/flare-floss): extracts static, stack, tight, and decoded strings using emulation of decoding routines. Lesson: plain strings misses obfuscated strings; decoding layers are mandatory.
- NSA Ghidra: https://github.com/NationalSecurityAgency/ghidra ; practitioner guide https://infosecmonkey.com/ghidra-zero-to-hero-a-practitioners-guide-to-the-nsas-reverse-engineering-framework/ : Ghidra 12.1.4 needs JDK 21 minimum, about 1.5 GB disk, 8 GB RAM workable. Headless analyzer (analyzeHeadless) gives real decompiled C pseudocode. In this VM: java not found, so Ghidra is NOT installable lightweight here without a heavy JDK+Ghidra download. It is documented as the optional deep backend, not the core.
- LIEF: https://lief.re : parses ELF/PE/Mach-O uniformly in Python, pip installable. Verified in this VM: lief 1.0.0 installs.
- Capstone: https://www.capstone-engine.org : multi-arch disassembler (x86, x64, ARM, ARM64, MIPS). Verified: capstone 5.0.9 pip installs.
- pefile (2024.8.26) and pyelftools (0.33): verified pip installable, used as cross-checks and fallbacks.
- radare2 / r2pipe, Detect It Easy, YARA: excellent on a full analyst VM (FLARE VM), but they are native installs, not pip-light; Event Zero detects and uses YARA rules files if present, and does not require them.
- Unicorn engine: CPU emulation for unpacking/decoding; heavy and risky on unknown code paths, used by FLOSS-style decoders. Event Zero v2 does NOT emulate unknown samples; it does bounded single-byte XOR and Base64 decoding on extracted byte blobs, which is safe and deterministic.

## Chosen stack (what actually runs in this VM)
Core: Python 3.10+ stdlib (hashes, entropy, Mach-O/ELF/PE fallback parsers, script AST).
Preferred: lief (format, sections, imports, symbols, entry) + capstone (disassembly) + pefile/pyelftools cross-check. Every lief/capstone use is guarded: if the wheel is missing, the stdlib parser fills the same fields and the report says which backend ran. No Docker. No network. No API key.
Optional: an LLM summariser interface (event_zero.llm.summarise) that takes the finished JSON report and a caller-supplied callable; it is never required and never sends anything by itself.

## Honest limits: what 100 percent means here
Perfect decompilation of arbitrary packed, virtualised, or self-modifying malware into exact original source is impossible in principle: packing hides code until runtime, anti-analysis defeats static views, and lost symbols/comments/types cannot be recovered from bytes alone. Any tool claiming that is lying.
The achievable, testable 100 percent target used for this rebuild: for every input file, the analyzer exits successfully and produces a complete plain-text report with no silent gaps, covering (1) identity and hashes, (2) format and architecture, (3) sections/segments with entropy and packing verdict, (4) imports and symbols explained in plain English, (5) all strings: ASCII, UTF-16, Base64-decoded, XOR-decoded, (6) functions found, with disassembly and a plain-English pseudocode summary per interesting function, (7) capa-style capabilities mapped to MITRE ATT&CK, (8) network, file, persistence, crypto, discovery, and anti-analysis behaviours, (9) a risk verdict with reasons, (10) an IOC list, and (11) an explicit Unknowns section listing what static analysis could not determine. Unknowns are labelled, never hidden.

## What was broken in the original (verified 2026-11-22, see VERIFICATION.md)
Local mode worked only as shallow triage; the headline autonomous mode was unusable in this environment and for most users. Full list in VERIFICATION.md.
