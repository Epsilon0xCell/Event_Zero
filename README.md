<p align="center">
  <img src="Event_Zero-Website/assets/ez-mark.svg" width="120" alt="Event Zero mark: an amber ring under crosshair ticks on black">
</p>

<h1 align="center">EVENT ZERO</h1>

<p align="center"><strong>Malware in. Plain English out. Evidence attached.</strong></p>

<p align="center">
Event Zero turns a suspicious file into a plain English report anyone can act on, with every claim tied to evidence found in the file itself.
</p>

<p align="center">
  <img src="https://img.shields.io/badge/license-CC%20BY--NC%204.0-lightgrey" alt="License: Creative Commons Attribution NonCommercial 4.0">
  <a href="https://github.com/Epsilon0xCell/Event_Zero/actions/workflows/tests.yml"><img src="https://github.com/Epsilon0xCell/Event_Zero/actions/workflows/tests.yml/badge.svg" alt="Test suite status from the tests workflow"></a>
  <img src="https://img.shields.io/badge/python-3.10%2B-blue" alt="Python 3.10 or newer, as declared in pyproject.toml">
</p>

## The Verdict: a proven YES or NO on any crack

Drop in a cracked game, a keygen, an installer, an archive, or a whole release folder. Event Zero takes it apart piece by piece, accounts for every byte as genuine program or explained crack, and gives you one headline. Not a score. Not a probability. A verdict with its proof attached.

```console
$ python3 -m event_zero verdict fake_malware
YES: MALWARE FOUND
Reason class: PROVEN
```

That is the real output on the bundled sample (Case 001 below). The proof names three behaviour chains: a credential stealer, persistence plus a remote host, and a cryptocurrency miner. Full report: [examples/fake_malware.verdict.txt](examples/fake_malware.verdict.txt).

A clean crack gets the opposite headline, and it has to earn it:

```console
$ python3 -m event_zero verdict release/ --reference genuine/
NO: NO MALWARE
Reason class: ACCOUNTED
```

In the recorded run the diff ledger classified all 3 changed regions as expected-crack: the licence check patch, and nothing else. Full report: [examples/clean_crack.verdict.txt](examples/clean_crack.verdict.txt).

The rules that make the headline worth trusting:

- **The crack itself is not malware.** A patched licence check, a key generator, and KMS emulation are the expected crack. They appear in the accounting, never in the proof.
- **YES, PROVEN** means a behaviour chain was demonstrated: theft, a miner mining for someone else, persistence plus a remote host, antivirus tampering, or the scope test (the first behaviour a file does not need for its claimed job decides it).
- **YES, UNACCOUNTED** means something could not be explained: an unexplained code region, an archive layer that would not open, a virtualized section. The accounting fails closed. Silence never becomes a pass.
- **NO** is issued only when every byte is accounted for as genuine or explained crack, against a signature-valid original or a fully classified diff.

## The 60 second demo

```console
$ git clone https://github.com/Epsilon0xCell/Event_Zero.git
$ cd Event_Zero
$ pip install -r requirements.txt
$ python3 -m event_zero analyze fake_malware --out report.txt
$ python3 -m event_zero verdict fake_malware
```

The sample is read as bytes. It is never executed on your machine.

### Case 001: fake_malware, in three layers

Every report opens with the same three layers. Exhibit A, the ELI5 layer, verbatim from [examples/fake_malware.report.txt](examples/fake_malware.report.txt):

> This is about a computer file called fake_malware.
> This file looks bad. It does things a good file should not do.
> Think of it like hiding a spare key.
> It hides a spare key so it can come back after the computer restarts.
> Think of it like peeking at a key box.
> It looks where secret keys and passwords are kept.
> What should you do? Do not open it. Give it to a grown up who studies bad files.

Exhibit B, the plain English layer, same file: it is a Mach-O file for ARM64, 33,920 bytes, SHA-256 `c9ab06a4fd594a82eb36d1aeb72e83e99df77a2ccd6a8ebd0ad078dd6b707802`, importing `connect`, `socket`, and `system` (it connects to a remote address, creates network sockets, and runs shell commands).

Exhibit C, the evidence layer: 22 numbered sections covering hashes, sections and packing, decoded strings, capabilities with MITRE ATT&CK IDs, a kill chain timeline, and a generated YARA rule built from the file's own strings.

## What it does, in plain English

Read the file as bytes, never run it. Parse the format (ELF, PE, Mach-O, .NET, APK, Office, PDF, email, firmware images). Decode what it hid (Base64, XOR, RC4, multi-layer chains). Carve out embedded binaries. Match what it can do against capability rules. Check evasion tricks (direct syscalls, API hashing, process injection, anti-VM checks). Census virtualized code instead of pretending to read it. Then write the layered report, the verdict, and the defences: a YARA rule, a Sigma style summary, IOC exports in CSV and STIX 2.1, and an ATT&CK Navigator layer.

Optional layers sit on top and never change the core: hash lookups against VirusTotal, Hybrid Analysis, MalwareBazaar, ThreatFox, URLhaus, urlscan.io, OTX, MetaDefender, filescan.io and tria.ge (keys from environment variables only, hash first, upload only behind an explicit flag), and an optional Gemini narration that may only polish words from the evidence set. Anything Gemini invents is stripped by the evidence gate and listed. No key, no network: the deterministic core runs unchanged.

## Capability summary

Status words are copied from [CAPABILITY-MATRIX.md](CAPABILITY-MATRIX.md), which carries the test or run that proves each row.

| Capability | Status |
|---|---|
| ELF, PE, Mach-O parsing, imports explained, Capstone disassembly | BUILT |
| String decoding: ASCII, UTF-16, Base64, XOR, RC4, multi-layer chains | BUILT |
| Unpacking: UPX detection, overlay, embedded binary carving | BUILT |
| Firmware: magic scan, UEFI volumes, DXE driver carving, red flags | BUILT |
| Rootkit indicators for drivers (.sys, .ko, eBPF), stated as "indicators consistent with" | BUILT |
| Rootkit confirmation via Volatility 3 | HANDOFF |
| Shellcode analysis and ROP gadget enumeration | BUILT |
| Evasion decoding: direct syscalls, API hashing, injection chains, anti-debug, anti-VM, AMSI and ETW patterns | BUILT |
| Shellcode emulation in Unicorn (no syscalls serviced) | BUILT |
| Sandbox detonation (your own CAPE); CAPE report ingestion | HANDOFF / BUILT |
| .NET, Android APK, Office, PDF, email, PCAP analysis | BUILT |
| ELI5 layer with jargon gate and reading metrics | BUILT |
| Gemini narration behind the evidence gate | BUILT (live call: SERVICE, your key) |
| Ghidra, capa, FLOSS, radare2, binwalk, unblob, Detect It Easy, YARA, Volatility, jadx, oletools, tshark and more | ADAPTER |
| VirusTotal, Hybrid Analysis, abuse.ch, urlscan, OTX, MetaDefender, filescan, tria.ge | SERVICE |
| ANY.RUN, Joe Sandbox, Koodous, Intezer, CyberChef, dogbolt, UnpacMe | HANDOFF (hash-only links) |
| The Verdict: YES / NO accounting on pirated software | BUILT |
| Folder manifest (JSON Lines) and verdict inheritance | BUILT |
| Connection ledger and behaviour ledger with genuine baseline diff | BUILT |
| Devirtualization: protector ID, handler census, Unicorn entry-stub trace | BUILT |
| Devirtualization: handler semantics pass (Triton, NoVmp class tools) | ADAPTER / HANDOFF |
| NSRL / CIRCL hashlookup | HANDOFF (corroboration only, never a NO basis) |

The format is a published spec, [format-spec.md](format-spec.md), with a validator: `python3 -m event_zero validate report.json` checks that every claim in a report carries evidence. Three gold reports in [examples/gold/](examples/gold/) pass it.

## Benchmark

Method: the same fixtures scored by the built-in capability rules alone, then by the full pipeline, as recorded in [VERIFICATION.md](VERIFICATION.md). Five adversarial fixtures (S1 to S5) were built after the modules, with tricks the modules were not designed around.

| Fixture | Rules only | Full pipeline |
|---|---|---|
| fake_malware (bundled sample) | 12 findings | 12 findings |
| EICAR test file | 0 | 0 |
| evil.py (synthetic) | 5 | 5 |
| S1 APK (XOR string hidden in DEX) | 1 | 2 |
| S2 DOCM (macro, DDE, template injection) | 3 | 4 |
| S3 blob (Base64, Base64, XOR chain) | 0 cold, 1 after fix | 1 |
| S4 .NET evasion (ConfuserEx, API hashing, injection) | 1 | 4 |
| S5 firmware (UEFI plus SquashFS plus nested DXE) | 0 | 1 |

Two cold misses (S1, S3) were found by this sweep, fixed, and locked in as regression tests. One limit is labelled, not hidden: on S5 the combined SMM-plus-network flag does not fire per driver yet; the evidence is in the report and per-driver verdicts are the documented next step.

ELI5 reading level, measured per report: 10.2 to 11.8 average words per sentence across six reports, with 0 untranslated banned jargon terms. The design target (Flesch Reading Ease at least 80, Flesch-Kincaid at most 6) is a design target, not a standard, and is labelled as one in the code.

Test suite: 91 tests passing at the v3 verification run (64 core, plus 19 verdict, 5 folder and link, 3 devirtualization). Run them yourself: `python3 -m pytest tests/ -q`.

## Its own tools

| Tool | Command | What it does |
|---|---|---|
| ez-carver | `python3 -m event_zero carve <file>` | Extracts embedded PE, ELF and Mach-O binaries with header validation |
| ez-shellcode | `python3 -m event_zero shellcode <file>` | Finds NOP sleds, egghunters and decoder stubs, enumerates ROP gadgets |
| ez-eli5 | built into every report | Generates the ELI5 layer from structured evidence (event_zero/eli5.py) |
| ez-capgen | `python3 -m event_zero capgen <file>` | Drafts capability rules from unknown patterns; a draft is promoted only if it fires on a malicious fixture and on zero benign fixtures |
| ez-diff | `python3 -m event_zero diff <a> <b>` | Plain English comparison of two samples |
| Tool registry | `python3 -m event_zero tools` | Lists 30+ external tools: installed or missing, version, what each adds, BlackArch package names |

## Safety

- Samples are never executed on the host. Emulation services no syscalls. Detonation belongs in your own isolated CAPE sandbox.
- Uploads are off by default. Enrichment is hash first, and the report footer carries hash-only lookup links: only the hash leaves the machine.
- API keys are read from environment variables only (`GEMINI_API_KEY`, `VIRUSTOTAL_API_KEY`, `ABUSECH_API_KEY`, and the rest in [.env.example](.env.example)). Never put a key in a commit, a config file, or a chat.
- Every bundled fixture is synthetic and self-crafted. No live malware is included or downloaded.
- Research and dual use: Event Zero is a defensive research tool for analysing files you have the right to analyse. Its capability rules describe malware behaviour in order to detect and explain it; the bundled fixtures carry those behaviours as inert data for the analyser, and nothing in the repository is a working malicious program.

## Honest limits

- Full decompilation of packed or virtualized code is not possible, for any tool. Event Zero censuses virtualized regions, traces what crosses into the real world, and marks the rest UNACCOUNTED rather than guessing.
- "Zero-day" is a disclosure status, not something a binary can certify. Exploit reports state the bug class and the primitive, and print disclosure status: unknown.
- A NO verdict is an accounting claim, stated exactly: every byte accounted for as genuine or explained crack, no behaviour beyond genuine plus explained crack observed, manifest linked. Environment-keyed and server-gated payloads stay on the disclosed open list in the research.
- Static analysis infers behaviour; it does not observe it. Reports say which layer produced each claim, and unknowns get their own section instead of being smoothed over.

## What Event Zero guarantees, and what it does not

**Event Zero does not promise that no malware can ever evade analysis: no tool can truthfully promise that, and you should distrust any tool that does.**

**What we guarantee is the accounting.** A verdict of NO from Event Zero means: every byte of this file was accounted for; every difference from a verified genuine reference was explained by a machine-checked explanation whose capabilities were bounded and checked; and the full receipt for that accounting is in your hands, so anyone can re-check our work.

**If any part of that accounting cannot be completed, Event Zero does not guess. The case is OPEN, not NO.**

**And if we ever learn that a NO was wrong, we will say so publicly, revoke that verdict with a signed notice, notify everyone holding it, and add the case permanently to the test suite every future release must pass. Our public miss ledger, including the misses, is in [docs/MISS-LEDGER.md](docs/MISS-LEDGER.md).**

The long form:

**We guarantee:**

1. **Completeness or no verdict.** NO is issued only when byte coverage is complete and independently asserted in the receipt. Incomplete accounting is always OPEN.
2. **Checked explanations.** Every differing region in a NO verdict carries a typed, machine-checked explanation with a bounded capability set. Capabilities beyond that set void the explanation.
3. **Verified references.** Where a NO rests on a reference, the report states that reference's provenance and how it was verified (publisher signature, or hash equality with the genuine original). A differing region that cannot be fully classified is OPEN, never waved through.
4. **Opaque means unresolved.** Code whose behaviour cannot be bounded (encrypted, self-decrypting, or environment-gated payloads) can never contribute to a NO.
5. **No silent fixes, ever.** Every confirmed miss receives a public EZ-BYPASS ID, a ledger entry, a signed revocation of affected verdicts, and a permanent regression fixture.
6. **No recurrence of a known miss.** No confirmed bypass, once fixed, will recur in a later release. Every release passes the full adversarial suite, including every miss ever found, and seeded canary fixtures, before it is signed.
7. **Revocability.** Every NO can be checked against the current signed Verdict Revocation List. If we revoke your report, we will tell you directly if we can, and publicly regardless.

**We do not guarantee:**

- That malware cannot exist which exploits a path we have not yet seen. We publish the residual paths we know about in the Miss Ledger and the verification reports, and update that list whenever we learn a new one.
- That a NO covers behaviour triggered only in environments we did not exercise. Your receipt lists the environments exercised and the opaque regions found.
- That any file is "safe" in every sense. A NO is a statement about this file, this reference, this tool and test-suite version, and this date, nothing broader.

The binding policy behind this wording is [docs/MISS-AND-REVOCATION-POLICY.md](docs/MISS-AND-REVOCATION-POLICY.md). The scoped claim language used across this project is: proof-backed, validator-checkable, complete accounting. The figure 100% is used only for the process claim (100% of issued verdicts proof-backed), never as a detection claim.

## Project files

- [CAPABILITY-MATRIX.md](CAPABILITY-MATRIX.md): every feature labelled BUILT, ADAPTER, SERVICE or HANDOFF, with its evidence
- [VERIFICATION.md](VERIFICATION.md): test runs, the adversarial sweep, the benchmark, ELI5 metrics
- [VERIFICATION-VERDICT.md](VERIFICATION-VERDICT.md): The Verdict run over the every-family verification corpus, with the full results table
- [docs/MISS-AND-REVOCATION-POLICY.md](docs/MISS-AND-REVOCATION-POLICY.md): how misses are disclosed, revoked, and turned into permanent regression fixtures
- [docs/MISS-LEDGER.md](docs/MISS-LEDGER.md): the public, append-only miss ledger
- [format-spec.md](format-spec.md): the evidence-anchored report format as an open spec, with the validator
- [HARDENING-ROADMAP.md](HARDENING-ROADMAP.md): signed reports, signed rule packs, and the adversarial regression suite plan
- [ONCE-IN-A-GENERATION.md](ONCE-IN-A-GENERATION.md): the narrow claim, and what would falsify it
- [research-v3.md](research-v3.md): sources, service tiers, BlackArch mapping
- [Event_Zero-Website/](Event_Zero-Website/): the case-file website, with real reports in its viewer

## Credits

Event Zero stands on named work: LIEF for parsing, Capstone for disassembly, Unicorn for emulation, and the design lineage of capa and FLOSS (capability rules and obfuscated string recovery), Ghidra, YARA, and CyberChef. Adapters detect and credit each tool in the registry. Author: Gavin Blacklock (Epsilon0xCell).

## License

Creative Commons Attribution-NonCommercial 4.0 International. See [LICENSE](LICENSE). Bundled fonts on the website are Chakra Petch and Inter, SIL Open Font License 1.1, licences shipped with the fonts.
