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
  <a href="https://github.com/Epsilon0xCell/Event_Zero/actions/workflows/verify.yml"><img src="https://github.com/Epsilon0xCell/Event_Zero/actions/workflows/verify.yml/badge.svg" alt="Verification corpus status from the verify workflow"></a>
  <img src="https://img.shields.io/badge/python-3.10%2B-blue" alt="Python 3.10 or newer, as declared in pyproject.toml">
</p>

> [!WARNING]
> **The Global Defence Initiative warning:** software obtained outside accountable channels is one of the most reliable malware delivery routes aimed at ordinary people, and the moment that decides the outcome is the moment before the first run. Event Zero is part of a global defence initiative to put a free, checkable verdict in exactly that moment, after the download and before the run. The full case, with dated and sourced figures, is in [Why this exists: a global defence initiative](#why-this-exists-a-global-defence-initiative) below.

## The Verdict: a proof-backed YES or NO on any file you download

The flagship feature is **The Verdict**. Drop in any download: an installer, an update, a game mod, a patched program, an archive, or a whole folder. Event Zero takes it apart piece by piece, accounts for every byte as genuine program or explained difference, and gives you one headline. Not a score. Not a probability. A verdict with its proof attached, or an open case where the accounting cannot close.

```console
$ python3 -m event_zero verdict fake_malware
YES: MALWARE FOUND
Reason class: PROVEN
```

That is the real headline on the bundled sample (Case 001 below). The proof names three behaviour chains: a credential stealer, persistence plus a remote host, and a cryptocurrency miner. Full report: [examples/fake_malware.verdict.txt](examples/fake_malware.verdict.txt).

A clean file gets the opposite headline, and it has to earn it:

```console
$ python3 -m event_zero verdict release/ --reference genuine/
NO: NO MALWARE
Reason class: ACCOUNTED
```

In the recorded run the diff ledger classified all 3 changed regions as expected-crack, the licence check patch, and nothing else. Full report: [examples/clean_crack.verdict.txt](examples/clean_crack.verdict.txt). Its scope sentence, verbatim from that report, is the whole claim and nothing more:

> Every byte is accounted for as genuine or explained crack, and no behaviour beyond the genuine program plus the explained crack was observed in the evidence. This verdict is linked to the evidence manifest in this report.

The rules that make the headline worth trusting:

- **The crack itself is not malware.** A patched licence check, a key generator, and KMS emulation are the expected crack. They appear in the accounting, never in the proof.
- **YES, PROVEN** means a behaviour chain was demonstrated from evidence in the file: theft, a miner mining for someone else, persistence plus a remote host, antivirus tampering, or the scope test (the first behaviour a file does not need for its claimed job decides it).
- **YES, UNACCOUNTED** means something could not be explained: an unexplained code region, an archive layer that would not open, a virtualized section. The accounting fails closed. Silence never becomes a pass, and UNACCOUNTED is always stated as unaccounted, never dressed up as proven malware.
- **NO** is issued only when every byte is accounted for as genuine or explained crack, against a signature-valid original or a fully classified diff, with every archive layer unpacked to the bottom.
- **OPEN** is a case state, not a third verdict. Where the accounting cannot close today (a virtualized lone binary, a server-keyed payload whose server is gone), the case stays OPEN with its open items listed, and the safety headline stays fail-closed.

## Why this exists: a global defence initiative

> **The warning at the top of this README is the warning this project is built on.** Read the figures below with their dates and sponsors attached: they are the best published measurements, several are industry funded, and the impact model at the end is scenario arithmetic, not a measured result and not a promise.

Event Zero is one instrument in a global defence initiative: cut malware infections where unlicensed software is most prevalent, by giving the person holding the file a verdict they can verify instead of a label they have to trust.

In the last comprehensive global survey, 37% of the software installed on PCs was unlicensed, and over 50% across Asia-Pacific, Central and Eastern Europe, the Middle East and Africa, and Latin America (BSA Global Software Survey, published 2018 with 2017 data; BSA is a software industry trade group and the survey was conducted with IDC). No comparable global survey has been published since, and the demand has not disappeared: piracy analytics firm MUSO counted 14.9 billion visits to software piracy sites in 2024 alone. A visit is not a download, and an unlicensed rate is a share of installed software, not a share of people; the figures below keep those universes separate.

Regional rates, BSA Global Software Survey 2018 (2017 data):

| Region | Unlicensed rate | Commercial value |
|---|---|---|
| Asia-Pacific | 57% | $16.4bn |
| Central & Eastern Europe | 57% | $2.9bn |
| Middle East & Africa | 56% | $3.1bn |
| Latin America | 52% | $5.0bn |
| Western Europe | 26% | $9.5bn |
| North America | 16% | $9.5bn |
| **World** | **37%** | **$46.3bn** |

Highest national rates in the same survey (2017 data): Libya 90%, Zimbabwe 89%, Venezuela 89%, Armenia 85%, Indonesia 83%, Moldova 83%, Belarus 82%, Algeria 82%, Azerbaijan 81%, Nicaragua 81%, Ukraine 80%, Nigeria 80%. For scale, China was 66%, Mexico 49%, and Brazil 46%.

That demand is hunted, and the hunting is measured. In a National University of Singapore study commissioned by Microsoft (2017), 34% of pirated packages downloaded from the internet were bundled with malware, 92% of new PCs sold with non-genuine software were already infected, and 24% of the bundled malware deactivated the machine's anti-malware. In IDC research sponsored by Microsoft (2014), a user obtaining a pirated package faced roughly a 1 in 3 chance of encountering malware. The independent academic anchor points the same way: in the largest independent sample of cracks and keygens (Kammerstetter et al., TU Wien, ACM CCS 2012), roughly half of the unique cracks and keygens showed malware indicators, a substantial share were malware with no working crack at all, and the authors concluded that even state of the art scanners could not fully protect users of these channels. Across methods, the defensible band for crack, keygen, and activator channels specifically is roughly 1 in 10 to 1 in 3 downloads carrying malware in measured samples, with the worst channel samples far higher. That is not a rate for all unlicensed software, much of which is a clean copy with a bad licence.

The pattern is current. Analysing 53,896 stealer infections in 2025, threat intelligence firm Flare found a "crack" or "cracked" version was the most common explicit lure (17.65% of infections, which Flare states is an undercount). The STOP/Djvu ransomware that dominated consumer ransomware reports in 2019 to 2021 spread, in Emsisoft's words, "typically through cracked software, key generators and activators." Campaigns are durable: the Crackonosh miner lived in cracked games for at least three years and infected over 222,000 systems before Avast named it in 2021. And the channel itself disarms victims: crack instructions routinely tell users to disable antivirus before running anything, which is the structural argument for a check that happens before the run and before the disable.

Field research on browser security warnings shows that clear warnings with low false positive rates are heeded 75 to 90% of the time (Akhawe and Porter Felt, USENIX Security 2013). That is why a single verdict, rather than 70 conflicting scanner labels a user can rationalise away, is the design.

### What Event Zero could reduce: scenario modelling, not a promise

Event Zero is unlaunched and has no measured efficacy or adoption yet. The model below is scenario arithmetic built from the published rates above; every input is stated so any reader can substitute their own. All figures are conditional on the verdict being correct and on the user heeding a YES.

Per 1,000 downloads checked:

| Scenario | Assumptions (share of checked downloads trojanised, share of YES verdicts heeded) | Infections that could be prevented |
|---|---|---|
| Low | 3%, 55% | about 17 |
| Central | 10%, 75% | about 75 |
| High | 20%, 85% | about 170 |

Whole year scenarios, from the same formula (active users, times downloads per user per year, times share checked, times share trojanised, times share heeded):

| Scenario | Year 1 | Year 3 | Assumption chain (Year 1) |
|---|---|---|---|
| Low | about 620 | about 2,500 | 25,000 users, 6 downloads, 25% checked, 3% trojanised, 55% heeded |
| Central | about 45,000 | about 225,000 | 100,000 users, 12 downloads, 50% checked, 10% trojanised, 75% heeded |
| High (ceiling) | about 1,070,000 | about 4,280,000 | 500,000 users, 18 downloads, 70% checked, 20% trojanised, 85% heeded |

The high scenario is a mathematical ceiling, not an expectation, and must never be quoted without the low and central scenarios beside it. It would require 2 million active users by Year 3, checking as a community norm in the forums and lists where downloads are shared, and heed rates holding at 85% with no fatigue collapse; at that scale it would rival a large fraction of the entire global crack-lure stealer flow. If real world sensitivity is below the conditional assumption (for example 80%), every figure falls proportionally. The second order effect has no honest number yet: if checking becomes a norm, a trojanised release gets burned earlier, which raises the distributor's cost and shortens the useful life of an upload, from the years Crackonosh enjoyed toward the days a public verdict makes possible. We describe that mechanism in words because the literature does not measure it for verdict tools.

We will report real impact only in measured units, after the fact: verdicts issued, files confirmed malicious that were stopped before execution, and how fast a flagged release disappears from the places it was shared.

## The 60 second quickstart

```console
$ git clone https://github.com/Epsilon0xCell/Event_Zero.git
$ cd Event_Zero
$ pip install -r requirements.txt
$ python3 -m event_zero analyze fake_malware --out report.txt
$ python3 -m event_zero verdict fake_malware
```

The sample is read as bytes. It is never executed on your machine. Optional extras (Unicorn emulation, report signing, the Gemini narrative layer) install with `pip install -e ".[full]"`.

Watch it run: the demo video is real terminal output, no mockups. [demo/event-zero-demo.mp4](demo/event-zero-demo.mp4) (MP4) or [demo/event-zero-demo.gif](demo/event-zero-demo.gif) (GIF), with the exact commands in [demo/SCRIPT.md](demo/SCRIPT.md).

### Case 001: fake_malware, in three layers

Every report opens with the same three layers. Exhibit A, the ELI5 layer, opening lines verbatim from [examples/fake_malware.report.txt](examples/fake_malware.report.txt):

> This is about a computer file called fake_malware.
> This file looks bad. It does things a good file should not do.
> Think of it like talking on a phone.
> It can open a phone line to talk to another computer.
> Think of it like hiding a spare key.
> It hides a spare key so it can come back after the computer restarts.
> Think of it like peeking at a key box.
> It looks where secret keys and passwords are kept.
> What should you do? Do not open it. Give it to a grown up who studies bad files.

Exhibit B, the plain English layer, same file: it is a Mach-O file for ARM64, 33,920 bytes, SHA-256 `c9ab06a4fd594a82eb36d1aeb72e83e99df77a2ccd6a8ebd0ad078dd6b707802`, importing `connect`, `socket`, and `system` (it connects to a remote address, creates network sockets, and runs shell commands).

Exhibit C, the evidence layer: 23 numbered sections (0 to 22) covering hashes, sections and packing, decoded strings, capabilities with MITRE ATT&CK IDs, a kill chain timeline, and a generated YARA rule built from the file's own strings.

## How the accounting works, in plain English

Read the file as bytes, never run it. Parse the format (ELF, PE, Mach-O, .NET, APK, Office, PDF, email, firmware images). Decode what it hid (Base64, XOR, RC4, multi-layer chains). Carve out embedded binaries. Open every archive layer to the bottom; a layer that will not open is recorded as unaccounted, never skipped. Match what the file can do against capability rules and against 20 researched malware families, each with a written proof standard (the evidence atoms that must be exhibited before the family name is used) and a false positive twin (the clean behaviour most easily confused with it, and the discriminator that separates them). Check evasion tricks (direct syscalls, API hashing, process injection, anti-VM checks). Census virtualized code instead of pretending to read it. Then write the layered report, the verdict, and the defences: a YARA rule, a Sigma style summary, IOC exports in CSV and STIX 2.1, and an ATT&CK Navigator layer.

For a verdict, every unit lands in exactly one of three places: proven malicious (a behaviour chain exhibited from the file), accounted (genuine, or an explained crack difference whose capabilities were machine-checked), or unaccounted (named, counted, and enough on its own to block a NO). There is no fourth bucket and no sampling: a NO is a statement about every byte, or it is not issued.

Optional layers sit on top and never change the core: hash lookups against VirusTotal, Hybrid Analysis, MalwareBazaar, ThreatFox, URLhaus, urlscan.io, OTX, MetaDefender, filescan.io and tria.ge (keys from environment variables only, hash first, upload only behind an explicit flag), and an optional Gemini narration that may only polish words from the evidence set. Anything Gemini invents is stripped by the evidence gate and listed. No key, no network: the deterministic core runs unchanged.

## Signed reports and run receipts

Every verdict and analysis run can carry a signed receipt: a canonical verdict core (RFC 8785), an Ed25519 signature, and a trust class printed next to the verdict token (CI-ATTESTED, AUTHOR-SIGNED, SELF-SIGNED, or UNSIGNED, with unsigned output labelled as such rather than hidden). Verify one yourself:

```console
$ python3 -m event_zero verify-report report.json
```

A public Verdict Revocation List can retire a report after the fact: a listed report verifies as REVOKED whatever its signature says. The format is specified in [format-spec.md](format-spec.md), and the policy that governs revocations is [docs/MISS-AND-REVOCATION-POLICY.md](docs/MISS-AND-REVOCATION-POLICY.md).

## Desktop apps

Native Windows and macOS apps live in [gui/](gui/), built on the same engine through its CLI and JSON interface. The Verdict is the first screen in both. Every result carries a scope sentence (what was checked, that nothing was executed, and what was not checked), and cancelling a folder scan mid-way produces a fail-closed partial verdict naming the unchecked files, never a clean one. Packaging commands are in [gui/README.md](gui/README.md).

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
| 20 malware families with proof standards and false positive twins | BUILT |
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
| Signed verdict reports, run receipts, Verdict Revocation List | BUILT |
| NSRL / CIRCL hashlookup | HANDOFF (corroboration only, never a NO basis) |

The report format is a published spec, [format-spec.md](format-spec.md), with a validator: `python3 -m event_zero validate report.json` checks that every claim in a report carries evidence. Three gold reports in [examples/gold/](examples/gold/) pass it.

## Its own tools

| Tool | Command | What it does |
|---|---|---|
| ez-carver | `python3 -m event_zero carve <file>` | Extracts embedded PE, ELF and Mach-O binaries with header validation |
| ez-shellcode | `python3 -m event_zero shellcode <file>` | Finds NOP sleds, egghunters and decoder stubs, enumerates ROP gadgets |
| ez-eli5 | built into every report | Generates the ELI5 layer from structured evidence (event_zero/eli5.py) |
| ez-capgen | `python3 -m event_zero capgen <file>` | Drafts capability rules from unknown patterns; a draft is promoted only if it fires on a malicious fixture and on zero benign fixtures |
| ez-diff | `python3 -m event_zero diff <a> <b>` | Plain English comparison of two samples |
| IOC export | `python3 -m event_zero export-iocs <file>` | Writes IOC CSV, STIX 2.1 bundle, and ATT&CK Navigator layer |
| Enrichment | `python3 -m event_zero enrich <file>` | Hash-first lookups against the configured services |
| Tool registry | `python3 -m event_zero tools` | Lists 30+ external tools: installed or missing, version, what each adds, BlackArch package names |

## Verification: how a stranger checks our work

Every number below names its corpus and its scope, because a score without its corpus is marketing.

- **Test suite: 166 tests passing** in the main suite, plus **18 GUI tests** passing offscreen. Run them yourself: `python3 -m pytest tests/ -q` and `python3 -m pytest gui/tests/ -q`.
- **Verification corpus: 37 of 37, zero false NO.** Purpose-built fixtures covering all 20 families, their false positive twins, designed-OPEN cases, and cold surprise fixtures, scored by an independent scorer that re-reads the fixture bytes instead of trusting the analyser's summary. Full table: [VERIFICATION-VERDICT.md](VERIFICATION-VERDICT.md). The same corpus runs in GitHub Actions inside a network-disabled container with an egress canary (the verify workflow above).
- **Validation pilot: 1,000 of 1,000 on the published pilot corpus.** The pilot measures engine and harness consistency across 68 independent clusters; it is a development instrument, not a generalisation measurement, and it is labelled that way in its own report: [validation/PILOT-REPORT.md](validation/PILOT-REPORT.md). Its first run scored 992 of 1,000 and caught two real defects (below). After the fixes, the rerun scored 1,000 of 1,000 with expectations untouched.
- **The miss ledger is public.** The pilot's two defects are entered as EZ-BYPASS-2026-001 (truncated or unenumerable archives were certified clean; containers now fail closed) and EZ-BYPASS-2026-002 (an archive's own bytes were judged as content, so a document inside a zip lost its context; containers are now enumeration units and members are judged as loose files). Both fixes ship with permanent regression fixtures. Ledger: [docs/MISS-LEDGER.md](docs/MISS-LEDGER.md).
- **Early adversarial sweep** (recorded in [VERIFICATION.md](VERIFICATION.md)): five fixtures built after the modules, with tricks the modules were not designed around. Two cold misses were found, fixed, and locked in as regression tests. One limit is labelled, not hidden: on the firmware fixture the combined SMM-plus-network flag does not fire per driver yet; the evidence is in the report and per-driver verdicts are the documented next step.

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

ELI5 reading level, measured per report: 10.2 to 11.8 average words per sentence across six reports, with 0 untranslated banned jargon terms. The design target (Flesch Reading Ease at least 80, Flesch-Kincaid at most 6) is a design target, not a standard, and is labelled as one in the code.

## Roadmap: the 100,000 case programme

The pilot harness is phase one of a pre-registered validation programme: a stratified 100,000 case corpus with a custodian-held blind portion, sealed expectations, an independent scorer, and a frozen gate run once per release candidate. The protocol, strata, scoring rules, and the exact claim wording a perfect run would license are published in advance in [validation/PREREGISTRATION.md](validation/PREREGISTRATION.md). Corpus scaling is underway. Until that gate runs, no 100,000 case result exists and none is claimed here; the programme's progress log is [validation/PROGRESS.md](validation/PROGRESS.md).

## Safety

- Samples are never executed on the host. Emulation services no syscalls. Detonation belongs in your own isolated CAPE sandbox.
- Uploads are off by default. Enrichment is hash first, and the report footer carries hash-only lookup links: only the hash leaves the machine.
- API keys are read from environment variables only (`GEMINI_API_KEY`, `VIRUSTOTAL_API_KEY`, `ABUSECH_API_KEY`, and the rest in [.env.example](.env.example)). Never put a key in a commit, a config file, or a chat.
- Every bundled fixture is synthetic and self-crafted. No live malware is included or downloaded.
- Research and dual use: Event Zero is a defensive research tool for analysing files you have the right to analyse. Its capability rules describe malware behaviour in order to detect and explain it; the bundled fixtures carry those behaviours as inert data for the analyser, and nothing in the repository is a working malicious program.

## Honest limits

- Full decompilation of packed or virtualized code is not possible, for any tool. Event Zero censuses virtualized regions, traces what crosses into the real world, and marks the rest UNACCOUNTED rather than guessing. A lone binary protected by a virtualizing protector stays OPEN.
- "Zero-day" is a disclosure status, not something a binary can certify. Exploit reports state the bug class and the primitive, and print disclosure status: unknown.
- A payload keyed to a server that no longer answers, or to an environment that cannot be reproduced, cannot be accounted. Those cases stay OPEN with the residual named, and no verdict of NO is issued over them.
- A NO verdict is an accounting claim, stated exactly: every byte accounted for as genuine or explained crack, no behaviour beyond genuine plus explained crack observed, manifest linked. It is a statement about this file, this reference, this tool version, and this date.
- Static analysis infers behaviour; it does not observe it. Reports say which layer produced each claim, and unknowns get their own section instead of being smoothed over.
- Rootkit findings are stated as "indicators consistent with" unless a memory image confirms them through the Volatility handoff. Firmware findings name the driver or volume they came from.

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

The binding policy behind this wording is [docs/MISS-AND-REVOCATION-POLICY.md](docs/MISS-AND-REVOCATION-POLICY.md). The scoped claim language used across this project is: proof-backed, validator-checkable, complete accounting. The figure 100% is used in this project only for the process claim (100% of issued verdicts proof-backed), never as a detection claim.

## Contributing

Contributions are welcome under the project's discipline:

- Run the tests before proposing a change: `python3 -m pytest tests/ -q` (and `gui/tests/` for GUI work). A change that breaks a regression fixture for a ledgered miss is rejected on that ground alone.
- Never commit a live sample, an API key, or a real user's file. Fixtures are synthetic, disarmed by construction, and documented as such.
- Claims in documentation follow the same rule as claims in reports: every number names its corpus and scope, and the banned vocabulary (detection guarantees, accuracy absolutes) stays out.
- A new capability rule ships with its positive example and its false positive twin, or it does not ship.

## Security

See [SECURITY.md](SECURITY.md). In short: Event Zero is a defensive research tool, samples are never executed, and the verification corpus is synthetic and disarmed by construction. Reports of a wrong verdict are handled under the Miss and Revocation Policy: confirmed misses are published in the Miss Ledger with an EZ-BYPASS identifier, affected verdicts are revoked the same day, and the case becomes a permanent regression fixture. There are no silent fixes.

## Project files

- [CAPABILITY-MATRIX.md](CAPABILITY-MATRIX.md): every feature labelled BUILT, ADAPTER, SERVICE or HANDOFF, with its evidence
- [VERIFICATION.md](VERIFICATION.md): test runs, the adversarial sweep, the benchmark, ELI5 metrics
- [VERIFICATION-VERDICT.md](VERIFICATION-VERDICT.md): The Verdict run over the every-family verification corpus, with the full results table
- [validation/](validation/): the validation harness, pilot report, pre-registration, and progress log for the 100,000 case programme
- [demo/](demo/): the demo video (MP4 and GIF) and the script of exact commands behind it
- [gui/](gui/): the native Windows and macOS apps
- [docs/MISS-AND-REVOCATION-POLICY.md](docs/MISS-AND-REVOCATION-POLICY.md): how misses are disclosed, revoked, and turned into permanent regression fixtures
- [docs/MISS-LEDGER.md](docs/MISS-LEDGER.md): the public, append-only miss ledger
- [format-spec.md](format-spec.md): the evidence-anchored report format as an open spec, with the validator
- [HARDENING-ROADMAP.md](HARDENING-ROADMAP.md): signed reports, signed rule packs, and the adversarial regression suite plan
- [ONCE-IN-A-GENERATION.md](ONCE-IN-A-GENERATION.md): the narrow claim, and what would falsify it
- [research-v3.md](research-v3.md): sources, service tiers, BlackArch mapping
- [SECURITY.md](SECURITY.md): the security policy and the synthetic corpus statement
- [Event_Zero-Website/](Event_Zero-Website/): the case-file website, with real reports in its viewer

## Credits

Event Zero stands on named work: LIEF for parsing, Capstone for disassembly, Unicorn for emulation, and the design lineage of capa and FLOSS (capability rules and obfuscated string recovery), Ghidra, YARA, and CyberChef. Adapters detect and credit each tool in the registry. Author: Gavin Blacklock (Epsilon0xCell).

## License

Creative Commons Attribution-NonCommercial 4.0 International. See [LICENSE](LICENSE). Bundled fonts on the website are Chakra Petch and Inter, SIL Open Font License 1.1, licences shipped with the fonts.
