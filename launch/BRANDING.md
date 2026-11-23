# Event Zero v3: Branding, README and Website Plan

Status: plan only, written 2026-11-23 while v3 is still being built. Nothing in this file is a finished launch surface. Every capability statement in the final README and website must be rechecked against the v3 VERIFICATION.md before publication. See READY.md for the build order and acceptance checks.

## 1. Research: how category defining security tools present themselves

Method: web research on 2026-11-23 into the public positioning of Nmap, Ghidra, Wireshark, Metasploit, CyberChef, DogBolt (Decompiler Explorer), capa and Velociraptor, plus the structure of high performing security GitHub READMEs. Sources are listed at the end. The pattern below is what the evidence supports, stated without borrowing any tool's own claims for Event Zero.

### 1.1 One tool, one sentence, one job

- Nmap: the official line is a single functional sentence, a free and open source utility for network discovery and security auditing. The name itself is a compression of the job: Network Mapper. No adjectives about power, no feature list in the headline.
- CyberChef: GCHQ's own README leads with a nickname that does the positioning work, The Cyber Swiss Army Knife, then one sentence about operations inside a browser. The metaphor tells a new user what shape of tool it is before any feature is named.
- capa: Mandiant's README opens with one plain sentence, capa detects capabilities in executable files, then immediately shows what that means: run it on a file and it may suggest the file is a backdoor, can install services, or relies on HTTP. Positioning first, example second, internals last.
- Wireshark: positioned everywhere as the network protocol analyzer, with the shark fin mark doing instant recognition. The job is the brand.
- Metasploit: positioned as a framework, not a script. The word framework promises an ecosystem and a way of working, and the project grew sub projects around the core rather than diluting the core promise.
- Ghidra: NSA origin is part of the identity, and the mark is a red dragon formed into a loop, memorable at favicon size. The positioning is a software reverse engineering framework. Authority came from the institution and from giving away, free, a capability class that had been expensive.
- DogBolt (Decompiler Explorer): the positioning is the comparison itself, several decompilers side by side on one binary. One visual idea a visitor understands in seconds.
- Velociraptor: positioned as endpoint visibility and collection, built around one named idea, VQL, and one mascot mark. A query language gave the community something to write, share and collect around.

### 1.2 The shared pattern

Every one of these tools can be described with the same five slots, and Event Zero v3 launch surfaces must fill all five before design work starts:

1. Name: short, pronounceable, ownable in search, ideally compressing the job or the moment. Event Zero already has this: the name names the first sample, the ground zero file a case starts from.
2. Mark: one simple shape that survives at 16 pixels, one or two colours, no detail. See section 3 for the direction, using the existing logo rather than inventing a new one in this plan.
3. One sentence: the positioning line in section 2. It must name the input, the output and the differentiator, and nothing else.
4. One visual proof: a single screenshot, terminal capture or report excerpt that shows the output, not the architecture. For the tools above this is a scan result, a recipe, a capability table. For Event Zero it is the ELI5 section of a real report, specified in section 4.
5. One command: a single copyable command that gets a stranger from clone to first result. capa shows one invocation. CyberChef is one URL. Event Zero already has one: `python3 -m event_zero analyze fake_malware --out report.txt`. The launch surfaces protect that simplicity: no required Docker, no required key, no required network in the hero path.

### 1.3 What strong security READMEs do above the fold

From the capa README and comparable projects, the working order is consistent:

- Logo or name, then a badge row that carries only verifiable facts: license, latest release, CI status, rule or test counts where a live badge exists, downloads where the platform provides them. Badges that matter are the ones a sceptical reader can click and confirm. Decorative badges, star begging and unverifiable claims are excluded.
- The one sentence positioning, in the first screenful.
- A real output excerpt or terminal capture within the first screenful, before installation detail. capa shows its ATT&CK table immediately. This is the single highest leverage README element: proof before instructions.
- A demo animation or video link near the top, short, showing a real run. See VIDEO-PLAN.md.
- Only then: install, usage, depth, contributing, license.

### 1.4 What this means for Event Zero

The category Event Zero enters already has trusted names for each layer: Ghidra for decompilation, capa for capabilities, FLOSS for obfuscated strings, VirusTotal for reputation, sandboxes for behaviour. Event Zero does not out claim any of them, and the brand must never position it as replacing them. The open seat, and the whole brand, is translation and fusion: many engines, one evidence file, written so a non specialist can act on it, with an anti hallucination gate on any AI narration. That is the positioning the research supports and the one the v3 build is actually implementing.

## 2. Positioning

Primary positioning line, for the README hero, the website hero and the repository description:

> Event Zero turns a suspicious file into a plain English report anyone can act on, with every claim tied to evidence found in the file itself.

Short form, for badges, social cards and talk slides:

> Malware in. Plain English out. Evidence attached.

Rules for the positioning line:

- It names input (a suspicious file), output (a plain English report) and differentiator (evidence attached). It does not claim perfect decompilation, complete coverage of all malware, or replacement of analyst tools.
- ELI5 is named as a layer, not as the whole product: the report leads with an explain like I am five summary, then plain technical English, then full evidence. The hero shows all three layers exist, so security readers do not mistake the tool for a toy.
- The words revolutionary, ultimate, 100 percent and perfect are banned from launch surfaces except where a number is a measured test result quoted with its method, in the benchmark section only.
- Gemini, VirusTotal and every external tool are described as optional layers that narrate or enrich evidence. The deterministic core, which needs no key and no network, is the product. This matches the v2 verified behaviour and the v3 design.

## 3. Visual identity direction

Decision: keep and evolve the existing forensic identity. Do not invent a new logo file in this phase.

Evidence for keeping it: the shipped website already carries a coherent forensic system, a case file framing (its title reads: Event Zero, specimen under examination, case file EZ / fake malware / 01), a dark examination palette and a two font pairing. Category defining tools almost never rebrand at the moment of a capability jump; recognition compounds. A new mark now would spend recognition the project has already earned and would separate the website from the existing logo, banner and visual assets already on GitHub.

### 3.1 Palette, evolved from the existing site

Existing site values, read from the shipped website on 2026-11-23:

- Examination black: #0e1013 (page ground), with panel tones #14161a and #191c1e.
- Evidence amber: #e39a1e, with deep amber #a96f0c for rules and secondary marks.
- Paper text: #eceff0 and #eef1f2 on dark, muted steel #b9bfc2 and #454b51 for secondary text and borders.

Evolution rules for v3 surfaces:

- Keep black and amber as the only brand colours. Amber is the evidence colour: it marks findings, highlights, exhibit tags and the verdict, and nothing else. If everything is amber, nothing is evidence.
- Add one functional colour only, reserved for the risk verdict scale, and derive it from report semantics rather than decoration: a muted red for high and critical verdicts, a muted green for clean and test file verdicts. It appears in reports, the website report viewer and the video, identically, so the scale becomes a learned brand asset.
- No gradients as decoration, no stock imagery, no generic shield or padlock clip art. Texture comes from real artefacts: hex, report text, section lines, exhibit labels.

### 3.2 Type

- Headings: Chakra Petch, already self hosted on the site with its licence, SIL Open Font License 1.1. It reads technical and forensic without costume.
- Reading text: Inter, already self hosted the same way.
- Data, hashes, terminal and report excerpts: a monospace stack, as the site already uses (ui-monospace, Menlo, Consolas). Report excerpts on the website must be real report text in monospace, never a redrawn mock.

### 3.3 Logo usage

- Use the existing Event Zero logo files already in the repository (logo.png and banner assets) as the mark for v3. This plan does not create, redraw or replace a logo file.
- Usage rules to apply when surfaces are built: mark plus wordmark in the hero, mark alone as favicon and social avatar, clear space equal to the height of the E in the wordmark, never place the mark on photography, never recolour it outside the black, amber and paper palette.
- One open task for the build phase, recorded here rather than solved here: confirm the existing logo reads at 16 pixels. If it does not, the fix is a simplified small size variant of the same mark, approved as its own task, not a new identity.

### 3.4 The case file system as the brand device

The existing site's strongest asset is its framing: every sample is a case file, opened on the examination table. Extend that into the system that ties all launch surfaces together:

- Reports are case files: the v3 report already carries file identity, hashes and exhibits in spirit; launch surfaces present report excerpts as exhibits with tags (Exhibit A: the ELI5 summary. Exhibit B: the decoded strings. Exhibit C: the generated YARA rule).
- The website report viewer in section 5 is an examination table: pick a case, read the layers.
- The video in VIDEO-PLAN.md is shot as an examination: one case, opened live on a terminal.
- Case numbers give social and talk material a repeatable form without inventing results: Case 001 is always the bundled fake_malware, so any reader can reproduce every public claim on their own machine. Reproducibility is the brand.

## 4. Voice rules

These bind README, website, video narration and social copy for the launch.

1. Zero em dashes, everywhere, including alt text and subtitles. Use commas, colons, semicolons, periods or parentheses.
2. No overclaim. Banned unless tied to a measured result with method stated: revolutionary, ultimate, perfect, complete protection, detects all, 100 percent accurate, replaces analysts, AI powered as a standalone claim.
3. Every claim tied to a test. Any sentence that says Event Zero does something must be traceable to a v3 test, a saved run in examples, or a row in CAPABILITY-MATRIX.md marked BUILT or ADAPTER with its evidence. If it cannot be traced, it is cut or rewritten as a roadmap item and labelled as one.
4. Honest limits are copy, not fine print. The limits paragraph from the v2 README is the model and stays: perfect decompilation of packed or virtualised code is not possible, unknowns are printed rather than hidden, and the report says so. Launch surfaces quote the limits in the same size as other body copy. A tool that states its limits in public is the trust signal this brand is built on.
5. Plain English first, jargon translated in the same sentence. Any term a non specialist would not know (syscall, entropy, persistence, payload) is translated where it first appears, in the README, on the website and in the video narration, exactly as the ELI5 layer does inside reports.
6. Evidence language. Findings are stated as evidence and inference: the file contains, the evidence shows, this suggests. Runtime behaviour is never stated as observed unless a sandbox or emulation layer actually produced it, and then the layer is named.
7. Names and credit. Author identity on public surfaces is Gavin Blacklock (Epsilon0xCell). No legal surname anywhere. Tools Event Zero builds on are credited by name (capa, FLOSS, Ghidra, LIEF, Capstone and the rest) wherever their output or design is referenced. Credit is part of the brand: the fusion tool that names its sources.

## 5. README structure spec

Target file: README.md at the repository root, replacing the v2 README only after v3 verification lands. Structure, in order:

1. Hero block: existing logo, the primary positioning line, the short form line, and a badge row limited to verifiable badges: license (the repository license as shipped), CI status from the tests workflow, latest release or last commit as the platform provides, and Python version support as tested. No other badges.
2. The 60 second demo: the one command on fake_malware, followed by a short real terminal capture or the demo video thumbnail linking to VIDEO output (see VIDEO-PLAN.md), then the first screen of the real report. A reader must see output before any explanation.
3. ELI5 sample excerpt: a verbatim excerpt of the ELI5 section from the saved fake_malware example report, in a quote block, labelled as real output with the command that reproduces it. Below it, one short excerpt of the technical layer and one of the evidence layer for the same sample, so the three layer structure is proven on one page.
4. What it does, in plain English: a short section translating the pipeline: read the file as bytes, never run it on the host, parse it, decode what it hid, match what it can do, ask outside services what they have seen, then write the layered report and the defences.
5. Capability matrix summary: a compact table summarising CAPABILITY-MATRIX.md, one row per capability area (formats, unpacking, firmware, rootkit drivers, exploits and shellcode, evasion, documents and scripts, enrichment services, defence generation, ELI5) with its status word (Built, Adapter, Service, Handoff) exactly as the matrix states. The full matrix stays a linked file. The README table must be generated or checked against the matrix at build time, never maintained as a second, drifting copy by hand.
6. Benchmark table: a placeholder in this plan, filled only from the v3 benchmark run: fixture, what basic rules alone found, what the full pipeline found, ELI5 reading level numbers, with the method in one paragraph and the corpus described. No numbers are written in the launch build until VERIFICATION.md supplies them.
7. Ecosystem diagram: one diagram, drawn from the tool registry, showing three rings: built in modules at the centre, free tool adapters around them (Ghidra headless, capa, FLOSS, Detect It Easy, YARA, binwalk or unblob, Speakeasy or Unicorn, binutils), and free services on the outside (VirusTotal, Hybrid Analysis, MalwareBazaar, ThreatFox, URLhaus, urlscan.io, OTX and the rest as verified), with Gemini marked as the optional narration layer. Every name on the diagram must correspond to a registry entry. The diagram is an inventory, not an aspiration map.
8. Install: the short path first (clone, pip install, run), then optional layers in order of value: Python dependencies, free tool adapters with their install hints including BlackArch package names where the registry records them, service keys as environment variables with the warning that keys never go in chat, commits or config files in the repo.
9. The own tools: one short subsection per shipped ez tool (carver, shellcode decoder, ELI5 generator, capability rule drafter, sample differ), each with its one command and one line of proven output. Only tools that ship with tests are listed.
10. Safety: samples are never executed on the host, uploads to services are off by default and hash first, live malware belongs in an isolated sandbox, and the bundled fixtures are synthetic. State plainly that the bundled fake_malware is a test sample and how it was verified.
11. Honest limits: the limits section, full size, as in rule 4 of the voice rules.
12. Tests and verification: how to run the suite, the passing count as verified, and links to VERIFICATION.md, the capability matrix and the example reports.
13. Contributing, license and credit: including the credit list from voice rule 7.

Length discipline: the README is a proof document, not a manual. Anything that needs more than a screen moves to linked docs (research, matrix, verification). If a section cannot be filled with verified content at build time, it ships shorter, not padded.

## 6. Website structure spec

Target: one single page site, evolving the existing Event Zero website rather than replacing its identity. The existing site is a static forensic page in the Event Zero Website folder of the repository, with self hosted fonts; the v3 site keeps that stack (static HTML, no build step, no tracking) unless the build phase records a reason to change it.

Page structure, in scroll order:

1. Hero: mark, positioning line, short form line, the one command in a copyable block, and two actions only: run it (link to README install) and read a real report (anchor to the viewer below). No email capture, no modal.
2. The examination: the live sample report viewer concept. A static, pre generated viewer, not a server: the verified example reports ship as text and JSON with the site, a case picker lists the cases (Case 001 fake_malware, plus the v3 fixture cases as verified: firmware, evasion, packed, document and the rest that pass), and the viewer renders the selected report in its three layers with a layer switcher (ELI5, Plain English, Evidence). Hash search links for the selected case, generated from its SHA-256 for the services that support hash lookup, are shown under a label that states only the hash leaves the machine. Nothing is uploaded, nothing is executed, and the viewer works offline from the shipped files. If a case is not in VERIFICATION.md, it is not in the picker.
3. Capability matrix section: the same summary table as the README, rendered from the same matrix source, with status words and a link to the full matrix.
4. Benchmark section: the verified benchmark table and method, identical numbers to the README. One number, one source, both surfaces.
5. Ecosystem section: the three ring diagram from the README spec, with a tools list under it generated from the registry output (name, installed or adapter status model, what it adds), so the page teaches the shape: core, adapters, services, narration.
6. Video section: the demo video from VIDEO-PLAN.md, embedded or linked, with its subtitle file and a transcript on the page for accessibility and search.
7. Safety and limits section: the same honest limits copy as the README, plus the hash only enrichment warning.
8. Get it section: clone and run commands, links to the repository, the reports, the matrix and the research. Footer with license and credit list.

Design rules for the site build:

- Same palette, type and case file system as section 3. Exhibit tags label every report excerpt.
- Mobile first check: the hero command, the ELI5 excerpt and the viewer layer switcher must be fully usable at phone width, since the owner reviews on iPhone. Tables collapse to stacked exhibit cards on narrow screens rather than horizontal scrolling.
- Performance and honesty: no external trackers, fonts self hosted as they already are, every image is a real capture or the existing brand assets, no stock photography.
- Accessibility: verdict colours always paired with text labels, subtitles and transcript for the video, alt text that follows the voice rules including zero em dashes.

## 7. Sources for the research in section 1

- CyberChef README, GCHQ: nickname positioning (The Cyber Swiss Army Knife), one sentence scope, live demo near the top, four part how it works. Retrieved through search of the project README, 2026-11-23.
- capa README, Mandiant: logo, verifiable badge row (release, rule count, CI, downloads, license), one sentence definition, immediate ATT&CK output table as proof. Retrieved through search of the project README, 2026-11-23.
- Google Cloud and Mandiant writing on capa: capability detection explained through example behaviours (backdoor, service installation, HTTP communication), the example second pattern. Retrieved 2026-11-23.
- Nmap official book and project descriptions: the one sentence definition (free and open source utility for network discovery and security auditing), name as job compression, project family around a stable core. Retrieved 2026-11-23.
- Ghidra public material: NSA origin, red dragon loop mark, framework positioning. Retrieved through search, 2026-11-23.
- Wireshark and Velociraptor public material: single job positioning (protocol analyzer; endpoint visibility and collection), mascot and fin marks, Velociraptor VQL as the named community idea. Retrieved through search, 2026-11-23.
- Existing Event Zero website and v2 README, read locally 2026-11-23: forensic case file framing, palette values, Chakra Petch and Inter pairing, the twelve section report, the limits paragraph and the one command quick start. These are the identity and voice baselines this plan evolves rather than replaces.
