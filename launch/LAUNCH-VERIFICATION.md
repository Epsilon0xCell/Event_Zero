# Event Zero v3 Launch Verification

Run 2026-11-23 against the launch build (README.md, Event_Zero-Website/, branding assets). Build order followed from READY.md: claims ledger first (launch/CLAIMS-LEDGER.md), example report pack copied byte-identical, README, website, ecosystem diagram (assets/ecosystem.svg with assets/ecosystem.png fallback). The video step is a separate later task and was not built; no surface links or promises it. Nothing was pushed and GitHub was not modified.

## 1. Claims audit: PASS

- Every claim on the README and website traces to launch/CLAIMS-LEDGER.md, and from there to VERIFICATION.md, CAPABILITY-MATRIX.md, or a saved example report.
- Capability status words on both surfaces match CAPABILITY-MATRIX.md: BUILT, ADAPTER, SERVICE, HANDOFF. The handler semantics devirtualization pass is labelled ADAPTER / HANDOFF on both surfaces, never built in. Live Gemini is labelled SERVICE.
- Benchmark numbers are identical on the README, the website, and VERIFICATION.md (rules-only vs full pipeline per fixture, 91 tests, ELI5 10.2 to 11.8 average words per sentence, 0 untranslated jargon).
- Verdict headlines quoted on the surfaces were reproduced live during this audit: running `python3 -m event_zero verdict fake_malware` in the v3 tree printed "YES: MALWARE FOUND / Reason class: PROVEN", matching examples/fake_malware.verdict.txt and the website hero strip.
- Banned word scan (revolutionary, ultimate, perfect, detects all, 100 percent accurate, replaces analysts) across README.md and Event_Zero-Website/index.html: 0 matches after one fix. The first pass found the word "perfect" inside the honest-limits negation on both surfaces; the sentence was reworded to "Full decompilation of packed or virtualized code is not possible" so the scan is clean without weakening the limit.
- Honest limits copy is present at body size on both surfaces (README "Honest limits", website Section 06).
- Credit check: LIEF, Capstone, Unicorn, capa, FLOSS, Ghidra, YARA, CyberChef are credited by name on both surfaces. Author identity reads Gavin Blacklock (Epsilon0xCell).
- Em dash scan across README.md, the website HTML, the claims ledger, and the SVG assets: 0.
- Legal surname scan across README.md, Event_Zero-Website/, and the claims ledger: 0.
- Badges: only three, all verifiable: license (CC BY-NC 4.0, matches LICENSE), the tests workflow badge (the workflow file tests.yml ships in .github/workflows/), and Python 3.10+ (matches pyproject.toml requires-python). No star, fork, or download badges.

## 2. Example report pack: PASS

The six reports the website viewer ships were copied from examples/ and verified byte-identical with cmp: fake_malware.verdict.txt, clean_crack.verdict.txt, fake_malware.report.txt, firmware_uefi.report.txt, dotnet_evasion.report.txt, eicar.report.txt. All internal file links from the README and the website resolve to files present in the tree (checked one by one: examples, gold reports, matrix, verification, format spec, hardening roadmap, once-in-a-generation note, research, .env.example, LICENSE, website assets).

## 3. Viewer check: PASS

- The viewer's section splitter was replicated against all six shipped reports: every file splits with section 0 (the ELI5 layer) first, 7 sections for verdict files and 17 matched headers for analysis reports (headers containing lowercase fold into the preceding section, so no report text is lost in any layer).
- Layer mapping: ELI5 shows section 0; Plain shows sections 0 to 1 for verdicts and 0 to 2 for reports; Evidence shows the remainder.
- JavaScript syntax checked with node --check: OK.
- Hash lookup links are generated from each case SHA-256 only, and the page copy next to them states that only the hash leaves the page. No upload link exists anywhere on the page.

## 4. Link check: PASS with one note

Fetched on the build day with curl: repository page 200, VirusTotal hash page for Case 001 200, ANY.RUN submissions 200, Intezer hash page 200, tests workflow badge 200, both shields.io badges 200. Joe Sandbox search returned 403 to the automated fetch, which is its bot protection answering a script, not a dead link; the URL pattern is the same one the tool itself prints in its verified report footer (examples/fake_malware.report.txt). Recorded as a note, not a failure.

## 5. Mobile check: STATIC AUDIT PASS, render check not run

No headless browser exists in this build environment, so the page was audited statically rather than screenshot-verified at 390px. Recorded honestly: this is the one READY.md check still owed a real-device pass. Static evidence: viewport meta present; a max-width 560px media query converts tables to stacked cards (status column stays visible as its own block), shrinks the report viewer text and caps its height at 70vh, wraps the hero verdict strip, and the hero command sits in a horizontally scrollable mono block with a copy button that never shrinks. Report text uses pre-wrap with word-break, so the ELI5 layer cannot force horizontal scrolling.

## 6. Branding assets

- Existing logo test: logo.png (900 by 900, copied into the v3 tree root with banner.png) was downscaled with Pillow. At 64px it reads as a blurred medallion with no letterform; at 16px it has 235 distinct colours and no dominant shape. Verdict: the existing mark fails at 16px, which is the open task BRANDING.md section 3.3 recorded.
- New simplified variant, same identity (black ground, evidence amber, paper): Event_Zero-Website/assets/ez-mark.svg, a thick amber ring (the zero) under paper crosshair ticks with a centre dot. Rendered at 16px it uses 3 colours and the ring-plus-ticks geometry survives. The original logo.png is kept untouched as the large-size mark.
- Favicon: assets/favicon.svg plus favicon-16/32/64.png renders of the same mark.
- Social preview: assets/social-preview.png (1280 by 640), drawn programmatically with the self-hosted Chakra Petch and Inter fonts: case file header, the mark, the short positioning line, and the real Case 001 verdict strip. Inspected visually twice; an overlap between the mark and the headline in the first render was fixed and re-inspected.
- Ecosystem diagram: assets/ecosystem.svg (three rings drawn from the tool registry names) with assets/ecosystem.png as the fallback render; alt text on the page follows the voice rules.

## 7. Not done, by design

- Demo video: separate later task per VIDEO-PLAN.md.
- Repository description and social copy (READY.md step 7) are derived from these finished surfaces but are not applied anywhere; applying them is a GitHub change and is not authorised.
- No push, no release, no Pages deployment.
