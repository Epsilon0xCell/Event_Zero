# Event Zero v3 Launch Surfaces: Ready State

Written 2026-11-23. This file is the wait state for the launch build. The launch surfaces (README, website, video) are planned in BRANDING.md and VIDEO-PLAN.md and are deliberately not built yet, because v3 is still being built and its claims are not yet verified.

## 1. The trigger

Work in this file starts the moment both of these are true:

1. `~/workspace/event-zero-v3/VERIFICATION.md` exists and records the v3 test suite passing, with the benchmark run and the surprise fixture results written up in it.
2. `~/workspace/event-zero-v3/Event_Zero/CAPABILITY-MATRIX.md` (or the matrix at the location the v3 build records in its progress notes) exists, with every row marked Built, Adapter, Service or Handoff, each with its evidence.

If either file is missing, incomplete, or records failing tests, the launch build does not start. A shorter launch later is better than a polished launch now that has to be corrected in public.

## 2. Exactly what will be built, in order

Build order is fixed. Each step is checked before the next begins.

1. Claims ledger first. Extract every factual claim the README, website and video will make, from VERIFICATION.md, the capability matrix and the saved example reports, into a working list where each claim names its source (test name, example report file, or matrix row). Any claim without a source is deleted at this step, before any design work. This ledger is a working file for the launch build and is kept with the launch artefacts.
2. Example report pack. Copy the verified example reports that the surfaces will quote (at minimum fake_malware, the firmware fixture and the evasion fixture) into the launch working set, byte identical to the verified examples. All excerpts on all surfaces come from these files and nowhere else.
3. README. Build README.md to the structure in BRANDING.md section 5, in the v3 repository tree (not pushed anywhere as part of this step). Fill the benchmark table from VERIFICATION.md. Generate or mechanically check the capability summary table against the matrix.
4. Website. Build the single page site to the structure in BRANDING.md section 6, evolving the existing forensic site (palette, Chakra Petch and Inter, case file framing, existing logo files). Implement the report viewer as static shipped report files with a case picker limited to verified cases, and the layer switcher (ELI5, Plain English, Evidence).
5. Ecosystem diagram. Draw the three ring diagram from the v3 tool registry output, so every name on it is a registry entry. Export as SVG with a PNG fallback, with alt text.
6. Video. Record and assemble the demo video exactly to VIDEO-PLAN.md: real runs only, in a clean demo directory, with subtitles (SRT and WebVTT) and a transcript. Keep the asciinema cast files, or the script typescripts if the fallback path is used, as source artefacts.
7. Social and description copy. Repository description and any launch post copy, written last, from the finished surfaces, under the same voice rules. No new claims are introduced at this step.
8. Final audit pass. Run every acceptance check in section 3 over all surfaces together, fix findings, and record the results in a launch check file next to this one. Only after that does anyone propose pushing or publishing, which is a separate decision for Mister Blacklock and is not authorised by this plan.

## 3. Acceptance checks

All checks must pass, with results recorded, before the launch is called ready.

### 3.1 Claims audit

- Every capability, number and comparison on the README, website and video narration or subtitles is traced to the claims ledger and its source. Untraced text is removed.
- The capability summary on the README and the website matches CAPABILITY-MATRIX.md word for word in its status column (Built, Adapter, Service, Handoff). No Adapter is described as built in, no Service as offline, no Handoff as automated.
- Benchmark numbers on the README, website and any video addition are identical to each other and to VERIFICATION.md, with the method stated wherever a number appears.
- Banned word scan across all surfaces, including alt text, subtitles and file names: revolutionary, ultimate, perfect, detects all, 100 percent accurate, replaces analysts. The only permitted use of a percentage is a measured result quoted with its method.
- Honest limits copy is present on the README and the website at body text size, and the Unknowns concept appears in the video.
- Credit check: capa, FLOSS, Ghidra, LIEF, Capstone and every adapter or service actually referenced are credited by name. Author identity reads Gavin Blacklock (Epsilon0xCell) and a grep for the legal surname across all launch files returns zero.
- Em dash check: a grep for the em dash character across all launch text files, subtitles and alt text returns zero.

### 3.2 Link check

- Every external link on the README and website is fetched and returns a live page, checked on the build day: tool and service homepages, documentation, the repository itself, hash lookup links for each case in the viewer (verified against the case SHA-256), and the video link or embed.
- Every internal anchor resolves, every linked file exists in the tree (research, matrix, verification, examples, license), and the one command in the hero is run once from a clean clone of the launch tree to prove the documented path works as written.
- No link uploads a sample or carries a key. Hash lookup links carry only the hash, and the page copy says so next to them.

### 3.3 Mobile check

- The website is rendered at phone width (iPhone class viewport, about 390 pixels wide) and checked page by page: hero command readable and copyable, ELI5 excerpt readable without horizontal scrolling, viewer layer switcher operable, capability table shown as stacked cards, video playable with subtitles visible.
- The README is read on a phone width render of the repository page: hero, demo and ELI5 excerpt must land in the first screens, tables must not force horizontal scrolling that hides the status column.
- The video is watched once at phone size with sound off and subtitles on, start to finish. If any report line is unreadable at that size, the terminal font size in the recording setup is increased and the affected shots are re-recorded, not sharpened in post.

### 3.4 Video specific checks

- Each shot's on screen output is compared against the verified example reports. Any mismatch, including a different verdict, capability name or fixture filename, fails the video.
- Timestamps confirm the length is between 90 and 150 seconds.
- Subtitles pass the em dash and banned word scans, and the transcript matches the final narration.
- A frame by frame skim confirms no keys, personal paths, notifications or unrelated windows appear.

## 4. What is not authorised by this plan

- No GitHub changes of any kind: no push, no release, no repository description edit, no Pages deployment. Those are separate decisions after the audit passes.
- No new logo file, no rebrand, no rename.
- No publication of benchmark numbers, capability claims or the video anywhere outside the local tree before the checks in section 3 are recorded as passing.
