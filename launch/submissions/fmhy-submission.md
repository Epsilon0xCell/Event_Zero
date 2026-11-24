# FMHY Submission Draft: Event Zero

Status: DRAFT ONLY. Do not submit yet. See READINESS.md in this folder for the conditions that must be true before this is sent.
Prepared: 2026-11-23.

## 1. Route facts, verified 2026-11-23

- FMHY's content source repository is `fmhy/edit` on GitHub (description: "Make changes to FMHY"). Content pages are Markdown files under `docs/`; the rendered site is fmhy.net.
- The official contribution guide is at fmhy.net/other/contributing ("Contributing: freemediaheckyeah"). Read in full on 2026-11-23.
- The guide's stated preference for new links: "using an issue rather than a pull request is easier", because FMHY staff have to check sites themselves. Feedback system and Discord are the other named routes.
- All additions go through FMHY's link testing process on their Discord first: "All additions have to first go through our testing process on Discord." The Discord opens every Friday, per the guide.
- Before submitting, the guide requires checking the entry is not already listed, using their Single Page or api.fmhy.net search. Checked 2026-11-23: Event Zero does not appear in the Antivirus section of fmhy.net/privacy, nor on fmhy.net/system-tools.
- No pull request template was found in `fmhy/edit` (the `.github` folder carries project assets and the repo README; no PR template text was visible on 2026-11-23). The PR draft below therefore follows the guide's own instructions for the GitHub editor flow: describe the changes in the PR box. The issue route is the primary draft because the guide names it as easier.
- Exclusion check against the guide's "Don't submit" list: Event Zero is free with no paid tier and no trial, English language, not an emulator, browser, leech, distro, coding library, mining or betting site, multiplayer hack, or custom Windows ISO. None of the exclusions apply. Note the guide uses the word mining only for mining and betting sites; Event Zero detects miners, it does not mine.
- House entry format, taken from comparable entries in the Antivirus section of the Privacy page on 2026-11-23: a linked name, then a short description in title case phrases separated by slashes. Examples as rendered: "Detect It Easy - File Identification + Static Inspection Tool"; "Winitor - EXE Malware Assessment"; "Manalyzer - PE File Scanner" (under Online Scanners); "pyWhat - Identify Anything".

## 2. Target section and file

- Site page: Adblocking / Privacy (fmhy.net/privacy), section heading `## Antivirus`.
- Source file in `fmhy/edit`: `docs/privacy.md`, in the Antivirus section.
- Placement: in the main Antivirus list near Detect It Easy and Winitor, the two existing entries for offline file inspection. Event Zero is not an online scanner, so it does not belong under the Online Scanners subsection, and it is not a sandbox, so it does not belong under Sandboxes / VMs.
- Ordering note from the guide: sections are ordered best to worst and placement is the maintainers' call. The draft asks for the Antivirus list and accepts wherever staff place it.

## 3. The exact entry text (FMHY house format)

One line, ready to paste into `docs/privacy.md`:

```markdown
- [Event Zero](https://github.com/Epsilon0xCell/Event_Zero) - Offline Malware Analysis / Proof-Backed YES or NO Verdict on Any Download / Never Executes the File
```

Shorter fallback, if staff prefer a single phrase:

```markdown
- [Event Zero](https://github.com/Epsilon0xCell/Event_Zero) - Offline Malware Analysis with Evidence-Based Reports
```

No star is requested. Per the guide, bold entries on a shared line are the community recommendations (stars); a new entry does not ask for one.

## 4. Primary route: the issue draft (their preferred route)

Open at: github.com/fmhy/edit, Issues, New issue.

Issue title:

```
Add Event Zero (offline malware analysis tool) to Privacy / Antivirus
```

Issue body:

```
Hi, suggesting a free tool for the Antivirus section of the Privacy page (docs/privacy.md).

**Event Zero** - https://github.com/Epsilon0xCell/Event_Zero

What it is: an offline malware analysis tool written in Python (3.10+). You point it at a suspicious file, installer, archive, or a whole release folder, and it reads the file as bytes. It never executes the sample. It produces a plain English report with every claim tied to evidence found in the file, and a feature called The Verdict gives a proof-backed YES or NO on whether a downloaded file is exactly what it claims to be, or carries malware hidden inside it. A NO is issued only when every byte is accounted for as genuine or as an explained difference. Anything it cannot account for blocks the NO and is reported as an open case instead.

Why it may fit the Antivirus section: the section already lists offline inspection tools such as Detect It Easy and Winitor. Event Zero sits next to those, aimed at people checking a download before running it. It is free, the source is public, the core works with no account, no API key, and no network. Optional hash lookups are off by default and hash-first.

Testing it: the repo ships a synthetic sample (fake_malware) and example reports, so the tool can be tried end to end without any real malware:

    git clone https://github.com/Epsilon0xCell/Event_Zero.git
    cd Event_Zero
    pip install -r requirements.txt
    python3 -m event_zero verdict fake_malware

That prints YES: MALWARE FOUND with the proof chains listed. A clean crack example with the opposite verdict is in examples/clean_crack.verdict.txt.

I am the author, declaring that interest here. Happy to go through the Discord link testing process, and happy for the entry to be placed, worded, or declined as staff decide.
```

## 5. Fallback route: the pull request draft

Use only if staff ask for a PR instead of an issue, or after Discord testing clears the tool and a PR is the agreed next step. Fork `fmhy/edit`, edit `docs/privacy.md` in the Antivirus section, add the one line from section 3 above, then open the PR with:

PR title:

```
Add Event Zero to Antivirus (Privacy)
```

PR body:

```
Adds one entry to the Antivirus section of docs/privacy.md:

- [Event Zero](https://github.com/Epsilon0xCell/Event_Zero) - Offline Malware Analysis / Proof-Backed YES or NO Verdict on Any Download / Never Executes the File

Event Zero is a free, offline malware analysis tool (Python 3.10+). It reads files as bytes, never executes them, and produces a plain English report with every claim tied to evidence in the file. Its Verdict feature gives a proof-backed YES or NO on any download: a NO requires every byte accounted for as genuine or explained difference, and anything unaccounted blocks the NO and stays an open case.

I am the author. I checked the Single Page and the Privacy and System Tools pages on 2026-11-23 and the tool is not already listed. I have read the contribution guide and I am submitting this for the Discord link testing process. Placement and wording are at staff discretion.
```

(The date in the last paragraph must be updated to the real submission date when this is used.)

## 6. What FMHY's guidelines require that we do not yet satisfy

1. **Discord link testing has not happened.** The guide states all additions go through their testing process on Discord before they can be added. This cannot be satisfied from our side in advance; it is a step in their process, and the drafts above offer to go through it. Their Discord opens every Friday.
2. **No packaged release or download exists yet.** Installation is clone the repo and `pip install -r requirements.txt`. There is no tagged GitHub Release, no installer, and the Windows and macOS apps in `gui/` ship as source with PyInstaller packaging commands, not as built downloads. The guide does not state a release requirement in so many words, and many listed tools link to a GitHub repo, but a tester who wants a download will not find one. Flagged honestly: this is the weakest point of the submission and a reason staff may defer it.
3. **The licence is CC BY-NC 4.0, not an OSI open source licence.** FMHY lists many public-source tools and the guide does not state a licence requirement, but if staff apply an open source test, the non-commercial clause may fail it. Do not describe Event Zero as "open source" to FMHY without the licence named; the drafts above say "free" and "the source is public", which is exact.
4. **Maturity signals are thin.** The repository is new, the verification corpus is the project's own (37 purpose-built fixtures, scored 37 of 37 by an independent scorer that re-reads the fixture bytes; a 1,000 case pilot scored 1,000 of 1,000 on a corpus drawn from 68 independent clusters, and the pilot report itself labels that a development instrument, not a generalisation measurement). Staff testing will form its own view; the drafts make no adoption or accuracy claims for them to trip over.
5. **Nothing else outstanding.** The tool is free with no paid tier, works offline, is in English, and is not on any of the guide's exclusion lists.
