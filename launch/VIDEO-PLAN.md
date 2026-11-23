# Event Zero v3: Demo Video Plan

Status: plan only, written 2026-11-23. The video is recorded only from real v3 runs, after v3 verification lands. No shot in this plan may be staged with typed output, a mock interface or stock footage. If a shot cannot be produced by a real run at record time, the shot is cut and the script is shortened. See READY.md for the gate this video must pass.

## 1. The idea

One case, opened live. The video is a single terminal examination of real samples, in the brand's case file framing: a suspicious file arrives, one command opens it, and the audience reads what it was, first in words a five year old understands, then in the defences the tool writes from it. The video proves the positioning line from BRANDING.md: malware in, plain English out, evidence attached.

- Length target: 90 to 150 seconds. Hard ceiling 150. If the first assembly runs long, cut shots in the order marked optional below, never speed up terminal output beyond readable pace.
- Audience: two viewers at once. A non specialist must follow the story. A security reader must see real commands, real output and real tool names, with nothing faked.
- Format: one master MP4 (H.264, 1920 by 1080), one subtitles file (SRT, plus WebVTT for the website), one full transcript for the website video section and the README link. Subtitles are part of the deliverable, not an afterthought, and follow the voice rules in BRANDING.md, including zero em dashes.
- Sound: narration recorded over the terminal capture, plus the natural terminal audio track muted. No music library tracks, no stock sound effects. If narration is not ready at assembly time, ship the subtitled silent version rather than synthetic narration passed off as a human voice. Any synthetic voice, if used at all, is labelled as synthetic in the video description.

## 2. Tooling, verified in this environment on 2026-11-23

Checked on the build machine for this plan:

- ffmpeg 8.1.2: installed at /usr/bin/ffmpeg. This is the assembly tool: trimming, concatenation, subtitle burn in for the social copy, soft subtitles for the master, loudness normalisation and poster frame extraction.
- script, from util-linux 2.39.3: installed at /usr/bin/script. Records a real terminal session with timing to a typescript file. This is the guaranteed fallback capture path.
- asciinema: not installed, and a system pip install is blocked on this machine because the Python environment is externally managed. Route: install asciinema inside the project virtual environment used for v3 verification (pip install asciinema in that venv), which also provides the .cast file the website can replay natively. If the venv install fails at record time, fall back to script plus a scripted replay, and record that choice in the build notes.
- agg and terminalizer: not installed. Not required. If a GIF is wanted for the README, generate it from the MP4 with ffmpeg rather than adding a second recording toolchain.

Recording method, in order of preference:

1. Primary: asciinema record inside the v3 environment, one cast per shot, real commands typed by a driver script at human pace or typed live. Cast files are kept as source artefacts next to the video, so any viewer can replay the exact session.
2. Fallback: script with timing, replayed in a clean terminal and screen captured, then assembled with ffmpeg.
3. Assembly in all cases: ffmpeg. Concatenate shot captures, add narration, attach subtitles, extract the poster frame from the ELI5 shot.

Terminal setup for every shot: dark background matching the site ground (#0e1013), light text (#eceff0), amber prompt accent (#e39a1e) if the shell theme allows it without other changes, font size large enough to read at phone width (test by shrinking the assembly to 360 pixels wide and reading the ELI5 lines), window sized 16 by 9, home directory and any personal paths kept out of frame by recording inside a clean demo directory containing only the sample files and the tool. No desktop, no notifications, no other windows.

## 3. Preconditions, all mandatory

- v3 VERIFICATION.md has landed and the full test suite passes in the recording environment. The exact commands in the script are run once off camera first, and their output is compared with the verified example reports. Any difference stops the recording.
- The demo directory contains only: the bundled fake_malware, the verified firmware fixture, the verified evasion fixture, and the tool checkout. Fixture filenames on screen must match the filenames in the example reports and the website case picker.
- Service enrichment in shot 7 runs in whichever mode is true at record time: if keys are configured in the environment, the real consensus output is shown and the narration says keys are optional and hash first. If keys are not configured, the shot shows the not configured state and the hash lookup links, and the narration says exactly that. The shot is never dressed up to look configured when it is not.
- Gemini narration in the reports, if it appears on screen, is labelled on screen by the report itself as AI assisted, as the tool already does. The video does not present AI narration as deterministic output.

## 4. Shot by shot script

Timing is a guide for the assembly, totalling about 130 seconds. Narration lines are drafts that must be rechecked against the actual output on screen at record time; where narration and output disagree, output wins and narration is rewritten.

### Shot 1. Cold open: the case arrives (0 to 10 seconds)

- Screen: clean terminal. A file listing shows one file: fake_malware. A single line of case text is typed as a comment or echoed: Case 001, one suspicious file.
- Command on screen: `ls -l fake_malware` and `file fake_malware` if the file command is present in the environment, otherwise the listing alone.
- Narration draft: This is a suspicious file. We are not going to run it. We are going to read it, and let it explain itself.
- Purpose: safety first, in the first ten seconds. The sample is never executed, and the video says so before any result appears.

### Shot 2. One command (10 to 25 seconds)

- Screen: the single command is typed at human pace: `python3 -m event_zero analyze fake_malware --out report.txt`
- The run scrolls real output. No editing inside the run. If the run is longer than the shot allows, the shot starts at the command and ends on the completed report summary, with the elision shown as a visible cut, never a fake instant finish.
- Narration draft: One command. No key, no network, no Docker. The file is read as bytes, and never executed.

### Shot 3. ELI5 first (25 to 50 seconds)

- Screen: the report opens at the top, in a pager or editor, showing the ELI5 section of the real report for fake_malware. The camera, meaning the scroll, moves slowly through the simple summary lines: what the file pretends to be, what it actually does, in simple words (it phones home to an address inside the file, it writes a script so it can come back, it looks at what else is running, in the report's own verified wording).
- Narration draft: Before any technical detail, the report explains the file like you are five. Simple words. Short sentences. Every hard word translated where it appears. And every one of these lines points back to evidence found in the file.
- Purpose: this is the differentiator shot and the poster frame source. If the video is cut anywhere else for length, this shot stays whole.

### Shot 4. Evidence under the simple words (50 to 65 seconds)

- Screen: scroll continues into the capabilities and decoded strings sections of the same report: the capability lines with their ATT&CK labels and evidence, the persistence script string, the network address, in the report's own formatting.
- Narration draft: Under the simple words is the evidence: what it can do, the exact strings it hid, and where each claim came from. If the tool could not prove something, it prints that under Unknowns instead of guessing.
- Optional if length requires: this shot can shrink to 10 seconds, but the Unknowns line must appear on screen at least once in the video.

### Shot 5. The tool writes the defences (65 to 85 seconds)

- Screen: the YARA rule generated from the same sample is shown, generated by the real v3 command recorded in the verified docs for YARA generation and IOC export. The IOC export is shown as a file listing and the first lines of the CSV or STIX output.
- Narration draft: The same run writes the defences: a YARA rule to catch this file again, and an indicator pack to share. Analysts usually write these by hand.
- Purpose: defence generation is the second differentiator. Show file names and real rule text, not a summary graphic.

### Shot 6. Harder cases: firmware and evasion (85 to 115 seconds)

- Screen: two short runs, same command shape, on the verified firmware fixture and the verified evasion fixture from the v3 fixture set. For the firmware case, the report section showing the carved embedded driver or filesystem inventory is shown. For the evasion case, the findings for the injection chain, the hashed API pattern or the direct syscall evidence are shown, using only findings the verified reports actually contain for those fixtures.
- Narration draft: The same command opens a firmware image, and pulls out what is hidden inside it. And it reads the tricks malware uses to hide from antivirus, and names them in plain words.
- Purpose: breadth proof, one command across classes. Each run gets one finding on screen, not a tour.

### Shot 7. The ecosystem and the outside view (115 to 135 seconds)

- Screen: `python3 -m event_zero tools` output, scrolled slowly: the registry list with installed and missing states exactly as the environment reports them. Then the enrichment section of a report, or the enrich command, showing the per service state (found, not found, not configured) and the consensus line, in whichever true state section 3 requires.
- Narration draft: Event Zero also drives the free tools already on a machine, and asks the free services what they have seen, by hash first. Nothing is uploaded by default. What is missing is printed as missing.
- Purpose: fusion proof, with the honest states visible. A missing tool on screen is a feature of this shot, not a flaw to hide.

### Shot 8. Close: the case file (135 to 150 seconds, optional)

- Screen: the report file, the YARA file and the IOC file listed together in the demo directory. Final frame is a still: the positioning line as on screen text over the terminal, with the repository address.
- Narration draft: Malware in. Plain English out. Evidence attached. That is Event Zero.
- Purpose: the short form positioning line as the last thing heard, over proof files, not over a logo animation.

## 5. Subtitles and transcript

- Subtitles are written from the final narration, sentence by sentence, timed in the assembly, and checked for the voice rules: zero em dashes, jargon translated, no claim that is not on screen.
- Reading pace: no subtitle block longer than two lines, no block under one second. The ELI5 shot subtitles reproduce the report's simple language rather than paraphrasing it into harder words.
- The transcript is the narration plus a plain description of what each shot shows, so a reader without video gets the same claims, and the same limits, as a viewer.

## 6. What must wait for v3 verification

- The exact wording of every report excerpt, capability name, fixture name and finding in shots 3 to 7. All of it is copied from verified example reports at record time, never from this plan.
- The YARA and IOC generation commands in shot 5, copied from the verified v3 CLI, including flag names.
- The tools registry output in shot 7, which depends on what is installed in the recording environment.
- The enrichment states in shot 7, which depend on key configuration at record time.
- The benchmark and capability claims: the video contains none. If a closing slide ever adds numbers, they come from the verified benchmark table only, added as a separate later edit, not in the first cut.

## 7. Prohibitions

- No fake UI, no mock reports, no retyped output presented as a run, no stock footage, no footage of other tools' interfaces presented as Event Zero, no live malware, no real victim data, no keys or personal paths on screen, no em dashes in any on screen text, subtitle or description.
