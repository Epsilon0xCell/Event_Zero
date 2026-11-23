# Event Zero Demo: Reproduction Script

Every frame of `event-zero-demo.mp4` is a real terminal session. The commands below are the exact commands run on camera, in order, in a clean demo directory. Nothing was staged, retyped as output, or edited inside a run. If you run the same commands in the same order, you get the same reports and the same verdicts.

## Setup (done once, off camera)

```sh
python3 -m venv /tmp/ezdemo
/tmp/ezdemo/bin/pip install -e . unicorn capstone lief cryptography pytest
```

The demo directory (`demo/work/`) contains only:

- `fake_malware`: the bundled sample from the repository root, copied unchanged (SHA-256 `c9ab06a4fd594a82eb36d1aeb72e83e99df77a2ccd6a8ebd0ad078dd6b707802`).
- `genuine/game.py`: a small program with a license check (the genuine reference).
- `release/game.py`: the same program with the license check patched out (the clean crack).
- `open_case/notes.txt` and `open_case/game.exe`: a release whose executable is wrapped in a virtualizing protector (VMProtect section), so part of it cannot be accounted for.

Signing is on for the session: an Ed25519 key is generated locally and passed to the shell through the `EZ_SIGNING_KEY` environment variable. The key itself never appears on screen. With no key set, the same runs work and every report and receipt is marked UNSIGNED instead of signed.

The terminal prompt is `ez-demo $ `. The sample is never executed at any point: every command below reads files as bytes.

## Shot 1. Help

```sh
python3 -m event_zero --help
```

## Shot 2. Analyze the bundled sample

```sh
ls -l fake_malware
python3 -m event_zero analyze fake_malware --out fake.report.txt
head -22 fake.report.txt
```

The report opens with the ELI5 section (section 0), then the evidence. The run also writes a signed run receipt at `fake.report.txt.receipt.json`.

## Shot 3. The Verdict on the clean crack (NO)

```sh
python3 -m event_zero verdict release --reference genuine --out clean.verdict.txt
head -6 clean.verdict.txt
awk '/DIFF LEDGER/,/PROOF AND ACCOUNTING/' clean.verdict.txt | head -12
```

Headline: `NO: NO MALWARE`, reason class `ACCOUNTED`. The diff ledger shows each changed region classified `expected-crack`, machine-verified against the named crack pattern with a capability check.

## Shot 4. The Verdict on fake_malware (YES, PROVEN)

```sh
python3 -m event_zero verdict fake_malware --out fake.verdict.txt
head -6 fake.verdict.txt
awk '/Malware proof, PROVEN/,/6. CONNECTION/' fake.verdict.txt | head -11
```

Headline: `YES: MALWARE FOUND`, reason class `PROVEN`, with the stealer and persistence-plus-C2 proof chains and their evidence.

## Shot 5. The OPEN case (unaccounted)

```sh
ls open_case
python3 -m event_zero verdict open_case --out open.verdict.txt
head -6 open.verdict.txt
awk '/2. PER-FILE/,/notes.txt/' open.verdict.txt | head -9
```

Headline stays fail-closed `YES: MALWARE FOUND` with reason class `UNACCOUNTED`, and the case state is `OPEN`: the virtualized functions are named as unaccounted units, with the next step that would account for them. Event Zero does not guess and does not say NO.

## Shot 6. Verify a signed report, then tamper with it

```sh
python3 -m event_zero verdict release --reference genuine --out clean.verdict.json
python3 -m event_zero verify-report clean.verdict.json
cp clean.verdict.json tampered.json
sed -i 's/"verdict": "NO"/"verdict": "YES"/' tampered.json
python3 -m event_zero verify-report tampered.json
```

The signed original verifies: `Verification: VERIFIED` and `PASS`. The tampered copy, with only the verdict token flipped, fails: `Verification: FAILED` and `FAIL: this file does not verify. Do not trust its verdict.` (exit code 1).

## Shot 7. The verification corpus

```sh
grep -c '| PASS |' ../../fixtures/verification/results_table.md
grep -c 'FAIL' ../../fixtures/verification/results_table.md
head -8 ../../fixtures/verification/results_table.md
```

Recorded result at record time: 37 PASS, 0 FAIL. The full corpus lives in `fixtures/verification/` and reruns with `fixtures/verification/run_verification.py`.

## Shot 8. Close

```sh
ls -l
echo "Event Zero: The Verdict"
echo "Malware in. Plain English out. Evidence attached."
```

## How the video was made

A driver script typed the commands above into a real shell at human pace and captured the terminal byte stream with timestamps. The frames were rendered from that captured stream with a dark theme matching the brand (ground `#0e1013`, paper `#eceff0`, evidence amber `#e39a1e` for the prompt, red and green for the YES and NO headlines). The text on screen is the commands' own output; only colours were themed. The capture is kept next to the video as `event-zero-demo.events.json`, so the session can be replayed and checked. The GIF was generated from the MP4 with ffmpeg.

Total running time: about 111 seconds.

One production note, stated plainly: at record time the build machine's home disk was over quota, which corrupted an earlier take when report files could not be written. The final take was therefore recorded in a scratch mirror with the identical relative layout (`demo/work/` beside `fixtures/verification/`), so every command and path on screen is exactly as written above. The session's generated reports from the recorded take are preserved with the capture.
