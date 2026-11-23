# Event Zero v3 Launch Claims Ledger

Built 2026-11-23, step 1 of the READY.md build order. Every factual claim on the README and the website traces to a row here. A claim with no source was deleted, not softened. Sources: VERIFICATION.md (V), CAPABILITY-MATRIX.md (M), saved example reports in examples/ (E).

## Verdict claims

| Claim | Source |
|---|---|
| One command, `event_zero verdict <path>`, returns a YES or NO headline on a file, installer, archive, or release folder | M: The Verdict row, BUILT, tests/test_verdict.py 19 tests |
| fake_malware verdict headline is "YES: MALWARE FOUND", reason class PROVEN, chains stealer, persistence-plus-c2, miner | E: examples/fake_malware.verdict.txt; V verdict section |
| Clean patched crack verdict headline is "NO: NO MALWARE", reason class ACCOUNTED, diff ledger 3 regions all expected-crack | E: examples/clean_crack.verdict.txt; V verdict section |
| Verdict on the bundled sample took about a second (1.114 s in the recorded run) | V verdict section |
| Reason classes are PROVEN and UNACCOUNTED, and the accounting fails closed: unaccounted bytes block a NO | M: verdict reason classes row, BUILT |
| The crack itself is not counted as malware: patched checks, keygen algorithms, and KMS emulation sit in the accounting, not the proof | E: fake_malware.verdict.txt section 1; M: scope test row |
| A virtualized file that cannot be accounted returns YES UNACCOUNTED, never a guessed clean | V verdict section; M: devirtualization rows |

## Analyzer claims

| Claim | Source |
|---|---|
| The sample is read as bytes and never executed on the host | E: fake_malware.report.txt closing line; M: sandbox row (detonation is the user's self-hosted CAPE, HANDOFF) |
| Reports open with an ELI5 layer, then plain English, then evidence sections 1 to 22 | V: one-command check |
| fake_malware scores HIGH RISK 100/100 with 12 capabilities in the reference set | V: benchmark, public reference set |
| EICAR scores TEST FILE 0/100 with 0 capabilities | V: benchmark |
| Benchmark deltas: S4 .NET evasion rules-only 1 finding, full pipeline 4; S5 firmware 0 to 1; S1 APK 1 to 2; S2 DOCM 3 to 4 | V: benchmark table |
| ELI5 sections measured 10.2 to 11.8 average words per sentence across six reports, 0 untranslated banned jargon | V: ELI5 scores table |
| Test suite: 91 tests passing (64 core plus 19 verdict, 5 folder and link, 3 devirtualization) | V: flagship verification section, "91 passed in 60.74s" |
| Gold reports pass the format validator | V: validator outputs, examples/gold |
| Hash lookup links carry only the hash; nothing is uploaded | E: fake_malware.report.txt browser lookup section; M: HANDOFF row |

## Status words used on surfaces

Copied from CAPABILITY-MATRIX.md status column only: BUILT, ADAPTER, SERVICE, HANDOFF. The handler semantics devirtualization pass is ADAPTER / HANDOFF and is never described as built in. Live Gemini narration is a SERVICE needing the user's own key in the environment; the gate and the no-key behaviour are BUILT.

## Deleted at this step (no source, or banned)

- Any "detects all malware" or accuracy percentage claim: no source, banned by READY.md 3.1.
- Any claim that Event Zero replaces Ghidra, capa, VirusTotal, or an analyst: contradicts BRANDING.md 1.4.
- Social proof badges (stars, forks, downloads): not in the BRANDING.md badge list.
- A demo video claim: the video is a separate later task and does not exist yet, so no surface links or promises it.
