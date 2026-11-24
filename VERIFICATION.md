# Verification (actual outputs, 2026-11-23)

## Test suite
Clean venv (/tmp/ez3-venv, lief, capstone, pefile, pyelftools, pytest, unicorn, cryptography):
`64 passed in 16.81s` at the v3 gate (earlier gates: v2 suite alone 14 passed, v2+v3 53 passed, plus final sweep 57 passed). After the verdict build, the family expansion, signing, revocation, and diff-verification work: **141 passed** (final full run, see the last section of this file).

## Validator on gold reports
```
$ event_zero validate examples/gold/fake_malware.report.json
VALID: every claim carries evidence and all required sections are present.
$ event_zero validate examples/gold/eicar.report.json
VALID
$ event_zero validate examples/gold/dotnet_evasion.report.json
VALID
```

## Adversarial self-test: 5 surprise fixtures, run cold
Fixtures were built after the modules, with mixed tricks the modules were not designed around:
| Fixture | Tricks | Cold result | Fix or honest label |
|---|---|---|---|
| S1 APK | device-admin and location permissions, XOR string in DEX, drop URL in assets | Permissions and asset URL found. DEX XOR string MISSED (whole-file XOR scan was masked by a plain http string elsewhere) | FIXED: per-entry DEX XOR scan in formats_extra.py. Regression: tests/test_top.py::test_regression_apk_dex_xor. Decodes http://hidden-dex.example/x with key 0x24 |
| S2 DOCM | macro with AutoOpen, DDEAUTO in document.xml, template injection URL | All found cold: macros, trigger, DDE, template URL | No fix needed |
| S3 blob | base64(base64(XOR(shellcode text))) inside a sentence | First layer decoded, full chain MISSED (decoder treated the whole sentence as one token) | FIXED: token splitting in unpack.multilayer_decode. Regression test added. Full chain now decodes to "EGGHUNT http://layer.example/shellcode VirtualAlloc", and decoded layers are re-scored for capabilities |
| S4 EXE | .NET with ConfuserEx plus ROR13 and injection chain | All found cold: .NET, obfuscator, API hashing, injection chain | No fix needed |
| S5 firmware | UEFI FV plus SquashFS plus gzip plus nested PE DXE with SMM and network strings | Firmware, DXE carving and secure-boot flag found. SMM-plus-network combined flag did NOT fire because the context strings are gathered repo-wide, not per driver | Labelled honestly: per-driver verdicts are the documented next step (research-v3.md firmware rule); the SMM and network evidence is present in the report sections |

## Benchmark: rules alone vs full v3 pipeline
Findings counted as capability rules alone, versus rules plus evasion, rootkit, firmware, exploit, .NET, APK, Office and PDF findings:
| Fixture | Rules only | Full v3 | Delta |
|---|---|---|---|
| fake_malware | 12 | 12 | +0 |
| EICAR | 0 | 0 | +0 |
| evil.py | 5 | 5 | +0 |
| adversarial S1 APK | 1 | 2 | +1 |
| adversarial S2 DOCM | 3 | 4 | +1 |
| adversarial S3 blob | 0 cold, 1 after fix | 1 | +1 after the adversarial fix |
| adversarial S4 .NET evasion | 1 | 4 | +3 |
| adversarial S5 firmware | 0 | 1 | +1 |

Public reference set (methodology: expected IDs are the documented fixture behaviours in tests/):
| Reference | Expected | Rules only hit | Full v3 hit | Verdict |
|---|---|---|---|---|
| fake_malware (public repo sample) | 6 | 6 | 6 | HIGH RISK 100/100 |
| EICAR (public AV test file) | 0 | 0 | 0 | TEST FILE 0/100 |
| evil.py (synthetic, documented) | 3 | 3 | 3 | HIGH RISK 70/100 |

## ELI5 scores (design target: FRE at least 80, FK at most 6, labelled as a design target)
| Report | Sentences | Avg words per sentence | Avg word length | Untranslated banned jargon |
|---|---|---|---|---|
| fake_malware | 29 | 10.7 | 3.83 | 0 |
| S1 APK | 7 | 10.9 | 3.80 | 0 |
| S2 DOCM | 11 | 11.1 | 3.84 | 0 |
| S3 blob | 5 | 11.8 | 3.66 | 0 |
| S4 .NET | 11 | 10.2 | 3.85 | 0 |
| S5 firmware | 7 | 11.7 | 3.56 | 0 |
FRE and FK are computed per report in the eli5_metrics field by readability.py and asserted in tests/test_research.py::test_readability_scores.

## Gemini gate proof
tests/test_v3.py::test_gemini_gate_strips_invented_ioc: a mock Gemini response mentioning the real 10.0.0.5 and an invented 203.0.113.99 returns a narrative with 10.0.0.5 kept, 203.0.113.99 dropped, and the dropped sentence listed in the status. test_gemini_key_never_in_report proves the env key value never appears in a report.

## Flagship verdict verification (2026-11-23)
Full suite after the verdict build: `91 passed in 60.74s` (the original 64 plus 19 verdict tests, 5 folder and link tests, 3 devirtualization tests).

Actual verdict outputs:
```
$ event_zero verdict fake_malware
YES: MALWARE FOUND   (reason class: PROVEN, 1.114 seconds)
  chains: stealer, persistence-plus-c2, miner
  per-file verdict: YES: MALWARE (PROVEN)
$ event_zero verdict /tmp/ezex/release --reference /tmp/ezex/genuine
NO: NO MALWARE   (reason class: ACCOUNTED)
  diff ledger: 3 regions, all classified expected-crack
$ event_zero validate examples/fake_malware.verdict.json
VALID
$ event_zero validate examples/clean_crack.verdict.json
VALID
```
Fixture coverage, all synthetic: benign program plus license patch with reference (NO, ledger explained); the same release plus a hidden stealer DLL inside a zip (YES PROVEN, DLL named); keygen that only generates keys (NO); keygen with socket exfiltration (YES PROVEN by the scope test); installer zip with a dropper script (YES PROVEN); clean release with one virtualized file (YES UNACCOUNTED); tampered diff with an unexplained code addition and no malicious capabilities (YES UNACCOUNTED); single cracked binary alone (NO, patch identified from the file itself); single binary with an embedded hidden payload (YES PROVEN); single virtualized binary (YES UNACCOUNTED); AV tampering script (YES PROVEN); reboot-gating plus Safe Mode script (YES PROVEN); reference manifest hash equality and mismatch; scene-group site provenance claim (YES UNACCOUNTED); KMS baseline activator (NO); archive inside archive with the payload at the bottom (YES PROVEN, manifest parent chain present); .url shortener and .lnk LOLBin download cradle (ledger entries present, .lnk is YES PROVEN); .torrent parsed locally into the ledger.

Devirtualization: the synthetic VM fixture (dispatcher loop bytes, entry stub, encrypted region) produces a VMProtect census (indirect jump sites, entry stubs, encrypted regions mapped) and a YES UNACCOUNTED verdict; the Unicorn trace harness logs the API crossing when traced code jumps out of the mapped image.

## The Verdict: family expansion, signing, and every-family verification (2026-11-23)

Per-family proof rules for The Verdict (stealer, RAT, ransomware, miner, loader, server-keyed, botnet, bootkit, keylogger, banking, proxy, PPI, adware grey zone, beacon config parsing, wiper, logic bomb, fileless, malicious scripts, sideload triad), each gated by its FP-twin discriminator: `tests/test_families.py`, 34 tests, PROVEN and FP-twin pairs for the highest-risk families.

Signed reports and run receipts: `tests/test_signing.py` covers the sign and verify round trip, a tampered verdict failing verification, unsigned-with-note degradation, a deterministic ledger root (same input twice, same root), a receipt with a swapped sample hash failing, the CLI verify path, and the Verdict Revocation List (a listed report verifies as REVOKED, an unlisted one still passes).

Machine-verified expected-crack: `tests/test_diff_verification.py` proves a payload planted inside a license-shaped region (same-length URL swap in an already network-capable file) comes back YES-UNACCOUNTED with the region capability check recorded as failed, never NO, and that a genuine conditional-branch patch still classifies expected-crack with its pattern named. OPEN cases carry the residual pack; reports state environment coverage as a number.

Every-family verification corpus: `fixtures/verification/`, 37 entries (20 family PROVEN fixtures, 9 benign FP-twin controls, 4 designed-OPEN Tier-2 cases, 4 surprise fixtures). Final batch: **PASS, 37 of 37, 0 mismatches, 0 unexpected Tier-1 unaccounted, 0 false NO, 0 determinism failures**, corpus ledger root b5e851ff1ba166a2083e15681256ec06a5af9603aba364b7b9f6fd1348cc1f4b. The path to PASS found 4 false NOs and 3 false positives in the first run; every miss, its cause, and its fix is logged in VERIFICATION-VERDICT.md, which also records the cloud verification design (`.github/workflows/verify.yml`: three-OS test suite; corpus in a network-disabled container with an egress canary and a determinism gate; run proof in the job summary) and the local no-egress proof run (egress canary PASS under a network namespace; corpus PASS twice with identical roots). GitHub Actions itself runs only after a push.

## CI-discovered platform defects: verify run #1 (2026-11-23)

The first cloud run of `.github/workflows/verify.yml` (commit 6783d04) passed on Ubuntu (166 tests) and in the verify-corpus job, and exposed five failures on Windows (4) and macOS (1). All five were test-harness or platform defects, not engine defects; no verdict behaviour changed, so no miss-ledger entry applies. Fixes are in the working tree and land in the next commit.

1. Windows, `test_verdict.py::test_yes_known_bad_hash` (returned NO, expected YES PROVEN) and `test_verdict.py::test_reference_manifest_equality` (game.py "hash does not equal the reference manifest entry", verdict YES instead of NO). Proven cause, one mechanism for both: the tests' `write()` helpers opened text files with `open(p, "w")`, and CPython text mode translates "\n" to os.linesep on write, which is CRLF on Windows. The engine hashes the bytes actually on disk (verdict.py known-bad lookup and the manifest comparison at verdict.py:1110), so the on-disk CRLF hash matched neither the known-bad key nor the manifest entry, both computed from the in-memory LF string. Proof: SHA-256 of the LF and CRLF forms of both fixture strings differ, and an end-to-end run writing the fixture with CRLF endings reproduces the exact Windows result (NO, ACCOUNTED) while the LF form returns YES PROVEN. The fault is in the tests, not the engine: a verdict tool must hash the bytes present, never a normalised form. Fix: every `write()` helper in tests/ now writes text with `newline=""` (byte-exact on all platforms), plus a regression test `test_verdict.py::test_write_helper_is_byte_exact` that pins the on-disk bytes to the in-memory string. Defence in depth for checked-in byte-sensitive material (verification corpus, example manifests): a new `.gitattributes` pins `* text=auto eol=lf` and marks the binary artefacts `binary`, so a Windows checkout cannot rewrite fixture bytes either.
2. Windows, `tests/test_event_zero.py::test_compiled_elf`: gcc failed on `#include <sys/socket.h>`, a POSIX header absent from Windows toolchains. Fix: the test now skips on non-Linux platforms with that reason stated; it still runs in full on Linux.
3. macOS, same test: clang/gcc compiles the source but emits a Mach-O binary while the test asserts ELF. Same fix: the test is a Linux ELF test and says so in its skip reason.
4. Windows, `tests/test_v3.py::test_rop_on_compiled_elf`: FileNotFoundError for the compiled "ropelf" binary. Cause: Windows gcc appends ".exe" to the output name, so the binary existed as ropelf.exe while the test looked for ropelf (a cascade of the Windows toolchain, not of the POSIX failure; the ROP source is portable C). Fix: the test now uses the platform-correct output name; the ROP gadget scan runs on raw code bytes and is format-agnostic.

Local re-verification after the fixes (Linux, fresh venv matching the CI workflow: requirements.txt plus pytest, unicorn, cryptography): `tests/` **167 passed** (166 baseline plus the new byte-exactness regression test; zero skips, so the platform gates are inactive on Linux and both compile tests run in full), `gui/tests/` **18 passed**. The Windows and macOS legs can only be re-proven by the next cloud run after the fixes are pushed.

## One-command check
`python -m event_zero analyze fake_malware` produces a report whose section 0 is the ELI5 layer (29 short sentences, metrics above), followed by plain English, then evidence sections 1 to 22, generated YARA, and hash-only browser links.
