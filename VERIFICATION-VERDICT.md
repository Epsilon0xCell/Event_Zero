# Verification: The Verdict against every malware family (2026-11-23)

This report is the record of running **The Verdict** (the flagship verdict feature, CLI `event_zero verdict`) over a purpose-built verification corpus covering every malware family in the project's per-family research table, plus false-positive twin controls, designed-OPEN cases, and surprise fixtures designed cold after the rules were written. It names every miss found on the way, plainly, with its cause and its fix. Expectations were never edited to match output: where a fixture's construction was wrong, that is recorded as a fixture correction, separately from rule defects, and the expected verdict stayed what the research table says it must be.

## The corpus

`fixtures/verification/` holds the corpus. `build_corpus.py` generates it deterministically; `manifest.json` records, per entry, the expected verdict, reason class or case state, family, tier, and the proof atoms the independent scorer must find in the fixture bytes. `run_verification.py` runs The Verdict over the whole corpus in one batch, twice, and scores it.

Every fixture is synthetic and disarmed by construction: proof atoms carried as data for a static analyser, network atoms restricted to `.invalid` names and TEST-NET addresses (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24), miner pools at lab addresses, crypto atoms acting only on sacrificial lab text, headers neutralised where applicable. Fixtures are never executed, and the batch makes no network use (proven by the egress canary run, below).

Scoring discipline, from the verification research protocol:

- The denominator is every manifest entry (37). Each must end YES with exhibited proof, NO, or OPEN/UNACCOUNTED.
- PASS requires zero mismatches overall, zero unexpected UNACCOUNTED on Tier-1 fixtures, and zero false NO.
- Tier-2 entries are designed-OPEN cases, disclosed in the manifest in advance: an unexplained kernel driver, an opaque logic-bomb arm, an undecodable fileless blob, and a password-protected archive member. For these, the fail-closed headline with an open ledger is the correct outcome, not a miss.
- The independent scorer does not trust the analyser's own summary. For every PROVEN-expected fixture it re-reads the fixture bytes and confirms each expected proof atom is literally present, and it confirms the issued report exhibits a proof chain for the family. For the beacon fixture, whose config is XOR-encoded by construction, it confirms the parsed configuration (with C2 host) in the report instead.
- Determinism gate: every fixture is run twice per batch and the two ledger root hashes must be identical.

## Final result: PASS

| Measure | Count |
|---|---|
| Corpus entries | 37 |
| Mismatches | 0 |
| Unexpected UNACCOUNTED on Tier-1 | 0 |
| False NO (release-blocking) | 0 |
| False positives on benign controls | 0 |
| Determinism failures | 0 |
| Corpus ledger root | b5e851ff1ba166a2083e15681256ec06a5af9603aba364b7b9f6fd1348cc1f4b |
| Corpus manifest SHA-256 | 671aca26e7890afb3d8a59ff47e5e5390a3b1820c363b53f8ded9592e445aef3 |

## Full results table (final batch)

| Fixture | Family | Tier | Expected | Issued | Case | Proof exhibited | Result |
|---|---|---|---|---|---|---|---|
| stealer_config.py | stealer | 1 | YES/PROVEN | YES/PROVEN | YES | family-stealer-config | PASS |
| stealer_chain.py | stealer | 1 | YES/PROVEN | YES/PROVEN | YES | stealer | PASS |
| rat_dispatcher.py | rat | 1 | YES/PROVEN | YES/PROVEN | YES | family-rat-dispatcher | PASS |
| ransomware.py | ransomware | 1 | YES/PROVEN | YES/PROVEN | YES | ransomware | PASS |
| miner_hidden.py | miner | 1 | YES/PROVEN | YES/PROVEN | YES | miner | PASS |
| loader_inject.py | loader | 1 | YES/PROVEN | YES/PROVEN | YES | download-and-execute | PASS |
| loader_dead_drop.py | loader | 1 | YES/PROVEN | YES/PROVEN | YES | download-and-execute (family-loader-dead-drop also exhibited) | PASS |
| server_keyed.py | server-keyed | 1 | YES/PROVEN | YES/PROVEN | YES | download-and-execute (family-loader-server-keyed also exhibited) | PASS |
| botnet_flood.py | botnet | 1 | YES/PROVEN | YES/PROVEN | YES | family-botnet-ddos | PASS |
| bootkit.py | bootkit | 1 | YES/PROVEN | YES/PROVEN | YES | family-bootkit-staging | PASS |
| keylogger_stash.py | keylogger | 1 | YES/PROVEN | YES/PROVEN | YES | family-keylogger-stash | PASS |
| banking_targets.py | banking | 1 | YES/PROVEN | YES/PROVEN | YES | family-banking-targets | PASS |
| proxy_operator.py | proxy | 1 | YES/PROVEN | YES/PROVEN | YES | persistence-plus-c2 (family-proxy also exhibited) | PASS |
| ppi_callback.py | ppi | 1 | YES/PROVEN | YES/PROVEN | YES | family-ppi-callback | PASS |
| hijacker.py | adware-hijacker | 1 | YES/PROVEN | YES/PROVEN | YES | persistence-plus-c2 (family-browser-hijacker also exhibited) | PASS |
| beacon_config.bin | beacon | 1 | YES/PROVEN | YES/PROVEN | YES | family-beacon-config | PASS |
| wiper.py | wiper | 1 | YES/PROVEN | YES/PROVEN | YES | family-wiper | PASS |
| fileless_decodable.py | fileless | 1 | YES/PROVEN | YES/PROVEN | YES | family-fileless-registry-blob | PASS |
| script_bad.bat | malicious-script | 1 | YES/PROVEN | YES/PROVEN | YES | download-and-execute (family-malicious-script also exhibited) | PASS |
| sideload_folder | sideload | 1 | YES/PROVEN | YES/PROVEN | YES | dll-sideload-triad | PASS |
| twin_password_manager.py | stealer-fp-twin | 1 | NO/ACCOUNTED | NO/ACCOUNTED | NO | none | PASS |
| twin_miner_disclosed.py | miner-fp-twin | 1 | NO/ACCOUNTED | NO/ACCOUNTED | NO | none | PASS |
| twin_backup_encryptor.py | ransomware-fp-twin | 1 | NO/ACCOUNTED | NO/ACCOUNTED | NO | none | PASS |
| twin_kms_clean.bat | script-fp-twin | 1 | NO/ACCOUNTED | NO/ACCOUNTED | NO | none | PASS |
| twin_proxy_disclosed.py | proxy-fp-twin | 1 | NO/ACCOUNTED | NO/ACCOUNTED | NO | none | PASS |
| twin_keygen.py | keygen-control | 1 | NO/ACCOUNTED | NO/ACCOUNTED | NO | none | PASS |
| twin_capture_tool.py | keylogger-fp-twin | 1 | NO/ACCOUNTED | NO/ACCOUNTED | NO | none | PASS |
| twin_xmrig_alone.py | miner-presence-control | 1 | NO/ACCOUNTED | NO/ACCOUNTED | NO | none | PASS |
| sideload_genuine | sideload-fp-twin | 1 | NO/ACCOUNTED | NO/ACCOUNTED | NO | none | PASS |
| open_rootkit.sys | rootkit | 2 | YES/UNACCOUNTED | YES/UNACCOUNTED | OPEN | none | PASS |
| open_logic_bomb.py | logic-bomb | 2 | YES/UNACCOUNTED | YES/UNACCOUNTED | OPEN | none | PASS |
| open_fileless_blob.py | fileless | 2 | YES/UNACCOUNTED | YES/UNACCOUNTED | OPEN | none | PASS |
| open_password_archive.zip | archive | 2 | YES/UNACCOUNTED | YES/UNACCOUNTED | OPEN | none | PASS |
| surprise_updater.bat | surprise-loader-script | 1 | YES/PROVEN | YES/PROVEN | YES | download-and-execute | PASS |
| surprise_shadow.bat | surprise-anti-recovery-script | 1 | YES/PROVEN | YES/PROVEN | YES | download-and-execute | PASS |
| surprise_dll_stealer | surprise-stealer-in-dll | 1 | YES/PROVEN | YES/PROVEN | YES | family-stealer-config | PASS |
| surprise_banking_article.txt | surprise-banking-fp | 1 | NO/ACCOUNTED | NO/ACCOUNTED | NO | none | PASS |

Raw batch output: `fixtures/verification/results.json` (full per-fixture records), `fixtures/verification/results_table.md` (the generated table), `fixtures/verification/results.csv` and `fixtures/verification/results_hashes.jsonl` (mirror formats), `fixtures/verification/roots.json` (per-fixture ledger roots).

## The misses found on the way, and their fixes

The first batch run failed 16 of 37 entries, including four false NOs. That is what the corpus is for. Each miss is logged below; the expectation was never changed to fit the output. Fix numbers are referenced from the code comments where a fix was non-obvious.

### Run 1: 16 mismatches, 4 false NO, 3 false positives

**False NO (release-blocking class), all fixed:**

1. **bootkit.py issued NO.** Cause: the bootkit rule's integrity-tamper atom list held only bcdedit-style spellings (`nointegritychecks`, `testsigning`), while the fixture, like real staging text, says "disable SecureBoot verification" and "integrity checks". Fix F1: widened `BOOT_TAMPER_ATOMS` with the natural phrasings (disable secureboot, secureboot disabled, integrity checks, unsigned driver). The ESP-write requirement still gates the chain, so the dual-boot FP twin still cannot fire it.
2. **keylogger_stash.py issued NO.** Two causes. (a) The `keylog` capability's API atoms sit in the rule's import column, and script text was never checked against import atoms, so `GetAsyncKeyState` in source code was invisible. Fix F2: capability matching now also checks import atoms against script text, as token-boundary matches (see fix F9 for why the boundary matters). (b) The hidden-stash atom list had no `.hidden` path form. Fix F3: added `\.hidden`, `/.hidden`, `.hidden\` to `HIDDEN_STASH_ATOMS`.
3. **fileless_decodable.py issued NO.** Fixture construction error, recorded as such: the generated fixture lacked the registry-persistence atoms and its base64 blob was below the parser's 200-character token floor and decoded to text with no code markers. The fixture was rebuilt in the family's natural form (WMI consumer strings, an EncodedCommand blob of realistic length decoding to a download cradle). Expectation unchanged.
4. **open_logic_bomb.py issued NO (expected OPEN).** Causes: the trigger vocabulary required ISO dates or specific phrases, missing the `datetime.date.today()` plus `date(2030, 1, 1)` constructor form; and "opaque arm" was recognised only as high entropy or the words "encrypted payload". Fix F4: trigger atoms added (`datetime.date.today`, `date.today()`), the date regex accepts the `date(YYYY, M, D)` constructor, and an arm is opaque when the gated action executes an external payload file (.bin, .dat, .enc) or is described as opaque.

**False positives, all fixed:**

5. **twin_miner_disclosed.py and twin_xmrig_alone.py issued YES-PROVEN.** Cause: the verdict's generic miner chain fired on mining capability plus a pool string alone, below the family's own proof standard (pool plus wallet plus concealment or persistence), and the disclosed-miner suppression could not see comment text. Fix F5: the generic chain now requires concealment or persistence evidence AND a wallet indicator, aligned with `families._miner`, and still yields to the disclosed-miner test. XMRig presence alone is not proof, and now the generic layer agrees with the family layer.
6. **sideload_genuine issued YES-UNACCOUNTED.** Scenario correction, recorded as such: the corpus first built the genuine case as a standalone folder, but under the accounting law an unverifiable compiled binary with no reference is unaccounted by design, so that scenario could never earn NO. The family's documented FP twin is the hash-matched emulator DLL judged against a genuine reference (the form the unit test uses). The corpus now builds exactly that scenario (release folder plus genuine reference folder, runner passes `--reference`). Expectation unchanged: NO.

**Proof exhibited under a different chain than the family rule (verdict correct, family rule not exercised), all fixed:**

7. **rat_dispatcher.py**: the RAT config test required config-shaped identifiers; a decoded operator config in source form (IP literal plus port assignment) was not recognised, and the dispatcher command list held only protocol-style names. Fix F6: config detection accepts an IPv4 literal with a nearby port assignment; `RAT_COMMANDS` accepts quoted dispatch-table entries ("shell", "download", "upload", "screenshot", "keylog", "persist").
8. **loader_inject.py, server_keyed.py**: the loader chain needs the `exec-download-run` capability, whose atoms lacked the standard-library download forms. Fix F7: atoms added (urlopen, urllib.request, invoke-webrequest, start-bitstransfer).
9. **loader_dead_drop.py**: the dead-drop capability's atom list omitted pastebin, the canonical dead drop its own chain text names. Fix F8: atoms added (pastebin.com/raw, pastebin.com/api, hastebin, ghostbin, dpaste). The loader rule also now checks the dead-drop branch before the injection branch, because the dead-drop property is the more specific family trait.
10. **botnet_flood.py**: flood atoms used spaced spellings only ("udp flood"), missing function-name forms; the dispatch leg did not accept a plain socket. Fix F9a: underscore forms added (udp_flood, syn_flood, http_flood); the C2 leg accepts net-socket and quoted "flood" command grammar.
11. **hijacker.py**: hijack atoms were config-key spellings only. Fix F10: natural forms added (set homepage, homepage =, default search provider, search provider =, new tab page). The watchdog or persistence requirement still gates the chain.
12. **beacon_config.bin issued UNACCOUNTED.** Two parser defects in the beacon TLV walker: it could not resync over inter-record zero padding (and a naive zero-skip eats the next header's high byte, which is itself zero), and it rejected the format's NUL-terminated strings. Fix F11: the walker probes each offset up to 8 bytes ahead for the next valid header, and string values are validated after stripping one trailing NUL. A fixture construction error compounded this (integer fields written at wrong lengths); the builder now writes the real field widths.
13. **sideload_folder issued UNACCOUNTED.** Fixture construction error: the corpus builder's home-grown PE construction produced a certificate the parser does not accept. The builder now uses the same PE construction as the test suite (`pe_with_body`, `pe_with_cert`).
14. **open_fileless_blob.py issued PROVEN (expected OPEN).** Fixture form error compounded by fix F2's blast radius: as a `.reg`-style text the script ledger proved lines the family rule treats as an undecodable blob. The fixture was rebuilt in the tested assignment form. (The F2 blast radius itself produced miss 15.)

### Run 2: 7 mismatches, 0 false NO

15. **twin_backup_encryptor.py issued YES-PROVEN (regression from fix F2).** With API atoms visible in script text, the generic ransomware chain (encrypt plus write plus delete) fired on the backup tool, which is the family's canonical FP twin. Fix F12: the generic chain now also requires a demand or anti-recovery element (ransom, bitcoin, shadow deletion, vssadmin, a payment demand), aligning it with the family proof standard (crypto loop plus 2 of ransom note, shadow deletion, key material). The corpus ransomware fixture carries all three and still proves.
16. **open_fileless_blob.py issued YES-PROVEN via the generic backdoor chain.** Cause: fix F2's substring matching let "bind" fire inside "binding" (`__EventFilter binding`), producing a spurious net-listen capability. Fix F13: script-text API matching is token-boundary based (`_atom_in_text`), so an API name counts only as a whole token. This is the fix that makes F2 safe.
17. Remaining run-2 items (rat, dead-drop, hijacker, beacon, sideload_genuine) were the fixes F6, F8, F10, F11 and the scenario correction 6 landing in stages; all cleared by run 3 except dead-drop's atom gap, which cleared in run 4.

### Runs 3 and 4

Run 3: 1 mismatch (dead-drop atoms, fix F8). Run 4: **PASS, 37 of 37**, repeated identically in the cloud-proof run below.

### Known remaining limitation, stated plainly

The firmware SMM-plus-network combined flag does not fire per-driver yet (carried over from the v3 verification). It is a labelled limitation, not a silent gap: firmware findings are reported per module, and the combined escalation is named here until it is built.

## Elite-analyst audit: expected-crack classifications are machine-verified

The audit requirement: accounting proves every byte is explained, not that every explanation is true, so an "expected crack" classification must be machine-verified, never a label.

**Audit outcome: a defect was found, and it is fixed.** The diff classifier previously classified regions as expected-crack on (a) license words in the surrounding context, or (b) small size alone. Its capability gate operated at whole-file level only: a payload planted inside a patch-shaped region, using capabilities the genuine file already had somewhere, could pass as expected-crack.

The classifier now works as follows (see `classify_diff` in `event_zero/verdict.py`):

- A region earns expected-crack only by matching a **named crack pattern**: conditional-branch-patch, checksum-or-integrity-fix, wrapper-removal, license-condition-neutralised, license-flag-flip, or key-or-serial-substitution.
- AND passing the **region capability check** on its own bytes: capability rules, network indicators (URLs, IPs, domains), and embedded executable headers are profiled over the enclosing string span of the region in both files (the diff engine emits minimal fragments, so the full string the region sits inside is what is checked). Any added capability or indicator fails the region to **unaccounted**, however patch-shaped it looks. The ledger records `crack_pattern` and `region_capability_check` per region.
- The whole-file capability gate is unchanged: any new capability anywhere in the patched file makes every region unaccounted.
- The benign-repack zeros rule is byte-verified by construction (every new byte is zero).
- One tightening landed during the fix: wrapper-removal no longer fires on deleted filler bytes; the deleted region must contain wrapper or DRM naming, or be mostly non-printable code.

**Regression fixtures** (`tests/test_diff_verification.py`): a same-length attacker-URL swap inside a license region, in a file that already has a network capability, comes back YES-UNACCOUNTED with the region capability check recorded as failed, never NO; a region carrying a new capability atom is never expected-crack; a genuine conditional-branch flip still classifies expected-crack with its pattern named.

**Also adopted from the same research:**

- **Environment coverage as a number.** Every verdict report and run receipt states coverage numerically (files total and statically analysed, files emulated, instructions emulated, entry-stub traces, operating-system environments executed: 0), lists the environments covered, and lists the environments **not** covered (OS execution, locale and date variation, network personalities, domain-joined and installed-software states) instead of omitting them.
- **The residual pack is the human handoff format.** Every OPEN case carries a `residual_pack`: each unaccounted item and unaccounted diff region with its ranges, its evidence, the specific question a human must adjudicate, and the next escalation rung. The analyst is handed only the residual, never the whole file.

## Cloud verification

`.github/workflows/verify.yml` runs two jobs:

- **test-suite**: the full test suite on ubuntu, windows, and macos. The suite is pure Python and platform-clean by design (samples never executed, fixtures in temporary directories, subprocesses only to `sys.executable`), so the full suite runs on all three; that choice is stated in the workflow comments.
- **verify-corpus** (ubuntu): a setup stage builds the verification image (network allowed there, and only there). The verification stage runs the image with `docker run --network none`: the egress canary must prove every outbound attempt fails, the corpus is built, The Verdict runs over the whole corpus **twice**, and the **determinism gate** fails the job if the two runs' ledger roots differ. The job summary publishes the run's proof: the corpus manifest hash, the per-fixture verdicts table, the independent scorer output, and the artifact digests. The uploaded artifact is a convenience copy only: Actions artifacts expire after 90 days, so durable proof copies live as Release assets and as the small in-repo proof files under `fixtures/verification/`.

**Local proof run (this machine, 2026-11-23).** Docker is not installed in this VM, so the verification stage's exact commands were run under a Linux network namespace (`unshare -n`, no routes, no DNS), which enforces the same no-egress property the container flag enforces on GitHub's runners. Results: egress canary PASS (1.1.1.1:53, 8.8.8.8:53 and 93.184.216.34:80 unreachable, DNS resolution failed, all as required); corpus batch PASS twice with identical summaries; determinism gate PASS (identical roots files); corpus ledger root b5e851ff1ba166a2083e15681256ec06a5af9603aba364b7b9f6fd1348cc1f4b, identical to the networked run, which is itself evidence the batch needs no network; manifest SHA-256 671aca26e7890afb3d8a59ff47e5e5390a3b1820c363b53f8ded9592e445aef3.

**Plain statement**: GitHub Actions itself runs only after the tree is pushed, and a push needs Mister Blacklock's explicit order. Nothing in this report claims an Actions run has happened. The workflow's steps were executed locally as described above; the Docker image build is the one step that can only run on the runner.

**Notebooks.** `notebooks/verify_event_zero.ipynb` reproduces the verification interactively on Colab (clone, install, build the corpus, run the batch, print the table). Kaggle does not host or run the corpus (its acceptable use has no research carve-out for this content, and dataset archives are stored uncompressed server-side), so `notebooks/kaggle_results_mirror.ipynb` is a results-only mirror: it reads the published report, the results CSV, and the hash-only JSONL with internet off, and contains no corpus.

## Test suite state at this verification

Full suite: see VERIFICATION.md for the current count and the one-command check. The family expansion, signing, revocation, diff-verification, corpus, and cloud-proof work in this report is covered by `tests/test_families.py`, `tests/test_signing.py`, `tests/test_diff_verification.py`, and the corpus batch itself, on top of the pre-existing 91 verdict-era tests, all passing.
