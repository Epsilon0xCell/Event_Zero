# Event Zero Miss Ledger

The public, append-only record of confirmed misses and bypasses against The Verdict, kept under the Miss Handling, Bypass Disclosure and Verdict Revocation Policy (`docs/MISS-AND-REVOCATION-POLICY.md`).

Rules of this ledger:

- **Append-only.** Entries are never deleted or edited, except by an appended correction entry that references the original.
- **No silent fixes.** Every confirmed miss appears here with its EZ-BYPASS identifier, and the fix ships with that identifier in the release notes.
- **Every confirmed miss becomes a permanent regression fixture** in the adversarial test suite, so the same miss cannot recur in a later release.
- **Revocation comes first.** Affected verdicts are revoked on the day of confirmation, before root-cause analysis is complete, by entry in the signed Verdict Revocation List (format in `format-spec.md`).

| EZ-BYPASS ID | Reported | Confirmed | Revoked | Affected tool / suite / corpus versions | Rule identifying affected reports | Residual path | Status |
|---|---|---|---|---|---|---|---|
| EZ-BYPASS-2026-001 | 2026-11-23 (validation pilot) | 2026-11-23 | n/a: found in a development pilot before any public release; no signed public verdicts exist from the affected build | Event Zero 3.0.0 local build; validation pilot corpus (manifest root fca33adc5e95a7ea6b836f50edbd22e1d09061e30d9f1f3df74a5a94c3ef5c2b) | Any verdict of NO ACCOUNTED issued by the affected build on a truncated or otherwise unenumerable container (pilot cases pilot-0937, 0941, 0945, 0949, 0953, 0956, 0960) | Container detection required a parseable container (zipfile.is_zipfile), so a truncated zip was treated as plain data and certified clean. Fixed generally: container detection by magic and declared name, fail-closed enumeration for zip and tar (corrupt, truncated, encrypted, unsupported, cap hits, non-regular tar members, unsupported 7z/rar/cab kinds), failed containers recorded as unaccounted units | Fixed 2026-11-23. Regression fixtures: tests/test_container_failclosed.py (11 container cases). Pilot rerun after the fix: 1000 of 1000, zero false NO |
| EZ-BYPASS-2026-002 | 2026-11-23 (validation pilot) | 2026-11-23 | n/a: found in a development pilot before any public release; no signed public verdicts exist from the affected build | Event Zero 3.0.0 local build; validation pilot corpus (same manifest root) | Any verdict of YES PROVEN issued by the affected build on a fully enumerated archive whose members are non-executable documents (pilot case pilot-0997) | Family context discriminators keyed on the analysed file's name; an archive container entry was judged from its raw bytes under the container's extension, so the banking-article discriminator that protects a loose .txt did not apply inside a .zip. Fixed: a fully enumerated, non-executable container is an enumeration unit, not a content unit; members are judged with loose-file context, and the container's raw bytes are not re-judged as code | Fixed 2026-11-23. Regression fixtures: tests/test_container_failclosed.py (banking article loose, banking article in zip, banking trojan in zip). Pilot rerun after the fix: 1000 of 1000, zero false YES |

The ledger held no entries before 2026-11-23. An empty ledger is a statement about what has been confirmed and published, not a claim that a miss is impossible; the guarantee wording in the README states exactly what is and is not guaranteed.
| EZ-BYPASS-2026-003 | 2026-11-24 (campaign smoke run 3, run 45499880998) | 2026-11-24 | n/a: the verdict was an unsigned internal campaign run output; no signed public verdict exists for this sample | Event Zero build at commit d47fd05; campaign manifest root f1091bc66389cf97388c72b250dec0fe169025d7ce867cbaf8de31d0b0148edb | The NO ACCOUNTED verdict on sha256 000a219ec381c86b6a1b2cb18f11d66f0a545749ac515335d772266d0720946a (results ledger root 044bee9692fb3d1b15c8dae18ade5ca1ed2abc7a3667c3d4ba7af54d7914b5b8) | The sample is FormBook delivered as a JavaScript dropper (file DB_aabhjcfgajig0x04EF.JS, first seen on MalwareBazaar 2026-11-17, 15 vendor detections including Joe Sandbox FormBook and ReversingLabs Script-JS.Backdoor.FormBook, read from the sample page 2026-11-24). The engine accounted it clean. Root cause is not yet established: per-sample evidence stays inside the campaign runner by design, so the verdict record is all that leaves. The audit of the same build proved script-side false-NO paths (20,000 character source truncation, 4,000 line ledger window, 2,000 string judgement cap) that are candidate mechanisms, all fixed in commit 349e6a9. Status: confirmed miss; determination of whether the fixed engine catches this sample awaits the shard 0 rerun on the fixed build, and the case becomes a permanent regression fixture once its path is reproduced |
| EZ-BYPASS-2026-004 | 2026-11-24 (campaign smoke run 3, run 45499880998) | 2026-11-24 | n/a: unsigned internal campaign run output; no signed public verdict exists for this sample | Event Zero build at commit d47fd05; campaign manifest root f1091bc66389cf97388c72b250dec0fe169025d7ce867cbaf8de31d0b0148edb | The NO ACCOUNTED verdict on sha256 003e626ae5b7daa892d5d169f4be988ed47a6338c4f4610e7bf6e803a3972291 (results ledger root e60f21b05f3cd98c9c2618198aa227af26cdc3ada0154dd8175e7a337b5f14f4) | The sample is an njRAT executable (first seen on MalwareBazaar 2026-09-10, 16 vendor detections including Joe Sandbox njRAT, Threatray njrat, and UnpacMe win_njrat_auto, read from the sample page 2026-11-24). The engine accounted it clean. Root cause is not yet established (per-sample evidence stays inside the campaign runner by design). The audit of the same build proved multiple false-NO paths, all fixed in commit 349e6a9. Status: confirmed miss; determination awaits the shard 0 rerun on the fixed build, and the case becomes a permanent regression fixture once its path is reproduced |
| EZ-BYPASS-2026-005 | 2026-11-24 (campaign smoke run 3, run 45499880998) | 2026-11-24 | n/a: unsigned internal campaign run output; no signed public verdict exists for this sample | Event Zero build at commit d47fd05; campaign manifest root f1091bc66389cf97388c72b250dec0fe169025d7ce867cbaf8de31d0b0148edb | The NO ACCOUNTED verdict on sha256 06068e7042a68b17c2a719f2b3eb07128ecefd9d7125c03ffa20eccce9409d2d (results ledger root b701e8b452f9656391871bb72c5d0f7bcfd921d9e3139203e5502499cb6c6dc1) | The sample is a RaccoonStealer executable (file 37038614b984271b4d4877e4d2ca53a1.exe, first seen on MalwareBazaar 2022-02-20, 13 vendor detections including Joe Sandbox Raccoon, Intezer Raccoon Stealer, and UnpacMe win_raccoon_auto, read from the sample page 2026-11-24). The engine accounted it clean. Root cause is not yet established (per-sample evidence stays inside the campaign runner by design). The audit of the same build proved multiple false-NO paths, all fixed in commit 349e6a9. Status: confirmed miss; determination awaits the shard 0 rerun on the fixed build, and the case becomes a permanent regression fixture once its path is reproduced |

## EZ-BYPASS-2026-006

- Sample (SHA-256):
  00a11f7f6f468459711a2907e4dc74f7d574b37c7bc5f2b8e73e518848ff9d50
- What it is: a 198-byte Windows .URL shortcut (file name
  Gennaio_url), a Gozi / Ursnif delivery artifact from an
  Italian tax-agency lure set, first seen 2023-01-12, reporter
  JAMESWT_WT. The bazaar page records 4 vendor detections:
  ClamAV detected it (an evil-shortcut signature), FileScan.IO
  rated it Likely Malicious at 7.5 of 10, YOROI rated it
  Malicious at 1.00, and the Spamhaus Hash Blocklist lists it
  as suspicious.
- Event Zero verdict: NO ACCOUNTED, issued by the fixed engine
  (commit 349e6a9) in campaign smoke run 5 (run 45514931922,
  2026-11-24).
- Adjudication: CONFIRMED MISS, 2026-11-24, from the public
  bazaar sample page (vendor detections and signature read
  directly; no sample downloaded). A malicious shortcut file
  was accounted clean.
- Status: open. Pattern note: all three run 5 misses are small
  script-class delivery files from the same lure set; the
  per-sample root cause is not established, because per-sample
  analysis evidence stays inside the campaign runner by design.

## EZ-BYPASS-2026-007

- Sample (SHA-256):
  03e548ca313467cc8716fa135199414f36ca37884cd95b6cdd1b9a37c3bee71a
- What it is: a batch file with a double extension
  (5441.pdf.cmd, 8,380 bytes), a Gozi / Ursnif delivery
  artifact, first seen 2023-03-31, reporter JAMESWT_WT. The
  bazaar page records 4 vendor detections: Joe Sandbox rated
  it malicious at 52 of 100 (evasion classification, double
  extension signature), ClamAV detected it, FileScan.IO rated
  it Suspicious, and the Spamhaus Hash Blocklist lists it as
  suspicious. One vendor (YOROI) dissented with a Legit rating.
- Event Zero verdict: NO ACCOUNTED, issued by the fixed engine
  (commit 349e6a9) in campaign smoke run 5 (run 45514931922,
  2026-11-24).
- Adjudication: CONFIRMED MISS, 2026-11-24, from the public
  bazaar sample page (no sample downloaded). A malicious batch
  dropper was accounted clean.
- Status: open. See the pattern note on EZ-BYPASS-2026-006.

## EZ-BYPASS-2026-008

- Sample (SHA-256):
  04b5784000d66093995c13dddb0f346996aea2b7fc9ce0d420f5b596ad70fe72
- What it is: an HTML Application downloader (azienda_08.hta,
  6,975 bytes), a Gozi delivery artifact from the same Italian
  tax-agency lure set, first seen 2023-02-07, reporter
  JAMESWT_WT. The bazaar page records 6 vendor detections:
  Hatching Triage rated it Malicious at 8 of 10 with download
  via BitsAdmin and certificate-store modification behaviours,
  VMRay and Hybrid Analysis rated it Malicious, DocGuard rated
  it Malicious with a payload URL, ClamAV detected it, and the
  Spamhaus Hash Blocklist lists it as suspicious. One vendor
  (YOROI) dissented with a Legit rating.
- Event Zero verdict: NO ACCOUNTED, issued by the fixed engine
  (commit 349e6a9) in campaign smoke run 5 (run 45514931922,
  2026-11-24).
- Adjudication: CONFIRMED MISS, 2026-11-24, from the public
  bazaar sample page (no sample downloaded). A malicious HTA
  downloader was accounted clean.
- Status: open. See the pattern note on EZ-BYPASS-2026-006.

## Status addendum, 2026-11-24 (fix waves 2 and 3)

- EZ-BYPASS-2026-003, 004, 005: re-judged by the wave 1 engine
  in campaign smoke run 5 (run 45514931922); all three now
  return YES UNACCOUNTED. The acquittal defect is closed; the
  samples remain unproven rather than convicted, which is the
  designed fail-closed outcome.
- EZ-BYPASS-2026-006, 007, 008: the three shapes are capped by
  fix wave 2 (script_class_findings in the verdict:
  remote-fetch-and-execute, url-shortcut-remote-payload,
  disguised-double-extension), proven on synthetic fixtures of
  the same shapes in tests/test_accuracy_audit_wave2.py, suite
  203 passed. Fix wave 3 adds the structural closure rules
  behind them (external-reference closure, engine
  incompleteness as a verdict cap, interpreter-proxy
  invocation), suite 224 passed. Confirmation on the real
  samples awaits the shard 0 re-run on the strengthened
  engine; until then these entries stay open on the record.

## Status addendum 2026-11-24 (shard 0 run 6, engine cd2b0c8)
- 006 re-judged on the real sample: YES. Defect closed on real evidence.
- 007 and 008 re-judged on the real samples: NO ACCOUNTED again. Fix wave 2 closed synthetic fixtures of their shapes, not the shapes the real files use. Both entries remain OPEN; fix wave 4 scoped from the vendor sandbox behaviours of record.

## Status addendum 2026-11-24 (fix wave 4)

- EZ-BYPASS-2026-007, 008: re-judged by the wave 2 and 3 engine in campaign smoke run 6 (run 45541655584); both returned NO ACCOUNTED again on the real samples. Fix wave 4 (validation/FIX-LOG-2026-11-24-WAVE4.md) closes the shape classes the vendor behaviours of record and the batch, VBScript and JScript dialects define: resolved-source analysis (variable substitution, fragment and growth assembly, Chr() character construction, dialect-faithful decoding that never silently empties), HTA script-body references under R1, the fetch-object plus staged-executable composition rule, content-keyed classification for extensionless files, and written-stage accounting for echo-written second stages. Fourteen synthetic shapes that returned NO ACCOUNTED on the wave 3 engine now cap, each with its mechanism named, and the benign twins keep NO. Suite: 331 passed, operator-verified. Confirmation on the real samples awaits the shard 0 re-run on the strengthened engine; until then these entries stay open on the record.

## Status addendum 2026-11-25 (shard 0 run 7, engine 130f2a4)

- Run 7 produced no verdicts: all 250 downloads failed (247 HTTP 429, 3 HTTP 502; per-IP quota on shared egress, exhausted before the run began). Entries 007 and 008 were not re-judged and remain OPEN. Fix wave 4's real-sample confirmation is still outstanding and rides the next run after the quota window resets.
