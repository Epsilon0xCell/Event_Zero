# Event Zero Validation Programme: Pilot Report (Phase 1)

Date: 2026-11-23. Scope: infrastructure plus a measured 1,000-case
pilot. The full 100,000-case run was NOT attempted. All numbers below
were measured in this session by running the real engine
(event_zero.verdict.verdict, the CLI entry point) and the independent
scorer. Nothing here is a frozen-gate result: the pilot is a
development instrument and licenses only the weak claim form in
validation/PREREGISTRATION.md.

## What was built

- validation/harness/manifest.py: canonical JSONL manifest (sorted
  keys, compact separators), manifest root = SHA-256 of the canonical
  file, schema validation, and split_manifest() producing a
  runner-visible copy with labels omitted plus a separate sealed
  expectations file.
- validation/harness/scorer.py: independent scorer. It imports
  nothing from event_zero (enforced by a test that walks its import
  AST). Error classes: false-no (release-blocking), false-yes,
  wrong-reason, wrong-family, fabricated-proof, label-atom-missing,
  determinism-failure, crash, timeout, missing-line, unexpected-line,
  duplicate-line. A missing result line is an error, never a drop.
- validation/harness/runner.py: runs each case twice (determinism
  gate on the ledger root), measures runtime, enforces the timeout
  policy (soft 60 s flag, hard 300 s recorded as a timeout result).
- validation/PREREGISTRATION.md: strata and counts slots, label
  rules, scoring rules, zero-error threshold, timeout policy,
  code-freeze rule, strong and weak claim forms, expiry rule.
- tests/test_validation_harness.py: 11 tests, all passing (manifest
  root stability and sensitivity, schema catching a bad token,
  sealed separation, planted false NO, planted missing line,
  false-yes, wrong-reason, OPEN_STATE rules, fabricated proof,
  wrong family, determinism, crash, timeout, scorer independence).

## Pilot corpus

Exactly 1,000 cases, assembled from existing material only. No live
malware, no downloads, no network.

- 37 cases: the verification corpus (fixtures/verification/), labels
  adjudicated in its manifest, including 4 designed-OPEN cases and 1
  genuine-reference folder case.
- 4 repo fixtures: fake_malware (YES PROVEN), fixtures/evil.py (YES
  PROVEN), fixtures/eicar.com (NO ACCOUNTED), fixtures/hello_elf
  (OPEN_STATE by design: a lone benign binary the tool cannot
  certify, the honest fail-closed label).
- 959 seeded synthetic variants from validation/harness/build_pilot.py:
  18 malicious templates (684 cases), 11 benign and FP-twin templates
  (245 cases, including 20 EICAR variants), 30 malformed files.
  Labels are true by construction; each template emits its required
  proof atoms. Every 25th file case was converted to a zip archive
  holding the same bytes.

Composition: tokens YES 709, NO 256, OPEN_STATE 35. Kinds: file 958,
archive 39, folder 3. Tiers: T0 959, T1 37, T2 4. Splits:
development 671, tuning 192, adversarial 96, regression 41.
Distinct clusters: 68. That last number is the honest one: 1,000
cases but only 68 independent clusters, so the pilot measures the
harness and the engine's consistency far more than it measures
generalisation. The 100k corpus must fix exactly this.

Manifest roots: full fca33adc5e95a7ea6b836f50edbd22e1d09061e30d9f1f3df74a5a94c3ef5c2b,
runner 5d9156379bdf14b727be2f95430887c3e27bcb560450e0f6f5882ce0b855578e,
sealed f864343a4908a2abae537fbf34da8dac6ddcec766dbfc9172f77f8b3f82b55fd.

## Measured results

Final scorecard (after the scorer correction disclosed below):
992 of 1,000 correct (99.2 percent). Errors: 7 false NO, 1 false YES.
Zero determinism failures, zero crashes, zero timeouts, zero cases
over the 60 s soft cap. Release-blocking count: 7 false NO, so this
pilot would fail any release gate. That is the pilot doing its job.

Runtime per case (first of the two runs; the determinism run roughly
doubles wall time): p50 33 ms, p95 176 ms, p99 304 ms, max 8,832 ms
(hello_elf), mean 68.6 ms, total first-run CPU 68.6 s for 1,000
cases. Extrapolation, with the caveat stated below: at this mix,
100,000 cases cost about 1.9 CPU-hours per pass, about 3.8 CPU-hours
with the determinism run, trivially shardable by manifest slice.
Caveat: the pilot mix is script-heavy. Real binaries are far slower
(fake_malware measured 2.83 s, hello_elf 7.79 s in probes), so a
binary-heavy 100k corpus will have a much heavier p95 and p99 and
needs its own measured pilot per stratum before any schedule claim.

Label-construction cost (qualitative): corpus labels were already
adjudicated; generated labels cost nothing per case because the
generator writes the bytes and the atoms together. The expensive
labels at 100k scale will be genuine-reference pairs and adjudicated
real-world cases, not synthetic ones.

## The three error groups, diagnosed

1. False NO, 7 cases, all one root cause (release-blocking).
   Every truncated-zip malformed variant (a zip cut to half its
   bytes) was issued NO ACCOUNTED. An archive whose contents cannot
   be fully enumerated must never be certified clean; these should
   be YES UNACCOUNTED or OPEN. This is a real engine fail-open on
   truncated archives, found by the pilot, and it belongs in the
   miss ledger and the regression set.
2. False YES, 1 case. A banking article (plain reporting text
   naming banks, a known FP twin as a loose file) was issued YES
   PROVEN when the identical text was wrapped in a zip: inside an
   archive, the bank-target chain fires without the article-context
   discriminator that protects the loose file. Context sensitivity
   differs for archive members; the discriminator must follow the
   member, not the container.
3. Fabricated-proof, 2 cases, a scorer defect, corrected and
   disclosed. The first scorecard (990 of 1,000) flagged
   beacon_config.bin and sideload_folder. Both exhibit analytical
   proof (a parsed XOR-encoded beacon configuration; a sideload
   triad statement), not literal byte strings, so the scorer's
   literal byte-presence check misfired. The check now applies only
   to literal evidence atoms (string/text: and import/symbol:);
   analytical atoms are exhibited proof of a different kind, the
   same distinction the verification corpus scorer already makes
   with its parsed-config check. Both scorecards are preserved
   (scorecard.v1.json and scorecard.json). The correction is in
   /tmp landing form (scorer_fixed.py) because of the quota issue
   below; it must land in validation/harness/scorer.py with its two
   regression tests before any further scoring is treated as final.

## Gaps to 100,000: strata that cannot be filled from existing material

- Genuine-reference crack pairs at scale: needs licensed genuine
  originals and crack releases with documented provenance and terms
  basis. The pilot has exactly one such pair (corpus sideload).
- Real packed and virtualized binaries (VMProtect, Themida class):
  needs lab-built protected binaries or a licensed sample channel.
- Binary diversity generally (PE, ELF, Mach-O): the pilot is
  script-heavy. Needs disarmed public sets (EMBER, SOREL-20M style,
  features and hashes) plus lab-compiled fixtures for full-accounting
  cases.
- Installers (Inno, NSIS, MSI) as subjects: needs real installer
  samples and the parser adapters installed.
- Documents and firmware: needs a disarmed document corpus and
  vendor firmware images with provenance.
- Time-split and family-holdout real sets: needs dated, hash-first
  acquisition and a secure lab tier for any real-sample work; never
  committed to the public repo.
- Blind custodian set: needs a named custodian and a sealed
  acquisition channel; by construction the project cannot build this
  from its own material.
- Cluster independence: 100k must be planned in clusters first
  (families, strains, release lineages), with per-cluster caps, or
  the count will flatter the result exactly as the pilot's does.

## Environment note (quota)

Midway through the pilot, the home filesystem began returning
Errno 122 (disk quota exceeded) on all writes under ~/workspace,
although df shows free space; the same failure killed the earlier
research run's report. Consequences, all disclosed: the pilot run
was completed from /tmp with a driver implementing the runner's
skip-existing logic (the runner --resume patch could not be written
into the workspace); the final results.jsonl, scorecards, and this
report are staged at /tmp/ezpilot/ and must be copied into
validation/pilot/ when the quota clears; and exactly one existing
test fails for this reason alone (tests/test_final.py::test_export_cli,
OSError Errno 122 writing fake_malware.iocs.csv). The suite otherwise
stands at 151 passed, which includes all 141 baseline tests that do
not need workspace writes, plus the 11 new harness tests.

## Fix note (2026-11-23, appended after the fixes)

Both engine defects diagnosed above are fixed, and the pilot was
rerun end to end through the harness (runner plus independent
scorer) against the untouched manifests. The sealed expectations
were not edited: sealed root still
f864343a4908a2abae537fbf34da8dac6ddcec766dbfc9172f77f8b3f82b55fd,
full manifest root still
fca33adc5e95a7ea6b836f50edbd22e1d09061e30d9f1f3df74a5a94c3ef5c2b.
The pre-fix results are preserved at validation/pilot/results.v1.jsonl
and the pre-fix scorecard at validation/pilot/scorecard.v2.json.

New scorecard: 1,000 of 1,000 correct (100 percent), pass true.
Zero false NO, zero false YES, zero errors of any class, zero
determinism failures, zero crashes, zero timeouts, zero cases over
the 60 s soft cap. Rerun runtime per case: p50 27 ms, p95 48 ms,
p99 88 ms, max 2,422 ms, mean 33.3 ms. The full test suite stands at
166 passed in tests/ (the 152 baseline plus 14 new regression tests)
and 18 passed in gui/tests/.

Defect 1, root cause and fix. Container detection used
zipfile.is_zipfile, which answers False for a truncated zip because
the end-of-central-directory record sits at the end of the file. A
truncated zip saved as .bin was therefore never recognised as a
container, never enumerated, and its bytes fell through the per-file
accounting to "accounted as data": NO ACCOUNTED on an archive that
could not be opened. The fix is general, in event_zero/verdict.py:

- container_kind() detects containers by magic bytes and declared
  name without requiring the container to parse (zip local-header
  signatures including a truncated zip, ustar magic, 7z, RAR and CAB
  signatures, and archive suffixes as a declared-name fallback).
- Enumeration is fail-closed for every container kind. Zip and tar
  extraction now raise on a member count past the enumeration cap
  (previously the member list was silently truncated at the cap), on
  a member whose extracted bytes do not match its declared size
  (truncation), on encrypted members, on unsupported compression, on
  CRC failure, and, for tar, on members that are not regular files
  (symlinks, hardlinks, devices and fifos were previously skipped
  silently). 7z, RAR and CAB containers, which this build has no
  parser for, are unaccounted by construction with the next step
  named.
- enumerate_subject() records failed containers, and the verdict
  marks each one as an explicit unaccounted unit: YES UNACCOUNTED,
  case state OPEN, with the enumeration failure named. Sibling paths
  audited and fixed in the same pass: tar member handling (above),
  nested archives (a truncated zip inside a valid zip now fails
  closed at the member level), the recursion depth-limit check (now
  uses the same container detection, so a truncated archive at the
  depth limit is still recognised as an unopened layer), and
  suffix-declared containers that do not parse at all.

Defect 2, root cause and fix. The container file itself was analysed
as a content file: its raw bytes (members stored uncompressed) were
judged under the container's own name, banking_article_10.txt.zip,
so the banking family rule fired on the article text while the
article-context discriminator, keyed on the member's .txt extension,
did not apply. The member itself was correctly judged NO; the false
YES came from the container entry. The fix: a fully enumerated
container that is not itself executable is an enumeration unit, not
a content unit. Its members are judged as the content, each with
exactly the context a loose file gets, and the container's raw bytes
are not re-judged for capability chains, carved payloads, scope test
hits, family chains, keygen behaviour or virtualization trace
chains. A container that is itself executable (a self-extracting PE)
is still judged as code in its own right. The control case holds: a
banking trojan script inside a zip is still YES PROVEN through its
member.

Permanent regression fixtures: tests/test_container_failclosed.py,
14 tests (11 container fail-closed shapes, a valid-zip control, and
the three banking context cases). Both defects are also recorded in
docs/MISS-LEDGER.md as EZ-BYPASS-2026-001 and EZ-BYPASS-2026-002.

One correction to the environment note below: the scorer correction
it describes as sitting in /tmp landing form has since landed in
validation/harness/scorer.py (verified byte-identical to the /tmp
copy during this fix session), and the rerun above used the
workspace scorer. The claim licensed by this pilot is unchanged in
form: a development instrument result, not a frozen gate, and no
general accuracy claim is made from it.

## Claim licensed by this pilot (weak form)

Event Zero 3.0.0 was run against a development pilot corpus of 1,000
cases (manifest root fca33adc5e95a7ea6b836f50edbd22e1d09061e30d9f1f3df74a5a94c3ef5c2b)
and identified 992 correctly, with 7 false NO (one root cause:
truncated archives), 1 false YES, and zero determinism failures.
This corpus is a development instrument, not a frozen gate, and no
general accuracy claim is made from it.
