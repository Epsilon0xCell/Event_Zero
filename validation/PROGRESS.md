# Event Zero 100k Validation Programme: Progress

Phase 1: infrastructure plus a measured pilot. The full 100,000-case run
is NOT attempted in this phase.

## Status log

- 2026-11-23: Design read (task brief plus research notes index at
  ~/workspace/research_notes/event-zero-100k-validation-improvement-l-20261123-0722/notes/sources.md;
  the on-disk report.md there is a skeleton only, lost to a disk quota
  failure during the research run).
- 2026-11-23: Engine interfaces probed with my own runs. The verdict
  API (event_zero.verdict.verdict) returns verdict, reason_class,
  case_state, yes_reasons with exhibited evidence, and a receipt with a
  ledger root hash. No engine changes are needed for scorer
  integration: the runner consumes the same JSON shape the CLI emits.
- 2026-11-23: Probe measurements (single runs, this VM): verdict on a
  small script about 0.1 s; eicar.com 0.28 s; evil.py 0.18 s;
  fake_malware 2.83 s; hello_elf 7.79 s and YES UNACCOUNTED with case
  state OPEN (a lone benign binary the tool cannot certify, the honest
  fail-closed outcome, labelled OPEN_STATE in the pilot by design).
- 2026-11-23: Manifest module, independent scorer, runner, and pilot
  builder written. Pilot manifest built: exactly 1,000 cases (37 corpus
  + 4 repo fixtures + 959 seeded synthetic variants), schema-valid,
  manifest root fca33adc5e95a7ea6b836f50edbd22e1d09061e30d9f1f3df74a5a94c3ef5c2b.
- 2026-11-23: PREREGISTRATION.md template written (strata, label rules,
  scoring rules, zero-error threshold, timeout policy soft 60 s / hard
  300 s, code-freeze rule, strong and weak claim forms, expiry rule).
- 2026-11-23: Harness tests written and passing: 11 tests in
  tests/test_validation_harness.py (manifest root stability, scorer
  classification including planted false NO and planted missing line,
  sealed-expectation separation, scorer imports no engine code).
- 2026-11-23: Pilot run completed and scored: 992 of 1,000, with 7
  false NO (one root cause: truncated archives certified NO) and 1
  false YES (banking article zip-wrapped). Full detail in
  PILOT-REPORT.md. The scorer literal-atom correction landed in
  validation/harness/scorer.py (byte-identical to the /tmp copy).
- 2026-11-23: Both pilot defects fixed in event_zero/verdict.py.
  Defect 1: container detection no longer requires a parseable
  container (magic and declared-name detection in container_kind),
  and enumeration is fail-closed across zip and tar (truncation,
  member size mismatch, encrypted members, unsupported compression,
  member-count and expansion caps as raises instead of silent
  truncation, non-regular tar members, unsupported 7z/rar/cab
  kinds); failed containers are explicit unaccounted units (YES
  UNACCOUNTED, case state OPEN). Defect 2: a fully enumerated,
  non-executable container is an enumeration unit, not a content
  unit; members carry the judgement with loose-file context
  discriminators, so the banking article in a zip is NO and the
  banking trojan in a zip is still YES PROVEN through its member.
  Regression fixtures: tests/test_container_failclosed.py, 14 tests.
  Miss ledger: EZ-BYPASS-2026-001 and EZ-BYPASS-2026-002.
- 2026-11-23: Full suite green: 166 passed in tests/ (152 baseline
  including the 11 harness tests, plus the 14 new regression tests)
  and 18 passed in gui/tests/.
- 2026-11-23: Pilot rerun end to end through the harness with the
  sealed expectations untouched (sealed root
  f864343a4908a2abae537fbf34da8dac6ddcec766dbfc9172f77f8b3f82b55fd):
  1,000 of 1,000 correct, pass true, zero false NO, zero false YES,
  zero errors of any class, zero determinism failures. Pre-fix
  results preserved at validation/pilot/results.v1.jsonl and
  scorecard.v2.json. Fix note appended to PILOT-REPORT.md.

## Layout

- validation/harness/manifest.py: canonical JSONL manifest, manifest
  root, runner/sealed split.
- validation/harness/scorer.py: independent scorer. Imports nothing
  from event_zero.
- validation/harness/runner.py: runs cases through the real engine,
  twice per case for the determinism gate, emits result JSONL.
- validation/harness/build_pilot.py: assembles the 1,000-case pilot
  from existing repo material and seeded synthetic generators only.
- validation/pilot/: generated pilot cases, manifests, results,
  scorecard.
- validation/PREREGISTRATION.md: the frozen-gate template.
- validation/PILOT-REPORT.md: measured pilot results and the gap map
  to 100,000 cases.
