# Pre-Registration Template: Event Zero Frozen Validation Gate

Fill in every slot, hash this file, and publish the hash before the
frozen run starts. Any change after the freeze voids the run and
requires a new pre-registration with a new version number. This
template follows the programme design: a perfect score is licensed
only as a process claim about a named, frozen, independently scored
corpus.

## 1. Run identity

- Pre-registration version: [ ]
- Date frozen: [ ]
- Code freeze commit: [ ]
- Rule-pack hash: [ ]
- Manifest root (full): [ ]
- Sealed expectations root: [ ]
- Scorer version and hash: [ ]
- Custodian of the blind split: [ ]

## 2. Corpus: strata and counts

Total cases: [ ]. Per stratum (name, count, tier, provenance basis):

- Known-family proven malware (synthetic and disarmed): [ ]
- Trojanized cracks with genuine references: [ ]
- Clean cracks and FP twins: [ ]
- Benign software: [ ]
- Dual-use tools (KMS, trainers, mods, capture tools): [ ]
- Installers and nested archives: [ ]
- Scripts, documents, firmware-like files: [ ]
- Packed and virtualized samples: [ ]
- Environment-keyed and server-keyed (designed OPEN): [ ]
- Test files (EICAR class): [ ]
- Malformed files and parser attacks: [ ]
- Unknown-family holdout (family-holdout split): [ ]
- Time-split (first seen after the tuning freeze): [ ]
- Adversarial cross-cut: [ ]

Splits: development [ ], tuning [ ], regression [ ], frozen [ ],
blind (custodian-held) [ ]. The regression set only grows; a case
never leaves it.

## 3. Label rules

- Labels are true by construction (synthetic fixtures with proof
  atoms), by byte-identity to a genuine reference, or by documented
  multi-source adjudication recorded in adjudication_ref.
- Hash presence in NSRL, CIRCL, or any antivirus consensus is
  corroboration only and never a label basis for NO.
- Disputed labels are resolved before the freeze or the case is
  labelled OPEN_STATE by design. No label changes after the freeze;
  a wrong label found later is published as a label erratum, the case
  is scored as labelled, and the correction enters the next corpus
  version.

## 4. Scoring rules

- The scorer is independent of the analyser and joins result JSONL
  to sealed expectations only.
- A missing result line is an error, never a dropped case.
- Error classes: false NO (release-blocking), false YES, wrong
  reason, wrong family, fabricated proof, determinism failure,
  crash, timeout.
- Correct for YES PROVEN requires the token, the rendering, and the
  required proof atoms exhibited or present in the subject bytes.
- Correct for NO requires NO ACCOUNTED: a complete accounting, not
  merely no detection.
- Correct for OPEN_STATE requires a fail-closed YES UNACCOUNTED or
  an OPEN case state; closing an unresolvable case as PROVEN or NO
  is an error.

## 5. Zero-error threshold

The gate passes only at zero errors of every class across the whole
frozen plus blind corpus, with zero false NO as an absolute condition
that no other result can offset. Anything less is reported as the
measured scorecard it is, with per-stratum results, and licenses only
the weak claim form in section 8.

## 6. Timeout policy

Soft cap 60 seconds per case, hard cap 300 seconds per case. A case
over the soft cap is flagged in the results. A case that hits the
hard cap is scored as a timeout result for that case. Caps are
results, not infrastructure failures, and never remove a case from
the denominator.

## 7. Code-freeze rule

From the freeze until the gate run completes: no engine, rule, or
scorer changes; no expectation edits; no case removals. Failures are
analysed only after the run is scored and published. A failed case
may move into the regression set for the next corpus version only
after its root cause is published in the miss ledger.

## 8. Claim wording slots

Strong form (licensed only by a zero-error frozen plus blind run,
with this pre-registration published):

"On [date], Event Zero [version, commit] was run against a frozen,
pre-registered corpus of [N] cases (manifest root [root]), scored
independently against sealed expectations. It identified every case
correctly: [n] malware proven, [n] not malware accounted, [n]
unresolvable cases held open, with zero false NO. The corpus,
manifest, scorer, and full scorecard are published at [location].
This is a claim about that corpus and that version."

Weak form (any run with errors, any non-frozen corpus, any pilot):

"Event Zero [version] was run against a [development / pilot] corpus
of [N] cases and identified [n] correctly ([x] percent), with
[k] false NO, [k] false YES, and [k] cases held open. Per-stratum
results: [location]. This corpus is a development instrument, not a
frozen gate, and no general accuracy claim is made from it."

Forbidden in all forms: "never misses", "100 percent detection",
"guaranteed clean", "miss-proof", "bypass-proof", and any accuracy
figure without its corpus, version, and manifest root attached.

## 9. Expiry rule

This pre-registration expires at the earlier of: 90 days after the
freeze date, the first engine or rule change after the gate run, or
the first confirmed miss against this version in the wild (which is
entered in the miss ledger and revokes the strong claim for that
version from that date).
