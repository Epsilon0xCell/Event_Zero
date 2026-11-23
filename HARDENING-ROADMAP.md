# Event Zero Hardening Roadmap: Anti-Bypass and Future-Proofing

Source: deep research report `event-zero-anti-bypass-future-hardening-20261123-0623` (researched 2026-11-23). This document turns that research into the project's own plan. It is a roadmap, not a claim: an item is only done when it ships, is tested, and is named in a release's notes.

## The position in one paragraph

No detector can be made bypass-proof, and Event Zero will never claim to be. Perfect detection is provably undecidable (Cohen; Rice's theorem; the Halting Problem), and for any given formal detector there are infinitely many constructible programs that evade it. What is achievable, and what this roadmap builds, is a detector where bypass is expensive, non-reusable, and publicly visible when it succeeds: several independent evidence channels must be defeated at once, the verdict rests on an accounting invariant that survives repacking, the tool and its reports are cryptographically verifiable, and every confirmed bypass becomes a permanent dated regression test.

## Standing design rules

1. Assume a perfect oracle. Event Zero is open source, so an attacker can download the exact tool and rule pack, run it offline against every mutation, and ship only what passes. Secrecy is not a control.
2. Rules are written at capability and invariant level (the top of the Pyramid of Pain), not at hash or literal-string level. Public rules that encode behaviour force an attacker to change what the program does, which often breaks the payload's function.
3. Determinism invariant: if it can change the verdict, it is versioned, hashed, and recorded in the evidence ledger. If it is not in the ledger, it cannot change the verdict. Moving-target variation lives outside the verdict inputs, or is seeded and recorded so a run is replayable.
4. The LLM layer has no vote. It narrates the deterministic ledger after the verdict is computed. Removing it changes no verdict.
5. Fail closed everywhere: any channel failure, timeout, unaccounted byte, or verification failure means the sample cannot receive a clean verdict, and the report says why.

## The 12-step roadmap, ordered by leverage

| # | Action | Bypass it kills or raises the cost of | Effort |
|---|---|---|---|
| 1 | Signed canonical verdict reports plus a public verifier plus published test vectors | The cheapest bypass of all: editing a YES into a NO, or forging a report outright. No detection work required. | S |
| 2 | TUF rule packs: monotonic versioning, expiry, threshold root keys, downgrade refusal | Rule downgrade and freeze attacks; also enables a signed fixing pack within hours of any future bypass. | M |
| 3 | PyPI Trusted Publishing, PEP 740 Sigstore attestations, reproducible wheel and sdist, published hashes | Trojaned installer and compromised-token substitution of the tool itself. | S |
| 4 | Frozen bypass regression corpus gated in CI | Re-shipping any known bypass. Converts every incident into permanent defence. | S to M |
| 5 | Conjunctive clean verdict across independent channels, fail-closed on any channel failure or unaccounted byte | Raises oracle cost from "beat one rule" to "beat every channel while staying functional". Audit existing code for silent fallbacks first. | M |
| 6 | Hash-pinned dependencies, pip-audit in CI, CycloneDX SBOM per release, SHA-pinned GitHub Actions, split build and publish jobs | The most common real-world Python supply-chain holes. | S |
| 7 | Standing adversarial fixture generator (the al-khaser pattern, inverted) run against release candidates, results published | Finds bypasses before attackers publish them; produces the cost-to-bypass metric. | M to L |
| 8 | Second independent parser cross-check; parser disagreement recorded as ledger evidence | Removes single-parser bugs as a universal bypass primitive. Two parsers sharing one library count as one engine. | M |
| 9 | Canary fixtures, decoy rules, and channel-watermarked rule packs | Makes crafting against the tool detectable and attributable. Canaries may add a `crafted-against-tool` finding; they are never the sole basis for a verdict. | M |
| 10 | Disclosure policy (ISO/IEC 29147), EZ-BYPASS identifiers, public verdict and dispute log, published metrics | Turns each bypass into reputation cost for attackers and trust evidence for users. | S |
| 11 | Emulator conformance interface plus a second emulation backend | Removes single-emulator fingerprinting as a durable bypass; future-proofs the layer most likely to be outpaced. | L |
| 12 | SLSA Build L3 hardened build, verified reproducible by an independent rebuilder | Defence in depth against build compromise, after steps 1 to 10 are done. Target at launch is SLSA Build L2 (hosted build plus signed provenance). | L |

## Release-engineering checklist

### Every release, no exceptions

- [ ] Tool version bumped (SemVer). Rule-pack version strictly greater than the previous pack. Ledger schema version and verdict-algorithm version stated in the changelog.
- [ ] Build runs in an isolated CI job from a tagged commit. `SOURCE_DATE_EPOCH` set to the commit time. Wheel and sdist are built twice and the hashes compared in CI (reproducibility check).
- [ ] Dependencies installed from a hash-pinned lockfile (`pip install --require-hashes`). `pip-audit` clean, or every exception documented. CycloneDX SBOM generated and shipped with the release.
- [ ] GitHub Actions pinned by full SHA. Workflow permissions minimal. The build job holds no publish credentials.
- [ ] Adversarial suite and the full bypass regression corpus pass against the release artefacts (the release binary plus the release pack, not development builds). Results archived with the release.
- [ ] Publish job is separate, runs in a protected GitHub Environment with a required reviewer, and uses PyPI Trusted Publishing (OIDC) only. No long-lived PyPI API token exists anywhere. PEP 740 attestations are produced by the publish action.
- [ ] Post-publish verification from a clean environment: Sigstore attestation verified against the expected repository and workflow identity.
- [ ] GitHub Release artefacts signed. A signed SHA-256SUMS file published. Hashes match the PyPI artefacts.
- [ ] Rule pack: TUF targets, snapshot, and timestamp metadata regenerated. Timestamp expiry at most 7 days, snapshot at most 30 days. Root changes happen only in a key ceremony, signed by the old root and the new root, meeting threshold (root: 2-of-3 offline hardware keys, named holders). Pack manifest carries `pack_version`, `created`, `expires`, `min_tool_version`, per-rule file hashes, and a changelog hash.
- [ ] Downgrade and tamper tests pass: a client on pack N refuses pack N-1 and an expired pack N; a one-byte-changed pack, a wrong-key pack, and a mixed-snapshot pack are all rejected; on any verification failure the tool issues no clean verdict and states the reason in the report.
- [ ] Report test vectors re-run: a valid signed report verifies; a verdict-edited report, a ledger-edited report, and a pack-downgraded report all fail verification.
- [ ] Release notes list bypasses fixed (with EZ-BYPASS IDs), rules added or changed, known limitations, and the metrics update. No silent security fixes, ever.

### Quarterly and per incident

- [ ] Key inventory and rotation drill, including a rehearsed TUF root ceremony.
- [ ] Signature-log monitoring (Rekor) for unexpected signatures under the project identity.
- [ ] Dependency and runner refresh; OpenSSF Scorecard or equivalent reviewed.
- [ ] Restore-from-compromise drill: revoke a targets key, ship a new root, prove clients recover.
- [ ] Emergency revocation path tested in CI, not during the first real incident: new targets metadata removes the bad pack, plus an advisory.

### Rule pack profile (TUF, do not invent a replacement)

- Root: offline, threshold 2-of-3, delegates all trust. Targets: hashes and lengths of every pack file, signed in release CI. Snapshot: one consistent repository state, prevents mix-and-match. Timestamp: short-lived and frequently re-signed, prevents indefinite freeze.
- The client stores the highest pack version it has ever trusted locally and refuses, or refuses to issue a clean verdict on, any regression.
- The validator and updater code is part of the root of trust: minimal, dependency-light, covered by negative tests, and never updatable through the rule-pack channel it validates.

### Signed verdict reports and the public verifier

- Sign a canonical serialisation of the verdict core only: deterministic JSON, sorted keys, explicit schema version. The core covers the sample SHA-256 and size, tool version and build hash, rule-pack version and pack hash, the ledger root hash (a hash chain over evidence entries), the verdict token, the timestamp, and the accounting summary (total bytes versus accounted bytes).
- The verdict token in signed reports, docs, and marketing is one fixed public definition from the format spec (`verdict`: YES or NO, with `reason_class`: PROVEN, UNACCOUNTED, or ACCOUNTED). Ambiguous labels are a forgery and confusion risk.
- LLM narration is never inside the signed core. It ships as an unsigned, clearly labelled appendix whose hash is recorded and which carries no verdict weight.
- Public verification path: `event_zero verify report.json` (plus a small dependency-light standalone verifier) recomputes the sample hash, the ledger hash, and the signature, checks tool and pack versions against TUF metadata, and prints PASS or FAIL plus exactly what was checked.
- Published test vectors: one valid report, one verdict-edited report, one ledger-edited report, one pack-downgraded report. The edited ones must fail.
- Stated limits: a signature proves this report was produced by this tool version and pack for this sample hash and has not changed since signing. It does not prove that a file offered today is the file that was analysed; the verifier must re-hash the actual file. A repacker can always omit a report or ship an unsigned one, so consumers must treat the absence of a verifying signed report as no clean claim.

### Signing stub status: PENDING (not yet implemented)

The cheap first code step toward roadmap item 1 is specified here and deliberately not yet written, because `event_zero/verdict.py` and `event_zero/virt.py` were mid-edit by the verdict builder when this roadmap was added (file timestamps 06:24 and 06:25 UTC, 2026-11-23). Implement it as soon as the verdict builder's work lands, without changing any verdict behaviour:

- New module `event_zero/signing.py`, no changes to existing modules except an optional import in the report writer once that file is stable.
- `verdict_core(report)`: extract exactly the signed fields from a verdict report dict: sample SHA-256, tool version, rule-pack version, ledger root hash, and the verdict token (`verdict` plus `reason_class`).
- `ledger_root_hash(entries)`: SHA-256 hash chain over the canonical JSON of each ledger or evidence entry, in order.
- `canonicalise(core)`: deterministic JSON bytes, sorted keys, no insignificant whitespace, explicit `schema` field.
- `sign_report(report, key=None)`: Ed25519 sign the canonical core using the `cryptography` library. Key material comes only from the environment variable `EZ_SIGNING_KEY` (a PEM or base64-encoded private key), never from a file in the repo, never logged, never written into the report. Returns the report with a `signature` block: algorithm, key fingerprint (SHA-256 of the public key), and the base64 signature.
- `verify_report(report)`: recompute the core and ledger root hash, verify the signature against the public key in the signature block, and return a structured result naming each check.
- Degradation rule: with no `EZ_SIGNING_KEY` set, or the `cryptography` library unavailable, signing returns the report unchanged plus an explicit `signature: {status: "unsigned", note: ...}` entry. An unsigned report is normal for local runs and must never be presented as verified.
- Tests (`tests/test_signing.py`, 2 minimum): (1) round trip, sign a synthetic verdict core with a generated key in the `EZ_SIGNING_KEY` environment variable and verify it passes, then flip the verdict token and verify it fails; (2) degradation, with no key set the output is the unsigned-with-note form and verification reports unsigned rather than passing.

## Adversarial regression suite design

Name and stance: `eventzero-redteam`. Generated, benign, adversarial fixtures. This is the al-khaser pattern inverted: al-khaser bundles anti-analysis tricks to stress a sandbox; this suite generates programs that each try one way to earn an unearned clean verdict.

### Fixture families

Each fixture declares the invariant it attacks and its expected outcome.

1. **Accounting attacks.** Overlay tricks, truncated or overlapping sections, data hidden in padding, certificate tables, or debug directories, appended archives, polyglot files. Expected: unaccounted bytes mean not clean.
2. **Packing and layer attacks.** Known packers, custom stub packers, multi-layer packing, layers that unpack only under a condition (date, filename, arguments, environment). Expected: capability closure across all layers, or not clean when a layer refuses to reveal itself within the stated budget.
3. **Parser differentials.** Malformed headers where two parsers disagree, zero-size and overflowing size fields, entry-point lies. Expected: the disagreement is recorded as evidence; not clean.
4. **Emulation evasions.** Timing loops, RDTSC-style checks, environment probes, sleep-acceleration detection, API sequences that fire only after long or unusual paths. Expected: a trace, or budget exceeded, which means not clean. Timing and environment checks are emulation-robustness tests, not static-rule tests.
5. **Capability splitting.** No single layer or file holds a full capability; the capability emerges only by combination. Expected: cross-layer correlation fires.
6. **Oracle-crafted fixtures.** An automated mutation fuzzer uses the release binary as its oracle: it mutates a flagged sample (section renames, opcode-equivalent substitutions, string encryption, import hiding) while preserving a functionality harness. Any mutant that reaches a clean verdict is auto-filed as a bypass candidate. Its budget and success rate are the published oracle-cost metric.
7. **Report and rule-channel attacks.** Edited reports, downgraded packs, mixed packs, unsigned-rule injection. Expected: verification failure and no clean verdict.
8. **Goodware controls.** Large, legitimately packed, self-extracting, installer and updater style benign programs. Expected: clean only with full accounting. This family measures the false-block rate; a suite that only tests evil teaches the tool to block everything.
9. **Canary fixtures.** The canary set from roadmap item 9. Expected: the `crafted-against-tool` finding behaviour is verified, and no canary alone ever produces a malware verdict.

### Mechanics

- Fixtures are generated from seeds recorded in the repo: same seed, same fixture, deterministic CI.
- Every fixture carries metadata: `id`, `family`, `invariant`, `expected_verdict`, `bypass_id` (when it came from a real bypass), `added_in`.
- The fast subset runs on every pull request. The full suite, including the mutation fuzzer with a fixed budget, runs on release candidates against the release artefacts.
- A suite failure blocks the release.
- A per-release public scoreboard is published: fixtures run, fixtures passed, new bypasses found by the suite itself.
- Real wild samples live in a restricted corpus behind the same harness (hashes plus access-controlled storage, private CI runner), never in the public repo. Where distributing a real sample is unsafe or unlawful, the corpus holds a synthetic non-functional equivalent plus the ledger snapshot.

### Bypass lifecycle and EZ-BYPASS identifiers

- Every confirmed bypass gets an identifier on reproduction: `EZ-BYPASS-YYYY-NNN` (four-digit year, zero-padded sequence within the year, for example `EZ-BYPASS-2026-001`). Identifiers are never reused.
- Lifecycle: report received, reproduced, ID assigned, regression fixture added to the corpus before the fix (test-first), fix shipped in code and/or a signed emergency rule pack, advisory published, post-mortem recorded.
- The advisory states: the ID, affected tool and pack versions, the bypass class, fixed-in versions, remediation, dates, and credit. While active exploitation in the wild is ongoing, the advisory describes the class rather than a turnkey recipe, and timing is coordinated. Fixes are never shipped silently.
- Disclosure follows ISO/IEC 29147 practice: a published policy, a secure reporting channel, acknowledgement and response timelines.
- The corpus is versioned and hashed. No release ships if any historical bypass regresses.

### Metrics, published per release or quarterly

- **Time-to-detect (TTD):** first report of a bypass to confirmed reproduction.
- **Time-to-pack (TTP):** confirmation to a signed fixing pack or release available through TUF.
- **Bypass half-life:** median TTP across bypasses in the period.
- **Regression rate:** historical bypasses re-passing on the latest release. Target zero; any value above zero blocks a release.
- **Oracle cost:** mutations plus wall-time for the internal mutation fuzzer to find a new clean-verdict evasion, per release. The trend should rise.
- **Accounting coverage:** percentage of bytes accounted for across the corpora, and the percentage of samples ending unaccounted or inconclusive. The inconclusive rate is a security metric: pushing samples into inconclusive is a soft bypass, and consumers must treat inconclusive as not clean.
- **Report verification failures** observed in the wild (forgery attempts): counted and disclosed.

## Claims ledger

Wording discipline: one public verdict definition, used identically in signed reports, documentation, and marketing. Strong claims always travel with the ceiling wording below.

### May say (copy-paste, scoped)

1. "Event Zero is deterministic: the same sample (SHA-256), tool version and rule-pack version produce the same evidence ledger and the same verdict."
2. "Event Zero is fail-closed: if any byte of a sample is unaccounted for, or any analysis channel fails or exceeds its stated budget, the sample cannot receive a clean verdict."
3. "A signed Event Zero report proves that the named tool version and rule-pack version produced that verdict for that sample hash, and that the report has not been altered since signing. Verify it with the public verifier."
4. "Rule updates are signed, dated and downgrade-protected using The Update Framework (TUF): clients reject older, expired, tampered or mixed rule packs."
5. "Releases are published via PyPI Trusted Publishing with Sigstore (PEP 740) attestations and are reproducibly built: you can rebuild from source and compare hashes."
6. "Bypassing Event Zero requires defeating [named channels] simultaneously while keeping the sample functional. In our published adversarial suite for version X, the measured cost was [metric]."
7. "Every confirmed bypass is assigned an ID, added to a permanent regression corpus, and disclosed in an advisory. Our median time from confirmed bypass to signed fixing pack for [period] was [X]."
8. "The LLM layer in Event Zero only narrates the deterministic ledger. It has no vote on the verdict, and removing it does not change any verdict."
9. "Event Zero's rules and code are public. Its security does not depend on their secrecy."

A may-say wording may only be used once the control it names has actually shipped and is tested. Until then it is roadmap language and must be labelled as planned.

### Mandatory ceiling wording (must accompany strong claims)

"No tool can detect all malware or all pirated software: perfect detection is mathematically impossible (Cohen). Event Zero will miss some samples, including samples crafted specifically against it. A clean verdict means: this sample's bytes were fully accounted for and matched no rule in this pack version, not that the software is lawful, safe, or original in the world."

### Banned claims (never, in any surface)

- "Bypass-proof", "undetectable-proof", "unhackable", "100% detection", "catches all pirated software", or any equivalent absolute.
- "A clean (NO) verdict proves this software is legitimate, licensed, or not pirated." A clean verdict proves accounting plus no rule match for that sample hash, nothing more.
- "Safe to run." Event Zero analyses; it does not guarantee execution safety.
- Any detection-rate percentage without the corpus, pack version, date, and false-positive rate attached.
- Any claim resting on rule secrecy, on the LLM's judgement, or on an unsigned or unverified report.
- Any claim that a roadmap item above is done before it has shipped, been tested, and been named in release notes.

## Future-proofing notes (supporting the roadmap)

- Rules as data, not code, in a declarative format in the capa and Sigma tradition. The rule schema is versioned separately from the pack; the tool supports the current and previous schema for one release cycle. Rules carry `id`, `version`, `author`, `references`, and false-positive notes. Community rules enter by pull request with CI validation (schema, goodware and malware corpus tests, a precision floor) and maintainer review, and ship only inside signed packs. An explicitly warned unsigned-rule mode exists for researchers and taints the report (`unsigned_rules: true` in the signed core), which removes official status.
- Code-executing plugins are a supply-chain hole: if allowed at all, they run sandboxed, are hash-listed in the report, and cannot vote on the verdict unless signed like rules.
- Emulation backends sit behind a narrow interface (input: layer bytes plus environment profile; output: deterministic trace events in one schema) with a conformance suite gating any swap. Backend name and version are recorded in every report.
- The evidence ledger is schema-versioned, append-only, and hash-chained. Migrations are one-way converters with golden-file tests that must preserve the verdict. Unknown future fields are ignored but preserved. The verdict algorithm is versioned alongside the schema, and the verifier refuses versions it does not know rather than guessing.
- Governance is published: who holds the TUF keys (names, roles, threshold, rotation ceremony notes), who can merge rules (two reviewers, at least one maintainer), and the verdict dispute process. A dispute is filed with a sample hash plus a signed report; maintainers reproduce with the pinned tool and pack; outcomes are upheld, overturned by a new pack (with a bypass or advisory ID), or inconclusive, and are published in a public verdict log keyed by sample hash. A signed report is never edited; it can only be superseded.
