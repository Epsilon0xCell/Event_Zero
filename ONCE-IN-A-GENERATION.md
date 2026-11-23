# Once in a Generation: the thesis, stated as narrowly as the evidence supports

## The claim
As of the research dated 2026-11-23, no known free tool combines, in one offline CLI: (1) evidence fusion across static, emulation, firmware, kernel, exploit and evasion analysis, (2) an anti-hallucination gate that drops AI sentences mentioning facts outside the evidence set, (3) an ELI5 translation layer with a jargon gate and reading metrics, and (4) defence generation (YARA, IOC CSV, STIX 2.1, ATT&CK Navigator) from the same evidence, plus (5) an open report format spec with a validator that checks every claim carries evidence.

That is the whole claim. It is a combination claim, not a claim that any single engine inside Event Zero beats Ghidra, capa, FLOSS or CAPE at their own job. They are better engines; Event Zero is the fusion, translation and verification layer, and it uses them as adapters when they are installed.

## Evidence
- 141 passing tests (VERIFICATION.md) covering every module in the claim, plus the 37-entry every-family verification corpus PASS with zero false NO (VERIFICATION-VERDICT.md).
- The Gemini gate test proves an invented IP address is stripped and a real one kept.
- The validator passes on three gold reports and fails on a report with an evidence-free capability.
- The adversarial sweep found two real misses cold; both were fixed and are regression tests now.

## What would falsify the claim
- A free tool, available before 2026-11-23, that does all five parts in one offline CLI. Naming one falsifies the first-of-kind claim and this file will be corrected.
- A gold report that fails the validator, or a report whose plain-English section mentions a fact with no evidence behind it.
- An ELI5 section that scores below the labelled design target while claiming to meet it.

## The flagship: an accounting verdict for pirated software
The verdict feature (`event_zero verdict`) is the sharpest expression of the thesis. Every other tool answers "does this look bad" with a score. Event Zero answers "is there malware in this crack" with an accounting: every byte of the release is genuine, expected-crack, benign-repack, proven malicious, or unaccounted, and the headline follows the accounting exactly. YES-PROVEN when malicious behaviour is proven (capability chains, the scope test, Crackonosh-class tampering, known-bad families). YES-UNACCOUNTED when anything cannot be accounted for, labelled plainly as unaccounted. NO only when the accounting is complete, phrased as the accounting claim itself, with the JSON Lines manifest as the linked evidence.

Three design decisions make it defensible where a scanner-style binary verdict is not:
1. Circumvention is defined out of malware (patched checks, keygens, KMS emulation are the expected crack), so YES means harm beyond the crack, and the scope test (first behaviour unnecessary for the claimed function) is the rule that finds it.
2. Fail-closed is a feature, not a failure: a virtualized region, an unopened archive layer, or an unaccounted diff region can never be laundered into a NO. The achievable bar, stated in the product, is that no sample can obtain a clean verdict by hiding.
3. Corroboration is demoted to its correct rank: NSRL presence, antivirus non-detection and VirusTotal counts never decide anything. A specific family on record, or behaviour proven in the bytes, decides.

What would falsify this claim: a trojaned synthetic crack in the test corpus that receives NO, or a clean crack whose unaccounted items cannot be named in its own report.

## The guarantee, as a claims ledger entry

The guarantee wording lives in the README ("What Event Zero guarantees, and what it does not") and is backed by docs/MISS-AND-REVOCATION-POLICY.md and the public, append-only docs/MISS-LEDGER.md. The claim is the accounting and the process, never omniscience: Event Zero does not promise that no malware can ever evade analysis. It guarantees that a NO means complete, machine-checked accounting with the receipt in the holder's hands; that incomplete accounting is OPEN, not NO; and that a confirmed miss is disclosed publicly, revoked with a signed notice under its EZ-BYPASS identifier, and added permanently to the regression suite. Banned as product claims across all project copy: "never misses", any detection percentage presented as a detection claim, "guaranteed clean", "miss-proof", "unbypassable", "zero false negatives". Approved scoped forms only: proof-backed, validator-checkable, complete accounting, and the process claim that 100% of issued verdicts are proof-backed.

## The self-improvement loop
ez-capgen drafts a rule from repeated unknown patterns. The promotion gate validates the draft against the corpus: it must fire on a malicious sample and on zero benign samples. Promotions are logged. The tool gets smarter from each new sample type only through that gate, never automatically into scoring without a logged promotion and a test.

## Public benchmark
Methodology and scores are in VERIFICATION.md: a reference set built from public test files (EICAR, the bundled public sample) and the documented synthetic corpus in tests/. Anyone can rerun it: clone, create the venv, run pytest, run the analyzers on the fixtures, compare. The numbers are small and honest, not a leaderboard claim.
