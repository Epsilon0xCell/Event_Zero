# Security policy

## What Event Zero is

Event Zero is a defensive malware-analysis tool. It statically analyses suspicious files and, through The Verdict, issues an accounting verdict (YES or NO, with OPEN as the fail-closed case state) for pirated or cracked software. Samples are never executed on the host.

## The verification corpus is synthetic

The fixtures under `fixtures/verification/` and in `tests/` are synthetic and disarmed by construction: proof atoms carried as data, network atoms restricted to `.invalid` names and TEST-NET addresses (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24), miner pools at lab addresses, crypto atoms acting only on sacrificial lab text, and headers neutralised where applicable. No live malware is included in this repository, downloaded by it, or executed by any test, notebook, or workflow. The GitHub Actions verification workflow runs the corpus inside a network-disabled container with an egress canary, so the corpus run makes no outbound network use by design.

## Reporting a vulnerability or a missed verdict

- Security issues in Event Zero itself, and reports of a wrong verdict (a Miss or a Bypass), are handled under the project's Miss Handling, Bypass Disclosure and Verdict Revocation Policy: see `docs/MISS-AND-REVOCATION-POLICY.md`. Good-faith research under that policy is authorised. Confirmed misses are recorded publicly in `docs/MISS-LEDGER.md`, receive an EZ-BYPASS identifier, trigger same-day revocation of affected verdicts, and become permanent regression fixtures. There are no silent fixes.
- Until the project publishes its security contact, reports can be opened as GitHub issues on this repository for non-sensitive matters; sensitive reports should wait for the published contact in the policy document rather than posting exploit detail publicly.

## Supported versions

Only the current release line is supported. Verdict reports name their tool version and rule-pack version, and the Verdict Revocation List (format in `format-spec.md`) is the mechanism by which already-issued reports are withdrawn.
