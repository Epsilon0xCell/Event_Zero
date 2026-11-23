# Event Zero: Miss Handling, Bypass Disclosure and Verdict Revocation Policy v1.0

This policy governs The Verdict, Event Zero's verdict feature. It is adopted from the project's reputation research (2026-11-23) and is binding on every release. The one-sentence summary: a miss cannot be promised away, but a miss can be made unable to stay silent, unable to stay issued, and unable to happen the same way twice.

**1. Definitions.** A *Miss* is a confirmed case in which Event Zero issued a verdict of NO for a file that was in fact malicious, or in which a NO relied on an explanation, reference, or coverage assertion that was wrong. A *Bypass* is a demonstrated method of obtaining a false NO. Each confirmed Miss or Bypass receives an identifier of the form EZ-BYPASS-YYYY-NNN, which is never reused.

**2. Reporting.** Reports may be submitted at [PLACEHOLDER: reporting URL or email, and PGP key, to be filled when the project publishes its security contact]. Good-faith research under this policy is authorised and will not be pursued legally. Anonymous reports are accepted; credit is given only with consent.

**3. Acknowledgement and triage.** We will acknowledge every report within **one business day** and assign a tracking identifier. We will communicate a triage outcome (confirmed / not reproduced / duplicate / out of scope, with reasons) to the reporter within **five business days** of acknowledgement.

**4. Revocation before root cause.** Upon confirmation of a Miss, we will revoke every affected verdict **on the same day as confirmation**, by entry in the signed Verdict Revocation List and a signed revocation notice, before root-cause analysis is complete. Revocation will not be delayed pending a fix.

**5. Notification.** On the day of revocation we will (a) publish the revocation notice, (b) directly notify all registered holders of affected reports, and (c) update the public Miss Ledger. If the number of affected reports is not yet known, we will state that it is unknown and state the method and upper bound by which we are determining it. We will not publish an affected count we may have to revise upward without labelling it a lower bound.

**6. Public ledger.** Within **seven calendar days** of confirmation we will publish a Miss Ledger entry stating: the EZ-BYPASS identifier; dates of report, confirmation, and revocation; affected tool, test-suite, and corpus versions; the rule identifying affected reports; the residual-path classification, or a statement that a new path has been identified; and current status. The Ledger is append-only and signed. Entries are never deleted or edited except by appended correction.

**7. Post-incident note.** Within **fourteen calendar days** of confirmation we will publish a post-incident note describing what happened, which control failed, and what interim mitigations are in force (including any revocation of an explanation type, reference, or tool version).

**8. Fix and regression fixture.** Every confirmed Miss becomes a permanent fixture in the adversarial test suite. We target a fix within **thirty calendar days** of confirmation. If that target will be missed, we will update the Ledger entry on or before the target date, stating why and the revised target. **No fix for a confirmed Miss will be released without its EZ-BYPASS identifier in the release notes. There are no silent fixes.**

**9. Release gating.** No release will be signed unless it passes (a) the full adversarial suite, including every fixture arising from a confirmed Miss, and (b) the seeded canary set for that release. Canary pass and fail counts are published with each release.

**10. Scope of revocation.** Revocation may apply to a single report, to all reports relying on a specified explanation type, to all reports against a specified reference, or to all reports issued by a specified tool version. The level applied will be stated in the revocation notice.

**11. Verdict status.** A NO verdict is a statement as of its issue date, tool and suite versions, and the Verdict Revocation List version cited in it. Holders should re-check reports against the current List. A report whose revocation status cannot be checked against a current List must be treated as STALE, not as a current NO.

**12. Human override.** No person may override Event Zero to issue a NO. A person may downgrade any verdict to OPEN or YES. Overrides are logged, and counts per release are published.

**13. Policy changes.** Changes to this policy apply prospectively, are versioned, and are announced at least 30 days before taking effect, except changes that increase disclosure speed or scope, which may take effect immediately.

## Related documents

- The public Miss Ledger: `docs/MISS-LEDGER.md` (append-only).
- The Verdict Revocation List format: `format-spec.md`, section on revocation.
- The guarantee wording this policy backs: `README.md`, section "What Event Zero guarantees, and what it does not".
