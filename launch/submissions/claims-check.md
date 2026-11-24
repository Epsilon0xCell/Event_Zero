# Claims Check: Submission Drafts

Checked: 2026-11-23.
Files checked: fmhy-submission.md, rpiracy-wiki-listing.md, rpiracy-post-modmail.md, READINESS.md (this folder).
Standard applied: the README claims ledger discipline (launch/CLAIMS-LEDGER.md and the guarantee section of README.md). Every claim in a draft must trace to the README, an example report in examples/, the capability matrix, or a verified route fact about FMHY or r/piracy. Process claims and scoped numbers only.

## 1. Banned wording scan

Searched all four drafts for the banned set and close variants: "never misses", "100% detection", "100% accurate", "guaranteed", "guarantee" used as a promise, "bypass-proof", "miss-proof", "detects all", "complete protection", "safe" used as a verdict on files generally, "revolutionary", "ultimate", "perfect".

Result: none present as claims about Event Zero. The words "guarantee" and "safe" appear only in negated or scoped contexts (for example "does not guess a clean result", "the headline stays on the safe side", which describes the fail-closed direction, not a safety promise). The 100% figure does not appear anywhere in the drafts.

## 2. Claim by claim trace

| Draft claim | Source |
|---|---|
| Verdict gives a proof-backed YES or NO on any file you download | README.md, The Verdict section; CAPABILITY-MATRIX.md verdict row, BUILT |
| NO issued only when every byte is accounted for as genuine or explained crack | README.md scope sentence, quoted from examples/clean_crack.verdict.txt |
| Anything unaccounted blocks the NO and stays an open case | README.md Verdict rules; examples and verdict reason classes PROVEN and UNACCOUNTED |
| The crack itself is not malware: patched licence check, keygen, KMS emulation are the expected crack | README.md Verdict rules; examples/fake_malware.verdict.txt section 8 standard text |
| The sample is read as bytes and never executed | README.md Safety section; examples/fake_malware.verdict.txt closing line |
| Works offline, no account, no API key for the core; optional hash lookups off by default and hash-first | README.md Safety and enrichment sections |
| Case 001 headline YES: MALWARE FOUND, reason class PROVEN, chains: credential stealer, persistence plus a remote host, cryptocurrency miner | examples/fake_malware.verdict.txt sections 1, 2 and 5 |
| Clean crack example earned NO: NO MALWARE, reason class ACCOUNTED, 3 diff regions all expected-crack | examples/clean_crack.verdict.txt, as quoted in README.md |
| Demo video about 111 seconds, real terminal runs, no staged output | demo/SCRIPT.md |
| Verification corpus 37 purpose-built fixtures, 37 of 37, independent scorer re-reads fixture bytes | README.md Verification section; VERIFICATION-VERDICT.md. Used only in fmhy-submission.md section 6, framed as the project's own corpus, not as an accuracy rate |
| Pilot 1,000 of 1,000 on a corpus from 68 independent clusters, labelled a development instrument, not a generalisation measurement | README.md Verification section; validation/PILOT-REPORT.md. Same restricted use as above |
| Python 3.10 or newer | README.md badge and pyproject.toml, as stated in README.md |
| Licence CC BY-NC 4.0, not an OSI open source licence | README.md License section and licence badge |
| FMHY route facts (issue preferred over PR, Discord link testing for all additions, exclusion list, entry format examples) | fmhy.net/other/contributing and fmhy.net/privacy, read 2026-11-23; fmhy/edit repo root and docs listing, read 2026-11-23 |
| r/piracy route facts (moderator maintained wiki, Tools page exists, rule 2 covers blatant self-promotion) | April 2021 megathread Tools page copy held in the project research archive; current third-party wiki guides read 2026-11-23. Flagged in the wiki draft itself as not re-read live, with a pre-send live read required in READINESS.md |

## 3. Numbers discipline

- No number appears in the FMHY entry line, the wiki entry text, or either modmail. Numbers appear only in fmhy-submission.md section 6 (the honest gaps note for our own use, not sent to FMHY) and in this check, each with its corpus and scope attached.
- No scenario figures from the README Global Defence Initiative section are used in any draft. They are scenario modelling for the README's own argument and would read as impact claims in a listing context.
- No infection, prevalence, or piracy statistics are used in any draft.

## 4. Tone check

- Both modmails declare the author's interest in the first lines, offer to accept refusal or conditions, and contain no hype adjectives, no comparisons against other tools, and no urgency.
- The FMHY drafts say "free" and "the source is public" rather than "open source", because the licence is CC BY-NC 4.0. See fmhy-submission.md section 6, item 3.

## 5. Mechanical checks

- Em dash character (U+2014) count across all five files in this folder: grep on 2026-11-23 returned 0 in every file.
- Legal surname: grep for the legal surname across all five files returned 0 in every file.
- Banned phrase grep across the submission drafts themselves (excluding this check file, which lists the phrases in order to ban them): no matches. Author identity in drafts is the GitHub handle Epsilon0xCell only; the drafts do not name the author at all beyond "I am the author".
- No draft contains an instruction to post, submit, or send. Every file carries a DRAFT ONLY status line.
