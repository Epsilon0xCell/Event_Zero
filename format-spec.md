# Event Zero Report Format Spec v1

An evidence-anchored plain-language malware report format. Anyone can implement it; Event Zero ships the reference implementation and a validator.

## Principles
1. Layered reading: ELI5 first, plain-English technical second, full evidence third.
2. No claim without evidence: every capability and finding carries an evidence list (import, string, instruction, offset, or hash).
3. Unknowns are a required section, never an omission.
4. External reputation never overrides local evidence.
5. AI wording is optional, gated, and labelled: sentences mentioning facts outside the evidence set are dropped by the gate.

## Required JSON fields
`tool`, `version`, `filename`, `hashes` (md5, sha1, sha256, sha512), `format`, `capabilities[]` (each: id, name, attack_id, technique, explanation, evidence[]), `iocs` (urls, ip_addresses, domains, file_paths), `risk` (score, verdict, reasons), `unknowns[]`, `eli5[]`, `plain_english[]`.

## Optional sections
`unpack`, `firmware`, `rootkit` (phrasing rule: "indicators consistent with", plus a Volatility handoff), `exploit` (must include disclosure_status; zero-day is never certified), `evasion`, `emulation`, `dotnet`, `apk`, `office`, `pdf`, `email`, `pcap`, `timeline`, `enrichment`, `llm` (status: not_configured, ai_assisted, or error), `eli5_metrics` (FRE and FK with the design target labelled as a design target), `generated_yara`, `browser_links` (hash only, never upload links).

## Validator
`event_zero validate <report.json>` exits 0 only when: all required fields exist, every capability and evasion finding has evidence, unknowns and ELI5 are non-empty, and no IP in the plain-English section is absent from evidence. Gold reports live in `examples/gold/` and all pass the validator (verified in VERIFICATION.md).

## Verdict reports (the flagship pirated-software verdict)
A verdict report (`report_type: "verdict"`) answers one question about pirated or cracked software: does it contain malware? It is an accounting verdict, and it fails closed. There are exactly two headlines: `YES: MALWARE FOUND` and `NO: NO MALWARE`. Scores, percentages and probability words are banned from verdict headlines and summaries; the validator rejects them.

Required verdict fields: `headline`, `verdict` (YES or NO), `reason_class` (PROVEN, UNACCOUNTED, or ACCOUNTED), `subject`, `elapsed_seconds`, `pipeline_order`, `files[]` (each: name, path_in_release, sha256, crc32, signed, signature_valid, verdict, why[], capabilities[], claimed_function, scope_test[]), `installer` (is_installer_or_archive, kind, contents[], drop_list[], extracted), `enumeration_aids[]`, `provenance[]`, `diff_ledger[]` (each differing region: file, tag, old_range, new_range, size_change, classification of expected-crack, benign-repack or unaccounted, reason), `yes_reasons[]` (each: file, chain, name, evidence[]), `unaccounted[]`, `next_steps[]`, `eli5[]`, `plain_english[]`, `corroboration`, `proof_standard`.

YES, reason class PROVEN (any one, each citing evidence): a malicious capability chain in context (stealer, injection plus payload, download-and-execute, persistence plus command and control, miner with pool or network, ransomware pattern, backdoor, rootkit hiding); a scope test failure (the scope test is a named rule: the first behaviour unnecessary for a file's claimed function decides YES; network access for a keygen, wallet or browser credential access, antivirus deletion or disabling, Defender exclusions outside the program folder, undisclosed mining); antivirus tampering, Safe Mode registry manipulation, or reboot-count gating (the Crackonosh pattern); a known-bad hash hit with a specific family on record; an unaccounted executable difference from the genuine original that carries a proven malicious chain. An unneeded remote download-and-execute capability is itself malicious class, because the payload it would fetch cannot be accounted for. A VirusTotal count alone is never a verdict: generic HackTool, RiskWare, CrackTool or PUA scatter is the UNACCOUNTED path, and PROVEN from services needs a specific family or family convergence plus locally proven behaviour.

YES, reason class UNACCOUNTED: any byte, file, script, archive layer or behaviour that could not be accounted for as genuine or as the explained crack: an unopened or password-protected inner archive, a virtualized or undecodable region, an unaccounted diff region, an executable inside an installer or archive that is not part of the genuine program, a compiled binary with no reference, no valid signature and no identified crack patch, or a hash that does not equal a reference manifest entry. UNACCOUNTED is labelled plainly as unaccounted, never as proven malware. Internally the state is UNACCOUNTED; the printed headline is YES because the only other headline is NO and NO must be earned.

NO, reason class ACCOUNTED (all required): every file is byte-identical to a genuine signature-valid original (hash match against a genuine reference, or hash equality with a reference manifest: when an SFV or checksum manifest or a reference manifest exists, NO requires hash equality with it), or a fully reverse-engineered difference classified expected-crack or benign-repack in the diff ledger, with all archive layers unpacked to the bottom and installer contents fully listed. A script is fully reverse-engineered by reading all of its source. A single binary with no reference earns NO only when it is fully decoded, its crack patch is identified and explained from the file itself (patched-out code or license markers), and no region is unaccounted. Every NO is phrased exactly as the accounting claim: every byte accounted for as genuine or explained crack, no behaviour beyond genuine plus explained crack observed, manifest linked.

Circumvention itself is not malware: patched license checks, keygen algorithms, KMS emulation, and hosts-file activation blocks are the expected crack. The KMS baseline is exactly: a local emulator service, a renewal task, and GVLK key installation; a verdict judges everything outside that baseline. Antivirus HackTool or CrackTool labels alone never trigger YES.

Provenance: scene groups have no websites, so a release claiming a group site is fraudulent by construction and cannot be accounted for as that group's release; impersonator signals (lookalike domains, hashes mismatched against a canonical post) are recorded as provenance evidence entries. Installer forensics are parser-only: innoextract, 7z NSIS script extraction and MSI table readers are adapters, and installers are never run to see what is inside. A .torrent file list and an .sfv are enumeration aids; an .sfv match proves self-consistency of the release only. NSRL and CIRCL hashlookup presence, and antivirus non-detection, are corroboration only and never a basis for NO; NSRL is queried through a local RDSv3 SQLite set or the CIRCL hashlookup service when configured, under the same environment-key rules as the other services.

## Folder manifest (JSON Lines)
A folder or archive verdict emits a manifest in the `eventzero.manifest/1` schema: a header line (root, limits, cache state), one entry record per file (id, container parent chain joined with `!`, per-stream hashes where detectable, magic, signature status, coverage, per-entry verdict), and a footer (entry count, total bytes, tree SHA-256 over the sorted entry hashes, proof and unaccounted entry ids). Recursion into containers is by magic bytes with explicit depth and expansion limits; hitting a limit marks the entry unaccounted, never clean. Verdict inheritance is exact: any PROVEN entry makes the release YES-PROVEN, else any UNACCOUNTED entry makes it YES-UNACCOUNTED, else NO.

## Connection ledger and behaviour ledger
Every verdict carries a connection ledger: every URL, domain and IP extracted from every file (binaries, scripts, .url and .lnk parsed as pure bytes and never through a shell, .nfo, .torrent parsed locally; a swarm is never joined, because joining would expose the user's IP address). Each entry is tagged by provenance (written-in-file, decrypted-at-runtime, or observed-live) and classified genuine-vendor, known-bad, lookalike, shortener, file-host or unknown. Unknown shortener or lookalike links are needs-more-evidence entries; inside an executable or script they are unaccounted. A .lnk pointing at a living-off-the-land binary with a download cradle is PROVEN. Observed-live entries arrive only through sandbox ingestion (SERVICE/HANDOFF). The behaviour ledger lists static-predicted file, registry, process and persistence effects per file, with the genuine baseline diff applied when a reference is provided.

## Virtualized files
A virtualized file carries a protector census (protector family, VM sections, entry stubs, dispatcher and handler census, encrypted regions) and an entry-stub trace record (API crossings, strings recovered from trace memory). Virtualized functions are unaccounted units, unless trace evidence proves a malicious chain (PROVEN) or the virtualized region is the known crack patch area fully enumerated in the diff ledger. The claims discipline is fixed: the bar is that no sample can obtain a clean verdict by hiding, never an absolute no-escape claim; environment-keyed and server-gated payload content is disclosed on the open list in every census.

## ELI5 rules
Simple words, short sentences, one concrete analogy per capability, banned jargon only with its plain translation in the same sentence, and an analogy break-point note: a picture in words is not exact, real code does more than any one picture can show. Design target (labelled as a design target, not a standard): Flesch Reading Ease at least 80, Flesch-Kincaid grade at most 6.

## Signed verdict core and run receipts (proof for every run)

Every verdict run, and every analyze run, emits a **run receipt** alongside its report. The receipt is the run's proof artifact: anyone can re-check that this tool version and rule pack produced this verdict for this sample, and that the report has not changed since.

### The signed verdict core (`eventzero.verdict-core/1`)
The signature covers exactly these fields and nothing else: `schema`, `sample_sha256`, `sample_size_bytes`, `sample_files`, `tool_version`, `rule_pack_version`, `ledger_root_hash`, `verdict`, `reason_class`, `case_state`. LLM narration is never inside the signed core; when present it is an unsigned, labelled appendix. Canonicalisation is **RFC 8785 (JSON Canonicalization Scheme)**: sorted keys, no insignificant whitespace, minimal escaping, UTF-8. Signed cores contain only strings, integers, booleans, nulls, lists and objects by construction, so the JCS float rules never arise. The signature block carries the **exact signed bytes** (base64, field `signed_bytes`), and the verifier verifies those bytes, never a re-serialisation.

### The ledger root hash
A Merkle tree over the accounted items list (per-file entries with relative path, hash and per-file verdict; one entry per proof, per open item, and per diff region), **RFC 6962 style with leaf and node domain separation**: a leaf is SHA-256(0x00 || canonical JSON of the entry), an interior node is SHA-256(0x01 || left || right), an unpaired leaf is promoted unchanged, and the root of an empty list is the SHA-256 of the empty byte string.

### The run receipt (`eventzero.run-receipt/1`)
Fields: `schema`, `kind` (verdict or analyze), `run_id`, `rule_pack_hash`, `trust_class`, `sample_sha256`, `sample_size_bytes`, `reference` ({sha256, provenance} or null), `ledger_root_hash`, `verdict`, `reason_class`, `case_state`, `tool_version`, `rule_pack_version`, `environment_coverage` (the numeric coverage summary: files total, files emulated, instructions emulated, entry-stub traces, operating-system environments executed), `issued_utc`, and `signature` (status, algorithm, signed bytes, signature, public key, key fingerprint, trust class).

- **run_id is derived, never random**: SHA-256 over the canonical form of {sample hash, reference hash, rule pack hash, tool version}. The same inputs reproduce the same run_id; a proof replayed against a different file, reference, pack, or tool cannot verify, because its run_id and ledger root will not match.
- **Deterministic core**: the signed core excludes volatile fields (wall-clock durations, absolute paths, the manifest creation timestamp), so the same inputs reproduce the same ledger root. The receipt's `issued_utc` timestamp sits outside the signed core for exactly that reason.
- **Trust classes**: every rendered verdict carries a trust class next to the token: `CI-ATTESTED` (produced in CI, covered by a keyless CI attestation), `AUTHOR-SIGNED` (project release key), `SELF-SIGNED` (a local key: proves the report is unchanged since signing, not who signed it), or `UNSIGNED` (carries no endorsement, plainly labelled as such).
- **Keys**: Ed25519 via the `cryptography` library. Key material comes only from the environment variable `EZ_SIGNING_KEY` (PEM or base64 seed). It is never read from a repo file, never logged, and never written into a report; only the public key and its fingerprint (SHA-256 of the raw public key) appear. With no key configured, the receipt and report carry an explicit unsigned signature block; an unsigned artifact is a record, not a proof, and must never be presented as verified.
- **Verification**: `event_zero verify-report <report.json>` recomputes the core and ledger root from the report, verifies the signature over the exact signed bytes, and names each check. It verifies reports, receipts, and verdict reports carrying an embedded receipt.
- **What the proof does and does not establish**: it establishes that the named tool and rule-pack versions produced that verdict token for that sample hash and that the artifact is unchanged since signing. It does not establish that a file offered today is the file that was analysed (the verifier re-hashes the actual file), and it cannot stop a repacker omitting the report or shipping an unsigned one: the absence of a verifying signed report is no clean claim.
- **Attestation predicate domain**: where an in-toto style attestation statement is produced for a run, its predicate domain is a **PLACEHOLDER** (`https://placeholder.invalid/event-zero/`) until the project controls a real domain. It must be presented as a placeholder, never as a final domain.

### Expected-crack classifications are machine-verified
A diff region classified `expected-crack` carries two extra fields: `crack_pattern` (the named pattern it matches: conditional-branch-patch, checksum-or-integrity-fix, wrapper-removal, license-condition-neutralised, license-flag-flip, or key-or-serial-substitution) and `region_capability_check` ({passed, added_capabilities, added_network_indicators}), computed over the enclosing string span of the region in both files. A region that adds any capability, network indicator, or embedded executable the genuine region did not have fails the check and is classified `unaccounted`, however patch-shaped it looks. Context or nearby strings alone classify nothing.

### Environment coverage and the residual pack
Every verdict report carries `environment_coverage`: the numeric coverage summary (files total and statically analysed, files emulated, instructions emulated, entry-stub traces), the environments covered, and the environments **not** covered, listed rather than omitted. Every OPEN case carries a `residual_pack`: the defined human handoff format, a list of items each with file, kind, ranges, evidence, the specific question a human must adjudicate, and the next escalation rung. The analyst is handed only the residual, never the whole file.

## Verdict Revocation List (`eventzero.verdict-revocation-list/1`)

Revocation is a format, not a service. A Verdict Revocation List is a JSON document, signed like a receipt (Ed25519 over the canonical core of {schema, entries}, key only from `EZ_SIGNING_KEY`), with an `entries` list. Each entry:

| Field | Meaning |
|---|---|
| `run_id` | The revoked report's derived run_id (required for level `report`) |
| `level` | One of `report` (a single report), `explanation-type` (all reports relying on the named crack pattern, field `explanation`), `reference` (all reports against the named reference hash, field `reference_sha256`), or `tool-version` (all reports from the named tool version, field `tool_version`) |
| `reason` | Why the verdict is withdrawn, in plain language |
| `ez_bypass_id` | The miss identifier (form EZ-BYPASS-YYYY-NNN) when the revocation arises from a confirmed miss, otherwise null |
| `revoked_utc` | When the revocation was issued |

**Verify behaviour**: `event_zero verify-report <report.json> --vrl <list.json>` checks the report against the supplied list before anything else. A report whose run_id appears in the list (or which matches a broader level) verifies as **REVOKED**: its signature may be genuine, but the verdict is withdrawn and must not be relied on. Revocation is governed by `docs/MISS-AND-REVOCATION-POLICY.md`; confirmed misses are recorded in `docs/MISS-LEDGER.md`. Retention note: GitHub Actions artifacts and logs expire after 90 days, so durable proof copies of verification runs live as Release assets and small in-repo proof files; an Actions artifact is a convenience copy only.
