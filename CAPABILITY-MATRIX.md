# Capability Matrix: the spec sheet

Every row is BUILT (in the core, test-proven), ADAPTER (used when installed, registry), SERVICE (external hash lookup, key from env), or HANDOFF (a link, a plugin list, or a documented next step). Evidence points to the test or run output that proves the row. Anything without evidence would be downgraded to HANDOFF or PLANNED.

| Capability | Kind | Evidence |
|---|---|---|
| ELF, PE, Mach-O parsing, imports explained | BUILT | tests/test_event_zero.py, 14 tests |
| Disassembly (Capstone), call sites | BUILT | test_bundled_macho, test_compiled_elf |
| ASCII, UTF-16, Base64, XOR string decoding | BUILT | test_xor_obfuscated, test_base64_decoded |
| Multi-layer decoding (base64, base64, XOR) | BUILT | tests/test_top.py::test_regression_multilayer_token_in_sentence |
| UPX detection, overlay, embedded binary carving (ez-carver) | BUILT | tests/test_v3.py::test_packed_xor_and_carve |
| RC4 implementation | BUILT | test_rc4_roundtrip |
| Virtualization detection with hard-limit wording | BUILT | unpack.py virtualization section, research-v3.md |
| Firmware magic scan, UEFI FV, DXE carving, red flags | BUILT | test_firmware_uefi, test_firmware_blob_squashfs_gzip, adversarial S5 |
| Rootkit indicators (.sys, .ko, eBPF), "indicators consistent with" | BUILT | test_rootkit_sys, test_rootkit_ko_strings, test_ebpf_detection, test_rootkit_phrasing_and_handoff |
| Rootkit confirmation | HANDOFF | Volatility 3 plugin list in every driver report |
| Shellcode: sled, egghunter, GetPC, decoder stubs (ez-shellcode) | BUILT | test_shellcode_fixture, test_ez_shellcode |
| ROP gadget enumeration | BUILT | test_rop_on_compiled_elf |
| Exploit explainer with disclosure status unknown | BUILT | test_zero_day_never_certified |
| Evasion: direct syscalls with SSN, API hashing, injection chain, hollowing, anti-debug, anti-VM, sandbox, AMSI/ETW | BUILT | test_evasion_fixture |
| Shellcode emulation (Unicorn) | BUILT | emulation.py, installed and importable in the test venv |
| Sandbox dynamic behaviour | HANDOFF plus BUILT ingestion | test_hybrid_sandbox_ingest (CAPE JSON parsing is BUILT, detonation is the user's self-hosted CAPE) |
| .NET detection, IL metadata, ConfuserEx indicators | BUILT | tests/test_final.py::test_dotnet, adversarial S4 |
| Android APK: manifest permissions explained, DEX strings, DEX XOR decoding | BUILT | test_apk, test_regression_apk_dex_xor, adversarial S1 |
| Office: OLE, macros, auto-open, DDE, template injection | BUILT | test_office_macro, test_office_zip_macro, adversarial S2 |
| PDF active features | BUILT | test_pdf |
| Email headers and attachment inventory | BUILT | test_email |
| PCAP quick look (DNS, endpoints, HTTP hosts) | BUILT | test_pcap |
| Kill chain timeline | BUILT | test_timeline |
| YARA generation, Sigma style summary, IOC CSV, STIX 2.1, ATT&CK Navigator | BUILT | test_exports, test_export_cli |
| ELI5 layer with jargon gate, reading metrics, analogy break-point | BUILT | tests/test_v3.py ELI5 tests, test_readability_scores, test_eli5_breakpoint_note |
| Gemini narrative with evidence gate | BUILT | test_gemini_gate_strips_invented_ioc, test_gemini_no_key, test_gemini_key_never_in_report. Live Gemini call: SERVICE, needs the user's key in env |
| ez-capgen draft rules plus corpus promotion gate | BUILT | test_ez_diff_and_capgen, test_capgen_promotion_gate, test_promotion_log_written |
| ez-diff sample comparison | BUILT | test_ez_diff_and_capgen |
| Report format validator and gold reports | BUILT | test_validator_gold_and_bad, examples/gold (3 reports, validator CLI output in VERIFICATION.md) |
| Tool registry with BlackArch mapping (30+ tools) | BUILT | test_tool_registry_shape, `event_zero tools` output |
| Ghidra, capa, FLOSS, radare2, binwalk, unblob, DIE, YARA, Volatility, jadx, oletools, tshark and others | ADAPTER | registry auto-detection, tests only assert registry shape and graceful absence |
| VirusTotal, Hybrid Analysis | SERVICE | test_vt_mock, services tests with mocks |
| MalwareBazaar, ThreatFox, URLhaus (abuse.ch Auth-Key) | SERVICE | test_abusech_needs_key, test_abusech_with_key_mock |
| urlscan, OTX, MetaDefender, filescan, tria.ge | SERVICE | enrich consensus and no-key tests in tests/test_v3.py |
| ANY.RUN, Joe Sandbox, Koodous, Intezer, CyberChef, dogbolt, UnpacMe | HANDOFF | browser_links test: hash-only links, no upload links generated |
| FLAGSHIP verdict (The Verdict): YES / NO accounting verdict on pirated software (file, installer, archive, release folder) | BUILT | tests/test_verdict.py, 19 tests; examples/fake_malware.verdict.txt (YES PROVEN), examples/clean_crack.verdict.txt (NO ACCOUNTED) |
| Verdict reason classes PROVEN / UNACCOUNTED with fail-closed accounting, diff ledger (expected-crack / benign-repack / unaccounted), reference manifest hash equality | BUILT | test_no_benign_patched_with_reference, test_reference_manifest_equality, test_yes_unaccounted_unexplained_diff |
| The Verdict, per-family proof rules: stealer (config atoms, DPAPI and SQLite theft chain), RAT dispatcher, ransomware (crypto loop plus 2 of note, shadow deletion, key material), miner (pool plus wallet plus concealment; presence alone is not proof), loader (injection, dead-drop, server-keyed), botnet and DDoS, rootkit and bootkit, keylogger and screencap (capture alone is not proof), banking (target list dispositive in code-bearing files), proxy and traffic-selling (consent, beneficiary, visibility test), adware grey zone (disclosed PUP versus hijacker), PPI (affiliate ID plus install callback), Cobalt Strike beacon TLV config parsing (XOR 0x69 and 0x2e, padding-tolerant), wiper, logic bomb (gated opaque arm), fileless registry blobs, malicious scripts (per-line ledger against the KMS allowlist), DLL sideload triad, each with its FP-twin discriminator | BUILT | tests/test_families.py (34 tests: PROVEN and FP-twin pairs for the highest-risk families, verdict-level coverage for the rest); the every-family verification corpus PASS in VERIFICATION-VERDICT.md (37 of 37, 0 false NO) |
| Expected-crack classifications machine-verified: named crack patterns (conditional-branch-patch, checksum-or-integrity-fix, wrapper-removal, license-condition-neutralised, license-flag-flip, key-or-serial-substitution) plus a region capability check on the region's own bytes; a payload planted in a patch-shaped region fails to UNACCOUNTED, never NO | BUILT | tests/test_diff_verification.py (URL-swap regression, capability-atom region, genuine branch patch); audit outcome in VERIFICATION-VERDICT.md |
| Case lifecycle state OPEN (not a verdict), escalation ladder rungs 0 to 7 as the OPEN work list, residual pack as the human handoff format, environment coverage stated as a number in every report and receipt | BUILT | tests/test_families.py case-state tests, tests/test_diff_verification.py residual pack and coverage tests; format-spec.md |
| Signed reports and run receipts: RFC 8785 canonical verdict core, RFC 6962 Merkle ledger root with domain separation, derived run_id, Ed25519 via EZ_SIGNING_KEY only, trust classes (CI-ATTESTED, AUTHOR-SIGNED, SELF-SIGNED, UNSIGNED), unsigned-with-note degradation, `event_zero verify-report` | BUILT | tests/test_signing.py (round trip, tamper fails, unsigned degradation, deterministic ledger root, swapped-hash receipt fails, CLI verify) |
| Verdict Revocation List (format, not a service): signed list, levels report / explanation-type / reference / tool-version, EZ-BYPASS identifiers; a listed report verifies as REVOKED | BUILT | tests/test_signing.py::test_revocation_list; format-spec.md; docs/MISS-AND-REVOCATION-POLICY.md; docs/MISS-LEDGER.md |
| Every-family verification corpus and cloud verification: 37-entry synthetic corpus with independent scorer, GitHub Actions workflow (three-OS test suite; corpus in a network-disabled container with egress canary and determinism gate; run proof in the job summary), Colab reproduction notebook, Kaggle results-only mirror | BUILT | fixtures/verification/ (build_corpus.py, run_verification.py, results in results.json and results_table.md); .github/workflows/verify.yml; notebooks/; local no-egress proof run recorded in VERIFICATION-VERDICT.md (Actions itself runs after a push) |
| The scope test (first behaviour unnecessary for the claimed function decides YES), KMS baseline, AV tampering / Safe Mode / reboot-gating (Crackonosh class) | BUILT | test_yes_keygen_scope_test_network, test_yes_av_tampering_proven, test_yes_reboot_gating_and_safe_mode, test_kms_baseline_expected |
| Provenance checks (scene-group site claim is fraudulent by construction) | BUILT | test_provenance_scene_group_site |
| Folder manifest as JSON Lines (header, per-entry container parent chain, per-stream hashes, footer tree hash), verdict inheritance PROVEN over UNACCOUNTED over NO | BUILT | tests/test_folder_link.py::test_manifest_jsonl_shape, test_archive_inside_archive_payload_found; examples/*.manifest.jsonl |
| Connection ledger (written-in-file and decrypted-at-runtime provenance, classified genuine-vendor / known-bad / lookalike / shortener / file-host / unknown), .url and .lnk parsed as pure bytes, .lnk LOLBin download cradle is PROVEN, .torrent parsed locally (swarm never joined) | BUILT | test_url_and_lnk_ledger_entries, test_torrent_ledger_entries |
| Behaviour ledger (static-predicted effects) with genuine baseline diff when a reference is provided | BUILT | verdict.behaviour_ledger and behaviour_baseline_diff in every verdict report; folder tests |
| Observed-live connection and behaviour entries (sandbox detonation) | SERVICE / HANDOFF | CAPE ingestion is BUILT (test_hybrid_sandbox_ingest); detonation itself is the user's self-hosted CAPE, never run by Event Zero on the host |
| Devirtualization: protector identification, handler census, entry stub census, encrypted region map | BUILT | tests/test_virt.py::test_virt_census; event_zero/virt.py |
| Devirtualization: Unicorn entry-stub trace with API crossings and decrypted strings recovered from trace memory as accounted evidence | BUILT | test_virt_trace_harness, test_virt_verdict_unaccounted |
| Devirtualization: handler semantics pass (Triton symbolic execution over handler clusters, opcode semantics table, targeted devirtualization with NoVmp-class tools) | ADAPTER / HANDOFF | Documented in virt.py and the devirtualization research claims ledger; not implemented in this build, and no verdict depends on it: virtualized units stay UNACCOUNTED until census, trace, or sandbox evidence accounts for them |
| NSRL / CIRCL hashlookup corroboration | HANDOFF | Corroboration only by design, never a NO basis; documented in format-spec.md and every verdict's corroboration field |
