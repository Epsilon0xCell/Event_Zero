# Progress
- Wave 1: copied v2 (live at GitHub 79186d4), read analyzer, report, capabilities.
- Wave 2: built unpack, firmware, rootkit, exploit, evasion, emulation modules; integrated sections 13 to 17; v2 tests still 14 passed.
- Wave 3: Gemini provider with evidence gate, ELI5 layered generator with jargon and reading gates; report section 0 and 19.
- Wave 4: hybrid ingestion, external and services enrichment (10 services), tool registry with BlackArch mapping, ez-carver, ez-shellcode, ez-eli5, ez-capgen, ez-diff; CLI subcommands.
- Wave 5: format analyzers (.NET, APK, Office, PDF, email), exports (YARA, Sigma style, CSV, STIX, Navigator), timeline, PCAP; sections 20 to 22.
- Wave 6: adversarial sweep, 5 surprise fixtures cold, 2 misses found and fixed with regression tests, 1 limitation labelled (per-driver firmware verdicts).
- Wave 7: self-improvement promotion gate, public benchmark, ELI5 metrics.
- Wave 8: deep research corrections: abuse.ch Auth-Key, VirusTotal limits, sandbox publication warning, rootkit phrasing, zero-day rule, VMProtect hard limit, format-spec.md plus validator plus 3 gold reports, FRE and FK design target.
- Final: 64 passed in a clean venv. Not pushed. See PUSH-PLAN-V3.md.

- 2026-11-23 22:52 CST: abuse.ch account created under Epsilon0xCell (GitHub sign-in, email verified). Free Auth-Key obtained by the founder on his phone (Turnstile blocks the cloud browser, including in-person takeover). Key PROVEN live against mb-api.abuse.ch: get_recent returned query_status ok with real entries. Key value is held by the founder only; it is not stored in this repo or any workspace file. Clients read it from the ABUSECH_API_KEY environment variable.
