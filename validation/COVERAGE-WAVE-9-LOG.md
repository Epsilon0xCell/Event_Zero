# Coverage Wave 9 Log: Capability Evidence Backed by capa, Pinned and Hashed Dependencies

Date: 2026-11-25. Source spec:
`~/workspace/research_notes/event-zero-next-frontier-20261124/report.md`,
item 9, with the companion rule from the same item (every tool
and corpus in the analysis pipeline pinned by version and hash)
and the governing constraint from
`~/workspace/research_notes/event-zero-accuracy-failure-modes-20261124-2226/report.md`:
capa reports capabilities, not verdicts. A capa hit is evidence
to be weighed, never a verdict, and capa silence contributes
zero clean evidence. Suite: 447 baseline plus new tests in
`tests/test_coverage_wave9.py` (full-suite counts, in this
environment's venv and in a fresh venv built from the pinned
set, in the closing section).

## Part A: current-state audit (recorded before any change)

### The capability interface and its call sites

- `event_zero/capabilities.py` holds 49 authored rules and one
  matcher, `match_capabilities(imports, strings, mnemonics,
  script_text="")`. Matching is deterministic; each fired rule
  returns {id, name, attack_id, tactic, technique, evidence,
  explanation} with the observed evidence strings carried.
- Call sites:
  1. `analyzer.py` (main per-file analysis): imports plus
     format symbols, all strings (plus the XOR-decoded marker),
     disassembly mnemonics, script source. The output feeds the
     analyzer risk score (weights keyed by authored rule ids),
     `report["capabilities"]`, and every downstream consumer.
  2. `analyzer.py` (second pass): the matcher runs again over
     the unpack module's multi-layer decoded texts; new rule
     ids are merged into the same list.
  3. `verdict.py` `_region_profile`: capability ids over a diff
     region's strings, for diff accounting.
  4. `verdict.py` (virtualized-trace path): a capability set
     over Unicorn-trace recovered strings, fed to
     `malicious_chains` for trace chains.
- Verdict consumption is keyed strictly on authored rule ids:
  `malicious_chains` and the claimed-function logic look up
  specific ids (the NET_CAPS set, cred-access, and so on);
  `rec["capabilities"]` records the id list per file;
  `classify_diff` compares capability id sets between a genuine
  reference analysis and the patched file's analysis, both
  produced by this same pipeline. Any new evidence source whose
  ids cannot collide with authored ids cannot form, break, or
  reweight a chain by construction.
- Consumers of a capability entry touch exactly: id, name,
  attack_id (string; `exports.py` lowercases it), tactic,
  technique, evidence (list of strings), explanation. Any
  merged entry must carry the full shape.

### Runtime dependency inventory (imports across event_zero/)

Third-party imports, all of them lazy (imported inside
functions, so a missing package degrades one feature, not the
engine), except as noted:

- lief: `analyzer.py`, `coverage3.py` (dual-parser gate).
  Declared core.
- capstone: `disasm.py`, `exploit.py`. Declared core.
- pefile: `coverage3.py`. Declared core.
- pyelftools: declared in `requirements.txt` and
  `pyproject.toml`, installed, and imported nowhere in
  `event_zero/` or `tests/` (grep: zero hits). Declared but
  unused. It stays in the pinned set (removing a declared
  dependency is a separate decision) and is named here so the
  fact is on record.
- unicorn: `emulation.py`, `virt.py` (shellcode emulation,
  virtualized-trace). Optional (`full` extra).
- cryptography: the report-signing paths. Optional (`full`).
- google-genai: `llm.py` (Gemini narrative). Optional
  (`full`). Not installed in this environment's venv; the
  narrative layer degrades with a named note, as designed.
- pyzipper: not used by `event_zero/` at all; used by the
  campaign tooling (`validation/campaign/run_shard.py`,
  `analyze_shard.py`) and installed ad hoc by the campaign
  workflow only.
- Everything else is the standard library.

### Installed versions in this environment (~/ezpush-venv, Python 3.12.3)

lief 1.0.0, capstone 5.0.9, pefile 2024.8.26, pyelftools 0.33,
unicorn 2.1.4, cryptography 50.0.2, pytest 9.2.0 (plus
pytest's own: iniconfig 2.3.1, packaging 26.4, pluggy 1.7.0,
Pygments 2.21.0; and cryptography's: cffi 2.1.1, pycparser
3.12). Note the gap the audit exists to close: the declared
floor for lief is `>=0.14` while what actually ran the suite
is 1.0.0; nothing in the repo recorded that.

### How requirements were declared

- `requirements.txt`: four lower bounds (lief, capstone,
  pefile, pyelftools), no pins, no hashes; the optional set
  named in a comment, also unpinned.
- `pyproject.toml`: the same lower bounds as project
  dependencies; `full` and `dev` extras as lower bounds.
- Workflows (all Python 3.12): `tests.yml` runs
  `pip install -r requirements.txt pytest unicorn`;
  `verify.yml` adds cryptography; `campaign.yml` adds
  pyzipper, unicorn, cryptography. Every ad hoc addition
  unpinned and unhashed. No hash appears anywhere in the
  install path.

### capa feasibility, probed in a scratch venv

- PyPI is reachable from this environment. flare-capa latest
  is 10.0.0; 9.4.0 (the spec's floor: "capa v9.4.0 and later")
  installs cleanly: 55 packages, about 188 MB of venv,
  including vivisect 1.3.2 (the pure-Python backend), dnfile
  and dncil (.NET routing), pydantic, networkx. No version
  conflicts with the engine's installed set (pefile and
  pyelftools resolve to the same versions already in use).
- The wheel does NOT bundle the rules corpus or the FLIRT
  signatures. Rules live in the separate mandiant/capa-rules
  repository. Pin used by this wave: tag v9.4.0, commit
  2af9fbfc1c9b4634dbeb76b5d34fca9389fa7f80, archive SHA-256
  273591b11737181b3bdaac18964f23627cf10c21c2b143fc9be88e4a33217669,
  1045 rule files, 1667 rules across scopes, 378 of them lib
  rules (library identification, not capabilities).
- Live probe on `fixtures/hello_elf`, vivisect backend, no
  FLIRT signatures: rules load in 16.8 s (a per-process cost,
  paid once), analysis in 2.9 s; matches returned with rule
  scope (file, function, basic block, instruction) recorded
  per rule; parsed rule meta carries MBC references and
  namespace, with ATT&CK mappings sparse (the failure-modes
  report's contested-coverage point, confirmed locally).
- capa's rules loader defaults to a pickle-based ruleset cache
  (`capa/rules/cache.py`). The spec's companion rule names
  exactly this shape (the capa v10 pickle lesson): a component
  that deserializes untrusted structures is a pipeline
  finding. The integration therefore loads rules with the
  cache disabled and never reads or writes a ruleset pickle.
- Ghidra backend assessment: capa 9.4.0 exposes a ghidra
  backend via PyGhidra. It needs a Ghidra installation and a
  JVM; neither is present in this environment (`java` and
  `ghidra` are not on PATH), and installing Ghidra is a
  deployment decision outside this wave. The adapter takes
  its backend from configuration (environment
  `EZ_CAPA_BACKEND`, default `vivisect`), and the ghidra
  backend name passes through the same code path, so adopting
  it later is a configuration change, not a rebuild. The
  vivisect backend is the one verified here.

## Part B: what was built

Decision on the audit's evidence: capa IS installable here
(PyPI reachable, 9.4.0 clean, live run verified), so this wave
builds the real integration, not only the seam. The seam
exists anyway, as the adapter's runner function, and the tests
use it for determinism; the production path runs real capa.

- `event_zero/capa_evidence.py` (new): the adapter.
  - `capa_capabilities(path, fmt, data)` never raises. It
    returns capability entries plus a status dict that lands
    on the analyzer report and the verdict's file record:
    status (ok, unavailable, failed, skipped), a named note,
    the capa version, the rules corpus identification, the
    backend, and the match count. A failure is therefore
    always named on the record; there is no silent path.
  - Scope: PE and ELF inputs only, files up to 32 MiB, a
    30-second per-file evidence budget (SIGALRM on the main
    thread), backend `vivisect` by default
    (`EZ_CAPA_BACKEND` overrides; `ghidra` passes through the
    same path when a deployment provides Ghidra and a JVM).
  - Rules: resolved from `EZ_CAPA_RULES`, then a vendored
    `tools/capa-rules`, then
    `~/.cache/event-zero/capa-rules-9.4.0`. Loaded once per
    process (the 16.8 s probe cost is per-process, not
    per-file), with capa's pickle ruleset cache disabled
    (`enable_cache=False`): the engine never reads or writes
    a ruleset pickle, which is the spec companion rule applied
    to our own pipeline. Results are memoised per file
    SHA-256 within the process (a repeat analysis of the same
    bytes measured at 0.2 s against 16.5 s cold).
  - Entry shaping: matches collapse by base rule name
    (subscope instances, whose names carry a /<hash> suffix,
    sum their locations into the base rule); lib rules are
    skipped (library identification is not a capability);
    each entry carries the full consumer shape (id, name,
    attack_id, tactic, technique, evidence, explanation) plus
    source ("capa"), rule_id, and the rule's scope (file,
    function, basic block, instruction), because the
    failure-modes research is explicit that a capa hit must be
    weighed with its scope. Ids are `capa:<slug>`, disjoint
    from every authored id.
  - Degradation semantics: package missing, rules missing,
    EZ_CAPA=0, unsupported format, oversized file, timeout,
    and any capa exception each produce their named status and
    zero entries. None of them adds a blocker or a cap
    anywhere: a missing optional evidence source is not
    unaccounted content.
- `event_zero/capabilities.py`: authored entries now carry
  `"source": "event-zero"`, so every capability in a report
  names its source (own matcher vs capa rule id) in the same
  field.
- `event_zero/analyzer.py`: after the decoded-layer merge
  (after risk scoring, deliberately: capa evidence can
  neither raise nor lower the analyzer's own risk verdict),
  PE and ELF inputs run the adapter and merge its entries via
  `merge_capabilities`; the status lands as `report["capa"]`.
  The other three matcher call sites stay own-matcher only,
  by scope: capa runs on whole PE/ELF files, not on decoded
  text layers, diff regions, or trace strings.
- `event_zero/verdict.py`: the file record gains
  `rec["capa"]` from the analyzer report, beside
  `rec["capabilities"]` (whose id list now includes any
  `capa:` ids, visibly prefixed).
- Live behaviour, verified before the suite runs: analyzing
  `fixtures/hello_elf` merges 12 capa entries (function,
  basic-block, and instruction scopes, each with namespace
  and MBC evidence) beside the own matcher's 3, with the
  status on the record reading ok, rules identified as
  capa-rules v9.4.0 with the fetch-verified archive hash.
  The governance tests then prove the boundary: with the
  recorded capa entry present and absent, the analyzer risk
  block is identical and the folder verdict headline is
  identical, and no proven chain cites capa evidence.

## Part C: the pinned set

Generated with pip-compile 7.7.0 (`--generate-hashes
--allow-unsafe`) from three committed inputs, so regeneration
is one command per file and the generated headers name it:

- `requirements.in` -> `requirements.txt`: the runtime set.
  The four core dependencies pinned at the versions this
  environment's suite is verified on (lief 1.0.0,
  capstone 5.0.9, pefile 2024.8.26, pyelftools 0.33), the
  optional runtime set (unicorn 2.1.4, cryptography 50.0.2,
  google-genai 3.6.1 as resolved), and the campaign tooling
  dependency (pyzipper 0.4.0 as resolved), with every
  transitive dependency pinned and hashed (829 artifact
  hashes).
- `requirements-capa.in` -> `requirements-capa.txt`:
  flare-capa 9.4.0 and its full tree (55 packages, 669
  artifact hashes), kept as a separate optional file: the
  capa source is an optional evidence source that degrades
  when absent, and no default install path should pay its
  188 MB for a source that is allowed to be missing.
- `requirements-dev.in` -> `requirements-dev.txt`:
  pytest 9.2.0 and its dependencies, pinned and hashed, for
  the verification environment.
- `pyproject.toml` is unchanged: it remains the abstract
  declaration (lower bounds) for package consumers; the
  requirements files are the deployment truth, and the
  workflow steps below consume them.
- Workflows updated to consume the pinned set with
  `--require-hashes` and no ad hoc additions:
  `tests.yml` and `verify.yml` now install
  `requirements.txt` plus `requirements-dev.txt` (unicorn and
  cryptography, formerly ad hoc, are inside
  `requirements.txt`); `campaign.yml` installs
  `requirements.txt` alone (pyzipper, formerly ad hoc, is
  inside it). The capa file is not installed by any workflow:
  CI runs the seam tests and the live test skips, named, when
  the source is unavailable, which is the designed posture
  for an optional source.
- `tools/fetch_capa_rules.sh` (new): fetches the capa-rules
  v9.4.0 archive, verifies its SHA-256
  (273591b11737181b3bdaac18964f23627cf10c21c2b143fc9be88e4a33217669)
  before extracting, installs to
  `~/.cache/event-zero/capa-rules-9.4.0` (or
  `$EZ_CAPA_RULES_HOME`), and stamps the directory with the
  corpus version, commit, and archive hash, which is what
  the adapter reads back onto each file record. Run once in
  this environment: 1045 rule files installed, hash verified.
- This environment's `~/ezpush-venv` had flare-capa installed
  from `requirements-capa.txt` with `--require-hashes`, so
  the operator venv and the pinned artifact agree.

## Verification

- Baseline, before any change, in `~/ezpush-venv`: 447
  passed (operator figure, reproduced at the start of this
  wave).
- Full suite in `~/ezpush-venv` after the wave, with
  flare-capa 9.4.0 installed from the pinned file and the
  pinned rules corpus in place: **463 passed, 0 failed**
  (447 baseline held exactly, plus 16 new tests in
  `tests/test_coverage_wave9.py`), in 4m38s against the
  baseline's 4m28s. No existing test was changed. The wave 9
  file alone: 16 passed, including the live capa run.
- Fresh-venv verification (Part C's required number): a new
  venv at `/tmp/ez-wave9-venv` was built from nothing but the
  three pinned files
  (`pip install --require-hashes -r requirements.txt
  -r requirements-dev.txt -r requirements-capa.txt`), imports
  verified, and the full suite run in it: **463 passed,
  0 failed**, in 4m14s. The venv was then deleted to return
  the /tmp tmpfs headroom it occupied; recreation is the
  three install commands above plus
  `tools/fetch_capa_rules.sh` for the corpus.
- One environment note: /tmp in this environment is a
  512 MB tmpfs. The first fresh-venv attempt ran it dry
  mid-install (a scratch probing venv from the audit was
  still resident); the scratch venv was removed and the
  install completed. No repo state was affected.

## Remainder, named

- FLIRT signatures are not bundled with the flare-capa wheel
  and are not fetched by this wave; library-function
  identification is reduced, which can raise capa false
  matches on library code. The status note on every ok
  record says so. Fetching and pinning the signature set
  (the capa repository's sigs, a separate artifact) is the
  named follow-up.
- The Ghidra backend is assessed, not installed: no JVM or
  Ghidra exists in this environment, and the wave does not
  make that deployment decision. The adapter's backend is
  configuration (`EZ_CAPA_BACKEND`), so the PyGhidra path
  the spec prices is open without code change; nothing here
  verifies it.
- capa runs on PE and ELF inputs only, under a 32 MiB size
  gate and a 30-second per-file budget; .NET inputs route
  through capa's vivisect handling as PE. Shellcode and
  dynamic-analysis formats capa supports are out of scope.
- CI does not install `requirements-capa.txt`: the live capa
  path is exercised in this environment and wherever an
  operator installs the extra, and the seam tests carry the
  merge and degradation semantics in CI. Wiring the capa
  extra into a scheduled (not per-push) CI job is a named
  follow-up, not done here.
- pyelftools remains declared and pinned while imported
  nowhere (Part A). Removing it from the declared set is a
  separate, deliberate change, not a wave-9 side effect.
- The rules corpus is fetched, not vendored: a fresh machine
  needs `tools/fetch_capa_rules.sh` (network to GitHub) once,
  after which the source works offline. Vendoring 1045 rule
  files into the repository was considered and not done;
  the pin (tag, commit, archive hash, fetch-time stamp)
  carries the provenance instead.
