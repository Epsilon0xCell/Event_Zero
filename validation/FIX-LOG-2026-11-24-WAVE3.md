# Fix Log, 2026-11-24, Wave 3: Closure Rules R1, R3, R5

The deep research report
`event-zero-no-clean-for-remote-payload-20261124` answered the
wave 2 misses with a principle rather than three more patches: a
file may receive NO only if its behaviour set is closed under the
evidence examined, meaning every reference the file makes to
content outside itself resolves to content examined in the same
run or to a provably inert target. This wave implements the three
rules the fix task named, in the report's own numbering: R1
(external-reference closure), R3 (engine incompleteness is a
blocker), and R5 (interpreter-proxy invocation). Direction
throughout is fail-closed only, as in waves 1 and 2: every fix is
a blocker that caps the verdict at YES UNACCOUNTED. No blocker is
a proof chain, no existing blocker, chain or test was weakened,
and the byte-identity and fully-enumerated-container exemptions
mirror waves 1 and 2 exactly. Nothing is committed or pushed; all
changes are in the working tree.

Final full-suite result: **224 passed** (203 wave 2 baseline plus
21 new regression tests), run with
`~/ezpush-venv/bin/python -m pytest tests/ -q`. No existing test
was changed. One existing test failed on the first pass and the
engine rule, not the test, was narrowed to fix it; see the R5
judgement calls.

All diagnosis below is proven with synthetic fixtures authored
for this wave (probe run before the fix and again after), in the
wave 2 pattern. No sample was downloaded.

---

## R1. External-reference closure

### What already existed

The verdict already built a connection ledger from the URLs in a
file's strings, parsed .url targets and .lnk URLs into it, and
read torrent trackers, but the ledger was evidence, not a gate:
only lookalike and shortener classifications inside executable or
script formats blocked NO. The Office analyzer surfaced
`template_injection_urls` from strings and the verdict never read
them. No code anywhere extracted OOXML relationship parts, .scf
fields, ClickOnce codebase URLs, HTML resource references, or PDF
/URI targets, and no code asked the closure question at all: what
does this file point at, and was that examined?

Probe, run before the fix: a .docx whose only external
relationship is an attachedTemplate to a remote .dotm returned NO
ACCOUNTED (the package and every member). An .scf whose IconFile
is a UNC path returned NO ACCOUNTED. A .url whose target is a
search-ms handler URI returned NO ACCOUNTED. A VBScript whose
fetch URL is assembled from split string literals returned NO
ACCOUNTED.

### What was wired

`event_zero/verdict.py`, in the wave 1 and 2 pattern: extraction
and disposition are computed in the per-file loop and land in the
file's own blockers and record (`rec["external_references"]`,
with each reference's disposition and basis stated).

- `external_references(name, data)` produces the list from the
  structures the build already parses: OOXML relationship parts
  (read from the package's own zip bytes, and from a standalone
  .rels member), .url URL and IconFile fields, .scf IconFile,
  .lnk targets recovered by the existing string carving,
  ClickOnce manifest codebase values and .appref-ms targets,
  HTML script-element and meta-refresh targets, and script source
  references. The Office analyzer's `template_injection_urls`,
  already computed and previously unconsumed, are appended as
  remote-template references, and literal PDF /URI targets are
  extracted from the raw bytes the PDF analyzer already decodes.
- Script references are extracted after a static-limit
  deobfuscation pass (`_deconcatenate`): PowerShell backtick
  escapes are removed and adjacent string literals joined by +
  or & are collapsed, so a URL split across literals is recovered
  whole. Comment lines are excluded first, keeping wave 2's
  boundary that a mention is not a reference.
- `_reference_disposition` resolves every entry. Resolved means
  one of: examined (the referenced file is part of this
  submission and was judged in this run), inert (a hyperlink to a
  page, image or data target; an external image relationship over
  http(s), which is display-only and can carry neither code nor
  credentials, with that basis stated on the record; a local icon
  path), or remote-data (recorded, not capping: a network path to
  data content, a machine-local path, a target class that could
  not be confirmed executable or inert). Unresolved means the
  target is executable, script, template, package or
  configuration content that was not examined; a remote template
  or OLE relationship; a remote icon reference (which makes the
  host contact and authenticate to a server when the file is
  merely displayed); a protocol handler URI (search-ms, ms-msdt),
  which is operative wherever it appears, including in prose and
  mail carriers; or a ClickOnce codebase, which is a subscription
  to code that can change under the same signed manifest. Any
  unresolved entry produces one named blocker,
  `external-reference-unresolved`, on the file's own record.
- Completeness is recorded per file. Where the current analyzers
  cannot enumerate a format's references, the list says so
  instead of a new parser being built: MSI files record that MSI
  table and custom-action targets are not enumerated by this
  build (the installer accounting already caps every MSI on that
  basis), and a PDF with compressed object streams records that
  only literal /URI targets were enumerated.

### Deliberately out of scope, with reasons

- Full structured parsers for the Shell Link binary format, MSI
  tables, and PDF object streams. The task scoped R1 to the
  reference classes the engine already parses or can parse with
  its existing analyzers. The .lnk string carve recovers every
  reference field the format stores (target, arguments and icon
  are all strings), and that completeness basis is stated on the
  record. MSI references ride the existing installer accounting,
  which caps the unit before R1 needs to. PDF references hidden
  in compressed streams are recorded as an incompleteness note,
  not a cap on their own, because the PDF features that execute
  (JavaScript, OpenAction, Launch, embedded files) are already
  verdict blockers from wave 1, and /URI hyperlinks are the inert
  class; capping every object-stream PDF would cap the modern
  benign PDF population on a gap that carries no executable
  reference class of its own.
- References in compiled binaries' strings beyond the existing
  connection ledger. A binary's URLs are already ledgered as
  evidence, and a compiled binary without byte identity cannot
  reach NO at all, so a reference gate there would change no
  verdict.
- Ordinary links in prose. A hyperlink in a text file is not an
  operative reference; only protocol handler URIs are extracted
  from prose and mail carriers, because a host program acts on
  those by design (the published search-ms carrier is an HTML
  attachment).

Probe after the fix: all four probe shapes return YES
UNACCOUNTED with the blocker named; the benign .docx twin
(external hyperlink to an https page, external image
relationship) keeps NO ACCOUNTED with both references recorded
as inert.

Regression tests: `tests/test_accuracy_audit_wave3.py`, the R1
section (11 tests): the external-template .docx and its benign
twin, the .scf UNC icon, the search-ms .url, the split-string
VBScript (adversarial variant, recovered by de-concatenation) and
a plain VBScript control, the ClickOnce codebase, PDF /URI
targets to an executable (caps) and to a page (still NO), a
protocol URI in a text file, and a plain text link control.

---

## R3. Engine incompleteness invariant

### What already existed

More than the audit pattern suggested. The wave 1 truncation
markers (`report["truncations"]`) already cap per file. Archive
enumeration fails loud: member-count and size caps raise,
extraction failures and unsupported container kinds become
failed-container blockers, depth-limit layers and failed
containers cap their own records, installer files carry entry
blockers, and a per-file analysis exception caps the unit.
`_safe_extract_zip` and `_safe_extract_tar` were checked and
already raise on every partial-enumeration path.

### What was wired

The audit for signals that exist but did not reach the verdict
found four, and all four are now wired:

- Script parse failure. `script_analysis` records `parse_error`
  when the Python parser rejects the source; the verdict never
  read it, so a script the parser could not parse was certified
  on the line ledger alone (probe: a four-line Python file with a
  syntax error returned NO ACCOUNTED). It is now a per-file
  blocker named `engine-incompleteness (script-parse-failure)`,
  and the file record carries `rec["incompleteness"]`.
- Binary parse failure. When the PE fallback parser cannot read
  a file's section table, its format record has no sections at
  all; that degradation was invisible to the verdict. It is now
  the blocker `engine-incompleteness (binary-parse-failure)`,
  under the same record field.
- Email enumeration failure. `expand_email` caught every parse
  exception and returned silently, and skipped attachments whose
  payload could not be decoded, also silently: an email whose
  attachments were never listed was an unaccounted unit with no
  signal anywhere. Both paths now record entry blockers on the
  message's own record, in the defect 16 pattern. Fixture note:
  the stdlib parser's tolerance makes the failure unreachable
  with real message bytes in probing (three malformed variants,
  including a bogus transfer encoding and corrupt base64, all
  still decode to some payload), so this wiring is verified by
  code inspection and by the entry-blocker channel's existing
  tests rather than by a dedicated behavioural fixture.
- Carved payload failures. The two carved-payload incompleteness
  blockers (payload could not be analysed; payload could not be
  decoded to a known format) were appended to the release-level
  blocker list only, leaving the unit's own record able to read
  ACCOUNTED under an UNACCOUNTED headline, the defect 16 shape.
  They are now per-file blockers. Fixture note: no synthetic
  fixture in probing could trigger either branch, because
  carve-validated payloads always parse to a known format or
  analyse without raising; the move is verified by code
  inspection and by the absence of suite regressions.

### Audited and deliberately not wired, with reasons

- The LIEF backend string (`parser_backend`). It cannot
  distinguish "lief not installed" (an environment property) or
  "lief does not apply to this format" (every text file) from a
  per-file parse failure, and the corpus's minimal synthetic
  binaries make lief refusal a fixture artifact rather than
  evidence about a file. The reliable per-file signal is the
  fallback parser's own failure, wired above.
- The disassembly availability flag. As recorded it conflates
  capstone missing, architecture unsupported, and no code bytes
  (it returns the capstone-present flag in all three cases), so
  it does not state that analysis was incomplete for any given
  file; and a compiled binary without byte identity already
  cannot reach NO, so the cap would change no verdict that the
  accounting does not already decide.
- The analyzer-side email `error` field. The verdict-relevant
  surface is attachment enumeration, wired above; the analyzer's
  own error key is display evidence for the same failure.

Regression tests: the R3 section of
`tests/test_accuracy_audit_wave3.py` (3 tests): the Python parse
error caps with the incompleteness named on the record, a valid
Python control keeps NO, and a direct-function test of the
reference extractor.

---

## R5. Interpreter-proxy invocation

### What already existed

Wave 2 covers mshta and rundll32 aimed at a remote URL, and any
fetch primitive composed with an execution side, inside
script-class files. The .lnk path proves a chain only when a
lolbin target combines with a URL or a download cradle. Nothing
covered a proxy aimed at encoded content, a proxy aimed at a
script or package that is not part of the submission, msiexec
aimed at a remote package, or regsvr32 aimed at a scriptlet (the
Squiblydoo carrier), and nothing stated the signature rule: the
verdict's signature handling reads the file under judgement, so
a proxy's signature could never be entered for it, but the
invoking file itself was simply never examined for invocations.

Probe, run before the fix: a .cmd running powershell with an
EncodedCommand argument and no fetch returned NO ACCOUNTED. A
.cmd running msiexec against a remote .msi returned NO
ACCOUNTED. A folder launcher running wscript on a script absent
from the folder returned NO ACCOUNTED. A synthetic .lnk aiming
regsvr32 at a payload.sct returned NO ACCOUNTED.

### What was wired

`proxy_invocation_findings(name, data, local_basenames)` in
`event_zero/verdict.py`, applied in the per-file loop beside the
wave 2 findings and recorded as
`rec["proxy_invocation_findings"]`, with one named blocker per
finding, `interpreter-proxy-invocation`, whose text states the
rule: the system binary's signature vouches for the binary,
never for this file's instructions.

- Carriers: script-class files (the wave 2 extension set) and
  .lnk files, whose invocation is read from the existing string
  carving. Invocation evidence only: a proxy named on a
  non-comment line together with an operative argument of a
  capped class. Comment lines are excluded by the same helper
  wave 3 uses for reference extraction.
- Capped argument classes: remote content (a URL, UNC path or
  file URI on the invocation) for executor proxies (mshta,
  rundll32, regsvr32, msiexec, wscript, cscript, powershell,
  msbuild), which execute what they fetch; encoded content (an
  -EncodedCommand or FromBase64String shape, a javascript: or
  vbscript: URI, or a long base64 argument to an executor
  proxy); and a target file (script, scriptlet, package, INF or
  DLL) whose basename is not part of this submission and was
  therefore not examined in this run. A target that is in the
  submission resolves, because it was judged in the same run.
- The benign-mention control holds by construction and by test:
  proxy names in a comment (even beside an encoded-invocation
  shape and an executable URL) and proxy names in an echo
  sentence carry no operative argument and do not fire.

### Judgement calls

- Platform scripts exemption. The first full-suite pass failed
  exactly one existing test, the KMS false-positive twin, whose
  helper runs `cscript ospp.vbs /act`. ospp.vbs ships with
  Microsoft Office and slmgr.vbs ships in the Windows image;
  invoking one by bare name aims the interpreter at content the
  platform image accounts for, the same basis on which system
  DLLs on system paths are exempt in this function. Both names
  form a named, closed set (`PLATFORM_SCRIPTS`), never a
  pattern, and the existing test was not changed: the engine
  rule was narrowed. This is the wave 1 KMS lesson applied in
  the other direction: the baseline is content and platform
  membership, never the file's own name or claims.
- Download-only proxies. bitsadmin and certutil are in the
  proxy list, but their remote shape is wave 2's fetch atom, and
  wave 2's data-download control (a bitsadmin fetch of a JSON
  file, no execution side) must keep its NO. They therefore fire
  under R5 on remote content only when the fetched target is
  itself executable-class: the staged executable is the
  unaccounted content. certutil decode of a local file is out of
  scope: the decoded output is a new file the run never sees,
  but the input file is in the submission and examined, and the
  shape is a transformation, not an invocation of unexamined
  content.
- DLL targets on system paths (System32, SysWOW64, the Windows
  directory) do not fire: they are the proxy's normal library
  surface, accounted by the platform image. A DLL referenced by
  a relative or user-writable path does fire.
- Machine-local targets of shortcut files are recorded as
  remote-data references, not caps, under R1: content already on
  the user's machine is outside the submission boundary this
  engine judges, and capping it would cap the entire legitimate
  shortcut class. The closure cap governs references a host will
  fetch or load from outside the machine and submission.

Probe after the fix: all four probe shapes return YES
UNACCOUNTED with the finding named; the folder control (launcher
plus the helper it invokes, both in the submission) keeps NO
ACCOUNTED.

Regression tests: the R5 section of
`tests/test_accuracy_audit_wave3.py` (7 tests): the encoded
PowerShell invocation, the remote msiexec package, the comment
and mention control, the in-submission wscript target control,
the missing wscript target, the regsvr32 scriptlet shortcut,
and a local-program shortcut control.

---

## Notes and scope

- Research rules not in this task's scope, untouched: R2
  (fetch-execute composition as a capability rule; wave 2 covers
  its adjudicated shapes in script classes), R4 (disguised
  identity beyond wave 2's double extension), R6 (active content
  in data-classified files; wave 1 wired the verdict consumption
  for the PDF and Office classes the analyzers surface), R7
  (unreadable gated content; the virtualization and entropy
  blockers already cap that class), R8 (container provenance
  inheritance; the wave 1 and 2 container treatment stands), R9
  (a review invariant, no code shape), R10 (installer action
  accounting; the installer blockers already cap that class).
- One interaction worth recording: a file that is PROVEN by a
  chain keeps its PROVEN verdict, and its wave 3 findings are
  still recorded on its record (external references with
  dispositions, proxy findings), because blockers are dropped
  when a proof exists but the record fields are set before the
  verdict is decided. The findings are evidence either way.
- Files changed: `event_zero/verdict.py`,
  `tests/test_accuracy_audit_wave3.py` (new), and this log.
- Final full-suite result: **224 passed** in 221.92s
  (`~/ezpush-venv/bin/python -m pytest tests/ -q`), against the
  203 passed wave 2 baseline. No existing test was changed.
