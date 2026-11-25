# Fix Log, 2026-11-24, Wave 4: Resolved Script Source

Campaign smoke run 6 (run 45541655584), run on the strengthened
engine (waves 2 and 3, commit cd2b0c8), returned NO ACCOUNTED
again for two of the three run 5 misses: EZ-BYPASS-2026-007 (the
batch dropper 5441.pdf.cmd) and EZ-BYPASS-2026-008 (the HTA
downloader azienda_08.hta). The third, 006, was re-judged YES on
the real sample and is closed. Waves 2 and 3 capped synthetic
fixtures of the shapes they imagined; the real files use the
shapes their dialects actually write. This wave works from the
vendor-reported behaviours of record (007: an evasive batch
dropper, Joe Sandbox malicious 52 of 100, FileScan suspicious
with a qbot tag; 008: an HTA that downloads via BitsAdmin and
modifies the certificate store, Triage Malicious 8 of 10,
payload URL named by DocGuard) and from the mechanics of the
batch, VBScript and JScript dialects. No sample was downloaded;
every shape below is a synthetic fixture authored for this wave,
run against the pre-fix engine to prove the NO, and re-run after
the fix. The campaign runner preserves original filenames
(validation/campaign/analyze_shard.py extractall into the sample
directory, verdict on the directory), so filename loss is
excluded as a cause; the double-extension name finding would in
any case have capped 007 on its name alone had the name been the
only gap, and it did not fire in the run, which is itself
evidence the gap sits in the content path, not the name path.

Direction throughout is fail-closed only, as in waves 1 to 3:
every fix is a blocker that caps the verdict at YES UNACCOUNTED.
No blocker is a proof chain, no existing blocker, chain or test
was weakened, and the byte-identity and
fully-enumerated-container exemptions mirror waves 1 to 3.
Nothing is committed or pushed; all changes are in the working
tree.

Final full-suite result: **331 passed** (308 wave 3 baseline
plus 23 new regression tests in
tests/test_accuracy_audit_wave4.py), run with
`~/ezpush-venv/bin/python -m pytest tests/ -q` in 322.67s, with
the wave 4 engine changes alone first re-proven at 308 passed
before the new tests were added. One test in the new file was
corrected during development (its assertion described
assignment lines as expanded; the designed behaviour emits them
as written, and the test now asserts the expanded command line
instead). No existing test was changed.

---

## Diagnosis: the shapes that still reached NO, and why

The probe battery spanned the task's named shapes and the
dialects' ordinary mechanics. Fourteen shapes returned NO
ACCOUNTED on the pre-fix engine. They reduce to six mechanisms.

### M1. The HTA's script body was invisible to R1

`external_references` routes .htm, .html and .hta to the HTML
branch, which extracts script-element sources, meta refreshes
and protocol URIs, and returns. Every other script class falls
to the script branch, which extracts URLs from the source. An
HTA's VBScript or JScript body is script source in every sense
the closure rule cares about (mshta executes it on open), but
its URLs were extracted by neither branch: the one script class
whose own URLs were invisible to R1.

Shapes proven NO on this mechanism: an HTA whose XMLHTTP fetch
takes its URL from a variable (H1), the same in JScript (H8),
and a WinHttp fetch composed with ShellExecute (H5, shared with
M2). A standalone .vbs twin of H1 capped correctly, through the
script branch, which isolates the defect to the HTA routing.

### M2. The fetch patterns are single-line; the object model is not

Wave 2's fetch patterns require the fetch token and a literal
URL within one line (`[^\n]{0,240}?`). The object model of these
dialects puts them on different lines by construction: the
fetch object is created on one line, opened against a variable
on another, and its response body written out by an ADODB.Stream
on a third. No rule composed the three. The same gap in the
command model: wave 2's chain needs an execution side or a
staged payload on the download line, so a download whose URL
and destination both travel in variables, executed by a bare
variable line, has neither.

Shapes proven NO on this mechanism: H1, H5, H9 (an HTA whose
payload URL is extensionless, so R1 would classify the target a
page even if extracted; the composition is the only gate that
can see it), and the batch shapes B11 (certutil, extensionless
URL, variable destination, bare-variable invocation), B1's job
form (bitsadmin /create, /addfile, /resume, which never uses
the /transfer token wave 2 keys on), and B3b/B4 (transfer with
variable destination and bare or delayed-expansion invocation).
Controls that pinned the boundaries: the same certutil shape
with a literal executable destination caps pre-fix (the payload
token on the download line is load-bearing), and the transfer
shape with a `start` invocation caps pre-fix (the start atom is
load-bearing).

### M3. Nothing resolved variables, fragments or character codes

The dialects execute a resolved text. Batch expands %VAR% and
!VAR! from set assignments; VBScript and JScript pass URLs and
paths through variables; strings are assembled from fragments
("htt" + "p://..."), grown by a second assignment
(set u=%u%.exe), concatenated inside a command string
("bitsadmin /trans" & "fer ..."), or built from Chr() character
codes with no literal form anywhere. Wave 3's de-concatenation
joins split string literals, and nothing else in the engine
resolved any of it, so each of these constructions removed the
URL, the destination, the tool name or the whole command from
every literal scan at once.

Shapes proven NO on this mechanism: B12 (fragmented URL), B13
(grown URL; the first literal is extensionless and inert), B7
(the tool name itself in a variable: %T% /transfer), H3
(bitsadmin command broken by concatenation, URL in a variable),
H2 (HTA URL from Chr() codes), P7b (standalone VBScript URL
from Chr() codes; its literal-URL twin caps pre-fix through
R1, isolating character construction as the gap), and B8's
PowerShell form is noted as covered pre-fix only because its
set line carried the literal URL for R1.

### M4. Reference extraction silently emptied on one bad byte

`external_references` decoded the file with strict UTF-8 and
returned "" on any error. `detect_format`'s text heuristic
reads only the first 4,096 bytes. One cp1252 byte (an accented
Italian lure character, the ordinary encoding of these files)
past that window in a file of 6,583 bytes left the format
reading "text / script" while the reference extractor saw an
empty file and extracted nothing: the file was acquitted on a
reference scan that never ran. The real 007 is 8,380 bytes.
The same strict decode, with a replacement fallback, did not
empty the wave 2 scan, which is why the failure was silent:
every other consumer still saw the file.

Shape proven NO on this mechanism: P3b (the certutil variable
shape behind 300 lines of benign padding and one cp1252 byte
at offset 6,487). Its twin with the byte inside the first
4,096 bytes capped pre-fix, through the unknown-format path,
which pins the window as the load-bearing detail.

### M5. Every script treatment keyed on the extension

script_class_findings, proxy_invocation_findings and the
script branch of external_references all gate on the file
extension. Identical bytes with no extension were judged as
plain text: the wave 2 HTA dropper's exact bytes, which cap
under an .hta name, returned NO ACCOUNTED under a bare hash
name, as did the batch dropper's content. The campaign runner
preserves names, so this is not the run 6 cause; it is the
same class of hole one rename away, proven in-engine, and
closed here because the fix is the class, not the fixture.

Shapes proven NO on this mechanism: P1 (batch content, hash
name), P5 (HTA dropper bytes, hash name).

### M6. A written second stage was nobody's content

A batch file that writes its dropper as a second script with
echo redirection and runs it moves its behaviour into a file
that is not in the submission. Wave 3's R5 caps an invocation
of an absent target file, but the target here is a variable
(%s%), which names nothing until substitution, and the stage's
content, though fully determined by the writer's own echo
lines, was reconstructed by nobody. The benign twin matters as
much: a batch that writes a MsgBox helper and runs it the same
way must stay NO, so the closure is reconstruction and
judgement, not a ban on the shape.

Shape proven NO on this mechanism in its hostile-variable
form in combination with M1 to M3 (the stage's fetch is an
object-model fetch with a variable URL): B5 and B6. Their
literal-URL variants capped pre-fix only because the URL sat
in an echo line where R1's script scan could see it, not
because the stage was judged.

---

## The fix

All changes are in `event_zero/verdict.py`, in the established
pattern: findings are computed from evidence the verdict holds
and land in the file's own blockers and record. The unifying
move is that waves 2 and 3 now read the source the host would
execute, not only the source as written.

- Dialect-faithful decoding (`_decode_script_bytes`): BOM
  sniffing for UTF-16 LE and BE and UTF-8, BOM-less UTF-16 by
  NUL interleave, strict UTF-8, and a cp1252 fallback. It never
  returns an empty string for non-empty input. It replaces the
  strict decode in `external_references` and the
  replacement-only decodes in `script_class_findings` and
  `proxy_invocation_findings`. (Closes M4; a UTF-16 HTA's chain
  is now found in its content, not only through the
  unknown-format accident.)
- Resolved source (`_resolved_script_text`): character-code
  construction decoded (`Chr()` and `ChrW()` runs and JScript
  `String.fromCharCode` become the quoted literal they build),
  literal concatenation collapsed (the wave 3 pass), and simple
  literal-valued variables substituted in the dialect's own
  syntax: batch `set` assignments feeding %VAR%, !VAR! and
  $env:VAR (a batch-set variable is the environment a child
  PowerShell process inherits), VBScript and JScript
  identifiers substituted outside quoted segments, PowerShell
  $VAR, shell $VAR and ${VAR}. Substitution runs on non-comment
  lines only, so the wave 2 comment control holds by
  construction. Batch assignment lines are emitted as written
  (their values built the environment; re-expanding a
  self-referential assignment would double-apply it). The
  static limit is stated in the code: function results,
  environment and registry reads, and substring arithmetic on
  non-literals stay visibly unresolved rather than guessed.
  (Closes M3.)
- Union consumption: `script_class_findings`,
  `proxy_invocation_findings` and the reference extraction run
  over the raw source and the resolved source and take the
  union, deduplicated, so nothing the raw scan caught is lost
  and the resolved scan adds what only it can see.
- HTA script-body references: the .hta branch of
  `external_references` additionally extracts URLs from the
  script body, raw and resolved, as script-url references with
  the ordinary dispositions. (Closes M1.)
- Composition rule (`_script_text_findings`): a network-fetch
  object (CreateObject or ActiveXObject of MSXML2.XMLHTTP,
  Microsoft.XMLHTTP, MSXML2.ServerXMLHTTP or
  WinHttp.WinHttpRequest, or a WebClient) composed with an
  executable staged to disk (an ADODB.Stream SaveToFile or a
  CreateTextFile whose target, after resolution, ends in an
  executable extension) is a remote-fetch-and-execute finding,
  with any shell Run or ShellExecute recorded as the execution
  side. The basis is wave 3's own: the staged executable is the
  unaccounted content. A bare invocation line (a line that is
  only an executable path, optionally through call) joins the
  execution atoms, because in this dialect typing the
  downloaded file's name is the execution primitive. (Closes
  M2, including the extensionless-URL HTA, whose target R1
  correctly calls a page: the composition, not the reference,
  is what caps it.)
- Content-keyed class (`_sniff_script_ext`): where the name
  carries no extension, a strong dialect signature in the
  content assigns the class: an HTA:APPLICATION element, a
  script element naming VBScript or JScript with an ActiveX
  object, a batch opening (@echo with set and expansion
  structure), a VBScript object script outside markup. The
  three consumers route extensionless files by the sniffed
  class. (Closes M5 for the extensionless form.)
- Written-stage accounting (`written_stage_findings`): a batch
  file's echo-redirection writes are reconstructed into the
  files they write, and each script-class stage is judged with
  the same three functions as a submitted file. A stage that
  fails its own accounting yields a `written-stage-unaccounted`
  finding on the writer, recorded as
  `rec["written_stage_findings"]` with its blocker text; a
  stage that is reconstructed and judged joins the local set
  for the writer's proxy check, so invoking it is invoking
  examined content. (Closes M6.)

Probe after the fix: all fourteen NO shapes return YES
UNACCOUNTED, each with its mechanism named on the record (the
chain finding, the unresolved reference with the resolved URL,
the proxy finding, or the written-stage finding). All benign
controls keep NO ACCOUNTED: the display-only HTA, the HTA that
fetches data and displays it, the HTA that stages fetched data
under a data name, the variable-held data download (the wave 2
control in resolved form), the benign echo-written stage run
through a variable, the local tool invoked through a variable,
and the wave 2 and 3 controls (the KMS platform-script
invocation, the comment and mention controls, the
in-submission wscript target), which the full suite re-proves.

Regression tests: `tests/test_accuracy_audit_wave4.py`, 23
tests. Fourteen hostile shapes (the HTA object-model family
including the Chr() and extensionless variants, the batch
indirection family including fragments, growth, the BITS job
form and the cp1252 window case, the standalone VBScript Chr()
case, both extensionless cases, and the echo-written stage),
each asserting NO is not issued and the mechanism is named;
direct-function tests for the resolver, the sniffer and the
stage reconstruction; and six benign twins asserting the
mechanics do not fire on accounted content.

## Judgement calls

- Resolution is a reading, not an execution. The resolver
  substitutes only literal-valued assignments it can see whole;
  it does not evaluate expressions, call functions, or guess
  at values read from the environment, the registry or the
  network. A value it cannot resolve stays a variable in the
  resolved text, where the composition and proxy rules can
  still see the shape around it. This is the wave 3 static
  limit, extended from concatenation to assignment.
- The composition rule requires the staged target to be
  executable-class. An HTA that fetches data and stages it
  under a data name is accounted (the staged content's class
  is data, and the reference to data is inert); the rule fires
  on what is staged, not on the presence of a stream object.
  This keeps the data-download philosophy of waves 2 and 3
  intact in the object model.
- The sniffer assigns a class only where the name carries no
  extension at all. A dropper renamed to a treated extension
  (.dat, .txt) is not sniffed in this wave; that remainder is
  recorded below rather than papered over.
- Written-stage reconstruction covers echo redirection, the
  dialect's literal transcription. Stages written by copy,
  by type from a companion file, or by a generator program are
  not reconstructible from the writer's lines and remain the
  R5 absent-target cap when invoked, which is the correct
  fail-closed outcome for them.
- The HTA body extraction is HTA-only. A browser HTML file's
  inline script URLs keep the wave 3 treatment (script-element
  sources and protocol URIs), because a browser page is not an
  intrinsic executor of local script the way mshta is.

## Notes and scope

- Files changed: `event_zero/verdict.py`,
  `tests/test_accuracy_audit_wave4.py` (new), and this log.
  No existing test was changed in its assertions; the one
  corrected test is new in this wave (see the header).
- Remainder, named: substring arithmetic (batch %VAR:~n,m%,
  VBScript Mid on non-literals) can still assemble a URL no
  static pass here resolves; a dropper renamed to a treated
  non-script extension is not content-sniffed; stages written
  by means other than echo redirection are capped only at
  invocation, under R5; and the per-sample root cause for the
  real 007 and 008 remains unprovable from outside the runner,
  by the campaign's own design. What this wave closes is the
  class space the vendor behaviours and the dialects define:
  every shape in that space now caps on synthetic fixtures,
  and confirmation on the real samples awaits the shard 0
  re-run on the strengthened engine, as with waves 2 and 3.
- Environment note: the home directory quota was exhausted
  partway through this wave (a pre-existing condition of the
  machine, recorded in the project memory), so the wave was
  built and verified in a staging copy of the working tree at
  /tmp/ez-wave4 and synced back; the suite results below are
  from the staging copy, byte-identical to the working tree
  it was synced to.

## Drafted ledger addendum for EZ-BYPASS-2026-007 and 008

For the operator to append to docs/MISS-LEDGER.md; not
appended by this wave.

    ## Status addendum 2026-11-24 (fix wave 4)

    - EZ-BYPASS-2026-007, 008: re-judged by the wave 2 and 3
      engine in campaign smoke run 6 (run 45541655584); both
      returned NO ACCOUNTED again on the real samples. Fix
      wave 4 (validation/FIX-LOG-2026-11-24-WAVE4.md) closes
      the shape classes the vendor behaviours of record and
      the batch, VBScript and JScript dialects define:
      resolved-source analysis (variable substitution,
      fragment and growth assembly, Chr() character
      construction, dialect-faithful decoding that never
      silently empties), HTA script-body references under R1,
      the fetch-object plus staged-executable composition
      rule, content-keyed classification for extensionless
      files, and written-stage accounting for echo-written
      second stages. Fourteen synthetic shapes that returned
      NO ACCOUNTED on the wave 3 engine now cap, each with
      its mechanism named, and the benign twins keep NO.
      Suite: see the wave 4 log's closing count. Confirmation
      on the real samples awaits the shard 0 re-run on the
      strengthened engine; until then these entries stay
      open on the record.
