# Coverage Wave 7 Log: Model Files as Code, Clipboard Payloads as Script Units

Date: 2026-11-24 (built overnight into 2026-11-25). Source spec:
`~/workspace/research_notes/event-zero-next-frontier-20261124/report.md`,
items 7 and 8. Suite: 402 baseline held, plus 27 new tests in
`tests/test_coverage_wave7.py` (full-suite count in the closing
section). No existing test was changed.

Build note: two delegated builders halted on the same surface
(a system security notice attached to their own probe output,
because hand-assembled pickle bytes would run code if they were
ever loaded). Per the standing recovery discipline, the wave
was built directly by the operator on the third route, with the
diagnosis from the first builder as its starting point. The
safety shape never changed: fixtures are hand-assembled byte
strings treated strictly as data, analysis is a disassembly
walk (`pickletools.genops`) only, and nothing in the engine or
the tests ever unpickles, loads, imports, or executes fixture
content.

## Item 7: pickle and model-file opcode accounting

### Prior behaviour, proven by probe (first builder, engine at 4143c87)

- Hostile protocol 0 pickle (`os.system` via GLOBAL + REDUCE):
  NO ACCOUNTED. The critical fail-open: protocol 0 is ASCII,
  falls into the text branch, and no opcode accounting existed.
- Hostile protocol 4 pickle (STACK_GLOBAL + REDUCE): YES
  UNACCOUNTED only incidentally, as unknown binary data; the
  callables were named nowhere.
- Plain-data protocol 4 pickle: YES UNACCOUNTED incidentally;
  protocol 0 plain data: NO via the text branch, never walked.
- Broken-after-payload pickle (REDUCE, then an invalid opcode,
  no STOP): capped incidentally; callables and stopping offset
  unrecorded.
- Benign GLOBAL (`collections.OrderedDict`) and non-allowlist
  callable (`datetime.datetime`) pickles: NO via the text
  branch, callables unexamined.
- Legacy torch layout (GLOBAL `torch._utils._rebuild_tensor`,
  PERSID, STOP, trailing storage bytes): YES incidentally; no
  persistent-id or storage accounting existed.
- Safetensors, consistent header: NO via the text branch (the
  JSON header decodes as UTF-8); the header was never parsed.
- Safetensors, header claiming 800 bytes of tensor data in an
  8-byte payload: NO ACCOUNTED. A proven false acquittal.
- Hostile protocol 0 pickle inside a torch-style ZIP
  (`checkpoint.pt`, member `archive/data.pkl`): the whole
  release NO ACCOUNTED. Container invariance failed in the
  worst direction.
- 7z-magic file with a stored hostile pickle: YES UNACCOUNTED
  as an unenumerated container (existing fail-closed
  behaviour), callables named nowhere. No `py7zr` and no `7z`
  binary exist in this environment, so 7z interiors cannot be
  enumerated here.

### What was built

New module `event_zero/coverage7.py`:

- `analyze_pickle`: an abstract-interpretation walk over
  `pickletools.genops` tracking string constants, memo slots,
  and GLOBAL/STACK_GLOBAL resolutions. Every callable is
  recorded with a tier (dangerous, allowed, other) and whether
  the walk saw it invoked (REDUCE, INST, OBJ, NEWOBJ,
  NEWOBJ_EX). An invoked dangerous callable is the PROVEN
  chain `pickle-code-execution`. Non-allowlist callables,
  referenced-but-not-invoked dangerous callables, unresolvable
  invocations, extension-registry codes, protocol 5
  out-of-band buffers, incomplete walks (with the stopping
  offset), and trailing bytes after STOP all cap with the
  callable or offset named. Trailing bytes named by persistent
  ids are accounted as storage data (the legacy torch layout).
  The allowlist is reconstruction and pure-data machinery:
  torch and numpy prefixes (with the dangerous-name check
  applied first inside them), collections, copyreg, and the
  standard pure value constructors (builtins containers,
  datetime, decimal, uuid). Claims: `.pkl`/`.pickle`/`.pck`
  names are strict (unparseable content is itself the
  finding); `.pt`/`.pth` names are soft (content that does not
  parse as a pickle is not claimed, so `.pth` path listings
  keep their path); other files are claimed by content when a
  disassembly walk consumes them completely to STOP. A content
  or soft claim that fails as a pickle within four opcodes is
  not claimed at all, so text files whose first byte is an
  opcode value are never swept in. The same guard requires at
  least two opcodes for a complete soft or content claim: a
  `.pth` path listing beginning with a dot (`../shared/libs`)
  disassembles as a lone STOP with trailing bytes, and the
  first full-suite run caught exactly that sweep-in against
  the wave 6 `.pth` control; the guard was added and the
  control passes again.
- `safetensors_accounting`: the header is parsed, every
  tensor's `data_offsets` are checked against the payload's
  actual extent, and payload bytes past the last tensor's
  declared extent cap as unaccounted.
- `onnx_accounting`: a targeted protobuf walk (generic
  varint/length-delimited field reader, interpreted at model,
  graph, node, and tensor level). Custom operator domains cap
  as external references; external-data tensors cap unless the
  named file is in the submission. A protobuf walk failure
  caps; bytes with no readable graph are capped by the
  verdict wiring, and `.onnx` names are exempted from the
  generic unknown-format blocker so the wave's own cap is the
  one that speaks.
- `keras_lambda_findings`: a parsed JSON configuration is
  searched recursively for Lambda layers, which carry
  serialised Python functions and are inventoried as
  unaccounted code.
- `scan_embedded_pickles`: for failed 7z containers, a
  naming-only raw scan finds binary pickle headers and
  protocol 0 GLOBAL lines in the stored bytes and names the
  callables a stored payload would resolve. The container cap
  itself is unchanged.
- Format labels in `analyzer.detect_format`, ahead of the
  text heuristic: binary pickle magic (`Python pickle`) and a
  validated safetensors header sniff (`safetensors model`).
- Verdict wiring in the established wave pattern: a wave 7
  section in the per-file loop, and a `model_accounted`
  decision branch beside `bytecode_accounted`.

Container invariance holds by construction: container members
are judged as their own per-file records, so the same pickle
bytes produce the same judgement loose, in a ZIP, or in a
torch-style archive.

### Remainder, named

- Compressed 7z interiors cannot be read in this environment
  (no py7zr, no 7z binary), so embedded-pickle naming covers
  stored content only; the container cap stands regardless.
- GGUF receives no dedicated accounting this wave; it caps as
  unknown binary data, fail-closed.
- ONNX custom-operator detection is limited to node domain
  fields read by the targeted protobuf walk; attributes
  carrying external library paths are remainder.
- Content-claimed pickles that fail as pickles within four
  opcodes are not claimed (the anti-sweep guard for text
  files); a truncated stream that short is remainder.
- Keras Lambda inventory covers JSON configurations; Lambda
  layers inside HDF5 model files are remainder.

## Item 8: HTML clipboard and instruction accounting

### Prior behaviour, proven by probe

- ClickFix fixture (fake verification framing, clipboard
  writeText of a PowerShell DownloadString cradle): already
  YES PROVEN, but incidentally, via generic capability
  matching on the page's script source; no clipboard unit was
  extracted and the framing was not what convicted.
- EtherHiding shape (clipboard content fetched from a remote
  URL and written via `fetch(...).then(t =>
  navigator.clipboard.writeText(t))`, with Run-dialog
  instructions): NO ACCOUNTED. The proven gap.
- Controls, both NO ACCOUNTED and both required to keep NO:
  a benign tutorial page (PowerShell instructions, `ipconfig
  /all` in a code block) and a benign clipboard page (a button
  copies `hello@example.com`).

### What was built

`coverage7.clipboard_units` extracts clipboard units from a
page's source: `navigator.clipboard.writeText` arguments
(literal strings scanned to their closing quote, because a
cradle contains parentheses; simple variable assignments
resolved; `fetch(...)` chains and fetch-assigned variables
classified remote-assembled; anything else unresolvable),
textarea payloads behind `execCommand('copy')`, and the
`fetch().then(... writeText)` shape directly. Visible-text
instruction framing is classified strong (fake verification,
Run dialog, Explorer address bar, paste-and-press-enter
phrasings) or none, and commands in the visible text are
extracted with a cradle test over both the units and the text.

Judgement line, as designed: a fully present fetch-and-execute
cradle in a clipboard write, or under strong framing in the
visible text, is the PROVEN chain `clickfix-paste-and-run`.
Remote-assembled and unresolvable clipboard content caps.
Strong framing plus a present non-cradle command caps as a
framing finding, not a conviction. Commands under
documentation framing alone are data: the tutorial control
keeps NO, and a benign clipboard string is nothing.

### Remainder, named

- Clipboard writes assembled by string concatenation or
  DOM construction beyond simple variable assignment are
  unresolvable and cap; resolving them is remainder.
- Framing detection is a phrase catalogue, a maintained list
  in the same sense as the wave 6 trigger catalogue; novel
  framing phrasings are remainder until catalogued.

## Files changed

- `event_zero/coverage7.py` (new)
- `event_zero/verdict.py` (import, wave 7 per-file section,
  `model_accounted` decision branch, `.onnx` exemption in the
  unknown-format blocker)
- `event_zero/analyzer.py` (pickle and safetensors format
  labels ahead of the text heuristic)
- `tests/test_coverage_wave7.py` (new, 27 tests)
- `validation/COVERAGE-WAVE-7-LOG.md` (this file)

## Verification

Wave tests: 27 passed. Full suite: 429 passed (402 baseline
plus 27), operator-verified by a full run before the push.
The first full run read 428 passed and 1 failed, the wave 6
`.pth` path-only control swept in by the lone-STOP shape
recorded above; the two-opcode guard fixed it and the
re-run is the 429.
