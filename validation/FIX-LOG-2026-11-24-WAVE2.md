# Fix Log, 2026-11-24, Wave 2: Script-Class Droppers

Campaign smoke run 5, run on the wave 1 engine, returned NO
ACCOUNTED for three confirmed malware samples, all small
script-class delivery files from one Gozi and Ursnif lure set,
adjudicated from their public MalwareBazaar pages (no sample was
downloaded, and none was needed: the diagnosis below is proven with
synthetic fixtures authored for this wave). The three classes:

1. A 198-byte Windows .url shortcut whose target is a remote
   payload on a dotted-quad IP host (4 vendor detections).
2. A batch file under a disguised double extension (the name
   pattern file.pdf.cmd, 8,380 bytes), rated malicious by Joe
   Sandbox with a double-extension evasion signature.
3. An .hta downloader (6,975 bytes) that downloads via bitsadmin
   and modifies the certificate store (6 vendor detections,
   Hatching Triage behaviours).

Direction throughout is fail-closed only, as in wave 1: every fix
is a blocker that makes NO unreachable for a shape that cannot be
accounted from the file alone. No blocker is a proof chain, and no
existing blocker, chain or test was weakened. Nothing is committed
or pushed; all changes are in the working tree.

Final full-suite result: **203 passed** (191 wave 1 baseline plus
12 new regression tests), run with
`~/ezpush-venv/bin/python -m pytest tests/ -q`. No existing test
was changed.

---

## Diagnosis: why all three classes could reach NO ACCOUNTED

One root cause serves all three classes, with a class-specific
aggravator each.

The root cause is classification. `detect_format`
(`event_zero/analyzer.py` line 84) has no branch for a shortcut, an
HTA, or a batch file: anything that decodes as UTF-8 text falls to
the "text / script" label at the end of the function.
`script_analysis` (`event_zero/analyzer.py` lines 145 to 146,
`SCRIPT_EXTS`) claims .py, .sh, .bash, .ps1, .js, .bat, .pl and
.rb, but not .cmd, .hta or .url, and its fallback branch returns
None for every other extension, shebang aside. So for all three
classes the analyzer records no script at all:
`script_analysis` is None, `script_source_full` is None, and three
consequences follow.

- The per-line script ledger in `families.py` never runs, because
  `_scripts` reads the recorded source and there is none. The wave
  1 ledger gate in the verdict (line 1708) is keyed on the same
  recorded language, so it cannot fire either.
- Capability matching receives an empty script text
  (`match_capabilities` is called with the script source or an
  empty string), so script tokens contribute nothing; only the
  raw string list is matched, and the only capability any of the
  three synthetic probes below earned was net-http, from the
  http:// string itself. bitsadmin, certutil and the other
  download primitives are not atoms of the exec-download-run rule
  in `capabilities.py` at all (its string atoms are curl http,
  wget http, downloadstring, invoke-expression and their kin).
- With no chain, no scope hit and no blocker, the accounting
  branch for "script" and "text / script" formats (line 1927)
  grants NO ACCOUNTED on the claim that the file "was fully
  reverse-engineered by reading all of its source", a claim the
  ledger never tested for these classes.

Class aggravators:

- **.url shortcut.** The verdict does parse the target
  (`parse_url_file`, consumed at line 1559), but only to feed the
  connection ledger as data. The ledger entry for a bare-IP host
  classifies as unknown and needs-more-evidence, and the one
  blocker that consumes needs-more-evidence ledger entries (line
  1590) fires only for lookalike and shortener classifications
  and only when the file format is PE, ELF, Mach-O or "script",
  which excludes the "text / script" label these files carry.
  The neighbouring .lnk class has a dedicated dropper chain
  (lolbin plus cradle or URL is PROVEN); the .url class had no
  treatment at all.
- **Double extension.** No code anywhere in the engine examines
  a file name for stacked extensions. A search for double
  extension handling across `event_zero/` returns nothing: the
  name invoice.pdf.cmd was never noticed as a shape, let alone
  weighed.
- **.hta.** Nothing extracts or separately analyses the script
  inside an HTA, and nothing records that an HTA is executed by
  mshta on open. It was judged as inert text.

Probe, run before the fix on synthetic fixtures mirroring the
three adjudicated shapes (a .url to a dotted-quad payload URL, a
.pdf.cmd with a bitsadmin transfer and a start line, an .hta with
a bitsadmin download and a Run call): all three returned
`NO: NO MALWARE`, reason ACCOUNTED, file verdict NO ACCOUNTED,
capabilities at most net-http, no ledger. The three benign
controls (a .url to an ordinary https page, a plain echo .cmd, an
.hta with no remote fetch) also returned NO ACCOUNTED, which is
the correct answer for them, and they still do.

---

## The fix

`event_zero/verdict.py` only, in the wave 1 pattern: findings are
computed from evidence the verdict already holds and are added to
the file's blockers in the per-file loop, next to the truncation
markers (line 1854), so they land in the file's own record, its
why text, and the report's unaccounted list.

- `script_class_findings(name, data)` (line 458) returns findings
  of three kinds. `remote-fetch-and-execute`: a script-class file
  (extension in SCRIPT_CLASS_EXTS: .bat, .cmd, .ps1, .vbs, .vbe,
  .js, .jse, .wsf, .wsh, .hta, .sh, .bash, .py, .pl, .rb) carrying
  a fetch primitive (bitsadmin transfer, certutil -urlcache,
  Start-BitsTransfer, curl or wget fetching, PowerShell download
  methods, Python web fetch, a remote script include, an XMLHTTP
  or WinHttp fetch, mshta or rundll32 aimed at a remote URL)
  together with an execution side (a pipe to a shell,
  Invoke-Expression, Start-Process, a batch start, a script host
  Run call, ShellExecute, shell command execution) or an
  executable payload staged on the download line. mshta and
  rundll32 aimed at a remote URL and a remote script include are
  chains on their own, because the named host program is the
  executor. An HTA needs only the fetch: mshta runs its script
  when the file opens, so the file itself is the executor.
  `url-shortcut-remote-payload`: a .url target that is a remote
  executable payload, meaning the URL path ends in an executable
  extension, or the host is a bare IP and the path is not a page.
  `disguised-double-extension`: a document extension (pdf, doc,
  docx, xls, xlsx, ppt, pptx, rtf, txt, jpg, jpeg, png, gif, zip)
  immediately before an executable extension (exe, scr, com, bat,
  cmd, ps1, vbs, vbe, js, jse, wsf, wsh, hta, msi, jar).
- Each finding becomes a named blocker stating the principle:
  what the file does is decided by content that is not in the
  file, so it is unaccounted by construction; for the double
  extension, that a name is not behaviour (the blocker is
  explicitly not proof) but a file that disguises what it is
  cannot be accounted as what it appears to be. Findings are
  also recorded on the file record as
  `rec["script_class_findings"]`, beside the established blocker
  channel.
- Exemptions mirror wave 1 exactly: a file accounted by byte
  identity (reference hash-match, or a strong manifest hash)
  does not depend on this reading and is not blocked by it, and
  fully enumerated or failed containers are exempt because their
  members are the judged content units.
- `_download_line_payload` (line 436) judges a URL token on its
  path only, never its host. This matters: the first version of
  the helper matched the .com top-level domain of an ordinary
  download host as the DOS executable extension and blocked a
  benign data download. The wave 2 control test caught it before
  the suite ran green, and the helper now strips the host before
  testing the extension.

Regression tests: `tests/test_accuracy_audit_wave2.py`, 12 tests.
The three adjudicated shapes as synthetic fixtures (the .url, the
.pdf.cmd bitsadmin dropper asserting both the chain and the
double-extension finding, the .hta bitsadmin downloader), each
asserting NO is not issued (YES UNACCOUNTED) and the finding is
named; a bare-IP extensionless .url variant; a double-extension
name over benign content, asserting the name alone blocks NO as
unaccounted and nothing more; and controls asserting the blockers
do not fire: a benign .url to an https page, a plain echo .cmd,
an .hta with no remote fetch, a .cmd that mentions an executable
URL in a comment only, and a .cmd that downloads data (a JSON
file by bitsadmin) with no execution side and no executable
payload. One further test asserts the byte-identity exemption: the
dropper bytes hash-matched against a genuine reference still earn
NO, accounted as genuine.

Probe after the fix: the three evil fixtures return
`YES: MALWARE FOUND`, reason UNACCOUNTED, each with its finding
named in the record; the three benign controls return
`NO: NO MALWARE` with no findings.

## Notes and scope

- Judgement call: the fix lives in the verdict, not in the
  analyzer. Adding .cmd or .hta to `SCRIPT_EXTS` in analyzer.py
  was considered and rejected: it would route batch and HTA
  source through the per-line ledger, which is shaped around the
  KMS allowlist and ordinary script structure, and an ordinary
  batch line such as `pause` is neither, so honest batch files
  would collect unaccounted lines and block on the ledger gate
  for a reason unrelated to their behaviour. The verdict-level
  chain test judges the one shape that matters, the fetch and
  execute chain, and leaves the ledger to the languages it was
  built for.
- Judgement call: a fetch alone does not block, except where the
  executor is intrinsic (mshta, rundll32, a remote script
  include, any fetch inside an HTA). A script that downloads data
  and stops there keeps its NO path, as does a script that only
  mentions a URL. This mirrors the wave 1 KMS lesson: the chain,
  not the atom, is the finding.
- Out of scope, noted and untouched: the pre-existing
  exec-download-run string atom "curl http" also matches the
  first nine characters of "curl https", so any file whose
  strings contain a curl command line earns that capability and,
  through the generic chain, a PROVEN download-and-execute
  verdict, whether or not anything is executed. That is a
  false-YES risk in the capability layer, not one of the three
  adjudicated false-NO classes, and wave 2 does not change it.
- Files changed: `event_zero/verdict.py`,
  `tests/test_accuracy_audit_wave2.py` (new), and this log.
- Final full-suite result: **203 passed** in 86.75s
  (`~/ezpush-venv/bin/python -m pytest tests/ -q`), against the
  191 passed wave 1 baseline. No existing test was changed.
