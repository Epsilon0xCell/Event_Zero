# Event Zero Verdict Engine: Accuracy Audit

Date: 2026-11-24. Scope: read-only audit of the verdict engine in
`event_zero/` (verdict.py, analyzer.py, families.py, capabilities.py,
unpack.py, disasm.py, emulation.py, virt.py, firmware.py, signing.py)
against the accounting contract: YES the moment malicious behaviour is
proven OR anything remains unaccounted; NO only when every file is
byte-identical to a genuine signature-valid original or a fully
reverse-engineered diff classified expected-benign, plus clean
behavioural accounting. A false NO is the release-blocking failure
class.

Method: full read of the verdict path, plus by-construction probes run
in /tmp against synthetic material only (a locally compiled C hello
program, hand-built zip/tar/PDF files, and hand-written scripts). No
malware was downloaded or executed. Probe results are quoted verbatim
where a defect is marked PROVEN BY PROBE.

Test suite at audit time: `~/ezpush-venv/bin/python -m pytest tests/ -q`
gives **167 passed** in 56.71s.

Severity key: FN = false-NO risk (release-blocking class), FY =
false-YES risk (a PROVEN claim or a block the evidence does not carry),
CORR = correctness or determinism.

## Critical: proven false-NO paths

### 1. FN, PROVEN BY PROBE. A lone compiled binary earns NO from `find_patch_evidence` on a keyword or a NOP run
File: `event_zero/verdict.py`, accounting branch at line 1476, fed by
`find_patch_evidence` at lines 565 to 585.
Mechanism: for a compiled PE, ELF or Mach-O with no reference and no
valid signature, the NO branch fires when `find_patch_evidence` returns
anything. That function returns evidence for a run of five or more
0x90 bytes (ordinary alignment padding in compiled code), a run of
eight or more zero bytes after a nonzero byte, or any string in the
file containing a word from LICENSE_WORDS or the substring "crack".
None of that proves the binary is an explained crack; it is not a
diff, it names no patch, and no region capability check runs. The
verdict text then claims "every region was decoded", which is false.
Probe: a GCC-compiled hello program whose only notable string is
"license check routine" (section .plt.sec removed so the protector
false positive in defect 15 does not mask the path) received
`NO: ACCOUNTED` with the why text "Accounted as the explained crack:
the crack patch was identified and explained from the file itself".
Fixture: compile any hello-world C program containing the string
"license check routine", strip nothing else, run the verdict with no
reference. Expected NO today; contract answer is YES UNACCOUNTED.
Minimal fix: delete this NO branch for compiled binaries. Patch
evidence may annotate a diff-based accounting (where a genuine
reference exists), but a binary with no reference and no valid
signature is unaccounted by definition. At minimum, require a named
crack pattern plus a passed region capability check, the same bar the
diff path is supposed to meet, and never let a bare keyword qualify.

### 2. FN, PROVEN BY PROBE. The report string list is capped at 2,000 entries and every judgement layer reads only the capped list
File: `event_zero/analyzer.py` line 300 (`"all": all_strings[:2000]`),
consumed at `event_zero/verdict.py` lines 1193 to 1195 (strings_blob,
scope test, tampering findings) and `event_zero/families.py` line 29
(`_blob`, used by every family detector).
Mechanism: strings past entry 2,000 do not exist for capability
matching inputs that flow through the report, for the Monero wallet
regex, for ransom and KMS markers, or for the scope test. Nothing
records that truncation happened, so no unaccounted marker is raised.
Probe: a script with a hidden stratum pool string early and a
Monero-shaped wallet string after 2,100 filler strings received
`NO: NO MALWARE (ACCOUNTED)`. The identical script with the wallet
string near the top received `YES: MALWARE (PROVEN)`. The verdict
flips purely on string position.
Fixture: the two scripts above; the late-wallet variant must be YES.
Minimal fix: judgement layers must consume the uncapped string set
(or a digest-complete index of it), and if any cap is kept for report
display, the verdict path must treat "string list was truncated" as
an unaccounted marker for that file.

### 3. FN, PROVEN BY PROBE (partially) and by code read. Script accounting covers only the first 20,000 characters, and the line ledger only the first 4,000
File: `event_zero/analyzer.py` line 152 (`"source": text[:20000]`),
line 304 (`script_source_excerpt` is `source[:4000]`);
`event_zero/families.py` lines 497 to 526 (the ledger runs on the
excerpt); `event_zero/verdict.py` line 1473 (the script NO branch).
Mechanism: capability matching for scripts uses the truncated source;
the per-line ledger that claims "every behaviour enumerated" sees at
most the first 4,000 characters. A script longer than that has most
of its behaviour unexamined while the NO text asserts the whole
source was read. No truncation marker reaches the verdict.
Fixture: a 30,000 character benign-looking script whose final lines
open a socket and write a persistence entry. Today the tail is
invisible to the ledger and to script capability matching.
Minimal fix: run the ledger and script capability matching over the
full decoded source regardless of display caps, and add an
unaccounted marker whenever any part of a script could not be decoded
or was skipped.

### 4. FN, PROVEN BY PROBE. Unaccounted script lines block NO only for activators
File: `event_zero/verdict.py` line 1324.
Mechanism: when the script line ledger lists lines it cannot classify,
the blocker is added only if the file's claimed function is
"activator". For every other claimed function the same unaccounted
lines are silently ignored and the file earns NO under text claiming
every behaviour was enumerated and classified.
Probe: a five-line patcher script containing one nonsense call line
received `NO: ACCOUNTED` while its own ledger in the same report
listed that line under "unaccounted".
Fixture: the probe script. Any script whose ledger has unaccounted
lines must not be NO, whatever it claims to be.
Minimal fix: drop the claimed-function condition. Ledger unaccounted
lines are unaccounted behaviour; they block NO for every script.

### 5. FN, PROVEN BY PROBE. Document and message analyzers are never consumed by the verdict, so active-content documents earn NO "as data"
File: `event_zero/verdict.py` line 1479 (data NO branch);
`event_zero/analyzer.py` lines 311 to 315 compute `analyze_pdf`,
`analyze_office`, `analyze_dotnet`, `analyze_apk` and
`analyze_email` results that verdict.py never reads.
Mechanism: a PDF is not in EXECUTABLE_FORMATS, so unless a generic
capability chain fires on its strings, it is "accounted as data". The
PDF feature analysis (JavaScript, OpenAction, Launch, embedded files)
exists in the report but has no path to a blocker or a chain. The
same applies to email: `analyze_email` lists attachments, but
attachments are never enumerated as verdict entries, so a malicious
attachment inside an .eml is never judged at all.
Probe: a minimal hand-built PDF containing /OpenAction, a /JavaScript
action and a /Launch action received `NO: ACCOUNTED` with the why
text "Accounted as data: the file was fully read, it is not
executable code, and it carries no malicious capability".
Fixture: the probe PDF; also an .eml carrying a script attachment.
Minimal fix: feed document features into the verdict: any active
content feature (embedded JavaScript, auto-run action, launch action,
embedded file, macro stream not fully accounted) is an unaccounted
marker at minimum, and enumerate .eml attachments as entries exactly
like archive members.

### 6. FN, PROVEN BY PROBE. The KMS baseline deletes real chains, and its "external" test treats all of 172.0.0.0/8 as local and ignores bare domains
File: `event_zero/verdict.py` lines 1352 to 1354 (chain suppression),
`event_zero/families.py` lines 36 to 45 (`kms_baseline`) and lines
243 to 247 (scope test external check).
Mechanism: `kms_baseline` fires when the substring "kms" appears
anywhere in the file's strings or name, or when markers such as
"1688" appear anywhere (a filler string containing the digits 1688
tripped it during this audit's first probe run). When it fires, the
verdict loop deletes the persistence-plus-c2 and generic net chains
from that file's chain list outright. Separately, the external check
counts an IP as external only if it does not start with "10.", "192."
or "172.", which classifies public addresses such as 172.217.14.206
(Google) as local, and it never counts a bare domain as external at
all. A file named like a KMS tool that persists and connects to a
public 172 address therefore loses both its chain and its scope hit.
Probe: one script whose comments mention schtasks and a connect to
172.217.14.206 was run twice. Named `kms_activator.py`:
`NO: NO MALWARE (ACCOUNTED)`. Same bytes named `renewal_tool.py`:
`YES: MALWARE (PROVEN)`.
Fixture: the probe pair. The name of a file must never acquit its
behaviour.
Minimal fix: remove the chain deletion. KMS context may downgrade a
chain to a note only when the destination is verifiably a local KMS
endpoint, judged with a real private-range test (172.16.0.0/12, not a
"172." prefix) and with domains resolved as external unless they are
provably internal names. The baseline test itself should require KMS
evidence in behaviour-bearing strings, not a substring anywhere.

### 7. FN, PROVEN BY PROBE. `classify_diff` classifies any small equal-length change as "license-flag-flip" with no license context, and the region capability check is vacuous for code
File: `event_zero/verdict.py` lines 870 to 877 (`_crack_pattern`),
lines 800 to 830 (`_region_capability_check`), accounting at lines
1490 to 1510.
Mechanism: the pattern cascade tries the license and checksum
branches first, then falls through: any replace region of equal
length with at most 4 differing bytes in a region of at most 64 bytes
is named "license-flag-flip" even when the surrounding context
contains no license, integrity or signature content at all. The
region capability check then profiles only the enclosing printable
string spans; for a pure code or data region there are no spans, so
the check passes trivially. A one-instruction call-target redirection
(a classic crack or backdoor patch) satisfies both gates.
Probe: a genuine settings script and a copy with `LIMIT = 1000`
changed to `LIMIT = 9999` (no license wording anywhere in the file)
produced a diff ledger entry classified `expected-crack` with pattern
`license-flag-flip`, and the release verdict was `NO: ACCOUNTED`.
Fixture: the probe pair; also a compiled genuine/patched pair where
the patch rewrites a call target inside a code region with no strings.
Minimal fix: the flag-flip branch must require positive license or
integrity context (the words or the check structure) in the region
context, not merely the absence of checksum words. The capability
check must profile the region's decoded instructions or bytes, not
only enclosing strings, and a region with nothing profiled must fail
the check, not pass it.

## High: the two known probe defects, re-verified

### 8. FY (proof integrity), PROVEN BY PROBE. Known defect (a) is STILL PRESENT: a container that fails enumeration is judged as content and can be PROVEN
File: `event_zero/verdict.py` line 1158 (`container_entry` requires the
file to be in the expanded set), line 1221 (chains computed for
non-container entries), line 1446 (the `if file_yes:` branch runs
before the failed-container blocker is consulted in accounting).
Mechanism: a zip whose member CRC is corrupted fails expansion, so it
is recorded as a failed container and does appear in the unaccounted
list. But because it is not in the expanded set, `container_entry` is
False, so capability chains, family chains, the scope test and carving
all run over the raw container bytes, and a chain found in the stored
member bytes produces YES PROVEN. The correct output is YES
UNACCOUNTED (or an OPEN case): the sample could not be enumerated, so
nothing in it is proven either way, and a PROVEN token printed for
unreadable content breaks the proof contract even though the headline
direction (YES) happens to match.
Probe: a stored zip whose only member is a short stealer script, with
the member CRC byte flipped in the central directory, received
headline `YES: MALWARE FOUND`, reason PROVEN, file verdict
`YES: MALWARE (PROVEN)`.
Fixture: the probe zip. Expected after fix: YES UNACCOUNTED naming
the failed container, with no chain verdicts computed from its raw
bytes.
Minimal fix: compute `failed_container` before any content judgement
and treat failed containers exactly like enumeration units for
judgement purposes (no chains, no scope, no carve verdicts from raw
bytes), letting the existing blocker produce UNACCOUNTED.

### 9. FY (proof integrity), PROVEN BY PROBE. Known defect (b) is STILL PRESENT for tar: the enumeration-unit exemption depends on the container's raw bytes passing a text heuristic
File: `event_zero/verdict.py` line 1158 (exemption requires the
container's format to not be in EXECUTABLE_FORMATS) and
`event_zero/analyzer.py` lines 60 to 97 (`detect_format` has no tar
magic branch).
Mechanism: zip containers are recognised by magic and get format
"ZIP archive", so the exemption holds. Tar has no magic branch in
`detect_format`, so a tar falls through to the UTF-8 text heuristic.
A tar whose header block and first member decode as text (the common
case when the first member is a text file) is classified
"text / script", which IS in EXECUTABLE_FORMATS, so `container_entry`
is False and the tar's raw bytes are judged as content, including the
member article's text. The identical article inside a zip is exempt.
Whether a tar is exempt therefore depends on its first member's
bytes, which is layout-dependent and wrong.
Probe: a tar containing the same banking article text used by the
zip regression test produced file verdicts
`article.tar = YES: MALWARE (PROVEN)` (banking chain over the raw tar
bytes) and `article.tar!banking_article_0.txt = NO: ACCOUNTED`.
Fixture: the probe tar, plus the same tar with a binary first member
(exemption applies) to show the layout dependence.
Minimal fix: detect tar by its ustar magic (offset 257) in
`detect_format`, and base the enumeration-unit exemption on
`container_kind` / expansion membership rather than on the analysed
format string. Add a tar regression test mirroring the zip banking
article test; today the test suite covers the zip shape only
(`tests/test_container_failclosed.py`).

### 10. FN. An installer inside a folder is never treated as an installer
File: `event_zero/verdict.py`, `installer_kind` is consulted only in
the single-file branch of `enumerate_subject` (line 719). Folder
members get no installer test.
Mechanism: a single-file Inno Setup or NSIS subject always blocks
("its dropped files are unaccounted"), which is correct. The same
file as a member of a folder is judged as an ordinary file, so an
installer EXE whose own bytes raise no chain is accounted on other
grounds and its payload is never treated as unaccounted.
Probe: the stripped hello binary carrying an "Inno Setup" string,
placed alone as `release/setup.exe` in a folder, gave the folder
verdict `NO: NO MALWARE (ACCOUNTED)`.
Fixture: any folder containing an installer EXE with inert bytes.
Minimal fix: run `installer_kind` for every enumerated entry, not
only for single-file subjects, and attach the installer blocker to
that entry.

## High: further false-NO and proof-integrity defects (code-read)

### 11. FN. A user-supplied CRC32 (.sfv) manifest match confers full NO
File: `event_zero/verdict.py` lines 1050 to 1075 (`ref_manifest`) and
line 1106 (an 8-hex-digit expected value is checked against CRC32).
Mechanism: when a release folder carries a manifest, a file whose
CRC32 matches the listed value is "verified unchanged from the
genuine release" and earns NO. CRC32 is a checksum, not a hash:
colliding files are craftable by construction, so a substituted file
can carry the listed CRC32 while doing anything. The code comments
acknowledge CRC32 is weak, yet the accounting branch treats the match
as proof.
Fixture: an .sfv listing a benign file's CRC32, plus a script whose
bytes are padded to collide on that CRC32 (standard CRC32 patch
construction, all synthetic).
Minimal fix: treat CRC32 and MD5 manifest matches as corroboration
only, never as the sole basis for NO; require SHA-256 (or SHA-1 at
minimum with a warning) for a manifest-based accounting.

### 12. FN. Carved embedded payloads are chain-checked but never accounting-checked
File: `event_zero/verdict.py` lines 1230 to 1255.
Mechanism: a PE, ELF, script or archive carved out of a data or text
file is checked only for capability chains and for being undecodable.
If it has no chain, it contributes nothing: no signature check, no
reference comparison, no patch evidence, no unaccounted marker. The
outer file can then earn NO while containing a complete embedded
executable whose behaviour was never accounted. `carve()` also has
no cap on the number of payloads it will return.
Fixture: a text file with an appended compiled hello binary (no
chain-bearing strings) as the only member of a release. Expected
today: NO with the payload invisible in the accounting. Contract
answer: the payload is an unaccounted unit.
Minimal fix: every carved payload that decodes to an executable
format must either be accounted (signature or reference) or raise an
unaccounted marker on its host file, and cap the carve count with an
unaccounted marker when the cap is hit.

### 13. FY. The DLL sideload triad convicts on shape alone; the API-by-API accounting its rationale describes is never performed
File: `event_zero/verdict.py` lines 1405 to 1428.
Mechanism: the rule fires PROVEN when a folder holds a signed EXE, an
unsigned DLL that is not hash-matched, and any file classified
"unknown binary data" of at least 64 bytes. The code comments say the
triad is malicious only because the DLL's imports were accounted API
by API and the sidecar matched nothing legitimate, but no such import
accounting exists in the code. A legitimate unsigned plugin DLL
beside an encrypted game asset or save file satisfies the triad.
Fixture: a folder with a signed hello EXE, an unsigned hello DLL and
a 64-byte random data file. Expected today: YES PROVEN. 
Minimal fix: implement the import accounting the rationale claims
(loader APIs present, exports matching the host's imports, sidecar
consistent with the DLL's decryption behaviour), or downgrade the
triad to UNACCOUNTED until that accounting exists.

### 14. FN (known limitation 3, confirmed still open). Firmware flags never reach the verdict, and there is no combined SMM plus network flag
File: `event_zero/firmware.py` lines 48 to 56; `event_zero/verdict.py`
contains no reference to the firmware analysis at all.
Mechanism: the firmware analyzer raises "DXE drivers with network
protocol access" and "contains SMM code" as separate flags, never
combined, and in any case the flags feed only the analyzer's risk
score. The verdict consumes neither flag. A firmware image is blocked
only by generic paths (unknown binary data), so a signed or
patch-evidence-bearing firmware image containing an SMM driver with
network reach can earn NO without the SMM plus network combination
ever being evaluated per driver.
Fixture: a synthetic UEFI image layout with one SMM driver carrying
network protocol GUIDs and a valid signature on the image. 
Minimal fix: add the combined per-driver flag in firmware.py (SMM
module that also references network protocols) and consume firmware
flags in verdict.py as blockers for any NO.

### 15. FY and CORR, PROVEN BY PROBE. The Safengine protector pattern ".se" matches the standard GCC section ".plt.sec", flagging ordinary ELFs as virtualized
File: `event_zero/virt.py` line 34.
Mechanism: protector detection substring-matches section names.
".se" is a substring of ".plt.sec", which GCC emits in ordinary
dynamically linked ELFs, so a stock hello-world binary is reported
as protected by Safengine with its functions "unaccounted". The
direction is fail-closed (it blocks NO), but it convicts nearly every
GCC-built ELF of VM protection, destroys precision, and masks real
accounting paths in testing (it masked defect 1 until the section was
stripped).
Probe: the unstripped GCC hello binary received a blocker reading
"a virtualizing protector was detected (Safengine). Census: 2
indirect jump site(s)..." while the same binary with .plt.sec removed
did not.
Fixture: any GCC-compiled dynamically linked ELF.
Minimal fix: match section patterns on whole section names or with a
trailing boundary (exact ".se" section, or names starting with the
pattern followed by a non-name character), and add a regression test
that a stock GCC ELF is not protector-flagged.

### 16. CORR, PROVEN BY PROBE. For a single-file installer subject, the file table and the headline contradict each other
File: `event_zero/verdict.py` lines 719 to 728 (the installer blocker
goes to the release-level blockers) versus the per-file accounting at
lines 1446 to 1483.
Mechanism: the installer blocker is recorded only in the global
blockers list, not in the file's own blockers, so the file entry
itself can earn NO: ACCOUNTED while the headline says YES UNACCOUNTED
because that same file's contents are unaccounted. The manifest
contract says the per-file table is the accounting; here the table
claims the installer is accounted.
Probe: the stripped hello binary containing an "Inno Setup" string,
run as a single-file subject, produced file verdict `NO: ACCOUNTED`
and headline `YES: MALWARE FOUND (UNACCOUNTED)` with the installer
reason in the release unaccounted list.
Minimal fix: attach the installer blocker to the file's own record so
its per-file verdict is UNACCOUNTED, keeping the release roll-up as
is.

## Medium: caps, determinism, and family detector calibration

### 17. FN and CORR. Extraction directory names use Python `hash()` on the archive path: nondeterministic across runs and collision-prone
File: `event_zero/verdict.py` line 763.
Mechanism: `dest` is built from `abs(hash(rel)) % 99999`. String
hashing is randomised per process, so the same archive extracts to a
different directory name on every run, and with only 99,999 buckets
two archives in one release can collide into the same directory,
merging or overwriting each other's members. Entries store absolute
paths into that directory, so after a collision one archive's member
can be judged on another archive's extracted bytes. Both properties
are wrong for an engine whose receipts claim byte-exact accounting.
Fixture: a release with many small zips; run the verdict twice under
different PYTHONHASHSEED values and compare extraction paths and
per-file hashes.
Minimal fix: derive the directory name from the archive's SHA-256
plus depth and an index, which is deterministic and collision-safe.

### 18. FN. Analysis caps end silently with no unaccounted marker: disassembly window, emulation, entry-stub gaps, entropy map, symbol list
Files: `event_zero/analyzer.py` lines 216 to 218 (code window capped
at 200,000 bytes) and line 128 (symbols capped at 500);
`event_zero/disasm.py` line 14 (4,000 instruction cap);
`event_zero/emulation.py` line 45 (500 instruction cap);
`event_zero/virt.py` `trace_entry_stub` (gaps are recorded in the
trace record but never become blockers; verdict.py uses the trace
only for coverage counts); `event_zero/unpack.py` line 76
(`entropy_map` covers only the first 16,384 bytes, yet its regions
feed the logic-bomb opacity test and the sideload sidecar test).
Mechanism: each cap is defensible as engineering, but none of them
raises an unaccounted marker when it truncates. Code past the
disassembly window, behaviour past the emulation budget, and entropy
past 16 KB are simply absent from the evidence while NO text can
claim full accounting.
Fixture: a compiled binary with a chain-bearing routine placed past
byte 200,000 of the code section; a file whose only high-entropy
region starts past byte 16,384.
Minimal fix: when a cap truncates material that a judgement depends
on, record the truncation in the report and surface it as an
unaccounted marker for NO purposes (annotation is fine for YES).

### 19. CORR (determinism). Signature-based NO depends on whether osslsigncode happens to be installed
File: `event_zero/unpack.py` lines 193 to 213 (`pe_signature`).
Mechanism: a PE earns the signature branch of NO only when
osslsigncode is present and returns success. The same file on a
machine without the tool falls through to other branches, so verdicts
are environment-dependent. The check is also returncode-only: any
certificate chain the local tool accepts counts as a genuine
publisher signature. The behaviour is disclosed in the code comments,
but the run receipt does not record whether the tool was present, so
two receipts for the same file can disagree without any field
explaining why.
Fixture: run the verdict on a self-signed PE with and without
osslsigncode on PATH and compare.
Minimal fix: record signature-tool presence and outcome class in the
receipt's environment coverage, and require the verification to name
a chain to a trusted root before the NO branch may use it.

### 20. FY. Family detectors: PROVEN rules rest on single substrings, and several benign-twin discriminators are weaker than the rules they guard
File: `event_zero/families.py` throughout; capability string evidence
in `event_zero/capabilities.py` is substring matching, which these
rules inherit.
Specific weaknesses, each a conviction or an acquittal resting on
less than the contract allows:
- Stealer (lines 66 to 101): class hits are substrings, so "discord"
  anywhere is a class hit and "tdata" matches inside "setdata". The
  config rule convicts on ONE stealer-config capability, which is one
  substring atom such as "ScanFiles" in any string. The staging sink
  is a file-write capability plus ".zip", "appdata" or "%temp%"
  appearing anywhere in strings.
- Keylogger (lines 136 to 149): capture capability plus file-write
  plus the substring "/tmp/" or "%appdata%" anywhere convicts. A
  benign hotkey tool that logs to a temp file satisfies this shape.
- RAT (lines 176 to 193): the config rule accepts "host=" and "port="
  substrings, or an IP plus a loose port regex, with three generic
  command words ("shell", "download", "upload" class vocabulary)
  completing the conviction.
- Banking (lines 232 to 244): three bank-name substrings in any code
  file convict, with no SDK or overlay discriminator; "paypal" alone
  counts as one of the three. Probe B showed these atoms firing over
  article text inside a tar.
- PPI (lines 380 to 391): unlike its adware sibling, the PPI rule has
  no disclosure check at all, so a disclosed affiliate installer with
  a callback convicts identically to a hidden one.
- Miner (lines 291 to 330): the concealed twin treats the substrings
  "watchdog", "fullscreen" and "taskmgr" as concealment, all common
  in legitimate miner and monitoring code, while the disclosed twin
  requires marketing phrases ("your wallet", "your earnings") that
  real XMRig-style configurations do not carry, so the own-miner
  acquittal is nearly unreachable and honest miners convict as
  concealed.
- Beacon config parser (lines 408 to 483): a "public_key" record
  accepts any 256 bytes at any offset under two XOR keys, and four
  records including one such blob convict as a Cobalt Strike beacon.
  Large benign files with high-entropy regions are a real false
  positive surface, and the parser runs on every file in the verdict
  loop, so it is also a standing performance cost.
Fixture ideas: a benign hotkey logger writing to %appdata%; a text
file containing "host=" and "port=" documentation plus three command
words; a disclosed affiliate installer sample; a large benign binary
with several 256-byte high-entropy regions for the beacon parser.
Minimal fix: require token-boundary or multi-atom evidence for class
hits, give PPI the same disclosure test as adware, rebuild the miner
twins around configuration evidence (pool, wallet, donation settings)
rather than marketing phrases, and require beacon records to parse
with internal consistency (matching lengths and checksums) before any
single record type counts toward PROVEN.

### 21. FN. Two more weak-evidence branches inside `classify_diff`
File: `event_zero/verdict.py` lines 889 to 899 ("wrapper-removal") and
lines 907 to 912 (the CRC branch of "benign-repack").
Mechanism: wrapper-removal classifies the deletion of up to 8,192
mostly non-printable bytes as an expected crack when the 256-byte
context merely contains "drm" or "protection"; what was removed is
never capability-profiled, so deleting an encrypted payload or a
check routine qualifies equally. The benign-repack CRC branch accepts
a same-CRC content swap as benign when the capped string lists are
60 percent similar, a threshold two related builds clear easily.
Fixture: a genuine/patched pair where the patch deletes a 4 KB
opaque region next to the string "protection"; a pair of builds
sharing a CRC with 60 percent string overlap and one added chain.
Minimal fix: profile removed bytes with the region capability check
before classifying a deletion, and drop the string-similarity route
to benign-repack in favour of the named-section and resource tests
that already exist beside it.

### 22. CORR. Remaining determinism and accounting nits
- Baseline manifest matching stops at the first 100 baseline entries
  (`event_zero/verdict.py` line 1052, `bent[:100]`), so genuine files
  listed later are reported missing from the baseline. Fail-closed,
  but a correctness defect in the accounting text.
- Folder enumeration order comes from `os.walk`, so the per-file
  order in reports can vary between filesystems. The ledger root is
  built from a sorted tree hash and is not affected; only the human
  facing order moves.
- The verdict report's coverage counts (`files_emulated` and friends)
  describe the analyzer's emulation of shellcode-like files, not
  execution of the subject; the receipt copies them faithfully, but
  readers should not mistake them for dynamic coverage of the sample.

## Checked and found sound

- Zip and tar extraction (`_safe_extract_zip`, `_safe_extract_tar` in
  verdict.py) fail closed on every branch this audit exercised:
  member count, total size and compression ratio caps raise; CRC and
  extracted-size mismatches raise; encrypted members raise; path
  escapes raise; non-regular tar members (links, devices, fifos)
  raise. Depth-limit archives land in the unexpanded set and block NO.
- Container kinds that cannot be enumerated by design (7z, rar, cab,
  OLE and unknown containers) are recorded as unaccounted units and
  block NO; they are never silently passed.
- Unknown-format files block NO; a file whose analysis raises is
  converted into a blocker by the verdict loop rather than classified.
- Single-file installer and MSI subjects always block with an adapter
  handoff message; the failure mode is the folder case in defect 10,
  not the single-file case.
- The KMS external test counts any URL in a file as external contact,
  which is the conservative direction; the defect is confined to bare
  IPs and domains (defect 6).
- `classify_link` handles vendor-domain lookalikes with explicit
  suffix and label checks (a lookalike host is classified as a
  phishing or impersonation link, not as the vendor).
- The fileless family rule fails closed: when its evidence blob cannot
  be decoded, it records an unaccounted blocker instead of passing.
- The diff path's outer gates are sound in shape: a NO through the
  diff requires a changed-file set fully covered by the ledger, every
  region classified, no new capabilities in the subject, and (for
  activators) a clean script ledger. The weaknesses are inside the
  region classifier (defects 7 and 21), not in the gate structure.
- Signing and receipts (signing.py): the wall-clock `issued_utc` is
  excluded from the signed core and from the ledger root, the run id
  is derived from content hashes, and the ledger tree hash is sorted
  before hashing, so the same sample, reference, tool version and rule
  pack reproduce the same ledger root. No timestamp or environment
  value was found inside the signed determinism inputs.
- Evasion and rootkit flag modules (evasion.py, rootkit.py) feed the
  analyzer's risk score and capability evidence only; no path was
  found where their absence acquits a file in the verdict.
- The firmware analyzer's per-format parsers raise on malformed input
  and the failures surface as analysis errors (which block), not as
  clean results; the firmware gap is the missing verdict wiring in
  defect 14, not silent parsing.

## Summary for the release gate

Seven defects are proven by probe, five of them false-NO paths
(defects 1, 2, 4, 5, 6, 7, with 3 proven by code read and partially by
probe). Known defect (a) is still present (defect 8), known defect
(b) is still present for tar through the format heuristic (defect 9),
and known limitation 3 is confirmed open (defect 14). Under the
contract, defects 1 to 7 each independently block a release that
claims NO verdicts are proof-backed. Test suite: 167 passed.
