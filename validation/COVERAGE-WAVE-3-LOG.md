# Coverage Wave 3 Log: Every Byte Has an Owner

Date: 2026-11-24. Scope: build wave 3 of the total coverage
programme (`~/workspace/research_notes/event-zero-total-coverage-20261124/report.md`,
gap 12 parser differentials, gap 13 polyglot second formats, the
1A driver matrix row's BYOVD carve-out, and byte completeness for
all classes), implementing fixes 1 and 2 of the accuracy failure
modes report (`~/workspace/research_notes/event-zero-accuracy-failure-modes-20261124-2226/report.md`,
sections 1.5 and 1.6). Method: synthetic fixtures only, built in
the test file from the format specifications. No sample was
downloaded. Prior behaviour was proven by probe before any code
changed (see each section).

Code: new module `event_zero/coverage3.py` (pure Python,
read-only parsers); `event_zero/verdict.py` wires its four
readings into the per-file loop as a coverage wave 3 section
modelled on the accuracy wave 2 and 3 sections. Coverage waves
1 and 2 behaviour is untouched: `containers.py` and
`bytecode.py` are unmodified by this wave.

## Byte-ownership ledger

Prior behaviour (proven by probe): a PE carrying a 613-byte
nonzero overlay was judged exactly like its clean twin (both
UNACCOUNTED under the compiled-binary rule, with no record
anywhere that the overlay bytes existed as a distinct range);
a ZIP archive with a complete PE appended past its end of
central directory reached NO ACCOUNTED, the appended PE
invisible because a fully enumerated container is exempt from
carving and nothing measured the bytes past the archive's
logical end.

Built, in `coverage3.byte_ownership`: a byte-range ledger for
the formats where ownership is tractable today. PE (detailed
internal structural parse: headers, section content, section
slack past the declared virtual size, data directories, the
Authenticode certificate record and any bytes past it, and the
overlay), ELF (header, program and section header tables,
section content), ZIP (local headers and member data with data
descriptors, the central directory located through zipfile's
prepend-adjusted start_dir, the end record, prepended and
appended ranges), TAR (member headers and data blocks, end
blocks, trailing ranges), DEX (the header-declared file size as
the owned extent; bytes past it are appended data), and Mach-O
thin and fat (header, load commands, segment ranges, code
signature superblob; fat slice ranges). Ranges are merged; the
complement is classified per range: all-zero ranges are owned
as verified zero padding, a nonzero unowned range at or below
the named 16-byte tolerance is recorded as alignment residue
and does not cap, and any other unowned range is material,
returned with offset, size, entropy and a reason (overlay past
the last section and the certificate table, section slack past
the declared virtual size, certificate table bytes past the
certificate record, data appended past the end of the central
directory, data prepended before the first zip member, data
appended past the DEX declared size, gap between accounted
structures). In the verdict, a material unowned range is a
named blocker on the file's own record (`rec["byte_ownership"]`
carries the full ledger). An appended archive inside a PE
overlay that was itself enumerated as members is owned by that
container identity, not flagged as overlay.

Exemptions mirror waves 2 and 3: byte identity (hash match or
a strong manifest hash) does not depend on this reading, and a
failed container is already capped as a unit.

Fixtures: clean PE twin (ledger complete), PE with an unowned
overlay (material range at the overlay offset, named overlay),
PE with nonzero section slack past the virtual size (named
section slack), clean ZIP (complete) and ZIP with appended
bytes (named past the end of the central directory), the
repository's real hello_elf fixture (complete) and the same
file with appended bytes (caps), a benign TAR reaching NO at
verdict level and the same TAR with appended bytes capping
with byte-ownership named, and the ZIP-plus-appended-PE probe
case, which no longer reaches NO.

## Dual-parser differential gate

Prior behaviour (proven by probe): the verdict consumed one
parser's view (LIEF, with the stdlib fallback only when LIEF
was absent). Readings taken during the probe: for a PE
declaring five sections with one real table, LIEF returned
phantom and garbage sections, pefile returned the one valid
section with a structural warning, and the engine's fallback
parser read the table at a fixed offset; for a PE whose first
section declares a raw size past the end of the file, pefile
recorded "Error parsing section 0. SizeOfRawData is larger
than file" while LIEF accepted the declaration silently. No
disagreement reached the verdict in either case.

Built, in `coverage3.dual_parser`: PE and ELF files are read
by three parsers, the engine's own detailed structural parser,
pefile, and LIEF (both installed in the environment; pefile is
the second independent parser the research specifies, the
internal parser is the loader-model view). Views are compared
on entry point, machine, the canonical section table (name,
raw size, raw pointer; phantom entries with no name, no raw
bytes and no raw pointer are dropped from every view alike),
and the imported function name set. Three further disagreement
classes are recorded: a parser that cannot read a structure
another parser read (parser failure is itself a differential:
the internal parser refuses a section table that runs past the
end of the file, which is the malformed shape, while another
parser may still produce a view); pefile structural warnings,
excluding its byte-frequency heuristic warning, which fires on
ordinary padded fixtures and is presentation noise, not
structure; and loader-model violations from the internal parse
(entry point outside every mapped section, a section declaring
raw bytes past the end of the file). LIEF's entry point is
normalised by its image base before comparison: LIEF reports
a virtual address where the other parsers report the RVA, a
presentation difference the first full-suite run surfaced on
the coverage wave 2 .NET fixture (LIEF 0x401000 against RVA
0x1000); the gate compares structure, not conventions. In the
verdict, any disagreement is a named blocker on the file's own
record (`rec["dual_parser"]` carries the views compared), and
a gate that cannot field two parsers is itself an
incompleteness cap, in the accuracy wave 3 R3 shape: a NO must
not rest on one parser.

Coverage, stated exactly: PE and ELF only. Mach-O has one
parser in this build (the coverage wave 2 slice parser) and no
second independent parser exists in the codebase to differ
against; ZIP and TAR are read by the container layer and the
ownership ledger's own structural parse, which is a partial
second view (their disagreement surface is the ownership
ledger's local-header and end-record checks, not this gate).
Building second parsers from scratch for those formats was
out of scope by the wave's terms and is named here as the
remainder.

Fixtures: clean PE (three views agree, no disagreements), the
repository hello_elf (internal and LIEF agree), the
five-sections-declared PE (disagreement recorded, and named
at verdict level as a dual-parser differential), and the
inflated-raw-size PE (disagreement recorded).

## Polyglot accounting

Prior behaviour (proven by probe): container detection already
enumerated an appended ZIP inside a PE or behind a GIF
(zipfile locates the end of central directory wherever it
sits), so those members were judged; the invisible cases were
the second identity that is not an archive: a PE appended to a
ZIP or JAR was never carved (a fully enumerated container is
exempt from carving) and never measured (see the ownership
probe above), and a GIF-plus-ZIP file reached NO with the GIF
identity never accounted as an image, only the archive members
judged.

Built, in `coverage3.polyglot_identities`: identity detection
over the whole file (PE at offset 0 or appended with a valid
signature at e_lfanew, ELF at 0 or appended, GIF, PNG and JPEG
at 0, PDF at 0, TAR at 257, ZIP at its first local header or
end record wherever it sits). In the verdict, two or more
identities put the identity list on the file's record
(`rec["polyglot"]`) and each identity must be accounted: the
ZIP identity by enumeration as members; an image identity at
offset 0 by being a complete image under its own format
(GIF trailer, PNG IEND, JPEG EOI at the end of the image's own
extent) in front of an enumerated archive; an appended PE or
ELF by having been carved and analysed in the existing
embedded-payload path; the primary identity by this loop's own
judgement. A TAR beginning past offset 0 is never enumerated
and caps by name. Any identity accounted under none of these
is a named blocker.

Fixtures: identity detection for PE-plus-ZIP and GIF-plus-ZIP
and the single-identity control; the benign GIF-plus-ZIP
polyglot reaching NO with both identities accounted (the GIF
complete, the member judged); the GIF-plus-ZIP whose member
is the bitsadmin dropper shape (member enumerated and judged,
not NO); the PE-plus-ZIP with a dropper script in the ZIP half
(the script is enumerated as a unit and judged, not NO); and
the JAR with an appended PE, which caps with the second
identity named.

## BYOVD carve-out

Prior behaviour (proven by probe): a synthetic driver importing
MmMapIoSpace, MmCopyVirtualMemory, ZwTerminateProcess,
__readmsr, READ_PORT_UCHAR and ZwLoadDriver from ntoskrnl.exe,
given a hash-match genuine reference and a verifying signature
(the probe monkeypatched the signature verifier to verified,
because no osslsigncode exists in this environment to verify a
synthetic fixture), reached NO ACCOUNTED: byte identity and
signature acquitted the capability set outright. Its benign
twin (IoCreateDevice, IoCompleteRequest, ZwClose) reached NO
by the same path.

Built, in `coverage3.driver_capabilities` and wired in the
verdict with NO provenance exemption: a file is a driver by
its .sys name, a native subsystem, an import from ntoskrnl.exe
or hal.dll, or the rootkit module's kernel-driver
identification. Its imports (from the detailed internal parse,
which reads the import directory directly, plus the analyzer's
import list) and a small set of string tokens for objects no
import table carries (the physical memory device name, the
g_CiOptions variable) are matched against the dangerous set:
physical memory access (MmMapIoSpace and its Ex and
locked-pages family, MmAllocateContiguousMemory), virtual
memory access (MmCopyVirtualMemory, KeStackAttachProcess,
KeAttachProcess, MmCopyMemory), MSR access (__readmsr,
__writemsr), port IO (the READ_PORT and WRITE_PORT family and
the __inbyte/__outbyte intrinsic family), process termination
(ZwTerminateProcess, NtTerminateProcess), and the driver-load
and DSE surface (ZwLoadDriver, NtLoadDriver, g_CiOptions).
Any category present is recorded on the driver's record
(`rec["driver_capabilities"]`, categories and evidence
enumerated) and caps the verdict at YES UNACCOUNTED with the
capability set named as the reason, even when the file is
hash-matched to a genuine original or its signature verifies:
provenance vouches for origin, never for what the driver can
be made to do. No new conviction path is added; a driver whose
capability chain meets an existing family standard (the
rootkit-hiding chain, for example) is still convicted by that
standard, and this carve-out only refuses clean.

Fixtures: capability extraction for the dangerous driver (all
six categories, evidence named) and the benign twin (driver,
no capabilities); the dangerous driver with hash-match
reference and verified signature refused clean with the
BYOVD carve-out and MmMapIoSpace named in the blocker; the
benign signed driver with the same provenance keeping its
NO ACCOUNTED.

## Remainder, named (capped or recorded, not implemented)

- Byte-range ownership is not computed for: Java class files
  (the coverage wave 2 parser accounts them at method level
  and fails a method by name on any byte its walk cannot
  account, but it does not emit file ranges, so trailing bytes
  past the class structure are not measured by this ledger);
  the coverage wave 1 container kinds (ISO, VHD, VHDX, QCOW2,
  DMG, deb, rpm, apk, firmware filesystems), whose accounting
  unit is member enumeration: their members are verdict units
  and the container's own bytes are not a content unit, so a
  range ledger over the container file itself is not the
  accounting those formats rest on; PDF and the document
  formats, whose active content already blocks NO under the
  accuracy wave 1 rules; and scripts and text, which are
  accounted by full-source reading. For these formats the
  ledger records nothing rather than pretending coverage, and
  the formats that can reach NO do so on their own accounting
  paths, named here so the boundary is explicit.
- The dual-parser gate covers PE and ELF. Mach-O, ZIP and TAR
  have no second independent parser in the codebase (see the
  gate section above).
- Polyglot detection recognises the identity pairs the current
  format detection can see: native binaries (PE, ELF), the
  three web image formats, PDF, TAR and ZIP. A script polyglot
  (a file that is valid shell and valid Python at once, say) is
  judged under its detected script identity only; a second
  format hidden in metadata or comment fields of an image or
  document is visible only through the carving and document
  rules that already exist.
- The DOS stub range of a PE is owned as structure. Its content
  is not semantically classified beyond the header parse; a
  stub grown far beyond the standard size with high-entropy
  content would be owned by this ledger while being, in
  substance, unexamined. Named here rather than silently
  trusted.
- The vulnerable-driver catalogue check (LOLDrivers-class
  digest lists) is not wired: this wave implements the
  capability rule the research specifies, which needs no
  catalogue, and a pinned catalogue is a maintenance artefact
  that belongs with the verdict-path tool integrations, not
  with this gate.
- Driver capability matching is import and token based. A
  driver that resolves the same primitives dynamically (through
  MmGetSystemRoutineAddress, whose name alone is not in the
  dangerous set because legitimate drivers resolve benign
  routines through it too) presents those primitives only in
  strings the token set does not cover; such a driver is
  capped by the standing unexplained-driver rule unless its
  signature verifies, and the residual is named here.

## Tests

`tests/test_coverage_wave3.py`: 21 tests covering the four
items in the shapes above (module-level ownership, dual-parser
and capability cases, and verdict-level positives and
controls). No existing test was changed. Full suite result is
recorded below at the end of the wave.

Full suite, run at the end of the wave with
`~/ezpush-venv/bin/python -m pytest tests/ -q`: 308 passed, 0
failed (the 287-test baseline intact, 21 new wave 3 tests, no
existing test changed), in 249.09s. The first full run of the
wave gave 307 passed and 1 failed
(tests/test_coverage_wave2.py::test_dotnet_benign_reaches_no),
root cause in this wave's gate, not in the fixture: LIEF
reports that assembly's entry point as a virtual address
(0x401000, image base plus RVA) where the internal parser and
pefile report the RVA (0x1000). Fix in
`event_zero/coverage3.py`: the LIEF view's entry point is
normalised by the image base before comparison, as recorded
in the dual-parser section above. The wave 1, 2 and 3 test
files were then re-run together (84 passed) and the full
suite re-run end to end for the result above.
tests/test_final.py::test_export_cli passed in both full runs
and did not need its standalone re-run.
