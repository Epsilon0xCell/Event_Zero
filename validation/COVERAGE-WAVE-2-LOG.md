# Coverage Wave 2 Log: Bytecode Accounted at Method Level

Date: 2026-11-24. Scope: build wave 2 of the total coverage
programme (`~/workspace/research_notes/event-zero-total-coverage-20261124/report.md`,
ranked gaps 3, 4 and 5, and the Mach-O matrix row): Java class
files and JARs, .NET assemblies at IL level, Android DEX inside
APKs, and per-slice Mach-O accounting with code signature and
entitlement extraction. Method: synthetic fixtures only, every
one hand-built in the test file from the format specifications
(JVM class file format, ECMA-335, the DEX format, the binary
Android XML format, the Mach-O format). No Java, .NET or Android
toolchain exists in this environment, and no sample was
downloaded. Prior behaviour was proven by probe before any code
changed (see each section).

Code: new module `event_zero/bytecode.py` (pure Python,
read-only parsers, one section per ecosystem, each stating its
own depth in its docstring); `event_zero/verdict.py` wires the
parsers into the per-file loop as a bytecode section modelled on
the accuracy wave 2 and 3 sections (same exemptions: byte
identity does not depend on this reading; a failed container is
already capped as a unit), adds a bytecode branch to the final
accounting decision, expands fat Mach-O binaries into slice
units in `enumerate_subject`, and reconciles JAR entry points
and APK components across units after the loop;
`event_zero/analyzer.py` labels Java class files and DEX files
before the Mach-O magic can claim them, and labels binary
Android XML so a manifest cannot fall through to the
unknown-format blocker. Two collisions were caught by reading
before the run: the fat splitter must not claim a Java class
file (CAFEBABE is both magics; the class check runs first in
`split_macho_fat` as well), and the binary manifest needed its
own format label for the reason above. Coverage wave 1
behaviour is untouched.

Verification status, stated plainly: the Java and .NET parsers
were exercised against the fixtures during the build and their
outputs read directly (results in the sections below). Partway
through the build, a system security notice flagged a tool
result and halted all further code execution in the session, so
the DEX, AXML and Mach-O parsers, the verdict wiring and the
test file were completed as written code and had NOT been run
at the time of the original writing.

Verified after the repair pass recorded at the end of this
log: the full suite in `~/ezpush-venv` reports 287 passed and
zero failures (252 baseline tests plus the 35 tests in
tests/test_coverage_wave2.py), run 2026-11-24 after the repair.
The operator's first verification run, before the repair,
reported 275 passed and 12 failed, all 12 in
tests/test_coverage_wave2.py; the repair section below lists
each failure, its root cause, and where its fix landed.

## Java class files and JARs (gap 3)

Prior behaviour (proven by probe): a .class file was labelled
"Mach-O" (the CAFEBABE magic collides with the fat Mach-O
magic) and judged UNACCOUNTED with zero bytecode read; the
benign and hostile fixtures were indistinguishable. A JAR
enumerated its members, but class members were unaccounted
pseudo-Mach-O entries, and a signer's CERT.RSA blocked an
otherwise benign signed JAR as "unknown binary data".

Built, in `bytecode.py`: a complete class-file parser. The
constant pool is parsed in full (every tag, including the
two-slot Long and Double entries), fields and methods are
walked, and every Code attribute is disassembled with a full
JVM opcode table, so each method body is decoded instruction
by instruction and any byte the walk cannot account for fails
the method by name. Capability and reference extraction runs
over the decoded instructions: URL and socket opens are the
fetch set; Runtime.exec and ProcessBuilder are the execution
set; Class.forName, ClassLoader.loadClass, Method.invoke,
Class.newInstance, Constructor.newInstance and
ClassLoader.defineClass are the dynamic set. A fetch and an
execution call in one class form the chain
`bytecode-fetch-execute`; URLClassLoader use together with a
remote URL constant forms `bytecode-remote-code-loading`. JAR
accounting reads the manifest (with continuation-line
unfolding), Main-Class and Class-Path, and inventories signer
information: every .SF signature file, whether its signature
block (.RSA, .DSA or .EC) is present, and the digest
algorithms it declares.

Parser depth, stated exactly: there is no operand-stack
dataflow. A dynamic-load target is resolved only when the
string or class constant is loaded immediately before the
call in the same method; any other target shape is named
unaccounted rather than guessed. invokedynamic is resolved
only for the known JDK bootstrap factories (LambdaMetafactory,
StringConcatFactory); any other bootstrap is named
unaccounted. Targets in platform packages (java/, javax/,
jdk/, sun/, com/sun/, kotlin/, scala/) and classes defined in
the same submission (collected in a verdict pre-pass) count as
resolved. JAR signature blocks are inventoried, NOT
cryptographically verified. Nested JARs route through the
existing container expansion and its depth limit.

Wired into the verdict: a fully accounted class earns the
bytecode branch of the final decision (NO ACCOUNTED at method
level); a parse failure caps by name; each unresolved dynamic
target is a named blocker on the class's own record; chains
are yes reasons; Class-Path entries go through the wave 3 R1
reference disposition; a signer file with no signature block
caps the JAR; after the loop, a JAR whose declared Main-Class
is not among its enumerated members is capped on the JAR's own
record. JAR signature members are exempt from the
unknown-format blocker (they are identified DER or digest
data, inventoried by the JAR accounting).

Observed during the build (probe, read directly): the benign
class parsed, accounted, no unaccounted items; the hostile
class parsed with the `bytecode-remote-code-loading` chain and
unaccounted items naming the URLClassLoader plugin.jar load
and the loadClass("evil.Plugin") target; the signed JAR parsed
with Main-Class com.example.Hello and signer CERT.SF/CERT.RSA
with SHA-256 declared.

Fixtures: benign class (parser and verdict NO), hostile class
(fetch plus remote class loading; cannot reach NO, target
named), truncated class (caps by name), signed benign JAR
(verdict NO), JAR with a missing Main-Class (caps, entry point
named), JAR with a hostile member (cannot reach NO).

## .NET assemblies (gap 4)

Prior behaviour (proven by probe): benign and obfuscated
assemblies were UNACCOUNTED as opaque PE files under the
compiled-binary rule; IL was never disassembled. The hostile
assembly was PROVEN, but only by string matching: the chain
came from the string "downloadstring" in the metadata strings,
not from the IL. A related observation from fixture building:
an early benign build was convicted by the string layer
because an unused MemberRef name and an unused #US string sat
in its metadata. Capability matching over metadata strings is
not IL accounting, in either direction; this wave adds the IL
layer beneath it and does not change the string layer.

Built, in `bytecode.py`: a complete ECMA-335 metadata parser
(metadata root, all five heaps, and a schema-driven walk of
all 45 metadata tables with the full coded-index map), and an
IL disassembler (tiny and fat method headers, the full
one-byte and 0xFE opcode tables) that decodes every method
body of every TypeDef. Token resolution covers MethodDef,
MemberRef, Field, TypeRef, TypeDef, strings and signatures.
Findings: a fetch call and a load or execute call in one
method form `bytecode-fetch-execute`; Assembly.Load whose
argument does not name a declared AssemblyRef, the assembly
itself or an embedded resource is unaccounted (a remote URL
argument is also recorded as an external reference);
Type.GetType of an undeclared name and reflective
Invoke/InvokeMember are unaccounted. Obfuscation indicators
are named, not scored: an encrypted string store (a method
returning String, taking Int32, whose body xors against a
static byte-array field), call sites passing integer keys to
such a store (the decrypted strings are unaccounted, counted
by call site), control-flow flattening shape (a switch with
four or more targets in one method), and proxy delegates
(types deriving from MulticastDelegate). Embedded resources
from the ManifestResource table are enumerated as units: an
embedded assembly is parsed recursively one level deep, UTF-8
text is accounted as data, and anything else is named
unaccounted with its size.

Parser depth, stated exactly: no operand-stack dataflow. An
Assembly.Load argument is resolved only when the instruction
immediately before the call is an ldstr; any other argument
shape is named unaccounted. Method signatures are parsed for
the element types the findings need, not resolved into
constructed generic types. Embedded assemblies are parsed one
level deep; a resource inside a resource caps by name. The IL
layer does not verify strong names or Authenticode; the
existing PE signature layer covers Authenticode separately.

Observed during the build (probe, read directly): benign
accounted with Main decoded; hostile produced the
`bytecode-fetch-execute` chain plus the unaccounted item
naming the Assembly.Load of the remote payload URL; the
obfuscated variant produced all three indicators and the item
"2 call site(s) pass integer keys to an encrypted string
store"; the text-resource variant accounted; the binary
resource variant named payload.bin (512 bytes) unaccounted.

Fixtures: benign assembly (parser and verdict NO), hostile
assembly (cannot reach NO, chain and load target named),
obfuscated assembly (caps by name: string store, flattening
switch, proxy delegate), text resource (accounted), binary
resource (caps, resource named), truncated assembly (cannot
reach NO).

## Android DEX and APKs (gap 5)

Prior behaviour (proven by probe): DEX files and APK members
were "unknown binary data"; the binary AndroidManifest.xml was
never parsed; benign and hostile fixtures were identical to
the engine, and dynamic loading was never named.

Built, in `bytecode.py`: a complete DEX parser. Header, string,
type, proto, field and method id lists, class defs and class
data are all parsed, and every code item is walked with the
full Dalvik opcode width table (including the packed-switch,
sparse-switch and fill-array-data payload pseudo-instructions).
A method whose walk does not end exactly at its declared end,
or whose declared code runs past the file, is unaccounted by
name. Findings over the decoded invokes: DexClassLoader,
PathClassLoader, InMemoryDexClassLoader, DexFile and
BaseDexClassLoader construction is dynamic loading, and the
path it is constructed over is resolved from the same method's
const-strings: a path that is not part of the submission is
unaccounted by construction, and a construction with no
string-constant path is unaccounted because the loaded code is
not identified. ClassLoader.loadClass and Class.forName
targets are resolved against the classes defined in this DEX,
the classes defined in the other DEX files of the same
submission (verdict pre-pass), and platform packages; anything
else is named unaccounted. System.loadLibrary, System.load,
Runtime.loadLibrary and Runtime.load resolve against the
submission's file list by library name. A URL or connection
open together with dynamic loading forms
`bytecode-fetch-execute`. A binary AndroidManifest.xml parser
(string pools in UTF-8 and UTF-16, the element tree, typed
attribute values) extracts the package, the uses-permission
list, and every activity, activity-alias, service, receiver
and provider with its android:exported flag. After the loop,
the verdict reconciles the manifest's components against the
union of DEX classes in the same package: a declared component
with no declaring DEX class is capped on the manifest's own
record.

Parser depth, stated exactly: no register dataflow. Dynamic
targets are resolved only from const-strings in the same
method; a target computed any other way is named unaccounted.
Try-catch regions and debug information are skipped by size,
not modelled. Native (abstract, coff 0) methods have no body
to decode and are recorded as such.

Fixtures: benign DEX (parser and verdict NO), hostile DEX
(DexClassLoader over an absent payload path, loadClass and
Class.forName of an absent class; cannot reach NO, each target
named), truncated DEX (caps by name: the header's declared
file size exceeds the bytes present), benign APK (verdict NO,
manifest reconciled), hostile APK (cannot reach NO), and an
APK whose manifest declares a component no DEX declares (caps,
component named).

## Mach-O and fat binaries

Prior behaviour (proven by probe): a fat Mach-O was a single
UNACCOUNTED entry; its slices were never split, and no code
signature or entitlement information was extracted from any
Mach-O.

Built, in `bytecode.py`: a fat splitter (big-endian and
little-endian fat headers, every slice bounds-checked by
name) and a thin Mach-O parser (load commands, segments,
linked libraries) that follows LC_CODE_SIGNATURE to the
superblob and parses it: the CodeDirectory (version, flags
including the adhoc bit, identifier, team id) and the
entitlements blob (parsed as a plist; when the blob is not a
parseable plist, its keys are recovered by scanning and the
record says so). In `enumerate_subject`, a fat binary is
expanded exactly like a firmware image: each slice is written
out and registered as an entry `rel!slice_<arch>`, so every
slice is analysed and verdicted as its own unit; a slice that
cannot be cut fails the bundle by name as a failed container.
The fat parent, when fully expanded, is an enumeration unit:
its slices are the judged content, and a new final-decision
branch accounts it when every slice is accounted. The
per-slice and bundle signature records ride on each file's
bytecode record, and a superblob that cannot be parsed caps
its file by name.

Parser depth, stated exactly: the code signature is
inventoried, NOT cryptographically verified; no certificate
chain is evaluated, and entitlements are recorded, not
enforced. Slices are judged by the ordinary native rules, so
an unsigned slice with no reference stays unaccounted under
the standing compiled-binary rule; the benign control reaches
NO by byte identity against a reference containing the same
fat file (its slices hash-match as units). LC_DYLD_INFO and
chained-fixup payloads are recorded as load commands, not
decoded.

Fixtures: fat split and per-slice parse (parser level),
entitlements and adhoc flag extraction (parser level), a
superblob pointed past the end of the file (caps by name,
parser and verdict level), fat verdict with both slices as
units, reference-matched fat bundle (verdict NO, slices
hash-matched), and a fat bundle whose last slice declares
more bytes than the file holds (caps by name, slice named).

## Remainder, named

- Operand-stack and register dataflow in all three bytecode
  parsers: targets not loaded immediately before the call (Java,
  .NET) or not held in a same-method const-string (DEX) cap as
  unaccounted instead of being resolved. This is the honest
  boundary of the accounting layer; resolving them needs a
  dataflow engine this build does not have.
- JAR and Mach-O signatures are inventoried, not verified:
  no PKCS#7 verification of JAR signature blocks, no Mach-O
  certificate chain evaluation.
- .NET embedded assemblies are parsed one level deep.
- Python bytecode (.pyc) is gap 6 of the research plan and is
  not in this wave's scope; it remains a recognised-unit item
  for a later wave.

## Repair pass, 2026-11-24

The operator's verification run gave 275 passed and 12 failed,
all 12 in tests/test_coverage_wave2.py. Each failure was run
individually, read, and diagnosed to root cause before any
change. No assertion was weakened: the hostile fixtures still
cannot reach NO, and the benign controls still reach NO for
the reasons the wave designed. Fixes landed in engine code
for eight failures and in test fixtures for four; no test
assertion was changed anywhere in this pass. The two fixture
builders that were wrong were wrong against their format
specifications, as itemised below. Final result after the
repair: 287 passed, zero failures, full suite in
`~/ezpush-venv`.

1. test_java_parser_benign_class_accounted. Root cause, code:
   parse_class_file presented this_class in JVM internal form
   (com/example/Hello) while the wave's presentation for class
   identity, the form JAR manifests and the verdict's
   entry-point reconciliation use, is dotted
   (com.example.Hello). Fix in event_zero/bytecode.py:
   this_class is presented dotted, the constant pool lists stay
   internal, and _java_findings normalises known classes to
   both spellings so resolution cannot miss on spelling alone.
2. test_java_parser_hostile_remote_code_loading. Root cause,
   code: _java_findings formed the bytecode-remote-code-loading
   chain but never recorded the URLClassLoader remote source
   itself as an unaccounted item, so the plugin.jar load was
   named in the chain evidence but in no unaccounted item,
   contrary to this log's Java section. Fix in
   event_zero/bytecode.py: a URLClassLoader over a remote URL
   constant now also records an unaccounted item naming the
   remote code source.
3. test_java_hostile_class_cannot_reach_no. Root cause, code:
   the verdict's final decision dropped a file's named
   blockers whenever the same file also carried a proven chain
   (the file_yes branch recorded only the chain), so the
   unresolved loadClass target vanished from the report's
   blocker list. Fix in event_zero/verdict.py: the proven
   branch now also records the file's blockers on its record
   and in the report blocker list. A proven chain decides the
   headline; it does not erase evidence.
4. test_jar_benign_signed_reaches_no. Root cause, two code
   defects. (a) is_jar_signature_member split the release path
   only on the directory separator, so a member path of the
   form app.jar!META-INF/CERT.RSA was not recognised as a
   signature member and the signature block was judged as
   unknown binary data. Fix in event_zero/bytecode.py: the
   path is split on "!" as well. (b) The Main-Class
   reconciliation grouped the JAR's own record under its
   directory while its members group under the JAR path, so
   the JAR was checked against a group containing no members;
   and presence was tested by class name rather than by member
   resource path. Fix in event_zero/verdict.py: the JAR's
   members are gathered by path prefix from the whole release,
   and presence is by member resource path
   (com/example/Hello.class), which is how a JAR launcher
   resolves Main-Class. This also puts
   test_jar_missing_main_class_caps on its designed footing: a
   class file stored under a different member name does not
   satisfy the declaration, whatever class its bytes define;
   before the repair that test capped only as a side effect of
   the grouping defect and the spelling mismatch in item 1.
5. test_jar_hostile_member_cannot_reach_no. Root cause, code:
   the same dropped-blocker defect as item 3. Fix in
   event_zero/verdict.py.
6. test_dotnet_parser_obfuscation_indicators. Root cause,
   code: _dotnet_findings recorded obfuscation indicators as
   bare strings, while the parser record's designed shape is
   structured entries with a kind and a detail. Fix in
   event_zero/bytecode.py: indicators are now
   {kind, detail} entries (encrypted-string-store,
   control-flow-flattening, proxy-delegate), and the verdict
   notes render the detail text.
7. test_dotnet_hostile_cannot_reach_no. Root cause, code: the
   same dropped-blocker defect as item 3; the Assembly.Load
   remote-target blocker was discarded because the
   fetch-execute chain was proven. Fix in
   event_zero/verdict.py.
8. test_dotnet_truncated_cannot_reach_no. Root cause, code:
   parse_dotnet_il never validated declared extents against
   the bytes present, so an assembly cut in half parsed as a
   smaller, benign-looking assembly and was accounted. Fix in
   event_zero/bytecode.py: a section whose raw extent runs
   past the end of the file, a metadata root that runs past
   the end of the file, or a metadata stream that runs past
   the end of the metadata now fails the parse as truncated,
   by name.
9. test_dex_parser_benign_accounted. Root cause, fixture:
   build_dex baked const-string operands with indices in
   encounter order while emitting the string_ids table sorted,
   as the DEX specification requires, so operands pointed at
   the wrong strings (the greet method's const-string resolved
   to a proto shorty). Fix in tests/test_coverage_wave2.py:
   instruction resolution is two-pass; pass one discovers
   every referenced string, pass two re-resolves operands
   against the sorted table. No assertion changed.
10. test_dex_parser_hostile_dynamic_loading_unaccounted. Root
    cause, fixture: the same operand-index defect as item 9;
    the DexClassLoader path and the loaded class name resolved
    to unrelated strings, so no dynamic-loading finding could
    name them. Fix in tests/test_coverage_wave2.py, as item 9.
11. test_axml_parser_components_and_permissions. Root cause,
    fixture: build_axml registered element names in the string
    pool only inside emit(), after the pool had already been
    serialised from the strings collected during tree
    construction, so every element tag index pointed past the
    end of the pool and all tags parsed as None; the package
    and components were therefore never extracted. Fix in
    tests/test_coverage_wave2.py: element names are registered
    when the tree is built. No assertion changed.
12. test_apk_manifest_component_without_code_caps. Root
    cause, fixture: the same tag loss as item 11; with no
    components extracted, the manifest reconciliation had
    nothing to check and the APK reached NO. Fix in
    tests/test_coverage_wave2.py, as item 11.

One further fixture correction, found during the repair
because test_apk_benign_reaches_no had been passing vacuously
while no components were extracted at all: benign_apk built
its manifest with the default package com.example.app while
its DEX class lives in com.example, so once the manifest
parsed, the manifest genuinely declared a component with no
code behind it and the verdict was right to cap it. Fix in
tests/test_coverage_wave2.py: benign_apk builds its manifest
with package="com.example", the package its DEX class
declares. No assertion changed.
