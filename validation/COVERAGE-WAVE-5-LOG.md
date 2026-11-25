# Coverage Wave 5 Log: Certificate Contents and Member Semantics

Date: 2026-11-24. Scope: items 1 and 2 of the next-frontier
research (`~/workspace/research_notes/event-zero-next-frontier-20261124/report.md`,
sections 2.1 and 2.2 and the ranked items 1 and 2): certificate
table content accounting, extending the coverage wave 3
byte-ownership ledger, and the archive member-semantics gate,
the wave 3 dual-view principle applied to archives as a
semantic model pair rather than a second parser. Method:
synthetic fixtures only, built in the test file from the
format specifications. No sample was downloaded. Prior
behaviour was proven by probe before any code changed (see
each section).

Code: `event_zero/coverage3.py` gains the certificate chain
walk inside the PE ownership ledger; new module
`event_zero/coverage5.py` carries the member-semantics gate
and the package member listings; `event_zero/verdict.py` wires
the gate into the per-file loop in the coverage wave 3
section, on the container's own record
(`rec["member_semantics"]`), with the wave 3 exemptions.
Coverage wave 1 enumeration behaviour is untouched: no
extractor changed, and the gate runs on containers that were
fully enumerated, after enumeration.

Environment note: `~/ezpush-venv` did not exist in this
session's environment and was recreated with the project
requirements plus pytest; the optional unicorn dependency was
initially missing, which failed
`tests/test_virt.py::test_virt_trace_harness` on the first
baseline run (330 passed, 1 failed, the failure text naming
the missing module). With unicorn installed the file passes
and the 331-test baseline holds exactly, before and after
this wave's code, as recorded below. No test was changed to
accommodate the environment.

## Certificate-table content accounting

Prior behaviour (proven by probe): the wave 3 ledger owned
the certificate table as a record sized by its first entry's
declared length. Three shapes escaped or were misjudged. A
payload appended inside the table under an inflated entry
length (the entry's declared length covering the certificate
and 512 bytes of high-entropy payload) read as fully owned,
complete, and at verdict level a signed-shape PE carrying it
reached NO ACCOUNTED under a verifying signature. A payload
placed past the DER content inside an honestly sized entry
read the same way. And a table with two legitimately chained
certificates capped, because everything past the first record
was unowned by construction: the ledger was simultaneously
too loose (entry contents unexamined) and too strict (the
chain unread).

Built, in `coverage3.certificate_table_accounting`, called
from `_pe_ownership`: the WIN_CERTIFICATE chain is walked
entry by entry. Each entry is 8-byte aligned from the table
start and declares its own length; for the two DER
certificate types (X.509, type 0x0001, and PKCS#7 signed
data, type 0x0002) the entry's certificate content is sized
by its DER structure (the outer SEQUENCE's definite length
bounds the blob), so the accounted range is exactly the
header plus the DER bytes. Everything else inside the table
is unowned, with the offset and size named by the existing
ownership verdict path and the reason carrying a content
classification (executable-shaped content, including the
CAFEBABE marker of the documented campaign, and high-entropy
content at or above 7.0 bits per byte are named as such):

- bytes past an entry's DER content inside its declared
  length (the inflated-length staging shape);
- an entry whose content is not a readable DER structure,
  and an entry of a certificate type this build cannot
  account (only the two DER types are accounted);
- nonzero padding between chained entries, and nonzero
  bytes past the end of the chain (the Authenticode layout
  leaves only zeros in both places; verified-zero padding
  in either place, and inside an entry past its DER
  content, is owned as padding);
- the remainder of the table after a malformed chain link
  (a declared length below the header size or overrunning
  the table).

The accounting summary rides on the file's record
(`rec["byte_ownership"]["certificate_table"]`: the entry
list with per-entry type, declared length, DER length and
accounted flag). A well-formed signed file whose table is
exactly its declared blob chain plus verified-zero padding
keeps its existing paths, now including the multi-certificate
chain the wave 3 ledger refused.

Fixtures: a single clean entry accounted; two chained
entries accounted (the behaviour change, tested as a
control); the inflated-length payload (module level: one
material unowned range of exactly the payload's size, the
reason naming the certificate table and the high-entropy
classification; verdict level: caps with byte-ownership and
certificate named); payload past the chain; nonzero
padding; a malformed chain; CAFEBABE-marked content past
the chain, named executable-shaped; an entry with no
readable DER; and the verdict-level pair, a clean chained
table under a verifying signature keeping NO and the staged
table capping.

## Archive member-semantics gate

Prior behaviour (proven by probe): the verdict judged the
members the engine's own extractor wrote, under the names
the listing gave, on a POSIX host. Each of these reached NO
ACCOUNTED in an otherwise benign archive: a ZIP or TAR
member named with NTFS alternate data stream syntax; a
member named with backslash traversal; a ZIP symbolic link
member whose target escapes the extraction root (extracted
here as a text file holding the target string); a duplicate
member name whose first member is the wave 2 dropper shape
and whose second is benign (the written file is the benign
one, so the dropper member was never judged; the reversed
order, where the dropper survives, was judged and not NO,
the control pair); a ZIP member whose local header declares
different sizes than its central directory; duplicate
members inside a deb, an rpm and an apk (the wave 1 member
dicts collapse duplicates silently, so the shadowed member
was never judged); and an rpm cpio symbolic link member
whose target climbs above the root (the cpio listing passed
link members by entirely). Two shapes already failed closed
through the enumeration contract, with generic text: a ZIP
local header naming a different member than the central
directory (zipfile refuses it), and any TAR link member
(the tar extractor refuses non-regular members). The gate
does not disturb either; it names the semantics where
enumeration is silent.

Built, in `coverage5.py`: for ZIP, TAR, and the wave 1
packages whose member semantics are tar or cpio (deb, apk,
rpm), the gate returns divergences, {member, kind, detail},
and the verdict caps the container at YES UNACCOUNTED with
the member and the divergence named. Two root models are
used. Archives extracted into a folder (ZIP, TAR) are judged
under the extraction-dir model, whose extractor population
includes Windows tools: backslash is a separator, a colon in
a name component is NTFS stream syntax, trailing dots and
spaces are stripped on write, and absolute and drive-letter
names write outside the root. OS packages are judged under
the install-root model: dpkg, rpm and apk install onto the
filesystem root by Unix tools, where backslash and colon are
ordinary filename characters and an absolute link target
names a path inside the root by definition, so the package
gate carries the classes that hold there (traversal above
the root, duplicate shadowing, link targets climbing above
the root). The classes:

- Name classes: path traversal in slash or backslash form;
  absolute and drive-letter names (extraction-dir); stream
  qualified names, including leading-colon stream names of
  the CVE-2026-58052 shape (extraction-dir); separator
  divergence for any backslash name (extraction-dir);
  trailing dot or space components (extraction-dir); control
  characters in a name (both models); and, for ZIP, a member
  name stored without the UTF-8 flag whose bytes are
  non-ASCII, which extractors decode under different
  codepages.
- Duplicate names: exact duplicates, and written-form
  collisions under separator normalisation, case folding,
  and Windows written-form rules, each reported once with
  the colliding members named. Directory entries are
  excluded: a repeated directory is idempotent under every
  extractor.
- Link classes: symbolic and hard link members whose
  targets escape the root (absolute targets escape the
  extraction-dir root; relative targets are resolved
  against the member's directory, hardlink targets against
  the root), and member paths that pass through a link
  member whose target escapes, which an extractor that
  creates the link writes outside the root as well.
- ZIP header classes: the local header's member name
  differing from the central directory's (read from the raw
  bytes, not from zipfile's view), the local header's
  declared sizes differing from the central directory's
  where no data descriptor or ZIP64 placeholder explains
  them, and the encryption or data-descriptor flag bits
  differing between the two headers.

For the packages, the gate re-reads the member listing from
the package's own structures (deb and apk tar interiors,
rpm cpio payload) with link targets and member types kept,
in the same keys the containers module's member dicts use,
because the dicts themselves collapse duplicates and pass
cpio links by: the listing the verdict judged is not
visible from them. A gate that cannot read a fully
enumerated container's member list caps it as an
engine-incompleteness blocker, in the accuracy wave 3 R3
shape.

Fixtures: for ZIP, one per class (stream-qualified name,
leading-colon stream name, backslash traversal, escaping
symlink, absolute symlink target, duplicate shadowing with
the dropper first, duplicate benign members capping on
semantics alone, case collision, local-header size
divergence), the through-link shape at gate level, the
record carrying the structured divergences, and the benign
controls (an in-tree symlink reaching NO, nested paths and
many members reaching NO). For TAR, duplicate shadowing,
stream-qualified and backslash names capping, the escaping
symlink named at gate level, an in-tree symlink clean at
gate level (its verdict-level refusal is the enumeration
contract's, recorded above), and nested benign members
reaching NO. For the packages, a deb and an apk with
duplicate members capping, an rpm whose cpio symlink climbs
above the root capping, and its in-tree twin (a symlink
resolving to another member of the same package) keeping
NO with the gate silent.

## Remainder, named (capped or recorded, not implemented)

- Certificate entries of types other than X.509 and PKCS#7
  signed data are unaccounted as a whole entry rather than
  parsed: the TS protocol stack certificate type is the
  known legitimate case, and it is rare enough that refusing
  it clean by name is the fail-closed choice this wave
  takes. The DER accounting reads the outer SEQUENCE length
  only; it does not validate the PKCS#7 interior (signer
  chains and digest agreement are the signature verifier's
  existing province, and a blob that parses as DER but is
  not a real certificate is a signature that does not
  verify, not an accounting gap).
- The member-semantics gate covers ZIP, TAR, deb, rpm and
  apk. The remaining wave 1 container kinds carry their
  members as files in filesystems and disk images, where
  link and name semantics belong to the filesystem layer
  (a FAT or ext directory entry has no stream syntax and
  its links are the filesystem's own structures); RAR and
  7-Zip archives have no parser in this build and are
  unaccounted as whole containers already, so the RAR5
  stream-name case that motivates part of this gate is
  refused at the container level, not modelled per member.
- Package link targets are judged on root escape only. A
  package link that resolves inside the root to a path the
  package does not contain points at host content by
  design (links to system libraries are the ordinary case),
  so it is not a divergence under the install-root model;
  archives under the extraction-dir model get the stricter
  reading because their root is a folder the user chose.
- The through-link check resolves one link member per path
  prefix and does not chase link-to-link chains; a chain of
  in-tree links whose final target escapes is caught at
  its final link only when that link's own target escapes
  the root from its own directory.
- ZIP header comparison trusts zipfile's central directory
  walk for the listing and reads local headers at the
  offsets the central directory declares; a central
  directory that itself lies about member order is a
  malformed archive the enumeration layer refuses, not a
  semantics case.

## Tests

`tests/test_coverage_wave5.py`: 35 tests covering both
items in the shapes above (module-level accounting and
gate cases, and verdict-level positives and controls). No
existing test was changed. Full suite result is recorded
below at the end of the wave.

Full suite, run at the end of the wave with
`~/ezpush-venv/bin/python -m pytest tests/ -q`: 366 passed, 0
failed (the 331-test baseline intact, 35 new wave 5 tests, no
existing test changed), in 235.71s. An intermediate full run
with both items implemented and before the wave 5 tests were
written also read 331 passed, which is the gate's
false-positive check against every pre-existing fixture.
tests/test_final.py::test_export_cli passed in the full runs
and did not need its standalone re-run.
