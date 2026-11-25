# Coverage Wave 1 Log: No Container With an Unenumerated Interior

Date: 2026-11-24. Scope: build wave 1 of the total coverage
programme (`~/workspace/research_notes/event-zero-total-coverage-20261124/report.md`,
ranked gaps 1, 2 and 7): disk images and virtual disks, firmware
filesystem interiors with per-driver verdicts, and OS package
formats. Method: synthetic fixtures only, built in the test file
or with the system mkfs tools. No sample was downloaded. Prior
behaviour was proven by probe before any code changed: an ISO and
a deb were each a single opaque verdict entry (the ISO was even
classified "text / script" from its raw bytes), and no member of
either interior was ever listed or judged.

Code: new module `event_zero/containers.py` (pure Python,
read-only parsers); `event_zero/verdict.py` routes the new kinds
through the existing container contract (full enumeration
registers members as verdict units; any failure is a failed
container, unaccounted by construction, never judged from raw
bytes); `event_zero/analyzer.py` gives the new kinds their own
format labels so a recognised container cannot fall through to
the text heuristic and lose the enumeration-unit exemption
(the audit defect 9 shape, applied to the new kinds).

One detection order fix fell out of the first probe:
`tarfile.is_tarfile` answers True for any file whose first block
is zeros, and an ISO 9660 image opens with sixteen zero sectors,
so disk images were claimed as empty tars. The wave 1 magic
checks now run before the tar check in `container_kind`.

## Disk images and virtual disks

Prior behaviour (proven): ISO interior invisible; the image was
one opaque entry, UNACCOUNTED, with nothing inside named.

Built, in `containers.py`: ISO 9660 enumeration (primary volume
descriptor, Joliet supplementary descriptor names where present,
directory recursion; interleaved and multi-extent files raise).
Raw disk images: MBR and GPT partition tables, with FAT12/16/32
(long file names included) and ext2/3/4 (extent trees and
indirect blocks, directory walk) interiors enumerated per
partition. VHD: fixed disks read directly, dynamic disks read
through the block allocation table and sector bitmaps. VHDX:
region table and metadata region parsed, payload blocks read
from the BAT (sector bitmap interleaving accounted). QCOW2:
L1/L2 walk over uncompressed clusters. DMG: koly trailer and
blkx plist parsed, raw, zerofill and zlib chunks decoded.

Caps, each naming the interior: differencing VHD and VHDX (a
parent locator in the metadata caps the VHDX), QCOW2 with a
backing file, encrypted QCOW2, compressed QCOW2 clusters, NTFS
partitions, DMG chunk types that carry data in a coding this
build does not decode (bzip2, ADC, LZFSE, LZ4), UDF-only discs,
GPT tables with no partitions, and any filesystem the dispatch
cannot identify.

Fixtures: benign FAT, ISO, VHD (fixed and dynamic), VHDX, QCOW2,
DMG and ext2 interiors reach NO ACCOUNTED; hostile interiors
(the wave 2 bitsadmin dropper as a .cmd member) are judged as
members and are not NO; the NTFS, differencing and backing-file
fixtures cap with the interior named.

## Firmware filesystems and carved drivers

Prior behaviour (proven by the audit, defect 14 follow-up):
filesystem regions were magic-scan hits only; DXE drivers were
carved for the image-level report and never individually
verdicted.

Built: `containers.firmware_regions` locates SquashFS, CRAMFS,
JFFS2 and UBI regions inside a firmware image (and the verdict's
`expand_firmware` hook runs whenever a non-container file carries
a firmware volume header or a filesystem region). SquashFS is
fully parsed (zlib and xz metadata and data blocks, fragment
table, basic and extended file and directory inodes). CRAMFS is
fully parsed (inode tree, per-block zlib data), validated
against images produced by the system `mkfs.cramfs`. JFFS2 is
parsed by node scan (dirent and inode nodes, none, zero and zlib
compression, highest version wins per fragment). Carved PE
images are sized from their own headers and re-submitted as
entries (`dxe_<offset>.efi`), so each DXE, PEI or SMM driver
receives its own verdict and the wave 1 combined SMM plus
network test applies per driver through the ordinary per-file
path.

Caps: a UBI region caps the firmware unit by name (its UBIFS
interior is a B-tree index, the TNC, that this build cannot
walk); big-endian SquashFS caps by name; a SquashFS member that
is a special file (device, fifo, socket) caps the filesystem,
because its contents cannot be enumerated as a file; any region
extraction failure is recorded on the firmware unit's own record
as a failed container.

Fixtures: a synthetic firmware image (FV header plus a carved
SMM/network PE plus a SquashFS region carrying a text file)
enumerates both the filesystem members and the carved driver,
and the driver is judged as its own unit; a firmware image with
a UBI region caps with UBIFS named.

## OS package formats

Prior behaviour (proven): a deb was "unknown binary data", one
opaque entry; rpm and Alpine apk were the same.

Built: deb is parsed as an ar archive; the control and data tar
members (gzip, xz, bzip2 and plain through tarfile) are
enumerated, control members under a `DEBIAN/` prefix so
maintainer scripts (postinst and kin) surface as script entries
subject to the wave 2 and 3 script rules. RPM is parsed through
its lead and header structures; scriptlets (PREIN, POSTIN,
PREUN, POSTUN and their program variants) are surfaced as
`RPMSCRIPT/` entries, and the payload (gzip, xz, bzip2 or plain)
is enumerated as a newc cpio archive. Alpine apk is parsed as
its three concatenated gzip streams, each a tar archive, with
`.PKGINFO` required for the package to be accounted as an apk
at all.

Caps: a zstd-compressed deb control or data archive caps by
name (this platform's own dpkg-deb produces control.tar.zst by
default, and the cap fires on it exactly as written); an RPM
payload compressor outside the supported set caps by name; cpio
members that are special files cap the package; an apk stream
that is truncated or lacks `.PKGINFO` caps by name.

Fixtures: benign deb, rpm and apk packages reach NO ACCOUNTED
with payload members enumerated; packages whose postinst,
POSTIN or .post-install script is the wave 2 dropper shape are
enumerated (the script appears as its own entry) and are not NO.

## What remains unenumerable after this wave

Named here so the next wave starts from the list, not from a
search: NTFS interiors; UBIFS interiors; UDF-only discs;
differencing virtual disks without their parents; compressed
QCOW2 clusters; DMG chunk codings other than raw, zerofill and
zlib; zstd-compressed deb members; SquashFS in big-endian form
and with LZO, LZ4 or Zstd compression; JFFS2 nodes with RTIME,
LZMA or LZO compression; ext filesystems with metadata checksums
that fail, 64-bit group descriptors beyond the fields read here,
and inline-data files; FAT exFAT volumes (no parser, and the
dispatch does not claim them: an exFAT image falls to the
unidentified-filesystem cap). Each of these caps by name today
rather than passing silently, which is the wave's claim: every
container format the engine accepts is enumerated to the bottom
or refused by name, and no verdict is issued over an unlisted
interior.

## Tests

`tests/test_coverage_wave1.py`: 28 tests covering every format
above in the three required shapes (benign interior reaching NO,
hostile interior judged as a member, unenumerable interior
capping by name). Full suite result is recorded below at the end
of the wave.

Full suite, run at the end of the wave with
`~/ezpush-venv/bin/python -m pytest tests/ -q`: 252 passed, 0
failed (the 224-test baseline intact, 28 new wave 1 tests, no
existing test changed).
