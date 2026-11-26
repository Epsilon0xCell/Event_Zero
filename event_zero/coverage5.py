"""Coverage wave 5: archive member semantics, and the package
member listings that carry them.

Design law (next-frontier research, item 2): enumeration is not
accounting until each member's extraction semantics are checked
against the platform extractor's model. An accounting engine
enumerates the member list; an extractor writes what the
member's semantics say. The 2025 archive CVE record is a
catalogue of the two diverging: 7-Zip symbolic links traversing
out of the extraction root (CVE-2025-11001, CVE-2025-11002),
WinRAR alternate data stream paths that display as one file and
write as another (CVE-2025-8088), WinRAR directory traversal
from crafted member paths (CVE-2025-6218), RAR5 stream names
overwriting the extracted file's own security marker
(CVE-2026-58052), and CPython tarfile differentials
(CVE-2025-4517, CVE-2025-8194, CVE-2025-13462).

This module supplies the second view, as a semantics model
rather than a second parser (the wave 3 dual-parser principle
applied to archives). For ZIP, TAR, and the wave 1 package
formats whose member semantics are tar or cpio (deb, apk,
rpm), it returns a list of divergences: {member, kind, detail}.
A member whose extraction semantics diverge from its listing
is an unaccounted member; the verdict caps the container with
the member and the divergence named. The gate judges
semantics, never intent, and adds no conviction path.

Two root models are used, because the extraction root differs:
"extraction-dir" for archives a user extracts into a folder
(ZIP, TAR subjects and members), where the platform extractors
include Windows tools that treat backslash as a separator,
names as NTFS stream syntax, and trailing dots and spaces as
strippable; and "install-root" for OS packages (deb, rpm,
apk), whose members are installed by Unix package tools onto
the filesystem root, where backslash and colon are ordinary
filename characters and an absolute link target names a path
inside the root by definition. The classes that hold under
both models are path traversal above the root, duplicate-name
shadowing, link targets escaping the root, member paths that
resolve through an escaping link, and control characters in
names.

Everything here is a pure read-only parse. Nothing is
extracted and nothing is executed.
"""
import gzip
import io
import lzma
import re
import stat
import struct
import tarfile
import zipfile

_DRIVE_RE = re.compile(r"^[A-Za-z]:")


# ======================================================================
# Shared path model
# ======================================================================

def _split(name):
    return name.replace("\\", "/").split("/")


def _resolve(base_parts, target):
    """Resolve a slash-or-backslash path against base_parts (the
    components of the directory it is resolved from, inside the
    root). Returns (parts, escaped): the normalised components,
    and whether resolution climbed above the root."""
    parts = list(base_parts)
    escaped = False
    for comp in _split(target):
        if comp in ("", "."):
            continue
        if comp == "..":
            if parts:
                parts.pop()
            else:
                escaped = True
        else:
            parts.append(comp)
    return parts, escaped


def _dir_parts(name):
    parts = [c for c in _split(name) if c not in ("", ".")]
    return parts[:-1]


def _name_divergences(name, model):
    """Divergences carried by a member name alone. Returns a
    list of (kind, detail)."""
    out = []
    if any(ord(c) < 0x20 or ord(c) == 0x7F for c in name):
        out.append(("control-characters-in-name",
                    "the member name contains control characters, "
                    "which extractors and filesystems do not "
                    "interpret uniformly, so the written name is "
                    "not the listed name"))
    if "\\" in name:
        _parts, escaped = _resolve([], name)
        if escaped:
            out.append(("path-traversal-backslash",
                        "the member name uses backslash separators "
                        "to climb out of the extraction root "
                        "(extractors that read backslash as a path "
                        "separator write this member outside the "
                        "root); the engine's own extractor, on a "
                        "POSIX host, writes the backslashes as "
                        "literal filename characters, so the "
                        "written form is not the listed form"))
        elif model == "extraction-dir":
            out.append(("separator-divergence",
                        "the member name contains backslashes, "
                        "which Windows extractors read as path "
                        "separators, so the member is written as "
                        "a nested path there and as a flat name "
                        "with literal backslashes here: the "
                        "written form differs from the listing"))
    if model == "extraction-dir":
        if name.startswith("/") or name.startswith("\\"):
            out.append(("absolute-path",
                        "the member name is an absolute path, so "
                        "an extractor that honours it writes "
                        "outside the extraction root entirely"))
        elif _DRIVE_RE.match(name):
            out.append(("absolute-path",
                        "the member name begins with a drive "
                        "letter, so a Windows extractor writes it "
                        "as an absolute path outside the "
                        "extraction root"))
        elif "\\" not in name:
            # backslash forms are reported by the backslash
            # branch above, under their own kind
            _parts, escaped = _resolve([], name)
            if escaped:
                out.append(("path-traversal",
                            "the member path resolves outside "
                            "the extraction root"))
        for comp in _split(name):
            if ":" in comp:
                out.append(("stream-qualified-name",
                            f"the name component {comp!r} "
                            f"contains a colon, which is NTFS "
                            f"alternate data stream syntax: an "
                            f"extractor on Windows writes this "
                            f"member as a stream of another file "
                            f"(or, for a leading-colon name, as a "
                            f"stream overwriting the listed file's "
                            f"own default stream and security "
                            f"marker), not as the listed file"))
                break
        for comp in _split(name):
            if comp not in ("", ".", "..") and (comp.endswith(".")
                                                or comp.endswith(" ")):
                out.append(("trailing-dot-or-space",
                            f"the name component {comp!r} ends "
                            f"in a dot or a space, which Windows "
                            f"strips when writing, so the written "
                            f"name differs from the listed name"))
                break
    else:
        _parts, escaped = _resolve([], name)
        if escaped:
            out.append(("path-traversal",
                        "the member path resolves above the "
                        "install root"))
    return out


def _norm_key(name, flavour):
    parts = []
    for comp in _split(name):
        if comp in ("", "."):
            continue
        parts.append(comp)
    if flavour == "exact":
        return name
    if flavour == "slash":
        return "/".join(parts)
    if flavour == "casefold":
        return "/".join(parts).casefold()
    # windows written form: case-insensitive, and trailing dots
    # and spaces stripped per component
    return "/".join(c.rstrip(". ") for c in parts).casefold()


def _duplicate_divergences(members):
    """Duplicate and written-form-colliding member names. The
    listing shows every member; the written tree holds one file
    per name, and extractors differ on whether the first or the
    last member wins, so the shadowed members are members the
    verdict never judged as written files."""
    out = []
    files = [m for m in members if not m["is_dir"]]
    for flavour, kind, label in (
            ("exact", "duplicate-member-name", "appears more "
             "than once with the identical name"),
            ("slash", "written-form-collision",
             "collides with another member once separators and "
             "dot components are normalised"),
            ("casefold", "written-form-collision",
             "collides with another member on a "
             "case-insensitive filesystem"),
            ("windows", "written-form-collision",
             "collides with another member under Windows "
             "written-form rules (case folding and trailing dot "
             "and space stripping)")):
        groups = {}
        for m in files:
            groups.setdefault(_norm_key(m["name"], flavour),
                              []).append(m["name"])
        for key, names in groups.items():
            if len(names) < 2:
                continue
            if flavour != "exact" and len(set(names)) == 1:
                continue  # already reported as an exact duplicate
            out.append({"member": names[0], "kind": kind,
                        "detail": (f"the member name {names[0]!r} "
                                   f"{label} ({len(names)} "
                                   f"members: "
                                   f"{', '.join(repr(n) for n in names)}); "
                                   f"extractors differ on whether "
                                   f"the first or the last member "
                                   f"is the written file, so the "
                                   f"shadowed members were never "
                                   f"judged as written files")})
    return out


def _link_divergences(members, model):
    """Link members whose targets escape the root, and member
    paths that resolve through a link member to outside the
    root."""
    out = []
    link_map = {}  # normalised member path -> (resolved parts, escaped, name)
    for m in members:
        if m["kind"] not in ("symlink", "hardlink"):
            continue
        target = m.get("linkname")
        if target is None:
            continue
        if m["kind"] == "hardlink":
            # tar hardlink targets are named from the root
            base = []
        else:
            base = _dir_parts(m["name"])
        if target.startswith("/") or target.startswith("\\"):
            if model == "extraction-dir":
                out.append({"member": m["name"],
                            "kind": "link-target-escapes",
                            "detail": (f"this {m['kind']} member's "
                                       f"target {target!r} is an "
                                       f"absolute path, so an "
                                       f"extractor that creates "
                                       f"the link points it "
                                       f"outside the extraction "
                                       f"root, at a file the "
                                       f"verdict never judged")})
                resolved, escaped = _split(target), True
            else:
                resolved, escaped = _resolve([], target)
        else:
            resolved, escaped = _resolve(base, target)
            if escaped:
                out.append({"member": m["name"],
                            "kind": "link-target-escapes",
                            "detail": (f"this {m['kind']} member's "
                                       f"target {target!r} resolves "
                                       f"outside the "
                                       f"{'extraction' if model == 'extraction-dir' else 'install'} "
                                       f"root, so an extractor that "
                                       f"creates the link points it "
                                       f"at a file the verdict "
                                       f"never judged")})
        key = "/".join(c for c in _split(m["name"])
                       if c not in ("", "."))
        link_map[key] = (resolved, escaped, m["name"])
    if not link_map:
        return out
    for m in members:
        parts = [c for c in _split(m["name"]) if c not in ("", ".")]
        for i in range(1, len(parts)):
            prefix = "/".join(parts[:i])
            if prefix not in link_map:
                continue
            resolved, escaped, link_name = link_map[prefix]
            if escaped:
                out.append({"member": m["name"],
                            "kind": "path-through-escaping-link",
                            "detail": (f"this member's path "
                                       f"passes through the link "
                                       f"member {link_name!r}, "
                                       f"whose target resolves "
                                       f"outside the root, so an "
                                       f"extractor that creates "
                                       f"the link writes this "
                                       f"member outside the root "
                                       f"as well")})
            break
    return out


def _semantics_for_members(members, model):
    out = []
    for m in members:
        if m["is_dir"]:
            continue
        for kind, detail in _name_divergences(m["name"], model):
            out.append({"member": m["name"], "kind": kind,
                        "detail": detail})
    out.extend(_duplicate_divergences(members))
    out.extend(_link_divergences(members, model))
    return out


# ======================================================================
# ZIP
# ======================================================================

def _zip_central_names(data, start_dir, count):
    """Raw member name bytes from the central directory, in
    order, or None when the walk fails."""
    names = []
    pos = start_dir
    for _ in range(count):
        if pos + 46 > len(data) or data[pos:pos + 4] != b"PK\x01\x02":
            return None
        nl, el, cl = struct.unpack_from("<HHH", data, pos + 28)
        names.append(data[pos + 46:pos + 46 + nl])
        pos += 46 + nl + el + cl
    return names


def zip_member_semantics(zf, data):
    """The member-semantics gate for a ZIP archive: zf is the
    open zipfile view (the listing), data is the raw archive
    bytes (the second view: local headers and the central
    directory as stored)."""
    infos = zf.infolist()
    # The gate judges the member names as stored in the archive.
    # The zipfile listing is not the stored name on every host:
    # ZipInfo rewrites the host separator in member names (on
    # Windows a stored name containing backslashes comes back
    # with forward slashes), which would make the classification
    # of the same archive depend on the host OS. The names are
    # therefore read from the central directory bytes, decoded
    # with the same codepage rule zipfile uses but with no
    # separator rewriting; the listing name is the fallback where
    # the central walk is unavailable.
    central_raw = None
    start_dir = getattr(zf, "start_dir", None)
    if start_dir is not None:
        central_raw = _zip_central_names(data, start_dir,
                                         len(infos))
    stored_names = []
    for i, info in enumerate(infos):
        nm = info.filename
        if central_raw is not None and i < len(central_raw):
            try:
                nm = central_raw[i].decode(
                    "utf-8" if info.flag_bits & 0x800 else "cp437")
            except Exception:
                nm = info.filename
        stored_names.append(nm)
    members = []
    divergences = []
    for i, info in enumerate(infos):
        mode = (info.external_attr >> 16) & 0xFFFF
        is_link = (info.create_system == 3
                   and stat.S_IFMT(mode) == stat.S_IFLNK)
        linkname = None
        if is_link:
            try:
                linkname = zf.read(info).decode("utf-8", "replace")
            except Exception:
                linkname = None
        members.append({"name": stored_names[i],
                        "is_dir": info.is_dir(),
                        "kind": "symlink" if is_link else
                                ("dir" if info.is_dir() else "file"),
                        "linkname": linkname})
        if not info.is_dir() and not (info.flag_bits & 0x800):
            if any(ord(c) > 127 for c in info.orig_filename):
                divergences.append(
                    {"member": stored_names[i],
                     "kind": "name-encoding-divergence",
                     "detail": "the member name is stored "
                               "without the UTF-8 flag and "
                               "contains non-ASCII bytes, so it "
                               "is decoded as CP437 by this "
                               "engine and under the local "
                               "codepage by other extractors: "
                               "the written name is not "
                               "determined by the listing"})
    divergences.extend(_semantics_for_members(members,
                                              "extraction-dir"))
    # Local header versus central directory: the listing comes
    # from the central directory, but streaming extractors read
    # the local headers, so a member whose local header names
    # it differently or sizes it differently is written
    # differently by those extractors. (central_raw was walked
    # once, above, for the stored names.)
    for i, info in enumerate(infos):
        ho = info.header_offset
        if ho + 30 > len(data) or data[ho:ho + 4] != b"PK\x03\x04":
            continue
        lflags = struct.unpack_from("<H", data, ho + 6)[0]
        lcrc, lcsize, lusize = struct.unpack_from("<III", data,
                                                  ho + 14)
        nl, el = struct.unpack_from("<HH", data, ho + 26)
        local_name = data[ho + 30:ho + 30 + nl]
        if central_raw is not None and i < len(central_raw):
            if local_name != central_raw[i]:
                divergences.append(
                    {"member": stored_names[i],
                     "kind": "local-central-name-divergence",
                     "detail": f"the member's local header "
                               f"names it {local_name!r} while "
                               f"the central directory names "
                               f"it {central_raw[i]!r}: "
                               f"extractors that read local "
                               f"headers write a different "
                               f"member than the listing shows"})
        if not (lflags & 0x8) and lcsize != 0xFFFFFFFF \
                and lusize != 0xFFFFFFFF:
            if lcsize != info.compress_size or \
                    lusize != info.file_size:
                divergences.append(
                    {"member": stored_names[i],
                     "kind": "local-central-size-divergence",
                     "detail": f"the member's local header "
                               f"declares compressed size "
                               f"{lcsize} and uncompressed "
                               f"size {lusize}, while the "
                               f"central directory declares "
                               f"{info.compress_size} and "
                               f"{info.file_size}: streaming "
                               f"extractors that trust local "
                               f"headers write a different "
                               f"member than the listing "
                               f"describes"})
        if (lflags ^ info.flag_bits) & 0x9:
            divergences.append(
                {"member": stored_names[i],
                 "kind": "local-central-flag-divergence",
                 "detail": "the member's local header "
                           "general-purpose flags differ from "
                           "the central directory's in the "
                           "encryption or data-descriptor bits, "
                           "so extractors disagree on how the "
                           "member's data is framed"})
    return divergences


# ======================================================================
# TAR
# ======================================================================

def tar_member_semantics(tf):
    """The member-semantics gate for a TAR archive, from the
    open tarfile view. Link members are reported here by
    semantics; whether a link member's contents can be
    enumerated at all is the enumeration layer's separate,
    stricter contract."""
    members = []
    for m in tf.getmembers():
        if m.isdir():
            kind = "dir"
        elif m.issym():
            kind = "symlink"
        elif m.islnk():
            kind = "hardlink"
        elif m.isfile():
            kind = "file"
        else:
            kind = "other"
        members.append({"name": m.name, "is_dir": m.isdir(),
                        "kind": kind,
                        "linkname": m.linkname
                        if kind in ("symlink", "hardlink") else None})
    return _semantics_for_members(members, "extraction-dir")


# ======================================================================
# Wave 1 packages: member listings for deb, apk (tar interiors)
# and rpm (cpio payload), in the same member shape, with the
# same keys the containers module's member dicts use, so
# duplicate detection sees the shadowing the dicts hide.
# ======================================================================

def _tar_listing(blob, prefix=""):
    out = []
    with tarfile.open(fileobj=io.BytesIO(blob), mode="r:*") as tf:
        for m in tf.getmembers():
            if m.isdir():
                kind = "dir"
            elif m.issym():
                kind = "symlink"
            elif m.islnk():
                kind = "hardlink"
            elif m.isfile():
                kind = "file"
            else:
                kind = "other"
            name = m.name
            while name.startswith("./"):
                name = name[2:]
            out.append({"name": prefix + name,
                        "is_dir": m.isdir(), "kind": kind,
                        "linkname": m.linkname
                        if kind in ("symlink", "hardlink") else None})
    return out


def _deb_listing(data):
    members = []
    pos = 8
    control = payload = None
    while pos + 60 <= len(data):
        hdr = data[pos:pos + 60]
        if hdr[58:60] != b"`\n":
            break
        name = hdr[0:16].decode("latin-1").strip()
        size = int(hdr[48:58].decode("latin-1").strip())
        body = data[pos + 60:pos + 60 + size]
        base = name.rstrip("/")
        if base.startswith("control.tar"):
            control = body
        elif base.startswith("data.tar"):
            payload = body
        pos += 60 + size + (size & 1)
    for body, prefix in ((control, "DEBIAN/"), (payload, "")):
        if body is None:
            continue
        members.extend(_tar_listing(body, prefix))
    return members


def _apk_listing(data):
    members = []
    rest = data
    import zlib
    while rest:
        dobj = zlib.decompressobj(31)
        out = dobj.decompress(rest)
        members.extend(_tar_listing(out))
        rest = dobj.unused_data
        if not dobj.eof:
            break
    return members


def _rpm_listing(data):
    from .containers import _rpm_header, _rpm_string
    pos = 96
    _e, _s, pos = _rpm_header(data, pos)
    pos = (pos + 7) & ~7
    entries, store, pos = _rpm_header(data, pos)
    compressor = None
    for tag, typ, off, cnt in entries:
        if tag == 1125:
            compressor = _rpm_string(store, typ, off, cnt)
    payload = data[pos:]
    if compressor in (None, "none"):
        blob = payload
    elif compressor == "gzip":
        blob = gzip.decompress(payload)
    elif compressor == "xz":
        blob = lzma.decompress(payload, format=lzma.FORMAT_XZ)
    elif compressor == "bzip2":
        import bz2
        blob = bz2.decompress(payload)
    else:
        return []
    members = []
    pos = 0
    while pos + 110 <= len(blob):
        if blob[pos:pos + 6] != b"070701":
            break
        fields = [int(blob[pos + 6 + i * 8:pos + 14 + i * 8], 16)
                  for i in range(13)]
        mode = fields[1]
        filesize = fields[6]
        namesize = fields[11]
        name = blob[pos + 110:pos + 110 + namesize - 1].decode(
            "utf-8", "surrogateescape")
        data_off = pos + ((110 + namesize + 3) & ~3)
        if name == "TRAILER!!!":
            break
        payload_bytes = blob[data_off:data_off + filesize]
        ftype = mode & 0xF000
        if ftype == 0x4000:
            kind, is_dir = "dir", True
        elif ftype == 0xA000:
            kind, is_dir = "symlink", False
        elif ftype == 0x8000:
            kind, is_dir = "file", False
        else:
            kind, is_dir = "other", False
        while name.startswith("./"):
            name = name[2:]
        members.append({"name": name, "is_dir": is_dir,
                        "kind": kind,
                        "linkname": payload_bytes.decode(
                            "utf-8", "replace")
                        if kind == "symlink" else None})
        pos = data_off + ((filesize + 3) & ~3)
    return members


def package_member_semantics(data, kind):
    """The member-semantics gate for a wave 1 OS package, under
    the install-root model. The listing is re-read from the
    package's own structures (the containers module's member
    dicts collapse duplicate names and pass cpio link members
    by, so the listing the verdict judged is not visible from
    them)."""
    if kind == "deb":
        members = _deb_listing(data)
    elif kind == "apk":
        members = _apk_listing(data)
    elif kind == "rpm":
        members = _rpm_listing(data)
    else:
        return []
    return _semantics_for_members(members, "install-root")


# ======================================================================
# Dispatch
# ======================================================================

def member_semantics(data, kind, path=None):
    """Divergences for one fully enumerated container, by kind:
    a list of {member, kind, detail}. Kinds outside the gate's
    scope return an empty list."""
    if kind == "zip":
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            return zip_member_semantics(zf, data)
    if kind == "tar":
        with tarfile.open(fileobj=io.BytesIO(data),
                          mode="r:*") as tf:
            return tar_member_semantics(tf)
    if kind in ("deb", "rpm", "apk"):
        return package_member_semantics(data, kind)
    return []
