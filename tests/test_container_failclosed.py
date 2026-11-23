"""Regression fixtures for the two defects found by the 1,000-case
validation pilot (validation/PILOT-REPORT.md):

Defect 1 (release-blocking): truncated or otherwise unenumerable
containers were issued NO ACCOUNTED. A container whose full contents
cannot be enumerated is unaccounted by construction and must fall to
YES UNACCOUNTED with the enumeration failure named. The shapes
covered here: truncated zip (by magic and by suffix), truncated
tar.gz, truncated tar member, encrypted zip member, member-count cap
hit, expansion-size cap hit, non-regular tar member, unsupported
container kind (7z), and a truncated zip nested inside a valid zip.

Defect 2: a banking-article false-positive twin was flagged YES
PROVEN when zip-wrapped, because the article-context discriminator
followed the container's extension (.zip) instead of the member's
(.txt). Context discriminators must apply identically to archive
members and loose files, and a fully enumerated container must not be
re-judged as code from its own raw bytes.
"""
import io, os, tarfile, zipfile

import pytest

from event_zero import verdict as verdict_mod
from event_zero.verdict import verdict


def _zip_bytes(members):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        for name, data in members:
            z.writestr(name, data)
    return buf.getvalue()


def _write(tmp_path, name, data):
    p = os.path.join(str(tmp_path), name)
    with open(p, "wb") as f:
        f.write(data)
    return p


def _assert_unaccounted(v, unit_hint):
    assert v["verdict"] == "YES", v["headline"]
    assert v["reason_class"] == "UNACCOUNTED", v["headline"]
    assert v["case_state"] == "OPEN"
    assert any(f["verdict"] == "YES: UNACCOUNTED" for f in v["files"]), v["files"]
    joined = "\n".join(v["unaccounted"])
    assert "enumerat" in joined, joined
    assert unit_hint in joined, joined


# ------------------------------------------------------------- defect 1
def test_truncated_zip_by_magic_is_unaccounted(tmp_path):
    # the exact pilot shape: a zip cut to half its bytes, saved as .bin
    data = _zip_bytes([("inner.py", b"print('hi')\n")])
    p = _write(tmp_path, "malformed.bin", data[: len(data) // 2])
    _assert_unaccounted(verdict(p), "malformed.bin")


def test_truncated_zip_by_suffix_is_unaccounted(tmp_path):
    data = _zip_bytes([("inner.py", b"print('hi')\n")])
    p = _write(tmp_path, "release.zip", data[: len(data) // 2])
    _assert_unaccounted(verdict(p), "release.zip")


def test_truncated_tar_gz_is_unaccounted(tmp_path):
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        info = tarfile.TarInfo("inner.py")
        payload = b"print('hi')\n"
        info.size = len(payload)
        tf.addfile(info, io.BytesIO(payload))
    data = buf.getvalue()
    p = _write(tmp_path, "release.tar.gz", data[: len(data) // 2])
    _assert_unaccounted(verdict(p), "release.tar.gz")


def test_truncated_tar_member_is_unaccounted(tmp_path):
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tf:
        info = tarfile.TarInfo("big.txt")
        payload = b"A" * 600
        info.size = len(payload)
        tf.addfile(info, io.BytesIO(payload))
    data = buf.getvalue()
    # keep the member header, cut the member data short
    p = _write(tmp_path, "release.tar", data[: 512 + 256])
    _assert_unaccounted(verdict(p), "release.tar")


def test_encrypted_zip_member_is_unaccounted(tmp_path):
    data = bytearray(_zip_bytes([("inner.py", b"print('hi')\n")]))
    # set the encryption flag bit in the local header and the central
    # directory header: the parser then refuses to open the member
    # without a password, so the member cannot be enumerated
    assert data[:4] == b"PK\x03\x04"
    data[6] |= 0x01
    cd = data.find(b"PK\x01\x02")
    assert cd > 0
    data[cd + 8] |= 0x01
    p = _write(tmp_path, "locked.zip", bytes(data))
    _assert_unaccounted(verdict(p), "locked.zip")


def test_member_count_cap_is_unaccounted(tmp_path, monkeypatch):
    monkeypatch.setattr(verdict_mod, "MAX_MEMBERS", 2)
    data = _zip_bytes([(f"f{i}.txt", b"hello\n") for i in range(3)])
    p = _write(tmp_path, "many.zip", data)
    _assert_unaccounted(verdict(p), "many.zip")


def test_expansion_size_cap_is_unaccounted(tmp_path, monkeypatch):
    monkeypatch.setattr(verdict_mod, "MAX_TOTAL_BYTES", 16)
    data = _zip_bytes([("big.txt", b"A" * 600)])
    p = _write(tmp_path, "big.zip", data)
    _assert_unaccounted(verdict(p), "big.zip")


def test_tar_symlink_member_is_unaccounted(tmp_path):
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tf:
        info = tarfile.TarInfo("link.py")
        info.type = tarfile.SYMTYPE
        info.linkname = "/etc/passwd"
        tf.addfile(info)
    p = _write(tmp_path, "links.tar", buf.getvalue())
    _assert_unaccounted(verdict(p), "links.tar")


def test_unsupported_7z_container_is_unaccounted(tmp_path):
    data = b"7z\xbc\xaf'\x1c" + b"\x00" * 26 + b"stored text that is not a program"
    p = _write(tmp_path, "release.7z", data)
    _assert_unaccounted(verdict(p), "release.7z")


def test_nested_truncated_zip_is_unaccounted(tmp_path):
    inner = _zip_bytes([("inner.py", b"print('hi')\n")])
    outer = _zip_bytes([("inner.zip", inner[: len(inner) // 2]), ("readme.txt", b"hello\n")])
    p = _write(tmp_path, "outer.zip", outer)
    _assert_unaccounted(verdict(p), "inner.zip")


def test_valid_zip_still_enumerates_clean(tmp_path):
    data = _zip_bytes([("notes.txt", b"ordinary release notes\n")])
    p = _write(tmp_path, "clean.zip", data)
    v = verdict(p)
    assert v["verdict"] == "NO", v["headline"]
    assert v["reason_class"] == "ACCOUNTED"


# ------------------------------------------------------------- defect 2
ARTICLE = """Banking trojans in the news, explained for readers. Article 0.
Security reporters this week described stealers that watch for banking sites.
The article mentions several banks by name for context:
Bank of America (bankofamerica.com), JPMorgan Chase (chase.com),
Wells Fargo (wellsfargo.com), and Citibank (citi.com) were all named in vendor blogs.
No code is included in this article; it is reporting, not software.
"""

TROJAN = """; generated variant 0
targets:
https://www.bankofamerica.com/login
https://www.chase.com/auth
https://online.wellsfargo.com/login
https://www.citi.com/login
hook = WebInject
formgrab = true
"""


def test_banking_article_loose_is_no(tmp_path):
    p = _write(tmp_path, "banking_article_0.txt", ARTICLE.encode())
    v = verdict(p)
    assert v["verdict"] == "NO", v["headline"]


def test_banking_article_in_zip_is_no(tmp_path):
    data = _zip_bytes([("banking_article_0.txt", ARTICLE.encode())])
    p = _write(tmp_path, "banking_article_0.txt.zip", data)
    v = verdict(p)
    assert v["verdict"] == "NO", v["headline"]
    assert v["reason_class"] == "ACCOUNTED"


def test_banking_trojan_in_zip_is_still_proven(tmp_path):
    # the member is judged with its own context: a real target list in
    # a code file inside the same kind of zip is still proof
    data = _zip_bytes([("banking_0.py", TROJAN.encode())])
    p = _write(tmp_path, "banking_0.py.zip", data)
    v = verdict(p)
    assert v["verdict"] == "YES", v["headline"]
    assert v["reason_class"] == "PROVEN"
    assert any("family-banking-targets" in (f.get("chains") or []) for f in v["files"]), v["files"]
