"""Tests for the campaign structural diagnosis shaping
(validation/campaign/diagnose.py).

The shaping function is exercised against synthetic engine
report fixtures only: no sample is downloaded, no network is
touched, and no engine code runs. The fixtures deliberately
plant content-bearing fields (string dumps, script source,
decoded-layer results, script-ledger line text) in the inputs
so the tests prove those fields never reach the diagnosis.
"""
import hashlib
import importlib.util
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

_SPEC = importlib.util.spec_from_file_location(
    "campaign_diagnose",
    os.path.join(os.path.dirname(__file__), "..",
                 "validation", "campaign", "diagnose.py"))
diagnose = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(diagnose)

NON_LEDGER_URL = "http://cdn.example.net:9090/drop/payload.exe?x=1"
LEDGER_URL = "http://protware.com/stage.bin"

CONTENT_KEYS = {"strings", "script_source", "script_source_full",
                "script_source_excerpt", "result"}


def _all_keys(node):
    keys = set()
    if isinstance(node, dict):
        for key, value in node.items():
            keys.add(key)
            keys |= _all_keys(value)
    elif isinstance(node, list):
        for value in node:
            keys |= _all_keys(value)
    return keys


def _no_report():
    return {
        "headline": "NO: ACCOUNTED",
        "verdict": "NO",
        "reason_class": "ACCOUNTED",
        "case_state": "NO",
        "scope": "Scope: every byte of artefact azienda_08.hta is accounted.",
        "files": [{
            "name": "azienda_08.hta",
            "path_in_release": "azienda_08.hta",
            "origin": "file",
            "size_bytes": 6975,
            "sha256": "a" * 64,
            "format": "script",
            "signed": None,
            "signature_valid": None,
            "reference": None,
            "verdict": "NO: ACCOUNTED",
            "analysis_verdict": "NO MALICIOUS CAPABILITY DETECTED",
            "why": ["Accounted: this is a script or text file, so it "
                    "was fully reverse-engineered by reading all of "
                    "its source."],
            "capabilities": [],
            "capa": None,
            "chains": [],
            "family_chains": [],
            "family_notes": [],
            "byte_ownership": None,
            "external_references": {
                "references": [{
                    "kind": "url",
                    "target": NON_LEDGER_URL,
                    "source": "script scan",
                    "disposition": "unresolved",
                    "basis": "the target was not examined in this run",
                }],
                "complete": True,
                "note": "",
            },
            "script_ledger": {
                "lines": 40, "allowlisted": 3, "structural": 37,
                "flagged": [], "unaccounted": [],
            },
        }],
        "blockers": [],
        "yes_reasons": [],
        "connection_ledger": [
            {"id": "c0001",
             "dest": {"url": NON_LEDGER_URL, "domain": "cdn.example.net",
                      "ip": None, "port": 9090, "scheme": "http",
                      "path": "/drop/payload.exe"},
             "source_file": "azienda_08.hta",
             "provenance": "written-in-file",
             "classification": "external", "tag": "",
             "observed": False, "note": ""},
            {"id": "c0002",
             "dest": {"url": LEDGER_URL, "domain": "protware.com",
                      "ip": None, "port": 80, "scheme": "http",
                      "path": "/stage.bin"},
             "source_file": "azienda_08.hta",
             "provenance": "written-in-file",
             "classification": "external", "tag": "",
             "observed": False, "note": ""},
        ],
        "open_items": [],
        "next_rung": None,
    }


def _no_analyzer_reports():
    return {"a" * 64: {
        "hashes": {"sha256": "a" * 64},
        "risk": {"verdict": "NO MALICIOUS CAPABILITY DETECTED",
                 "score": 0},
        "strings": {"all": ["SECRET_STRING_DUMP"],
                    "count": 1},
        "script_source_full": "SECRET_SCRIPT_SOURCE",
        "unpack": {"decoded_layers": [
            {"chain": ["base64"], "result": "SECRET_DECODED_CONTENT"},
        ]},
        "truncations": ["the entropy map covers only the first "
                        "16384 bytes"],
    }}


def _yes_report():
    unowned = {"start": 3584, "end": 4096, "size": 512,
               "offset_hex": "0xe00", "entropy": 7.9,
               "reason": "no analysis owns this range",
               "material": True}
    blocker = ("payload.exe: byte-ownership: the range at offset "
               "0xe00 (512 bytes) has no accounted owner; see "
               "http://hidden.example.org/x.bin for the pattern.")
    return {
        "headline": "YES: UNACCOUNTED",
        "verdict": "YES",
        "reason_class": "UNACCOUNTED",
        "case_state": "OPEN",
        "scope": "Scope: this case is OPEN, with 1 open item(s).",
        "files": [{
            "name": "payload.exe",
            "path_in_release": "payload.exe",
            "origin": "file",
            "size_bytes": 4096,
            "sha256": "b" * 64,
            "format": "PE",
            "signed": False,
            "signature_valid": False,
            "reference": None,
            "verdict": "YES: UNACCOUNTED",
            "analysis_verdict": "HIGH RISK",
            "why": [blocker],
            "capabilities": ["net-connect", "capa:download-file"],
            "capa": {"status": "ok", "note": "capa evidence merged",
                     "capa_version": "9.4.0", "rules": "v9.4.0",
                     "backend": "vivisect", "matches": 1},
            "chains": [],
            "family_chains": [],
            "family_notes": [],
            "byte_ownership": {
                "format": "PE", "basis": "structure parsed",
                "complete": False,
                "owned": [{"start": 0, "end": 1024,
                           "owner": "PE headers"},
                          {"start": 1024, "end": 3584,
                           "owner": "section .text"}],
                "unowned": [unowned],
                "material_unowned": [unowned],
                "notes": [],
            },
            "external_references": None,
            "script_ledger": None,
        }],
        "blockers": [blocker],
        "yes_reasons": [],
        "connection_ledger": [],
        "open_items": [blocker],
        "next_rung": 4,
    }


def test_shape_no_accounted_has_decision_trace_and_no_content():
    shaped = diagnose.shape_diagnosis(
        _no_report(), analyzer_reports=_no_analyzer_reports(),
        sample={"sha256": diagnose.SAMPLE_008})
    assert shaped["verdict"] == "NO"
    assert shaped["reason_class"] == "ACCOUNTED"
    trace = shaped["decision_trace"]
    assert trace["decision_rule"]
    assert trace["proven_chains_fired"] == 0
    assert trace["blockers_fired"] == 0
    assert trace["units"][0]["decision_branch"] == "script-fully-read"
    assert trace["evaluated_but_unfired_blockers"]["recorded_by_engine"] is False

    unit = shaped["units"][0]
    assert unit["name"] == "azienda_08.hta"
    assert unit["format"] == "script"
    # decoded layers are summarised by kind, size, and hash only
    layers = unit["decoded_layers"]
    assert len(layers) == 1
    assert layers[0]["chain"] == ["base64"]
    assert layers[0]["result_bytes"] == len("SECRET_DECODED_CONTENT")
    assert layers[0]["result_sha256"] == hashlib.sha256(
        b"SECRET_DECODED_CONTENT").hexdigest()
    # script ledger is counts and kinds, never line text
    assert unit["findings"]["script_ledger"]["lines"] == 40

    blob = json.dumps(shaped)
    for marker in ("SECRET_STRING_DUMP", "SECRET_SCRIPT_SOURCE",
                   "SECRET_DECODED_CONTENT"):
        assert marker not in blob
    assert not (CONTENT_KEYS & _all_keys(shaped))


def test_shape_no_accounted_reduces_external_references():
    shaped = diagnose.shape_diagnosis(
        _no_report(), analyzer_reports=_no_analyzer_reports())
    unit = shaped["units"][0]
    ref = unit["external_references"]["references"][0]
    assert ref["scheme"] == "http"
    assert ref["host"] == "cdn.example.net"
    assert ref["url_sha256"] == hashlib.sha256(
        NON_LEDGER_URL.encode()).hexdigest()
    assert ref["full_url_recorded"] is False
    assert "url" not in ref
    assert "target" not in ref

    ledger = shaped["connection_ledger"]
    assert ledger[0]["dest"]["host"] == "cdn.example.net"
    assert "path" not in ledger[0]["dest"]
    # the ledger-public host keeps its full URL
    assert ledger[1]["dest"]["url"] == LEDGER_URL
    assert ledger[1]["dest"]["full_url_recorded"] is True

    blob = json.dumps(shaped)
    assert NON_LEDGER_URL not in blob
    assert "/drop/payload.exe" not in blob


def test_shape_yes_unaccounted_has_coverage_summary_and_trace():
    shaped = diagnose.shape_diagnosis(_yes_report())
    assert shaped["verdict"] == "YES"
    assert shaped["reason_class"] == "UNACCOUNTED"
    trace = shaped["decision_trace"]
    assert trace["blockers_fired"] == 1
    assert trace["units"][0]["decision_branch"] == "blocker"
    assert trace["next_rung"] == 4

    unit = shaped["units"][0]
    ownership = unit["byte_ownership"]
    assert ownership["owned_bytes"] == 3584
    assert ownership["owned_ranges"][1]["owner"] == "section .text"
    assert ownership["material_unowned_count"] == 1
    assert ownership["unowned_ranges"][0]["offset_hex"] == "0xe00"
    assert ownership["complete"] is False

    sources = {c["id"]: c["source"] for c in unit["capabilities"]}
    assert sources == {"net-connect": "event-zero",
                       "capa:download-file": "capa"}
    assert unit["capa"]["status"] == "ok"

    # a non-ledger URL inside a blocker reason string is reduced
    blob = json.dumps(shaped)
    assert "http://hidden.example.org/x.bin" not in blob
    assert "[url reduced: http://hidden.example.org" in blob


def test_reduce_reference_keeps_only_scheme_host_and_hash():
    url = "https://evil.example.com:8443/a/b.exe?token=zzz"
    entry = diagnose.reduce_reference(url)
    assert entry["scheme"] == "https"
    assert entry["host"] == "evil.example.com"
    assert entry["url_sha256"] == hashlib.sha256(
        url.encode()).hexdigest()
    assert entry["full_url_recorded"] is False
    assert "url" not in entry


def test_reduce_reference_ledger_public_host_keeps_full_url():
    entry = diagnose.reduce_reference(LEDGER_URL)
    assert entry["url"] == LEDGER_URL
    assert entry["full_url_recorded"] is True
    subdomain = diagnose.reduce_reference("http://cdn.protware.com/x")
    assert subdomain["full_url_recorded"] is True
    lookalike = diagnose.reduce_reference("http://notprotware.com/x")
    assert lookalike["full_url_recorded"] is False


def test_default_hashes_are_the_007_and_008_samples():
    assert diagnose.DEFAULT_HASHES == [diagnose.SAMPLE_007,
                                       diagnose.SAMPLE_008]
    assert diagnose.SAMPLE_007 == (
        "03e548ca313467cc8716fa135199414f36ca37884cd95b6cdd1b9a37c3bee71a")
    assert diagnose.SAMPLE_008 == (
        "04b5784000d66093995c13dddb0f346996aea2b7fc9ce0d420f5b596ad70fe72")
