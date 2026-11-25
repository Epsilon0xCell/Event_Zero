"""Coverage wave 9 tests: capa-backed capability evidence and
the pinned, hashed dependency set.

Synthetic fixtures only. The capa seam tests substitute a
recorded capa-shaped result at the adapter's runner seam, so
they are deterministic in any environment; one live test runs
the real flare-capa 9.4.0 against the pinned capa-rules v9.4.0
corpus when both are present and skips, named, when they are
not. See validation/COVERAGE-WAVE-9-LOG.md for the audit, what
was built, and the named remainder.

Governance under test, from the failure-modes research: capa
reports capabilities, not verdicts. A capa-only match forms no
chain, moves no score, and changes no headline; a capa failure
degrades to the own-matcher evidence with the failure named,
never to silence and never to a cap.
"""
import json
import os
import re
import shutil
import sys
from types import SimpleNamespace

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from event_zero import capa_evidence
from event_zero.analyzer import analyze
from event_zero.verdict import verdict

REPO = os.path.join(os.path.dirname(__file__), "..")
HELLO_ELF = os.path.join(REPO, "fixtures", "hello_elf")

RECORDED_ENTRY = {
    "id": "capa:connect-tcp-socket",
    "name": "connect TCP socket",
    "attack_id": "",
    "tactic": "communication",
    "technique": "communication/socket/tcp",
    "evidence": ["capa rule matched at 1 location(s)",
                 "rule scope: function",
                 "capa namespace: communication/socket/tcp"],
    "explanation": "Capability reported by the capa rule "
                   "'connect TCP socket' (recorded fixture).",
    "source": "capa",
    "rule_id": "connect TCP socket",
    "scope": "function",
}


def _fake_bundle():
    return (object(), {}, "capa-rules v9.4.0 (recorded fixture)")


@pytest.fixture(autouse=True)
def _clean_memo():
    capa_evidence._memo.clear()
    yield
    capa_evidence._memo.clear()


@pytest.fixture()
def seam_ok(monkeypatch):
    """The adapter with its runner seam returning a recorded
    capa-shaped result."""
    monkeypatch.setattr(capa_evidence, "_capa_installed",
                        lambda: True)
    monkeypatch.setattr(capa_evidence, "_load_ruleset",
                        _fake_bundle)
    monkeypatch.setattr(
        capa_evidence, "_run_capa",
        lambda path, fmt, bundle: [dict(RECORDED_ENTRY)])
    return capa_evidence


# ======================================================================
# Merge and entry-shaping semantics
# ======================================================================

def test_merge_capabilities_dedupes_and_keeps_own_first():
    own = [{"id": "net-connect"}, {"id": "exec-shell"}]
    extra = [{"id": "capa:connect-tcp-socket"},
             {"id": "net-connect"},
             {"id": "capa:check-os-version"}]
    merged = capa_evidence.merge_capabilities(own, extra)
    assert [c["id"] for c in merged] == [
        "net-connect", "exec-shell",
        "capa:connect-tcp-socket", "capa:check-os-version"]


def _fake_rule(name, meta, scope="Scope.FUNCTION"):
    return SimpleNamespace(
        name=name, meta=meta,
        scopes=SimpleNamespace(static=scope))


def test_entries_from_matches_shape_scope_and_lib_filter():
    by_name = {
        "connect TCP socket": _fake_rule(
            "connect TCP socket",
            {"namespace": "communication/socket/tcp",
             "mbc": ["Communication::Socket Communication::"
                     "Connect Socket [C0001.004]"]}),
        "contain loop": _fake_rule("contain loop", {"lib": True}),
        "check OS version": _fake_rule(
            "check OS version",
            {"namespace": "host-interaction/os/version"},
            scope="Scope.BASIC_BLOCK"),
    }
    matches = {
        "connect TCP socket": [object(), object()],
        "contain loop": [object()],
        "check OS version/1326e971fae74b5d9484c2fa64dbde69":
            [object()],
        "check OS version/8f47fbe8dfc744aa9624887b93821ac3": 
            [object(), object()],
    }
    entries = capa_evidence._entries_from_matches(matches, by_name)
    ids = [e["id"] for e in entries]
    # lib rules are library identification, not capabilities.
    assert "capa:contain-loop" not in ids
    # subscope instances collapse into the base rule, locations
    # summed.
    assert ids == ["capa:check-os-version",
                   "capa:connect-tcp-socket"]
    check = entries[0]
    assert check["evidence"][0] == \
        "capa rule matched at 3 location(s)"
    assert check["scope"] == "basic_block"
    for entry in entries:
        assert entry["source"] == "capa"
        assert entry["rule_id"]
        for key in ("id", "name", "attack_id", "tactic",
                    "technique", "evidence", "explanation"):
            assert key in entry
        assert isinstance(entry["attack_id"], str)
        assert isinstance(entry["evidence"], list)


# ======================================================================
# Degradation: named, never silent, never a cap
# ======================================================================

def test_capa_failure_degrades_named(monkeypatch, tmp_path):
    monkeypatch.setattr(capa_evidence, "_capa_installed",
                        lambda: True)
    monkeypatch.setattr(capa_evidence, "_load_ruleset",
                        _fake_bundle)

    def boom(path, fmt, bundle):
        raise RuntimeError("vivisect exploded")

    monkeypatch.setattr(capa_evidence, "_run_capa", boom)
    target = tmp_path / "sample.exe"
    target.write_bytes(b"MZ" + b"\x00" * 64)
    entries, status = capa_evidence.capa_capabilities(
        str(target), "PE", target.read_bytes())
    assert entries == []
    assert status["status"] == "failed"
    assert "vivisect exploded" in status["note"]
    assert "own-matcher evidence stands" in status["note"]


def test_capa_unavailable_when_package_missing(monkeypatch,
                                              tmp_path):
    monkeypatch.setattr(capa_evidence, "_capa_installed",
                        lambda: False)
    target = tmp_path / "sample.exe"
    target.write_bytes(b"MZ" + b"\x00" * 64)
    entries, status = capa_evidence.capa_capabilities(
        str(target), "PE", target.read_bytes())
    assert entries == []
    assert status["status"] == "unavailable"
    assert "requirements-capa.txt" in status["note"]


def test_capa_unavailable_when_rules_missing(monkeypatch,
                                             tmp_path):
    monkeypatch.setattr(capa_evidence, "_capa_installed",
                        lambda: True)

    def no_rules():
        raise RuntimeError("the capa-rules corpus is not present")

    monkeypatch.setattr(capa_evidence, "_load_ruleset", no_rules)
    target = tmp_path / "sample"
    target.write_bytes(b"\x7fELF" + b"\x00" * 64)
    entries, status = capa_evidence.capa_capabilities(
        str(target), "ELF", target.read_bytes())
    assert entries == []
    assert status["status"] == "unavailable"
    assert "capa-rules corpus is not present" in status["note"]


def test_capa_skips_other_formats_and_oversized(monkeypatch):
    monkeypatch.setattr(capa_evidence, "_capa_installed",
                        lambda: True)
    entries, status = capa_evidence.capa_capabilities(
        "x.txt", "script", b"echo hi")
    assert entries == [] and status["status"] == "skipped"
    monkeypatch.setattr(capa_evidence, "MAX_FILE_BYTES", 4)
    entries, status = capa_evidence.capa_capabilities(
        "x.bin", "PE", b"MZ" + b"\x00" * 64)
    assert entries == [] and status["status"] == "skipped"
    assert "budget" in status["note"]


def test_capa_disabled_by_env(monkeypatch, tmp_path):
    monkeypatch.setenv("EZ_CAPA", "0")
    target = tmp_path / "sample"
    target.write_bytes(b"\x7fELF" + b"\x00" * 64)
    entries, status = capa_evidence.capa_capabilities(
        str(target), "ELF", target.read_bytes())
    assert entries == []
    assert status["status"] == "unavailable"
    assert "EZ_CAPA=0" in status["note"]


# ======================================================================
# The merge at the analyzer and verdict layers (seam-driven)
# ======================================================================

def test_analyzer_merges_capa_entries_with_source(seam_ok):
    rep = analyze(HELLO_ELF)
    assert rep["capa"]["status"] == "ok"
    assert rep["capa"]["rules"] and \
        "capa-rules v9.4.0" in rep["capa"]["rules"]
    capa_entries = [c for c in rep["capabilities"]
                    if c.get("source") == "capa"]
    own_entries = [c for c in rep["capabilities"]
                   if c.get("source") == "event-zero"]
    assert [c["id"] for c in capa_entries] == \
        ["capa:connect-tcp-socket"]
    assert own_entries, "the own matcher still reports its own"


def test_capa_evidence_does_not_move_analyzer_risk(seam_ok,
                                                   monkeypatch):
    with_capa = analyze(HELLO_ELF)
    monkeypatch.setattr(
        capa_evidence, "_run_capa",
        lambda path, fmt, bundle: [])
    capa_evidence._memo.clear()
    without = analyze(HELLO_ELF)
    assert with_capa["risk"] == without["risk"]


def test_verdict_record_carries_capa_status(seam_ok, tmp_path):
    shutil.copy(HELLO_ELF, tmp_path / "hello_elf")
    v = verdict(str(tmp_path))
    rec = next(f for f in v["files"]
               if f["path_in_release"] == "hello_elf")
    assert rec["capa"]["status"] == "ok"
    assert "capa:connect-tcp-socket" in rec["capabilities"]


def test_capa_only_match_does_not_convict(seam_ok, monkeypatch,
                                          tmp_path):
    """The governance test: the same release, with and without
    the capa entry, earns the same headline, and no proven
    chain cites the capa evidence."""
    shutil.copy(HELLO_ELF, tmp_path / "hello_elf")
    with_capa = verdict(str(tmp_path))
    monkeypatch.setattr(
        capa_evidence, "_run_capa",
        lambda path, fmt, bundle: [])
    capa_evidence._memo.clear()
    without = verdict(str(tmp_path))
    assert with_capa["verdict"] == without["verdict"]
    blob = json.dumps(with_capa.get("yes_reasons", []),
                      default=str)
    assert "capa" not in blob


# ======================================================================
# Live run (real flare-capa, pinned corpus), when present
# ======================================================================

def test_live_capa_run_on_hello_elf():
    entries, status = capa_evidence.capa_capabilities(
        HELLO_ELF, "ELF")
    if status["status"] == "unavailable":
        pytest.skip(f"capa source unavailable here: "
                    f"{status['note']}")
    assert status["status"] == "ok", status
    assert status["rules"] and \
        "capa-rules v9.4.0" in status["rules"]
    assert entries, "the live run matched no capa rules"
    for entry in entries:
        assert entry["source"] == "capa"
        assert entry["id"].startswith("capa:")
        for key in ("name", "attack_id", "tactic", "technique",
                    "evidence", "explanation", "rule_id",
                    "scope"):
            assert key in entry


# ======================================================================
# The pinned set (Part C)
# ======================================================================

def _pins(fname):
    pins = {}
    text = open(os.path.join(REPO, fname)).read()
    for line in text.splitlines():
        m = re.match(r"^([A-Za-z0-9_.-]+)==([^\s\\]+)", line)
        if m:
            pins[m.group(1).lower()] = m.group(2)
    return pins, text


def test_requirements_files_are_fully_pinned_and_hashed():
    for fname in ("requirements.txt", "requirements-capa.txt",
                  "requirements-dev.txt"):
        _pins_d, text = _pins(fname)
        for line in text.splitlines():
            if line and not line.startswith((" ", "#", "-")):
                assert "==" in line, f"{fname}: unpinned: {line}"
        assert "--hash=sha256:" in text, \
            f"{fname}: no hashes recorded"


def test_pinned_set_covers_the_runtime_audit():
    pins, _text = _pins("requirements.txt")
    for pkg in ("lief", "capstone", "pefile", "pyelftools",
                "unicorn", "cryptography", "google-genai",
                "pyzipper"):
        assert pkg in pins, f"{pkg} missing from requirements.txt"
    # The versions the suite is verified on in this environment.
    assert pins["lief"] == "1.0.0"
    assert pins["capstone"] == "5.0.9"
    assert pins["pefile"] == "2024.8.26"
    assert pins["pyelftools"] == "0.33"
    assert pins["unicorn"] == "2.1.4"
    assert pins["cryptography"] == "50.0.2"
    capa_pins, _t = _pins("requirements-capa.txt")
    assert capa_pins["flare-capa"] == "9.4.0"
    dev_pins, _t2 = _pins("requirements-dev.txt")
    assert dev_pins["pytest"] == "9.2.0"


def test_workflows_consume_the_pinned_set():
    for wf in ("tests.yml", "verify.yml", "campaign.yml"):
        text = open(os.path.join(
            REPO, ".github", "workflows", wf)).read()
        installs = [ln.strip() for ln in text.splitlines()
                    if "pip install" in ln and "run:" in ln]
        assert installs, f"{wf}: no pip install step"
        for ln in installs:
            assert "--require-hashes" in ln, \
                f"{wf}: unpinned install step: {ln}"
            assert "requirements" in ln


def test_rules_pin_constants_match_fetch_script():
    script = open(os.path.join(
        REPO, "tools", "fetch_capa_rules.sh")).read()
    assert capa_evidence.RULES_COMMIT in script
    assert capa_evidence.RULES_ARCHIVE_SHA256 in script
    assert capa_evidence.RULES_VERSION in script
    assert capa_evidence.CAPA_VERSION_PIN == "9.4.0"
