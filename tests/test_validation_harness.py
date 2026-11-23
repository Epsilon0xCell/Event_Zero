"""Tests for the validation harness itself (phase 1).

Covers: manifest root stability, sealed-expectation separation, and
the scorer's error classification, including a planted false NO and a
planted missing line. The scorer is imported directly; it must never
import the engine.
"""
import os, sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from validation.harness.manifest import (canonical, manifest_root, split_manifest,
                                         validate_case)
from validation.harness import scorer


def make_case(case_id="c1", token="YES", rendering="PROVEN"):
    return {
        "case_id": case_id,
        "sha256": "a" * 64,
        "kind": "file",
        "stratum": "test-stratum",
        "split": "development",
        "tier": "T0",
        "provenance": {"source": "test", "source_ref": "test", "terms_basis": "none",
                       "acquired": "2026-11-23", "first_seen": "2026-11-23"},
        "label": {"expected_token": token, "expected_rendering": rendering,
                  "required_atoms": ["Login Data"], "family": "stealer",
                  "label_status": "constructed", "labellers": ["test"],
                  "adjudication_ref": "test"},
        "structure": {"layer_tree_hash": "b" * 64, "genuine_ref_sha256": None,
                      "twin_case_id": None, "cluster_id": "cluster-test"},
    }


def sealed_of(case):
    return {"case_id": case["case_id"], "stratum": case["stratum"],
            "split": case["split"], "tier": case["tier"], "label": case["label"]}


def result(case_id="c1", token="YES", rendering="PROVEN", atoms=("string/text: Login Data",), **kw):
    r = {"case_id": case_id, "verdict_token": token, "rendering": rendering,
         "atoms": list(atoms), "ledger_root": "c" * 64, "runtime_ms": 10, "status": "ok"}
    r.update(kw)
    return r


def test_manifest_root_stable_and_sensitive():
    cases = [make_case("c1"), make_case("c2")]
    root1 = manifest_root(cases)
    assert root1 == manifest_root([make_case("c1"), make_case("c2")])
    changed = [make_case("c1"), make_case("c2")]
    changed[1]["stratum"] = "other"
    assert manifest_root(changed) != root1
    # canonical form is key-order independent
    a = {"b": 1, "a": 2}
    b = {"a": 2, "b": 1}
    assert canonical(a) == canonical(b)


def test_validate_case_catches_bad_token():
    case = make_case()
    assert validate_case(case) == []
    case["label"]["expected_token"] = "MAYBE"
    assert any("expected_token" in p for p in validate_case(case))


def test_split_manifest_separates_labels():
    cases = [make_case("c1"), make_case("c2", token="NO", rendering="ACCOUNTED")]
    runner, sealed = split_manifest(cases)
    for rc in runner:
        assert "label" not in rc
        assert rc["case_id"] in ("c1", "c2")
    assert sealed[0]["label"]["expected_token"] == "YES"
    assert sealed[1]["label"]["expected_token"] == "NO"


def test_scorer_correct_case_passes():
    card = scorer.score([sealed_of(make_case())], [result()])
    assert card["pass"] is True
    assert card["correct"] == 1


def test_scorer_planted_false_no_is_release_blocking():
    exp = sealed_of(make_case(token="YES", rendering="PROVEN"))
    bad = result(token="NO", rendering="ACCOUNTED")
    card = scorer.score([exp], [bad])
    assert card["pass"] is False
    assert card["error_counts"].get("false-no") == 1
    assert card["release_blocking"]["false-no"] == 1


def test_scorer_planted_missing_line():
    exp = sealed_of(make_case())
    card = scorer.score([exp], [])
    assert card["error_counts"].get("missing-line") == 1
    assert card["correct"] == 0


def test_scorer_false_yes_and_wrong_reason():
    exp_no = sealed_of(make_case(token="NO", rendering="ACCOUNTED"))
    card = scorer.score([exp_no], [result(token="YES", rendering="UNACCOUNTED")])
    assert card["error_counts"].get("false-yes") == 1
    exp_yes = sealed_of(make_case(token="YES", rendering="PROVEN"))
    card2 = scorer.score([exp_yes], [result(token="YES", rendering="UNACCOUNTED")])
    assert card2["error_counts"].get("wrong-reason") == 1


def test_scorer_open_state_rules():
    exp = sealed_of(make_case(token="OPEN_STATE", rendering="OPEN"))
    ok = result(token="YES", rendering="UNACCOUNTED", atoms=(), case_state="OPEN")
    assert scorer.score([exp], [ok])["pass"] is True
    closed = result(token="YES", rendering="PROVEN")
    assert scorer.score([exp], [closed])["error_counts"].get("wrong-reason") == 1
    clean = result(token="NO", rendering="ACCOUNTED")
    assert scorer.score([exp], [clean])["error_counts"].get("false-no") == 1


def test_scorer_fabricated_proof_and_wrong_family():
    exp = sealed_of(make_case())
    empty = result(atoms=())
    assert scorer.score([exp], [empty])["error_counts"].get("fabricated-proof") == 1
    wrong_fam = result(family="miner")
    assert scorer.score([exp], [wrong_fam])["error_counts"].get("wrong-family") == 1


def test_scorer_determinism_and_crash_and_timeout():
    exp = sealed_of(make_case())
    det = result(determinism_ok=False)
    assert scorer.score([exp], [det])["error_counts"].get("determinism-failure") == 1
    crash = result(status="crash")
    assert scorer.score([exp], [crash])["error_counts"].get("crash") == 1
    timeout = result(status="timeout")
    assert scorer.score([exp], [timeout])["error_counts"].get("timeout") == 1


def test_scorer_does_not_import_engine():
    import validation.harness.scorer as s
    import ast
    tree = ast.parse(open(s.__file__).read())
    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(a.name.split(".")[0] for a in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.add(node.module.split(".")[0])
    assert "event_zero" not in imported
