"""Report signing and run receipts (HARDENING-ROADMAP item 1, plus
the proof-for-every-run order): sign and verify round trip, tampered
verdict fails, unsigned degradation, deterministic ledger root, and a
receipt with a swapped sample hash fails verification. Keys are
generated per test and passed only through the EZ_SIGNING_KEY
environment variable, exactly as in production."""
import copy, json, os, subprocess, sys
import pytest
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
cryptography = pytest.importorskip("cryptography")
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
from event_zero.verdict import verdict
from event_zero.signing import (sign_report, verify_report, build_receipt, sign_receipt,
                                verify_receipt, receipt_core, canonicalise)
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

KEYGEN = 'import hashlib\n# keygen\nprint("serial:", hashlib.md5(b"x").hexdigest()[:8])\n'

def pem_key():
    k = Ed25519PrivateKey.generate()
    return k.private_bytes(serialization.Encoding.PEM,
                           serialization.PrivateFormat.PKCS8,
                           serialization.NoEncryption()).decode()

def make_verdict(tmp_path):
    p = os.path.join(str(tmp_path), "keygen.py")
    with open(p, "w") as f:
        f.write(KEYGEN)
    return verdict(p)

def test_sign_verify_round_trip(tmp_path, monkeypatch):
    monkeypatch.setenv("EZ_SIGNING_KEY", pem_key())
    v = make_verdict(tmp_path)
    signed = sign_report(v)
    assert signed["signature"]["status"] == "signed"
    assert signed["signature"]["algorithm"] == "Ed25519"
    res = verify_report(signed)
    assert res["status"] == "verified", res
    assert all(res["checks"].values()), res["checks"]

def test_tampered_verdict_fails(tmp_path, monkeypatch):
    monkeypatch.setenv("EZ_SIGNING_KEY", pem_key())
    signed = sign_report(make_verdict(tmp_path))
    tampered = copy.deepcopy(signed)
    tampered["verdict"] = "YES" if signed["verdict"] == "NO" else "NO"
    res = verify_report(tampered)
    assert res["status"] == "failed", res
    assert res["problems"]

def test_unsigned_degradation(tmp_path, monkeypatch):
    monkeypatch.delenv("EZ_SIGNING_KEY", raising=False)
    v = make_verdict(tmp_path)
    out = sign_report(v)
    assert out["signature"]["status"] == "unsigned"
    assert "must never be presented as verified" in out["signature"]["note"]
    res = verify_report(out)
    assert res["status"] == "unsigned", res

def test_receipt_deterministic_ledger_root(tmp_path):
    v = make_verdict(tmp_path)
    r1 = build_receipt(v)
    r2 = build_receipt(v)
    assert r1["ledger_root_hash"] == r2["ledger_root_hash"]
    assert canonicalise(receipt_core(r1)) == canonicalise(receipt_core(r2))
    # a second identical run of the tool reproduces the same root
    v2 = make_verdict(tmp_path)
    assert v2["receipt"]["ledger_root_hash"] == v["receipt"]["ledger_root_hash"]

def test_receipt_sign_and_swapped_sample_hash_fails(tmp_path, monkeypatch):
    monkeypatch.setenv("EZ_SIGNING_KEY", pem_key())
    v = make_verdict(tmp_path)
    receipt = sign_receipt(build_receipt(v))
    assert receipt["signature"]["status"] == "signed"
    res = verify_receipt(receipt, report=v)
    assert res["status"] == "verified", res
    bad = copy.deepcopy(receipt)
    bad["sample_sha256"] = "0" * 64
    res2 = verify_receipt(bad, report=v)
    assert res2["status"] == "failed", res2

def test_verdict_carries_receipt(tmp_path, monkeypatch):
    monkeypatch.delenv("EZ_SIGNING_KEY", raising=False)
    v = make_verdict(tmp_path)
    r = v["receipt"]
    assert r["schema"] == "eventzero.run-receipt/1"
    assert r["verdict"] == v["verdict"] and r["reason_class"] == v["reason_class"]
    assert r["case_state"] == v["case_state"]
    assert r["signature"]["status"] == "unsigned"

def test_run_id_is_derived_not_random(tmp_path):
    from event_zero.signing import derive_run_id, build_receipt
    v = make_verdict(tmp_path)
    r = build_receipt(v)
    expect = derive_run_id(r["sample_sha256"], None, "3.0.0")
    assert r["run_id"] == expect
    assert build_receipt(v)["run_id"] == r["run_id"]          # same inputs, same id
    other = derive_run_id("f" * 64, None, "3.0.0")
    assert other != r["run_id"]                                # different file, different id

def test_trust_classes(tmp_path, monkeypatch):
    monkeypatch.delenv("EZ_SIGNING_KEY", raising=False)
    v = make_verdict(tmp_path)
    assert v["trust_class"] == "UNSIGNED"
    assert v["receipt"]["trust_class"] == "UNSIGNED"
    monkeypatch.setenv("EZ_SIGNING_KEY", pem_key())
    v2 = make_verdict(tmp_path)
    assert v2["trust_class"] == "SELF-SIGNED"
    assert v2["receipt"]["signature"]["status"] == "signed"
    from event_zero.signing import verify_receipt
    assert verify_receipt(v2["receipt"], report=v2)["status"] == "verified"

def test_merkle_root_domain_separation():
    from event_zero.signing import ledger_root_hash
    import hashlib
    e = [{"kind": "file", "path": "a", "sha256": "x", "verdict": "accounted"}]
    # single leaf root is the leaf hash itself: SHA-256(0x00 || canonical)
    from event_zero.signing import canonicalise
    assert ledger_root_hash(e) == hashlib.sha256(b"\x00" + canonicalise(e[0])).hexdigest()
    two = e + [{"kind": "open", "item": "x"}]
    assert ledger_root_hash(two) != ledger_root_hash(list(reversed(two)))  # order matters
    assert ledger_root_hash([]) == hashlib.sha256(b"").hexdigest()
    assert ledger_root_hash(e) != ledger_root_hash([{"kind": "file", "path": "b", "sha256": "x", "verdict": "accounted"}])

def test_revocation_list(tmp_path, monkeypatch):
    """A report whose run_id appears in a supplied Verdict Revocation
    List verifies as REVOKED; an unrevoked report still passes."""
    from event_zero.signing import build_vrl, sign_vrl, check_revocation
    env = dict(os.environ)
    env["EZ_SIGNING_KEY"] = pem_key()
    p = os.path.join(str(tmp_path), "keygen.py")
    with open(p, "w") as f:
        f.write(KEYGEN)
    out = os.path.join(str(tmp_path), "report.json")
    r = subprocess.run([sys.executable, "-m", "event_zero", "verdict", p, "--out", out],
                       capture_output=True, text=True, cwd=ROOT, env=env)
    assert r.returncode == 0, r.stderr
    obj = json.load(open(out))
    run_id = obj["receipt"]["run_id"]
    vrl = sign_vrl(build_vrl([{"run_id": run_id, "level": "report",
                               "reason": "confirmed miss in regression testing",
                               "ez_bypass_id": "EZ-BYPASS-2026-001"}]))
    assert check_revocation(obj, vrl)["ez_bypass_id"] == "EZ-BYPASS-2026-001"
    vrlp = os.path.join(str(tmp_path), "vrl.json")
    json.dump(vrl, open(vrlp, "w"))
    ok = subprocess.run([sys.executable, "-m", "event_zero", "verify-report", out],
                        capture_output=True, text=True, cwd=ROOT, env=env)
    assert ok.returncode == 0 and "PASS" in ok.stdout, ok.stdout
    rev = subprocess.run([sys.executable, "-m", "event_zero", "verify-report", out, "--vrl", vrlp],
                         capture_output=True, text=True, cwd=ROOT, env=env)
    assert rev.returncode == 1 and "REVOKED" in rev.stdout, rev.stdout
    other = sign_vrl(build_vrl([{"run_id": "0" * 64, "level": "report", "reason": "unrelated"}]))
    json.dump(other, open(vrlp, "w"))
    ok2 = subprocess.run([sys.executable, "-m", "event_zero", "verify-report", out, "--vrl", vrlp],
                         capture_output=True, text=True, cwd=ROOT, env=env)
    assert ok2.returncode == 0 and "PASS" in ok2.stdout, ok2.stdout

def test_cli_verify_report(tmp_path, monkeypatch):
    env = dict(os.environ)
    env["EZ_SIGNING_KEY"] = pem_key()
    p = os.path.join(str(tmp_path), "keygen.py")
    with open(p, "w") as f:
        f.write(KEYGEN)
    out = os.path.join(str(tmp_path), "report.json")
    r = subprocess.run([sys.executable, "-m", "event_zero", "verdict", p, "--out", out],
                       capture_output=True, text=True, cwd=ROOT, env=env)
    assert r.returncode == 0, r.stderr
    assert os.path.isfile(out + ".receipt.json"), r.stdout
    ok = subprocess.run([sys.executable, "-m", "event_zero", "verify-report", out],
                        capture_output=True, text=True, cwd=ROOT, env=env)
    assert ok.returncode == 0 and "PASS" in ok.stdout, ok.stdout + ok.stderr
    okr = subprocess.run([sys.executable, "-m", "event_zero", "verify-report", out + ".receipt.json"],
                         capture_output=True, text=True, cwd=ROOT, env=env)
    assert okr.returncode == 0, okr.stdout + okr.stderr
    obj = json.load(open(out))
    obj["verdict"] = "YES"
    badp = os.path.join(str(tmp_path), "tampered.json")
    json.dump(obj, open(badp, "w"))
    bad = subprocess.run([sys.executable, "-m", "event_zero", "verify-report", badp],
                         capture_output=True, text=True, cwd=ROOT, env=env)
    assert bad.returncode == 1 and "FAIL" in bad.stdout, bad.stdout
