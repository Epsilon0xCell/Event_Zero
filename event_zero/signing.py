"""Signed verdict reports and run receipts for Event Zero.

Implements roadmap item 1 in HARDENING-ROADMAP.md: a signed canonical
verdict core, a public verification path, and a run receipt for every
run. The signature proves that the named tool version and rule-pack
version produced that verdict for that sample hash, and that the
report has not changed since signing. It does not prove that a file
offered today is the file that was analysed: the verifier re-hashes
the actual file. A repacker can always omit a report or ship an
unsigned one, so the absence of a verifying signed report is no clean
claim.

Key discipline: key material comes only from the environment variable
EZ_SIGNING_KEY (a PEM or base64-encoded Ed25519 private key). It is
never read from a file in the repo, never logged, and never written
into a report. Only the public key and its fingerprint appear in
reports.

Deterministic core: the signed canonical core excludes volatile
fields (wall-clock durations such as elapsed_seconds, absolute paths
such as the subject path, and the manifest creation timestamp), so
the same sample, reference, tool version and rule pack reproduce the
same ledger root hash and the same core bytes. The receipt carries a
UTC timestamp, and the timestamp sits outside the signed core for
exactly that reason.

Degradation: with no EZ_SIGNING_KEY set, or the cryptography library
unavailable, signing returns the report or receipt with an explicit
signature block of status "unsigned" and a note. An unsigned report
is normal for local runs and must never be presented as verified.

LLM narration is never inside the signed core. It ships as an
unsigned appendix whose presence carries no verdict weight.
"""
import base64, datetime, hashlib, json, os

SCHEMA = "eventzero.verdict-core/1"
RECEIPT_SCHEMA = "eventzero.run-receipt/1"
# The built-in rule set ships with the tool and is versioned with it.
# When rule packs become separately distributed (roadmap item 2, TUF),
# this constant is replaced by the pack manifest version.
RULE_PACK_VERSION = "3.0.0-builtin"


def canonicalise(core):
    """RFC 8785 (JSON Canonicalization Scheme, JCS) bytes: sorted
    keys, no insignificant whitespace, minimal string escaping, UTF-8.
    Signed cores contain only strings, integers, booleans, nulls,
    lists and objects by construction, so the JCS number rules for
    floats never arise inside a signed core; floats are excluded from
    signed cores deliberately. The verifier verifies the exact signed
    bytes carried in the signature block, never a re-serialisation:
    see the signed_bytes field."""
    return json.dumps(core, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def rule_pack_hash():
    """Hash of the rule pack that produced a verdict: the pack version
    plus the canonical form of the built-in capability rules. A replay
    with a different pack produces a different hash, and therefore a
    different run_id."""
    try:
        from .capabilities import RULES
        material = json.dumps({"version": RULE_PACK_VERSION, "rules": RULES},
                              sort_keys=True, default=str).encode("utf-8")
    except Exception:
        material = RULE_PACK_VERSION.encode("utf-8")
    return hashlib.sha256(material).hexdigest()


def derive_run_id(sample_sha256, reference_sha256, tool_version):
    """The run_id is DERIVED, never random: a hash of the inputs
    (sample hash, reference hash, rule pack hash, tool version). The
    same inputs reproduce the same run_id; a proof replayed against a
    different file, reference, pack or tool cannot verify, because its
    run_id and ledger root will not match."""
    material = canonicalise({"sample_sha256": sample_sha256,
                             "reference_sha256": reference_sha256,
                             "rule_pack_hash": rule_pack_hash(),
                             "tool_version": tool_version})
    return hashlib.sha256(material).hexdigest()


def ledger_entries(report):
    """The accounted items list for a report, in deterministic order.
    For a verdict: one entry per file (relative path, hash, per-file
    verdict), one per proof, one per open item, one per diff region.
    For an analysis report: one entry per capability and finding.
    Volatile fields (durations, absolute paths) are excluded."""
    entries = []
    if report.get("report_type") == "verdict" or "files" in report and "headline" in report:
        for f in report.get("files", []):
            entries.append({"kind": "file", "path": f.get("path_in_release"),
                            "sha256": f.get("sha256"), "verdict": f.get("verdict")})
        for y in report.get("yes_reasons", []):
            entries.append({"kind": "proof", "file": y.get("file"), "chain": y.get("chain"),
                            "evidence": [str(e) for e in y.get("evidence", [])]})
        for u in report.get("unaccounted", []):
            entries.append({"kind": "open", "item": str(u)})
        for le in report.get("diff_ledger", []):
            entries.append({"kind": "diff", "file": le.get("file"),
                            "classification": le.get("classification"),
                            "new_range": le.get("new_range")})
    else:
        h = report.get("hashes", {})
        if h:
            entries.append({"kind": "sample", "sha256": h.get("sha256")})
        for c in report.get("capabilities", []):
            entries.append({"kind": "capability", "id": c.get("id"),
                            "evidence": [str(e) for e in c.get("evidence", [])]})
        for f in report.get("evasion", {}).get("findings", []):
            entries.append({"kind": "evasion", "id": f.get("id"),
                            "evidence": [str(e) for e in f.get("evidence", [])]})
    return entries


def ledger_root_hash(entries):
    """The ledger root: a Merkle tree over the accounted items list,
    RFC 6962 style, with leaf and node domain separation. A leaf is
    SHA-256(0x00 || canonical JSON of the entry); an interior node is
    SHA-256(0x01 || left || right); an unpaired leaf is promoted
    unchanged, as in RFC 6962. The root of an empty list is the
    SHA-256 of the empty byte string. (This replaces the earlier
    sequential hash chain; the domain separation is what stops a leaf
    from ever being reinterpreted as a node.)"""
    if not entries:
        return hashlib.sha256(b"").hexdigest()
    level = [hashlib.sha256(b"\x00" + canonicalise(e)).digest() for e in entries]
    while len(level) > 1:
        nxt = []
        for i in range(0, len(level) - 1, 2):
            nxt.append(hashlib.sha256(b"\x01" + level[i] + level[i + 1]).digest())
        if len(level) % 2:
            nxt.append(level[-1])
        level = nxt
    return level[0].hex()


def verdict_core(report):
    """Extract exactly the signed fields from a verdict report:
    sample SHA-256 and size, tool version, rule-pack version, ledger
    root hash, and the verdict token (verdict plus reason_class),
    plus the case lifecycle state."""
    files = report.get("files", [])
    if len(files) == 1:
        sample_sha = files[0].get("sha256")
        sample_size = files[0].get("size_bytes")
    else:
        sample_sha = report.get("manifest", {}).get("tree_sha256")
        sample_size = sum(f.get("size_bytes", 0) for f in files)
    return {
        "schema": SCHEMA,
        "sample_sha256": sample_sha,
        "sample_size_bytes": sample_size,
        "sample_files": len(files),
        "tool_version": report.get("version"),
        "rule_pack_version": RULE_PACK_VERSION,
        "ledger_root_hash": ledger_root_hash(ledger_entries(report)),
        "verdict": report.get("verdict"),
        "reason_class": report.get("reason_class"),
        "case_state": report.get("case_state"),
    }


TRUST_CLASS_MEANINGS = {
    "CI-ATTESTED": "produced in CI and covered by a keyless CI attestation for the run",
    "AUTHOR-SIGNED": "signed by the project release key",
    "SELF-SIGNED": "signed by a local key: proves the report is unchanged since signing, not who signed it",
    "UNSIGNED": "carries no endorsement: an unsigned report or receipt is a record, not a proof",
}


def trust_class(signed):
    """The trust class rendered next to every verdict token. A runner
    may declare CI-ATTESTED or AUTHOR-SIGNED through EZ_TRUST_CLASS
    when its infrastructure actually provides that backing; a local
    key is SELF-SIGNED; no key is UNSIGNED, plainly labelled as
    carrying no endorsement."""
    if not signed:
        return "UNSIGNED"
    declared = os.environ.get("EZ_TRUST_CLASS", "").strip().upper()
    if declared in ("CI-ATTESTED", "AUTHOR-SIGNED", "SELF-SIGNED"):
        return declared
    return "SELF-SIGNED"


# ---------------------------------------------------------------- keys
def _load_private_key():
    """Return (key, error). Key material comes only from the
    EZ_SIGNING_KEY environment variable: a PEM private key, or a
    base64-encoded raw 32-byte Ed25519 seed."""
    raw = os.environ.get("EZ_SIGNING_KEY")
    if not raw:
        return None, "EZ_SIGNING_KEY is not set"
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from cryptography.hazmat.primitives import serialization
    except Exception:
        return None, "the cryptography library is not available"
    text = raw.strip()
    key = None
    try:
        key = serialization.load_pem_private_key(text.encode(), password=None)
    except Exception:
        key = None
    if key is None:
        try:
            key = Ed25519PrivateKey.from_private_bytes(base64.b64decode(text))
        except Exception:
            return None, "EZ_SIGNING_KEY could not be parsed as a PEM or base64 Ed25519 private key"
    if not isinstance(key, Ed25519PrivateKey):
        return None, "EZ_SIGNING_KEY is not an Ed25519 private key"
    return key, None


def _public_block(pub):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    from cryptography.hazmat.primitives import serialization
    raw = pub.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return {"public_key": base64.b64encode(raw).decode(),
            "key_fingerprint": hashlib.sha256(raw).hexdigest()}


def _load_public_key(b64):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    return Ed25519PublicKey.from_public_bytes(base64.b64decode(b64))


# ---------------------------------------------------------------- reports
def sign_report(report, key=None):
    """Sign the canonical verdict core of a verdict report. Returns
    the report with a signature block. With no key available, returns
    the report with an explicit unsigned signature block."""
    out = dict(report)
    priv, err = (key, None) if key is not None else _load_private_key()
    if priv is None:
        out["signature"] = {"status": "unsigned", "trust_class": "UNSIGNED",
                            "note": f"Unsigned report ({err}). An unsigned report is normal for local runs and must never be presented as verified."}
        return out
    core = verdict_core(report)
    core_bytes = canonicalise(core)
    sig = priv.sign(core_bytes)
    block = {"status": "signed", "algorithm": "Ed25519", "schema": SCHEMA,
             "core": core, "signed_bytes": base64.b64encode(core_bytes).decode(),
             "signature": base64.b64encode(sig).decode(), "trust_class": trust_class(True)}
    block.update(_public_block(priv.public_key()))
    out["signature"] = block
    return out


def verify_report(report):
    """Recompute the core and the ledger root hash from the report,
    verify the signature against the public key in the signature
    block, and return a structured result naming each check."""
    checks = {}
    problems = []
    block = report.get("signature") or {}
    if block.get("status") != "signed":
        return {"status": "unsigned", "checks": {"signature_present": False},
                "problems": ["report is unsigned: it carries no proof and must not be presented as verified"]}
    checks["signature_present"] = True
    stored_core = block.get("core") or {}
    recomputed = verdict_core(report)
    checks["core_recomputed_matches"] = (canonicalise(recomputed) == canonicalise(stored_core))
    if not checks["core_recomputed_matches"]:
        problems.append("recomputed verdict core does not match the signed core: the report was altered after signing, or the verdict fields changed")
    checks["ledger_root_hash_matches"] = (recomputed.get("ledger_root_hash") == stored_core.get("ledger_root_hash"))
    if not checks["ledger_root_hash_matches"]:
        problems.append("ledger root hash mismatch: the evidence ledger entries do not hash to the signed root")
    checks["verdict_token_matches"] = (stored_core.get("verdict") == report.get("verdict")
                                       and stored_core.get("reason_class") == report.get("reason_class"))
    if not checks["verdict_token_matches"]:
        problems.append("verdict token in the report does not match the signed core")
    # verify the exact signed bytes, never a re-serialisation
    if block.get("signed_bytes"):
        try:
            exact = base64.b64decode(block["signed_bytes"])
        except Exception:
            exact = b""
        checks["signed_bytes_match_core"] = (exact == canonicalise(stored_core))
        if not checks["signed_bytes_match_core"]:
            problems.append("the signed bytes in the signature block do not match the stored core: the core was altered after signing")
        signed_payload = exact
    else:
        signed_payload = canonicalise(stored_core)
    try:
        pub = _load_public_key(block["public_key"])
        checks["key_fingerprint_matches"] = (_public_block(pub)["key_fingerprint"] == block.get("key_fingerprint"))
        pub.verify(base64.b64decode(block["signature"]), signed_payload)
        checks["signature_valid"] = True
    except Exception as e:
        checks["signature_valid"] = False
        problems.append(f"signature verification failed: {e}")
    ok = all(checks.values()) and not problems
    return {"status": "verified" if ok else "failed", "checks": checks, "problems": problems}


# ---------------------------------------------------------------- receipts
def build_receipt(report, reference_sha256=None, reference_provenance=None):
    """Build the run receipt for a verdict or analysis report. The
    receipt core (everything except issued_utc and the signature
    block) is deterministic: the same sample, reference, tool version
    and rule pack reproduce the same ledger root hash."""
    is_verdict = report.get("report_type") == "verdict" or "headline" in report
    if is_verdict:
        core_fields = verdict_core(report)
        sample_sha = core_fields["sample_sha256"]
        sample_size = core_fields["sample_size_bytes"]
        verdict_token = report.get("verdict")
        reason_class = report.get("reason_class")
        case_state = report.get("case_state")
    else:
        sample_sha = report.get("hashes", {}).get("sha256")
        sample_size = report.get("size_bytes")
        verdict_token = report.get("risk", {}).get("verdict")
        reason_class = None
        case_state = None
    receipt = {
        "schema": RECEIPT_SCHEMA,
        "kind": "verdict" if is_verdict else "analyze",
        "run_id": derive_run_id(sample_sha, reference_sha256, report.get("version")),
        "rule_pack_hash": rule_pack_hash(),
        "trust_class": "UNSIGNED",
        "sample_sha256": sample_sha,
        "sample_size_bytes": sample_size,
        "reference": ({"sha256": reference_sha256, "provenance": reference_provenance}
                      if reference_sha256 or reference_provenance else None),
        "ledger_root_hash": ledger_root_hash(ledger_entries(report)),
        "verdict": verdict_token,
        "reason_class": reason_class,
        "case_state": case_state,
        "tool_version": report.get("version"),
        "rule_pack_version": RULE_PACK_VERSION,
        "environment_coverage": ({"files_total": c.get("files_total"), "files_emulated": c.get("files_emulated"),
                                  "instructions_emulated": c.get("instructions_emulated"),
                                  "entry_stub_traces": c.get("entry_stub_traces"),
                                  "os_environments_executed": 0}
                                 if (c := report.get("environment_coverage")) else None),
        "issued_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
    }
    return receipt


def receipt_core(receipt):
    """The signed core of a receipt: every field except the volatile
    issued_utc timestamp and the signature block itself."""
    return {k: v for k, v in receipt.items() if k not in ("issued_utc", "signature")}


def sign_receipt(receipt, key=None):
    out = dict(receipt)
    priv, err = (key, None) if key is not None else _load_private_key()
    if priv is None:
        out["trust_class"] = "UNSIGNED"
        out["signature"] = {"status": "unsigned", "trust_class": "UNSIGNED",
                            "note": f"Unsigned receipt ({err}). An unsigned receipt is a record, not a proof."}
        return out
    out["trust_class"] = trust_class(True)
    core_bytes = canonicalise(receipt_core(out))
    sig = priv.sign(core_bytes)
    block = {"status": "signed", "algorithm": "Ed25519", "schema": RECEIPT_SCHEMA,
             "signed_bytes": base64.b64encode(core_bytes).decode(),
             "signature": base64.b64encode(sig).decode(), "trust_class": out["trust_class"]}
    block.update(_public_block(priv.public_key()))
    out["signature"] = block
    return out


def verify_receipt(receipt, report=None):
    """Verify a run receipt. When the report is supplied, the ledger
    root hash and verdict token are recomputed from it and compared;
    the signature is verified over the canonical receipt core."""
    checks = {}
    problems = []
    block = receipt.get("signature") or {}
    if block.get("status") != "signed":
        return {"status": "unsigned", "checks": {"signature_present": False},
                "problems": ["receipt is unsigned: it is a record, not a proof"]}
    checks["signature_present"] = True
    if report is not None:
        checks["ledger_root_hash_matches"] = (ledger_root_hash(ledger_entries(report)) == receipt.get("ledger_root_hash"))
        if not checks["ledger_root_hash_matches"]:
            problems.append("ledger root hash mismatch: the report's evidence does not hash to the receipt root")
        checks["sample_hash_matches"] = True
        if receipt.get("kind") == "verdict":
            checks["sample_hash_matches"] = (verdict_core(report)["sample_sha256"] == receipt.get("sample_sha256"))
        else:
            checks["sample_hash_matches"] = (report.get("hashes", {}).get("sha256") == receipt.get("sample_sha256"))
        if not checks["sample_hash_matches"]:
            problems.append("sample hash in the receipt does not match the report: the receipt was issued for a different sample")
        checks["verdict_token_matches"] = (receipt.get("verdict") == (report.get("verdict") if receipt.get("kind") == "verdict" else report.get("risk", {}).get("verdict")))
        if not checks["verdict_token_matches"]:
            problems.append("verdict token in the receipt does not match the report")
    # verify the exact signed bytes, never a re-serialisation
    if block.get("signed_bytes"):
        try:
            exact = base64.b64decode(block["signed_bytes"])
        except Exception:
            exact = b""
        checks["signed_bytes_match_core"] = (exact == canonicalise(receipt_core(receipt)))
        if not checks["signed_bytes_match_core"]:
            problems.append("the signed bytes in the receipt signature block do not match the receipt core: the receipt was altered after signing")
        signed_payload = exact
    else:
        signed_payload = canonicalise(receipt_core(receipt))
    try:
        pub = _load_public_key(block["public_key"])
        checks["key_fingerprint_matches"] = (_public_block(pub)["key_fingerprint"] == block.get("key_fingerprint"))
        pub.verify(base64.b64decode(block["signature"]), signed_payload)
        checks["signature_valid"] = True
    except Exception as e:
        checks["signature_valid"] = False
        problems.append(f"signature verification failed: {e}")
    ok = all(checks.values()) and not problems
    return {"status": "verified" if ok else "failed", "checks": checks, "problems": problems}


def verify_any(obj):
    """Verify a signed report, a run receipt, or a verdict report
    carrying an embedded receipt. Returns the structured result."""
    if obj.get("schema") == RECEIPT_SCHEMA:
        return verify_receipt(obj)
    if obj.get("signature", {}).get("status") == "signed":
        return verify_report(obj)
    if obj.get("receipt"):
        return verify_receipt(obj["receipt"], report=obj)
    return verify_report(obj)


# ---------------------------------------------------------------- revocation
VRL_SCHEMA = "eventzero.verdict-revocation-list/1"


def build_vrl(entries):
    """Build a Verdict Revocation List document. Entry format (see
    format-spec.md): each entry carries the revoked report run_id
    (for level 'report'), a level (report, explanation-type,
    reference, or tool-version), a reason, and the EZ-BYPASS
    identifier when the revocation arises from a confirmed miss."""
    return {"schema": VRL_SCHEMA, "entries": list(entries)}


def sign_vrl(vrl, key=None):
    """Sign a Verdict Revocation List the way a receipt is signed:
    Ed25519 over the canonical core (schema plus entries), key only
    from EZ_SIGNING_KEY. Unsigned lists are labelled unsigned."""
    out = dict(vrl)
    priv, err = (key, None) if key is not None else _load_private_key()
    if priv is None:
        out["signature"] = {"status": "unsigned", "trust_class": "UNSIGNED",
                            "note": f"Unsigned revocation list ({err}). Treat its contents as unverified."}
        return out
    core = {"schema": VRL_SCHEMA, "entries": vrl.get("entries", [])}
    core_bytes = canonicalise(core)
    sig = priv.sign(core_bytes)
    block = {"status": "signed", "algorithm": "Ed25519", "schema": VRL_SCHEMA,
             "signed_bytes": base64.b64encode(core_bytes).decode(),
             "signature": base64.b64encode(sig).decode(), "trust_class": trust_class(True)}
    block.update(_public_block(priv.public_key()))
    out["signature"] = block
    return out


def check_revocation(obj, vrl):
    """Return the revocation entry that matches this report or
    receipt, or None. Levels: 'report' matches the run_id;
    'tool-version' matches every report issued by that tool version;
    'reference' matches reports issued against that reference hash;
    'explanation-type' matches reports whose diff ledger relies on
    that named crack pattern. A matching report verifies as REVOKED:
    its signature may be genuine, but the verdict is withdrawn."""
    if not vrl or vrl.get("schema") != VRL_SCHEMA:
        return None
    receipt = obj.get("receipt") if isinstance(obj.get("receipt"), dict) else (obj if obj.get("schema") == RECEIPT_SCHEMA else {})
    run_id = receipt.get("run_id")
    version = obj.get("version") or receipt.get("tool_version")
    ref = receipt.get("reference") if isinstance(receipt.get("reference"), dict) else {}
    ref_hash = ref.get("sha256")
    patterns = {le.get("crack_pattern") for le in obj.get("diff_ledger", []) if le.get("crack_pattern")}
    for e in vrl.get("entries", []):
        lvl = e.get("level")
        if lvl == "report" and run_id and e.get("run_id") == run_id:
            return e
        if lvl == "tool-version" and version and e.get("tool_version") == version:
            return e
        if lvl == "reference" and ref_hash and e.get("reference_sha256") == ref_hash:
            return e
        if lvl == "explanation-type" and e.get("explanation") in patterns:
            return e
    return None
