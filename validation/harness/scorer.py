"""Independent scorer for the validation programme.

This module is deliberately separate from the analyser: it imports
nothing from event_zero and never calls the engine. It joins per-case
result JSONL against sealed expectations and classifies every error.

Result line schema (produced by the runner):
  {case_id, verdict_token, rendering, atoms[], ledger_root, family?,
   runtime_ms, case_state?, status?, determinism_ok?}
status is "ok" when absent; "timeout" and "crash" are result classes,
not infrastructure failures.

Error classes:
  false-no            expected YES or OPEN_STATE, issued NO. Release-blocking.
  false-yes           expected NO, issued YES.
  wrong-reason        token right, rendering wrong (or an OPEN_STATE case
                      closed as PROVEN).
  wrong-family        both sides name a family and they differ.
  fabricated-proof    PROVEN claimed but the exhibited proof is empty, or
                      (when subject bytes are supplied) no exhibited atom
                      and no required atom is present in the subject bytes.
  label-atom-missing  a required atom is absent from the subject bytes
                      themselves: the expectation, not the engine, is wrong.
  determinism-failure two runs of one case produced different ledger roots.
  crash / timeout     the engine crashed or hit the hard cap on this case.
  missing-line        a case with no result line. Never dropped silently.
  unexpected-line     a result line for a case not in the expectations.
  duplicate-line      two result lines for one case_id.

A case is correct only when it carries no error class.
"""
import json, sys

RELEASE_BLOCKING = ("false-no",)


def _atom_in_bytes(atom, blob_low):
    return atom.lower().encode("utf-8", "replace") in blob_low


def _evidence_token(atom):
    """Reduce an exhibited evidence string to its checkable tail token:
    'string/text: Login Data' becomes 'Login Data'; 'import/symbol:
    connect' becomes 'connect'."""
    a = atom
    if ":" in a:
        a = a.split(":", 1)[1].strip()
    return a


def classify_case(exp, result, subject_bytes=None):
    """Return the list of error classes for one case (empty = correct)."""
    errors = []
    if result is None:
        return ["missing-line"]
    status = result.get("status", "ok")
    if status == "timeout":
        return ["timeout"]
    if status == "crash":
        return ["crash"]
    if result.get("determinism_ok") is False:
        errors.append("determinism-failure")
    lab = exp["label"]
    exp_token = lab["expected_token"]
    exp_rendering = lab["expected_rendering"]
    got_token = result.get("verdict_token")
    got_rendering = result.get("rendering")

    if exp_token == "NO" and got_token == "YES":
        errors.append("false-yes")
        return errors
    if exp_token in ("YES", "OPEN_STATE") and got_token == "NO":
        errors.append("false-no")
        return errors
    if exp_token == "OPEN_STATE":
        # Correct only as a fail-closed open case: YES rendered
        # UNACCOUNTED, or an explicit OPEN case state. A PROVEN claim
        # on an unresolvable-by-design case is a wrong reason.
        if got_token == "YES" and (got_rendering == "UNACCOUNTED" or result.get("case_state") == "OPEN"):
            pass
        else:
            errors.append("wrong-reason")
        return errors
    if got_token != exp_token:
        errors.append("wrong-reason")
        return errors
    if got_rendering != exp_rendering:
        errors.append("wrong-reason")

    # Family check: only when both sides actually name one.
    exp_family = lab.get("family")
    got_family = result.get("family")
    if exp_family and got_family and exp_family != got_family:
        errors.append("wrong-family")

    # Proof checks for PROVEN expectations.
    if exp_rendering == "PROVEN":
        exhibited = result.get("atoms") or []
        required = lab.get("required_atoms") or []
        blob_low = subject_bytes.lower() if subject_bytes is not None else None
        if not exhibited:
            errors.append("fabricated-proof")
        elif blob_low is not None:
            # Byte-presence checks apply to literal evidence atoms only
            # (string/text: and import/symbol:). Analytical atoms (a
            # parsed configuration, a triad statement) claim a derived
            # fact, not byte presence, and are not judged by this check.
            literal = [a for a in exhibited if a.startswith(("string/text:", "import/symbol:"))]
            exhibited_hit = (any(_atom_in_bytes(_evidence_token(a), blob_low) for a in literal)
                             if literal else True)
            required_hit = any(_atom_in_bytes(a, blob_low) for a in required)
            if not exhibited_hit and not required_hit:
                errors.append("fabricated-proof")
        if blob_low is not None:
            for a in required:
                if not _atom_in_bytes(a, blob_low):
                    errors.append("label-atom-missing")
                    break
    return errors


def score(expectations, results, bytes_by_case=None):
    """Join results to sealed expectations and build the scorecard."""
    by_id = {}
    errors_by_class = {}
    duplicates = []
    for r in results:
        cid = r.get("case_id")
        if cid in by_id:
            duplicates.append(cid)
        by_id.setdefault(cid, r)
    exp_ids = {e["case_id"] for e in expectations}
    for cid in by_id:
        if cid not in exp_ids:
            errors_by_class.setdefault("unexpected-line", []).append(cid)
    for cid in duplicates:
        errors_by_class.setdefault("duplicate-line", []).append(cid)

    per_stratum = {}
    per_case = {}
    correct = 0
    for exp in expectations:
        cid = exp["case_id"]
        result = by_id.get(cid)
        subject = (bytes_by_case or {}).get(cid)
        errs = classify_case(exp, result, subject)
        if cid in duplicates and "duplicate-line" not in errs:
            errs = errs + ["duplicate-line"]
        per_case[cid] = errs
        st = per_stratum.setdefault(exp["stratum"], {"total": 0, "correct": 0, "errors": {}})
        st["total"] += 1
        if not errs:
            correct += 1
            st["correct"] += 1
        for e in errs:
            errors_by_class.setdefault(e, []).append(cid)
            st["errors"][e] = st["errors"].get(e, 0) + 1
    total = len(expectations)
    return {
        "total": total,
        "correct": correct,
        "incorrect": total - correct,
        "accuracy": (correct / total) if total else 0.0,
        "release_blocking": {c: len(errors_by_class.get(c, [])) for c in RELEASE_BLOCKING},
        "pass": total > 0 and correct == total,
        "errors_by_class": {k: sorted(v) for k, v in sorted(errors_by_class.items())},
        "error_counts": {k: len(v) for k, v in sorted(errors_by_class.items())},
        "per_stratum": per_stratum,
        "per_case_errors": {k: v for k, v in per_case.items() if v},
    }


def main(argv=None):
    import argparse
    from .manifest import load_jsonl
    p = argparse.ArgumentParser(prog="ez-scorer", description="Independent scorer: sealed expectations versus result JSONL.")
    p.add_argument("--sealed", required=True)
    p.add_argument("--results", required=True)
    p.add_argument("--subjects", default=None, help="Directory of subject files named by case_id, for byte-level proof checks")
    p.add_argument("--out", default=None)
    args = p.parse_args(argv)
    expectations = load_jsonl(args.sealed)
    results = load_jsonl(args.results)
    bytes_by_case = None
    if args.subjects:
        import os
        bytes_by_case = {}
        for e in expectations:
            path = os.path.join(args.subjects, e["case_id"])
            if os.path.isfile(path):
                bytes_by_case[e["case_id"]] = open(path, "rb").read()
    card = score(expectations, results, bytes_by_case)
    text = json.dumps(card, indent=2, sort_keys=True)
    if args.out:
        with open(args.out, "w") as f:
            f.write(text + "\n")
    print(text)
    return 0 if card["pass"] else 1


if __name__ == "__main__":
    sys.exit(main())
