"""Deterministic runner for the validation programme.

Consumes a runner manifest (labels already stripped by
manifest.split_manifest), runs each case through the real engine
(event_zero.verdict.verdict, the same entry point the CLI uses),
twice per case for the determinism gate, and emits result JSONL in
the scorer's schema.

Timeout policy (from the pre-registration): soft cap 60 s, hard cap
300 s per case. A case that hits the hard cap is recorded with status
"timeout": the cap is a result, not an infrastructure failure. A case
that raises is recorded with status "crash". Neither is ever dropped.

The engine never executes the sample; this runner adds no execution.
"""
import argparse, json, os, signal, sys, time

SOFT_CAP_S = 60
HARD_CAP_S = 300


class _Timeout(Exception):
    pass


def _alarm_handler(signum, frame):
    raise _Timeout()


def _ledger_root(v):
    receipt = v.get("receipt") or {}
    if receipt.get("ledger_root_hash"):
        return receipt["ledger_root_hash"]
    manifest = v.get("manifest") or {}
    return manifest.get("tree_sha256")


def _atoms(v):
    atoms = []
    for r in v.get("yes_reasons", []) or []:
        atoms.extend(r.get("evidence", []) or [])
        if r.get("chain"):
            atoms.append(r["chain"])
    for f in v.get("files", []) or []:
        atoms.extend(f.get("chains", []) or [])
        atoms.extend(f.get("capabilities", []) or [])
    seen, out = set(), []
    for a in atoms:
        if a not in seen:
            seen.add(a)
            out.append(a)
    return out


def run_one(path, reference, hard_cap_s=HARD_CAP_S):
    """Run the engine once; return (verdict_dict, runtime_ms, status)."""
    from event_zero.verdict import verdict
    old = signal.signal(signal.SIGALRM, _alarm_handler)
    signal.setitimer(signal.ITIMER_REAL, hard_cap_s)
    started = time.perf_counter()
    try:
        v = verdict(path, reference=reference) if reference else verdict(path)
        status = "ok"
    except _Timeout:
        v, status = None, "timeout"
    except Exception:
        v, status = None, "crash"
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, old)
    return v, int((time.perf_counter() - started) * 1000), status


def run_case(case, subjects_root):
    subject = os.path.join(subjects_root, case["subject_path"])
    reference = None
    if case.get("reference_path"):
        reference = os.path.join(subjects_root, case["reference_path"])
    v1, ms1, status1 = run_one(subject, reference)
    if status1 != "ok":
        return {"case_id": case["case_id"], "verdict_token": None, "rendering": None,
                "atoms": [], "ledger_root": None, "runtime_ms": ms1, "status": status1}
    v2, _ms2, status2 = run_one(subject, reference)
    determinism_ok = status2 == "ok" and _ledger_root(v1) == _ledger_root(v2) and _ledger_root(v1) is not None
    return {
        "case_id": case["case_id"],
        "verdict_token": v1.get("verdict"),
        "rendering": v1.get("reason_class"),
        "case_state": v1.get("case_state"),
        "atoms": _atoms(v1),
        "ledger_root": _ledger_root(v1),
        "runtime_ms": ms1,
        "over_soft_cap": ms1 > SOFT_CAP_S * 1000,
        "determinism_ok": determinism_ok,
        "status": "ok",
    }


def main(argv=None):
    p = argparse.ArgumentParser(prog="ez-runner", description="Run a runner manifest through the real engine.")
    p.add_argument("--manifest", required=True)
    p.add_argument("--subjects-root", required=True)
    p.add_argument("--out", required=True)
    p.add_argument("--split", default=None, help="Only run cases with this split value")
    p.add_argument("--limit", type=int, default=None)
    args = p.parse_args(argv)
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))
    from .manifest import load_jsonl, canonical
    cases = load_jsonl(args.manifest)
    if args.split:
        cases = [c for c in cases if c.get("split") == args.split]
    if args.limit:
        cases = cases[:args.limit]
    done = 0
    with open(args.out, "w", encoding="utf-8") as f:
        for case in cases:
            line = run_case(case, args.subjects_root)
            f.write(canonical(line) + "\n")
            f.flush()
            done += 1
            if done % 50 == 0:
                print(f"ran {done}/{len(cases)}", flush=True)
    print(f"ran {done} cases, results at {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
