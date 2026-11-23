"""Run The Verdict over the whole verification corpus in one batch,
twice, and score the results independently.

Scoring discipline (from the verification research protocol):
- The denominator is every manifest entry. Each must end YES with
  exhibited proof, NO, or OPEN/UNACCOUNTED.
- PASS requires zero mismatches overall, zero unexpected UNACCOUNTED
  on Tier-1 fixtures, and zero false NO. Tier-2 entries are
  designed-OPEN cases disclosed in the manifest in advance; ending
  OPEN is their correct outcome, not a miss.
- The independent scorer does NOT trust the analyzer's own summary:
  for every PROVEN-expected fixture it re-reads the fixture bytes and
  confirms each expected proof atom is literally present, and it
  confirms the issued report exhibits a proof chain. For the beacon
  fixture (atoms XOR-encoded by construction) it confirms the parsed
  configuration in the report instead.
- Determinism gate: every fixture is run twice; the two ledger root
  hashes must be identical, or the run fails.

The corpus run makes no network use: analysis is offline and the
fixtures are never executed.

Usage: python3 run_verification.py [--outdir DIR]
Writes results.json, results_table.md and roots.json to the outdir
(default: this folder). Exit code 0 only on PASS.
"""
import hashlib, json, os, sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, ROOT)

from event_zero.verdict import verdict  # noqa: E402


def fixture_bytes(base):
    if os.path.isfile(base):
        return open(base, "rb").read()
    blob = b""
    for dp, _dn, fn in os.walk(base):
        for f in sorted(fn):
            blob += open(os.path.join(dp, f), "rb").read()
    return blob


def score_entry(entry, issued, data):
    """Independent scorer: returns (ok, problems). Uses only the
    manifest expectations, the fixture bytes, and the issued report's
    exhibited proof, never the analyzer's internal reasoning."""
    problems = []
    exp = entry["expected"]
    if issued.get("verdict") != exp["verdict"]:
        problems.append(f"verdict {issued.get('verdict')} != expected {exp['verdict']}")
    if issued.get("reason_class") != exp["reason_class"]:
        problems.append(f"reason class {issued.get('reason_class')} != expected {exp['reason_class']}")
    if exp.get("case_state") and issued.get("case_state") != exp["case_state"]:
        problems.append(f"case state {issued.get('case_state')} != expected {exp['case_state']}")
    if exp["reason_class"] == "PROVEN":
        reasons = issued.get("yes_reasons", [])
        if not reasons:
            problems.append("PROVEN expected but the report exhibits no proof chain")
        chain_words = " ".join(r.get("chain", "") for r in reasons).lower()
        if entry.get("chain") and entry["chain"] not in chain_words:
            problems.append(f"expected a proof chain naming '{entry['chain']}', exhibited: {chain_words or 'none'}")
        low = data.lower()
        for atom in entry.get("atoms", []):
            if atom.encode().lower() not in low:
                problems.append(f"scorer: expected proof atom not present in fixture bytes: {atom!r}")
        if entry["family"] == "beacon":
            cfg = None
            for f in issued.get("files", []):
                if f.get("beacon_config"):
                    cfg = f["beacon_config"]
            if not cfg or not cfg.get("c2_host"):
                problems.append("scorer: beacon fixture but no parsed configuration with a C2 host in the report")
    if exp["reason_class"] == "ACCOUNTED" and issued.get("verdict") == "YES":
        problems.append("FALSE POSITIVE: benign control issued YES")
    if exp["reason_class"] in ("PROVEN", "UNACCOUNTED") and issued.get("verdict") == "NO":
        problems.append("FALSE NO (release-blocking): a malicious or unaccountable fixture issued NO")
    return (not problems), problems


def main():
    outdir = HERE
    if "--outdir" in sys.argv:
        outdir = sys.argv[sys.argv.index("--outdir") + 1]
    os.makedirs(outdir, exist_ok=True)
    manifest = json.load(open(os.path.join(HERE, "manifest.json")))
    files_dir = os.path.join(HERE, "files")
    rows, roots = [], {}
    mismatches = 0
    tier1_unexpected_unaccounted = 0
    false_no = 0
    determinism_failures = 0
    for entry in manifest["entries"]:
        base = os.path.join(files_dir, entry["path"])
        data = fixture_bytes(base)
        ref = os.path.join(files_dir, entry["reference_path"]) if entry.get("reference_path") else None
        issued = verdict(base, reference=ref) if ref else verdict(base)
        issued2 = verdict(base, reference=ref) if ref else verdict(base)
        root1 = issued.get("receipt", {}).get("ledger_root_hash")
        root2 = issued2.get("receipt", {}).get("ledger_root_hash")
        roots[entry["name"]] = root1
        det_ok = (root1 == root2 and root1 is not None)
        if not det_ok:
            determinism_failures += 1
        ok, problems = score_entry(entry, issued, data)
        if not det_ok:
            ok = False
            problems.append("determinism: two runs produced different ledger roots")
        exp = entry["expected"]
        if issued.get("reason_class") == "UNACCOUNTED" and exp["reason_class"] != "UNACCOUNTED" and entry["tier"] == 1:
            tier1_unexpected_unaccounted += 1
        if "FALSE NO" in " ".join(problems):
            false_no += 1
        if not ok:
            mismatches += 1
        proof = ""
        if issued.get("yes_reasons"):
            proof = issued["yes_reasons"][0].get("chain", "")
        rows.append({"name": entry["name"], "family": entry["family"], "tier": entry["tier"],
                     "expected": f"{exp['verdict']}/{exp['reason_class']}",
                     "issued": f"{issued.get('verdict')}/{issued.get('reason_class')}",
                     "case_state": issued.get("case_state"),
                     "proof": proof, "ok": ok, "problems": problems,
                     "ledger_root": root1, "note": entry.get("note", "")})
        print(f"{'PASS' if ok else 'FAIL'}  {entry['name']:<32} expected {exp['verdict']}/{exp['reason_class']:<11} "
              f"issued {issued.get('verdict')}/{issued.get('reason_class')}  {'; '.join(problems)}")
    corpus_root = hashlib.sha256(json.dumps(roots, sort_keys=True).encode()).hexdigest()
    passed = (mismatches == 0 and tier1_unexpected_unaccounted == 0 and false_no == 0 and determinism_failures == 0)
    summary = {"entries": len(rows), "mismatches": mismatches,
               "tier1_unexpected_unaccounted": tier1_unexpected_unaccounted,
               "false_no": false_no, "determinism_failures": determinism_failures,
               "corpus_ledger_root": corpus_root, "result": "PASS" if passed else "FAIL"}
    json.dump({"summary": summary, "rows": rows}, open(os.path.join(outdir, "results.json"), "w"), indent=2)
    json.dump(roots, open(os.path.join(outdir, "roots.json"), "w"), indent=2, sort_keys=True)
    lines = ["| Fixture | Family | Tier | Expected | Issued | Case | Proof exhibited | Result |",
             "|---|---|---|---|---|---|---|---|"]
    for r in rows:
        lines.append(f"| {r['name']} | {r['family']} | {r['tier']} | {r['expected']} | {r['issued']} | {r['case_state']} | {r['proof'] or 'none'} | {'PASS' if r['ok'] else 'FAIL: ' + '; '.join(r['problems'])} |")
    lines.append("")
    lines.append(f"Corpus ledger root (hash of the per-fixture ledger roots): {corpus_root}")
    lines.append(f"Result: {summary['result']} ({len(rows)} entries, {mismatches} mismatches, "
                 f"{tier1_unexpected_unaccounted} unexpected Tier-1 unaccounted, {false_no} false NO, "
                 f"{determinism_failures} determinism failures)")
    open(os.path.join(outdir, "results_table.md"), "w").write("\n".join(lines) + "\n")
    print(json.dumps(summary, indent=2))
    return 0 if passed else 1


if __name__ == "__main__":
    sys.exit(main())
