"""Canonical JSONL manifest system for the validation programme.

One line per case. Canonical form: JSON with sorted keys, compact
separators, UTF-8, one object per line, trailing newline. The manifest
root is the SHA-256 of the canonical file bytes, so any edit to any
case changes the root and is visible.

For frozen and blind manifests the runner-visible copy omits the label
object entirely; expectations live in a separate sealed file held by
the scorer side. Splitting is done by split_manifest() and the two
halves carry cross-referencing roots.
"""
import hashlib, json

CASE_KINDS = ("file", "folder", "installer", "archive")
TOKENS = ("YES", "NO", "OPEN_STATE")
RENDERINGS = ("PROVEN", "UNACCOUNTED", "ACCOUNTED", "OPEN")
TIERS = ("T0", "T1", "T2", "T3")
SPLITS = ("development", "tuning", "regression", "frozen", "blind",
          "family-holdout", "time-split", "adversarial")

REQUIRED_CASE_FIELDS = ("case_id", "sha256", "kind", "stratum", "split",
                        "tier", "provenance", "label", "structure")
PROVENANCE_FIELDS = ("source", "source_ref", "terms_basis", "acquired", "first_seen")
LABEL_FIELDS = ("expected_token", "expected_rendering", "required_atoms",
                "family", "label_status", "labellers", "adjudication_ref")
STRUCTURE_FIELDS = ("layer_tree_hash", "genuine_ref_sha256", "twin_case_id", "cluster_id")


def canonical(obj):
    """Canonical JSON text for one object (sorted keys, compact)."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def validate_case(case):
    """Return a list of schema problems; empty means valid."""
    problems = []
    for f in REQUIRED_CASE_FIELDS:
        if f not in case:
            problems.append(f"missing field: {f}")
    if problems:
        return problems
    if case["kind"] not in CASE_KINDS:
        problems.append(f"kind not in {CASE_KINDS}: {case['kind']}")
    if case["tier"] not in TIERS:
        problems.append(f"tier not in {TIERS}: {case['tier']}")
    if case["split"] not in SPLITS:
        problems.append(f"split not in {SPLITS}: {case['split']}")
    for f in PROVENANCE_FIELDS:
        if f not in case["provenance"]:
            problems.append(f"provenance missing: {f}")
    for f in LABEL_FIELDS:
        if f not in case["label"]:
            problems.append(f"label missing: {f}")
    for f in STRUCTURE_FIELDS:
        if f not in case["structure"]:
            problems.append(f"structure missing: {f}")
    lab = case["label"]
    if lab.get("expected_token") not in TOKENS:
        problems.append(f"expected_token not in {TOKENS}: {lab.get('expected_token')}")
    if lab.get("expected_rendering") not in RENDERINGS:
        problems.append(f"expected_rendering not in {RENDERINGS}: {lab.get('expected_rendering')}")
    if not isinstance(lab.get("required_atoms"), list):
        problems.append("required_atoms must be a list")
    sha = case["sha256"]
    if not (isinstance(sha, str) and len(sha) == 64 and all(c in "0123456789abcdef" for c in sha)):
        problems.append("sha256 must be 64 lowercase hex characters")
    return problems


def manifest_bytes(cases):
    """Canonical file bytes for a list of case objects."""
    return "".join(canonical(c) + "\n" for c in cases).encode("utf-8")


def manifest_root(cases):
    """SHA-256 of the canonical manifest file bytes."""
    return hashlib.sha256(manifest_bytes(cases)).hexdigest()


def file_root(path):
    with open(path, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()


def write_jsonl(path, rows):
    with open(path, "w", encoding="utf-8") as f:
        for r in rows:
            f.write(canonical(r) + "\n")
    return file_root(path)


def load_jsonl(path):
    rows = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                rows.append(json.loads(line))
    return rows


def split_manifest(cases):
    """Split full cases into (runner_cases, sealed_expectations).

    Runner cases keep every field except label. Sealed expectations
    carry case_id plus the label and the stratum, split and tier the
    scorer needs for its per-stratum scorecard. Neither half alone can
    be used to tune against expectations while pretending to be blind.
    """
    runner, sealed = [], []
    for c in cases:
        rc = {k: v for k, v in c.items() if k != "label"}
        runner.append(rc)
        sealed.append({
            "case_id": c["case_id"],
            "stratum": c["stratum"],
            "split": c["split"],
            "tier": c["tier"],
            "label": c["label"],
        })
    return runner, sealed
