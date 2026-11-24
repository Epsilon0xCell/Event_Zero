#!/usr/bin/env python3
"""Build the frozen 10,000-hash MalwareBazaar campaign manifest.

Fetches the full MalwareBazaar hash export, selects exactly 10,000
hashes with a deterministic seeded sample, and writes:

  manifest-10k.jsonl   one JSON object per line (hashes only)
  manifest-10k.root    SHA-256 of the canonical manifest file

Hashes and metadata only. This script never downloads a sample.

Export endpoint history, verified 2026-11-23: the legacy export
paths under bazaar.abuse.ch/export/ (txt and csv, recent and full)
now return HTTP 410 Gone. The current official export is the v2
endpoint documented at https://bazaar.abuse.ch/export/ :

  https://mb-api.abuse.ch/v2/files/exports/<AUTH-KEY>/<dataset>

with the dataset full.csv tried first and full.txt second. The
Auth-Key travels in the URL path on this endpoint, by abuse.ch
design. The key is therefore read from the ABUSECH_API_KEY
environment variable at runtime and held in memory only: it is
never printed, never written to a file, and never accepted as a
command line argument. Run this script where that secret already
lives (a CI job holding the repository secret, or the operator's
own shell). It cannot run through the registered custom.abusech
connector, whose credential placement is the Auth-Key header and
whose helper by design refuses to place the key in a URL path.

Selection is reproducible byte for byte: export lines are parsed in
file order, every 64-hex field is collected, the set is
deduplicated, sampled with random.Random(SEED), and the chosen
hashes are written in ascending sorted order with sorted JSON keys.
Re-running against the same export yields the same file and the
same root.

Expectation class: every entry is "bazaar-listed", meaning the
sample was submitted to MalwareBazaar as malware. No family label
is invented. The campaign scorer treats a NO verdict on any entry
as a false-NO candidate for adjudication (see CAMPAIGN.md).
"""
import hashlib
import json
import os
import random
import re
import sys
import urllib.request
from pathlib import Path

EXPORT_BASE = "https://mb-api.abuse.ch/v2/files/exports"
DATASETS = ("full.csv", "full.txt")
SEED = 20261123
SAMPLE_SIZE = 10_000
SOURCE = "malwarebazaar-full-export"
SELECTED_BY = "seeded-sample-v1"
EXPECTATION = "bazaar-listed"

HERE = Path(__file__).resolve().parent
MANIFEST_PATH = HERE / "manifest-10k.jsonl"
ROOT_PATH = HERE / "manifest-10k.root"

HASH_FIELD = re.compile(r"^[0-9a-f]{64}$")


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args):
        raise RuntimeError("redirect refused, verify the endpoint")


def fetch_export(api_key):
    """Return (dataset_name, text) for the first dataset that
    answers. The key is interpolated into the URL in memory only."""
    last_error = None
    for dataset in DATASETS:
        url = f"{EXPORT_BASE}/{api_key}/{dataset}"
        request = urllib.request.Request(url)
        try:
            with urllib.request.build_opener(NoRedirect()).open(request, timeout=600) as response:
                return dataset, response.read().decode("utf-8", errors="replace")
        except Exception as exc:  # try the next dataset name
            last_error = exc
    raise RuntimeError(f"no export dataset answered (last error: {last_error})")


def parse_hashes(text):
    hashes = []
    seen = set()
    total_lines = 0
    for raw in text.splitlines():
        total_lines += 1
        for field in re.split(r"[,\s;]+", raw.strip().lower()):
            if HASH_FIELD.match(field) and field not in seen:
                seen.add(field)
                hashes.append(field)
    return total_lines, hashes


def main():
    api_key = os.environ.get("ABUSECH_API_KEY")
    if not api_key:
        print("ABUSECH_API_KEY is not set. The current MalwareBazaar export")
        print("endpoint carries the key in the URL path, so this script needs")
        print("the key in its environment. Run it where the secret lives")
        print("(a CI job or the operator shell). Nothing was fetched.")
        return 2
    dataset, text = fetch_export(api_key)
    print(f"export dataset: {dataset}")
    total_lines, hashes = parse_hashes(text)
    print(f"export total lines: {total_lines}")
    print(f"export unique sha256 hashes: {len(hashes)}")
    if len(hashes) < SAMPLE_SIZE:
        print(f"export holds fewer than {SAMPLE_SIZE} hashes, cannot build the manifest")
        return 1
    selected = sorted(random.Random(SEED).sample(hashes, SAMPLE_SIZE))
    lines = []
    for sha256 in selected:
        entry = {
            "sha256": sha256,
            "source": SOURCE,
            "selected_by": SELECTED_BY,
            "expectation": EXPECTATION,
        }
        lines.append(json.dumps(entry, sort_keys=True))
    canonical = ("\n".join(lines) + "\n").encode("utf-8")
    MANIFEST_PATH.write_bytes(canonical)
    root = hashlib.sha256(canonical).hexdigest()
    ROOT_PATH.write_text(root + "\n", encoding="utf-8")
    print(f"manifest entries: {len(lines)}")
    print(f"manifest root: {root}")
    print(f"wrote {MANIFEST_PATH}")
    print(f"wrote {ROOT_PATH}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
