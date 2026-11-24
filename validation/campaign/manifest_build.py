#!/usr/bin/env python3
"""Build the frozen 10,000-hash MalwareBazaar campaign manifest.

Collects a hash pool from the MalwareBazaar API (get_siginfo, limit
1,000 per signature, over the fixed SIGNATURES list below, plus the
most recent submissions), selects exactly 10,000 hashes with a
deterministic seeded sample, and writes:

  manifest-10k.jsonl   one JSON object per line (hashes only)
  manifest-10k.root    SHA-256 of the canonical manifest file

Hashes and metadata only. This script never downloads a sample.

Why the API and not the hash export: the legacy export endpoints
under bazaar.abuse.ch/export/ were retired by abuse.ch (they answer
410 Gone), and the replacement v2 export requires the Auth-Key in
the URL path, which the connector surrogate cannot supply. The v1
API takes the key in a header, which the surrogate supplies.

Selection is reproducible against a fixed pool: the pool is the
deduplicated union in SIGNATURES order, sampled with
random.Random(SEED), and the chosen hashes are written in ascending
sorted order with sorted JSON keys. MalwareBazaar is a living
database, so the frozen artefact is the manifest and its root, not
the pool.

Expectation class: every entry is "bazaar-listed", meaning the sample
was submitted to MalwareBazaar as malware. No family label is
invented. The campaign scorer treats a NO verdict on any entry as a
false-NO candidate for adjudication (see CAMPAIGN.md).

Auth: the registered custom.abusech connection supplies the Auth-Key
header through a surrogate (see the connector doc). The real key
never appears in this file, in arguments, or in output.
"""
import hashlib
import json
import random
import re
import sys
import urllib.parse
import urllib.request
from pathlib import Path

sys.path.insert(0, "/opt/muse/skills/custom-connector-setup/bin")
from dynamic_credentials import add_surrogate_to_request, read_json_response

API_URL = "https://mb-api.abuse.ch/api/v1/"
HOSTS = ["mb-api.abuse.ch", "bazaar.abuse.ch", "auth.abuse.ch"]
SEED = 20261123
SAMPLE_SIZE = 10_000
SOURCE = "malwarebazaar-api-siginfo"
SELECTED_BY = "seeded-sample-v1"
EXPECTATION = "bazaar-listed"
PER_SIGNATURE_LIMIT = "1000"

SIGNATURES = [
    "CobaltStrike", "AgentTesla", "RedLineStealer", "LummaStealer",
    "Stealc", "Vidar", "FormBook", "LokiBot", "Emotet", "QakBot",
    "IcedID", "Remcos", "AsyncRAT", "njRAT", "NanoCore", "Amadey",
    "SmokeLoader", "XWorm", "DCRat", "VenomRAT", "QuasarRAT",
    "AveMaria", "MassLogger", "SnakeKeylogger", "VIPKeylogger",
    "Rhadamanthys", "RisePro", "PureLogs", "MeduzaStealer",
    "WarzoneRAT", "NetWire", "DarkComet", "PrivateLoader",
    "RaccoonStealer", "PhemedroneStealer", "UmbralStealer",
    "MetaStealer", "ACRStealer", "Fabookie", "Gozi",
]

HERE = Path(__file__).resolve().parent
MANIFEST_PATH = HERE / "manifest-10k.jsonl"
ROOT_PATH = HERE / "manifest-10k.root"

HASH_LINE = re.compile(r"^[0-9a-f]{64}$")


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args):
        raise RuntimeError("redirect refused, verify the endpoint")


def api_call(params):
    body = urllib.parse.urlencode(params).encode()
    request = urllib.request.Request(API_URL, data=body, method="POST")
    request.add_header("Content-Type", "application/x-www-form-urlencoded")
    add_surrogate_to_request(request, "custom.abusech", allowed_hosts=HOSTS)
    with urllib.request.build_opener(NoRedirect()).open(request, timeout=300) as response:
        return read_json_response(response)


def hashes_of(result):
    found = []
    data = result.get("data") or []
    if isinstance(data, list):
        for entry in data:
            if isinstance(entry, dict):
                value = str(entry.get("sha256_hash", "")).strip().lower()
                if HASH_LINE.match(value):
                    found.append(value)
    return found


def collect_pool():
    pool = []
    seen = set()

    def add(values):
        for value in values:
            if value not in seen:
                seen.add(value)
                pool.append(value)

    recent = api_call({"query": "get_recent", "selector": "time"})
    add(hashes_of(recent))
    print(f"get_recent: pool {len(pool)}")
    for signature in SIGNATURES:
        result = api_call({
            "query": "get_siginfo",
            "signature": signature,
            "limit": PER_SIGNATURE_LIMIT,
        })
        add(hashes_of(result))
        print(f"get_siginfo {signature}: pool {len(pool)}")
    return pool


def main():
    hashes = collect_pool()
    print(f"pool unique sha256 hashes: {len(hashes)}")
    if len(hashes) < SAMPLE_SIZE:
        print(f"pool holds fewer than {SAMPLE_SIZE} hashes, cannot build the manifest")
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
