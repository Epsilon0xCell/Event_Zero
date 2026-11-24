#!/usr/bin/env python3
"""Campaign shard downloader. Runs in CI only. Never run this where
samples must not land: it downloads live samples as their original
password-protected AES ZIPs.

Usage:
  run_shard.py --manifest PATH --shard-index N --shard-size S \
      --out PATH [--dry-run] [--delay-ms 100]

Reads the manifest slice for the shard (entries
[N*S, (N+1)*S) ), downloads each sample with the MalwareBazaar
get_file API, and writes one downloads.jsonl line per manifest entry
to --out. The ZIPs are saved beside it under zips/<sha256>.zip.

Rules that do not bend:
  - This script NEVER extracts and NEVER executes anything.
    Extraction and analysis happen in the separate networkless
    stage (analyze_shard.py inside a --network none container).
  - Every manifest entry in the slice gets exactly one result line.
    A failed download is recorded, never silently dropped. A
    missing result line is an error by design.
  - The Auth-Key comes from the ABUSECH_API_KEY environment
    variable (a repository secret in CI) and is never printed.

Download status values: downloaded, not_found, error.
"""
import argparse
import json
import os
import sys
import time
import urllib.parse
import urllib.request
from pathlib import Path

API = "https://mb-api.abuse.ch/api/v1/"


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args):
        raise RuntimeError("redirect refused, verify the endpoint")


def load_slice(manifest_path, shard_index, shard_size):
    entries = []
    with open(manifest_path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line:
                entries.append(json.loads(line))
    start = shard_index * shard_size
    end = start + shard_size
    return entries[start:end], len(entries)


def validate_aes_zip(blob):
    """Confirm the blob is a readable ZIP archive without extracting
    anything. Returns the member count. Raises on failure."""
    import io

    import pyzipper

    with pyzipper.AESZipFile(io.BytesIO(blob)) as zf:
        return len(zf.namelist())


def download_one(sha256, api_key, timeout=120):
    body = urllib.parse.urlencode(
        {"query": "get_file", "sha256_hash": sha256}
    ).encode()
    request = urllib.request.Request(API, data=body, method="POST")
    request.add_header("Content-Type", "application/x-www-form-urlencoded")
    request.add_header("Auth-Key", api_key)
    with urllib.request.build_opener(NoRedirect()).open(request, timeout=timeout) as response:
        return response.read()


def classify_response(blob):
    """get_file returns ZIP bytes on success and a small JSON body on
    failure. Returns (status, detail)."""
    if blob[:2] == b"PK":
        return "downloaded", ""
    try:
        parsed = json.loads(blob.decode("utf-8", errors="replace"))
        status = parsed.get("query_status", "")
        if status in ("file_not_found", "hash_not_found"):
            return "not_found", status
        return "error", f"api query_status: {status or 'unparseable response'}"
    except Exception:
        return "error", "response was neither a ZIP nor JSON"


def main(argv=None):
    parser = argparse.ArgumentParser(description="Download one campaign shard (CI only).")
    parser.add_argument("--manifest", required=True)
    parser.add_argument("--shard-index", type=int, required=True)
    parser.add_argument("--shard-size", type=int, required=True)
    parser.add_argument("--out", required=True, help="path of the downloads.jsonl to write")
    parser.add_argument("--dry-run", action="store_true",
                        help="list the slice and exit without any network use")
    parser.add_argument("--delay-ms", type=int, default=100,
                        help="pause between downloads, milliseconds")
    args = parser.parse_args(argv)

    if args.shard_index < 0 or args.shard_size <= 0:
        parser.error("shard-index must be >= 0 and shard-size must be > 0")

    shard, total = load_slice(args.manifest, args.shard_index, args.shard_size)
    start = args.shard_index * args.shard_size
    print(f"manifest entries: {total}")
    print(f"shard {args.shard_index}: entries [{start}, {start + len(shard)}) of size {args.shard_size}")

    if args.dry_run:
        for entry in shard:
            print(entry["sha256"])
        print(f"dry run: {len(shard)} entries listed, no downloads attempted")
        return 0

    if not shard:
        print("empty shard slice, nothing to download")
        return 1

    api_key = os.environ.get("ABUSECH_API_KEY")
    if not api_key:
        print("ABUSECH_API_KEY is not set, refusing to download")
        return 2

    out_path = Path(args.out)
    zips_dir = out_path.parent / "zips"
    zips_dir.mkdir(parents=True, exist_ok=True)

    counts = {"downloaded": 0, "not_found": 0, "error": 0}
    with open(out_path, "w", encoding="utf-8") as out:
        for entry in shard:
            sha256 = entry["sha256"]
            record = {"sha256": sha256, "status": "error", "zip_bytes": None}
            try:
                blob = download_one(sha256, api_key)
                status, detail = classify_response(blob)
                record["status"] = status
                if detail:
                    record["detail"] = detail
                if status == "downloaded":
                    members = validate_aes_zip(blob)
                    zip_path = zips_dir / f"{sha256}.zip"
                    zip_path.write_bytes(blob)
                    record["zip_bytes"] = len(blob)
                    record["zip_members"] = members
            except Exception as exc:  # recorded, never dropped
                record["status"] = "error"
                record["detail"] = f"{type(exc).__name__}: {exc}"
            counts[record["status"]] += 1
            out.write(json.dumps(record, sort_keys=True) + "\n")
            out.flush()
            if args.delay_ms > 0:
                time.sleep(args.delay_ms / 1000.0)

    print(f"downloads: {counts}")
    if sum(counts.values()) != len(shard):
        print("result line count does not match the slice size")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
