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
  - Transient refusals (HTTP 429 and 5xx, network errors) are
    retried with exponential backoff, honouring Retry-After when
    the server sends it. The attempt count is recorded on every
    downloads line. If ten consecutive files exhaust their
    retries on 429, a circuit breaker drops the remaining files
    to a single attempt each, so a spent daily quota makes the
    shard finish and record the state instead of burning hours.
    One progress line is printed per manifest entry.

Download status values: downloaded, not_found, error.
"""
import argparse
import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

API = "https://mb-api.abuse.ch/api/v1/"
RETRYABLE_HTTP = {429, 500, 502, 503, 504}
CIRCUIT_BREAKER_THRESHOLD = 10


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


def _sleep(seconds):
    time.sleep(seconds)


def _retry_delay(exc, attempt, base_seconds, max_seconds):
    """Delay before the next attempt: Retry-After when the server
    sent a parseable one, else exponential backoff. Always capped."""
    headers = getattr(exc, "headers", None) or getattr(exc, "hdrs", None)
    if headers is not None:
        raw = headers.get("Retry-After")
        if raw:
            try:
                return min(max_seconds, max(0, int(raw)))
            except (TypeError, ValueError):
                pass
    return min(max_seconds, base_seconds * (2 ** (attempt - 1)))


def download_with_retry(sha256, api_key, max_attempts, base_seconds, max_seconds,
                        attempts_out=None):
    """download_one with retries on transient failure. Returns
    (blob, attempts_used). Re-raises the last exception when the
    attempts are exhausted or the failure is not retryable. When
    attempts_out (a one-element list) is given, it is updated with
    the current attempt count as the attempts proceed, so the
    caller can record it even when the call raises."""
    attempt = 0
    while True:
        attempt += 1
        if attempts_out is not None:
            attempts_out[0] = attempt
        try:
            return download_one(sha256, api_key), attempt
        except urllib.error.HTTPError as exc:
            if exc.code not in RETRYABLE_HTTP or attempt >= max_attempts:
                raise
            delay = _retry_delay(exc, attempt, base_seconds, max_seconds)
            print(f"  {sha256[:12]} attempt {attempt} got HTTP {exc.code}; "
                  f"retrying in {delay}s", flush=True)
            _sleep(delay)
        except urllib.error.URLError as exc:
            if attempt >= max_attempts:
                raise
            delay = _retry_delay(exc, attempt, base_seconds, max_seconds)
            print(f"  {sha256[:12]} attempt {attempt} network error "
                  f"({exc.reason}); retrying in {delay}s", flush=True)
            _sleep(delay)


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
    parser.add_argument("--max-attempts", type=int, default=4,
                        help="attempts per file before recording the failure (default 4)")
    parser.add_argument("--retry-base-seconds", type=int, default=20,
                        help="first backoff delay in seconds, doubling per attempt (default 20)")
    parser.add_argument("--retry-max-seconds", type=int, default=180,
                        help="cap on any single backoff delay in seconds (default 180)")
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
    shard_total = len(shard)
    consecutive_429 = 0
    breaker_open = False
    with open(out_path, "w", encoding="utf-8") as out:
        for index, entry in enumerate(shard, start=1):
            entry_started = time.monotonic()
            sha256 = entry["sha256"]
            record = {"sha256": sha256, "status": "error", "zip_bytes": None,
                      "attempts": 0}
            attempts_allowed = 1 if breaker_open else args.max_attempts
            attempts_box = [0]
            last_was_429 = False
            try:
                blob, attempts = download_with_retry(
                    sha256, api_key, attempts_allowed,
                    args.retry_base_seconds, args.retry_max_seconds,
                    attempts_out=attempts_box,
                )
                record["attempts"] = attempts
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
            except urllib.error.HTTPError as exc:
                record["attempts"] = attempts_box[0]
                record["status"] = "error"
                record["detail"] = f"{type(exc).__name__}: {exc}"
                last_was_429 = exc.code == 429
            except Exception as exc:  # recorded, never dropped
                record["attempts"] = attempts_box[0]
                record["status"] = "error"
                record["detail"] = f"{type(exc).__name__}: {exc}"
            counts[record["status"]] += 1
            out.write(json.dumps(record, sort_keys=True) + "\n")
            out.flush()
            elapsed = time.monotonic() - entry_started
            print(f"[{index}/{shard_total}] {sha256[:12]} {record['status']} "
                  f"(attempts {record['attempts']}) in {elapsed:.1f}s", flush=True)
            if last_was_429 and not breaker_open:
                consecutive_429 += 1
                if consecutive_429 >= CIRCUIT_BREAKER_THRESHOLD:
                    breaker_open = True
                    print(f"circuit breaker open: {CIRCUIT_BREAKER_THRESHOLD} "
                          "consecutive files exhausted their retries on HTTP 429; "
                          "the remaining files get a single attempt each so the "
                          "shard finishes and records the state", flush=True)
            elif record["status"] in ("downloaded", "not_found"):
                consecutive_429 = 0
            if args.delay_ms > 0:
                time.sleep(args.delay_ms / 1000.0)

    print(f"downloads: {counts}")
    if sum(counts.values()) != len(shard):
        print("result line count does not match the slice size")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
