#!/usr/bin/env python3
"""Campaign shard analysis stage. Runs ONLY inside a container
started with --network none (see .github/workflows/campaign.yml).

Usage:
  analyze_shard.py --downloads PATH --zips DIR --results PATH --work DIR

For every line in downloads.jsonl:
  - entries not marked downloaded get a result line carrying their
    download status and a null verdict, so the shard accounts for
    every manifest entry. A missing result line is an error.
  - downloaded entries are extracted from their password-protected
    AES ZIP (password "infected") into the work directory, the
    Event Zero verdict runs on the extracted folder, one result
    line is appended, and the extracted bytes are deleted.

The sample is never executed. Event Zero is a static engine: it
parses, disassembles and accounts, it does not run the subject.

Each verdict runs in its own child process under a per-sample
timeout (default 120 seconds). A sample whose verdict exceeds
the timeout is killed and recorded as YES UNACCOUNTED with
analysis_status "analysis-timeout": a pathological sample can
never stall the shard, and it can never obtain a clean verdict
by hanging. One progress line is printed per downloads line so
the stage log shows exactly where the shard is.

Before any extraction, an egress canary must prove outbound
connections fail. If the canary can connect, the stage aborts
before a single byte is extracted.
"""
import argparse
import json
import multiprocessing as mp
import shutil
import socket
import sys
import time
from pathlib import Path

ZIP_PASSWORD = b"infected"


def egress_canary():
    """Return True when outbound network use is impossible."""
    for host, port in (("1.1.1.1", 443), ("8.8.8.8", 53)):
        try:
            with socket.create_connection((host, port), timeout=3):
                return False
        except OSError:
            pass
    try:
        socket.getaddrinfo("bazaar.abuse.ch", 443)
        return False
    except OSError:
        pass
    return True


def extract_zip(zip_path, dest):
    import pyzipper

    dest.mkdir(parents=True, exist_ok=True)
    with pyzipper.AESZipFile(zip_path) as zf:
        zf.extractall(path=dest, pwd=ZIP_PASSWORD)
    return [p for p in dest.rglob("*") if p.is_file()]


def family_of(verdict_dict):
    for file_entry in verdict_dict.get("files", []):
        chains = file_entry.get("family_chains") or []
        if chains:
            return chains[0]
    for reason in verdict_dict.get("yes_reasons", []):
        fam = reason.get("family")
        if fam:
            return fam
    return None


def ledger_root_of(verdict_dict):
    receipt = verdict_dict.get("receipt") or {}
    if receipt.get("ledger_root_hash"):
        return receipt["ledger_root_hash"]
    core = receipt.get("core") or {}
    return core.get("ledger_root_hash")


def verdict_worker(sample_dir, out_path):
    """Run the verdict for one extracted sample directory and
    write the result fields as JSON to out_path. Runs in a child
    process so the parent can time it out and kill it without
    stalling the shard."""
    result = {}
    try:
        from event_zero.verdict import verdict

        v = verdict(str(sample_dir))
        result["verdict"] = v.get("verdict")
        result["reason"] = v.get("reason_class")
        result["family"] = family_of(v)
        result["ledger_root"] = ledger_root_of(v)
        result["case_state"] = v.get("case_state")
        result["analysis_status"] = "analysed"
    except Exception as exc:  # recorded, never dropped
        result["analysis_status"] = "analysis-error"
        result["detail"] = f"{type(exc).__name__}: {exc}"
    Path(out_path).write_text(json.dumps(result, sort_keys=True), encoding="utf-8")


def main(argv=None):
    parser = argparse.ArgumentParser(description="Analyse one campaign shard (networkless stage).")
    parser.add_argument("--downloads", required=True)
    parser.add_argument("--zips", required=True)
    parser.add_argument("--results", required=True)
    parser.add_argument("--work", required=True, help="scratch directory, wiped per sample")
    parser.add_argument("--sample-timeout", type=int, default=120,
                        help="per-sample verdict timeout in seconds (default 120)")
    parser.add_argument("--skip-canary", action="store_true",
                        help="skip the egress canary (local debugging only, never in CI)")
    args = parser.parse_args(argv)

    if args.skip_canary:
        print("egress canary SKIPPED by --skip-canary (local debugging only)", flush=True)
    elif not egress_canary():
        print("EGRESS CANARY FAILED: outbound connections succeeded. Aborting before extraction.")
        return 3
    else:
        print("egress canary passed: outbound connections failed as required", flush=True)

    downloads = []
    with open(args.downloads, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line:
                downloads.append(json.loads(line))

    zips_dir = Path(args.zips)
    work_dir = Path(args.work)
    work_dir.mkdir(parents=True, exist_ok=True)
    results_path = Path(args.results)
    results_path.parent.mkdir(parents=True, exist_ok=True)

    total = len(downloads)
    print(f"analysing {total} downloads lines; per-sample verdict timeout "
          f"{args.sample_timeout}s", flush=True)
    counts = {}
    written = 0
    with open(results_path, "w", encoding="utf-8") as out:
        for index, record in enumerate(downloads, start=1):
            record_started = time.monotonic()
            sha256 = record["sha256"]
            result = {
                "sha256": sha256,
                "download_status": record["status"],
                "verdict": None,
                "reason": None,
                "family": None,
                "ledger_root": None,
            }
            if record["status"] == "downloaded":
                sample_dir = work_dir / sha256
                try:
                    files = extract_zip(zips_dir / f"{sha256}.zip", sample_dir)
                    if not files:
                        result["analysis_status"] = "empty-archive"
                    else:
                        out_json = work_dir / f"{sha256}.result.json"
                        ctx = mp.get_context("fork")
                        proc = ctx.Process(
                            target=verdict_worker,
                            args=(str(sample_dir), str(out_json)),
                        )
                        proc.start()
                        proc.join(args.sample_timeout)
                        if proc.is_alive():
                            proc.terminate()
                            proc.join(10)
                            if proc.is_alive():
                                proc.kill()
                                proc.join()
                            result["verdict"] = "YES"
                            result["reason"] = "UNACCOUNTED"
                            result["analysis_status"] = "analysis-timeout"
                            result["detail"] = (
                                f"verdict exceeded the {args.sample_timeout}s "
                                "per-sample timeout and was killed; the sample "
                                "is unaccounted, so the verdict fails closed"
                            )
                        elif out_json.exists():
                            result.update(
                                json.loads(out_json.read_text(encoding="utf-8"))
                            )
                        else:
                            result["analysis_status"] = "analysis-error"
                            result["detail"] = (
                                f"verdict worker exited with code {proc.exitcode} "
                                "without writing a result"
                            )
                        out_json.unlink(missing_ok=True)
                except Exception as exc:  # recorded, never dropped
                    result["analysis_status"] = "analysis-error"
                    result["detail"] = f"{type(exc).__name__}: {exc}"
                finally:
                    shutil.rmtree(sample_dir, ignore_errors=True)
            else:
                result["analysis_status"] = "not-downloaded"
            token = result["verdict"] or result["analysis_status"]
            counts[token] = counts.get(token, 0) + 1
            out.write(json.dumps(result, sort_keys=True) + "\n")
            out.flush()
            written += 1
            elapsed = time.monotonic() - record_started
            print(f"[{index}/{total}] {sha256[:12]} {token} "
                  f"({result['analysis_status']}) in {elapsed:.1f}s", flush=True)

    print(f"results written: {written} of {len(downloads)} downloads lines")
    print(f"counts: {json.dumps(counts, sort_keys=True)}")
    if written != len(downloads):
        print("result line count does not match the downloads line count")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
