#!/usr/bin/env python3
"""Campaign structural diagnosis for confirmed misses. CI only.

Usage:
  diagnose.py --stage download --out DIR [SHA256 ...]
  diagnose.py --stage analyze --downloads PATH --zips DIR \
      --work DIR --out PATH [--sample-timeout 300]

Why this exists: shard run 8 (run 45745957476) re-judged the
miss-ledger entries EZ-BYPASS-2026-007 and EZ-BYPASS-2026-008 on
the current engine and both returned NO ACCOUNTED again. Fix
wave 4 closed fourteen synthetic shapes reconstructed from
vendor behaviour reports; the real files use shapes outside
that reconstruction. The next fix wave must be scoped from the
samples' actual structure, and this tool obtains that structure
under the campaign's standing safety shape (CAMPAIGN.md).

Shape, mirroring the campaign flow exactly:
  - Download stage (network allowed, this stage only): the
    named samples are fetched through run_shard.py itself (same
    get_file API, same retry and circuit-breaker discipline,
    same AES ZIP validation), saved as their original
    password-protected ZIPs. Nothing is extracted here.
  - Analysis stage: runs inside the campaign container with
    --network none. analyze_shard.py's egress canary must prove
    outbound connections fail before any ZIP is opened. Each
    sample is extracted with analyze_shard.py's own extraction
    (password "infected", original filenames preserved), the
    verdict and the per-unit analyzer run in a child process
    under a per-sample timeout, the diagnosis is shaped, and
    the extracted bytes are deleted.

The boundary (a deliberate, bounded extension of the campaign's
"hashes and verdicts only" rule, documented in CAMPAIGN.md):
what leaves the runner is diagnosis.json, structural facts
only. It contains hashes, sizes, format classifications,
finding and chain ids with the engine's recorded reason
strings, capability ids with their sources, byte-ownership
counts and ranges, decoded-layer kinds with the decoded
content's size and hash, and the decision trace the engine's
report supports. It never contains sample bytes, full file
text, string dumps, script source, decoded-layer content, or
script-ledger line text. External references are reduced to
scheme, host, and a SHA-256 of the full URL; a full URL is
recorded only when its host is already public in
docs/MISS-LEDGER.md (LEDGER_PUBLIC_HOSTS). Every free-text
reason string passes through the same reduction (scrub_text),
so a URL embedded in an engine reason is reduced by the same
rule. The shaping function, shape_diagnosis, is a pure function
of the engine's report objects and is unit-tested without any
sample.

Decision-trace honesty: the engine's report records the
blockers that fired and the chains that proved; it does not
record candidate blockers that were evaluated and did not
fire. The diagnosis says so on its face instead of inventing
a trace, and the per-unit decision branch is reconstructed
from the record's own fields (verdict token, reference state,
signature state, accounting flags) and labelled as a
reconstruction.
"""
import argparse
import hashlib
import json
import multiprocessing as mp
import re
import shutil
import sys
import time
from pathlib import Path
from urllib.parse import urlparse

sys.path.insert(0, str(Path(__file__).resolve().parent))

import analyze_shard
import run_shard

SAMPLE_007 = "03e548ca313467cc8716fa135199414f36ca37884cd95b6cdd1b9a37c3bee71a"
SAMPLE_008 = "04b5784000d66093995c13dddb0f346996aea2b7fc9ce0d420f5b596ad70fe72"
DEFAULT_HASHES = [SAMPLE_007, SAMPLE_008]

# Hosts already public in docs/MISS-LEDGER.md. A reference to
# one of these hosts (or a subdomain of it) may be recorded in
# full; every other reference is reduced to scheme, host, and
# a hash of the full URL.
LEDGER_PUBLIC_HOSTS = {"protware.com"}

_URL_RE = re.compile(r"https?://[^\s\"'<>\)\]]+")


def _sha256_text(text):
    return hashlib.sha256(text.encode("utf-8", "replace")).hexdigest()


def _host_of(url):
    try:
        host = urlparse(url).hostname
    except Exception:
        return None
    return host.lower() if host else None


def _is_ledger_public(host):
    if not host:
        return False
    return any(host == h or host.endswith("." + h) for h in LEDGER_PUBLIC_HOSTS)


def reduce_reference(url):
    """Reduce one external reference to scheme, host, and a
    SHA-256 of the full URL. The full URL is included only when
    its host is already public in the miss ledger."""
    parsed = urlparse(url)
    host = _host_of(url)
    entry = {"scheme": parsed.scheme or None,
             "host": host,
             "url_sha256": _sha256_text(url),
             "full_url_recorded": False}
    if _is_ledger_public(host):
        entry["url"] = url
        entry["full_url_recorded"] = True
    return entry


def scrub_text(text):
    """Apply the reference reduction to URLs embedded in an
    engine reason string. Ledger-public URLs stay verbatim;
    every other URL is replaced by a reduced marker carrying
    its scheme, host, and a truncated hash of the full URL."""
    if not text:
        return text

    def _sub(match):
        url = match.group(0)
        host = _host_of(url)
        if _is_ledger_public(host):
            return url
        scheme = urlparse(url).scheme or "?"
        return (f"[url reduced: {scheme}://{host or 'no-host'}"
                f"#sha256:{_sha256_text(url)[:16]}]")

    return _URL_RE.sub(_sub, text)


def _scrubbed(strings):
    return [scrub_text(s) for s in strings or []]


def _reduce_dest(dest):
    """Shape one connection-ledger destination. The ledger's
    dest carries url, domain, ip, port, scheme, and path; the
    diagnosis keeps scheme and host (the URL reduced by the
    standing rule), never the path or query."""
    url = dest.get("url")
    if url:
        entry = reduce_reference(url)
    else:
        entry = {"scheme": dest.get("scheme"),
                 "host": dest.get("domain") or dest.get("ip"),
                 "url_sha256": None,
                 "full_url_recorded": False}
    entry["port"] = dest.get("port")
    return entry


def _shape_byte_ownership(own):
    if not own:
        return None
    owned = own.get("owned") or []
    return {
        "format": own.get("format"),
        "basis": own.get("basis"),
        "complete": own.get("complete"),
        "owned_bytes": sum((r.get("end") or 0) - (r.get("start") or 0)
                           for r in owned),
        "owned_ranges": owned,
        "unowned_ranges": own.get("unowned") or [],
        "material_unowned_count": len(own.get("material_unowned") or []),
        "notes": _scrubbed(own.get("notes")),
    }


def _shape_external_references(rec):
    er = rec.get("external_references")
    if not er:
        return None
    refs = []
    for r in er.get("references") or []:
        entry = {"kind": r.get("kind"),
                 "source": r.get("source"),
                 "disposition": r.get("disposition")}
        target = r.get("target") or ""
        if "://" in target:
            entry.update(reduce_reference(target))
        else:
            entry["target_sha256"] = _sha256_text(target)
        refs.append(entry)
    note = scrub_text(er.get("note") or "")
    return {"references": refs,
            "complete": er.get("complete"),
            "note": note or None}


def _shape_findings(rec):
    """Curated structural findings from the file record. Only
    ids, kinds, counts, and scrubbed reason strings are shaped;
    content-bearing fields (script-ledger line text, beacon
    configuration values, decoded content) are reduced to
    counts, kinds, and field names."""
    findings = {}
    for key in ("script_class_findings", "written_stage_findings",
                "proxy_invocation_findings"):
        entries = rec.get(key)
        if entries:
            findings[key] = [
                {"kind": f.get("kind"),
                 "evidence": _scrubbed(f.get("evidence"))}
                for f in entries]
    if rec.get("incompleteness"):
        findings["incompleteness_kinds"] = list(rec["incompleteness"])
    ledger = rec.get("script_ledger")
    if ledger:
        findings["script_ledger"] = {
            "lines": ledger.get("lines"),
            "allowlisted": ledger.get("allowlisted"),
            "structural": ledger.get("structural"),
            "flagged_count": len(ledger.get("flagged") or []),
            "flagged_kinds": sorted({f.get("kind")
                                     for f in ledger.get("flagged") or []}),
            "unaccounted_count": len(ledger.get("unaccounted") or []),
            "unaccounted_line_numbers": [u.get("line")
                                         for u in ledger.get("unaccounted") or []],
        }
    if rec.get("embedded_payloads"):
        findings["embedded_payloads"] = [
            {"type": p.get("type"), "offset": p.get("offset"),
             "offset_hex": p.get("offset_hex"),
             "analysed": p.get("analysed")}
            for p in rec["embedded_payloads"]]
    if rec.get("clipboard"):
        findings["clipboard"] = rec["clipboard"]
    if rec.get("autoexec"):
        findings["autoexec_triggers"] = sorted(
            {u.get("trigger") for u in rec["autoexec"]
             if isinstance(u, dict) and u.get("trigger")})
    member = rec.get("member_semantics")
    if member:
        findings["member_semantics"] = {
            "kind": member.get("kind"),
            "divergences": [{"member": d.get("member"),
                             "kind": d.get("kind")}
                            for d in member.get("divergences") or []],
        }
    dual = rec.get("dual_parser")
    if dual:
        findings["dual_parser"] = {
            "available": dual.get("available"),
            "parsers": dual.get("parsers"),
            "compared": dual.get("compared"),
            "kind": dual.get("kind"),
            "disagreements": [
                {"field": d.get("field"),
                 "detail": scrub_text(d.get("detail") or "")}
                for d in dual.get("disagreements") or []],
        }
    if rec.get("polyglot"):
        findings["polyglot_identities"] = rec["polyglot"]
    driver = rec.get("driver_capabilities")
    if driver:
        findings["driver_capabilities"] = {
            "is_driver": driver.get("is_driver"),
            "categories": [c.get("category")
                           for c in driver.get("capabilities") or []],
        }
    if rec.get("beacon_config") is not None:
        findings["beacon_config_fields"] = sorted(
            (rec.get("beacon_config") or {}).keys())
    lnk = rec.get("lnk")
    if lnk:
        findings["lnk"] = {
            "lolbin": lnk.get("lolbin"),
            "cradle": lnk.get("cradle"),
            "urls": [reduce_reference(u) for u in lnk.get("urls") or []],
        }
    return findings


def _unit_branch(rec, unit_blockers):
    """Reconstruct which decision branch produced this unit's
    verdict token, from the record's own fields. This is a
    reconstruction from recorded state, not an engine trace:
    the engine does not record its branch decisions."""
    token = rec.get("verdict") or ""
    if token.startswith("YES: MALWARE"):
        return "proven-chain"
    if token.startswith("YES"):
        return "blocker" if unit_blockers else "unaccounted-no-named-blocker"
    reference = rec.get("reference")
    if reference == "hash-match":
        return "reference-hash-match"
    if reference == "manifest-match":
        return "reference-manifest-match"
    if reference == "differs-from-reference":
        return "reference-diff-classified"
    if rec.get("signature_valid"):
        return "signature-byte-identity"
    if rec.get("bytecode_accounted"):
        return "bytecode-accounting"
    if rec.get("model_accounted"):
        return "model-accounting"
    fmt = rec.get("format") or ""
    if fmt in ("script", "text / script"):
        return "script-fully-read"
    if fmt and fmt not in ("PE", "ELF", "Mach-O"):
        return "data-accounting"
    return "container-accounting"


def _shape_unit(rec, report, analyzer_reports):
    rel = rec.get("path_in_release") or rec.get("name") or ""
    blockers = [b for b in report.get("blockers") or []
                if b.startswith(rel + ":")]
    unit = {
        "name": rec.get("name"),
        "path_in_release": rel,
        "origin": rec.get("origin"),
        "size_bytes": rec.get("size_bytes"),
        "sha256": rec.get("sha256"),
        "format": rec.get("format"),
        "signed": rec.get("signed"),
        "signature_valid": rec.get("signature_valid"),
        "reference": rec.get("reference"),
        "verdict": rec.get("verdict"),
        "analysis_verdict": rec.get("analysis_verdict"),
        "decision_branch": _unit_branch(rec, blockers),
        "why": _scrubbed(rec.get("why")),
        "blockers": _scrubbed(blockers),
        "chains": list(rec.get("chains") or []),
        "family_chains": list(rec.get("family_chains") or []),
        "family_notes": _scrubbed(rec.get("family_notes")),
        "capabilities": [
            {"id": cid,
             "source": "capa" if cid.startswith("capa:") else "event-zero"}
            for cid in rec.get("capabilities") or []],
        "byte_ownership": _shape_byte_ownership(rec.get("byte_ownership")),
        "external_references": _shape_external_references(rec),
        "findings": _shape_findings(rec),
    }
    capa = rec.get("capa")
    if capa is not None:
        unit["capa"] = {"status": capa.get("status"),
                        "note": scrub_text(capa.get("note") or ""),
                        "capa_version": capa.get("capa_version"),
                        "rules": capa.get("rules"),
                        "backend": capa.get("backend"),
                        "matches": capa.get("matches")}
    rep = analyzer_reports.get(rec.get("sha256") or "")
    if rep is not None:
        layers = []
        for layer in (rep.get("unpack") or {}).get("decoded_layers") or []:
            result = layer.get("result") or ""
            encoded = result.encode("utf-8", "replace")
            layers.append({"chain": list(layer.get("chain") or []),
                           "result_bytes": len(encoded),
                           "result_sha256": hashlib.sha256(encoded).hexdigest()})
        unit["decoded_layers"] = layers
        unit["truncations"] = rep.get("truncations") or []
    return unit


def shape_diagnosis(verdict_report, analyzer_reports=None, sample=None):
    """Shape one sample's diagnosis from the engine's reports.
    Pure: takes the verdict dict (and optionally per-unit
    analyzer reports keyed by unit SHA-256) and returns the
    diagnosis dict. No sample bytes or content fields are read
    or emitted; see the module docstring for the boundary."""
    v = verdict_report
    analyzer_reports = analyzer_reports or {}
    units = [_shape_unit(rec, v, analyzer_reports)
             for rec in v.get("files") or []]
    ledger = []
    for entry in v.get("connection_ledger") or []:
        dest = entry.get("dest") or {}
        ledger.append({
            "id": entry.get("id"),
            "source_file": entry.get("source_file"),
            "provenance": entry.get("provenance"),
            "classification": entry.get("classification"),
            "tag": entry.get("tag"),
            "dest": _reduce_dest(dest),
            "note": scrub_text(entry.get("note") or "") or None,
        })
    return {
        "schema": "eventzero.diagnosis/1",
        "sample": sample or {},
        "headline": v.get("headline"),
        "verdict": v.get("verdict"),
        "reason_class": v.get("reason_class"),
        "case_state": v.get("case_state"),
        "scope": scrub_text(v.get("scope") or "") or None,
        "units": units,
        "blockers": _scrubbed(v.get("blockers")),
        "yes_reasons": [
            {"file": y.get("file"), "chain": y.get("chain"),
             "name": scrub_text(y.get("name") or ""),
             "evidence": _scrubbed(y.get("evidence"))}
            for y in v.get("yes_reasons") or []],
        "connection_ledger": ledger,
        "decision_trace": {
            "decision_rule": (
                "engine ladder: any proven chain in yes_reasons "
                "produces YES PROVEN; else any blocker produces "
                "YES UNACCOUNTED with the case OPEN; else NO "
                "ACCOUNTED"),
            "proven_chains_fired": len(v.get("yes_reasons") or []),
            "blockers_fired": len(v.get("blockers") or []),
            "next_rung": v.get("next_rung"),
            "units": [
                {"path_in_release": u["path_in_release"],
                 "verdict": u["verdict"],
                 "decision_branch": u["decision_branch"]}
                for u in units],
            "evaluated_but_unfired_blockers": {
                "recorded_by_engine": False,
                "note": ("the engine report records blockers "
                         "that fired; it does not record "
                         "candidate blockers that were evaluated "
                         "and did not fire, so this diagnosis "
                         "cannot list them"),
            },
        },
    }


def diagnose_worker(sample_dir, sample_meta, out_path):
    """Run the verdict and the per-unit analyzer for one
    extracted sample directory and write the shaped diagnosis
    fragment as JSON to out_path. Runs in a child process so
    the parent can time it out and kill it, mirroring
    analyze_shard.py's verdict worker."""
    fragment = {}
    try:
        from event_zero.analyzer import analyze
        from event_zero.verdict import verdict

        v = verdict(str(sample_dir))
        analyzer_reports = {}
        for unit_path in sorted(Path(sample_dir).rglob("*")):
            if not unit_path.is_file():
                continue
            try:
                rep = analyze(str(unit_path))
                analyzer_reports[rep["hashes"]["sha256"]] = rep
            except Exception as exc:  # recorded, never dropped
                analyzer_reports.setdefault("__errors__", []).append(
                    {"unit": unit_path.name,
                     "detail": f"{type(exc).__name__}: {exc}"})
        fragment = shape_diagnosis(v, analyzer_reports=analyzer_reports,
                                   sample=sample_meta)
        fragment["analysis_status"] = "analysed"
        errors = analyzer_reports.get("__errors__")
        if errors:
            fragment["analyzer_errors"] = errors
    except Exception as exc:  # recorded, never dropped
        fragment = {"sample": sample_meta,
                    "analysis_status": "analysis-error",
                    "detail": f"{type(exc).__name__}: {exc}"}
    Path(out_path).write_text(json.dumps(fragment, sort_keys=True),
                              encoding="utf-8")


def download_stage(hashes, out_dir):
    """Fetch the named samples through run_shard.py itself:
    same API, same retry and circuit-breaker discipline, same
    AES ZIP validation, ZIPs saved under out_dir/zips. A
    throwaway manifest is generated from the hash arguments so
    the download path is the campaign's own, unchanged."""
    out_dir.mkdir(parents=True, exist_ok=True)
    manifest = out_dir / "diagnosis-manifest.jsonl"
    with open(manifest, "w", encoding="utf-8") as fh:
        for sha256 in hashes:
            fh.write(json.dumps({"sha256": sha256,
                                 "expectation": "bazaar-listed"}) + "\n")
    return run_shard.main([
        "--manifest", str(manifest),
        "--shard-index", "0",
        "--shard-size", str(len(hashes)),
        "--out", str(out_dir / "downloads.jsonl"),
    ])


def analyze_stage(downloads_path, zips_dir, work_dir, out_path,
                  sample_timeout, skip_canary):
    """The networkless stage. Mirrors analyze_shard.py: egress
    canary first, extraction through analyze_shard.extract_zip,
    one child process per sample under a timeout, extracted
    bytes deleted per sample."""
    if skip_canary:
        print("egress canary SKIPPED by --skip-canary "
              "(local debugging only)", flush=True)
    elif not analyze_shard.egress_canary():
        print("EGRESS CANARY FAILED: outbound connections "
              "succeeded. Aborting before extraction.")
        return 3
    else:
        print("egress canary passed: outbound connections "
              "failed as required", flush=True)

    downloads = []
    with open(downloads_path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line:
                downloads.append(json.loads(line))

    work_dir.mkdir(parents=True, exist_ok=True)
    samples = []
    total = len(downloads)
    for index, record in enumerate(downloads, start=1):
        started = time.monotonic()
        sha256 = record["sha256"]
        sample = {"sha256": sha256,
                  "download_status": record["status"],
                  "attempts": record.get("attempts"),
                  "zip_bytes": record.get("zip_bytes")}
        if record["status"] != "downloaded":
            sample["analysis_status"] = "not-downloaded"
            samples.append(sample)
            print(f"[{index}/{total}] {sha256[:12]} not-downloaded",
                  flush=True)
            continue
        sample_dir = work_dir / sha256
        try:
            files = analyze_shard.extract_zip(
                Path(zips_dir) / f"{sha256}.zip", sample_dir)
            if not files:
                sample["analysis_status"] = "empty-archive"
                samples.append(sample)
                continue
            sample["extracted_filenames"] = sorted(
                str(p.relative_to(sample_dir)) for p in files)
            frag_path = work_dir / f"{sha256}.diagnosis.json"
            ctx = mp.get_context("fork")
            proc = ctx.Process(target=diagnose_worker,
                               args=(str(sample_dir), sample,
                                     str(frag_path)))
            proc.start()
            proc.join(sample_timeout)
            if proc.is_alive():
                proc.terminate()
                proc.join(10)
                if proc.is_alive():
                    proc.kill()
                    proc.join()
                sample["analysis_status"] = "analysis-timeout"
                sample["detail"] = (
                    f"diagnosis exceeded the {sample_timeout}s "
                    "per-sample timeout and was killed")
                samples.append(sample)
            elif frag_path.exists():
                samples.append(json.loads(
                    frag_path.read_text(encoding="utf-8")))
            else:
                sample["analysis_status"] = "analysis-error"
                sample["detail"] = (
                    f"diagnosis worker exited with code "
                    f"{proc.exitcode} without writing a fragment")
                samples.append(sample)
            frag_path.unlink(missing_ok=True)
        except Exception as exc:  # recorded, never dropped
            sample["analysis_status"] = "analysis-error"
            sample["detail"] = f"{type(exc).__name__}: {exc}"
            samples.append(sample)
        finally:
            shutil.rmtree(sample_dir, ignore_errors=True)
        elapsed = time.monotonic() - started
        print(f"[{index}/{total}] {sha256[:12]} "
              f"{samples[-1].get('analysis_status')} in "
              f"{elapsed:.1f}s", flush=True)

    document = {"schema": "eventzero.diagnosis/1",
                "tool": "Event Zero campaign diagnosis",
                "samples": samples}
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(document, indent=2, sort_keys=True),
                        encoding="utf-8")
    print(f"diagnosis written: {len(samples)} sample(s) to {out_path}")
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Structural diagnosis of named campaign samples (CI only).")
    parser.add_argument("--stage", required=True,
                        choices=("download", "analyze"))
    parser.add_argument("hashes", nargs="*",
                        help="sample SHA-256 hashes for the download "
                             "stage (default: the 007 and 008 samples)")
    parser.add_argument("--out", required=True,
                        help="download stage: output directory; "
                             "analyze stage: path of diagnosis.json")
    parser.add_argument("--downloads",
                        help="analyze stage: downloads.jsonl path")
    parser.add_argument("--zips", help="analyze stage: ZIP directory")
    parser.add_argument("--work", help="analyze stage: scratch directory")
    parser.add_argument("--sample-timeout", type=int, default=300,
                        help="per-sample diagnosis timeout in seconds "
                             "(default 300: the diagnosis runs the "
                             "verdict plus a per-unit analyzer pass)")
    parser.add_argument("--skip-canary", action="store_true",
                        help="skip the egress canary (local debugging "
                             "only, never in CI)")
    args = parser.parse_args(argv)

    if args.stage == "download":
        hashes = [h.lower() for h in args.hashes] or list(DEFAULT_HASHES)
        for h in hashes:
            if not re.fullmatch(r"[0-9a-f]{64}", h):
                parser.error(f"not a SHA-256 hash: {h}")
        return download_stage(hashes, Path(args.out))

    if not (args.downloads and args.zips and args.work):
        parser.error("the analyze stage requires --downloads, "
                     "--zips, and --work")
    return analyze_stage(Path(args.downloads), Path(args.zips),
                         Path(args.work), Path(args.out),
                         args.sample_timeout, args.skip_canary)


if __name__ == "__main__":
    raise SystemExit(main())
