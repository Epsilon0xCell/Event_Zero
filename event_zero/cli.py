import argparse, json, os, sys
from .analyzer import analyze
from .report import to_text, to_markdown, to_json
def main(argv=None):
    p=argparse.ArgumentParser(prog="event_zero", description="Event Zero: offline malware analysis into plain English. The sample is never executed.")
    sub=p.add_subparsers(dest="cmd")
    a=sub.add_parser("analyze", help="Analyze a file")
    a.add_argument("file"); a.add_argument("--out", default=None, help="Output path; format from suffix .txt/.md/.json (default: print text, also write .txt if --out has no suffix)")
    a.add_argument("--format", choices=["txt","md","json"], default=None)
    a.add_argument("--gemini", action="store_true", help="Enable the evidence-gated Gemini narrative layer (needs GEMINI_API_KEY or GOOGLE_API_KEY)")
    a.add_argument("--enrich", action="store_true", help="Query hash lookup enrichment services")
    a.add_argument("--sandbox-report", default=None, help="Path to a CAPE/Cuckoo style JSON sandbox report to merge")
    a.add_argument("--upload", action="store_true", help="Explicitly allow VirusTotal upload (never done by default)")
    for name, helptext in [("validate","Validate a report JSON against format-spec.md"),("export-iocs","Export IOCs as CSV, STIX 2.1 and Navigator layer"),("tools","List the tool registry"),("enrich","Enrich one file by hash"),("shellcode","Analyse a file as shellcode (ez-shellcode)"),("carve","Carve embedded binaries (ez-carver)"),("capgen","Draft capability rules from a sample (ez-capgen)"),("diff","Compare two samples (ez-diff)")]:
        sp=sub.add_parser(name, help=helptext)
        if name!="tools": sp.add_argument("file")
        if name=="diff": sp.add_argument("file2")
    v=sub.add_parser("verdict", help="Flagship: YES / NO accounting verdict on pirated or cracked software (file, installer, archive or release folder)")
    v.add_argument("file"); v.add_argument("--reference", default=None, help="Genuine original file or folder to diff against")
    v.add_argument("--out", default=None, help="Output path; format from suffix .txt/.json (default: print text)")
    v.add_argument("--format", choices=["txt","json"], default=None)
    v.add_argument("--enrich-known-bad", action="store_true", help="Also check hashes against configured known-bad services (MalwareBazaar, VirusTotal)")
    v.add_argument("--manifest", default=None, help="Also write the folder manifest as JSON Lines to this path")
    vr=sub.add_parser("verify-report", help="Verify a signed Event Zero report or run receipt (Ed25519, canonical verdict core)")
    vr.add_argument("file")
    vr.add_argument("--vrl", default=None, help="Verdict Revocation List (JSON): a report listed in it verifies as REVOKED")
    # legacy compat: event_zero --file X --local
    p.add_argument("--file", dest="legacy_file"); p.add_argument("--local", action="store_true"); p.add_argument("--output", dest="legacy_output")
    args=p.parse_args(argv)
    if getattr(args,"cmd",None)=="verify-report":
        if not os.path.isfile(args.file): print(f"Error: file not found: {args.file}"); return 1
        from .signing import verify_any
        try: obj=json.load(open(args.file))
        except Exception as e: print(f"Error: not a JSON report or receipt: {e}"); return 1
        if getattr(args,"vrl",None):
            from .signing import check_revocation
            try: vrl=json.load(open(args.vrl))
            except Exception as e: print(f"Error: not a JSON revocation list: {e}"); return 1
            entry=check_revocation(obj, vrl)
            if entry:
                print(f"REVOKED: this report is revoked at level '{entry.get('level')}'. Reason: {entry.get('reason')}")
                if entry.get("ez_bypass_id"): print(f"Miss identifier: {entry['ez_bypass_id']}")
                print("A revoked verdict is withdrawn: do not rely on it, whatever its signature says. See docs/MISS-LEDGER.md.")
                return 1
            print("Revocation check: not listed in the supplied Verdict Revocation List.")
        res=verify_any(obj)
        print(f"Verification: {res['status'].upper()}")
        for k,val in res.get("checks",{}).items(): print(f" - {k}: {val}")
        for pr in res.get("problems",[]): print(f" - problem: {pr}")
        if res["status"]=="verified": print("PASS: the signature is valid and the recomputed core, ledger root hash and verdict token all match.")
        elif res["status"]=="unsigned": print("UNSIGNED: this file carries no proof and must not be presented as verified.")
        else: print("FAIL: this file does not verify. Do not trust its verdict.")
        return 0 if res["status"]=="verified" else 1
    if getattr(args,"cmd",None)=="verdict":
        if not os.path.exists(args.file): print(f"Error: subject not found: {args.file}"); return 1
        from .verdict import verdict as _verdict, verdict_to_text, verdict_to_json
        try: vv=_verdict(args.file, reference=args.reference, enrich_known_bad=args.enrich_known_bad)
        except Exception as e: print(f"Error: verdict failed: {e}"); return 1
        if getattr(args,"manifest",None):
            from .verdict import verdict_to_manifest_jsonl
            with open(args.manifest,"w") as mf: mf.write(verdict_to_manifest_jsonl(vv))
            print(f"Manifest saved: {args.manifest}")
        vfmt=args.format or ("json" if (args.out or "").endswith(".json") else "txt")
        if vfmt=="json":
            from .signing import sign_report
            content=verdict_to_json(sign_report(vv))
        else:
            content=verdict_to_text(vv)
        if args.out:
            with open(args.out,"w") as f: f.write(content)
            print(verdict_to_text(vv)); print(f"Verdict saved: {args.out}")
        else: print(content)
        # every run writes its run receipt alongside the report
        receipt=vv.get("receipt")
        if receipt:
            if args.out: rpath=args.out+".receipt.json"
            else: rpath=os.path.join(os.path.dirname(os.path.abspath(args.file)), os.path.basename(args.file)+".receipt.json")
            with open(rpath,"w") as rf: rf.write(json.dumps(receipt, indent=2))
            print(f"Run receipt saved: {rpath} (signature status: {receipt.get('signature',{}).get('status','none')})")
        return 0
    target=None; out=None; fmt=None
    use_llm=False
    if args.cmd in ("tools","enrich","shellcode","carve","capgen","diff","export-iocs","validate"):
        import json as _j
        from .tools_registry import registry
        if args.cmd=="tools":
            for x in registry(): print(f"{x['tool']}: {'installed' if x['installed'] else 'missing'} version={x['version']} adds={x['adds']} blackarch={x['blackarch_package']} hint={x['install_hint']}")
            return 0
        if not os.path.isfile(args.file): print(f"Error: file not found: {args.file}"); return 1
        if args.cmd=="validate":
            from .validate import validate_file
            ok, problems=validate_file(args.file)
            print("VALID: every claim carries evidence and all required sections are present." if ok else "INVALID:")
            for pr in problems: print(f" - {pr}")
            return 0 if ok else 1
        if args.cmd=="export-iocs":
            from .exports import iocs_csv, stix_bundle, navigator_layer
            r0=analyze(args.file); stem=args.file
            open(stem+".iocs.csv","w").write(iocs_csv(r0)); open(stem+".stix.json","w").write(_j.dumps(stix_bundle(r0),indent=2)); open(stem+".navigator.json","w").write(_j.dumps(navigator_layer(r0),indent=2))
            print(f"Wrote {stem}.iocs.csv, {stem}.stix.json, {stem}.navigator.json"); return 0
        if args.cmd=="enrich":
            from .services import enrich as _en; import hashlib
            print(_j.dumps(_en(hashlib.sha256(open(args.file,'rb').read()).hexdigest()), indent=2, default=str)); return 0
        if args.cmd=="shellcode":
            from .eztools import ez_shellcode; print(_j.dumps(ez_shellcode(open(args.file,'rb').read()), indent=2, default=str)); return 0
        if args.cmd=="carve":
            from .unpack import carve; print(_j.dumps(carve(open(args.file,'rb').read()), indent=2, default=str)); return 0
        r0=analyze(args.file)
        if args.cmd=="capgen":
            from .eztools import ez_capgen; print(_j.dumps(ez_capgen(r0), indent=2, default=str)); return 0
        if args.cmd=="diff":
            from .eztools import ez_diff; print("\n".join(ez_diff(r0, analyze(args.file2))["lines"])); return 0
    if args.cmd=="analyze": target=args.file; out=args.out; fmt=args.format; use_llm=args.gemini
    elif args.legacy_file: target=args.legacy_file; out=args.legacy_output
    else: p.print_help(); return 2
    if not os.path.isfile(target):
        print(f"Error: file not found: {target}"); return 1
    try: r=analyze(target, use_llm=use_llm, sandbox_report=getattr(args,"sandbox_report",None), enrich=getattr(args,"enrich",False))
    except Exception as e:
        print(f"Error: analysis failed: {e}"); return 1
    # every run emits a run receipt (signed when EZ_SIGNING_KEY is set)
    try:
        from .signing import build_receipt, sign_receipt
        r["receipt"]=sign_receipt(build_receipt(r))
    except Exception as e:
        r["receipt"]={"schema":"eventzero.run-receipt/1","status":"receipt-error","note":f"Receipt could not be built: {e}"}
    if not fmt:
        fmt="json" if (out or "").endswith(".json") else "md" if (out or "").endswith(".md") else "txt"
    content={"txt":to_text,"md":to_markdown,"json":to_json}[fmt](r)
    if out:
        with open(out,"w") as f: f.write(content)
        print(to_text(r)); print(f"Report saved: {out}")
    else:
        print(content)
    if r.get("receipt"):
        rpath=(out+".receipt.json") if out else os.path.join(os.path.dirname(os.path.abspath(target)), os.path.basename(target)+".receipt.json")
        with open(rpath,"w") as rf: rf.write(json.dumps(r["receipt"], indent=2))
        print(f"Run receipt saved: {rpath} (signature status: {r['receipt'].get('signature',{}).get('status','none')})")
    return 0
if __name__=="__main__": sys.exit(main())
