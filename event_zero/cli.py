import argparse, json, os, sys
from .analyzer import analyze
from .report import to_text, to_markdown, to_json
def main(argv=None):
    p=argparse.ArgumentParser(prog="event_zero", description="Event Zero: offline malware analysis into plain English. The sample is never executed.")
    sub=p.add_subparsers(dest="cmd")
    a=sub.add_parser("analyze", help="Analyze a file")
    a.add_argument("file"); a.add_argument("--out", default=None, help="Output path; format from suffix .txt/.md/.json (default: print text, also write .txt if --out has no suffix)")
    a.add_argument("--format", choices=["txt","md","json"], default=None)
    # legacy compat: event_zero --file X --local
    p.add_argument("--file", dest="legacy_file"); p.add_argument("--local", action="store_true"); p.add_argument("--output", dest="legacy_output")
    args=p.parse_args(argv)
    target=None; out=None; fmt=None
    if args.cmd=="analyze": target=args.file; out=args.out; fmt=args.format
    elif args.legacy_file: target=args.legacy_file; out=args.legacy_output
    else: p.print_help(); return 2
    if not os.path.isfile(target):
        print(f"Error: file not found: {target}"); return 1
    try: r=analyze(target)
    except Exception as e:
        print(f"Error: analysis failed: {e}"); return 1
    if not fmt:
        fmt="json" if (out or "").endswith(".json") else "md" if (out or "").endswith(".md") else "txt"
    content={"txt":to_text,"md":to_markdown,"json":to_json}[fmt](r)
    if out:
        with open(out,"w") as f: f.write(content)
        print(to_text(r)); print(f"Report saved: {out}")
    else:
        print(content)
    return 0
if __name__=="__main__": sys.exit(main())
