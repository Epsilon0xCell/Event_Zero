"""Event Zero's own tools: the differentiator layer.
ez-carver (unpack.carve), ez-shellcode (this file), ez-eli5 (eli5.py),
ez-capgen (this file), ez-diff (this file)."""
import re
from collections import Counter
from .unpack import carve, rc4
from .exploit import analyze_exploit
from .emulation import emulate_shellcode

def ez_shellcode(data, arch="x86-64"):
    """Decode and emulated-trace a shellcode blob."""
    r=analyze_exploit(data, [], [], data, arch!="x86")
    emu=emulate_shellcode(data, arch)
    # xor decoder stub detection: xor byte ptr [reg+..], key pattern 80 30 xx / 30 .. etc
    decoders=[]
    for m in re.finditer(rb'\x80\x30(.)', data): decoders.append({"pattern":"xor byte [eax], imm8","key_hex":hex(m.group(1)[0] if isinstance(m.group(1),int) else m.group(1)),"offset":m.start()})
    for m in re.finditer(rb'\xac\x30\xc8\xaa', data): decoders.append({"pattern":"lodsb/xor al,cl/stosb decoder loop","offset":m.start()})
    return {"exploit": r, "emulation": emu, "decoder_stubs": decoders,
            "carved": carve(data),
            "plain_english": "ez-shellcode treats the file as raw shellcode: it finds the landing pad, the egghunter and the address-finding trick, lists ROP gadgets, notes any decoder loop, and emulates the first instructions inside Unicorn only, never on the host processor."}

def ez_capgen(report, min_repeats=3):
    """Turn unknown repeated patterns in a sample into draft capability rules.
    Looks at strings and API-like tokens that matched no existing capability,
    plus repeated byte n-grams in high-signal regions, and drafts YAML rules."""
    known=set()
    for c in report.get("capabilities",[]): known.update(e.split(": ")[-1] for e in c.get("evidence",[]))
    strings=report.get("strings",{}).get("all",[])
    cand=Counter()
    for s in strings:
        for tok in re.findall(r'[A-Za-z][A-Za-z0-9_]{4,}', s):
            if tok not in known and tok.lower() not in ("http","https","windows","system","program","files"):
                cand[tok]+=1
    drafts=[]
    for tok, n in cand.most_common(20):
        if n>=min_repeats:
            drafts.append({"draft_rule_id": f"draft-{tok.lower()}", "pattern": tok, "occurrences": n,
                           "yaml": f"rule:\n  meta:\n    name: draft capability for repeated token {tok}\n    namespace: event-zero-draft\n  features:\n    - string: {tok}\n  # DRAFT: a human analyst must confirm this pattern is behaviour, not noise, before it ships.\n"})
    return {"draft_rules": drafts, "note": "Drafts only. ez-capgen proposes, a human disposes: no draft rule affects scoring until an analyst promotes it into capabilities.py."}

def ez_diff(a, b):
    """Compare two analysis reports and explain differences in plain text."""
    def caps(r): return {c["id"]: c["name"] for c in r.get("capabilities",[])}
    ca, cb = caps(a), caps(b)
    lines=[]
    lines.append(f"Comparing {a.get('filename')} with {b.get('filename')}.")
    if a.get("hashes",{}).get("sha256")==b.get("hashes",{}).get("sha256"): lines.append("They are the exact same file, byte for byte. There is nothing more to compare.")
    only_a=sorted(set(ca)-set(cb)); only_b=sorted(set(cb)-set(ca)); both=sorted(set(ca)&set(cb))
    if both: lines.append("Both can do: "+", ".join(ca[i] for i in both)+".")
    if only_a: lines.append(f"Only the first can do: "+", ".join(ca[i] for i in only_a)+".")
    if only_b: lines.append(f"Only the second can do: "+", ".join(cb[i] for i in only_b)+".")
    ia=set(a.get("iocs",{}).get("ip_addresses",[])); ib=set(b.get("iocs",{}).get("ip_addresses",[]))
    if ia!=ib: lines.append(f"Network addresses differ. First: {sorted(ia) or 'none'}. Second: {sorted(ib) or 'none'}.")
    lines.append(f"Risk: first is {a.get('risk',{}).get('verdict')} ({a.get('risk',{}).get('score')}/100), second is {b.get('risk',{}).get('verdict')} ({b.get('risk',{}).get('score')}/100).")
    ea={f["id"] for f in a.get("evasion",{}).get("findings",[])}; eb={f["id"] for f in b.get("evasion",{}).get("findings",[])}
    if ea!=eb: lines.append(f"Evasion tricks differ. First only: {sorted(ea-eb) or 'none'}. Second only: {sorted(eb-ea) or 'none'}.")
    return {"lines": lines, "only_first": only_a, "only_second": only_b, "shared": both}


def validate_and_promote(draft, corpus_reports, log_path=None):
    """Self-improvement loop: a draft capgen rule is validated against the corpus.
    Promotion requires: fires on at least one malicious/source report, fires on
    ZERO benign reports (labelled benign by empty capabilities and low score).
    Promoted rules are appended to the promotion log; capabilities.py promotion
    is a code change an analyst ships, this function is the gate and the record."""
    import json, os
    pat=draft["pattern"]
    def fires(rep):
        import re as _re
        return any(_re.search(r"\b"+_re.escape(pat)+r"\b", s) for s in rep.get("strings",{}).get("all",[]))
    benign=[r for r in corpus_reports if not r.get("capabilities") and r.get("risk",{}).get("score",0)<25]
    malicious=[r for r in corpus_reports if r.get("capabilities")]
    fires_benign=sum(1 for r in benign if fires(r)); fires_mal=sum(1 for r in malicious if fires(r))
    promoted = fires_mal>=1 and fires_benign==0 and len(benign)>=1
    rec={"draft_rule_id": draft.get("draft_rule_id"), "pattern": pat, "fires_on_malicious": fires_mal, "fires_on_benign": fires_benign, "benign_corpus_size": len(benign), "promoted": promoted,
         "reason": "passed corpus gate" if promoted else "rejected: must fire on a malicious sample and on zero benign samples"}
    if log_path:
        with open(log_path,"a") as f: f.write(json.dumps(rec)+"\n")
    return rec
