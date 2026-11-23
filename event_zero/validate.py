"""Validator for the Event Zero report format spec (format-spec.md).
Every load-bearing claim must carry evidence. Returns (ok, problems)."""
import json
REQUIRED=["tool","version","filename","hashes","format","capabilities","iocs","risk","unknowns","eli5","plain_english"]
def validate_report(r):
    problems=[]
    for k in REQUIRED:
        if k not in r: problems.append(f"missing required field: {k}")
    for c in r.get("capabilities",[]):
        if not c.get("evidence"): problems.append(f"capability {c.get('id')} has no evidence")
        if not c.get("attack_id"): problems.append(f"capability {c.get('id')} has no ATT&CK ID")
    for f in r.get("evasion",{}).get("findings",[]):
        if not f.get("evidence"): problems.append(f"evasion finding {f.get('id')} has no evidence")
    if not r.get("unknowns"): problems.append("unknowns section is empty: a report must state what it could not determine")
    if not r.get("eli5"): problems.append("ELI5 section is empty")
    # every IP in plain_english must exist in IOCs or strings
    import re
    blob=" ".join(r.get("strings",{}).get("all",[]))
    allowed=set(r.get("iocs",{}).get("ip_addresses",[])) | set(re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', blob))
    for para in r.get("plain_english",[]):
        for ip in re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', para):
            if ip not in allowed: problems.append(f"plain-English section mentions IP {ip} that is not in evidence")
    return (not problems), problems
def validate_verdict(r):
    """Verdict JSON (format-spec.md, verdict section). Exactly two
    headlines exist. YES must carry a reason class: PROVEN needs cited
    proof, UNACCOUNTED needs the unaccounted items listed plainly.
    NO needs every file accounted, no unaccounted items, and the
    accounting claim phrased in the plain-English section."""
    problems=[]
    headlines={"YES":"YES: MALWARE FOUND","NO":"NO: NO MALWARE"}
    v=r.get("verdict")
    if v not in headlines: problems.append(f"verdict field is not YES or NO: {v}")
    elif r.get("headline")!=headlines[v]: problems.append(f"headline does not match verdict: {r.get('headline')}")
    if not r.get("files"): problems.append("verdict has no per-file table")
    if "elapsed_seconds" not in r: problems.append("verdict has no timing field")
    if not r.get("eli5"): problems.append("verdict ELI5 section is empty")
    rc=r.get("reason_class")
    if v=="YES":
        if rc not in ("PROVEN","UNACCOUNTED"): problems.append(f"YES verdict without a valid reason class: {rc}")
        if rc=="PROVEN":
            if not r.get("yes_reasons"): problems.append("YES-PROVEN with no proof: yes_reasons is empty")
            for y in r.get("yes_reasons",[]):
                if not y.get("evidence"): problems.append(f"YES reason {y.get('chain')} has no evidence")
        if rc=="UNACCOUNTED":
            if not r.get("unaccounted"): problems.append("YES-UNACCOUNTED without the unaccounted items listed")
            if not r.get("next_steps"): problems.append("YES-UNACCOUNTED without next steps")
    if v=="NO":
        if rc!="ACCOUNTED": problems.append(f"NO verdict without reason class ACCOUNTED: {rc}")
        if r.get("unaccounted") or r.get("blockers"): problems.append("NO verdict issued while unaccounted items exist")
        for f in r.get("files",[]):
            if f.get("verdict")!="NO: ACCOUNTED": problems.append(f"NO verdict but file {f.get('path_in_release')} is {f.get('verdict')}")
        if not any("Every byte is accounted for" in p for p in r.get("plain_english",[])):
            problems.append("NO verdict without the accounting claim phrased in plain English")
    blob=json.dumps({k: r.get(k) for k in ("headline","eli5","plain_english")}).lower()
    for word in ("likely","probably","% confident"):
        if word in blob: problems.append(f"verdict headline or summary contains a banned probability word: {word}")
    return (not problems), problems
def validate_file(path):
    with open(path) as f: r=json.load(f)
    if r.get("report_type")=="verdict" or "headline" in r: return validate_verdict(r)
    return validate_report(r)
