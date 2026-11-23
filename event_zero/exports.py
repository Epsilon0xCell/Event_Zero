"""Output generators from findings: YARA, Sigma style summary, IOC CSV, STIX 2.1, ATT&CK Navigator."""
import csv, io, json, re, uuid

def yara_rule(report):
    name=re.sub(r'[^A-Za-z0-9_]', '_', "EZ_"+os.path.splitext(report["filename"])[0]) if (os:=__import__("os")) else "EZ_rule"
    strs=[]
    for i,s in enumerate(report.get("strings",{}).get("all",[])[:400]):
        if len(s)>=8 and any(k in s.lower() for k in ("http","socket","persist","powershell","cmd","/tmp","registry","run","token","password","miner","inject")):
            strs.append((f"s{i}", s.replace('\\','\\\\').replace('"','\\"')))
    strs=strs[:20]
    lines=[f"rule {name} {{","  meta:","    author = \"Event Zero (generated from local evidence)\"",
           f"    sha256 = \"{report['hashes']['sha256']}\"","    description = \"Generated rule: review before production use\"","  strings:"]
    for sid,s in strs: lines.append(f'    ${sid} = "{s}" ascii wide')
    if not strs: lines.append('    $h = "'+report["hashes"]["sha256"][:16]+'"')
    lines.append("  condition:"); lines.append("    any of them" if strs else "    $h")
    lines.append("}")
    return "\n".join(lines)+"\n"

def sigma_summary(report):
    caps=[c["name"] for c in report.get("capabilities",[])]
    return {"title": f"Event Zero behaviour summary: {report['filename']}", "status": "experimental",
            "description": "Sigma style summary generated from local static evidence. It describes behaviours to hunt for, it is not a validated Sigma rule for a specific log source.",
            "logsource": {"category": "process_creation", "product": "windows"},
            "behaviours": caps, "level": "high" if report["risk"]["score"]>=50 else "medium" if report["risk"]["score"]>=25 else "low",
            "tags": [f"attack.{c['attack_id'].lower()}" for c in report.get("capabilities",[])]}

def iocs_csv(report):
    buf=io.StringIO(); w=csv.writer(buf); w.writerow(["type","value","source_file","sha256"])
    m={"urls":"url","ip_addresses":"ipv4-addr","domains":"domain-name","file_paths":"file-path"}
    for k,typ in m.items():
        for v in report.get("iocs",{}).get(k,[]): w.writerow([typ, v, report["filename"], report["hashes"]["sha256"]])
    return buf.getvalue()

def stix_bundle(report):
    objs=[{"type":"malware","spec_version":"2.1","id":"malware--"+str(uuid.uuid5(uuid.NAMESPACE_URL, report["hashes"]["sha256"])),
           "name": report["filename"], "is_family": False, "malware_types":["unknown"],
           "labels":[c["id"] for c in report.get("capabilities",[])]}]
    for ip in report.get("iocs",{}).get("ip_addresses",[]):
        objs.append({"type":"ipv4-addr","spec_version":"2.1","id":"ipv4-addr--"+str(uuid.uuid5(uuid.NAMESPACE_URL, ip)),"value":ip})
    for d in report.get("iocs",{}).get("domains",[]):
        objs.append({"type":"domain-name","spec_version":"2.1","id":"domain-name--"+str(uuid.uuid5(uuid.NAMESPACE_URL, d)),"value":d})
    objs.append({"type":"file","spec_version":"2.1","id":"file--"+str(uuid.uuid5(uuid.NAMESPACE_URL, "f"+report["hashes"]["sha256"])),
                 "name": report["filename"], "hashes":{"SHA-256": report["hashes"]["sha256"], "MD5": report["hashes"]["md5"]}})
    return {"type":"bundle","id":"bundle--"+str(uuid.uuid5(uuid.NAMESPACE_URL, "b"+report["hashes"]["sha256"])),"objects":objs}

def navigator_layer(report):
    techs={}
    for c in report.get("capabilities",[]): techs[c["attack_id"]]=max(techs.get(c["attack_id"],0), report["risk"]["score"])
    for f in report.get("evasion",{}).get("findings",[]): techs[f["attack_id"]]=max(techs.get(f["attack_id"],0), 50)
    return {"name": f"Event Zero: {report['filename']}", "versions": {"attack":"14","navigator":"5.0","layer":"4.5"},
            "domain":"enterprise-attack","description":"Generated from local evidence by Event Zero.",
            "techniques":[{"techniqueID":k,"score":v,"enabled":True,"comment":report["filename"]} for k,v in sorted(techs.items())]}
