"""Hybrid analysis: emulation results + external sandbox report ingestion.
No live malware is ever executed on the host by this module. Dynamic evidence
comes from (a) Unicorn emulation, (b) a CAPE/Cuckoo style JSON report the user
supplies, or (c) a Docker runner config the user supplies (interface only:
Event Zero parses the resulting report, it does not detonate samples itself
unless a user configured runner produced that report elsewhere)."""
import json, os

def ingest_sandbox_report(path_or_obj):
    """Parse a CAPE/Cuckoo-style JSON report into the shared evidence model."""
    if isinstance(path_or_obj, (str, os.PathLike)):
        with open(path_or_obj) as f: rep=json.load(f)
    else: rep=path_or_obj
    out={"source":"CAPE/Cuckoo style sandbox report","processes":[],"files":[],"registry":[],"network":[],"api_calls":[],"signatures":[]}
    beh=rep.get("behavior",{}) if isinstance(rep,dict) else {}
    for p in beh.get("processes",[]):
        out["processes"].append({"name":p.get("process_name") or p.get("name"),"pid":p.get("process_id") or p.get("pid"),
                                  "calls":[c.get("api") for c in p.get("calls",[]) if isinstance(c,dict)]})
        for c in p.get("calls",[]):
            if isinstance(c,dict) and c.get("api"): out["api_calls"].append(c["api"])
    summary=beh.get("summary",{}) if isinstance(beh,dict) else {}
    out["files"]=summary.get("files",[]) or rep.get("dropped",[]) if isinstance(rep,dict) else []
    out["registry"]=summary.get("keys",[]) or summary.get("registry",[])
    net=rep.get("network",{}) if isinstance(rep,dict) else {}
    out["network"]={"hosts":net.get("hosts",[]),"dns":net.get("dns",[]),"http":net.get("http",[])}
    out["signatures"]=[s.get("name") for s in rep.get("signatures",[]) if isinstance(s,dict)]
    out["plain_english"]="Dynamic behaviour supplied by an external sandbox was merged in: processes, files, registry, network and API calls are listed from that report and are labelled as sandbox observed, separate from static evidence."
    return out

def docker_runner_status(config=None):
    cfg=config or os.environ.get("EVENT_ZERO_SANDBOX_CONFIG")
    if not cfg: return {"configured": False, "note": "No local Docker sandbox runner configured. Set EVENT_ZERO_SANDBOX_CONFIG to a runner config file to enable detonation in your own isolated Docker sandbox, or supply a CAPE report with --sandbox-report. Event Zero never detonates a sample on the host itself."}
    return {"configured": True, "config": str(cfg), "warning": "Free public sandboxes publish the sample. CAPE self-hosted is the only private-by-default dynamic option.", "note": "A runner config is present. Event Zero will ingest the report that runner produces; detonation stays inside the user configured isolated container."}
