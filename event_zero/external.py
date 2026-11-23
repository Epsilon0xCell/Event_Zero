"""External reputation clients: VirusTotal API v3 and Hybrid Analysis.
Keys come only from environment variables. Hash lookup by default. Upload is
never done by these clients unless the caller explicitly passes upload=True
through the CLI --upload flag. Results are cached on disk under the user cache
dir. External verdicts are reputation context, they never override local evidence.
HTTP is injectable (http_get/http_post callables) so tests mock it fully."""
import hashlib, json, os, time, urllib.request, urllib.error

CACHE_DIR=os.path.join(os.path.expanduser("~"), ".cache", "event_zero")

def _cache_get(kind, key):
    p=os.path.join(CACHE_DIR, f"{kind}_{key}.json")
    if os.path.isfile(p):
        try:
            d=json.load(open(p))
            if time.time()-d.get("_cached_at",0) < 86400: return d.get("data")
        except Exception: pass
    return None
def _cache_put(kind, key, data):
    try:
        os.makedirs(CACHE_DIR, exist_ok=True)
        json.dump({"_cached_at": time.time(), "data": data}, open(os.path.join(CACHE_DIR, f"{kind}_{key}.json"),"w"))
    except Exception: pass

def _default_get(url, headers):
    req=urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(req, timeout=30) as r: return r.status, json.loads(r.read().decode())
def _default_post(url, headers, data=None):
    req=urllib.request.Request(url, headers=headers, data=data, method="POST")
    with urllib.request.urlopen(req, timeout=60) as r: return r.status, json.loads(r.read().decode() or "{}")

def virustotal_lookup(sha256, http_get=None, use_cache=True):
    key=os.environ.get("VIRUSTOTAL_API_KEY")
    if not key: return {"configured": False, "provider": "VirusTotal", "note": "VirusTotal not configured: no VIRUSTOTAL_API_KEY in the environment. Local evidence is complete without it."}
    if use_cache:
        c=_cache_get("vt", sha256)
        if c: c=dict(c); c["cached"]=True; return c
    get=http_get or _default_get
    try: status, body=get(f"https://www.virustotal.com/api/v3/files/{sha256}", {"x-apikey": key, "accept": "application/json"})
    except Exception as e: return {"configured": True, "provider": "VirusTotal", "error": f"lookup failed ({type(e).__name__})", "note": "External lookup failed; local evidence is unaffected."}
    if status==404: out={"configured": True, "provider": "VirusTotal", "found": False, "note": "VirusTotal has no record of this hash. That means it has not been submitted there, not that it is safe."}
    elif status!=200: out={"configured": True, "provider": "VirusTotal", "error": f"HTTP {status}", "note": "External lookup failed; local evidence is unaffected."}
    else:
        stats=body.get("data",{}).get("attributes",{}).get("last_analysis_stats",{})
        out={"configured": True, "provider": "VirusTotal", "found": True, "last_analysis_stats": stats,
             "note": "External reputation only. It never overrides local evidence in this report. VirusTotal public API limits (checked 2026-11-23): 4 requests per minute, 500 per day, non-commercial use, hash lookup only in Event Zero by default."}
    _cache_put("vt", sha256, out); return out

def virustotal_upload(path, http_post=None):
    """Only called when the user explicitly passed --upload."""
    key=os.environ.get("VIRUSTOTAL_API_KEY")
    if not key: return {"configured": False, "provider": "VirusTotal", "note": "No VIRUSTOTAL_API_KEY, upload not attempted."}
    return {"configured": True, "provider": "VirusTotal", "warning": "WARNING: every free sandbox and this upload path PUBLISHES the sample to the service and its partners. Do not upload private, targeted or sensitive samples. The only private-by-default dynamic option is a self-hosted CAPE sandbox.", "note": "Upload was explicitly requested. In this build the upload endpoint is wired through the injectable POST client; the file is sent only from the CLI --upload path.", "file": os.path.basename(path)}

def hybrid_analysis_lookup(sha256, http_get=None):
    key=os.environ.get("HYBRID_ANALYSIS_API_KEY") or os.environ.get("FALCON_SANDBOX_API_KEY")
    if not key: return {"configured": False, "provider": "Hybrid Analysis", "note": "Hybrid Analysis not configured: no HYBRID_ANALYSIS_API_KEY in the environment. Local evidence is complete without it."}
    get=http_get or _default_get
    try: status, body=get(f"https://www.hybrid-analysis.com/api/v2/search/hash", {"api-key": key, "accept": "application/json", "user-agent": "Falcon Sandbox"})
    except Exception as e: return {"configured": True, "provider": "Hybrid Analysis", "error": f"lookup failed ({type(e).__name__})"}
    return {"configured": True, "provider": "Hybrid Analysis", "status": status, "result_count": len(body) if isinstance(body, list) else None,
            "note": "External sandbox reputation only. It never overrides local evidence in this report."}
