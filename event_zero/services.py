"""Web enrichment: every free and useful hash-lookup service, unified.
Rules: hash first, upload NEVER by default, keys only from environment,
serial requests with cache, external consensus never overrides local evidence.
All clients accept an injectable http_get/http_post so tests mock everything."""
import json, os, time, urllib.request
from .external import virustotal_lookup, hybrid_analysis_lookup, _cache_get, _cache_put

UA={"User-Agent": "EventZero/3.0 (hash lookup; contact: local analyst)"}

def _get(url, headers=None, http_get=None):
    if http_get: return http_get(url, {**UA, **(headers or {})})
    req=urllib.request.Request(url, headers={**UA, **(headers or {})})
    with urllib.request.urlopen(req, timeout=30) as r: return r.status, json.loads(r.read().decode() or "{}")
def _post(url, data, headers=None, http_post=None):
    if http_post: return http_post(url, {**UA, **(headers or {})}, data)
    import urllib.parse
    req=urllib.request.Request(url, headers={**UA, **(headers or {})}, data=urllib.parse.urlencode(data).encode(), method="POST")
    with urllib.request.urlopen(req, timeout=30) as r: return r.status, json.loads(r.read().decode() or "{}")

def _nc(provider, env): return {"provider": provider, "configured": False, "found": None, "note": f"Not configured: no {env} in the environment. Local evidence is complete without it."}
def _err(provider, e): return {"provider": provider, "configured": True, "found": None, "error": type(e).__name__, "note": "Lookup failed; local evidence is unaffected."}

def _abuse_key():
    import os as _os
    return _os.environ.get("ABUSECH_API_KEY")
def malwarebazaar(sha256, http_post=None):
    if not _abuse_key(): return {"provider":"MalwareBazaar","configured":False,"found":None,"note":"Not configured: abuse.ch now requires a free Auth-Key. Set ABUSECH_API_KEY (get one at auth.abuse.ch). Keyless requests return 401."}
    try:
        s,b=_post("https://mb-api.abuse.ch/api/v1/", {"query":"get_info","hash":sha256}, {"Auth-Key": _abuse_key()}, http_post=http_post)
        if b.get("query_status")=="hash_not_found": return {"provider":"MalwareBazaar","configured":True,"found":False,"note":"No sample with this hash in MalwareBazaar (abuse.ch)."}
        d=(b.get("data") or [{}])[0]
        return {"provider":"MalwareBazaar","configured":True,"found":True,"family": d.get("signature"),"first_seen": d.get("first_seen"),"tags": d.get("tags",[]),"file_type": d.get("file_type")}
    except Exception as e: return _err("MalwareBazaar", e)
def threatfox(sha256, http_post=None):
    if not _abuse_key(): return {"provider":"ThreatFox","configured":False,"found":None,"note":"Not configured: abuse.ch requires ABUSECH_API_KEY."}
    try:
        s,b=_post("https://threatfox-api.abuse.ch/api/v1/", {"query":"search_hash","hash":sha256}, {"Auth-Key": _abuse_key()}, http_post=http_post)
        return {"provider":"ThreatFox","configured":True,"found": b.get("query_status")=="ok","iocs": [d.get("ioc") for d in b.get("data",[])][:20],"note":"IOC context from abuse.ch ThreatFox."}
    except Exception as e: return _err("ThreatFox", e)
def urlhaus(sha256, http_post=None):
    if not _abuse_key(): return {"provider":"URLhaus","configured":False,"found":None,"note":"Not configured: abuse.ch requires ABUSECH_API_KEY."}
    try:
        s,b=_post("https://urlhaus-api.abuse.ch/v1/payload/", {"sha256_hash":sha256}, {"Auth-Key": _abuse_key()}, http_post=http_post)
        return {"provider":"URLhaus","configured":True,"found": b.get("query_status")=="ok","urls": [u.get("url") for u in b.get("urls",[])][:20]}
    except Exception as e: return _err("URLhaus", e)
def urlscan(sha256, http_get=None):
    key=os.environ.get("URLSCAN_API_KEY")
    h={"API-Key": key} if key else {}
    try:
        s,b=_get(f"https://urlscan.io/api/v1/search/?q=hash:{sha256}", h, http_get)
        return {"provider":"urlscan.io","configured":True,"found": b.get("total",0)>0,"results": b.get("total",0),"note":"Search works without a key; a key raises limits."}
    except Exception as e: return _err("urlscan.io", e)
def otx(sha256, http_get=None):
    key=os.environ.get("OTX_API_KEY") or os.environ.get("ALIENVAULT_API_KEY")
    if not key: return _nc("AlienVault OTX","OTX_API_KEY")
    try:
        s,b=_get(f"https://otx.alienvault.com/api/v1/indicators/file/{sha256}/general", {"X-OTX-API-KEY": key}, http_get)
        pulses=b.get("pulse_info",{})
        return {"provider":"AlienVault OTX","configured":True,"found": pulses.get("count",0)>0,"pulses": pulses.get("count",0),"tags": list({t for p in pulses.get("pulses",[]) for t in p.get("tags",[])})[:20]}
    except Exception as e: return _err("AlienVault OTX", e)
def metadefender(sha256, http_get=None):
    key=os.environ.get("METADEFENDER_API_KEY")
    if not key: return _nc("MetaDefender","METADEFENDER_API_KEY")
    try:
        s,b=_get(f"https://api.metadefender.com/v4/hash/{sha256}", {"apikey": key}, http_get)
        det=b.get("scan_results",{}).get("total_detected_avs")
        return {"provider":"MetaDefender","configured":True,"found": s==200,"detections": det,"total_avs": b.get("scan_results",{}).get("total_avs")}
    except Exception as e: return _err("MetaDefender", e)
def filescan(sha256, http_get=None):
    try:
        s,b=_get(f"https://www.filescan.io/api/search?query={sha256}", {}, http_get)
        return {"provider":"filescan.io","configured":True,"found": bool(b.get("tasks") or b.get("results")),"note":"Hash search, no key needed for basic use."}
    except Exception as e: return _err("filescan.io", e)
def triage(sha256, http_get=None):
    key=os.environ.get("TRIAGE_API_KEY")
    if not key: return _nc("tria.ge","TRIAGE_API_KEY")
    try:
        s,b=_get(f"https://tria.ge/api/v0/search?query=sha256:{sha256}", {"Authorization": f"Bearer {key}"}, http_get)
        return {"provider":"tria.ge","configured":True,"found": len(b.get("data",[]))>0,"samples": len(b.get("data",[]))}
    except Exception as e: return _err("tria.ge", e)

def enrich(sha256, clients=None, use_cache=True):
    """Serial, cached, hash-only enrichment across all services."""
    if use_cache:
        c=_cache_get("enrich", sha256)
        if c: c=dict(c); c["cached"]=True; return c
    vt=virustotal_lookup(sha256, use_cache=use_cache)
    ha=hybrid_analysis_lookup(sha256)
    results=[vt, ha, malwarebazaar(sha256), threatfox(sha256), urlhaus(sha256), urlscan(sha256), otx(sha256), metadefender(sha256), filescan(sha256), triage(sha256)]
    if clients:  # test injection: replace by provider name
        results=[clients.get(r["provider"], r) for r in results]
    found=[r for r in results if r.get("found")]
    det=None
    for r in results:
        if r.get("last_analysis_stats"): det=r["last_analysis_stats"].get("malicious")
        if r.get("detections") is not None: det=r["detections"]
    consensus=(f"{len(found)} of {len(results)} services have a record of this hash." if found else "No configured service has a record of this hash. That is absence of a record, not proof of safety.")
    out={"sha256": sha256, "services": results, "found_count": len(found), "detections": det,
         "consensus": consensus+" External reputation is context only and never overrides local evidence in this report.",
         "cached": False}
    _cache_put("enrich", sha256, out); return out

def not_configured_enrichment(sha256):
    return {"sha256": sha256, "services": [], "found_count": 0, "detections": None,
            "consensus": "Enrichment not run. Run event_zero enrich <file> or analyze --enrich to query hash lookup services. Local evidence is complete without it."}

def browser_links(sha256):
    """Hash-search links only. No upload links are ever generated."""
    return [
      ("ANY.RUN", f"https://app.any.run/submissions/#filehash:{sha256}", "hash search page, no file shared"),
      ("Joe Sandbox", f"https://www.joesandbox.com/search?q={sha256}", "hash search page, no file shared"),
      ("Koodous", f"https://koodous.com/apks?search={sha256}", "hash search page, mainly Android, no file shared"),
      ("Intezer", f"https://analyze.intezer.com/files/{sha256}", "hash lookup page, no file shared"),
      ("CyberChef", "https://gchq.github.io/CyberChef/", "tool page only, nothing is sent until you paste data yourself"),
      ("dogbolt decompiler", "https://dogbolt.org/", "tool page only, uploading there is your choice and is NOT done by Event Zero"),
      ("UnpacMe", "https://www.unpac.me/", "tool page only, uploading there is your choice and is NOT done by Event Zero"),
    ]
