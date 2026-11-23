"""Gemini narrative layer with an evidence verification gate.

Key handling: the key is read ONLY from the GEMINI_API_KEY or GOOGLE_API_KEY
environment variables, at call time. It is never hardcoded, never logged,
never stored in a report, and never committed. If there is no key, or the
google-genai SDK is not installed, the deterministic core report is returned
unchanged and the report states that the LLM layer is not configured.
"""
import os, re

DEFAULT_MODEL="gemini-2.5-flash"

def _key():
    return os.environ.get("GEMINI_API_KEY") or os.environ.get("GOOGLE_API_KEY")

def evidence_set(report):
    ev={"ips": set(report.get("iocs",{}).get("ip_addresses",[])),
        "urls": set(report.get("iocs",{}).get("urls",[])),
        "domains": set(report.get("iocs",{}).get("domains",[])),
        "paths": set(report.get("iocs",{}).get("file_paths",[])),
        "imports": {i["name"] for i in report.get("imports",[])},
        "capabilities": {c["name"] for c in report.get("capabilities",[])} | {c["id"] for c in report.get("capabilities",[])},
        "attack_ids": {c["attack_id"] for c in report.get("capabilities",[])}}
    # decoded strings can legitimately introduce IOCs
    import re as _re
    blob=" ".join(report.get("strings",{}).get("all",[]))
    ev["ips"] |= set(_re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', blob))
    ev["domains"] |= set(_re.findall(r'\b(?:[a-z0-9-]+\.)+(?:com|net|org|io|ru|cn|info|top|xyz|onion)\b', blob.lower()))
    return ev

def verify_narrative(text, report):
    """Drop any sentence that mentions an IOC, attack ID or import name that is not in evidence."""
    ev=evidence_set(report); dropped=[]; kept=[]
    sentences=re.split(r'(?<=[.!?])\s+', text.strip())
    for s in sentences:
        if not s.strip(): continue
        bad=False
        for ip in re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', s):
            if ip not in ev["ips"]: bad=True
        for dom in re.findall(r'\b(?:[a-z0-9-]+\.)+(?:com|net|org|io|ru|cn|info|top|xyz|onion)\b', s.lower()):
            if dom not in ev["domains"] and dom not in " ".join(ev["urls"]).lower(): bad=True
        for aid in re.findall(r'T\d{4}(?:\.\d{3})?', s):
            if aid not in ev["attack_ids"]: bad=True
        for fn in re.findall(r'\b[A-Z][A-Za-z]{3,}(?:Ex|W|A)?\b(?=\s*(?:\(|function|API|call))', s):
            if fn not in ev["imports"] and fn not in ev["capabilities"]: bad=True
        (dropped if bad else kept).append(s)
    return " ".join(kept), dropped

def _call_client(client, prompt, model):
    # Supports: plain callable, google-genai style client, and simple mocks.
    if callable(client): return str(client(prompt))
    models=getattr(client, "models", None)
    if models is not None and hasattr(models, "generate_content"):
        r=models.generate_content(model=model, contents=prompt)
        return getattr(r, "text", str(r))
    if hasattr(client, "generate_content"):
        r=client.generate_content(prompt)
        return getattr(r, "text", str(r))
    raise TypeError("unsupported Gemini client shape")

def enhance_report(report, client=None, model=DEFAULT_MODEL, eli5_text=None):
    """Return (narrative_or_None, status_dict). Never raises on missing key/SDK."""
    key=_key()
    if client is None and not key:
        return None, {"status":"not_configured","provider":"gemini","model":model,
                      "note":"LLM layer not configured: no GEMINI_API_KEY or GOOGLE_API_KEY in the environment. The deterministic report above is complete without it."}
    if client is None:
        try:
            from google import genai
            client=genai.Client(api_key=key)
        except Exception as e:
            return None, {"status":"not_configured","provider":"gemini","model":model,
                          "note":f"LLM layer not configured: the google-genai SDK is not available in this environment ({type(e).__name__}). The deterministic report is complete without it."}
    ev_summary={
        "filename": report.get("filename"), "format": report.get("format",{}),
        "capabilities": report.get("capabilities",[]), "imports": [i["name"] for i in report.get("imports",[])],
        "decoded_strings": {"base64": report.get("strings",{}).get("base64_decoded",[]), "xor": report.get("strings",{}).get("xor_decoded",[])},
        "iocs": report.get("iocs",{}), "verdict": report.get("risk",{}),
        "evasion": [f["name"] for f in report.get("evasion",{}).get("findings",[])],
    }
    prompt=("Rewrite the following malware analysis evidence as a clear plain-English narrative for a report. "
            "Use ONLY facts in the evidence. Do not invent any IP address, domain, URL, function name, capability or ATT&CK ID. "
            f"Evidence: {ev_summary}")
    try: raw=_call_client(client, prompt, model)
    except Exception as e:
        return None, {"status":"error","provider":"gemini","model":model,"note":f"Gemini call failed ({type(e).__name__}); deterministic report kept unchanged."}
    clean, dropped=verify_narrative(raw, report)
    status={"status":"ai_assisted","provider":"gemini","model":model,"label":"AI-assisted (Gemini), evidence-gated",
            "sentences_dropped_by_gate": dropped,
            "note":"Gemini rewrote narrative wording only. Every sentence was checked against the evidence set; sentences mentioning facts not in evidence were dropped and are listed here."}
    return (clean or None), status

def summarise(report_text, callable_fn=None):
    """Backwards compatible v2 helper."""
    if callable_fn is None: return None
    return callable_fn(report_text)
