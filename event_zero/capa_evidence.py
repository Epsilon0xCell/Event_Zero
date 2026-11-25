"""capa-backed capability evidence (coverage wave 9).

The engine's own capability matcher (capabilities.py) is one
evidence source. This module adds a second, independent source
behind the same interface: Mandiant's capa, pinned at
flare-capa 9.4.0 with the capa-rules v9.4.0 corpus, run through
its pure-Python vivisect backend.

Governance, from the accuracy failure-modes research: capa
reports capabilities, not verdicts. Entries produced here are
evidence in the same list the verdict already consumes, under
ids (`capa:<rule>`) that cannot collide with the authored rule
ids every chain is keyed on, so a capa match cannot form,
break, or reweight a chain by construction. A capa failure
(unsupported format, timeout, exception, missing package,
missing rules corpus) degrades to the own-matcher evidence
with the failure named on the file's record; it never produces
silence presented as a result, and it is never a cap by
itself: a missing optional evidence source is not unaccounted
content, and the file's other accounting decides. Capa silence
likewise contributes zero clean evidence.

Pipeline hygiene, per the frontier report's companion rule:
capa's rules loader defaults to a pickle-based ruleset cache.
This integration loads rules with that cache disabled
(`enable_cache=False`): the engine never reads or writes a
ruleset pickle. The rules corpus itself is pinned by tag,
commit, and archive SHA-256 (tools/fetch_capa_rules.sh
verifies the hash before extracting).

Configuration, all optional:
- EZ_CAPA=0 disables the source (named as disabled).
- EZ_CAPA_RULES points at a rules corpus directory.
- EZ_CAPA_BACKEND selects the capa backend (default
  `vivisect`; `ghidra` passes through the same code path and
  needs a Ghidra installation plus a JVM, which is a
  deployment decision, not a code change).
"""

import hashlib
import json
import logging
import os
import signal
import threading

CAPA_VERSION_PIN = "9.4.0"
RULES_VERSION = "v9.4.0"
RULES_COMMIT = "2af9fbfc1c9b4634dbeb76b5d34fca9389fa7f80"
RULES_ARCHIVE_SHA256 = \
    "273591b11737181b3bdaac18964f23627cf10c21c2b143fc9be88e4a33217669"
MAX_FILE_BYTES = 32 * 1024 * 1024
ANALYSIS_TIMEOUT_SECONDS = 30
RULES_LOAD_TIMEOUT_SECONDS = 180

_FORMATS = {"PE": "pe", "ELF": "elf"}

_ruleset = None          # (ruleset, {name: rule}, rules_description)
_ruleset_error = None    # str, cached load failure
_memo = {}               # sha256 -> (entries, status)
_MEMO_MAX = 128


class _Timeout(Exception):
    pass


def _with_timeout(seconds, fn):
    """Run fn under a SIGALRM budget on the main thread; without
    a timer where signals are unavailable (worker threads)."""
    if threading.current_thread() is not threading.main_thread() \
            or not hasattr(signal, "SIGALRM"):
        return fn()
    def handler(signum, frame):
        raise _Timeout()
    old = signal.signal(signal.SIGALRM, handler)
    signal.setitimer(signal.ITIMER_REAL, seconds)
    try:
        return fn()
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, old)


def rules_dir():
    """Resolve the capa-rules corpus directory, or None."""
    env = os.environ.get("EZ_CAPA_RULES")
    if env and os.path.isdir(env):
        return env
    here = os.path.dirname(os.path.abspath(__file__))
    vendored = os.path.join(os.path.dirname(here), "tools", "capa-rules")
    if os.path.isdir(vendored):
        return vendored
    cached = os.path.join(os.path.expanduser("~"), ".cache",
                          "event-zero", "capa-rules-9.4.0")
    if os.path.isdir(cached):
        return cached
    return None


def _rules_description(path):
    stamp = os.path.join(path, ".ez-capa-rules.json")
    try:
        with open(stamp, "r", encoding="utf-8") as f:
            meta = json.load(f)
        return (f"capa-rules {meta.get('version')} "
                f"(commit {str(meta.get('commit'))[:12]}, "
                f"archive sha256 verified at fetch)")
    except Exception:
        return f"capa-rules corpus at {path} (unstamped)"


def _load_ruleset():
    """Lazy per-process RuleSet load. Returns (ruleset, by_name,
    description) or raises RuntimeError with the named cause."""
    global _ruleset, _ruleset_error
    if _ruleset is not None:
        return _ruleset
    if _ruleset_error is not None:
        raise RuntimeError(_ruleset_error)
    try:
        path = rules_dir()
        if path is None:
            raise RuntimeError(
                "the capa-rules corpus is not present (looked in "
                "EZ_CAPA_RULES, tools/capa-rules, and "
                "~/.cache/event-zero/capa-rules-9.4.0); fetch it "
                "with tools/fetch_capa_rules.sh")
        from pathlib import Path
        import capa.rules
        import capa.rules.cache  # noqa: F401 (import order: get_rules needs it)
        logging.getLogger("capa").setLevel(logging.CRITICAL)
        ruleset = _with_timeout(
            RULES_LOAD_TIMEOUT_SECONDS,
            lambda: capa.rules.get_rules([Path(path)],
                                         enable_cache=False))
        by_name = {}
        for attr in ("file_rules", "function_rules",
                     "basic_block_rules", "instruction_rules",
                     "call_rules", "span_of_calls_rules"):
            for rule in getattr(ruleset, attr, None) or []:
                by_name.setdefault(rule.name, rule)
        _ruleset = (ruleset, by_name, _rules_description(path))
        return _ruleset
    except Exception as ex:
        _ruleset_error = f"{type(ex).__name__}: {ex}"
        raise RuntimeError(_ruleset_error)


def _slug(name):
    out = []
    for ch in name.lower():
        out.append(ch if ch.isalnum() else "-")
    return "".join(out).strip("-")[:80]


def _attack_id(rule):
    attacks = rule.meta.get("attacks") or []
    ids = []
    for a in attacks:
        aid = getattr(a, "id", None) or (a.get("id") if isinstance(a, dict) else None)
        ids.append(str(aid or a))
    return ", ".join(ids)


def _entries_from_matches(matches, by_name):
    """Collapse capa matches into capability entries in the
    engine's entry shape. Subscope matches (names carrying a
    /<hash> suffix) collapse into their base rule; lib rules
    (library identification) are not capabilities and are
    skipped."""
    grouped = {}
    for name, results in matches.items():
        base = name.split("/")[0]
        rule = by_name.get(base) or by_name.get(name)
        if rule is not None and rule.meta.get("lib"):
            continue
        slot = grouped.setdefault(base, {"rule": rule, "locations": 0})
        slot["locations"] += len(results)
    entries = []
    for base, slot in sorted(grouped.items()):
        rule = slot["rule"]
        meta = rule.meta if rule is not None else {}
        namespace = meta.get("namespace") or ""
        mbc = meta.get("mbc") or []
        scope = ""
        if rule is not None:
            try:
                scope = str(rule.scopes.static).split(".")[-1].lower()
            except Exception:
                scope = ""
        evidence = [f"capa rule matched at {slot['locations']} location(s)"]
        if scope:
            evidence.append(f"rule scope: {scope}")
        if namespace:
            evidence.append(f"capa namespace: {namespace}")
        if mbc:
            evidence.append(f"mbc: {mbc[0]}")
        entries.append({
            "id": "capa:" + _slug(base),
            "name": base,
            "attack_id": _attack_id(rule) if rule is not None else "",
            "tactic": namespace.split("/")[0] if namespace else "capa",
            "technique": namespace or (mbc[0] if mbc else ""),
            "evidence": evidence,
            "explanation": (
                f"Capability reported by the capa rule '{base}' "
                f"(flare-capa {CAPA_VERSION_PIN}, capa-rules "
                f"{RULES_VERSION}). capa reports capabilities, "
                f"not verdicts: this entry is evidence for the "
                f"accounting, never a finding by itself."),
            "source": "capa",
            "rule_id": base,
            "scope": scope,
        })
    return entries


def _run_capa(path, fmt, bundle):
    """The real capa run: extractor construction plus matching.
    Kept as one function so tests can substitute a recorded
    capa-shaped result at exactly this seam."""
    from pathlib import Path
    import capa.loader
    from capa.capabilities.common import find_capabilities
    ruleset, by_name, _desc = bundle
    backend = os.environ.get("EZ_CAPA_BACKEND", "vivisect")
    extractor = capa.loader.get_extractor(
        Path(path), _FORMATS[fmt], "auto", backend, [],
        should_save_workspace=False, disable_progress=True)
    caps = _with_timeout(
        ANALYSIS_TIMEOUT_SECONDS,
        lambda: find_capabilities(ruleset, extractor,
                                  disable_progress=True))
    return _entries_from_matches(caps.matches, by_name)


def _capa_installed():
    try:
        import capa.version  # noqa: F401
        return True
    except Exception:
        return False


def capa_capabilities(path, fmt, data=None):
    """Return (entries, status). Never raises. Status is one of
    ok, unavailable, failed, skipped, each with a named note,
    the capa version, the rules corpus identification, and the
    backend, so the file record states what the evidence source
    did."""
    status = {"status": "skipped", "note": "",
              "capa_version": CAPA_VERSION_PIN,
              "rules": None, "backend": os.environ.get(
                  "EZ_CAPA_BACKEND", "vivisect"),
              "matches": 0}
    if os.environ.get("EZ_CAPA") == "0":
        status["status"] = "unavailable"
        status["note"] = "capa evidence source disabled by EZ_CAPA=0"
        return [], status
    if fmt not in _FORMATS:
        status["note"] = f"capa evidence applies to PE and ELF inputs, not {fmt}"
        return [], status
    try:
        size = len(data) if data is not None else os.path.getsize(path)
    except Exception as ex:
        status["status"] = "failed"
        status["note"] = f"could not size the file for capa: {ex}"
        return [], status
    if size > MAX_FILE_BYTES:
        status["note"] = (f"file is {size} bytes, past the "
                          f"{MAX_FILE_BYTES}-byte capa evidence budget")
        return [], status
    digest = None
    try:
        digest = hashlib.sha256(
            data if data is not None else open(path, "rb").read()
        ).hexdigest()
    except Exception:
        digest = None
    if digest is not None and digest in _memo:
        entries, cached_status = _memo[digest]
        return list(entries), dict(cached_status)
    if not _capa_installed():
        status["status"] = "unavailable"
        status["note"] = (f"flare-capa is not installed in this "
                          f"environment; install the pinned set "
                          f"with: pip install -r "
                          f"requirements-capa.txt")
        return [], status
    try:
        bundle = _load_ruleset()
    except Exception as ex:
        status["status"] = "unavailable"
        status["note"] = f"capa rules unavailable: {ex}"
        return [], status
    status["rules"] = bundle[2]
    try:
        entries = _run_capa(path, fmt, bundle)
    except _Timeout:
        status["status"] = "failed"
        status["note"] = (f"capa analysis exceeded the "
                          f"{ANALYSIS_TIMEOUT_SECONDS}-second "
                          f"evidence budget and was abandoned; "
                          f"the file's own-matcher evidence stands")
        return [], status
    except Exception as ex:
        status["status"] = "failed"
        status["note"] = (f"capa analysis failed "
                          f"({type(ex).__name__}: {ex}); the "
                          f"file's own-matcher evidence stands")
        return [], status
    status["status"] = "ok"
    status["matches"] = len(entries)
    status["note"] = ("capa evidence merged; no FLIRT signatures "
                       "are bundled with the wheel, so library-"
                       "function identification is reduced")
    if digest is not None:
        if len(_memo) >= _MEMO_MAX:
            _memo.clear()
        _memo[digest] = (list(entries), dict(status))
    return entries, status


def merge_capabilities(own, extra):
    """Merge two capability lists by id, own entries first.
    Pure function; the merge rule the analyzer applies."""
    seen = {c["id"] for c in own}
    merged = list(own)
    for entry in extra:
        if entry["id"] not in seen:
            merged.append(entry)
            seen.add(entry["id"])
    return merged
