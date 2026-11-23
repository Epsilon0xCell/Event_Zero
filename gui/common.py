"""Shared engine contract for the Event Zero desktop GUIs.

Both platform apps (windows/event_zero_win.py and macos/event_zero_mac.py)
consume the engine ONLY through its CLI and JSON output. The engine runs as
a subprocess: python3 -m event_zero analyze|verdict <path> --out <tmp>.json
The sample is never executed by the GUI or by the engine. The GUI never
imports event_zero core modules.

This module is deliberately UI-toolkit-light: it imports PySide6 only for
the QThread runner. All report parsing and verdict-band logic is plain
Python so it can be unit tested headless.
"""

import json
import os
import subprocess
import sys
import tempfile

ABOUT_TEXT = (
    "Event Zero turns a suspicious file into a plain English report anyone "
    "can act on, with every claim tied to evidence found in the file itself.\n\n"
    "Malware in. Plain English out. Evidence attached.\n\n"
    "The flagship feature is The Verdict: a proven YES or NO on whether a "
    "pirated or cracked release contains malware, with every byte accounted "
    "for as genuine, as the explained crack, as proven malicious, or as "
    "unaccounted. No scores and no probabilities, by design.\n\n"
    "Files are read, never run. Event Zero works fully offline: the engine "
    "runs on this machine, no account is needed, nothing is uploaded, and no "
    "usage data leaves this computer. Optional hash lookups, when you enable "
    "them in the engine, send hashes only, never files."
)

# Banner kinds (semantic). Each app maps these to its own platform palette.
DANGER = "danger"    # YES verdict, or high risk analysis
SAFE = "safe"        # NO verdict, or no malicious capability found
WARN = "warn"        # unaccounted, partial, medium risk
INFO = "info"        # test file, neutral, informational


def find_engine_root():
    """Locate the folder that contains the event_zero package.

    Order: EVENT_ZERO_HOME env var, then walk up from this file, then the
    current working directory. Returns None when the engine is missing.
    """
    candidates = []
    env = os.environ.get("EVENT_ZERO_HOME")
    if env:
        candidates.append(env)
    here = os.path.abspath(os.path.dirname(__file__))
    node = here
    for _ in range(5):
        candidates.append(node)
        node = os.path.dirname(node)
    candidates.append(os.getcwd())
    for cand in candidates:
        if os.path.isfile(os.path.join(cand, "event_zero", "__main__.py")):
            return cand
    return None


def engine_python():
    """Interpreter used to run the engine. EVENT_ZERO_PYTHON wins."""
    return os.environ.get("EVENT_ZERO_PYTHON") or sys.executable or "python3"


def enumerate_target(path):
    """All regular files under a file or folder target, sorted."""
    if os.path.isfile(path):
        return [path]
    found = []
    for root, dirs, files in os.walk(path):
        dirs.sort()
        for name in sorted(files):
            found.append(os.path.join(root, name))
    return found


def _as_lines(value):
    if value is None:
        return []
    if isinstance(value, str):
        return [ln for ln in value.splitlines() if ln.strip()]
    out = []
    for item in value:
        if isinstance(item, dict):
            out.append(json.dumps(item, indent=2))
        else:
            out.append(str(item))
    return out


def scope_sentence(report, files_checked=None, not_checked=None):
    """The scope sentence that must sit under every verdict headline.

    States how many files were checked, that the sample was never executed,
    and names anything that could not be checked. Never a naked verdict.
    """
    raw = report.get("raw", {})
    if files_checked is None:
        files = raw.get("files")
        files_checked = len(files) if isinstance(files, list) else 1
    parts = []
    noun = "file" if files_checked == 1 else "files"
    parts.append(f"Checked {files_checked} {noun}.")
    parts.append("The sample was never executed.")
    unchecked = list(not_checked or [])
    if raw.get("report_type") == "verdict":
        for item in raw.get("unaccounted") or raw.get("blockers") or []:
            text = str(item)
            if text not in unchecked:
                unchecked.append(text)
    if unchecked:
        shown = "; ".join(unchecked[:6])
        more = f" (+{len(unchecked) - 6} more in the report)" if len(unchecked) > 6 else ""
        parts.append(f"Could not be fully checked: {shown}{more}.")
    else:
        parts.append("Nothing was skipped.")
    elapsed = raw.get("elapsed_seconds")
    if isinstance(elapsed, (int, float)):
        parts.append(f"Finished in {elapsed:.1f} seconds.")
    return " ".join(parts)


class Banner:
    """Verdict band content: headline text, semantic kind, scope sentence."""

    def __init__(self, text, kind, scope):
        self.text = text
        self.kind = kind
        self.scope = scope

    def __repr__(self):
        return f"Banner({self.text!r}, {self.kind!r})"


def banner_for(report, files_checked=None, not_checked=None):
    """Map a parsed report to its verdict band. Pure logic, unit tested."""
    raw = report.get("raw", {})
    scope = scope_sentence(report, files_checked=files_checked,
                           not_checked=not_checked)
    if raw.get("report_type") == "verdict" or "headline" in raw:
        word = str(raw.get("verdict", "")).upper()
        headline = str(raw.get("headline") or f"{word}: MALWARE VERDICT")
        if word == "YES":
            reason = str(raw.get("reason_class", "")).upper()
            kind = DANGER if "PROVEN" in reason else WARN
            if kind == WARN and "UNACCOUNTED" not in headline:
                headline = headline  # headline already carries the class
            return Banner(headline, kind, scope)
        if word == "NO":
            return Banner(headline, SAFE, scope)
        return Banner(headline, WARN, scope)
    # Analysis report: risk block decides.
    risk = raw.get("risk") or {}
    verdict = str(risk.get("verdict", "")).upper()
    name = raw.get("filename") or raw.get("file") or "file"
    if raw.get("eicar_test_file") or verdict == "TEST FILE":
        return Banner(f"TEST FILE: {name} is the EICAR test file, not real malware",
                      INFO, scope)
    if "HIGH" in verdict or "CRITICAL" in verdict:
        return Banner(f"HIGH RISK: {name} (score {risk.get('score', '?')}/100)",
                      DANGER, scope)
    if "MEDIUM" in verdict:
        return Banner(f"MEDIUM RISK: {name} (score {risk.get('score', '?')}/100)",
                      WARN, scope)
    if "LOW" in verdict:
        return Banner(f"LOW RISK: {name} (score {risk.get('score', '?')}/100)",
                      WARN, scope)
    if verdict:
        return Banner(f"{verdict}: {name}", SAFE, scope)
    return Banner(f"Report ready: {name}", INFO, scope)


def file_rows(report):
    """Per-file table rows, problems first.

    Row keys: name, verdict, why, signer, sha256, size.
    """
    raw = report.get("raw", {})
    rows = []
    if raw.get("report_type") == "verdict" or "headline" in raw:
        for rec in raw.get("files") or []:
            why = rec.get("why") or []
            if isinstance(why, list):
                why_text = " ".join(str(w) for w in why)[:220]
            else:
                why_text = str(why)[:220]
            if rec.get("signed") is True:
                signer = "Signed, valid" if rec.get("signature_valid") else "Signed"
            elif rec.get("signed") is False:
                signer = "Not signed"
            else:
                signer = "Not checked"
            rows.append({
                "name": rec.get("path_in_release") or rec.get("name") or "?",
                "verdict": str(rec.get("verdict", "")),
                "why": why_text or str(rec.get("analysis_verdict") or ""),
                "signer": signer,
                "sha256": rec.get("sha256") or "",
                "size": rec.get("size_bytes") or 0,
            })
    else:
        hashes = raw.get("hashes") or {}
        risk = raw.get("risk") or {}
        reasons = risk.get("reasons") or []
        fmt = (raw.get("format") or {}).get("format")
        rows.append({
            "name": raw.get("filename") or raw.get("file") or "?",
            "verdict": str(risk.get("verdict", "")),
            "why": ("; ".join(str(r) for r in reasons)[:220]
                    or (f"Format: {fmt}" if fmt else "")),
            "signer": "Not checked",
            "sha256": hashes.get("sha256", ""),
            "size": raw.get("size_bytes") or 0,
        })

    def rank(row):
        v = row["verdict"].upper()
        if "PROVEN" in v or "HIGH" in v or "CRITICAL" in v:
            return 0
        if "UNACCOUNTED" in v or "MEDIUM" in v or "UNACCOUNT" in v:
            return 1
        if "LOW" in v:
            return 2
        return 3

    rows.sort(key=rank)
    return rows


def ioc_lists(report):
    """Connection and IOC lists: urls, domains, ip_addresses, file_paths."""
    raw = report.get("raw", {})
    out = {"urls": [], "domains": [], "ip_addresses": [], "file_paths": []}
    iocs = raw.get("iocs") or {}
    for key in out:
        vals = iocs.get(key) or []
        out[key] = [str(v) for v in vals]
    # Verdict reports carry a per-file connection ledger instead.
    for rec in raw.get("files") or []:
        for dest in rec.get("connections") or rec.get("destinations") or []:
            if isinstance(dest, dict):
                if dest.get("url"):
                    out["urls"].append(str(dest["url"]))
                if dest.get("domain"):
                    out["domains"].append(str(dest["domain"]))
                if dest.get("ip"):
                    out["ip_addresses"].append(str(dest["ip"]))
            elif isinstance(dest, str):
                out["urls"].append(dest)
    for key in out:
        seen = set()
        deduped = []
        for v in out[key]:
            if v not in seen:
                seen.add(v)
                deduped.append(v)
        out[key] = deduped
    return out


def render_text(report):
    """Full plain-text rendering of a parsed report (fallback when the
    engine stdout text was not captured)."""
    raw = report.get("raw", {})
    if report.get("text"):
        return report["text"]
    lines = []
    banner = banner_for(report)
    lines.append(banner.text)
    lines.append(banner.scope)
    lines.append("")
    eli5 = _as_lines(raw.get("eli5"))
    if eli5:
        lines.append("ELI5")
        lines.extend(f"  {ln}" for ln in eli5)
        lines.append("")
    plain = _as_lines(raw.get("plain_english"))
    if plain:
        lines.append("PLAIN ENGLISH")
        lines.extend(f"  {ln}" for ln in plain)
        lines.append("")
    caps = raw.get("capabilities") or []
    if caps:
        lines.append("CAPABILITIES")
        for cap in caps:
            if isinstance(cap, dict):
                lines.append(f"  - {cap.get('name', cap.get('id', '?'))} "
                             f"({cap.get('attack_id', '')}) "
                             f"{cap.get('explanation', '')}")
            else:
                lines.append(f"  - {cap}")
        lines.append("")
    iocs = ioc_lists(report)
    lines.append("CONNECTIONS AND IOCS")
    for key, vals in iocs.items():
        lines.append(f"  {key}: {', '.join(vals) if vals else 'none found'}")
    lines.append("")
    unknowns = _as_lines(raw.get("unknowns"))
    if unknowns:
        lines.append("UNKNOWNS")
        lines.extend(f"  {ln}" for ln in unknowns)
    return "\n".join(lines)


def load_report_json(path):
    with open(path, "r", encoding="utf-8") as fh:
        data = json.load(fh)
    return {"raw": data, "source": path}


def partial_verdict(target, enumerated, reason):
    """Synthesise the partial (unaccounted) result produced on cancel.

    Fail closed: a cancelled scan is YES: UNACCOUNTED, never a pass, and the
    scope sentence names what was not checked.
    """
    not_checked = [os.path.basename(p) for p in enumerated] or [target]
    data = {
        "tool": "Event Zero", "version": "gui-partial",
        "report_type": "verdict",
        "subject": target,
        "headline": "YES: UNACCOUNTED (scan cancelled)",
        "verdict": "YES", "reason_class": "UNACCOUNTED",
        "files": [{"name": os.path.basename(p), "path_in_release": p,
                   "verdict": "YES: UNACCOUNTED",
                   "why": [f"Not checked: {reason}"],
                   "signed": None, "signature_valid": None,
                   "sha256": "", "size_bytes": 0} for p in enumerated],
        "unaccounted": [f"{n}: not checked, {reason}" for n in not_checked],
        "eli5": ["The check was stopped before it finished, so this file "
                 "has not been proven clean. Treat it as unproven until a "
                 "full check completes."],
        "plain_english": [f"Scan cancelled. {reason}. No file in this "
                          "target was proven clean by this run."],
    }
    return {"raw": data, "source": None, "partial": True}


try:
    from PySide6.QtCore import QThread, Signal

    class EngineRunner(QThread):
        """Runs the engine as a subprocess. Never executes the sample.

        analyze + folder: one engine run per file, so progress is real and
        per file. verdict: one engine run for the whole target (release
        accounting is a whole-release judgement). Cancel kills the current
        subprocess and emits a partial, unaccounted result.
        """

        progress = Signal(int, int, str)     # done, total, current name
        report_ready = Signal(object)        # report dict (see load_report_json)
        failed = Signal(str)
        partial_ready = Signal(object)

        def __init__(self, mode, target, reference=None, parent=None):
            super().__init__(parent)
            self.mode = mode
            self.target = target
            self.reference = reference
            self._cancelled = False
            self._proc = None

        def cancel(self):
            self._cancelled = True
            if self._proc is not None:
                try:
                    self._proc.kill()
                except Exception:
                    pass

        def _run_engine(self, mode, target):
            root = find_engine_root()
            if root is None:
                raise RuntimeError(
                    "Event Zero engine not found. Set EVENT_ZERO_HOME to the "
                    "folder that contains the event_zero package, or run the "
                    "GUI from inside the Event Zero repository.")
            tmp = tempfile.NamedTemporaryFile(
                suffix=".json", prefix="event_zero_gui_", delete=False)
            tmp.close()
            cmd = [engine_python(), "-m", "event_zero", mode, target,
                   "--out", tmp.name]
            if mode == "verdict" and self.reference:
                cmd += ["--reference", self.reference]
            env = dict(os.environ)
            env["PYTHONPATH"] = root + os.pathsep + env.get("PYTHONPATH", "")
            self._proc = subprocess.Popen(
                cmd, cwd=root, env=env, stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT, text=True)
            out, _ = self._proc.communicate()
            self._proc = None
            if self._cancelled:
                raise InterruptedError("cancelled")
            if not os.path.isfile(tmp.name) or os.path.getsize(tmp.name) == 0:
                raise RuntimeError(
                    "The engine produced no report. Output was:\n"
                    + (out or "(no output)")[-2000:])
            report = load_report_json(tmp.name)
            report["text"] = out or ""
            return report

        def run(self):
            try:
                enumerated = enumerate_target(self.target)
                total = max(len(enumerated), 1)
                if self.mode == "analyze" and os.path.isdir(self.target):
                    done = 0
                    for path in enumerated:
                        if self._cancelled:
                            self.partial_ready.emit(partial_verdict(
                                self.target, enumerated,
                                "scan cancelled by the user"))
                            return
                        self.progress.emit(done, total,
                                           os.path.basename(path))
                        report = self._run_engine("analyze", path)
                        self.report_ready.emit(report)
                        done += 1
                    self.progress.emit(done, total, "")
                    return
                self.progress.emit(0, total,
                                   os.path.basename(self.target))
                report = self._run_engine(self.mode, self.target)
                if self._cancelled:
                    self.partial_ready.emit(partial_verdict(
                        self.target, enumerated,
                        "scan cancelled by the user"))
                    return
                self.progress.emit(total, total, "")
                self.report_ready.emit(report)
            except InterruptedError:
                self.partial_ready.emit(partial_verdict(
                    self.target, enumerate_target(self.target),
                    "scan cancelled by the user"))
            except Exception as exc:  # surfaced in the UI, never swallowed
                if self._cancelled:
                    self.partial_ready.emit(partial_verdict(
                        self.target, enumerate_target(self.target),
                        "scan cancelled by the user"))
                else:
                    self.failed.emit(str(exc))

except ImportError:  # PySide6 missing: parsing logic stays importable.
    EngineRunner = None
