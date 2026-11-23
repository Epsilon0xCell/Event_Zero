import json, os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from event_zero.analyzer import analyze
from event_zero.services import malwarebazaar, threatfox, urlhaus
from event_zero.validate import validate_report
from event_zero.readability import scores
ROOT=os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
def test_abusech_needs_key(monkeypatch):
    monkeypatch.delenv("ABUSECH_API_KEY", raising=False)
    for fn in (malwarebazaar, threatfox, urlhaus):
        out=fn("ab"*32); assert out["configured"] is False and "ABUSECH_API_KEY" in out["note"]
def test_abusech_with_key_mock(monkeypatch):
    monkeypatch.setenv("ABUSECH_API_KEY","placeholder")
    def fake_post(url, headers, data=None):
        assert headers.get("Auth-Key")=="placeholder"
        return 200, {"query_status":"hash_not_found"}
    out=malwarebazaar("ab"*32, http_post=fake_post); assert out["found"] is False
def test_rootkit_phrasing_and_handoff():
    r=analyze(os.path.join(ROOT,"fake_malware"))
    # fake_malware is not a driver; check a sys-like report via test_v3 fixture path instead
    from tests.test_v3 import pe_with_body
    import tempfile
    body=b"ntoskrnl.exe\x00MmCopyVirtualMemory\x00IoCreateDevice\x00"
    p=os.path.join(tempfile.mkdtemp(),"x.sys"); open(p,"wb").write(pe_with_body(body))
    r=analyze(p)
    assert "indicators consistent with" in r["rootkit"]["plain_english"].lower()
    assert "Volatility" in r["rootkit"]["volatility_handoff"]
def test_zero_day_never_certified():
    r=analyze(os.path.join(ROOT,"fake_malware"))
    assert "never certifies" in r["exploit"]["explainer"].get("disclosure_status","") or "unknown" in r["exploit"].get("disclosure_status","")
def test_validator_gold_and_bad():
    r=analyze(os.path.join(ROOT,"fake_malware"))
    ok, problems=validate_report(r); assert ok, problems
    bad=dict(r); bad["capabilities"]=[{"id":"x","attack_id":"T0000","evidence":[]}]
    ok2, problems2=validate_report(bad); assert not ok2
def test_readability_scores():
    r=analyze(os.path.join(ROOT,"fake_malware"))
    s=r["eli5_metrics"]; assert "flesch_reading_ease" in s and "design_target" in s
    assert scores(["The cat sat. It was soft."])["flesch_reading_ease"]>80
def test_eli5_breakpoint_note():
    r=analyze(os.path.join(ROOT,"fake_malware"))
    assert any("not exact" in s for s in r["eli5"])
