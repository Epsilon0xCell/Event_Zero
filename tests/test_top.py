import io, os, sys, zipfile
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from event_zero.analyzer import analyze
from event_zero.eztools import ez_capgen, validate_and_promote
from event_zero.unpack import analyze_unpack
import base64
ROOT=os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
def write(tmp,name,data):
    p=os.path.join(str(tmp),name)
    # newline="" for text writes: byte-exact fixtures on every platform.
    with open(p,'wb' if isinstance(data,bytes) else 'w', newline=None if isinstance(data,bytes) else '') as f: f.write(data)
    return p
def test_regression_multilayer_token_in_sentence():
    inner=bytes(b^0x55 for b in b"EGGHUNT http://layer.example/shellcode VirtualAlloc")
    l2=base64.b64encode(base64.b64encode(inner)).decode()
    u=analyze_unpack(b"x", [f"BLOB {l2} END"], [])
    assert any(d["chain"]==["base64","base64","xor-0x55"] for d in u["decoded_layers"])
def test_regression_apk_dex_xor(tmp_path):
    buf=io.BytesIO()
    with zipfile.ZipFile(buf,'w') as z:
        z.writestr("AndroidManifest.xml","android.permission.INTERNET".encode('utf-16le'))
        z.writestr("classes.dex", b"dex\n035\x00"+bytes(b^0x24 for b in b"http://hidden-dex.example/x"))
    r=analyze(write(tmp_path,"a.apk",buf.getvalue()))
    assert r["apk"]["dex_xor_decoded"]
def test_capgen_promotion_gate(tmp_path):
    benign=analyze(write(tmp_path,"b.txt","ordinary gardening and tea notes"))
    mal=analyze(os.path.join(ROOT,"fake_malware"))
    draft={"draft_rule_id":"draft-persistence","pattern":"persistence.sh"}
    rec=validate_and_promote(draft, [benign, mal], log_path=os.path.join(str(tmp_path),"promo.jsonl"))
    assert rec["promoted"] and rec["fires_on_benign"]==0
    bad=validate_and_promote({"draft_rule_id":"draft-gardening","pattern":"gardening"}, [benign, mal])
    assert not bad["promoted"]
def test_promotion_log_written(tmp_path):
    benign=analyze(write(tmp_path,"b.txt","plain ordinary text"))
    mal=analyze(os.path.join(ROOT,"fake_malware"))
    log=os.path.join(str(tmp_path),"p.jsonl")
    validate_and_promote({"draft_rule_id":"d","pattern":"persistence.sh"}, [benign, mal], log_path=log)
    assert "promoted" in open(log).read()
