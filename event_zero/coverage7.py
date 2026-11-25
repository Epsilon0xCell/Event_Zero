"""Coverage wave 7: model files as code, and clipboard payloads
as script units.

Two content classes earned verdicts in this engine without ever
being read as what they are.

Model files. A Python pickle is a program for a small stack
machine whose instruction set includes "call this named
callable": loading one executes whatever its GLOBAL and REDUCE
opcodes name. The engine read protocol 0 pickles as readable
text (they are ASCII) and acquitted them unexamined, so a stream
that runs a shell command on load earned NO ACCOUNTED; binary
pickles capped only incidentally, as unrecognised bytes, with
their callables named nowhere. A safetensors header was never
parsed at all, so a header claiming more tensor data than the
file holds also earned NO. This module walks pickle streams as
bytecode with pickletools.genops, a pure disassembler: nothing
in this module, or anywhere in the engine, ever unpickles,
loads, imports, or executes the content it judges. Safetensors
files are accounted by parsing the header and checking every
tensor's declared extent against the file's actual extent.
ONNX models are walked as protobuf: node domains and external
data locations are inventoried, and a custom operator domain or
an external tensor is an external reference under the closure
rules. Keras Lambda layers are code by design (a serialised
Python function) and are inventoried as unaccounted code.

Clipboard payloads. A page that writes a command to the
clipboard, or instructs the reader to paste and run one, ships
a script unit whose execution surface is the reader's own
shell (the ClickFix shape, ATT&CK T1204.004). The generic
capability machinery sometimes convicted the cradle text
incidentally, but clipboard content assembled from a remote
read earned NO ACCOUNTED, because the unit was never extracted.
This module extracts clipboard units, resolves their content
(literal, remote-assembled, unresolvable), reads the page's
visible instruction framing, and judges the unit under the
script rules: a fully present fetch-and-execute command in a
clipboard write, or under paste-and-run framing, is a provable
chain; remotely assembled or unresolvable clipboard content
caps; commands in documentation framing are data.
"""

import io
import json
import pickletools
import re
import struct

# ------------------------------------------------------------------
# Pickle opcode accounting. The walk is an abstract
# interpretation over pickletools.genops: it tracks string
# constants, memo slots, and GLOBAL resolutions well enough to
# name every callable a stream references and every callable it
# actually invokes, and it records where the walk stopped when
# a stream cannot be consumed completely. It never builds the
# objects the stream describes.
# ------------------------------------------------------------------

_SCALAR_PUSH = {
    "INT", "BININT", "BININT1", "BININT2", "LONG", "LONG1",
    "LONG4", "FLOAT", "BINFLOAT", "STRING", "BINBYTES",
    "SHORT_BINBYTES", "BINBYTES8", "BYTEARRAY8", "UNICODE",
    "SHORT_BINUNICODE", "BINUNICODE", "BINUNICODE8", "NONE",
    "NEWTRUE", "NEWFALSE",
}

_STRING_PUSH = {
    "STRING", "UNICODE", "SHORT_BINUNICODE", "BINUNICODE",
    "BINUNICODE8",
}

# Callables whose invocation is code execution, shell access,
# dynamic import, network fetch, or reflective reach. An invoked
# dangerous callable is a provable chain: the stream, when
# loaded by any standard unpickler, runs it.
_DANGEROUS_MODULES = {"os", "posix", "nt", "subprocess",
                      "builtins", "__builtin__", "commands",
                      "urllib", "urllib.request", "urllib2",
                      "socket", "ctypes", "ctypes.util",
                      "importlib", "shutil", "pathlib",
                      "io", "code", "codeop", "runpy", "pty",
                      "webbrowser", "multiprocessing"}
_DANGEROUS_NAMES = {
    "system", "popen", "popen2", "popen3", "popen4",
    "execv", "execve", "execvp", "execvpe", "execl", "execle",
    "execlp", "execlpe", "spawnv", "spawnve", "spawnvp",
    "spawnvpe", "spawnl", "spawnle", "spawnlp", "spawnlpe",
    "startfile", "Popen", "run", "call", "check_call",
    "check_output", "getoutput", "getstatusoutput",
    "eval", "exec", "__import__", "compile", "getattr",
    "setattr", "delattr", "urlopen", "urlretrieve", "CDLL",
    "WinDLL", "OleDLL", "PyDLL", "cdll", "windll", "oledll",
    "pydll", "create_function", "execfile", "interact",
    "compile_command", "fork", "forkpty", "exec_",
}

# Reconstruction and pure-data constructors: invoking one of
# these builds data, and only data. Tensor machinery (torch,
# numpy), container and copyreg reconstruction, and the standard
# library's pure value types.
_ALLOW_MODULE_PREFIXES = ("torch", "numpy", "collections",
                          "copyreg", "__main__")
_ALLOW_EXACT = {
    ("builtins", "list"), ("builtins", "dict"),
    ("builtins", "set"), ("builtins", "frozenset"),
    ("builtins", "bytearray"), ("builtins", "slice"),
    ("builtins", "range"), ("builtins", "complex"),
    ("__builtin__", "list"), ("__builtin__", "dict"),
    ("__builtin__", "set"), ("__builtin__", "frozenset"),
    ("datetime", "datetime"), ("datetime", "date"),
    ("datetime", "time"), ("datetime", "timedelta"),
    ("datetime", "timezone"), ("decimal", "Decimal"),
    ("uuid", "UUID"), ("re", "Pattern"),
    ("copyreg", "__newobj__"), ("copyreg", "__newobj_ex__"),
    ("copyreg", "_reconstructor"), ("__builtin__", "object"),
    ("builtins", "object"),
}


def _callable_tier(module, name):
    if (module, name) in _ALLOW_EXACT:
        return "allowed"
    if any(module == p or module.startswith(p + ".")
           for p in _ALLOW_MODULE_PREFIXES):
        # torch and numpy expose execution surfaces too; the
        # prefix allowance covers their reconstruction
        # machinery, and the dangerous-name check below runs
        # first for the names that execute.
        if name in _DANGEROUS_NAMES:
            return "dangerous"
        return "allowed"
    if module in _DANGEROUS_MODULES and name in _DANGEROUS_NAMES:
        return "dangerous"
    if name in ("eval", "exec", "__import__", "getattr") \
            and module in ("builtins", "__builtin__"):
        return "dangerous"
    return "other"


def _split_global(arg):
    parts = re.split(r"[\s\n]+", str(arg).strip(), maxsplit=1)
    if len(parts) == 2:
        return parts[0], parts[1]
    return str(arg).strip(), ""


def looks_like_pickle(data):
    """Content test, no extension involved: a binary protocol
    header, or a stream a disassembly walk consumes completely
    to STOP."""
    if len(data) >= 2 and data[0] == 0x80 and 2 <= data[1] <= 5:
        return True
    try:
        count = 0
        for opcode, _arg, _pos in pickletools.genops(data):
            count += 1
            if opcode.name == "STOP":
                return count >= 2
        return False
    except Exception:
        return False


def analyze_pickle(data, claim="none"):
    """Walk a pickle stream as bytecode. Returns None when the
    content is not a pickle at all (no claim, or a soft claim
    whose bytes do not parse as even one pickle opcode); with a
    strict claim (a .pkl name), unparseable content is itself
    the finding. Otherwise returns the accounting dict:
    callables named with their tier and whether invoked, the
    walk's completeness, persistent ids, trailing bytes, and
    the outcome as exactly one of chain, caps, or accounted."""
    if claim == "none" and not looks_like_pickle(data):
        return None
    stack = []
    memo = {}
    callables = []
    by_key = {}
    persids = []
    caps = []
    chain = False
    complete = False
    stop_end = None
    oob = False
    ext_codes = []
    opcodes_seen = 0
    error = None
    error_pos = None

    def record(module, name, invoked):
        key = (module, name)
        entry = by_key.get(key)
        if entry is None:
            entry = {"module": module, "name": name,
                     "tier": _callable_tier(module, name),
                     "invoked": False}
            by_key[key] = entry
            callables.append(entry)
        if invoked:
            entry["invoked"] = True
        return entry

    def pop_to_mark():
        items = []
        while stack:
            value = stack.pop()
            if isinstance(value, tuple) and value and \
                    value[0] == "mark":
                break
            items.append(value)
        return items

    positions = []
    try:
        ops = list(pickletools.genops(data))
    except Exception:
        ops = None
    if ops is None:
        # genops is lazy; force the failure through the walk
        # loop below instead so the stopping offset is kept.
        ops = []
        try:
            for item in pickletools.genops(data):
                ops.append(item)
        except Exception as ex:
            error = str(ex)
    if error is None:
        positions = [pos for _op, _arg, pos in ops]
    try:
        for idx, (opcode, arg, pos) in enumerate(ops):
            name = opcode.name
            opcodes_seen += 1
            nxt = ops[idx + 1][2] if idx + 1 < len(ops) \
                else len(data)
            if name in ("PROTO", "FRAME"):
                continue
            if name == "STOP":
                complete = True
                # Every pickle opcode is one byte; the next
                # opcode's position is not used because a
                # stream that fails to disassemble past STOP
                # (trailing bytes that are not opcodes) has no
                # next position, and STOP's own end is exact.
                stop_end = pos + 1
                break
            if name in _SCALAR_PUSH:
                if name in _STRING_PUSH and isinstance(arg, str):
                    stack.append(("const", arg))
                elif name in ("SHORT_BINBYTES", "BINBYTES",
                              "BINBYTES8", "BYTEARRAY8"):
                    stack.append(("bytes",))
                else:
                    stack.append(("other",))
                continue
            if name == "GLOBAL":
                module, gname = _split_global(arg)
                record(module, gname, False)
                stack.append(("global", module, gname))
                continue
            if name == "STACK_GLOBAL":
                gname = stack.pop() if stack else ("other",)
                module = stack.pop() if stack else ("other",)
                if module and module[0] == "const" and \
                        gname and gname[0] == "const":
                    record(module[1], gname[1], False)
                    stack.append(("global", module[1], gname[1]))
                else:
                    caps.append(
                        "a STACK_GLOBAL whose module and name are "
                        "not string constants in the stream, so "
                        "the callable it resolves cannot be named")
                    stack.append(("other",))
                continue
            if name == "MARK":
                stack.append(("mark",))
                continue
            if name in ("DICT", "LIST", "TUPLE", "SET"):
                pop_to_mark()
                stack.append(("other",))
                continue
            if name in ("EMPTY_DICT", "EMPTY_LIST", "EMPTY_TUPLE",
                        "EMPTY_SET"):
                stack.append(("other",))
                continue
            if name in ("TUPLE1",):
                if stack:
                    stack.pop()
                stack.append(("other",))
                continue
            if name in ("TUPLE2",):
                for _ in range(2):
                    if stack:
                        stack.pop()
                stack.append(("other",))
                continue
            if name in ("TUPLE3",):
                for _ in range(3):
                    if stack:
                        stack.pop()
                stack.append(("other",))
                continue
            if name == "SETITEM":
                for _ in range(2):
                    if stack:
                        stack.pop()
                continue
            if name in ("SETITEMS", "APPENDS", "ADDITEMS"):
                pop_to_mark()
                continue
            if name == "APPEND":
                if stack:
                    stack.pop()
                continue
            if name == "POP":
                if stack:
                    stack.pop()
                continue
            if name == "POP_MARK":
                pop_to_mark()
                continue
            if name == "DUP":
                stack.append(stack[-1] if stack else ("other",))
                continue
            if name in ("PUT", "BINPUT", "LONG_BINPUT"):
                try:
                    midx = int(arg)
                except Exception:
                    midx = len(memo)
                memo[midx] = stack[-1] if stack else ("other",)
                continue
            if name == "MEMOIZE":
                memo[len(memo)] = stack[-1] if stack \
                    else ("other",)
                continue
            if name in ("GET", "BINGET", "LONG_BINGET"):
                try:
                    midx = int(arg)
                except Exception:
                    midx = -1
                stack.append(memo.get(midx, ("other",)))
                continue
            if name == "REDUCE":
                if stack:
                    stack.pop()
                callee = stack.pop() if stack else ("other",)
                if callee and callee[0] == "global":
                    record(callee[1], callee[2], True)
                else:
                    caps.append(
                        "a REDUCE whose callable is not a named "
                        "global in the stream, so what it invokes "
                        "cannot be accounted")
                stack.append(("other",))
                continue
            if name == "INST":
                module, gname = _split_global(arg)
                record(module, gname, True)
                pop_to_mark()
                stack.append(("other",))
                continue
            if name == "OBJ":
                items = pop_to_mark()
                if items:
                    cls = items[-1]
                    if cls and cls[0] == "global":
                        record(cls[1], cls[2], True)
                    else:
                        caps.append(
                            "an OBJ whose class is not a named "
                            "global in the stream, so what it "
                            "instantiates cannot be accounted")
                stack.append(("other",))
                continue
            if name == "NEWOBJ":
                if stack:
                    stack.pop()
                cls = stack.pop() if stack else ("other",)
                if cls and cls[0] == "global":
                    record(cls[1], cls[2], True)
                else:
                    caps.append(
                        "a NEWOBJ whose class is not a named "
                        "global in the stream, so what it "
                        "constructs cannot be accounted")
                stack.append(("other",))
                continue
            if name == "NEWOBJ_EX":
                for _ in range(2):
                    if stack:
                        stack.pop()
                cls = stack.pop() if stack else ("other",)
                if cls and cls[0] == "global":
                    record(cls[1], cls[2], True)
                else:
                    caps.append(
                        "a NEWOBJ_EX whose class is not a named "
                        "global in the stream, so what it "
                        "constructs cannot be accounted")
                stack.append(("other",))
                continue
            if name in ("EXT1", "EXT2", "EXT4"):
                ext_codes.append(arg)
                stack.append(("other",))
                continue
            if name == "PERSID":
                persids.append(str(arg))
                stack.append(("persid", str(arg)))
                continue
            if name == "BINPERSID":
                if stack:
                    stack.pop()
                persids.append("<stack value>")
                stack.append(("persid", "<stack value>"))
                continue
            if name == "BUILD":
                if stack:
                    stack.pop()
                continue
            if name == "NEXT_BUFFER":
                oob = True
                stack.append(("other",))
                continue
            if name == "READONLY_BUFFER":
                continue
            caps.append(
                f"opcode {name} is not modelled by the pickle "
                f"walk, so the stream is unaccounted from that "
                f"instruction")
            break
    except Exception as ex:
        error = str(ex)
        match = re.search(r"at position (\d+)", error)
        if match:
            error_pos = int(match.group(1))

    if error_pos is None and error:
        _match = re.search(r"at position (\d+)", error)
        if _match:
            error_pos = int(_match.group(1))
    if claim in ("none", "soft") and \
            ((complete and opcodes_seen < 2) or
             (not complete and opcodes_seen < 4)):
        # A content or soft claim whose bytes fail as a pickle
        # almost immediately is not a pickle at all (a text file
        # whose first byte is an opcode value, a .pth path
        # listing beginning with a dot, which disassembles as a
        # lone STOP); the engine does not claim it.
        return None
    if claim == "strict" and opcodes_seen == 0 and not complete:
        return {"is_pickle": True, "complete": False,
                "callables": [], "persids": [],
                "trailing_bytes": 0, "stop_offset": error_pos,
                "error": error or "no pickle opcodes could be read",
                "chain": False, "accounted": False,
                "caps": ["the file claims to be a pickle stream "
                         "but no pickle opcode could be read from "
                         "it, so its content is unaccounted"]}
    if claim != "strict" and opcodes_seen == 0 and not complete:
        return None

    trailing = 0
    if complete and stop_end is not None:
        trailing = max(0, len(data) - stop_end)
    for entry in callables:
        if entry["tier"] == "dangerous" and entry["invoked"]:
            chain = True
    if not complete:
        where = f" at offset {error_pos}" if error_pos is not None \
            else ""
        caps.append(
            f"the pickle walk stopped{where} before the end of "
            f"the stream ({error or 'the stream ends without a STOP'}), "
            f"so the remainder is unaccounted")
    if ext_codes:
        caps.append(
            "the stream resolves callables through the extension "
            f"registry (codes {', '.join(str(c) for c in ext_codes)}), "
            "which cannot be resolved from the stream itself, so "
            "those callables are unaccounted")
    if oob:
        caps.append(
            "the stream reads protocol 5 out-of-band buffers, "
            "which travel outside the stream, so that data is "
            "unaccounted from the stream alone")
    for entry in callables:
        label = f"{entry['module']}.{entry['name']}"
        if entry["tier"] == "dangerous" and not entry["invoked"]:
            caps.append(
                f"the stream references the code-execution "
                f"callable {label} without invoking it in the "
                f"walk; a referenced callable is code the loader "
                f"receives, so it is unaccounted")
        elif entry["tier"] == "other":
            caps.append(
                f"the stream's callable {label} is outside the "
                f"reconstruction and data allowlist, so what it "
                f"does is unaccounted")
    if trailing and not persids:
        caps.append(
            f"{trailing} byte(s) follow the stream's STOP "
            f"opcode and are named by no persistent id, so they "
            f"are unaccounted")
    accounted = not chain and not caps
    return {"is_pickle": True, "complete": complete,
            "callables": callables, "persids": persids,
            "trailing_bytes": trailing,
            "stop_offset": error_pos, "error": error,
            "chain": chain, "accounted": accounted, "caps": caps}


def scan_embedded_pickles(data):
    """Naming-only scan for pickle streams stored inside a
    container the engine cannot enumerate (a failed 7z): find
    binary pickle headers and protocol 0 GLOBAL lines in the
    raw bytes and walk what is found, so a stored payload's
    callables are named on the container's record. The
    container's own cap is unchanged."""
    found = []
    starts = set()
    for match in re.finditer(rb"\x80[\x02-\x05]", data):
        starts.add(match.start())
    for match in re.finditer(rb"c[a-zA-Z0-9_.]+\n[a-zA-Z0-9_]+\n",
                             data):
        starts.add(match.start())
    for start in sorted(starts):
        result = analyze_pickle(data[start:start + 65536],
                                 claim="none")
        if result and result["callables"]:
            for entry in result["callables"]:
                label = f"{entry['module']}.{entry['name']}"
                if label not in found:
                    found.append(label)
    return found


# ------------------------------------------------------------------
# Safetensors accounting: the header is JSON, each tensor
# declares dtype, shape, and data_offsets into the payload that
# follows the header. The accounting checks the header against
# the file's actual extent.
# ------------------------------------------------------------------

def safetensors_header(data):
    if len(data) < 8:
        return None
    (size,) = struct.unpack("<Q", data[:8])
    if size <= 0 or size > 100_000_000 or 8 + size > len(data):
        return None
    try:
        header = json.loads(data[8:8 + size].decode("utf-8"))
    except Exception:
        return None
    if not isinstance(header, dict) or not header:
        return None
    for key, value in header.items():
        if key == "__metadata__":
            if not isinstance(value, dict):
                return None
            continue
        if not isinstance(value, dict) or \
                "data_offsets" not in value:
            return None
    return header


def is_safetensors(data):
    return safetensors_header(data) is not None


def safetensors_accounting(data):
    header = safetensors_header(data)
    if header is None:
        return None
    (size,) = struct.unpack("<Q", data[:8])
    payload = len(data) - 8 - size
    caps = []
    max_end = 0
    tensors = 0
    for key, value in header.items():
        if key == "__metadata__":
            continue
        tensors += 1
        offsets = value.get("data_offsets")
        if not isinstance(offsets, list) or len(offsets) != 2:
            caps.append(
                f"tensor {key!r} declares no readable "
                f"data_offsets, so its extent is unaccounted")
            continue
        start, end = offsets
        if not isinstance(start, int) or not isinstance(end, int) \
                or start < 0 or end < start or end > payload:
            caps.append(
                f"tensor {key!r} declares data_offsets "
                f"[{start}, {end}] against a payload of "
                f"{payload} byte(s), so the header disagrees "
                f"with the file's actual extent")
            continue
        max_end = max(max_end, end)
    trailing = payload - max_end
    if trailing > 0:
        caps.append(
            f"{trailing} payload byte(s) sit past the last "
            f"tensor's declared extent and are named by no "
            f"tensor, so they are unaccounted")
    return {"tensors": tensors, "payload_bytes": payload,
            "accounted": not caps, "caps": caps}


# ------------------------------------------------------------------
# ONNX accounting: a targeted protobuf walk. Fields are read
# generically (varint and length-delimited), then interpreted
# at the three levels the accounting needs: the model's graph,
# its nodes (op_type and domain), and its tensors (external
# data locations).
# ------------------------------------------------------------------

def _read_varint(buf, pos):
    result = 0
    shift = 0
    while pos < len(buf):
        byte = buf[pos]
        pos += 1
        result |= (byte & 0x7F) << shift
        if not byte & 0x80:
            return result, pos
        shift += 7
        if shift > 70:
            raise ValueError("varint too long")
    raise ValueError("truncated varint")


def _parse_fields(buf):
    fields = []
    pos = 0
    while pos < len(buf):
        tag, pos = _read_varint(buf, pos)
        number, wire = tag >> 3, tag & 7
        if number == 0:
            raise ValueError("field number 0")
        if wire == 0:
            value, pos = _read_varint(buf, pos)
            fields.append((number, wire, value))
        elif wire == 2:
            size, pos = _read_varint(buf, pos)
            if pos + size > len(buf):
                raise ValueError("length-delimited field overruns")
            fields.append((number, wire, buf[pos:pos + size]))
            pos += size
        elif wire == 1:
            if pos + 8 > len(buf):
                raise ValueError("truncated 64-bit field")
            fields.append((number, wire, buf[pos:pos + 8]))
            pos += 8
        elif wire == 5:
            if pos + 4 > len(buf):
                raise ValueError("truncated 32-bit field")
            fields.append((number, wire, buf[pos:pos + 4]))
            pos += 4
        else:
            raise ValueError(f"unsupported wire type {wire}")
    return fields


def _fields_of(buf, number):
    return [value for num, _wire, value in _parse_fields(buf)
            if num == number]


def onnx_accounting(data, entry_basenames=()):
    """Returns None when the bytes do not parse as protobuf at
    the model level at all; otherwise the accounting dict."""
    try:
        model_fields = _parse_fields(data)
    except Exception as ex:
        return {"parsed": False, "error": str(ex), "nodes": [],
                "external_refs": [], "accounted": False,
                "caps": [f"the ONNX protobuf walk failed "
                         f"({ex}), so the model's content is "
                         f"unaccounted"]}
    graphs = [v for n, w, v in model_fields if n == 7 and w == 2]
    if not graphs:
        return None
    nodes = []
    external_refs = []
    caps = []
    try:
        for graph in graphs:
            for node_buf in _fields_of(graph, 1):
                node = {"op_type": "", "domain": ""}
                for num, wire, value in _parse_fields(node_buf):
                    if wire != 2:
                        continue
                    if num == 4:
                        node["op_type"] = value.decode(
                            "utf-8", "replace")
                    elif num == 7:
                        node["domain"] = value.decode(
                            "utf-8", "replace")
                nodes.append(node)
            for tensor_buf in _fields_of(graph, 5):
                location = None
                data_location = 0
                for num, wire, value in _parse_fields(tensor_buf):
                    if num == 11 and wire == 0:
                        data_location = value
                    elif num == 9 and wire == 2:
                        entry = {}
                        for knum, kwire, kvalue in \
                                _parse_fields(value):
                            if kwire != 2:
                                continue
                            if knum == 1:
                                entry["key"] = kvalue.decode(
                                    "utf-8", "replace")
                            elif knum == 2:
                                entry["value"] = kvalue.decode(
                                    "utf-8", "replace")
                        if entry.get("key") == "location":
                            location = entry.get("value")
                if data_location == 1 or location:
                    external_refs.append(
                        location or "<unnamed external tensor>")
    except Exception as ex:
        return {"parsed": False, "error": str(ex), "nodes": nodes,
                "external_refs": external_refs, "accounted": False,
                "caps": [f"the ONNX protobuf walk failed "
                         f"({ex}), so the model's content is "
                         f"unaccounted"]}
    for node in nodes:
        if node["domain"]:
            caps.append(
                f"node {node['op_type'] or '<unnamed>'} runs in "
                f"the custom operator domain {node['domain']!r}, "
                f"whose implementation is a library outside "
                f"this submission, so the node is unaccounted")
    basenames = {str(b).lower() for b in entry_basenames}
    for ref in external_refs:
        base = ref.replace("\\", "/").rsplit("/", 1)[-1].lower()
        if base not in basenames:
            caps.append(
                f"a tensor's data lives in the external file "
                f"{ref!r}, which is not part of this "
                f"submission, so that tensor is unaccounted")
    return {"parsed": True, "nodes": nodes,
            "external_refs": external_refs,
            "accounted": not caps, "caps": caps}


# ------------------------------------------------------------------
# Keras Lambda layers: a Lambda layer's config carries a
# serialised Python function (marshal bytecode, base64-wrapped).
# It is code by design; the inventory names it as unaccounted
# code rather than reading it as configuration.
# ------------------------------------------------------------------

def keras_lambda_findings(data):
    try:
        text = data.decode("utf-8")
    except Exception:
        return []
    if '"Lambda"' not in text and "'Lambda'" not in text:
        return []
    try:
        doc = json.loads(text)
    except Exception:
        return []
    found = []

    def visit(node, path):
        if isinstance(node, dict):
            if node.get("class_name") == "Lambda":
                found.append(path or "Lambda layer")
            for key, value in node.items():
                visit(value, f"{path}/{key}" if path else key)
        elif isinstance(node, list):
            for idx, value in enumerate(node):
                visit(value, f"{path}[{idx}]")

    visit(doc, "")
    return found


# ------------------------------------------------------------------
# Clipboard and instruction accounting for HTML pages.
# ------------------------------------------------------------------

_CRADLE_PATTERNS = [
    r"downloadstring", r"downloadfile\s*\(", r"net\.webclient",
    r"invoke-expression", r"\biex\b", r"invoke-command",
    r"-encodedcommand", r"\s-enc\s", r"frombase64string",
    r"certutil[^\n]{0,80}-urlcache", r"bitsadmin[^\n]{0,80}/transfer",
    r"mshta\s+https?://", r"curl[^\n|]{0,120}\|\s*(sh|bash|powershell)",
    r"wget[^\n|]{0,120}\|\s*(sh|bash|powershell)",
    r"start-process[^\n]{0,120}https?://",
]
_CRADLE_RE = re.compile("|".join(_CRADLE_PATTERNS), re.IGNORECASE)

_STRONG_FRAMING = [
    "verify you are human", "complete the verification",
    "windows key + r", "win + r", "win+r", "run dialog",
    "press enter", "paste and press enter",
    "paste the code", "paste it into", "address bar",
    "i am not a robot", "i'm not a robot", "not a robot",
    "open file explorer and type", "press ctrl + v",
    "press ctrl+v",
]
_COMMAND_LIKE_RE = re.compile(
    r"\b(powershell|cmd|pwsh|mshta|rundll32|regsvr32|notepad|"
    r"calc|wscript|cscript|bash|sh|curl|wget)\b"
    r"|\.(exe|bat|cmd|ps1|vbs|js|sh)\b", re.IGNORECASE)


def _visible_text(html):
    text = re.sub(r"(?is)<(script|style)[^>]*>.*?</\1>", " ", html)
    text = re.sub(r"(?s)<[^>]+>", " ", text)
    return re.sub(r"\s+", " ", text)


def _resolve_clipboard_arg(html, arg):
    """Classify one writeText argument: literal content, a
    simple variable's literal, remote-assembled, or
    unresolvable."""
    arg = arg.strip()
    if not arg:
        return "unresolvable", None
    if arg[0] in "'\"`":
        quote = arg[0]
        end = arg.find(quote, 1)
        if end > 0:
            return "literal", arg[1:end]
        return "unresolvable", None
    if re.match(r"^[A-Za-z_$][\w$]*$", arg):
        assign = re.search(
            r"(?:var|let|const)?\s*" + re.escape(arg) +
            r"\s*=\s*(['\"`])(.*?)\1", html, re.DOTALL)
        if assign:
            return "literal", assign.group(2)
        fetch_assign = re.search(
            r"(?:var|let|const)?\s*" + re.escape(arg) +
            r"\s*=\s*[^;]{0,200}(fetch\s*\(|XMLHttpRequest)",
            html)
        if fetch_assign:
            return "remote", None
        return "unresolvable", None
    if "fetch(" in arg or "XMLHttpRequest" in arg:
        return "remote", None
    return "unresolvable", None


def clipboard_units(html):
    """Extract clipboard units and instruction framing from an
    HTML page's source. Each unit: its resolution, its literal
    content when resolved, and whether the content is a
    fetch-and-execute cradle."""
    units = []
    for match in re.finditer(
            r"navigator\.clipboard\.writeText\s*\(\s*", html):
        rest = html[match.end():match.end() + 1200]
        if rest[:1] in ("'", '"', "`"):
            # A quoted literal may itself contain parentheses
            # (a PowerShell cradle does), so the literal is
            # scanned to its closing quote, not to the first
            # close parenthesis.
            quote = rest[0]
            scan = 1
            while scan < len(rest):
                if rest[scan] == "\\":
                    scan += 2
                    continue
                if rest[scan] == quote:
                    break
                scan += 1
            units.append({"kind": "clipboard.writeText",
                          "resolution": "literal",
                          "content": rest[1:scan]})
            continue
        close = rest.find(")")
        arg = rest[:close] if close >= 0 else rest
        resolution, content = _resolve_clipboard_arg(html, arg)
        units.append({"kind": "clipboard.writeText",
                      "resolution": resolution,
                      "content": content})
    if re.search(r"fetch\s*\([^)]*\)\s*\.then\([^)]{0,300}?"
                 r"clipboard\.writeText", html, re.DOTALL):
        units.append({"kind": "clipboard.writeText",
                      "resolution": "remote", "content": None})
    if "execCommand" in html and \
            re.search(r"execCommand\s*\(\s*['\"]copy['\"]", html):
        for area in re.finditer(
                r"(?is)<textarea[^>]*>(.*?)</textarea>", html):
            units.append({"kind": "execCommand copy",
                          "resolution": "literal",
                          "content": area.group(1).strip()})
    visible = _visible_text(html)
    lowered = visible.lower()
    framing = "strong" if any(p in lowered for p in _STRONG_FRAMING) \
        else "none"
    in_text = []
    for match in _COMMAND_LIKE_RE.finditer(visible):
        start = max(0, match.start() - 20)
        snippet = visible[start:match.start() + 220]
        in_text.append(snippet)
    for unit in units:
        unit["cradle"] = bool(unit.get("content")) and \
            bool(_CRADLE_RE.search(unit["content"]))
    in_text_cradle = any(_CRADLE_RE.search(s) for s in in_text)
    return {"units": units, "framing": framing,
            "in_text_commands": in_text,
            "in_text_cradle": in_text_cradle}
