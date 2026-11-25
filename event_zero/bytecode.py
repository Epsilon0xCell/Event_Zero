"""Bytecode and managed-format accounting (coverage wave 2).

Parsers for the formats whose code is not native machine code and
not plain script source: Java class files and JARs, .NET assemblies
(metadata tables and IL method bodies), Android DEX bytecode and
binary AndroidManifest.xml, and Mach-O binaries (fat slicing, code
signature and entitlements).

Depth, stated exactly, per parser:

- Java: the constant pool is parsed completely (every entry typed),
  every method's Code attribute is walked opcode by opcode with the
  full JVM opcode table, and invoked methods, field references,
  string and class constants are resolved against the pool.
  invokedynamic call sites are resolved only when their bootstrap
  method is a known JDK factory (lambda metafactory, string concat
  factory); any other bootstrap is named unaccounted. No attempt is
  made to follow the operand stack, so a reflection target is
  resolved only when it is the string constant loaded immediately
  before the call in the same method.
- .NET: the CLR header, metadata root, all five heaps and every
  present metadata table are parsed (row schemas for all 45 tables),
  and every MethodDef body is walked opcode by opcode (one-byte and
  0xFE opcodes, tokens resolved to names). Embedded manifest
  resources are enumerated and judged as units (text as data, an
  embedded assembly by a recursive parse at depth 1, anything else
  named unaccounted). String decryption is not performed: a method
  whose shape is an encrypted string store (returns String, takes
  Int32, xors over a static byte array) is identified by shape, and
  every call site passing it an integer key is named as a string
  whose decrypted content is not in evidence.
- DEX: the header, string, type, proto, field and method id lists,
  class defs and class data are parsed completely, and every code
  item is walked with the full Dalvik opcode width table, resolving
  invoke, string, type and field references. No register dataflow is
  tracked: a dynamic-loading target is resolved only when it is a
  string constant loaded in the same method.
- AXML: the binary XML string pool (UTF-8 and UTF-16) and element
  tree are parsed; component elements and their android:name and
  android:exported attributes are extracted.
- Mach-O: fat headers are split into slices; each thin slice's load
  commands are walked; LC_CODE_SIGNATURE superblobs are parsed for
  the CodeDirectory (flags, identifier, team) and the entitlements
  blob (parsed as a plist). Cryptographic verification of the
  signature is not performed; the signature is inventoried.

Nothing in this module executes the analysed bytes.
"""
import io, os, plistlib, re, struct, zipfile

# ======================================================================
# Java class files
# ======================================================================

# JVM opcode table: opcode -> (mnemonic, operand kind). Operand
# kinds: "" none, "u1", "u2", "i1", "i2", "br2", "br4", "iinc"
# (u1 index + i1 constant), "inv" (invokeinterface and invokedynamic:
# u2 index + 2 bytes), "ma" (multianewarray: u2 + u1), "ts"
# (tableswitch), "ls" (lookupswitch), "wide".
_JVM = {}
def _jvm(ops, kind=""):
    for op, name in ops:
        _JVM[op] = (name, kind)
_jvm([(0x00, "nop"), (0x01, "aconst_null"), (0x02, "iconst_m1"), (0x03, "iconst_0"),
      (0x04, "iconst_1"), (0x05, "iconst_2"), (0x06, "iconst_3"), (0x07, "iconst_4"),
      (0x08, "iconst_5"), (0x09, "lconst_0"), (0x0a, "lconst_1"), (0x0b, "fconst_0"),
      (0x0c, "fconst_1"), (0x0d, "fconst_2"), (0x0e, "dconst_0"), (0x0f, "dconst_1")])
_jvm([(0x10, "bipush")], "i1")
_jvm([(0x11, "sipush")], "i2")
_jvm([(0x12, "ldc")], "u1")
_jvm([(0x13, "ldc_w"), (0x14, "ldc2_w")], "u2")
_jvm([(0x15, "iload"), (0x16, "lload"), (0x17, "fload"), (0x18, "dload"), (0x19, "aload")], "u1")
_jvm([(i, n) for i, n in enumerate(
    ["iload_0", "iload_1", "iload_2", "iload_3", "lload_0", "lload_1", "lload_2", "lload_3",
     "fload_0", "fload_1", "fload_2", "fload_3", "dload_0", "dload_1", "dload_2", "dload_3",
     "aload_0", "aload_1", "aload_2", "aload_3"], start=0x1a)])
_jvm([(i, n) for i, n in enumerate(
    ["iaload", "laload", "faload", "daload", "aaload", "baload", "caload", "saload"], start=0x2e)])
_jvm([(0x36, "istore"), (0x37, "lstore"), (0x38, "fstore"), (0x39, "dstore"), (0x3a, "astore")], "u1")
_jvm([(i, n) for i, n in enumerate(
    ["istore_0", "istore_1", "istore_2", "istore_3", "lstore_0", "lstore_1", "lstore_2", "lstore_3",
     "fstore_0", "fstore_1", "fstore_2", "fstore_3", "dstore_0", "dstore_1", "dstore_2", "dstore_3",
     "astore_0", "astore_1", "astore_2", "astore_3"], start=0x3b)])
_jvm([(i, n) for i, n in enumerate(
    ["iastore", "lastore", "fastore", "dastore", "aastore", "bastore", "castore", "sastore",
     "pop", "pop2", "dup", "dup_x1", "dup_x2", "dup2", "dup2_x1", "dup2_x2", "swap",
     "iadd", "ladd", "fadd", "dadd", "isub", "lsub", "fsub", "dsub", "imul", "lmul", "fmul", "dmul",
     "idiv", "ldiv", "fdiv", "ddiv", "irem", "lrem", "frem", "drem", "ineg", "lneg", "fneg", "dneg",
     "ishl", "lshl", "ishr", "lshr", "iushr", "lushr", "iand", "land", "ior", "lor"], start=0x4f)])
_jvm([(0x82, "iinc")], "iinc")
_jvm([(i, n) for i, n in enumerate(
    ["ixor", "lxor", "i2l", "i2f", "i2d", "l2i", "l2f", "l2d", "f2i", "f2l", "f2d",
     "d2i", "d2l", "d2f", "i2b", "i2c", "i2s"], start=0x83)])
_jvm([(i, n) for i, n in enumerate(
    ["lcmp", "fcmpl", "fcmpg", "dcmpl", "dcmpg"], start=0x94)])
_jvm([(i, n) for i, n in enumerate(
    ["ifeq", "ifne", "iflt", "ifge", "ifgt", "ifle", "if_icmpeq", "if_icmpne", "if_icmplt",
     "if_icmpge", "if_icmpgt", "if_icmple", "if_acmpeq", "if_acmpne", "goto", "jsr"], start=0x99)], "br2")
_jvm([(0xa9, "ret")], "u1")
_JVM[0xaa] = ("tableswitch", "ts")
_JVM[0xab] = ("lookupswitch", "ls")
_jvm([(i, n) for i, n in enumerate(
    ["ireturn", "lreturn", "freturn", "dreturn", "areturn", "return"], start=0xac)])
_jvm([(0xb2, "getstatic"), (0xb3, "putstatic"), (0xb4, "getfield"), (0xb5, "putfield"),
      (0xb6, "invokevirtual"), (0xb7, "invokespecial"), (0xb8, "invokestatic")], "u2")
_jvm([(0xb9, "invokeinterface"), (0xba, "invokedynamic")], "inv")
_jvm([(0xbb, "new")], "u2")
_jvm([(0xbc, "newarray")], "u1")
_jvm([(0xbd, "anewarray")], "u2")
_jvm([(0xbe, "arraylength"), (0xbf, "athrow")])
_jvm([(0xc0, "checkcast"), (0xc1, "instanceof")], "u2")
_jvm([(0xc2, "monitorenter"), (0xc3, "monitorexit")])
_JVM[0xc4] = ("wide", "wide")
_JVM[0xc5] = ("multianewarray", "ma")
_jvm([(0xc6, "ifnull"), (0xc7, "ifnonnull")], "br2")
_jvm([(0xc8, "goto_w"), (0xc9, "jsr_w")], "br4")

_JAVA_FETCH = {
    ("java/net/URL", "openStream"), ("java/net/URL", "openConnection"),
    ("java/net/URLConnection", "getInputStream"), ("java/net/HttpURLConnection", "getInputStream"),
    ("java/net/Socket", "<init>"),
}
_JAVA_EXEC = {
    ("java/lang/Runtime", "exec"), ("java/lang/ProcessBuilder", "start"),
    ("java/lang/ProcessBuilder", "<init>"),
}
_JAVA_DYNAMIC = {
    ("java/lang/Class", "forName"), ("java/lang/ClassLoader", "loadClass"),
    ("java/lang/reflect/Method", "invoke"),
    ("java/lang/Class", "newInstance"), ("java/lang/reflect/Constructor", "newInstance"),
    ("java/lang/ClassLoader", "defineClass"),
}
_JAVA_PLATFORM_PREFIXES = ("java/", "javax/", "jdk/", "sun/", "com/sun/", "kotlin/", "scala/")


class _Reader:
    def __init__(self, data):
        self.d = data
        self.i = 0
    def take(self, n):
        if self.i + n > len(self.d):
            raise ValueError(f"read of {n} bytes at offset {self.i} runs past the end of the file ({len(self.d)} bytes)")
        out = self.d[self.i:self.i + n]
        self.i += n
        return out
    def u1(self):
        return self.take(1)[0]
    def u2(self):
        return struct.unpack(">H", self.take(2))[0]
    def u4(self):
        return struct.unpack(">I", self.take(4))[0]


def is_java_class(data):
    if len(data) < 8 or data[:4] != b"\xca\xfe\xba\xbe":
        return False
    major = struct.unpack(">H", data[6:8])[0]
    return 45 <= major <= 99


def parse_class_file(data, known_classes=()):
    """Parse one Java class file completely. Returns a dict with
    parsed=False and an error string when the file cannot be read to
    the bottom; the caller turns that into a cap by name."""
    out = {"is_class": False, "parsed": False, "error": None}
    if not is_java_class(data):
        out["error"] = "not a Java class file (bad magic or version)"
        return out
    out["is_class"] = True
    r = _Reader(data)
    try:
        r.u4()
        out["minor"] = r.u2()
        out["major"] = r.u2()
        cp_count = r.u2()
        cp = [None] * cp_count
        i = 1
        while i < cp_count:
            tag = r.u1()
            if tag == 1:
                n = r.u2()
                cp[i] = ("Utf8", r.take(n).decode("utf-8", "replace"))
            elif tag == 3:
                cp[i] = ("Integer", r.u4())
            elif tag == 4:
                cp[i] = ("Float", r.u4())
            elif tag == 5:
                cp[i] = ("Long", (r.u4(), r.u4()))
                i += 1
            elif tag == 6:
                cp[i] = ("Double", (r.u4(), r.u4()))
                i += 1
            elif tag == 7:
                cp[i] = ("Class", r.u2())
            elif tag == 8:
                cp[i] = ("String", r.u2())
            elif tag in (9, 10, 11):
                cp[i] = (("Fieldref", "Methodref", "InterfaceMethodref")[tag - 9], r.u2(), r.u2())
            elif tag == 12:
                cp[i] = ("NameAndType", r.u2(), r.u2())
            elif tag == 15:
                cp[i] = ("MethodHandle", r.u1(), r.u2())
            elif tag == 16:
                cp[i] = ("MethodType", r.u2())
            elif tag == 17:
                cp[i] = ("Dynamic", r.u2(), r.u2())
            elif tag == 18:
                cp[i] = ("InvokeDynamic", r.u2(), r.u2())
            elif tag == 19:
                cp[i] = ("Module", r.u2())
            elif tag == 20:
                cp[i] = ("Package", r.u2())
            else:
                raise ValueError(f"unknown constant pool tag {tag} at entry {i}")
            i += 1
    except ValueError as e:
        out["error"] = f"constant pool could not be parsed: {e}"
        return out

    def utf(idx):
        e = cp[idx] if 0 < idx < len(cp) else None
        return e[1] if e and e[0] == "Utf8" else None
    def cls_name(idx):
        e = cp[idx] if 0 < idx < len(cp) else None
        return utf(e[1]) if e and e[0] == "Class" else None
    def ref_parts(idx):
        e = cp[idx] if 0 < idx < len(cp) else None
        if not e or e[0] not in ("Fieldref", "Methodref", "InterfaceMethodref"):
            return None
        nt = cp[e[2]] if 0 < e[2] < len(cp) else None
        return (cls_name(e[1]), utf(nt[1]) if nt else None, utf(nt[2]) if nt else None)

    out["cp_classes"] = sorted({cls_name(i) for i in range(1, len(cp))
                                if cp[i] and cp[i][0] == "Class" and cls_name(i)})
    out["cp_strings"] = sorted({utf(cp[i][1]) for i in range(1, len(cp))
                                if cp[i] and cp[i][0] == "String" and utf(cp[i][1]) is not None})
    try:
        out["access_flags"] = r.u2()
        _this = cls_name(r.u2())
        # Presented dotted, the way JAR manifests and the verdict's
        # entry-point reconciliation name classes; the constant pool
        # lists (cp_classes) stay in JVM internal form, which is
        # what the findings resolver compares against.
        out["this_class"] = _this.replace("/", ".") if _this else _this
        out["super_class"] = cls_name(r.u2())
        n_iface = r.u2()
        out["interfaces"] = [cls_name(r.u2()) for _ in range(n_iface)]
        fields = []
        for _ in range(r.u2()):
            fa = r.u2()
            fname, fdesc = utf(r.u2()), utf(r.u2())
            for _a in range(r.u2()):
                r.u2()
                r.take(r.u4())
            fields.append({"name": fname, "descriptor": fdesc, "access": fa})
        out["fields"] = fields
        methods = []
        bootstrap_methods = []
        for _ in range(r.u2()):
            ma = r.u2()
            mname, mdesc = utf(r.u2()), utf(r.u2())
            method = {"name": mname, "descriptor": mdesc, "access": ma,
                      "instructions": [], "invokes": [], "ldc_strings": [],
                      "ldc_classes": [], "decoded": False, "code_bytes": 0}
            for _a in range(r.u2()):
                aname = utf(r.u2())
                alen = r.u4()
                abody = r.take(alen)
                if aname == "Code":
                    method.update(_parse_jvm_code(abody, cp, utf, cls_name, ref_parts))
            methods.append(method)
        out["methods"] = methods
        for _a in range(r.u2()):
            aname = utf(r.u2())
            alen = r.u4()
            abody = r.take(alen)
            if aname == "BootstrapMethods":
                br = _Reader(abody)
                for _b in range(br.u2()):
                    ref = br.u2()
                    args = [br.u2() for _ in range(br.u2())]
                    parts = ref_parts(ref)
                    bootstrap_methods.append({"method": parts, "args": args})
        out["bootstrap_methods"] = bootstrap_methods
    except ValueError as e:
        out["error"] = f"class file could not be parsed to the bottom: {e}"
        return out
    out["parsed"] = True
    _java_findings(out, known_classes)
    return out


def _parse_jvm_code(body, cp, utf, cls_name, ref_parts):
    r = _Reader(body)
    res = {"instructions": [], "invokes": [], "ldc_strings": [], "ldc_classes": [],
           "decoded": False, "code_bytes": 0}
    r.u2()  # max_stack
    r.u2()  # max_locals
    code_len = r.u4()
    code_start = r.i
    code = r.take(code_len)
    res["code_bytes"] = code_len
    pc = 0
    last_ldc = None
    while pc < len(code):
        op = code[pc]
        entry = _JVM.get(op)
        if entry is None:
            res["decode_error"] = f"unknown opcode {hex(op)} at code offset {pc}"
            return res
        name, kind = entry
        ins = {"pc": pc, "op": name}
        adv = 1
        try:
            if kind == "u1":
                ins["index"] = code[pc + 1]
                adv = 2
                if name in ("ldc",):
                    ins["ldc"] = _cp_value(cp, code[pc + 1], utf, cls_name)
            elif kind == "u2" or kind == "br2":
                ins["index"] = struct.unpack(">H", code[pc + 1:pc + 3])[0]
                adv = 3
                if name in ("ldc_w", "ldc2_w"):
                    ins["ldc"] = _cp_value(cp, ins["index"], utf, cls_name)
            elif kind == "i1":
                adv = 2
            elif kind == "i2" or kind == "br4":
                adv = 3 if kind == "i2" else 5
            elif kind == "iinc":
                adv = 3
            elif kind == "inv":
                ins["index"] = struct.unpack(">H", code[pc + 1:pc + 3])[0]
                adv = 5
            elif kind == "ma":
                ins["index"] = struct.unpack(">H", code[pc + 1:pc + 3])[0]
                adv = 4
            elif kind == "ts":
                pad = (4 - ((pc + 1) % 4)) % 4
                base = pc + 1 + pad
                _def, low, high = struct.unpack(">iii", code[base:base + 12])
                adv = 1 + pad + 12 + 4 * (high - low + 1)
            elif kind == "ls":
                pad = (4 - ((pc + 1) % 4)) % 4
                base = pc + 1 + pad
                npairs = struct.unpack(">i", code[base + 4:base + 8])[0]
                adv = 1 + pad + 8 + 8 * npairs
            elif kind == "wide":
                op2 = code[pc + 1]
                adv = 6 if op2 == 0x82 else 4  # wide iinc is longer
            if pc + adv > len(code):
                res["decode_error"] = f"instruction {name} at code offset {pc} runs past the end of the code array"
                return res
        except IndexError:
            res["decode_error"] = f"instruction {name} at code offset {pc} is truncated"
            return res
        if name in ("ldc", "ldc_w", "ldc2_w") and "ldc" in ins:
            last_ldc = ins["ldc"]
            if isinstance(ins["ldc"], tuple) and ins["ldc"][0] == "string":
                res["ldc_strings"].append(ins["ldc"][1])
            if isinstance(ins["ldc"], tuple) and ins["ldc"][0] == "class":
                res["ldc_classes"].append(ins["ldc"][1])
        if name in ("invokevirtual", "invokespecial", "invokestatic", "invokeinterface"):
            parts = ref_parts(ins.get("index", 0))
            if parts:
                res["invokes"].append({"class": parts[0], "name": parts[1],
                                       "descriptor": parts[2], "kind": name,
                                       "preceding_ldc": last_ldc})
        if name == "invokedynamic":
            e = cp[ins.get("index", 0)] if 0 < ins.get("index", 0) < len(cp) else None
            nt = cp[e[2]] if e and e[0] == "InvokeDynamic" and 0 < e[2] < len(cp) else None
            res.setdefault("invokedynamic", []).append(
                {"name": utf(nt[1]) if nt else None, "descriptor": utf(nt[2]) if nt else None,
                 "bootstrap_index": e[1] if e else None})
        res["instructions"].append(ins)
        pc += adv
    res["decoded"] = True
    return res


def _cp_value(cp, idx, utf, cls_name):
    e = cp[idx] if 0 < idx < len(cp) else None
    if not e:
        return None
    if e[0] == "String":
        return ("string", utf(e[1]))
    if e[0] == "Class":
        return ("class", cls_name(idx))
    if e[0] == "Integer":
        return ("int", e[1])
    return (e[0].lower(), None)


_KNOWN_BOOTSTRAPS = {
    ("java/lang/invoke/LambdaMetafactory", "metafactory"),
    ("java/lang/invoke/LambdaMetafactory", "altMetafactory"),
    ("java/lang/invoke/StringConcatFactory", "makeConcat"),
    ("java/lang/invoke/StringConcatFactory", "makeConcatWithConstants"),
}


def _java_findings(out, known_classes=()):
    # Known classes arrive in both spellings: constant pool entries
    # and load targets are JVM internal form (com/example/Foo),
    # while this_class and the verdict pre-pass present dotted form
    # (com.example.Foo). Normalise every entry to both spellings so
    # the comparison below cannot miss on spelling alone.
    known = set()
    for _k in set(known_classes) | set(out.get("cp_classes") or []) | {out.get("this_class")}:
        if _k:
            known.add(str(_k))
            known.add(str(_k).replace(".", "/"))
    unaccounted = []
    references = []
    chains = []
    dyn_sites = []
    for s in out.get("cp_strings") or []:
        if re.match(r"(?:https?|ftp)://", s or ""):
            references.append({"kind": "java-constant-url", "target": s,
                               "source": "Java constant pool string"})
    fetch_methods = []
    exec_methods = []
    remote_loader = False
    for m in out.get("methods") or []:
        if not m.get("decoded"):
            unaccounted.append(f"method {m.get('name')}{m.get('descriptor')} could not be decoded to the bottom"
                               + (f" ({m['decode_error']})" if m.get("decode_error") else ""))
            continue
        for inv in m.get("invokes") or []:
            key = (inv.get("class"), inv.get("name"))
            if key in _JAVA_FETCH:
                fetch_methods.append(f"{inv['class']}.{inv['name']} in method {m['name']}")
            if key in _JAVA_EXEC:
                exec_methods.append(f"{inv['class']}.{inv['name']} in method {m['name']}")
            if inv.get("class") == "java/net/URLClassLoader":
                remote_loader = True
            if key in _JAVA_DYNAMIC:
                target = None
                ldc = inv.get("preceding_ldc")
                if isinstance(ldc, tuple) and ldc[0] == "string":
                    target = ldc[1]
                if isinstance(ldc, tuple) and ldc[0] == "class":
                    target = ldc[1]
                dyn_sites.append({"site": f"{inv['class']}.{inv['name']}", "method": m["name"],
                                  "target": target})
                if target is None:
                    unaccounted.append(
                        f"method {m['name']} calls {inv['class']}.{inv['name']} with a target that is not a "
                        "string or class constant loaded immediately before the call in the same method, so the "
                        "dynamically loaded or invoked code is not identified in the file")
                else:
                    internal = str(target).replace(".", "/")
                    if internal in known or any(internal.startswith(p) for p in _JAVA_PLATFORM_PREFIXES):
                        pass  # resolved: examined here or a platform class
                    else:
                        unaccounted.append(
                            f"method {m['name']} dynamically loads or invokes {target} through "
                            f"{inv['class']}.{inv['name']}, and that class is not part of this submission, "
                            "so the loaded code is unaccounted")
        for dyn in m.get("invokedynamic") or []:
            boots = out.get("bootstrap_methods") or []
            b = boots[dyn["bootstrap_index"]] if dyn.get("bootstrap_index") is not None and dyn["bootstrap_index"] < len(boots) else None
            bparts = b["method"] if b else None
            if bparts and (bparts[0], bparts[1]) in _KNOWN_BOOTSTRAPS:
                continue
            unaccounted.append(
                f"method {m['name']} has an invokedynamic call site ({dyn.get('name')}) whose bootstrap method "
                f"is {bparts[0] + '.' + bparts[1] if bparts else 'not present in this file'}, not a known JDK "
                "factory, so what the call site links to at run time is unaccounted")
    if fetch_methods and exec_methods:
        chains.append({"chain": "bytecode-fetch-execute",
                       "name": "This Java class both fetches remote content and executes code: the fetch and the execution are both proven in its bytecode",
                       "evidence": [f"fetch: {fetch_methods[0]}", f"execute: {exec_methods[0]}"]})
    if remote_loader:
        urls = [s for s in out.get("cp_strings") or [] if re.match(r"https?://", s or "")]
        if urls:
            unaccounted.append(
                f"this class builds a URLClassLoader over the remote code source {urls[0]}, and code loaded "
                "from that source at run time is not part of this submission, so the loaded code is unaccounted")
            chains.append({"chain": "bytecode-remote-code-loading",
                           "name": "This Java class builds a URLClassLoader over a remote URL and loads classes through it: the loaded code is fetched at run time and is not in this file",
                           "evidence": [f"remote code source: {urls[0]}",
                                        "URLClassLoader use proven in the constant pool references"]})
    out["references"] = references
    out["dynamic_sites"] = dyn_sites
    out["unaccounted_items"] = unaccounted
    out["chains"] = chains
    out["accounted"] = bool(out.get("parsed")) and not unaccounted and \
        all(m.get("decoded") for m in out.get("methods") or [])


def parse_jar(data):
    """JAR accounting: manifest, signer inventory, member classes.
    The members themselves are verdict units through the ordinary
    zip expansion; this reads the JAR-level structures."""
    out = {"is_jar": False, "parsed": False, "error": None}
    if not zipfile.is_zipfile(io.BytesIO(data)):
        out["error"] = "not a zip archive"
        return out
    try:
        z = zipfile.ZipFile(io.BytesIO(data))
        names = z.namelist()
    except Exception as e:
        out["error"] = f"the archive could not be opened: {e}"
        return out
    out["is_jar"] = True
    out["members"] = names
    out["class_members"] = [n for n in names if n.lower().endswith(".class")]
    out["nested_jars"] = [n for n in names if n.lower().endswith((".jar", ".war", ".ear", ".zip"))]
    manifest = {}
    raw = None
    for n in names:
        if n.upper() == "META-INF/MANIFEST.MF":
            raw = z.read(n)
            break
    if raw is not None:
        text = raw.decode("utf-8", "replace")
        unfolded = []
        for line in text.replace("\r\n", "\n").split("\n"):
            if line.startswith(" ") and unfolded:
                unfolded[-1] += line[1:]
            else:
                unfolded.append(line)
        section = manifest
        for line in unfolded:
            if not line.strip():
                section = {}
                continue
            if ": " in line:
                k, v = line.split(": ", 1)
                section[k.strip()] = v.strip()
        out["manifest"] = manifest
    else:
        out["manifest"] = {}
    out["main_class"] = manifest.get("Main-Class")
    cp = manifest.get("Class-Path")
    out["class_path"] = cp.split() if cp else []
    signers = []
    for n in names:
        up = n.upper()
        if up.startswith("META-INF/") and up.endswith(".SF"):
            base = up[:-3]
            block = next((m for m in names if m.upper().startswith(base + ".")
                          and m.upper().rsplit(".", 1)[-1] in ("RSA", "DSA", "EC")), None)
            sf_text = z.read(n).decode("utf-8", "replace")
            signers.append({"signature_file": n, "signature_block": block,
                            "has_block": block is not None,
                            "digest_algorithms": sorted(set(re.findall(r"(SHA-?\d+|MD5)", sf_text)))})
    out["signers"] = signers
    out["parsed"] = True
    return out

# ======================================================================
# .NET assemblies: metadata tables and IL
# ======================================================================

_CODED = {
    "TypeDefOrRef": ([2, 1, 27], 2), "HasConstant": ([4, 8, 23], 2),
    "HasCustomAttribute": ([6, 4, 1, 2, 8, 9, 10, 0, 14, 23, 20, 17, 26, 27, 32, 35, 38, 39, 40, 42, 44, 43], 5),
    "HasFieldMarshal": ([4, 8], 1), "HasDeclSecurity": ([2, 6, 32], 2),
    "MemberRefParent": ([2, 1, 26, 6, 27], 3), "HasSemantics": ([20, 23], 1),
    "MethodDefOrRef": ([6, 10], 1), "MemberForwarded": ([4, 6], 1),
    "Implementation": ([38, 35, 39], 2),
    "CustomAttributeType": ([None, None, 6, 10, None], 3),
    "ResolutionScope": ([0, 26, 35, 1], 2), "TypeOrMethodDef": ([2, 6], 1),
}
# Row schemas: column kinds "u2", "u4", "str", "guid", "blob",
# ("i", table) simple index, ("c", coded-name) coded index.
_SCHEMAS = {
    0: ["u2", "str", "guid", "guid", "guid"],
    1: [("c", "ResolutionScope"), "str", "str"],
    2: ["u4", "str", "str", ("c", "TypeDefOrRef"), ("i", 4), ("i", 6)],
    3: [("i", 4)],
    4: ["u2", "str", "blob"],
    5: [("i", 6)],
    6: ["u4", "u2", "u2", "str", "blob", ("i", 8)],
    7: [("i", 8)],
    8: ["u2", "u2", "str"],
    9: [("i", 2), ("c", "TypeDefOrRef")],
    10: [("c", "MemberRefParent"), "str", "blob"],
    11: ["u2", ("c", "HasConstant"), "blob"],
    12: [("c", "HasCustomAttribute"), ("c", "CustomAttributeType"), "blob"],
    13: [("c", "HasFieldMarshal"), "blob"],
    14: ["u2", ("c", "HasDeclSecurity"), "blob"],
    15: ["u2", "u4", ("i", 2)],
    16: ["u4", ("i", 4)],
    17: ["blob"],
    18: [("i", 2), ("i", 20)],
    19: [("i", 20)],
    20: ["u2", "str", ("c", "TypeDefOrRef")],
    21: [("i", 2), ("i", 23)],
    22: [("i", 23)],
    23: ["u2", "str", "blob"],
    24: ["u2", ("c", "HasSemantics"), ("i", 6)],
    25: [("i", 2), ("c", "MethodDefOrRef"), ("c", "MethodDefOrRef")],
    26: ["str"],
    27: ["blob"],
    28: ["u2", ("c", "MemberForwarded"), "str", ("i", 26)],
    29: ["u4", ("i", 4)],
    30: ["u4", "u4"],
    31: ["u4"],
    32: ["u4", "u2", "u2", "u2", "u2", "u4", "blob", "str", "str"],
    33: ["u4"],
    34: ["u4", "u4", "u4"],
    35: ["u2", "u2", "u2", "u2", "u4", "blob", "str", "str", "blob"],
    36: ["u4", ("i", 35)],
    37: ["u4", "u4", "u4", ("i", 35)],
    38: ["u4", "str", "blob"],
    39: ["u4", "u4", "str", "str", ("c", "Implementation")],
    40: ["u4", "u4", "str", ("c", "Implementation")],
    41: [("i", 2), ("i", 2)],
    42: ["u2", "u2", ("c", "TypeOrMethodDef"), "str"],
    43: [("c", "MethodDefOrRef"), "blob"],
    44: [("i", 42), ("c", "TypeDefOrRef")],
}
# IL operand kinds: byte widths, with "switch" and "token" special.
_IL_NONE = 0
_IL_OPS = {}
def _il(ops, kind):
    for op, name in ops:
        _IL_OPS[op] = (name, kind)
_il([(0x00, "nop"), (0x01, "break"), (0x02, "ldarg.0"), (0x03, "ldarg.1"), (0x04, "ldarg.2"),
     (0x05, "ldarg.3"), (0x06, "ldloc.0"), (0x07, "ldloc.1"), (0x08, "ldloc.2"), (0x09, "ldloc.3"),
     (0x0a, "stloc.0"), (0x0b, "stloc.1"), (0x0c, "stloc.2"), (0x0d, "stloc.3"),
     (0x14, "ldnull"), (0x15, "ldc.i4.m1"), (0x16, "ldc.i4.0"), (0x17, "ldc.i4.1"),
     (0x18, "ldc.i4.2"), (0x19, "ldc.i4.3"), (0x1a, "ldc.i4.4"), (0x1b, "ldc.i4.5"),
     (0x1c, "ldc.i4.6"), (0x1d, "ldc.i4.7"), (0x1e, "ldc.i4.8"), (0x25, "dup"), (0x26, "pop"),
     (0x2a, "ret"), (0x46, "ldind.i1"), (0x47, "ldind.u1"), (0x48, "ldind.i2"), (0x49, "ldind.u2"),
     (0x4a, "ldind.i4"), (0x4b, "ldind.u4"), (0x4c, "ldind.i8"), (0x4d, "ldind.r4"),
     (0x4e, "ldind.r8"), (0x4f, "ldind.i"), (0x50, "ldind.ref"), (0x51, "stind.ref"),
     (0x52, "stind.i1"), (0x53, "stind.i2"), (0x54, "stind.i4"), (0x55, "stind.i8"),
     (0x56, "stind.r4"), (0x57, "stind.r8"), (0x58, "add"), (0x59, "sub"), (0x5a, "mul"),
     (0x5b, "div"), (0x5c, "div.un"), (0x5d, "rem"), (0x5e, "rem.un"), (0x5f, "and"),
     (0x60, "or"), (0x61, "xor"), (0x62, "shl"), (0x63, "shr"), (0x64, "shr.un"),
     (0x65, "neg"), (0x66, "not"), (0x67, "conv.i1"), (0x68, "conv.i2"), (0x69, "conv.i4"),
     (0x6a, "conv.i8"), (0x6b, "conv.r4"), (0x6c, "conv.r8"), (0x6d, "conv.u4"),
     (0x6e, "conv.u8"), (0x76, "conv.r.un"), (0x7a, "throw"), (0x8e, "ldlen"),
     (0x90, "ldelem.i1"), (0x91, "ldelem.u1"), (0x92, "ldelem.i2"), (0x93, "ldelem.u2"),
     (0x94, "ldelem.i4"), (0x95, "ldelem.u4"), (0x96, "ldelem.i8"), (0x97, "ldelem.i"),
     (0x98, "ldelem.r4"), (0x99, "ldelem.r8"), (0x9a, "ldelem.ref"), (0x9b, "stelem.i"),
     (0x9c, "stelem.i1"), (0x9d, "stelem.i2"), (0x9e, "stelem.i4"), (0x9f, "stelem.i8"),
     (0xa0, "stelem.r4"), (0xa1, "stelem.r8"), (0xa2, "stelem.ref"), (0xb0, "conv.ovf.i1"),
     (0xb1, "conv.u1"), (0xb2, "conv.ovf.i2"), (0xb3, "conv.u2"), (0xb4, "conv.ovf.i4"),
     (0xb5, "conv.u4"), (0xb6, "conv.ovf.i8"), (0xb7, "conv.u8"), (0xc3, "ckfinite"),
     (0xd1, "conv.u2"), (0xd2, "conv.u1"), (0xd3, "conv.i"), (0xd4, "conv.ovf.i"),
     (0xd5, "conv.ovf.u"), (0xd6, "add.ovf"), (0xd7, "add.ovf.un"), (0xd8, "mul.ovf"),
     (0xd9, "mul.ovf.un"), (0xda, "sub.ovf"), (0xdb, "sub.ovf.un"), (0xdc, "endfinally"),
     (0xdf, "stind.i"), (0xe0, "conv.u")], "none")
_il([(0x0e, "ldarg.s"), (0x0f, "ldarga.s"), (0x10, "starg.s"), (0x11, "ldloc.s"),
     (0x12, "ldloca.s"), (0x13, "stloc.s"), (0x1f, "ldc.i4.s")], "i1")
_il([(0x2b, "br.s"), (0x2c, "brfalse.s"), (0x2d, "brtrue.s"), (0x2e, "beq.s"), (0x2f, "bge.s"),
     (0x30, "bgt.s"), (0x31, "ble.s"), (0x32, "blt.s"), (0x33, "bne.un.s"), (0x34, "bge.un.s"),
     (0x35, "bgt.un.s"), (0x36, "ble.un.s"), (0x37, "blt.un.s"), (0xde, "leave.s")], "br1")
_il([(0x09 - 0x09 + 0xfe09, "ldarg")], "var2")  # placeholder removed below
_IL_OPS.pop(0xfe09, None)
_il([(0x20, "ldc.i4")], "i4")
_il([(0x21, "ldc.i8")], "i8")
_il([(0x22, "ldc.r4")], "r4")
_il([(0x23, "ldc.r8")], "r8")
_il([(0x27, "jmp")], "method")
_il([(0x28, "call"), (0x6f, "callvirt"), (0x73, "newobj")], "method")
_il([(0x29, "calli")], "sig")
_il([(0x38, "br"), (0x39, "brfalse"), (0x3a, "brtrue"), (0x3b, "beq"), (0x3c, "bge"),
     (0x3d, "bgt"), (0x3e, "ble"), (0x3f, "blt"), (0x40, "bne.un"), (0x41, "bge.un"),
     (0x42, "bgt.un"), (0x43, "ble.un"), (0x44, "blt.un"), (0xdd, "leave")], "br4")
_IL_OPS[0x45] = ("switch", "switch")
_il([(0x70, "cpobj"), (0x71, "ldobj"), (0x74, "castclass"), (0x75, "isinst"), (0x79, "unbox"),
     (0x81, "stobj"), (0x8c, "box"), (0x8d, "newarr"), (0x8f, "ldelema"), (0xa3, "ldelem"),
     (0xa4, "stelem"), (0xa5, "unbox.any"), (0xc2, "refanyval"), (0xc6, "mkrefany")], "type")
_il([(0x72, "ldstr")], "string")
_il([(0x7b, "ldfld"), (0x7c, "ldflda"), (0x7d, "stfld"), (0x7e, "ldsfld"),
     (0x7f, "ldsflda"), (0x80, "stsfld")], "field")
_il([(0xd0, "ldtoken")], "tok")
_IL_OPS2 = {}
def _il2(ops, kind):
    for op, name in ops:
        _IL_OPS2[op] = (name, kind)
_il2([(0x00, "arglist"), (0x01, "ceq"), (0x02, "cgt"), (0x03, "cgt.un"), (0x04, "clt"),
      (0x05, "clt.un"), (0x11, "endfilter"), (0x13, "volatile."), (0x14, "tail."),
      (0x17, "readonly."), (0x18, "rethrow"), (0x1a, "refanytype")], "none")
_il2([(0x06, "ldftn"), (0x07, "ldvirtftn")], "method")
_il2([(0x09, "ldarg"), (0x0a, "ldarga"), (0x0b, "starg"), (0x0c, "ldloc"),
      (0x0d, "ldloca"), (0x0e, "stloc")], "var2")
_il2([(0x0f, "localloc"), (0x19, "endfilter-unused")], "none")
_IL_OPS2.pop(0x19, None)
_il2([(0x12, "unaligned.")], "i1")
_il2([(0x15, "initobj"), (0x16, "constrained."), (0x1c, "sizeof")], "type")
_IL_OPS2[0x0f] = ("localloc", "none")
_IL_KIND_SIZE = {"none": 0, "i1": 1, "br1": 1, "var2": 2, "i4": 4, "br4": 4, "r4": 4,
                 "i8": 8, "r8": 8, "string": 4, "method": 4, "field": 4, "type": 4,
                 "sig": 4, "tok": 4}

_DOTNET_FETCH = {"DownloadString", "DownloadData", "DownloadFile", "OpenRead",
                 "GetStringAsync", "GetByteArrayAsync", "GetStreamAsync", "Fetch"}
_DOTNET_LOAD = {"Load", "LoadFrom", "LoadFile", "LoadWithPartialName"}
_DOTNET_EXEC = {"Start", "CreateInstance", "Invoke", "InvokeMember", "GetType",
                "CreateInstanceAndUnwrap", "ExecuteAssembly"}


def _pe_sections(data):
    peoff = struct.unpack("<I", data[0x3c:0x40])[0]
    nsec = struct.unpack("<H", data[peoff + 6:peoff + 8])[0]
    opt_size = struct.unpack("<H", data[peoff + 20:peoff + 22])[0]
    magic = struct.unpack("<H", data[peoff + 24:peoff + 26])[0]
    dd_base = peoff + 24 + (112 if magic == 0x20b else 96)
    dirs = []
    for i in range(16):
        rva, size = struct.unpack("<II", data[dd_base + i * 8:dd_base + i * 8 + 8])
        dirs.append((rva, size))
    sections = []
    soff = peoff + 24 + opt_size
    for i in range(nsec):
        off = soff + i * 40
        name = data[off:off + 8].rstrip(b"\x00").decode("ascii", "replace")
        vsize, vaddr, rsize, rptr = struct.unpack("<IIII", data[off + 8:off + 24])
        sections.append({"name": name, "vsize": vsize, "vaddr": vaddr,
                         "rsize": rsize, "rptr": rptr})
    return dirs, sections


def _rva_to_off(sections, rva):
    for s in sections:
        span = max(s["vsize"], s["rsize"])
        if s["vaddr"] <= rva < s["vaddr"] + span:
            return s["rptr"] + (rva - s["vaddr"])
    return None


def _read_comp(data, i):
    b0 = data[i]
    if b0 & 0x80 == 0:
        return b0, i + 1
    if b0 & 0xC0 == 0x80:
        return ((b0 & 0x3f) << 8) | data[i + 1], i + 2
    return ((b0 & 0x3f) << 24) | (data[i + 1] << 16) | (data[i + 2] << 8) | data[i + 3], i + 4


def _heap_str(heap, idx):
    if idx == 0 or idx >= len(heap):
        return ""
    end = heap.find(b"\x00", idx)
    return heap[idx:end if end >= 0 else len(heap)].decode("utf-8", "replace")


def _heap_blob(heap, idx):
    if idx == 0 or idx >= len(heap):
        return b""
    n, i = _read_comp(heap, idx)
    return heap[i:i + n]


def _heap_us(heap, idx):
    if idx == 0 or idx >= len(heap):
        return None
    n, i = _read_comp(heap, idx)
    raw = heap[i:i + n]
    if raw and raw[-1:] in (b"\x00", b"\x01"):
        raw = raw[:-1]
    try:
        return raw.decode("utf-16le")
    except Exception:
        return None


_ET = {0x01: "void", 0x02: "bool", 0x03: "char", 0x04: "int8", 0x05: "uint8",
       0x06: "int16", 0x07: "uint16", 0x08: "int32", 0x09: "uint32", 0x0a: "int64",
       0x0b: "uint64", 0x0c: "float32", 0x0d: "float64", 0x0e: "string",
       0x0f: "ptr", 0x10: "byref", 0x1c: "object", 0x1d: "[]", 0x1e: "pinned"}


def parse_dotnet_il(data, _depth=0):
    """Full metadata and IL parse of one .NET assembly."""
    out = {"is_dotnet_il": False, "parsed": False, "error": None}
    if data[:2] != b"MZ":
        out["error"] = "not a PE file"
        return out
    try:
        dirs, sections = _pe_sections(data)
    except Exception as e:
        out["error"] = f"PE headers could not be parsed: {e}"
        return out
    clr_rva, clr_size = dirs[14]
    if not clr_rva:
        out["error"] = "no CLR runtime header (not a .NET assembly)"
        return out
    out["is_dotnet_il"] = True
    # A PE whose declared extents run past the bytes present is a
    # truncated file, and a truncated assembly cannot be accounted:
    # the metadata and bodies the parser cannot see are not in
    # evidence. Without this check a cut file parses as a smaller,
    # benign-looking assembly.
    for s in sections:
        if s["rptr"] and s["rptr"] + s["rsize"] > len(data):
            out["error"] = (f"PE section {s['name']} declares {s['rsize']} raw bytes at file offset "
                            f"{s['rptr']} but the file has {len(data)} bytes: the file is truncated")
            return out
    clr_off = _rva_to_off(sections, clr_rva)
    if clr_off is None:
        out["error"] = "CLR header RVA does not map into any section"
        return out
    md_rva, md_size = struct.unpack("<II", data[clr_off + 8:clr_off + 16])
    res_rva, res_size = struct.unpack("<II", data[clr_off + 24:clr_off + 32])
    md_off = _rva_to_off(sections, md_rva)
    if md_off is None:
        out["error"] = "metadata RVA does not map into any section"
        return out
    if md_off + md_size > len(data):
        out["error"] = (f"the metadata root declares {md_size} bytes at file offset {md_off} "
                        f"but the file has {len(data)} bytes: the file is truncated")
        return out
    md = data[md_off:md_off + md_size]
    if md[:4] != b"BSJB":
        out["error"] = "metadata root signature missing (BSJB)"
        return out
    ver_len = struct.unpack("<I", md[12:16])[0]
    pos = 16 + ((ver_len + 3) & ~3)
    out["runtime_version"] = md[16:16 + ver_len].rstrip(b"\x00").decode("ascii", "replace")
    nstreams = struct.unpack("<H", md[pos + 2:pos + 4])[0]
    pos += 4
    streams = {}
    for _ in range(nstreams):
        soff, ssize = struct.unpack("<II", md[pos:pos + 8])
        pos += 8
        end = md.index(b"\x00", pos)
        name = md[pos:end].decode("ascii", "replace")
        pos += ((end - pos + 1 + 3) & ~3)
        if soff + ssize > len(md):
            out["error"] = (f"metadata stream {name} declares {ssize} bytes at metadata offset {soff} "
                            f"but the metadata is {len(md)} bytes: the file is truncated")
            return out
        streams[name] = md[soff:soff + ssize]
    tilde = streams.get("#~") or streams.get("#-")
    if tilde is None:
        out["error"] = "no #~ tables stream"
        return out
    heap_str = streams.get("#Strings", b"\x00")
    heap_us = streams.get("#US", b"\x00")
    heap_blob = streams.get("#Blob", b"\x00")
    heap_guid = streams.get("#GUID", b"")
    heap_sizes = tilde[6]
    str_sz = 4 if heap_sizes & 0x01 else 2
    guid_sz = 4 if heap_sizes & 0x02 else 2
    blob_sz = 4 if heap_sizes & 0x04 else 2
    valid = struct.unpack("<Q", tilde[8:16])[0]
    rows = {}
    pos = 24
    present = [t for t in range(45) if valid & (1 << t)]
    for t in present:
        rows[t] = struct.unpack("<I", tilde[pos:pos + 4])[0]
        pos += 4

    def idx_size(table):
        return 2 if rows.get(table, 0) < 65536 else 4
    def coded_size(name):
        tables, bits = _CODED[name]
        mx = max((rows.get(t, 0) for t in tables if t is not None), default=0)
        return 2 if mx < (1 << (16 - bits)) else 4
    def col_size(col):
        if col == "u2": return 2
        if col == "u4": return 4
        if col == "str": return str_sz
        if col == "guid": return guid_sz
        if col == "blob": return blob_sz
        if isinstance(col, tuple) and col[0] == "i": return idx_size(col[1])
        if isinstance(col, tuple) and col[0] == "c": return coded_size(col[1])
        raise ValueError(f"bad column kind {col}")

    tables = {}
    for t in present:
        schema = _SCHEMAS.get(t)
        if schema is None:
            out["error"] = f"metadata table {t} has no schema in this build"
            return out
        sizes = [col_size(c) for c in schema]
        recs = []
        for _r in range(rows[t]):
            vals = []
            for sz in sizes:
                vals.append(int.from_bytes(tilde[pos:pos + sz], "little"))
                pos += sz
            recs.append(vals)
        tables[t] = recs
    out["tables_present"] = {str(t): rows[t] for t in present}

    def type_name_of_coded(coded):
        tables_list, bits = _CODED["TypeDefOrRef"]
        tag = coded & ((1 << bits) - 1)
        row = coded >> bits
        t = tables_list[tag] if tag < len(tables_list) else None
        if t == 1 and 1 <= row <= len(tables.get(1, [])):
            rec = tables[1][row - 1]
            ns, nm = _heap_str(heap_str, rec[2]), _heap_str(heap_str, rec[1])
            return (ns + "." if ns else "") + nm
        if t == 2 and 1 <= row <= len(tables.get(2, [])):
            rec = tables[2][row - 1]
            ns, nm = _heap_str(heap_str, rec[2]), _heap_str(heap_str, rec[1])
            return (ns + "." if ns else "") + nm
        if t == 27:
            return "TypeSpec"
        return f"coded-type-{tag}:{row}"

    def type_name_of_ref(row):
        if 1 <= row <= len(tables.get(1, [])):
            rec = tables[1][row - 1]
            ns, nm = _heap_str(heap_str, rec[2]), _heap_str(heap_str, rec[1])
            return (ns + "." if ns else "") + nm
        return f"TypeRef#{row}"

    def sig_type(sig, i):
        """Parse one type from a signature blob; return (text, next_i)."""
        if i >= len(sig):
            return "?", i
        t = sig[i]
        i += 1
        if t in _ET:
            if t == 0x1d:
                inner, i = sig_type(sig, i)
                return inner + "[]", i
            if t in (0x0f, 0x10, 0x1e):
                inner, i = sig_type(sig, i)
                return _ET[t] + " " + inner, i
            return _ET[t], i
        if t in (0x11, 0x12):
            coded, i = _read_comp(sig, i)
            return type_name_of_coded(coded), i
        if t == 0x15:
            base, i = sig_type(sig, i)
            _rank, i = _read_comp(sig, i)
            nsizes, i = _read_comp(sig, i)
            for _ in range(nsizes):
                _v, i = _read_comp(sig, i)
            nlow, i = _read_comp(sig, i)
            for _ in range(nlow):
                _v, i = _read_comp(sig, i)
            return base + "[,]", i
        if t in (0x13, 0x1f, 0x20):
            v, i = _read_comp(sig, i)
            return f"var{v}", i
        if t == 0x14:
            _c, i = _read_comp(sig, i)
            inner, i = sig_type(sig, i)
            return inner, i
        return f"type-{hex(t)}", i

    def parse_method_sig(blob_idx):
        sig = _heap_blob(heap_blob, blob_idx)
        if not sig:
            return {"params": [], "ret": "?", "raw": ""}
        i = 1 if sig and sig[0] in (0x00, 0x20, 0x05, 0x25) else 0
        if i == 0:
            return {"params": [], "ret": "?", "raw": ""}
        count, i = _read_comp(sig, i)
        ret, i = sig_type(sig, i)
        params = []
        for _ in range(count):
            p, i = sig_type(sig, i)
            params.append(p)
        return {"params": params, "ret": ret}

    # types and their method ranges
    typedefs = tables.get(2, [])
    methoddefs = tables.get(6, [])
    types = []
    for ti, rec in enumerate(typedefs):
        start = rec[5]
        end = (typedefs[ti + 1][5] if ti + 1 < len(typedefs) else len(methoddefs) + 1)
        types.append({"name": _heap_str(heap_str, rec[1]),
                      "namespace": _heap_str(heap_str, rec[2]),
                      "extends": type_name_of_coded(rec[3]),
                      "method_rows": list(range(start, max(start, end)))})
    out["assembly_name"] = None
    if tables.get(32):
        out["assembly_name"] = _heap_str(heap_str, tables[32][0][7])
    out["assembly_refs"] = [_heap_str(heap_str, r[6]) for r in tables.get(35, [])]
    out["types"] = [{"name": (t["namespace"] + "." if t["namespace"] else "") + t["name"],
                     "extends": t["extends"]} for t in types]

    def resolve_token(tok):
        table = tok >> 24
        row = tok & 0xFFFFFF
        if table == 0x70:
            return ("string", _heap_us(heap_us, row))
        if table == 0x0A and 1 <= row <= len(tables.get(10, [])):
            rec = tables[10][row - 1]
            parent, pb = _CODED["MemberRefParent"]
            tag = rec[0] & ((1 << pb) - 1)
            prow = rec[0] >> pb
            ptable = parent[tag] if tag < len(parent) else None
            if ptable == 1:
                pname = type_name_of_ref(prow)
            elif ptable == 2 and 1 <= prow <= len(typedefs):
                tr = typedefs[prow - 1]
                ns, nm = _heap_str(heap_str, tr[2]), _heap_str(heap_str, tr[1])
                pname = (ns + "." if ns else "") + nm
            else:
                pname = f"parent-{ptable}:{prow}"
            return ("memberref", f"{pname}::{_heap_str(heap_str, rec[1])}")
        if table == 0x06 and 1 <= row <= len(methoddefs):
            owner = next((t for t in types if row in t["method_rows"]), None)
            nm = _heap_str(heap_str, methoddefs[row - 1][3])
            return ("methoddef", f"{owner['name'] if owner else '?'}::{nm}" if owner else nm)
        if table == 0x02 and 1 <= row <= len(typedefs):
            tr = typedefs[row - 1]
            ns, nm = _heap_str(heap_str, tr[2]), _heap_str(heap_str, tr[1])
            return ("typedef", (ns + "." if ns else "") + nm)
        if table == 0x01:
            return ("typeref", type_name_of_ref(row))
        if table == 0x04 and 1 <= row <= len(tables.get(4, [])):
            return ("field", _heap_str(heap_str, tables[4][row - 1][1]))
        if table == 0x1B:
            return ("typespec", "TypeSpec")
        if table == 0x2B:
            return ("methodspec", "MethodSpec")
        if table == 0x11:
            return ("sig", "StandAloneSig")
        return ("token", f"{hex(table)}:{row}")

    methods = []
    for mi, rec in enumerate(methoddefs):
        rva, _impl, _flags, name_idx, sig_idx, _plist = rec
        name = _heap_str(heap_str, name_idx)
        owner = next((t for t in types if (mi + 1) in t["method_rows"]), None)
        m = {"name": name, "owner": (owner["name"] if owner else None),
             "signature": parse_method_sig(sig_idx), "rva": rva,
             "decoded": False, "instructions": [], "calls": [], "ldstr": [],
             "int_constants": [], "switch_targets": 0}
        if rva == 0:
            m["decoded"] = True  # abstract or extern method: no body to decode
            m["no_body"] = True
            methods.append(m)
            continue
        off = _rva_to_off(sections, rva)
        if off is None or off >= len(data):
            m["decode_error"] = f"method body RVA {hex(rva)} does not map into the file"
            methods.append(m)
            continue
        b0 = data[off]
        if b0 & 0x3 == 0x2:
            code_size = b0 >> 2
            code_off = off + 1
        elif b0 & 0xF == 0x3:
            hdr_dwords = (b0 >> 4) & 0xF
            code_size = struct.unpack("<I", data[off + 4:off + 8])[0]
            code_off = off + hdr_dwords * 4
        else:
            m["decode_error"] = f"method body header byte {hex(b0)} is neither tiny nor fat format"
            methods.append(m)
            continue
        code = data[code_off:code_off + code_size]
        if len(code) < code_size:
            m["decode_error"] = f"method body is truncated: header declares {code_size} code bytes, {len(code)} are present"
            methods.append(m)
            continue
        m["code_size"] = code_size
        pc = 0
        last_ldc_int = None
        ok = True
        while pc < len(code):
            start = pc
            op = code[pc]
            pc += 1
            if op == 0xFE:
                if pc >= len(code):
                    ok = False
                    m["decode_error"] = "truncated two-byte opcode at the end of the method"
                    break
                entry = _IL_OPS2.get(code[pc])
                pc += 1
                if entry is None:
                    ok = False
                    m["decode_error"] = f"unknown two-byte IL opcode 0xFE{code[pc - 1]:02x} at IL offset {start}"
                    break
                name_op, kind = entry
            else:
                entry = _IL_OPS.get(op)
                if entry is None:
                    ok = False
                    m["decode_error"] = f"unknown IL opcode {hex(op)} at IL offset {start}"
                    break
                name_op, kind = entry
            operand = None
            if kind == "switch":
                if pc + 4 > len(code):
                    ok = False
                    break
                n = struct.unpack("<I", code[pc:pc + 4])[0]
                operand = n
                m["switch_targets"] = max(m["switch_targets"], n)
                pc += 4 + 4 * n
            elif kind in _IL_KIND_SIZE:
                sz = _IL_KIND_SIZE[kind]
                raw = code[pc:pc + sz]
                if len(raw) < sz:
                    ok = False
                    m["decode_error"] = f"operand of {name_op} at IL offset {start} is truncated"
                    break
                if kind in ("string", "method", "field", "type", "sig", "tok"):
                    tok = struct.unpack("<I", raw)[0]
                    operand = resolve_token(tok)
                    if name_op == "ldstr" and operand[0] == "string":
                        m["ldstr"].append(operand[1])
                    if name_op in ("call", "callvirt", "newobj", "ldftn", "ldvirtftn"):
                        m["calls"].append({"op": name_op, "target": operand[1],
                                           "kind": operand[0], "preceding_int": last_ldc_int,
                                           "preceding_ldstr": m["ldstr"][-1] if m["ldstr"] else None})
                    if name_op in ("ldsfld", "stsfld", "ldfld", "stfld"):
                        m.setdefault("field_refs", []).append(operand[1])
                elif kind in ("i4",):
                    operand = struct.unpack("<i", raw)[0]
                    last_ldc_int = operand
                elif kind in ("i1",) and name_op == "ldc.i4.s":
                    operand = struct.unpack("<b", raw)[0]
                    last_ldc_int = operand
                pc += sz
            if name_op.startswith("ldc.i4.") and len(name_op) == 9 and name_op[-1].isdigit():
                last_ldc_int = int(name_op[-1])
            if name_op == "ldc.i4.m1":
                last_ldc_int = -1
            m["instructions"].append({"il": start, "op": name_op, "operand": str(operand) if operand is not None else None})
        m["decoded"] = ok and pc == len(code)
        if ok and pc != len(code):
            m["decode_error"] = f"IL walk ended at offset {pc} of {len(code)} code bytes"
            m["decoded"] = False
        methods.append(m)
    out["methods"] = methods
    # embedded manifest resources, enumerated and judged as units
    resources = []
    res_unaccounted = []
    if tables.get(40) and res_rva and res_size:
        res_off = _rva_to_off(sections, res_rva)
        for rec in tables[40]:
            off_r, _flags_r, name_idx, impl = rec
            rname = _heap_str(heap_str, name_idx)
            entry = {"name": rname, "offset": off_r, "flags": _flags_r}
            if impl != 0:
                entry["kind"] = "external-file"
                res_unaccounted.append(f"manifest resource {rname} is implemented by an external file (implementation coded index {impl}); that file is not part of this assembly")
            elif res_off is None or res_off + off_r + 4 > len(data):
                entry["kind"] = "unreadable"
                res_unaccounted.append(f"manifest resource {rname} could not be read from the resources directory")
            else:
                ln = struct.unpack("<I", data[res_off + off_r:res_off + off_r + 4])[0]
                blob = data[res_off + off_r + 4:res_off + off_r + 4 + ln]
                entry["size"] = ln
                if len(blob) < ln:
                    entry["kind"] = "truncated"
                    res_unaccounted.append(f"manifest resource {rname} is truncated: it declares {ln} bytes and {len(blob)} are present")
                elif blob[:2] == b"MZ":
                    entry["kind"] = "embedded-assembly"
                    if _depth < 1:
                        sub = parse_dotnet_il(blob, _depth + 1)
                        entry["assembly_name"] = sub.get("assembly_name")
                        entry["sub_accounted"] = bool(sub.get("accounted"))
                        if not sub.get("parsed"):
                            res_unaccounted.append(f"embedded assembly resource {rname} could not be parsed: {sub.get('error')}")
                        elif not sub.get("accounted"):
                            res_unaccounted.append(f"embedded assembly resource {rname} ({sub.get('assembly_name')}) is itself unaccounted: "
                                                   + "; ".join((sub.get("unaccounted_items") or ["its IL accounting is incomplete"])[:2]))
                    else:
                        res_unaccounted.append(f"embedded assembly resource {rname} sits past this build's recursion depth of 1 and is unaccounted")
                else:
                    try:
                        txt = blob.decode("utf-8")
                        if "\x00" in txt:
                            raise ValueError("nul byte")
                        entry["kind"] = "text"
                    except Exception:
                        entry["kind"] = "binary"
                        res_unaccounted.append(f"embedded resource {rname} ({ln} bytes) is neither text nor a recognised assembly; its content is unaccounted")
            resources.append(entry)
    out["resources"] = resources
    out["_res_unaccounted"] = res_unaccounted
    _dotnet_findings(out, data, sections, res_rva, res_size, _depth)
    out["parsed"] = True
    return out


def _dotnet_findings(out, data, sections, res_rva, res_size, depth):
    unaccounted = []
    references = []
    chains = []
    indicators = []
    fields = {}
    # field name -> signature type text, for the string store shape
    # (recomputed from the tables recorded in out is not possible, so
    # the store shape uses field refs seen in method bodies instead)
    store_rows = set()
    for m in out["methods"]:
        if not m.get("decoded"):
            unaccounted.append(f"method {m.get('owner')}::{m.get('name')} could not be decoded to the bottom"
                               + (f" ({m['decode_error']})" if m.get("decode_error") else ""))
    for m in out["methods"]:
        sig = m.get("signature") or {}
        body_ops = [i["op"] for i in m.get("instructions") or []]
        if sig.get("ret") == "string" and sig.get("params") == ["int32"] \
                and "xor" in body_ops and any(True for _ in m.get("field_refs") or []):
            store_rows.add(m["name"])
            indicators.append({"kind": "encrypted-string-store",
                               "detail": f"encrypted string store shape: method {m.get('owner')}::{m['name']} returns String, "
                                         "takes an Int32 key, and xors over field data; strings it produces are not in the file"})
    unresolved_strings = 0
    for m in out["methods"]:
        for call in m.get("calls") or []:
            target = call["target"] or ""
            tname = target.split("::")[-1]
            tcls = target.split("::")[0]
            if tname in store_rows or (call["kind"] == "methoddef" and target.split("::")[-1] in store_rows):
                unresolved_strings += 1
            if tname in _DOTNET_FETCH:
                m.setdefault("fetch_calls", []).append(target)
            if tcls.endswith("Assembly") and tname in _DOTNET_LOAD:
                arg = call.get("preceding_ldstr")
                known = set(out.get("assembly_refs") or []) | {out.get("assembly_name")}
                res_names = {r["name"] for r in out.get("resources") or []}
                if arg is None:
                    unaccounted.append(f"method {m.get('owner')}::{m.get('name')} calls {target} with an argument that is "
                                       "not a string constant in the method, so the assembly it loads at run time is not identified in the file")
                elif arg.split(",")[0].strip() not in known and arg not in res_names:
                    unaccounted.append(f"method {m.get('owner')}::{m.get('name')} loads assembly '{arg}' through {target}, "
                                       "and that assembly is neither a declared reference nor an embedded resource of this file")
            if tname == "GetType" and tcls.endswith("Type"):
                arg = call.get("preceding_ldstr")
                if arg:
                    tpart = arg.split(",")[0].strip()
                    known_types = {t["name"] for t in out.get("types") or []}
                    if tpart not in known_types:
                        unaccounted.append(f"method {m.get('owner')}::{m.get('name')} resolves type '{arg}' by name at run time "
                                           "through Type.GetType, and that type is not declared in this assembly")
            if tname in ("Invoke", "InvokeMember") and tcls.split(".")[-1] in ("MethodInfo", "MethodBase", "Type"):
                unaccounted.append(f"method {m.get('owner')}::{m.get('name')} invokes {target} reflectively; the invoked "
                                   "member is chosen at run time and is not statically identified in this build")
        if m.get("fetch_calls") and any((c["target"] or "").split("::")[-1] in (_DOTNET_LOAD | _DOTNET_EXEC)
                                        for c in m.get("calls") or []):
            chains.append({"chain": "bytecode-fetch-execute",
                           "name": "This .NET method both fetches remote content and loads or executes code: the fetch and the load are both proven in its IL",
                           "evidence": [f"fetch: {m['fetch_calls'][0]}",
                                        f"method: {m.get('owner')}::{m.get('name')}"]})
        if (m.get("switch_targets") or 0) >= 4:
            indicators.append({"kind": "control-flow-flattening",
                               "detail": f"control-flow flattening shape: method {m.get('owner')}::{m.get('name')} dispatches through a "
                                         f"switch with {m['switch_targets']} targets"})
        for s in m.get("ldstr") or []:
            if s and re.match(r"(?:https?|ftp)://", s):
                references.append({"kind": "dotnet-string-url", "target": s,
                                   "source": ".NET user-string heap (ldstr)"})
    if unresolved_strings:
        unaccounted.append(f"{unresolved_strings} call site(s) pass integer keys to an encrypted string store; the "
                           "decrypted strings those calls produce are not in evidence and are unaccounted")
        out["unresolved_string_calls"] = unresolved_strings
    for t in out.get("types") or []:
        if t.get("extends") == "System.MulticastDelegate":
            indicators.append({"kind": "proxy-delegate",
                               "detail": f"delegate type '{t['name']}' deriving from System.MulticastDelegate (proxy delegate surface)"})
    unaccounted.extend(out.pop("_res_unaccounted", []))
    out["references"] = references
    out["chains"] = chains
    out["obfuscation_indicators"] = indicators
    out["unaccounted_items"] = unaccounted
    out["accounted"] = not unaccounted and all(m.get("decoded") for m in out["methods"])

# ======================================================================
# Android DEX and binary AndroidManifest.xml (AXML)
# ======================================================================

# Dalvik opcode widths in 16-bit code units, by opcode. Index 0x00
# with a nonzero high byte is a pseudo-op payload (packed-switch,
# sparse-switch, fill-array-data) and is handled in the walker.
_DEX_WIDTHS = [
    1, 1, 2, 3, 1, 2, 3, 1, 2, 3, 1, 1, 1, 1, 1, 1,   # 00-0f
    1, 1, 1, 2, 3, 2, 2, 3, 5, 2, 2, 3, 2, 1, 1, 2,   # 10-1f
    2, 1, 2, 2, 2, 2, 2, 1, 1, 2, 3, 3, 3, 2, 2, 2,   # 20-2f
    2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 1, 1, 1, 1,   # 30-3f (3e-43 unused: width 1 nominal)
    1, 1, 1, 1, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,   # 40-4f (44-51 aget/aput are 2; 40-43 unused)
    2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,   # 50-5f iget/iput family
    2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 3, 3,   # 60-6f sget/sput, invoke-virtual/super
    3, 3, 3, 1, 3, 3, 3, 3, 3, 1, 1, 1, 1, 1, 1, 1,   # 70-7f invoke family, unary ops begin
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,   # 80-8f unary ops
    2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,   # 90-9f binops
    2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,   # a0-af binops
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,   # b0-bf binops/2addr
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,   # c0-cf binops/2addr
    2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,   # d0-df binops literal
    2, 2, 2, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,   # e0-ef lit8 tail, unused
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 4, 3, 3, 1, 2, 2,   # f0-ff invoke-polymorphic/custom at fa/fb/fc
]
_DEX_WIDTHS[0x38] = 2; _DEX_WIDTHS[0x39] = 2; _DEX_WIDTHS[0x3a] = 2
_DEX_WIDTHS[0x3b] = 2; _DEX_WIDTHS[0x3c] = 2; _DEX_WIDTHS[0x3d] = 2
for _i in range(0x3e, 0x44):
    _DEX_WIDTHS[_i] = 1
for _i in range(0x40, 0x44):
    _DEX_WIDTHS[_i] = 1

_DEX_INVOKE_OPS = {0x6e: "invoke-virtual", 0x6f: "invoke-super", 0x70: "invoke-direct",
                  0x71: "invoke-static", 0x72: "invoke-interface",
                  0x74: "invoke-virtual/range", 0x75: "invoke-super/range",
                  0x76: "invoke-direct/range", 0x77: "invoke-static/range",
                  0x78: "invoke-interface/range"}
_DEX_DYNAMIC_CLASSES = ("dalvik/system/DexClassLoader", "dalvik/system/PathClassLoader",
                       "dalvik/system/InMemoryDexClassLoader", "dalvik/system/DexFile",
                       "dalvik/system/BaseDexClassLoader")
_DEX_PLATFORM_PREFIXES = ("java/", "javax/", "android/", "dalvik/", "kotlin/", "org/json/")


def _uleb(data, i):
    result = 0
    shift = 0
    while True:
        if i >= len(data):
            raise ValueError("ULEB128 runs past the end of the file")
        b = data[i]
        i += 1
        result |= (b & 0x7f) << shift
        if not (b & 0x80):
            return result, i
        shift += 7


def is_dex(data):
    return len(data) > 8 and data[:4] == b"dex\n" and data[7] == 0


def parse_dex(data, known_files=(), known_classes=()):
    """Parse one DEX file completely: id lists, class defs, class
    data, and a full opcode walk of every code item. known_classes
    holds internal class names (Lcom/example/Foo;) defined in other
    DEX files of the same submission, so a cross-DEX load resolves."""
    out = {"is_dex": False, "parsed": False, "error": None}
    if not is_dex(data):
        out["error"] = "not a DEX file (bad magic)"
        return out
    out["is_dex"] = True
    try:
        if len(data) < 112:
            raise ValueError(f"DEX header is truncated: {len(data)} of 112 bytes present")
        (string_ids_size, string_ids_off, type_ids_size, type_ids_off,
         proto_ids_size, proto_ids_off, field_ids_size, field_ids_off,
         method_ids_size, method_ids_off, class_defs_size, class_defs_off,
         data_size, data_off) = struct.unpack("<14I", data[56:112])
        file_size = struct.unpack("<I", data[32:36])[0]
        if file_size > len(data):
            raise ValueError(f"DEX header declares a file size of {file_size} bytes but {len(data)} are present: the file is truncated")
        def _need(off, n, what):
            if off + n > len(data):
                raise ValueError(f"{what} at offset {off} ({n} bytes) runs past the end of the file")
        strings = []
        for i in range(string_ids_size):
            _need(string_ids_off + i * 4, 4, "string_ids")
            soff = struct.unpack("<I", data[string_ids_off + i * 4:string_ids_off + i * 4 + 4])[0]
            _need(soff, 1, "string data")
            _len, p = _uleb(data, soff)
            end = data.index(b"\x00", p)
            strings.append(data[p:end].decode("utf-8", "replace"))
        types = []
        for i in range(type_ids_size):
            _need(type_ids_off + i * 4, 4, "type_ids")
            didx = struct.unpack("<I", data[type_ids_off + i * 4:type_ids_off + i * 4 + 4])[0]
            types.append(strings[didx] if didx < len(strings) else f"string#{didx}")
        protos = []
        for i in range(proto_ids_size):
            _need(proto_ids_off + i * 12, 12, "proto_ids")
            _shorty, ret_idx, params_off = struct.unpack("<III", data[proto_ids_off + i * 12:proto_ids_off + i * 12 + 12])
            params = []
            if params_off:
                _need(params_off, 4, "proto type list")
                n = struct.unpack("<I", data[params_off:params_off + 4])[0]
                for j in range(n):
                    tidx = struct.unpack("<H", data[params_off + 4 + j * 2:params_off + 6 + j * 2])[0]
                    params.append(types[tidx] if tidx < len(types) else f"type#{tidx}")
            protos.append({"ret": types[ret_idx] if ret_idx < len(types) else f"type#{ret_idx}",
                           "params": params})
        fields = []
        for i in range(field_ids_size):
            _need(field_ids_off + i * 8, 8, "field_ids")
            cidx, tidx, nidx = struct.unpack("<HHI", data[field_ids_off + i * 8:field_ids_off + i * 8 + 8])
            fields.append({"class": types[cidx] if cidx < len(types) else f"type#{cidx}",
                           "type": types[tidx] if tidx < len(types) else f"type#{tidx}",
                           "name": strings[nidx] if nidx < len(strings) else f"string#{nidx}"})
        methods_ids = []
        for i in range(method_ids_size):
            _need(method_ids_off + i * 8, 8, "method_ids")
            cidx, pidx, nidx = struct.unpack("<HHI", data[method_ids_off + i * 8:method_ids_off + i * 8 + 8])
            methods_ids.append({"class": types[cidx] if cidx < len(types) else f"type#{cidx}",
                                "proto": protos[pidx] if pidx < len(protos) else {},
                                "name": strings[nidx] if nidx < len(strings) else f"string#{nidx}"})
        class_defs = []
        for i in range(class_defs_size):
            _need(class_defs_off + i * 32, 32, "class_defs")
            vals = struct.unpack("<8I", data[class_defs_off + i * 32:class_defs_off + i * 32 + 32])
            class_defs.append({"class": types[vals[0]] if vals[0] < len(types) else f"type#{vals[0]}",
                               "access": vals[1],
                               "super": types[vals[2]] if vals[2] < len(types) else None,
                               "class_data_off": vals[6]})
    except (ValueError, IndexError, struct.error) as e:
        out["error"] = f"DEX structure could not be parsed: {e}"
        return out
    out["strings"] = strings
    out["types"] = types
    classes = []
    unaccounted = []
    references = []
    chains = []
    defined = {cd["class"] for cd in class_defs} | set(known_classes)
    known_files = {str(k).lower() for k in (known_files or ())}
    has_fetch = False
    has_loader = False
    for cd in class_defs:
        cls = {"name": cd["class"], "super": cd["super"], "methods": []}
        if cd["class_data_off"] == 0:
            classes.append(cls)
            continue
        try:
            p = cd["class_data_off"]
            _sf, p = _uleb(data, p)
            _inf, p = _uleb(data, p)
            n_direct, p = _uleb(data, p)
            n_virtual, p = _uleb(data, p)
            midx = 0
            enc = []
            for _ in range(_sf):
                d, p = _uleb(data, p); _a, p = _uleb(data, p); midx += d
            midx = 0
            for _ in range(_inf):
                d, p = _uleb(data, p); _a, p = _uleb(data, p); midx += d
            midx = 0
            for _ in range(n_direct + n_virtual):
                d, p = _uleb(data, p)
                acc, p = _uleb(data, p)
                coff, p = _uleb(data, p)
                midx += d
                enc.append((midx, acc, coff))
        except ValueError as e:
            unaccounted.append(f"class {cd['class']}: class data could not be parsed: {e}")
            classes.append(cls)
            continue
        for midx, acc, coff in enc:
            minfo = methods_ids[midx] if midx < len(methods_ids) else {"name": f"method#{midx}", "class": cd["class"]}
            m = {"name": minfo["name"], "class": minfo["class"], "decoded": False,
                 "invokes": [], "const_strings": [], "code_units": 0}
            if coff == 0:
                m["decoded"] = True
                m["no_body"] = True
                cls["methods"].append(m)
                continue
            try:
                if coff + 16 > len(data):
                    raise ValueError(f"code item at offset {coff} runs past the end of the file")
                _regs, _ins, _outs, _tries, _dbg, insns_size = struct.unpack("<HHHHII", data[coff:coff + 16])
                insns_off = coff + 16
                if insns_off + insns_size * 2 > len(data):
                    raise ValueError(f"code item at offset {coff} declares {insns_size} code units but the file ends early: the method is truncated")
                units = struct.unpack(f"<{insns_size}H", data[insns_off:insns_off + insns_size * 2])
            except (ValueError, struct.error) as e:
                m["decode_error"] = str(e)
                unaccounted.append(f"method {minfo['class']}->{minfo['name']}: {e}")
                cls["methods"].append(m)
                continue
            m["code_units"] = insns_size
            pc = 0
            ok = True
            while pc < insns_size:
                unit = units[pc]
                op = unit & 0xFF
                if op == 0x00 and (unit >> 8) in (1, 2, 3):
                    kind = unit >> 8
                    if kind == 1:
                        if pc + 2 > insns_size:
                            ok = False; break
                        size = units[pc + 1]
                        adv = 4 + size * 2
                    elif kind == 2:
                        if pc + 2 > insns_size:
                            ok = False; break
                        size = units[pc + 1]
                        adv = 2 + size * 4
                    else:
                        if pc + 4 > insns_size:
                            ok = False; break
                        ew = units[pc + 1]
                        size = units[pc + 2] | (units[pc + 3] << 16)
                        adv = 4 + (ew * size + 1) // 2
                    if pc + adv > insns_size:
                        ok = False
                        m["decode_error"] = f"payload pseudo-instruction at code unit {pc} runs past the end of the method"
                        break
                    pc += adv
                    continue
                width = _DEX_WIDTHS[op]
                if width == 0 or pc + width > insns_size:
                    ok = False
                    m["decode_error"] = f"opcode {hex(op)} at code unit {pc} has no valid width or runs past the end of the method"
                    break
                if op in (0x1a, 0x1b):
                    sidx = units[pc + 1] if op == 0x1a else (units[pc + 1] | (units[pc + 2] << 16))
                    if sidx < len(strings):
                        m["const_strings"].append(strings[sidx])
                elif op in _DEX_INVOKE_OPS:
                    refidx = units[pc + 1]
                    ref = methods_ids[refidx] if refidx < len(methods_ids) else {"class": f"type#{refidx}", "name": "?"}
                    m["invokes"].append({"op": _DEX_INVOKE_OPS[op], "class": ref["class"], "name": ref["name"]})
                elif op in (0x1c, 0x22, 0x1f, 0x20, 0x23):
                    tidx = units[pc + 1]
                    m.setdefault("type_refs", []).append(types[tidx] if tidx < len(types) else f"type#{tidx}")
                elif op in (0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d,
                            0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5a, 0x5b, 0x5c, 0x5d, 0x5e, 0x5f):
                    fidx = units[pc + 1]
                    if fidx < len(fields):
                        m.setdefault("field_refs", []).append(fields[fidx])
                pc += width
            m["decoded"] = ok and pc == insns_size
            if not m["decoded"] and "decode_error" not in m:
                m["decode_error"] = f"opcode walk ended at code unit {pc} of {insns_size}"
                unaccounted.append(f"method {minfo['class']}->{minfo['name']}: {m['decode_error']}")
            elif not m["decoded"]:
                unaccounted.append(f"method {minfo['class']}->{minfo['name']}: {m['decode_error']}")
            cls["methods"].append(m)
        classes.append(cls)
    out["classes"] = classes
    # findings over the decoded methods
    for cls in classes:
        for m in cls["methods"]:
            inv = m.get("invokes") or []
            for iv in inv:
                icls = (iv["class"] or "").strip("L;")
                if icls in ("java/net/URL", "java/net/HttpURLConnection", "java/net/URLConnection") \
                        and iv["name"] in ("openConnection", "openStream", "getInputStream", "<init>"):
                    has_fetch = True
                if icls in _DEX_DYNAMIC_CLASSES:
                    has_loader = True
                    if iv["name"] == "<init>":
                        paths = [s for s in m.get("const_strings") or []
                                 if "/" in s or s.lower().endswith((".dex", ".jar", ".apk")) or "://" in s]
                        for tgt in paths:
                            base = os.path.basename(tgt)
                            if base and base.lower() in known_files:
                                continue
                            unaccounted.append(
                                f"method {cls['name']}->{m['name']} constructs a {icls.rsplit('/', 1)[-1]} over "
                                f"'{tgt}', which is not part of this submission: code loaded from that path at "
                                "run time is unaccounted by construction")
                        if not paths:
                            unaccounted.append(
                                f"method {cls['name']}->{m['name']} constructs a {icls.rsplit('/', 1)[-1]} with no "
                                "string-constant path in the same method, so the code it loads is not identified in the file")
                if iv["name"] == "loadClass" and icls in ("java/lang/ClassLoader",) + _DEX_DYNAMIC_CLASSES:
                    names = [s for s in m.get("const_strings") or [] if "." in s and " " not in s]
                    for nm in names:
                        internal = "L" + nm.replace(".", "/") + ";"
                        if internal in defined or any(nm.replace(".", "/").startswith(p) for p in _DEX_PLATFORM_PREFIXES):
                            continue
                        unaccounted.append(
                            f"method {cls['name']}->{m['name']} loads class {nm} by name through a class loader, "
                            "and that class is not defined in this DEX file, so the loaded code is unaccounted")
                if icls == "java/lang/Class" and iv["name"] == "forName":
                    names = [s for s in m.get("const_strings") or [] if "." in s and " " not in s]
                    for nm in names:
                        internal = "L" + nm.replace(".", "/") + ";"
                        if internal in defined or any(nm.replace(".", "/").startswith(p) for p in _DEX_PLATFORM_PREFIXES):
                            continue
                        unaccounted.append(
                            f"method {cls['name']}->{m['name']} resolves class {nm} by name through Class.forName, "
                            "and that class is not defined in this DEX file, so the reflected code is unaccounted")
                if icls == "java/lang/System" and iv["name"] in ("loadLibrary", "load"):
                    for nm in m.get("const_strings") or []:
                        lib = nm if iv["name"] == "load" else f"lib{nm}.so"
                        if os.path.basename(lib).lower() in known_files:
                            continue
                        unaccounted.append(
                            f"method {cls['name']}->{m['name']} loads native library '{lib}' through System.{iv['name']}, "
                            "and that library is not part of this submission, so the native code is unaccounted")
                if icls == "java/lang/Runtime" and iv["name"] in ("loadLibrary", "load"):
                    for nm in m.get("const_strings") or []:
                        lib = nm if iv["name"] == "load" else f"lib{nm}.so"
                        if os.path.basename(lib).lower() in known_files:
                            continue
                        unaccounted.append(
                            f"method {cls['name']}->{m['name']} loads native library '{lib}' through Runtime.{iv['name']}, "
                            "and that library is not part of this submission, so the native code is unaccounted")
            for s in m.get("const_strings") or []:
                if re.match(r"(?:https?|ftp)://", s):
                    references.append({"kind": "dex-constant-url", "target": s,
                                       "source": "DEX const-string"})
    if has_fetch and has_loader:
        chains.append({"chain": "bytecode-fetch-execute",
                       "name": "This DEX both opens remote connections and dynamically loads code: the fetch and the dynamic loading are both proven in its bytecode",
                       "evidence": ["a URL or connection open is invoked", "a DexClassLoader-family class is used"]})
    out["references"] = references
    out["chains"] = chains
    out["unaccounted_items"] = unaccounted
    out["accounted"] = not unaccounted and all(
        m.get("decoded") for c in classes for m in c["methods"])
    out["parsed"] = True
    return out


def _axml_string_pool(data, off):
    ctype, hsize, size = struct.unpack("<HHI", data[off:off + 8])
    if ctype != 0x0001:
        raise ValueError(f"chunk at offset {off} is not a string pool (type {hex(ctype)})")
    scount, _styles, flags, strings_start, _styles_start = struct.unpack("<IIIII", data[off + 8:off + 28])
    utf8 = bool(flags & 0x100)
    offsets = [struct.unpack("<I", data[off + hsize + i * 4:off + hsize + i * 4 + 4])[0] for i in range(scount)]
    base = off + strings_start
    strings = []
    for o in offsets:
        p = base + o
        if utf8:
            _ulen, p = _uleb(data, p)
            blen, p = _uleb(data, p)
            strings.append(data[p:p + blen].decode("utf-8", "replace"))
        else:
            n = struct.unpack("<H", data[p:p + 2])[0]
            p += 2
            if n & 0x8000:
                n = ((n & 0x7fff) << 16) | struct.unpack("<H", data[p:p + 2])[0]
                p += 2
            strings.append(data[p:p + n * 2].decode("utf-16le", "replace"))
    return strings, size


def parse_axml(data):
    """Parse a binary AndroidManifest.xml: package, permissions,
    and application components with their exported flags."""
    out = {"is_axml": False, "parsed": False, "error": None}
    try:
        if len(data) < 8 or struct.unpack("<H", data[0:2])[0] != 0x0003:
            out["error"] = "not a binary XML file (bad magic)"
            return out
        out["is_axml"] = True
        total = struct.unpack("<I", data[4:8])[0]
        if total > len(data):
            raise ValueError(f"binary XML declares {total} bytes but {len(data)} are present: the file is truncated")
        strings, pool_size = _axml_string_pool(data, 8)
        def _s(idx):
            return strings[idx] if idx != 0xFFFFFFFF and idx < len(strings) else None
        pos = 8 + pool_size
        elements = []
        while pos + 8 <= len(data):
            ctype, hsize, csize = struct.unpack("<HHI", data[pos:pos + 8])
            if csize < 8 or pos + csize > len(data):
                raise ValueError(f"chunk at offset {pos} declares {csize} bytes and runs past the end of the file")
            if ctype == 0x0102:
                name_idx = struct.unpack("<I", data[pos + 20:pos + 24])[0]
                attr_start, attr_size, attr_count = struct.unpack("<HHH", data[pos + 24:pos + 30])
                attrs = {}
                abase = pos + 16 + attr_start
                for ai in range(attr_count):
                    ao = abase + ai * attr_size
                    _ns, aname, raw = struct.unpack("<III", data[ao:ao + 12])
                    vsize, _res0, vtype, vdata = struct.unpack("<HBBI", data[ao + 12:ao + 20])
                    key = _s(aname)
                    if key is None:
                        continue
                    if raw != 0xFFFFFFFF:
                        attrs[key] = _s(raw)
                    elif vtype == 0x03:
                        attrs[key] = _s(vdata)
                    elif vtype == 0x12:
                        attrs[key] = bool(vdata)
                    elif vtype == 0x10:
                        attrs[key] = vdata
                    else:
                        attrs[key] = vdata
                elements.append({"tag": _s(name_idx), "attributes": attrs})
            pos += csize
    except (ValueError, IndexError, struct.error) as e:
        out["error"] = f"binary XML could not be parsed: {e}"
        return out
    out["elements"] = elements
    out["package"] = None
    out["permissions"] = []
    out["components"] = []
    for el in elements:
        if el["tag"] == "manifest":
            out["package"] = el["attributes"].get("package")
        elif el["tag"] == "uses-permission":
            nm = el["attributes"].get("name")
            if nm:
                out["permissions"].append(nm)
        elif el["tag"] in ("activity", "activity-alias", "service", "receiver", "provider"):
            nm = el["attributes"].get("name")
            if nm:
                out["components"].append({"kind": el["tag"], "name": nm,
                                          "exported": el["attributes"].get("exported")})
    out["parsed"] = True
    return out


def axml_component_class(package, name):
    """Normalise a manifest component name to a dotted class name."""
    if not name:
        return None
    if name.startswith("."):
        return (package or "") + name
    if "." not in name:
        return ((package + ".") if package else "") + name
    return name


# ======================================================================
# Mach-O: fat slicing, load commands, code signature, entitlements
# ======================================================================

_FAT_MAGICS = (b"\xca\xfe\xba\xbe", b"\xbe\xba\xfe\xca")
_CPU_NAMES = {0x01000007: "x86_64", 0x0100000c: "arm64", 0x07: "x86", 0x0c: "arm",
              0x01000009: "x86_64h", 0x0200000c: "arm64_32"}
_LC_NAMES = {0x01: "LC_SEGMENT", 0x02: "LC_SYMTAB", 0x0c: "LC_LOAD_DYLIB",
             0x18: "LC_LOAD_WEAK_DYLIB", 0x19: "LC_SEGMENT_64", 0x1c: "LC_RPATH",
             0x1d: "LC_CODE_SIGNATURE", 0x1f: "LC_ENCRYPTION_INFO", 0x21: "LC_ENCRYPTION_INFO_64",
             0x22: "LC_DYLD_INFO", 0x24: "LC_VERSION_MIN_MACOSX", 0x25: "LC_VERSION_MIN_IPHONEOS",
             0x26: "LC_FUNCTION_STARTS", 0x27: "LC_DYLD_ENVIRONMENT", 0x28: "LC_MAIN",
             0x29: "LC_DATA_IN_CODE", 0x2a: "LC_SOURCE_VERSION", 0x2b: "LC_DYLIB_CODE_SIGN_DRS",
             0x2c: "LC_ENCRYPTION_INFO_64", 0x2e: "LC_LINKER_OPTION", 0x30: "LC_NOTES",
             0x32: "LC_BUILD_VERSION", 0x33: "LC_DYLD_EXPORTS_TRIE", 0x34: "LC_DYLD_CHAINED_FIXUPS",
             0x8000001c: "LC_REEXPORT_DYLIB", 0x80000022: "LC_DYLD_INFO_ONLY",
             0x80000028: "LC_MAIN", 0x8000001f: "LC_ENCRYPTION_INFO_64"}


def split_macho_fat(data):
    """Split a fat Mach-O into slices. Returns (slices, error):
    slices is a list of {arch, cputype, offset, data} or None when
    the file is not fat; error names the slice that cannot be cut."""
    if data[:4] not in _FAT_MAGICS:
        return None, None
    if is_java_class(data):
        # CAFEBABE is also the Java class magic; a class file's
        # version bytes are not a fat header's slice count.
        return None, None
    big = data[:4] == b"\xca\xfe\xba\xbe"
    en = ">" if big else "<"
    if len(data) < 8:
        return None, "fat Mach-O header is truncated"
    nfat = struct.unpack(en + "I", data[4:8])[0]
    if nfat == 0 or nfat > 32:
        return None, f"fat Mach-O header declares {nfat} architecture slices, which is not a plausible slice count"
    slices = []
    for i in range(nfat):
        off = 8 + i * 20
        if off + 20 > len(data):
            return None, f"fat Mach-O header is truncated at slice record {i}"
        cputype, _sub, soff, ssize, _align = struct.unpack(en + "IIIII", data[off:off + 20])
        arch = _CPU_NAMES.get(cputype, f"cputype-{cputype}")
        if soff + ssize > len(data):
            return None, (f"fat Mach-O slice {i} ({arch}) declares {ssize} bytes at offset {soff} "
                          f"but the file has {len(data)} bytes: the slice is truncated")
        slices.append({"arch": arch, "cputype": cputype, "offset": soff,
                       "data": data[soff:soff + ssize]})
    return slices, None


def _parse_superblob(data, off, size):
    out = {"present": True, "parsed": False}
    if off + size > len(data) or size < 12:
        out["error"] = "the code signature superblob runs past the end of the file"
        return out
    blob = data[off:off + size]
    magic, _length, count = struct.unpack(">III", blob[:12])
    if magic != 0xFADE0CC0:
        out["error"] = f"code signature superblob magic is {hex(magic)}, not an embedded signature"
        return out
    out["parsed"] = True
    out["blob_types"] = []
    for i in range(count):
        btype, boff = struct.unpack(">II", blob[12 + i * 8:20 + i * 8])
        out["blob_types"].append(btype)
        if boff + 8 > len(blob):
            continue
        bmagic, blen = struct.unpack(">II", blob[boff:boff + 8])
        sub = blob[boff:boff + blen] if boff + blen <= len(blob) else blob[boff:]
        if btype == 0 and bmagic == 0xFADE0C02 and len(sub) >= 52:
            (_m, _l, version, flags, _hashoff, ident_off, _nspec, _ncode,
             _limit) = struct.unpack(">IIIIIIIII", sub[:36])
            ident = ""
            if ident_off and ident_off < len(sub):
                ident = sub[ident_off:sub.index(b"\x00", ident_off) if b"\x00" in sub[ident_off:] else len(sub)].decode("utf-8", "replace")
            team = ""
            team_off = struct.unpack(">I", sub[48:52])[0] if len(sub) >= 52 else 0
            if team_off and team_off < len(sub):
                team = sub[team_off:sub.index(b"\x00", team_off) if b"\x00" in sub[team_off:] else len(sub)].decode("utf-8", "replace")
            out["code_directory"] = {"version": hex(version), "flags": flags,
                                     "adhoc": bool(flags & 0x2),
                                     "identifier": ident, "team_id": team}
        elif btype == 5 and bmagic == 0xFADE7171:
            xml = sub[8:]
            ent = {"xml_bytes": len(xml), "keys": [], "values": {}}
            try:
                parsed = plistlib.loads(xml)
                if isinstance(parsed, dict):
                    ent["values"] = {k: (v if isinstance(v, (bool, int, str)) else str(v))
                                      for k, v in parsed.items()}
                    ent["keys"] = sorted(parsed.keys())
            except Exception:
                ent["keys"] = sorted(set(re.findall(rb"<key>([^<]+)</key>", xml)))
                ent["keys"] = [k.decode("utf-8", "replace") for k in ent["keys"]]
                ent["parse_note"] = "the entitlements blob is not a parseable plist; keys were recovered by scanning"
            out["entitlements"] = ent
    return out


def parse_macho_slice(data):
    """Parse one thin Mach-O: load commands, libraries, and the code
    signature superblob with its entitlements."""
    out = {"is_macho": False, "parsed": False, "error": None}
    if len(data) < 28:
        out["error"] = "file is too short to be a Mach-O"
        return out
    magic = data[:4]
    if magic in (b"\xcf\xfa\xed\xfe", b"\xce\xfa\xed\xfe"):
        en, is64 = "<", magic == b"\xcf\xfa\xed\xfe"
    elif magic in (b"\xfe\xed\xfa\xcf", b"\xfe\xed\xfa\xce"):
        en, is64 = ">", magic == b"\xfe\xed\xfa\xcf"
    else:
        out["error"] = "not a thin Mach-O (bad magic)"
        return out
    out["is_macho"] = True
    try:
        cputype = struct.unpack(en + "I", data[4:8])[0]
        out["arch"] = _CPU_NAMES.get(cputype, f"cputype-{cputype}")
        out["filetype"] = struct.unpack(en + "I", data[12:16])[0]
        ncmds = struct.unpack(en + "I", data[16:20])[0]
        off = 32 if is64 else 28
        out["load_commands"] = []
        out["libraries"] = []
        out["segments"] = []
        sig = None
        for _ in range(ncmds):
            if off + 8 > len(data):
                raise ValueError(f"load command {_} at offset {off} runs past the end of the file")
            cmd, cmdsize = struct.unpack(en + "II", data[off:off + 8])
            if cmdsize < 8 or off + cmdsize > len(data):
                raise ValueError(f"load command {_} declares {cmdsize} bytes and runs past the end of the file")
            base_cmd = cmd & 0x7FFFFFFF
            out["load_commands"].append(_LC_NAMES.get(cmd, _LC_NAMES.get(base_cmd, hex(cmd))))
            body = data[off:off + cmdsize]
            if cmd in (0x01, 0x19):
                out["segments"].append(body[8:24].rstrip(b"\x00").decode("ascii", "replace"))
            if cmd in (0x0c, 0x1c, 0x8000001c, 0x18, 0x80000018, 0x1f):
                try:
                    noff = struct.unpack(en + "I", body[8:12])[0]
                    out["libraries"].append(body[noff:].split(b"\x00")[0].decode("utf-8", "replace"))
                except Exception:
                    pass
            if cmd == 0x1d:
                doff, dsize = struct.unpack(en + "II", body[8:16])
                sig = (doff, dsize)
            off += cmdsize
        if sig:
            out["code_signature"] = _parse_superblob(data, sig[0], sig[1])
        else:
            out["code_signature"] = {"present": False}
    except (ValueError, struct.error) as e:
        out["error"] = f"Mach-O load commands could not be parsed: {e}"
        return out
    out["parsed"] = True
    return out


def parse_macho(data):
    """Mach-O accounting for one file: fat files are reported as
    their slice list, thin files as their own parse."""
    if data[:4] in _FAT_MAGICS:
        slices, err = split_macho_fat(data)
        if err:
            return {"is_macho": True, "fat": True, "parsed": False, "error": err}
        return {"is_macho": True, "fat": True, "parsed": True,
                "slices": [{"arch": s["arch"], "size": len(s["data"]),
                            **{k: v for k, v in parse_macho_slice(s["data"]).items()
                               if k in ("arch", "parsed", "error", "libraries", "code_signature", "entitlements", "load_commands")}}
                           for s in slices]}
    one = parse_macho_slice(data)
    one["fat"] = False
    return one


# ======================================================================
# Verdict-facing dispatcher
# ======================================================================

def is_jar_signature_member(rel):
    # The release path of a container member joins the container and
    # the member with "!" (app.jar!META-INF/CERT.RSA), so the path
    # must be split on "!" as well as on the directory separators.
    parts = [p for p in re.split(r"[/!\\]", str(rel)) if p]
    if len(parts) < 2 or parts[-2].upper() != "META-INF":
        return False
    up = parts[-1].upper()
    return up.endswith((".SF", ".RSA", ".DSA", ".EC"))


def bytecode_report(name, data, known_files=(), known_classes=(), known_dex_classes=()):
    """Run the wave 2 bytecode accounting for one file. Returns None
    when the file is not a wave 2 class, else a dict:
    {kind, rec, blockers, chains, accounted, references, notes}.
    Blockers are reason strings without the file prefix; the verdict
    attaches them to the file's own record. Chains are yes-reason
    dicts without the file key. References are raw external
    references for the verdict's disposition machinery."""
    base = os.path.basename(str(name).split("!")[-1])
    low = base.lower()
    known = set(known_files)
    # Java class file (standalone or a JAR member)
    if is_java_class(data):
        r = parse_class_file(data, known_classes=known_classes)
        rec = {"kind": "java-class", "this_class": r.get("this_class"),
               "super_class": r.get("super_class"),
               "methods": [{"name": m["name"], "descriptor": m["descriptor"],
                            "decoded": m["decoded"], "instructions": len(m["instructions"]),
                            "invokes": [f"{i['class']}.{i['name']}" for i in m["invokes"]]}
                           for m in r.get("methods") or []],
               "cp_classes": r.get("cp_classes"), "cp_strings": r.get("cp_strings")}
        if not r["parsed"]:
            return {"kind": "java-class", "rec": rec, "accounted": False, "references": [],
                    "chains": [], "notes": [],
                    "blockers": [f"bytecode accounting (java-class): the class file could not be parsed completely: {r['error']}. "
                                 "A class file this build cannot read to the bottom is unaccounted. "
                                 "Next step: supply the file intact, or account for it by byte identity against a genuine reference."]}
        blockers = [f"bytecode accounting (java-class): {u}" for u in r.get("unaccounted_items") or []]
        return {"kind": "java-class", "rec": rec, "accounted": bool(r.get("accounted")),
                "references": r.get("references") or [], "chains": r.get("chains") or [],
                "notes": [], "blockers": blockers}
    # JAR (the file itself; members are separate verdict units)
    if low.endswith((".jar", ".war", ".ear")) and data[:4] == b"PK\x03\x04":
        r = parse_jar(data)
        rec = {"kind": "jar", "manifest": r.get("manifest"), "main_class": r.get("main_class"),
               "class_path": r.get("class_path"), "signers": r.get("signers"),
               "class_members": r.get("class_members"), "nested_jars": r.get("nested_jars"),
               "signer_note": "Signer signature blocks are inventoried (presence and digest algorithms); the signatures themselves are not cryptographically verified in this build."}
        blockers = []
        references = [{"kind": "jar-class-path", "target": t, "source": "JAR manifest Class-Path"}
                      for t in r.get("class_path") or []]
        if not r["parsed"]:
            blockers.append(f"bytecode accounting (jar): the JAR structures could not be read: {r['error']}")
        for s in r.get("signers") or []:
            if not s["has_block"]:
                blockers.append(f"bytecode accounting (jar): signature file {s['signature_file']} has no matching signature block, "
                                "so the JAR's signer claim cannot be inventoried completely")
        return {"kind": "jar", "rec": rec, "accounted": False, "references": references,
                "chains": [], "notes": [], "blockers": blockers}
    # JAR signature member files are PKCS#7 or digest data: identified
    # format, inventoried by the JAR accounting, not code.
    if is_jar_signature_member(name) and data[:1] in (b"\x30",) or \
            (is_jar_signature_member(name) and low.endswith(".sf")):
        return {"kind": "jar-signature", "accounted": True, "references": [], "chains": [],
                "notes": ["JAR signature member: inventoried as data by the JAR accounting. The signature it carries is not cryptographically verified in this build."],
                "blockers": [],
                "rec": {"kind": "jar-signature"}}
    # .NET assembly (PE with a CLR header the IL parser can read)
    if data[:2] == b"MZ":
        r = parse_dotnet_il(data)
        if r.get("is_dotnet_il"):
            rec = {"kind": "dotnet", "assembly_name": r.get("assembly_name"),
                   "runtime_version": r.get("runtime_version"),
                   "assembly_refs": r.get("assembly_refs"),
                   "types": r.get("types"),
                   "methods": [{"name": f"{m.get('owner')}::{m['name']}", "decoded": m["decoded"],
                                "instructions": len(m.get("instructions") or []),
                                "calls": [c["target"] for c in m.get("calls") or []]}
                               for m in r.get("methods") or []],
                   "resources": r.get("resources"),
                   "obfuscation_indicators": r.get("obfuscation_indicators"),
                   "unresolved_string_calls": r.get("unresolved_string_calls", 0)}
            if not r["parsed"]:
                return {"kind": "dotnet", "rec": rec, "accounted": False, "references": [],
                        "chains": [], "notes": [],
                        "blockers": [f"bytecode accounting (dotnet): the assembly's metadata could not be parsed completely: {r['error']}. "
                                     "An assembly this build cannot read to the bottom is unaccounted."]}
            blockers = [f"bytecode accounting (dotnet): {u}" for u in r.get("unaccounted_items") or []]
            notes = [f"obfuscation indicator: {i.get('detail', i) if isinstance(i, dict) else i}"
                     for i in r.get("obfuscation_indicators") or []]
            return {"kind": "dotnet", "rec": rec, "accounted": bool(r.get("accounted")),
                    "references": r.get("references") or [], "chains": r.get("chains") or [],
                    "notes": notes, "blockers": blockers}
    # DEX (standalone or an APK member)
    if is_dex(data):
        r = parse_dex(data, known_files=known, known_classes=known_dex_classes)
        rec = {"kind": "dex",
               "classes": [c["name"].strip("L;").replace("/", ".") for c in r.get("classes") or []],
               "methods": [{"name": f"{m['class']}->{m['name']}", "decoded": m["decoded"]}
                           for c in r.get("classes") or [] for m in c["methods"]],
               "class_details": [{"name": c["name"], "super": c["super"],
                                  "methods": [m["name"] for m in c["methods"]]} for c in r.get("classes") or []]}
        if not r["parsed"]:
            return {"kind": "dex", "rec": rec, "accounted": False, "references": [],
                    "chains": [], "notes": [],
                    "blockers": [f"bytecode accounting (dex): the DEX file could not be parsed completely: {r['error']}. "
                                 "A DEX file this build cannot read to the bottom is unaccounted."]}
        blockers = [f"bytecode accounting (dex): {u}" for u in r.get("unaccounted_items") or []]
        return {"kind": "dex", "rec": rec, "accounted": bool(r.get("accounted")),
                "references": r.get("references") or [], "chains": r.get("chains") or [],
                "notes": [], "blockers": blockers}
    # binary AndroidManifest.xml
    if low == "androidmanifest.xml":
        r = parse_axml(data)
        rec = {"kind": "axml", "package": r.get("package"),
               "permissions": r.get("permissions"), "components": r.get("components")}
        if not r["parsed"]:
            return {"kind": "axml", "rec": rec, "accounted": False, "references": [],
                    "chains": [], "notes": [],
                    "blockers": [f"bytecode accounting (axml): the binary Android manifest could not be parsed: {r['error']}. "
                                 "A manifest this build cannot read is unaccounted."]}
        return {"kind": "axml", "rec": rec, "accounted": True, "references": [],
                "chains": [], "notes": [], "blockers": []}
    # Mach-O (thin or fat parent): recorded; native accounting rules
    # decide the verdict, except an unparsable signature caps by name.
    if data[:4] in (b"\xcf\xfa\xed\xfe", b"\xfe\xed\xfa\xcf", b"\xce\xfa\xed\xfe",
                    b"\xfe\xed\xfa\xce") or data[:4] in _FAT_MAGICS:
        r = parse_macho(data)
        rec = {"kind": "macho", "fat": r.get("fat"), "arch": r.get("arch"),
               "libraries": r.get("libraries"), "load_commands": r.get("load_commands"),
               "code_signature": r.get("code_signature"),
               "slices": r.get("slices")}
        blockers = []
        if not r.get("parsed"):
            blockers.append(f"bytecode accounting (macho): the Mach-O could not be parsed completely: {r.get('error')}")
        else:
            sig = r.get("code_signature") or {}
            if sig.get("present") and not sig.get("parsed"):
                blockers.append(f"bytecode accounting (macho): the code signature superblob could not be parsed: {sig.get('error')}")
            for s in r.get("slices") or []:
                ssig = s.get("code_signature") or {}
                if ssig.get("present") and not ssig.get("parsed"):
                    blockers.append(f"bytecode accounting (macho): the code signature superblob of slice {s.get('arch')} could not be parsed: {ssig.get('error')}")
        return {"kind": "macho", "rec": rec, "accounted": False, "references": [],
                "chains": [], "notes": [], "blockers": blockers}
    return None

