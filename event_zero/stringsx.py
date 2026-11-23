import base64, re, string
PRINTABLE=set(bytes(string.printable[:-5],'ascii'))
def ascii_strings(data, min_len=4):
    out=[]; cur=bytearray()
    for b in data:
        if 32<=b<127 or b in (9,):
            cur.append(b)
        else:
            if len(cur)>=min_len: out.append(cur.decode('ascii','ignore'))
            cur=bytearray()
    if len(cur)>=min_len: out.append(cur.decode('ascii','ignore'))
    return out
def utf16_strings(data, min_len=4):
    out=[]
    for enc,pat in (('utf-16le',rb'(?:[\x20-\x7e]\x00){%d,}'%min_len),('utf-16be',rb'(?:\x00[\x20-\x7e]){%d,}'%min_len)):
        for m in re.finditer(pat, data):
            try: out.append(m.group().decode(enc))
            except Exception: pass
    return out
def base64_decoded(strings):
    out=[]
    cand=re.compile(r'^[A-Za-z0-9+/]{12,}={0,2}$')
    for s in strings:
        for tok in re.split(r'[^A-Za-z0-9+/=]', s):
            if len(tok)>=16 and len(tok)%4==0 and cand.match(tok):
                try: dec=base64.b64decode(tok, validate=True)
                except Exception: continue
                txt=''.join(chr(b) if 32<=b<127 else '.' for b in dec)
                if sum(1 for b in dec if 32<=b<127)/max(len(dec),1)>0.8 and len(dec)>=6:
                    out.append({"encoded":tok,"decoded_bytes_text":txt})
    return out[:50]
KEYWORDS=[b'http',b'password',b'socket',b'connect',b'/tmp/',b'.com']
def xor_decoded(data, strings):
    """Single-byte XOR brute force on the whole blob, kept only when the
    result reveals a known keyword and stays mostly printable."""
    out=[]
    joined=b'\n'.join(s.encode() for s in strings)
    for key in range(1,256):
        dec=bytes(b^key for b in data[:200000])
        low=dec.lower()
        hits=[k.decode() for k in KEYWORDS if k in low]
        # require keyword not already visible in raw data
        raw_hits=[k.decode() for k in KEYWORDS if k in data.lower()]
        new=[h for h in hits if h not in raw_hits]
        if new:
            # extract printable runs containing keyword
            runs=[]
            for m in re.finditer(rb'[\x20-\x7e]{6,120}', dec):
                t=m.group().decode()
                if len(t)>=10 and any(h in t.lower() for h in new) and any(ch in t for ch in (' ','.','/','_','-')): runs.append(t)
            if runs: out.append({"key":key,"key_hex":hex(key),"keywords":new,"strings":runs[:20]})
        if len(out)>=10: break
    return out
def extract_all(data):
    a=ascii_strings(data); u=utf16_strings(data)
    alls=a+ [s for s in u if s not in a]
    return {"ascii":a,"utf16":u,"all":alls,"base64_decoded":base64_decoded(alls),"xor_decoded":xor_decoded(data,alls)}
