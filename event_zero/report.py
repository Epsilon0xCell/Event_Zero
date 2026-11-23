import json
def to_text(r):
    L=[]
    L.append("EVENT ZERO: PLAIN-ENGLISH MALWARE REPORT"); L.append("="*60)
    L.append(f"File: {r['filename']}  ({r['size_bytes']} bytes)"); L.append(f"Path analysed: {r['file']}")
    L.append(f"Parser backend: {r['parser_backend']}   Disassembly available: {r['disassembly']['available']}")
    L.append(""); L.append("1. IDENTITY AND HASHES")
    for k,v in r['hashes'].items(): L.append(f"  {k}: {v}")
    L.append(f"  EICAR test file: {r['eicar_test_file']}")
    L.append(""); L.append("2. WHAT THIS FILE IS, IN PLAIN ENGLISH")
    for p in r['plain_english']: L.append(f"  {p}")
    f=r['format']; L.append(""); L.append("3. FORMAT AND ARCHITECTURE")
    for k in ('format','variant','architecture','object_type','entry_point','load_commands'): 
        if k in f: L.append(f"  {k}: {f[k]}")
    if f.get('libraries'): L.append(f"  libraries: {f['libraries']}")
    if f.get('linked_libraries'): L.append(f"  linked libraries: {f['linked_libraries']}")
    if f.get('segments'): L.append(f"  segments: {f['segments']}")
    L.append(""); L.append("4. SECTIONS AND PACKING")
    for s in r['sections']: L.append(f"  {s}")
    for p in r['packing_assessment']: L.append(f"  {p}")
    L.append(f"  Overall entropy: {r['overall_entropy']} / 8.0")
    L.append(""); L.append("5. IMPORTED FUNCTIONS, EXPLAINED")
    if r['imports']:
        for i in r['imports']: L.append(f"  {i['name']}: it {i['plain_english']}")
    else: L.append("  None could be listed. See Unknowns.")
    L.append(""); L.append("6. STRINGS FOUND IN THE FILE")
    L.append(f"  Total: {r['strings']['count']} (ASCII {r['strings']['ascii_count']}, UTF-16 {r['strings']['utf16_count']})")
    for s in r['strings']['all'][:300]: L.append(f"  - {s}")
    L.append(""); L.append("7. DECODED STRINGS (things the file tried to hide)")
    L.append(f"  Base64 decoded: {r['strings']['base64_decoded'] or 'none found'}")
    L.append(f"  XOR decoded: {r['strings']['xor_decoded'] or 'none found'}")
    L.append(""); L.append("8. CAPABILITIES (capa-style, mapped to MITRE ATT&CK)")
    if r['capabilities']:
        for c in r['capabilities']: L.append(f"  [{c['attack_id']}] {c['name']} ({c['tactic']}: {c['technique']})\n    {c['explanation']}\n    Evidence: {', '.join(c['evidence'])}")
    else: L.append("  No built-in capability rule matched.")
    L.append(""); L.append("9. DISASSEMBLY AND FUNCTIONS")
    L.append(f"  {r['disassembly']['note']}  Instructions shown: {min(len(r['disassembly']['instructions']),500)}")
    for ins in r['disassembly']['instructions'][:200]: L.append(f"  {ins['address']}: {ins['text']}")
    if r['script_analysis']: L.append(f"  Script analysis: {r['script_analysis']}")
    if r['script_source_excerpt']: L.append("  Script source excerpt:\n" + "\n".join("    "+x for x in r['script_source_excerpt'].splitlines()[:60]))
    L.append(""); L.append("10. INDICATORS OF COMPROMISE (IOCs)")
    for k,v in r['iocs'].items(): L.append(f"  {k}: {v or 'none found'}")
    L.append(""); L.append("11. RISK VERDICT")
    L.append(f"  {r['risk']['verdict']}  (rule score {r['risk']['score']}/100)")
    for x in r['risk']['reasons']: L.append(f"  - {x}")
    L.append(""); L.append("12. UNKNOWNS: WHAT STATIC ANALYSIS COULD NOT DETERMINE")
    for u in r['unknowns']: L.append(f"  - {u}")
    L.append(""); L.append("End of report. The sample was read as bytes and was never executed.")
    return "\n".join(L)+"\n"
def to_markdown(r):
    t=to_text(r)
    return "# Event Zero Report: "+r['filename']+"\n\n```text\n"+t+"```\n"
def to_json(r):
    return json.dumps(r, indent=2, default=str)
