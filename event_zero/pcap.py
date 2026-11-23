"""PCAP quick look: stdlib only parser for global header, Ethernet/IP/UDP/TCP basics, DNS names, HTTP hosts.
For deep work the registry points to tshark when installed."""
import struct
def analyze_pcap(data):
    if data[:4] not in (b'\xd4\xc3\xb2\xa1', b'\xa1\xb2\xc3\xd4', b'\x4d\x3c\xb2\xa1'):
        return {"is_pcap": False, "note": "Not a classic pcap file. If tshark is installed, use it for pcapng and deep protocol work; Event Zero lists tshark in the tool registry."}
    endian='< ' if data[:4]==b'\xd4\xc3\xb2\xa1' else '>'
    endian='<' if data[:4] in (b'\xd4\xc3\xb2\xa1', b'\x4d\x3c\xb2\xa1') else '>'
    off=24; ips=set(); dns=[]; http_hosts=[]; packets=0
    while off+16<=len(data) and packets<10000:
        try: ts_sec, ts_usec, incl, orig = struct.unpack(endian+'IIII', data[off:off+16])
        except Exception: break
        off+=16; pkt=data[off:off+incl]; off+=incl; packets+=1
        if len(pkt)<34: continue
        ip=pkt[14:]
        if len(ip)<20: continue
        src=".".join(str(b) for b in ip[12:16]); dst=".".join(str(b) for b in ip[16:20])
        ips.add(src); ips.add(dst)
        ihl=(ip[0]&0xf)*4; proto=ip[9]; payload=ip[ihl:]
        if proto==17 and len(payload)>=12:  # UDP, DNS port 53
            sport, dport = struct.unpack('>HH', payload[:4])
            if 53 in (sport, dport):
                q=payload[8+12:]; labels=[]; i=0
                while i<len(q) and q[i]!=0 and i<200:
                    ln=q[i]; labels.append(q[i+1:i+1+ln].decode(errors='ignore')); i+=1+ln
                if labels: dns.append(".".join(labels))
        if proto==6 and len(payload)>=20:  # TCP HTTP
            thl=(payload[12]>>4)*4; http=payload[thl:]
            if http[:3] in (b'GET',b'POS') or http[:4]==b'HTTP':
                for line in http.split(b'\r\n')[:15]:
                    if line.lower().startswith(b'host:'): http_hosts.append(line[5:].strip().decode(errors='ignore'))
    return {"is_pcap": True, "packets": packets, "ip_endpoints": sorted(ips), "dns_queries": sorted(set(dns)), "http_hosts": sorted(set(http_hosts)),
            "plain_english": "This is a network capture. Event Zero listed the computers that talked, the names that were looked up, and any plain web hosts. Encrypted traffic shows endpoints and names only, never content."}
