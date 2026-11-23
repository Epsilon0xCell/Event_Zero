"""Firmware and UEFI analysis: magic scan, FV carving, red flags."""
import re, struct
MAGICS=[
 (b'hsqs',"SquashFS filesystem (little-endian)"),(b'sqsh',"SquashFS filesystem (big-endian)"),
 (b'\x1f\x8b\x08',"gzip compressed data"),(b'\xfd7zXZ\x00',"xz compressed data"),
 (b'\x5d\x00\x00',"LZMA compressed data (typical header)"),(b'UBI#',"UBI erase-counter header (flash filesystem)"),
 (b'\x19\x85\x19\x03',"JFFS2 filesystem node"),(b'_FVH',"UEFI firmware volume header signature"),
 (b'\x7fELF',"ELF binary embedded in firmware"),(b'MZ',"PE/DOS binary embedded in firmware"),
 (b'ustar',"tar archive"),(b'PK\x03\x04',"ZIP archive"),
]
def analyze_firmware(data, strings):
    hits=[]
    for magic, name in MAGICS:
        for m in re.finditer(re.escape(magic), data):
            hits.append({"magic": name, "offset": m.start(), "offset_hex": hex(m.start())})
    hits=sorted(hits, key=lambda x: x["offset"])[:200]
    fv=[]
    for m in re.finditer(rb'_FVH', data):
        off=m.start()-40
        if off>=0:
            fv.append({"header_offset": off, "signature_offset": m.start(), "note": "UEFI firmware volume: signature _FVH found at header offset +40, as specified in the UEFI Platform Initialization specification."})
    # carve PE32 inside firmware (DXE drivers are PE32/PE32+)
    dxe=[]
    for m in re.finditer(rb'MZ', data):
        off=m.start()
        if off+0x40<=len(data):
            try: peoff=struct.unpack('<I', data[off+0x3c:off+0x40])[0]
            except Exception: continue
            if 0<peoff<4096 and data[off+peoff:off+peoff+4]==b'PE\x00\x00':
                ctx=[s for s in strings if any(k in s for k in ("Dxe","DXE","Smm","SMM","Uefi","UEFI","Network","Tcp","Http"))]
                dxe.append({"offset": off, "offset_hex": hex(off), "kind": "PE32/PE32+ image inside firmware, consistent with a UEFI DXE driver or UEFI application", "context_strings": ctx[:10]})
    joined="\n".join(strings)
    flags=[]
    def flag(name, ev, why): flags.append({"name":name,"evidence":ev,"plain_english":why})
    if dxe and re.search(r'\b(Tcp|Http|Network|PXE|Dns)\b', joined): flag("DXE driver with network indicators", "network strings near carved PE32 images", "Firmware that can talk to the network before the operating system loads can download code that the operating system and its antivirus never see.")
    if re.search(r'\b(Smm|SMM|System Management Mode)\b', joined): flag("SMM indicator", "SMM strings present", "System Management Mode runs below the operating system with very high privilege. Code there is a classic firmware rootkit hiding place (CHIPSEC flags unexpected SMM code for this reason).")
    if fv and not re.search(r'(SecureBoot|secure boot|dbx|PK\b|KEK)', joined): flag("Firmware volume with no secure-boot strings found", "no SecureBoot/PK/KEK strings", "No evidence of secure boot key material was found in strings. That is not proof secure boot is off, it means this static pass could not confirm it.")
    is_fw = bool(fv) or len([h for h in hits if "SquashFS" in h["magic"] or "UBI" in h["magic"] or "JFFS2" in h["magic"]])>=1 and len(data)>65536
    return {"is_firmware_image": is_fw, "magic_hits": hits, "uefi_volumes": fv, "dxe_drivers_carved": dxe, "red_flags": flags,
            "plain_english": ("This file looks like a firmware image: the code that runs before and underneath the operating system. Event Zero mapped its embedded filesystems and carved the UEFI drivers inside it." if is_fw else "This file does not show strong firmware image structure (no UEFI volume and no flash filesystem signature cluster). The magic scan results are still listed so embedded content is not missed.")}
