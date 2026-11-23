"""Kill chain timeline reconstruction from evidence."""
STAGES=[
 ("setup","Setup and arrival", ["exec-shell","file-write","crypto-aes"], "It arrives and sets itself up."),
 ("persistence","Staying power (persistence)", ["persist-file","persist-runkey","persist-schtask"], "It makes sure it comes back after a restart."),
 ("defence_evasion","Hiding from guards (defence evasion)", [], "It tries to hide from the guards."),
 ("discovery","Looking around (discovery)", ["discovery-process","discovery-identity","discovery-sysinfo"], "It looks around to learn about this computer."),
 ("credential_access","Stealing secrets (credential access)", ["cred-access","keylog"], "It tries to steal secret keys and passwords."),
 ("c2","Talking to its boss (command and control)", ["net-socket","net-connect","net-listen","exec-download-run"], "It talks to a far away computer that gives it orders."),
 ("actions","Doing its job (actions on objective)", ["mining","file-delete","inject-process"], "It does the job it came for."),
]
def build_timeline(report):
    cap_ids={c["id"] for c in report.get("capabilities",[])}
    ev_ids={f["id"] for f in report.get("evasion",{}).get("findings",[])}
    out=[]
    for key, name, caps, eli5 in STAGES:
        hit=[c for c in caps if c in cap_ids]
        if key=="defence_evasion" and ev_ids: hit=sorted(ev_ids)
        if key=="actions" and "inject-chain" in ev_ids: hit=hit+["inject-chain"]
        if hit: out.append({"stage": key, "name": name, "evidence_ids": hit, "eli5": eli5,
                            "plain_english": f"Evidence for this stage: {', '.join(hit)}."})
    if report.get("rootkit",{}).get("is_kernel_driver"):
        out.insert(1, {"stage":"persistence","name":"Staying power (persistence)","evidence_ids":["rootkit-driver"],"eli5":"It hides under the floor so it stays.","plain_english":"Kernel driver loading is itself a staying and hiding mechanism."})
    return {"timeline": out, "note": "Order is the logical kill chain order (MITRE ATT&CK tactic order), reconstructed from static evidence. It is not observed timing: the sample was never run, so the report does not claim these steps happened at specific times."}
