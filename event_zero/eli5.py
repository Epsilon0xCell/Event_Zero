"""ELI5 generator: deterministic, template based, evidence bound.
Every sentence is built from a capability or finding that exists in the report.
Jargon rule: a banned word may only appear if its plain translation is in the same sentence.
"""
ANALOGIES={
 "net-socket": ("talking on a phone", "It can open a phone line to talk to another computer."),
 "net-connect": ("calling a bad friend", "It can call out to a far away computer, like calling someone on the phone."),
 "net-listen": ("waiting by the door", "It can wait by the door and let other computers knock and come in."),
 "exec-shell": ("a magic remote control", "It can type orders into the computer. The magic remote types for it."),
 "exec-download-run": ("fetching a new toy and playing with it right away", "It can fetch a new file. Then it runs it right away."),
 "persist-file": ("hiding a spare key", "It hides a spare key so it can come back after the computer restarts."),
 "persist-runkey": ("putting its name on the wake up list", "It puts its name on the wake up list."),
 "persist-schtask": ("setting an alarm clock", "It sets an alarm clock that wakes it up again later."),
 "discovery-process": ("looking around the room", "It looks around to see what other programs are in the room."),
 "discovery-identity": ("reading a name tag", "It reads the name tag to learn who uses this computer."),
 "discovery-sysinfo": ("reading the label on a box", "It reads the label to learn what kind of computer this is."),
 "file-write": ("writing in a notebook", "It can write new files, like writing in a notebook."),
 "file-delete": ("rubbing out pencil marks", "It can rub out files, like rubbing out pencil marks to hide what it did."),
 "file-chmod-exec": ("putting shoes on a file", "It can put shoes on a file so the file can run and move."),
 "cred-access": (" peeking at a key box", "It looks where secret keys and passwords are kept."),
 "mining": ("using your bike to carry its shopping", "It uses your computer power for its own work, like using your bike to carry its shopping."),
 "inject-process": ("hiding inside a friend's coat", "It can hide inside another program, like hiding inside a friend's big coat."),
 "inject-chain": ("hiding inside a friend's coat", "It can hide inside another program, like hiding inside a friend's big coat."),
 "anti-debug": ("checking if a teacher is watching", "It checks if a grown up is watching it, and acts good when watched."),
 "keylog": ("copying every letter you type", "It can copy the letters you type, like someone reading over your shoulder."),
 "crypto-aes": ("locking things in a safe", "It can lock things in a safe so only someone with the key can read them."),
}
DEFAULT=("a new trick", "It can do something the report lists, and the grown up part of the report shows the proof.")
BANNED=["syscall","entropy","payload","persistence"]
TRANSLATIONS={"syscall":"a direct ask to the computer's core, called a syscall in grown up words","entropy":"mixed-up-ness, called entropy in grown up words","payload":"the main bad part, called a payload in grown up words","persistence":"staying power, called persistence in grown up words"}

def _cap_sentences(report):
    out=[]
    for c in report.get("capabilities",[]):
        analogy, simple = ANALOGIES.get(c["id"], DEFAULT)
        out.append(f"Think of it like {analogy.strip()}."); out.append(simple)
    # advanced findings also become ELI5 claims, each mapped to its finding id
    adv=[]
    for f in report.get("evasion",{}).get("findings",[]):
        adv.append((f["id"], "Think of it like wearing a disguise.")); adv.append((f["id"], f"It tries a trick so the guards do not spot it."))
    if report.get("rootkit",{}).get("is_kernel_driver"):
        adv.append(("rootkit-driver","Think of it like hiding under the floor.")); adv.append(("rootkit-driver","It lives under the floor. The guards in the house cannot see it there."))
    if report.get("firmware",{}).get("is_firmware_image"):
        adv.append(("firmware-image","Think of it like the first page of a book.")); adv.append(("firmware-image","This part wakes up first. A bad page here is hard to spot."))
    if report.get("exploit",{}).get("egghunter_detected"):
        adv.append(("exploit-egghunter","Think of it like a treasure hunt.")); adv.append(("exploit-egghunter","A tiny helper hunts for the big bad part. It is hidden in the house."))
    return out, adv

def generate_eli5(report):
    lines=[]
    name=report.get("filename","this file")
    verdict=report.get("risk",{}).get("verdict","")
    lines.append(f"This is about a computer file called {name}.")
    if report.get("eicar_test_file"):
        lines.append("This one is a pretend bad file. It is a test. It can not hurt a computer.")
        lines.append("Grown ups use it to check that their guard tools work.")
        return lines
    if "HIGH RISK" in verdict:
        lines.append("This file looks bad. It does things a good file should not do.")
    elif report.get("capabilities"):
        lines.append("This file does some things that need a close look.")
    else:
        lines.append("We did not find bad tricks in this file. That is not a promise that it is good.")
    caps, adv=_cap_sentences(report)
    lines.extend(caps)
    lines.extend(s for _,s in adv)
    if report.get("unpack",{}).get("virtualization",{}).get("detected"):
        lines.append("Think of it like a story in a secret language."); lines.append("We can see the book. We can not read every page yet.")
    if report.get("unpack",{}).get("upx",{}).get("detected"):
        lines.append("Think of it like a squished teddy in a box."); lines.append("The file is squished down. It puffs back up when it runs.")
    lines.append("What should you do? Do not open it. Give it to a grown up who studies bad files.")
    lines.append("This simple part says only what the proof shows."); lines.append("It does not add new proof.")
    lines.append("A picture in words is not exact.")
    lines.append("Real code does more than any one picture can show.")
    return lines

def eli5_claim_ids(report):
    ids=[c["id"] for c in report.get("capabilities",[])]
    ids += [f["id"] for f in report.get("evasion",{}).get("findings",[])]
    if report.get("rootkit",{}).get("is_kernel_driver"): ids.append("rootkit-driver")
    if report.get("firmware",{}).get("is_firmware_image"): ids.append("firmware-image")
    if report.get("exploit",{}).get("egghunter_detected"): ids.append("exploit-egghunter")
    return ids
