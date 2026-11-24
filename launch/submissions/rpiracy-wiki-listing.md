# r/piracy Wiki Listing Draft: Event Zero

Status: DRAFT ONLY. Do not send yet. See READINESS.md in this folder for the conditions that must be true before this is sent.
Prepared: 2026-11-23.

## 1. Route facts

- The r/piracy wiki and megathread are moderator maintained. There is no self-service edit for a listing; a new tool gets in by asking the mod team, which is why this deliverable is an entry text plus a modmail, not an edit we can make ourselves.
- Target page: the megathread Tools page (r/Piracy/wiki/megathread/tools). A local April 2021 copy of that page is held in the project's own research archive and was read for format; current secondary guides to the wiki (read 2026-11-23) confirm the megathread still has a Tools category alongside Software and Unsafe Sites.
- Format on the Tools page: grouped sections with plain headings, entries as a linked name followed by a short factual description of what the tool does. The page also carries standing caution notes (for example, its activation tools table is prefaced with a note that those tools trigger antivirus and that the triggers are false positives). A checking tool belongs in that company: it is the tool you run before deciding whether a warning is a false positive or a real infection.
- Proposed placement: the Tools page, in a safety or checking grouping if the current page has one; if it does not, wherever the mods place pre-run checking tools. The modmail below asks for placement rather than assuming it.
- Direct page fetch note: reddit.com could not be fetched from this environment on 2026-11-23, so the current page text was not re-read live. The format above rests on the project's held April 2021 copy and on current third-party guides to the wiki structure. Before sending, one live read of the current Tools page should confirm the section names, and the modmail already asks the mods to place the entry, which covers a format change.

## 2. The exact proposed entry text

Wiki markdown, ready to paste:

```markdown
**Event Zero** - [GitHub](https://github.com/Epsilon0xCell/Event_Zero) - Free offline tool that checks a downloaded file, installer, archive, or release folder before you run it, and gives a proof-backed YES or NO on whether it contains malware, with the evidence attached in a plain English report. It reads files as bytes and never executes them. A NO is issued only when every byte is accounted for as genuine or as an explained crack. Anything it cannot account for stays listed as an open case, not a pass. The crack itself (a patched licence check, a keygen, KMS emulation) is treated as the expected crack, not as malware.
```

One line version, if the section uses single line entries:

```markdown
- [Event Zero](https://github.com/Epsilon0xCell/Event_Zero) - Offline pre-run malware check for downloads and cracks: proof-backed YES or NO, evidence attached, never executes the file, and anything it cannot account for stays an open case instead of a pass.
```

## 3. The modmail draft (wiki listing request)

Send to: r/piracy modmail. Subject and body below.

Subject:

```
Request to list a free pre-run malware checking tool in the megathread Tools page
```

Body:

```
Hello mods,

I am the author of Event Zero, a free tool on GitHub, and I am asking whether it can be listed on the megathread Tools page. Declaring the interest up front: it is my project, and there is nothing to sell. There is no paid tier.

What it does, in one paragraph: you point it at a file, installer, archive, or release folder you have downloaded, before running anything. It reads the files as bytes and never executes them. It then gives a YES or NO on whether the release contains malware, with the evidence for the verdict in a plain English report. A YES names the behaviour chains it proved (for example a credential stealer, or persistence plus a remote host). A NO is issued only when every byte is accounted for as genuine or as an explained crack difference. If part of a release cannot be accounted for, the case stays open and the headline stays on the safe side; the tool does not guess a clean result. The crack itself is not counted as malware: patched licence checks, keygens, and KMS emulation are treated as the expected crack.

Repo: https://github.com/Epsilon0xCell/Event_Zero

It runs offline with no account and no API key. The repo includes a synthetic test sample and example reports, so anyone can try it without handling real malware:

    python3 -m event_zero verdict fake_malware

prints YES: MALWARE FOUND with the proof listed. A clean crack example with a NO verdict is in examples/clean_crack.verdict.txt, and a short demo video recorded from real runs is in the repo under demo/.

Proposed entry text, if you are willing to list it. Wording and placement are entirely yours to change:

**Event Zero** - [GitHub](https://github.com/Epsilon0xCell/Event_Zero) - Free offline tool that checks a downloaded file, installer, archive, or release folder before you run it, and gives a proof-backed YES or NO on whether it contains malware, with the evidence attached in a plain English report. It reads files as bytes and never executes them. A NO is issued only when every byte is accounted for as genuine or as an explained crack. Anything it cannot account for stays listed as an open case, not a pass.

If the answer is no, or not yet, that is fine. If you want changes first (a release download, a different description, more testing), tell me what would make it listable and I will do that work before asking again.

Thank you for maintaining the megathread.
```

## 4. Notes for whoever sends this

- Send the wiki modmail and the post approval modmail (rpiracy-post-modmail.md in this folder) as separate messages, wiki first. Do not combine them; each asks for one decision.
- If the mods reply with conditions, the conditions get done and verified before any follow-up. One ask, then silence until they answer.
