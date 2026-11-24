# r/piracy Post Approval Modmail Draft: Event Zero

Status: DRAFT ONLY. Do not send yet. See READINESS.md in this folder for the conditions that must be true before this is sent.
Prepared: 2026-11-23.

## 1. Purpose and route facts

- This modmail asks permission for one self-post about Event Zero in r/piracy. Subreddit rule 2, as recorded on the megathread Tools page copy held in the project's research archive, covers spam and blatant self-promotion posts, so a tool post from its author needs moderator approval first. This message is that request.
- It is sent separately from, and after, the wiki listing modmail (rpiracy-wiki-listing.md). One decision per message.
- The post it describes does not exist yet and is not drafted here. If the mods approve, the post is written to match whatever conditions they set, and it leads with a real verdict on a real case and the demo video, as stated in the request.

## 2. The modmail draft

Send to: r/piracy modmail. Subject and body below.

Subject:

```
Permission request: one post about a free malware checking tool I built
```

Body:

```
Hello mods,

Asking permission before posting, because the tool is mine and I do not want to break the self-promotion rule.

The tool: Event Zero, free, source public on GitHub, works offline.
Repo: https://github.com/Epsilon0xCell/Event_Zero

It checks a downloaded file, installer, archive, or release folder before you run it, reads it as bytes, never executes it, and gives a proof-backed YES or NO on whether it contains malware, with the evidence in a plain English report. A NO requires every byte accounted for as genuine or as an explained crack. Anything it cannot account for stays an open case, not a pass.

The post I would like to make:

- Title along the lines of: I built a free offline tool that gives a YES or NO verdict on whether a crack contains malware, with the proof attached. Here is a real case.
- Body leads with a real verdict on a real case: the bundled synthetic sample, Case 001, where the tool returns YES: MALWARE FOUND and names the three behaviour chains it proved (a credential stealer, persistence plus a remote host, and a miner), with the full report linked so anyone can re-run it and check.
- It includes the demo video from the repo (about 111 seconds, recorded from real terminal runs, no staged output).
- It includes the opposite case as well: a clean crack that earned a NO, with its accounting, and a case that stayed open because part of the file could not be accounted for.
- It states the limits plainly in the post: the tool cannot fully decompile packed or virtualized code, a payload keyed to a dead server cannot be accounted for, and a NO is an accounting statement about that file and that reference, not a promise about every file.
- No download link other than the GitHub repo, no paid anything, no mailing list, no Discord to join.

I will answer questions in the thread, including hard ones, and if the verdict on a case is challenged I will re-run it in public.

If a post like this is not welcome, I accept that and will not post it. If it is welcome with conditions (different title, no video, a specific flair, posting in a weekly thread instead), tell me the conditions and I will follow them exactly.

Thank you.
```

## 3. Claims discipline inside this draft

- The draft says "proof-backed YES or NO", "fail-closed" behaviour described in plain words ("stays an open case, not a pass"), and states the tool's limits in the request itself. It makes no accuracy claim, no detection rate claim, and no comparison against antivirus products or VirusTotal.
- The Case 001 facts (verdict headline, three behaviour chains) are copied from examples/fake_malware.verdict.txt in the repository, the same report any reader can reproduce.
- The demo video length (about 111 seconds) and its real-runs property are from demo/SCRIPT.md in the repository.
