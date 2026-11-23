# r/Piracy Archive Mining: Malware in Pirated Software

Mined for the Event Zero verdict feature (binary YES/NO malware verdict on cracked software). Source: Mister Blacklock's own local r/Piracy harvest, not the live web. Compiled 2026-11-23.

## 1. Where the data lives and what was mined

Archive root: `~/workspace/research/rpiracy-community-archive/` (protected research archive).

- Posts and comments: `data/raw/api/posts_YYYY-MM.jsonl` and `data/raw/api/comments_YYYY-MM.jsonl`, harvested from Arctic Shift. Posts: 211 monthly files spanning 2009-05 to 2026-11; the progress manifest (`manifests/api_progress.json`) banks 525,247 post records. Comments: 99 merged monthly files plus 141 in-progress slice files under `data/raw/api/.parts/`; the manifest banks 1,438,457 comment records.
- Wiki and megathread copies: `data/raw/recovery-sweep/archive-org/piracy_megathread.zip` (11 megathread wiki pages, April 2021), `data/raw/recovery-sweep/archive-org/megathread-piracy.html` (megathread index, February 2025), and `data/raw/recovery-sweep/wiki-mirrors/` (rentry mirrors).
- Method: full-text keyword scan of every post (title plus selftext) and every comment (body) for a malware term set (malware, virus, trojan, infected, keylogger, stealer, ransomware, backdoor, spyware, rootkit, botnet, miner variants, false positive, virustotal, is it safe, activator, kms, keygen, antivirus, windows defender, malwarebytes, and variants). Hits: 23,077 post records and 53,012 comment records raw; after dedup by record id, 22,829 posts and 28,436 comments formed the mined corpus.
- Coverage caveat, stated plainly: the post corpus spans the subreddit's whole life, but the comment harvest is still in progress and is weighted toward the early years and toward 2025 to 2026 slices. Several famous older threads therefore show a post but few or no harvested comments locally (for example the SadeemPC thread, section 3). Frequencies below are frequencies inside this mined corpus, not inside all of Reddit.

## 2. Corpus shape: what the community talks about

Post term frequency (posts mentioning the term, out of 22,829 malware-context posts):

| Term | Posts |
|---|---|
| virus | 8,899 |
| malware | 4,871 |
| kms | 2,501 |
| is it safe | 2,104 |
| keygen | 1,938 |
| false positive | 1,596 |
| trojan | 1,572 |
| virustotal | 1,542 |
| antivirus | 1,499 |
| windows defender | 1,230 |
| malwarebytes | 1,156 |
| activator | 1,063 |
| infected | 557 |
| spyware | 298 |
| ransomware | 149 |
| backdoor | 148 |
| coin miner / crypto miner / cryptominer | 226 combined |
| stealer | 93 |
| keylogger | 79 |
| botnet | 52 |
| rootkit | 31 |

Comment term frequency (out of 28,436 deduped hit comments): virus 12,507; malware 8,766; antivirus 2,605; false positive 2,044; windows defender 1,717; virustotal 1,616; kms 1,451; trojan 1,429; infected 1,106; malwarebytes 1,085; keygen 1,014; spyware 977; stealer 395; rootkit 267; botnet 265; ransomware 250.

Reading: the dominant community activity is not incident reporting. It is verdict anxiety: is this flagged file actually dangerous, and can this source be trusted. "Is it safe" style questions plus false positive discussion together outweigh named incident reports by orders of magnitude. 7,728 posts carry a core malware term in the title itself.

## 3. Concrete named incidents found in the archive

Each entry: date of the r/Piracy post, what the post itself states. These are community reports as recorded in the archive; inclusion means the community treated them as incidents, not that each was independently forensically confirmed.

1. **uTorrent bundled bitcoin miner (EpicScale), recalled in the April 2021 megathread tools page.** The wiki states BitTorrent Inc. "bundled malware (a bitcoin miner) into uTorrent in the past, it is not trustworthy", calls BitLord "malware" outright, and steers users to qBittorrent, Transmission, and the pre-malware uTorrent 2.2.1 build from 2011. Separately, "A uTorrent ad is using a flash exploit to install malware" (2017-05-12, score 1004) and "uTorrent Flagged as 'Threat' by Microsoft and Anti-Virus Vendors" (2018-04-12, score 971).
2. **TPB user "zElvaakq" fake-seeder uploads, 2017-01-05** (score 1,693): "His uploads contains a file named 'Setup.exe'. He uses fake seeders to trick you into installing PUP and malware."
3. **TPB user "boysetsfire221" flooding the site with malware, 2018-05-12** (score 7,802, 413 comments): "BEWARE: User 'boysetsfire221' is flooding Pirates Bay with malware."
4. **TPB games section flooded with disguised viruses, twice**: "WARNING: The Pirate Bay currently has countless viruses disguised as games up" on 2018-02-27 (score 1,814) and again 2018-06-08 (score 2,162). A companion analysis post the same day (2018-06-08) dissected one of the "virus" torrents.
5. **Games4Up distributing malware via FitGirl repacks, 2018-03-13** (score 615): an early documented case of a third-party site re-uploading a trusted repacker's name with malware attached, the impersonation pattern in section 6.
6. **COREPACK repacks, 2018-07-07** (score 1,248): "COREPACK are indeed putting malware in their repacks." The post body was later deleted; the title and score stand in the archive.
7. **Ableton Live 10 Mac torrent with a cryptocurrency miner, 2018-06-11** (331 comments on the thread): a user reports a cracked Ableton Live 10 download "ended up giving me cryptocurrency mining malware".
8. **IGG Games, recurring, 2019 to 2026.** "PSA: IGG Games include trojan in new Human Fall Flat update" (2020-03-01, score 856). A heavily upvoted comment in the 2026-01-13 FitGirl thread recaps the community case against IGG with links: ads built into games at runtime, DRM added to releases, "cryptominers and startup malware included in their games" (linking a 2019 r/Piracy thread, "I think I found an infected game on igggamescom"), browser hijacker install attempts, and hostile JavaScript on their website. IGG is the single most persistently accused named source in the corpus relative to its size: 473 malware-context posts and 411 comments.
9. **Vegas Pro 17 torrents carrying ransomware, 2019-08-30** (score 1,672): "PSA | Ransomware (All Current Vegas Pro 17 Torrents)". The poster reports files encrypted with the .ADAME extension days after installing a TPB Vegas Pro 17 copy "complete with an activator" that appeared to work normally.
10. **BBRepacks DOOM Eternal repack, 2020-03-21** (score 686, 460 comments): the post documents the payload precisely: the repack starts `FirewallModule.exe` from `%APPDATA%\Microsoft\Firewallmodule\`, writes an AutoRun value under the Command Processor registry key and Shell values under Winlogon keys, and links a VirusTotal report. The torrent was removed from 1337x but remained on TPB at posting time.
11. **SadeemPC banned from 1337x, 2021-05-19** (score 3,734, 457 comments): "SadeemPC banned from 1337x after malware was found." A platform-level enforcement action against a known software uploader, reported by the community as fact.
12. **Malicious uploaders on 1337x, named one by one**: "SunRiseZone on 1337x is spreading malware!" (2022-03-17); "PSA: Uploader 'PROAC12' on 1337x uploads malware" (2022-07-03); "1337x fake torrents linking to malware" (2024-11-05).
13. **Ocean of Games, called out by a game developer, 2019-03-12** (score 315): the developers of The Savior's Gang post that OceanOfGames lists their roughly 2 GB game at over 5 GB and ask what fills the extra 3 GB, noting they already knew of uploads "with some small malware". Size mismatch against the genuine release as a detection signal comes straight from a victim developer here.
14. **SteamUnlocked, chronic suspicion**: "Tried using Steamunlocked, but I keep getting this message when trying to launch my game, is it a virus?" (2024-02-18, 341 comments); "Heard my friend raving about SteamUnlocked, told him to try malwarebytes..." (2023-09-22, score 1,518); a 2026-08-22 post mocks the defence "Steamunlocked isn't that bad I never got a virus from it after 6 years!". Contrast in the same corpus: SteamRIP is repeatedly praised for re-verifying uploads, one user (2025-07-07) describing a game taken down after a VirusTotal flag and restored days later "back online and with no malware. they verify all games to be clear before upload."
15. **DownloadPirate, a megathread-listed site, long tail of accusations**: at least 20 distinct posts from 2024 to 2026, including "downloadpirate.com contains a virus", "Got multiple Trojans from Downloadpirate" (2026-02-20), a 2024-08-29 report (346 comments) of Discord and Spotify accounts hacked days after installing Office from the site despite an AV reporting nothing, a 2025 report naming dropped files "Gevaldiges.exe or Killas.exe" and calling it a RAT infection, and a 2026-02 post reporting a random outbound connection to downloadpirate when the site was not open. Also a defender's data point (2025-07-18): an older version of a title from the site checks clean on VirusTotal while the current one fails checks.
16. **Disguised episode torrent with an .scr payload, 2025-07-27** (score 4,701, 294 comments): "Possible malware in popular torrent". A .scr file posing as a Rick and Morty episode with over 4,000 seeds. Commenters confirmed by VM detonation that it was an infostealer, and the top comment (score 3,137) advises blocking .scr and other common malware vectors in qBittorrent. The same thread notes .arj archives as a rising vector: an archive holding "a single password-protected executable with instructions like 'Run this to install'".
17. **heroskeep repacks and the FitGirl accusation, 2026-01-13** (score 4,922): "FitGirl is claiming another Repacker Is spreading malware." Comments allege it took "almost 2 years of warnings" before the community accepted that heroskeep "was repacking miners and some other viruses then uploading them to fitgirl['s name/sites]", and one commenter reports a 1337x torrent under that name infecting them long before.
18. **DODI's website, 2026-11-12** (score 1,548): "DODI's real legacy is the malware infested website he left everyone to download his repacks." The complaint targets the site and its ad chain, not the repacks themselves; the poster says they ended up finding torrents under his username directly. A separate 2023-09-26 post reports a trojan alert from a DODI Armored Core update file. The distinction between a clean release group and a hostile download site carrying its name is a recurring theme (see also Games4Up/FitGirl, item 5).
19. **Fake AAA releases by size, 2026-06-14** (score 2,807): "TOP DOWNLOADS ARE VIRUSES AT THE MOMENT, BE CAREFUL WITH DOWNLOADS." Commenters identify a "Forza Horizon 6, 500 MB" torrent as an obvious virus that roughly 29,000 people downloaded anyway: a headline game at a fraction of its real size is treated as a self-evident tell.
20. **MAS impostor command, 2026-01-17**: a highly upvoted comment defending MAS notes a recent incident where users ran "an intentionally misspelled impostor command not the actual MAS script on Massgrave": the activation command itself was typosquatted, so the check is the exact command string from the official page, not the tool's name.

## 4. Which release types get accused most

Mentions inside malware-context posts (title) and comments (body), mined corpus:

| Release type | Post titles | Comments |
|---|---|---|
| crack (the word) | 1,566 | 2,358 |
| keygen | 1,541 | 1,060 |
| torrent (file or site context) | 1,383 | 1,941 |
| activator / KMS / MAS | 1,218 | 1,095 |
| installer / setup / install | 453 | 1,843 |
| repack | 401 | 480 |
| patch / patcher | 173 | 246 |
| DLL | 181 | 322 |
| APK / mod apk | 160 | 207 |
| trainer | 11 | 19 |

Named sources and groups inside malware-context posts (title plus selftext) and comments, for scale: KMSPico 1,053 posts / 750 comments; FitGirl 587 / 551; IGG 473 / 411; 1337x 363 / 260; SteamRIP 302 / 316; RuTracker 192 / 122; DODI 190 / 217; SteamUnlocked 180 / 83; FileCR 190 / 46; uTorrent 195 / 243; GetIntoPC 125 / 37; The Pirate Bay 112 / 68; RARBG 99 / 21; Skidrow 79 / 49; CODEX 68 / 19; AnkerGames 64 / 61; RELOADED 62 / 41; EMPRESS 32 / 14; RUNE 21 / 22; CS.RIN 43 / 31.

How to read this honestly: mention counts mix accusations, defence, questions, and impersonation reports. FitGirl's high count is mostly questions and impersonator cases, and the community's settled view in the corpus is that her own site is the reference source. KMSPico's count is mostly the absence of any official source (section 8). IGG and SteamUnlocked carry the highest share of outright accusations. Raw accusation volume tracks popularity as much as dirtiness, which is exactly why Event Zero must verdict files, not reputations.

## 5. Community heuristics, in their own logic

Paraphrased from high-scoring comments in the mined corpus, with short quotes where the wording itself is the heuristic.

1. **Source first, file second.** The single most repeated rule: verdicts attach to where a file came from before what any scanner says. "In the piracy world you can't really use AV to determine if files are clean or not. Instead you should use the reputation of the uploader and the site" (2026-01-04). Stick to the megathread and FMHY, and treat even those as fallible: "if something seems fishy then don't trust it, even if it's on the megathread" (2025-04-14, score 753).
2. **Read the detection name, not the count.** A label naming a crack, keygen, hacktool, PUA, riskware, "packed" or "VMProtect" is treated as the scanner describing crack behaviour; a label naming a specific malware family is treated as a real finding. "A false positive would be where they warn you it's a keygen or a crack, but don't list anything specific like the name of a trojan or malware. This one does name specifics. Don't use it." (2026-01-28). Another user (2026-02-03) gives the three-sign version: few detections, all from weak engines, all generic ("MALICIOUS", "Heuristics", "AI Detection") means likely safe.
3. **Weight the engines.** Detections are weighted by vendor reputation: Bitdefender, ESET, Malwarebytes, Kaspersky, Trend Micro count; unknown engines are discounted as the source of "dozens of false positives" (2025-09-10). One popular rule (2025-03-08, score 88): check what Kaspersky says specifically, because most vendors "automatically flag" anything using a protector or crypter. The mirror heuristic also appears: if a file were truly malicious, "it makes no sense for the majority to not detect it" (2025-08-16).
4. **Small counts get shrugged, big counts do not.** "Up to 5 detections you can just shrug it off" (2025-08-16, score 115). At the other end, users balk at rationalising 45 detections as all false positives (2025-09-01), and onlinefix64.dll at "47/72" is the community's stock example of a legitimately scary-looking clean file.
5. **Upload the executable, not the archive; hash when it is too big.** Extract first ("just extracting a zip can't hurt you"), upload the .exe to VirusTotal for efficient analysis, and for files over roughly 650 MB compute a SHA-256 and search the hash instead (2025-04-15, score 68). Hash lookup through a sandbox or VM if the file itself is suspect (2026-06-15).
6. **Block hostile extensions in the torrent client.** Block .scr and similar vectors in qBittorrent (top advice in the 2025-07-27 stealer thread, score 3,137). Watch .arj and any archive containing one password-protected executable plus "run this to install" instructions. Media files that are actually executables are a standing tell.
7. **Size sanity.** A release wildly smaller than the genuine product (a 500 MB "Forza Horizon 6") is malware until proven otherwise; wildly larger is also evidence (the Ocean of Games developer case, section 3 item 13). Attackers rarely pad a small payload up to a realistic multi-GB size, a point raised explicitly in the 2026-06-14 thread.
8. **Seed counts prove nothing.** Fake seeders are a documented attack (section 3 item 2), and the 2025-07-27 stealer had over 4,000 seeds: "high seeds doesn't usually mean [safe]... It's to trick you into thinking that's a legit torrent."
9. **Detonate when unsure.** Run it in a VM or a sandbox service (any.run, tria.ge are named) and read or share the behaviour report: process injection, hooks, anti-debugging, VM detection, GetKeyState keylogging indicators, screen capture APIs. One 2026-11-06 comment (score 3,659) posts exactly such a behaviour list as the way a verdict gets made. Caveat repeated in the same threads: some malware detects or escapes VMs, so scan the host afterwards too.
10. **Torrent hashes bound the damage.** A torrent's per-chunk hashes mean a seeder cannot slip you different bytes than the torrent defines: "if someone tries to spread a malicious chunk, other leeches can't download them as the hash of that chunk would never match" (2025-07-27). The risk lives in the originally authored torrent and in what you run, not in fellow peers.
11. **Compare against the same file elsewhere.** If every other source ships the identical file, a lone flag is likely the file, not your source (2025-05-20, on a DownloadPirate Cinema 4D flag). Conversely a file that changed between versions from the same site, where the old one was clean, is treated as a real warning (2025-07-18).
12. **Exclusions are a loaded gun.** The standard crack setup (an antivirus-excluded folder) is taught with an explicit warning: "nothing in that folder will ever be scanned... and will have free realm inside your PC if it happened to be malicious and not a false positive" (2025-03-16).
13. **Separation of machines.** The paranoid tier: a sacrificial second system or dual boot for warez, no core accounts on it, encrypted main disk, because "virus will not able integrate to your files" across that boundary (2025-10-07).
14. **Symptoms as retrospective detection.** GPU fans spinning and a GPU "held hostage" equals miner until proven innocent (2026-01-13 and 2026-01-15 comments); accounts hacked days after an install with a clean AV result equals stealer behaviour, because a trojan "seems fine but actually it's not" (2025-10-06). A visible console window flashing is, counterintuitively, read as a good sign: "any sophisticated malware would not let a window pop up" (2026-01-14).

## 6. Recurring false-positive explanations

These explanations recur hundreds of times (1,596 posts and 2,044 comments mention "false positive") and form the community's shared model of why cracks flag:

1. **Modification is the trigger.** "Any cracked file is going to have some positive results on virustotal. Cracked files are modified, and thats basically what virus scanners are looking for." (2026-01-04). "Modified DLLs, patched executables, unpackers, loaders, or anything that tampers with the original protection can easily look suspicious to an antivirus." (2026-04-30).
2. **Injection is the crack's job.** Steam emulator DLLs (Goldberg, onlinefix) inject and hook by design: "Emulator... injects itself and do other stuff... so it's marked. Example here are Goldberg and cold steam client" (2025-11-02). A replacement DLL that does not inject "just replaces the DLL entirely, so no false positive."
3. **Packers and protectors.** Cracked files packed with the same protectors malware uses (Yoda, WinKript, FSG named; VMProtect flagged on VT reports) draw automatic flags from engines that shortcut on the wrapper rather than the content (2025-03-08).
4. **No signature.** "Most pirated software will give false positive virus warning... because the softwares dont have a signature that Windows defender recognizes" (2025-11-21).
5. **Detection names that are categories, not families.** "HackTool" and "Crack" verdicts are read as the AV naming the activity, with users posting "'HackTool' 'Crack' -> False positive!" as a complete analysis (2025-06-25). Wacatac and hacktool.gen results "identical to most other cracks" are treated the same way (2026-07-20).
6. **Platform policy flags.** Microsoft and Google are believed to flag cracks on instruction: "Microsoft and google throw false positives as they are told to flag cracks" (2025-09-10). A 2021-10-15 PSA (326 comments) reports a Windows Defender update that "disables torrent programs, and outright treats torrent software installers as viruses".
7. **The meta-problem, stated by users themselves.** The top false-positive complaint (2025-09-01, score 1,971) is epistemic: "How are you supposed to know if the detection is false or not?" And the sharpest version (same day, score 55): "if everything flags it as malware instantly, wouldn't that be the best place to hide malware because everyone thinks it's a false positive and uses it anyway?" A user who lost session cookies to a stealer from "a well known trusted source" while assuming false positive (2025-09-01, score 36) is the standing proof this failure mode is real. This is precisely the gap the Event Zero verdict feature exists to close: the community can explain flags, but cannot resolve them.

## 7. VirusTotal culture

VirusTotal is the community's courtroom and its most argued-about evidence: 1,542 posts and over 2,100 comments. Settled practices: scan before running; interpret by detection names and vendor weight (section 5, items 2 and 3); prefer hash search for large files; treat the ratio as a weak signal that needs a reading guide (a community VT reading guide hosted off-Reddit is cited in-thread, and users repeatedly demand a pinned "how to read VirusTotal" post, 2026-02-03). Settled scepticism: VT ratios on cracks are so noisy that one user calls VT "a rough estimate on par with reading future from tea leaves" (2025-11-28) and another warns that posting ratio questions without interpretation skill just manufactures panic (2026-08-01). The escalation path when VT is ambiguous is behavioural: sandbox detonation reports from any.run or tria.ge, posted back to the subreddit for literate readers to verdict (2025-11-28).

## 8. The activator debate (KMS, KMSPico, MAS)

Activators are the second-largest topic in the corpus (KMS in 2,501 posts; KMSPico alone in 1,053 posts) and the debate has a stable shape:

- **The megathread position (April 2021 tools page, held locally):** the wiki lists MAS 1.4, Office C2R-R2V, KMS_VL_ALL, KMSAuto Net, Daz Loader, and HWIDGEN with canonical sources (GitHub for MAS, MyDigitalLife forums for abbodi1406's tools), and prefaces the whole table: "Many of these tools will trigger your browser, Windows Defender, and personal antivirus. These are false positives."
- **KMSPico is the cautionary tale.** With no official site, every download site is a claim. The community line (2026-05-26): "Don't use KMSPico, there is no 'right website' for it." KMSPico's 1,053 malware-context posts are dominated by this provenance vacuum: the tool's behaviour (KMS emulation, AV tampering) is indistinguishable from malware to scanners, and bundled-malware copies are common enough that the tool name itself became a malware-context keyword.
- **MAS (Microsoft Activation Scripts, massgravel) is the resolution the community converged on:** open source, inspectable, GitHub-canonical. "It's safe. It's open source and probably one of the most used activators in the world right now." (2025-08-27). "massgravel scripts... are 100% safe and legitimate, yet are recognised as malicious by a lot of AVs" (2025-11-28). HWID activation is recommended over KMS emulation as "superior and no risk" (2025-08-12, score 265).
- **The residual risks are provenance and imitation, not the tool:** pasting random PowerShell activation commands is called out as a top infection route, with the defence being to fetch the exact command from the official MAS page yourself (2025-08-30); a misspelled impostor command circulated in January 2026 (section 3 item 20); and activator download sites with aggressive shorteners "force zero-click redirects to malware like Lumma stealers" (2026-10-18).
- **For the verdict engine, the lesson is precise:** an activator's expected behaviours (KMS server emulation, licensing service tampering, Defender exclusions, scheduled activation tasks) must be modelled as proof-of-crack-only when the file matches the canonical open-source release, and the same behaviours in an unverifiable binary remain needs-more-evidence, never auto-clean.

## 9. What the megathread and wiki copies held locally say

- The February 2025 megathread index carries a standing **Unsafe Sites** wiki page, described as: "Reputation of these malicious websites has been tarnished by numerous serious offenses." Trust is therefore a maintained list with a negative list beside it, curated by moderators.
- Its disclaimer is the community's own honesty clause: "Trustworthy links that were formerly safe may occasionally turn hazardous. The moderators do their best to maintain it, but always use care while sailing."
- The April 2021 tools page security section sets the baseline stack: "Windows defender should be more than enough for virus protection, combined with malwarebytes as an extra precaution. You do not need paid antiviruses, nor is it recommended to pirate any paid antiviruses", plus av-comparatives for AV test data and VirusTotal as the scanning service, and a link to r/techsupport's malware removal guide.
- The same page's torrent client notes (uTorrent miner, BitLord, section 3 item 1) show the megathread acting as institutional memory: incidents stay written into the tooling advice years later.

## 10. Implications for the Event Zero verdict engine

Indicator tags distilled from the archive. Proof-of-malware means the community record treats it as decisive; proof-of-crack-only means the behaviour is fully explained by cracking; needs-more-evidence means the archive shows it argued both ways.

**Proof of malware (verdict YES):**
- Extra dropped executable with persistence: a payload process in AppData with AutoRun or Winlogon Shell registry persistence (BBRepacks pattern, item 10).
- A media or document torrent whose payload is an executable (.scr episode, item 16), or an archive whose only content is a password-protected executable plus run-me instructions.
- Detection labels naming a specific malware family from a heavyweight engine, where the community's own rule (section 5 item 2) accepts specificity as truth.
- Post-install account compromise pattern: session cookie theft and account hijack days after install (items 15 and section 6 item 7), the stealer signature the community recognises in hindsight.
- Release size grossly inconsistent with the genuine product in either direction (items 13 and 19).
- Uploader or site under a platform ban or on the megathread Unsafe Sites list for malware offences (items 11 and 12), as corroborating, not sole, evidence.

**Proof of crack only (expected, verdict-neutral):**
- Generic, heuristic, AI, PUA, riskware, HackTool, and Crack detection labels, especially from low-reputation engines.
- Injection, hooking, and DLL replacement by known Steam emulator components (Goldberg, onlinefix), patched license checks, unpackers and loaders.
- Packer or protector wrappers (VMProtect and similar) on a crack binary.
- Unsigned binaries from release groups, absent any other signal.
- Activator behaviours (KMS emulation, licensing tampering, exclusions) in a binary that matches the canonical MAS or KMS_VL_ALL releases.

**Needs more evidence (must not be auto-resolved either way):**
- Any file whose only provenance is a name: a "FitGirl" or "DODI" release not fetched from the group's own site (impersonation is documented, items 5, 17, 18).
- KMSPico and any activator without a canonical source (section 8).
- High VirusTotal ratios on emulator DLLs (the 47/72 onlinefix64.dll case): route to behavioural detonation, which is the community's own escalation (section 7).
- A formerly trusted site whose current files changed while old files were clean (DownloadPirate pattern, item 15): verdict per file and per version, never per brand.
- Seed count, uploader age, and comment-section reassurance: all documented as gameable (items 2 and 16).

**Design consequences for Event Zero:**
1. Verdict the file, then attach reputation as context. The archive shows reputation failing in both directions (trusted sites shipping stealers; clean files at 47/72), so reputation can raise or lower scrutiny but must never be the verdict.
2. Ship a detection-name classifier: family-specific labels versus crack-category labels is the community's core skill, and it is mechanisable.
3. Model the crack's expected behaviour per release type (emulator injection, license patch, KMS emulation) so those behaviours stop counting as evidence, while anything outside the model counts double.
4. Treat size and manifest deltas against the genuine release as first-class evidence; the community discovered real cases exactly this way.
5. When static evidence is ambiguous, the verdict path is detonation behaviour (injection, hooks, keylogging APIs, persistence), mirroring the community's sandbox escalation, not a probability score.

## Appendix: method notes

- Scan and analysis scripts were run locally against the archive on 2026-11-23; hit sets and extracts were generated from the files named in section 1.
- All quotations are short excerpts from harvested posts and comments, cited by post date and, where relevant, comment score. Scores are as recorded in the Arctic Shift capture.
- Nothing in this file comes from the live web or from memory of the subreddit; every claim traces to a record in the local archive or to the local wiki copies named in section 1. Where the archive's comment coverage is thin (section 1 caveat), this file says so instead of filling the gap.
