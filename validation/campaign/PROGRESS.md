# Campaign Progress

## Built 2026-11-23

- `validation/campaign/manifest_build.py`: builds the frozen
  10,000-hash manifest from a hash pool collected through the
  MalwareBazaar API (get_siginfo, limit 1,000 per signature over
  forty signatures, plus get_recent). Deterministic seeded sample
  (seed 20261123), canonical sorted JSONL, SHA-256 root written
  beside it.
- `validation/campaign/run_shard.py`: the CI download worker.
  Manifest slicing, get_file downloads saved as the original AES
  ZIPs, downloads.jsonl with one line per entry (downloaded,
  not_found, error), nothing extracted, nothing executed.
  Dry-run verified against a synthetic manifest: shard 1 of size 3
  over 7 entries listed exactly entries [3, 6) and wrote nothing.
- `validation/campaign/analyze_shard.py`: the networkless analysis
  worker. Egress canary first (aborts before extraction if any
  outbound connection succeeds), per-sample extraction into a
  scratch dir, Event Zero verdict, one results line per downloads
  line, extracted bytes deleted per sample.
- `validation/campaign/Dockerfile.campaign`: the analysis image,
  mirroring fixtures/verification/Dockerfile.verify (built with
  network, only ever run with --network none).
- `.github/workflows/campaign.yml`: workflow_dispatch with
  shard_index and shard_size inputs, contents: read permission,
  concurrency group with cancel-in-progress false, download stage,
  network-disabled analysis stage, artifact guard (only .jsonl and
  .txt may be uploaded), verdict and download counts in the job
  summary, ZIP removal before upload. YAML validated by parsing.
- `validation/campaign/CAMPAIGN.md`: the campaign declaration.

All three Python scripts compile clean. No sample was downloaded
to this machine at any point. Hashes and metadata only.

## Manifest status: FROZEN (2026-11-23)

- Pool collected live through the API: 25,548 unique SHA-256
  hashes across forty family signatures plus recent submissions.
- Manifest entries: 10,000, every entry expectation class
  "bazaar-listed", source "malwarebazaar-api-siginfo".
- Manifest root: f1091bc66389cf97388c72b250dec0fe169025d7ce867cbaf8de31d0b0148edb
- Verified after generation: the manifest file hashes to its own
  root and holds exactly 10,000 lines.

Route facts behind the API build:

- The legacy export endpoints under bazaar.abuse.ch/export/
  (txt and csv, recent and full) return HTTP 410 Gone. abuse.ch
  retired them.
- The replacement v2 export requires the Auth-Key in the URL
  path, which the connector surrogate cannot supply (its
  placement is the Auth-Key header, and the helper refuses to
  place the key in a URL). Header-only probes of the v2 paths
  answer 404.
- The v1 API takes the key in the header, so the pool was built
  with get_siginfo queries through the registered connection.
  Broad get_taginfo queries were not used: they fail server-side
  on broad tags. The campaign declaration in CAMPAIGN.md states
  the pool construction plainly.

## Correction (2026-11-23, later the same night)

The first campaign push (0966b24) carried the right manifest and
the wrong builder: a parallel draft of manifest_build.py aimed at
the v2 export overwrote the API builder in the working tree before
the sync, and the copy carried it into the push. The manifest
itself was always the API-built one (its source field reads
"malwarebazaar-api-siginfo" and its root verifies). The builder
file has been restored to the API version that actually froze the
manifest, compile-checked, and its parsing and seeded-selection
logic verified offline. The manifest was not regenerated: the
frozen artefact stands.

## Exact next commands

The smoke shard (after this tree is pushed and the
ABUSECH_API_KEY secret exists on the repo):

```bash
gh workflow run campaign.yml --field shard_index=0 --field shard_size=250
gh run watch
```

Inspect the campaign-shard-0 artifact and the job summary counts
by hand before dispatching shard 1. Full 10,000 stage: shards 0
to 39 at size 250, at most 8 dispatches per day under the
campaign's aggregate self-cap of 2,000 downloads per day, so the
stage spans at least 5 days.

## 2026-11-24: smoke run lessons and the analysis-stage fix

Smoke run 1 (run 45481999984, commit d4a548b): all 250 downloads
succeeded in about 7 minutes; the analysis stage then failed in
seconds with ModuleNotFoundError: the campaign image never
installed the event_zero package, and analyze_shard.py runs as a
script, so the repo root is not on sys.path. Fixed by installing
the project in Dockerfile.campaign (commit e921dd1).

Smoke run 2 (run 45483586290, commit e921dd1): downloads completed
in 5m13s; the analysis stage then ran past one hour with no
visible progress. The live log showed parser and emulator output
from early samples and then silence at the tail: the stage had no
per-sample timeout and printed nothing per sample, so one heavy
or pathological sample could hold the whole shard and the state
was unreadable from outside. Whether that run was stalled or
merely slow could not be determined, which is itself the defect.

Fix (analyze_shard.py, locally proven 2026-11-24 on synthetic
shards built from the repo's own fixtures): each verdict now runs
in a forked child process under a per-sample timeout (default
120s, --sample-timeout). A timed-out sample is killed and written
as YES UNACCOUNTED with analysis_status "analysis-timeout". One
progress line is printed per downloads line (index, total, short
hash, token, status, seconds), the canary result is printed, and
the final counts print as before. Local proof: normal shard of 3
(fake_malware YES PROVEN in 4.9s, EICAR-string file NO ACCOUNTED,
one not_found carried) completed with exit 0; a 400-file folder
with --sample-timeout 2 hit the timeout branch, was killed, and
was written as YES UNACCOUNTED while the shard still completed
with exit 0 and full line accounting.

## 2026-11-24: smoke run 3, the 429 wall, and download retries

Smoke run 3 (run 45499880998, commit d47fd05) succeeded end to
end in 3m36s: downloads in 2m32s, analysis in 40s, progress lines
to [250/250], artifact uploaded and read back by hand. But only
3 of 250 samples actually downloaded: 246 fetches were refused
with HTTP 429 and 1 with a 502. The abuse.ch get_file limit
(2,000 per day) is counted per IP address, and GitHub-hosted
runners share egress addresses with other tenants; after the
day's earlier runs the shared bucket was spent. All 247 refusals
were recorded as their own downloads lines, so the shard still
accounts for all 250 entries. The 3 downloaded samples were
analysed and all returned NO ACCOUNTED; as bazaar-listed samples
they are adjudication cases under CAMPAIGN.md (their bazaar
identities could not be pulled from the agent side at the time;
adjudication stays open and named, never guessed).

Fix (run_shard.py): transient refusals (HTTP 429 and 5xx,
network errors) are now retried with exponential backoff
(20s/60s/180s, 4 attempts, Retry-After honoured when sent), the
attempt count is recorded on every downloads line, one progress
line prints per entry, and a circuit breaker drops the shard to
single attempts after 10 consecutive files exhaust retries on
429, so a spent quota makes the shard finish and record the
state instead of burning hours. Locally proven with a scripted
download stub: 429 twice then success (attempts 3, ZIP saved),
file_not_found terminal (attempts 1), persistent 429 recorded
as error after 4 attempts, exit 0 with full accounting.

## 2026-11-24: adjudication of the three smoke run 3 verdicts

The three samples smoke run 3 analysed and returned NO ACCOUNTED
have been adjudicated against their MalwareBazaar sample pages
(read 2026-11-24). All three are confirmed misses, entered in
docs/MISS-LEDGER.md as EZ-BYPASS-2026-003 (FormBook, JavaScript
dropper, 15 vendor detections), EZ-BYPASS-2026-004 (njRAT
executable, 16 vendor detections), and EZ-BYPASS-2026-005
(RaccoonStealer executable, 13 vendor detections). None of the
three is a benign listing. The verdicts were issued by the build
at commit d47fd05, before the accuracy fix wave (349e6a9); root
cause per sample is not established because per-sample evidence
stays inside the runner by design. Whether the fixed engine
catches them is determined by the shard 0 rerun on the fixed
build, and each case becomes a regression fixture once its path
is reproduced.

## 2026-11-24: smoke run 4, the retry build, completes

Run 45502122642 (commit fde150c, the retry build, pre-fix engine)
completed successfully in 2h53m43s. Downloads: 241 of 250
fetched, 9 recorded errors, every one HTTP 429 after 4 attempts;
239 files succeeded on the first attempt, one needed 2 attempts
and one needed 3, so the retry path both absorbed the hostile
early stretch and stepped aside once the quota refilled.
Verdicts on the 241 analysed: YES 206 (115 PROVEN, 91
UNACCOUNTED), NO ACCOUNTED 35, with the 9 download errors
carrying no verdict. Of the three adjudicated misses: njRAT and
RaccoonStealer were downloaded and again returned NO ACCOUNTED
by the pre-fix engine, as expected; the FormBook sample was one
of the 9 quota errors and was not re-judged. The 35 NO verdicts
are adjudication candidates under CAMPAIGN.md. The decisive
re-test is run 5 on the fixed engine (commit 349e6a9),
dispatched 2026-11-25 00:02 UTC.

## 2026-11-24: smoke run 5, the fixed engine, completes

Run 45514931922 (commit 349e6a9, the accuracy fix wave)
completed successfully. Downloads: 250 of 250 fetched, zero
errors; 247 files on the first attempt and 3 on the second, on
a fresh UTC day quota. Verdicts: YES 247 (123 PROVEN, 124
UNACCOUNTED), NO ACCOUNTED 3, down from 35 NO on the pre-fix
engine over the same shard. All three adjudicated misses from
smoke run 3 (FormBook 000a219e, njRAT 003e626a, RaccoonStealer
06068e70) now return YES UNACCOUNTED: the fixed engine declines
to acquit them, which is the fail-closed behaviour the fix wave
was built to produce. The 3 remaining NO verdicts (00a11f7f,
03e548ca, 04b57840) went to adjudication against their bazaar
sample pages.

Adjudication of the 3 remaining NO verdicts completed
2026-11-24 from the public bazaar sample pages: all three are
CONFIRMED MISSES, entered in the miss ledger as
EZ-BYPASS-2026-006, 007, and 008. All three are Gozi / Ursnif
delivery artifacts from one Italian tax-agency lure set
(reporter JAMESWT_WT): a 198-byte .URL shortcut (4 vendor
detections), a double-extension batch dropper 5441.pdf.cmd
(4 detections, Joe Sandbox malicious), and an HTA downloader
azienda_08.hta (6 detections, Triage malicious with BitsAdmin
download behaviour). The pattern across the three is small
script-class delivery files; the per-sample root cause is not
established, because per-sample evidence stays inside the
runner by design. Shard 0 smoke stage closes with: old engine
35 NO of 241 analysed with at least 5 confirmed misses among
them (3 adjudicated of 3 sampled, plus 2 of the run 5 set
re-judged), fixed engine 3 NO of 250, all 3 confirmed misses.

## 2026-11-24: fix waves 2 and 3 land locally

Wave 2 closes the three run 5 miss shapes with named verdict
blockers (remote-fetch-and-execute, url-shortcut-remote-payload,
disguised-double-extension), proven on synthetic fixtures;
suite 203 passed. Wave 3 implements the closure rules from the
remote-payload research (external-reference closure, engine
incompleteness as a verdict-layer cap, interpreter-proxy
invocation caps); suite 224 passed, verified by the operator.
Both waves are recorded in validation/FIX-LOG-2026-11-24-WAVE2.md
and validation/FIX-LOG-2026-11-24-WAVE3.md. Next: push, then
re-run shard 0 on the strengthened engine.
