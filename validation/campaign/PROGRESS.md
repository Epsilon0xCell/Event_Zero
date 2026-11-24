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
