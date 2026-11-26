# The MalwareBazaar Verdict Campaign

## Purpose

Event Zero is a public, open-source static malware analysis engine.
Its flagship, The Verdict, issues a proof-backed YES or NO on a file:
YES the moment malicious behaviour is proven or any byte remains
unaccounted, NO only when every byte is accounted for as genuine or
as the explained difference. The verdict fails closed by design.

This campaign measures that engine against a public corpus:
MalwareBazaar (abuse.ch), the community malware sample library.
Every manifest entry carries the expectation class "bazaar-listed",
meaning the sample was submitted to MalwareBazaar as malware. No
family label is invented by the campaign. The published result is a
per-stratum accounting of verdicts, with the corpus, the tool
version, and the manifest root attached, never a bare number.

## The never-executes fact

Event Zero never executes a sample, in this campaign or anywhere.
It parses file formats, disassembles, decodes strings, matches
capability rules, and accounts for bytes. Samples in this campaign
exist only as their original password-protected AES ZIPs on
ephemeral GitHub Actions runners. They are never committed to this
repository, never uploaded as artifacts, and never written to logs.
What leaves a runner is hashes and verdicts only: results.jsonl and
downloads.jsonl.

## How a run is shaped

Each workflow dispatch runs one shard (default 250 entries):

1. Download stage (network allowed, this stage only): the shard's
   samples are fetched with the MalwareBazaar get_file API and
   saved as encrypted ZIPs. Nothing is extracted or executed.
   Every manifest entry gets a downloads line; a failed download is
   recorded, never silently dropped.
2. Analysis stage: a container built from this repository runs with
   --network none. An egress canary must prove outbound connections
   fail before any ZIP is opened. Each sample is extracted into a
   tmpfs scratch directory, the verdict runs in its own child
   process under a 120 second per-sample timeout, one results line
   is appended (hash, verdict token, reason class, family if any,
   ledger root), and the extracted bytes are deleted. A sample
   whose verdict exceeds the timeout is killed and recorded as
   YES UNACCOUNTED with analysis_status "analysis-timeout": it
   can neither stall the shard nor earn a clean verdict by
   hanging. One progress line is printed per sample so the stage
   log always shows where the shard is.
3. A guard step fails the job if any file other than .jsonl or .txt
   appears in the artifact paths.

## Acquisition discipline

Acquisition follows the abuse.ch FAQ guidance for bulk work (the
hourly and daily batch exports exist for bulk consumers) and the
campaign adds its own engineering discipline on top: get_file
downloads are self-capped at 2,000 per day in aggregate across all
runners, matching the per-address daily limit abuse.ch publishes
for the file download API. At the default shard size of 250, that
is at most 8 shard dispatches per day. The cap is a pacing rule the
campaign imposes on itself, recorded here so the cadence is public.

The 10,000-hash manifest is a deterministic seeded sample (seed
fixed in manifest_build.py) of a 25,548-hash pool collected from
the MalwareBazaar API across forty known family signatures plus
the most recent submissions. The legacy hash export endpoints
were retired by abuse.ch, so the pool is built through the live
API; the frozen artefact is the manifest itself. Its SHA-256
root is committed beside it in manifest-10k.root, so any later
dispute about which corpus produced a scorecard resolves to one
hash.

One endpoint fact, verified 2026-11-23: the legacy hash export
paths under bazaar.abuse.ch/export/ have been retired (HTTP 410).
The current official export is the v2 endpoint documented at
bazaar.abuse.ch/export, which carries the Auth-Key in the URL
path. manifest_build.py therefore runs where the key already
lives as a secret (a CI job or the operator's shell), reads it
from the environment, and holds it in memory only. The manifest
and its root are generated once from that export and committed;
no shard run ever regenerates them.

## Staged plan

1. Smoke shard: shard 0 at the default size, end to end, with the
   artifact guard and the job summary counts inspected by a human
   before any scale-up.
2. The 10,000 stage: 40 shards of 250, spread over at least 5 days
   under the aggregate cap.
3. The frozen 100,000 gate: a separate, larger manifest built the
   same deterministic way, frozen and hash-pinned before it runs,
   run once per release candidate under the pre-registration in
   validation/PREREGISTRATION.md. The gate is a measurement, not a
   tuning target: the engine is never adjusted against it.

## How a NO on a bazaar-listed sample is handled

A NO verdict on any manifest entry is a false-NO candidate, never a
quiet pass. Each one is adjudicated: the sample's evidence is
re-examined, and the outcome is one of three recorded results: the
listing was wrong or the file is a benign twin (documented, with
the accounting attached), the verdict stands as a scope question
for the corpus design, or the engine missed, in which case the case
enters docs/MISS-LEDGER.md under the existing EZ-BYPASS process and
becomes a permanent regression fixture. A confirmed miss is fixed
in the open, with the ledger entry naming it. Nothing is deleted
from the record.

## Structural diagnosis of a confirmed miss

Adjudication names a miss; it does not explain one. The shard
results carry verdicts, not structure, because per-sample
analysis evidence stays inside the runner by design. When a fix
wave built from outside reports fails on the real samples, the
next wave has to be scoped from the samples' actual structure,
and that structure has to cross the runner boundary without
breaking the rule that sample bytes never leave it.

That is what happened with EZ-BYPASS-2026-007 and
EZ-BYPASS-2026-008. Shard run 8 (run 45745957476) re-judged
both on the engine carrying fix wave 4 and coverage waves 5
to 9, and both returned NO ACCOUNTED again: fix wave 4 closes
the fourteen synthetic shapes reconstructed from vendor
behaviour reports, not the shapes the real files use. The
diagnosis route exists because of that result.

The route (.github/workflows/diagnose.yml driving
validation/campaign/diagnose.py, dispatched manually for named
hashes, the 007 and 008 hashes by default) mirrors the shard
flow's stage separation exactly: the samples are downloaded
through run_shard.py's own code path as encrypted ZIPs, and
the analysis runs in the campaign container with
--network none, egress canary first, extraction through
analyze_shard.py's own extraction, extracted bytes deleted
after each sample. What leaves the runner is one file,
diagnosis.json, guarded by a workflow step that fails the job
if the artifact directory contains anything else.

The boundary is a deliberate, bounded extension of this
document's "hashes and verdicts only" rule, and it is stated
here so the exception is part of the public record, not a
quiet widening. diagnosis.json carries structural facts only:
hashes, sizes, format classifications, finding and chain ids
with the engine's recorded reason strings, capability ids
with their sources, byte-ownership counts and ranges,
decoded-layer kinds with the decoded content's size and hash,
and the decision trace the engine's report supports. It never
carries sample bytes, full file text, string dumps, script
source, decoded-layer content, or script-ledger line text.
External references are reduced to scheme, host, and a
SHA-256 of the full URL; a full URL is recorded only when its
host is already public in docs/MISS-LEDGER.md, and every
engine reason string passes through the same reduction. The
diagnosis also states its own limit on its face: the engine
records blockers that fired, not candidates that were
evaluated and did not fire, so no unfired-blocker trace is
claimed.
