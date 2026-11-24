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
   tmpfs scratch directory, the verdict runs, one results line is
   appended (hash, verdict token, reason class, family if any,
   ledger root), and the extracted bytes are deleted.
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
