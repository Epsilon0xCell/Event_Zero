# Event Zero, drawn out

I made these five pictures because the README describes two modes in
prose and the split is easier to see than to read. Everything in them
comes from the one file that does the work,
autonomous_docker_malware_analyzer.py, and from the test file beside it.

## The visuals

- [architecture.svg](architecture.svg): the system shape. One entry
  point, main(), and the fork between the offline local analyzer and
  the Docker plus Gemini autonomous analyzer. The two columns never
  share code paths after that fork, which is the thing I most need a
  reader to understand before changing anything.
- [data-flow.svg](data-flow.svg): the local mode pipeline, left to
  right. Bytes in, hashes and format parse, entropy and strings,
  indicators, assessment, JSON report out. I drew it as a straight line
  because the code is a straight line: there is no branch in this path
  that sends anything anywhere.
- [flowchart.svg](flowchart.svg): a run, followed as decisions. The
  local branch is one pass. The autonomous branch loops up to 50 rounds,
  with error output fed back into healing code, until the model marks
  the analysis complete.
- [product-map.svg](product-map.svg): the product in one frame: who it
  serves, what goes in, what comes out, and where it stops.

- [statistics.svg](statistics.svg): the numbers from the table below, drawn as bars on paper: lines by kind, with the file and commit counts noted under them.

Each sheet also ships as a PNG beside its SVG (architecture.png, flowchart.png, and so on): the same drawing, finished as a photograph of the paper page.

Every sheet here is drawn to look like what it is: a page sketched by hand on paper, and each one is signed GK somewhere in the drawing, never twice in the same place, because that is what I do with a page I made.

## Written product map

What it is: a malware triage tool with two engines. Local mode is pure
standard library static analysis that runs anywhere Python 3.8 runs.
Autonomous mode builds a BlackArch container and lets Gemini direct
standard analysis tools against the sample.

Who it serves: me, on my own machine, deciding whether a file deserves
trust, and anyone doing the same first-pass check before deeper work.

Capabilities, grouped:

- Reading a file without running it: MD5, SHA-1, and SHA-256 hashes;
  header parsing for Mach-O (including fat binaries), ELF, and PE;
  signature checks for ZIP, PDF, scripts, and text.
- Looking for leads: whole-file Shannon entropy, ASCII and UTF-16LE
  strings, URLs and IP addresses pulled from those strings, a built-in
  suspicious-keyword watchlist, and the EICAR test file matched by its
  known SHA-256.
- Judging, carefully: a rule-based assessment that states its own
  limits in the report. Absence of indicators is not called proof of
  safety anywhere in the output.
- The autonomous loop: container setup and reuse, tool execution with
  timeouts, Gemini calls, self-healing code generation when tool code
  fails, a fallback analysis, a final report, and container cleanup.

Inputs: a file path. Autonomous mode also takes a Gemini API key and a
running Docker daemon. Outputs: a plain-English terminal summary and a
JSON report (timestamped file name by default, or the path given to
--output).

Boundaries, what it does NOT do: local mode never executes the sample
and never touches the network. Neither mode detonates a sample and
records behavior. It does not replace a real sandbox, and its verdict
is a triage lead, not a final word on a file.

## Statistics, with citations

Counted 2026-10-30, from the clone this folder ships in, at the commit
before this visuals commit.

| Number | Value | How it was counted, and from what |
|---|---|---|
| Files in the repo | 9 | git ls-files in the clone, counted 2026-10-30 |
| Python lines | 2,182 | Line count over the 2 tracked .py files (the analyzer at 2,062 lines and tests/test_local_analysis.py at 120 lines, by wc -l on each file), 2026-10-30 |
| HTML lines | 233 | Line count over the 1 tracked .html file (the Pages site), same method, 2026-10-30 |
| Commits | 15 | git log in the clone, counted 2026-10-30 |
| First commit | 2025-07-26 | git log, oldest entry, 2026-10-30 |
| Last commit before this one | 2026-10-30 | git log, newest entry, 2026-10-30 |
| Tests | 8, all passing | python3 -m unittest discover -s tests, run by me 2026-10-30 in this clone: "Ran 8 tests, OK" |
| Languages (API) | Python 103,545 bytes; HTML 16,982 bytes | GitHub API, GET /repos/Epsilon0xCell/Event_Zero/languages, read 2026-10-30 |
| Repo size (API) | 137 KB | GitHub API, GET /repos/Epsilon0xCell/Event_Zero, size field, read 2026-10-30 |
| Stars / forks (API) | 1 / 0 | Same API response, read 2026-10-30 |

External statistics: none. No outside number says anything honest about
this repo, so the repo's own numbers are the whole table.

## Roadmap summary

Done: both modes working, the local test suite green, and the repair
history that got it there. Working now: nothing in flight. Next, if I
return to it: container runs for the autonomous path in a test, so that
half stops being verified by hand alone. The full roadmap, with the
Later and Not planned sections, is in [ROADMAP.md](ROADMAP.md).
