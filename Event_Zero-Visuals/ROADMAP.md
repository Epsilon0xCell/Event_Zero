# Event Zero roadmap

Written 2026-10-30 from the repo as it stands. No dates on the future
items, because I do not know when I will be back in this code, and a
date I invent here would be a small lie in a public file.

## Done

- Local mode: offline static analysis in pure standard library. Hashes,
  Mach-O, ELF, and PE parsing, entropy, strings, indicators, EICAR
  detection, and a rule-based assessment that states its limits.
- Autonomous mode: BlackArch container build and reuse, Gemini-directed
  tool loop with self-healing on tool errors, fallback analysis, final
  JSON report, container cleanup.
- A working command line: --file, --local, --api-key, --output,
  --max-iterations, --verbose and --quiet, after the repair commit that
  made the tool actually run end to end (ed07054).
- Test suite for the local path: 8 tests in
  tests/test_local_analysis.py, passing 2026-10-30.
- First-person comments across the analyzer and its tests, a project
  website, and these visuals.

## Working now

- Nothing in flight. The repo is in a finished, working state as of the
  2026-10-30 campaigns.

## Next

- An automated test that exercises the autonomous path against a stub
  container, so that half of the tool is verified by a test instead of
  only by hand. It is the one coverage gap I know about and admit here.
- Read the four duplicated smart_install_package definitions in the
  analyzer (the file carries several near-identical copies left by the
  self-healing design) and decide whether they should collapse into
  one. I have not decided; it works as it stands, and touching working
  malware tooling for tidiness has its own risk.

## Later

- More format parsers in local mode, in the order I actually meet the
  formats: Mach-O and ELF got the deepest treatment because those are
  what I handle.

## Not planned

- Detonation and behavior recording. That is a different tool with a
  different safety shape, and bolting it onto a triage script would
  blur the one promise local mode makes: the sample is never run.
- A graphical interface. The terminal summary is the interface I use.
