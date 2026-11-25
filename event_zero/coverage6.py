"""Coverage wave 6: what runs automatically, and what it loads.

Design law (next-frontier research, items 3, 4 and 6): code that
runs because a package was installed, a folder was opened, an
interpreter started, or an agent session began is a first-class
unit of the submission, judged by the same closure rules as any
script, with its trigger named. The inventory is defined by
effect (what runs automatically, on what trigger), never by
location, because the observed supply-chain record migrated the
hook steadily away from the manifest: postinstall, preinstall,
bin shims, a git dependency's prepare hook, binding.gyp native
builds with no manifest script at all, Python .pth files that
execute at interpreter start, and editor and agent configuration
committed to repositories (VS Code tasks with runOn folderOpen,
devcontainer lifecycle commands, Claude Code settings hooks,
MCP server definitions whose command field the client executes).

This module builds the inventory: for each file it returns the
auto-execution units the file declares, as {surface, kind,
trigger, recognised, commands, local_targets, remote_targets,
modules, parse_error, detail}. A unit's commands are judged by
the verdict with the ordinary script machinery; this module
decides what the units are, which local files they name, and
which remote content they reach. A trigger class the catalogue
does not recognise, in a file whose format claims an
auto-execution surface, is returned with recognised False: the
verdict caps it rather than letting it pass silently, because
the catalogue below is a maintained list, not a finished one.

The module also parses a PE's import and delay-import
directories (the names of the libraries it loads), which the
verdict's sideload composite pass judges at folder scope: a
signed host's signature covers the host only, never the unit it
loads from its own folder.

Everything here is a pure read-only parse. Nothing is executed
and nothing is extracted.
"""
import json
import os
import plistlib
import re
import shlex
import struct
import sys

from .coverage3 import parse_pe_detailed


# ======================================================================
# The trigger catalogue (a maintained list, not a finished one)
# ======================================================================

# npm lifecycle events that run automatically at install, update
# or publish time. Other keys in "scripts" run only when a user
# invokes them by name, so they are not auto-execution units.
NPM_INSTALL_TRIGGERS = {
    "preinstall", "install", "postinstall", "prepare",
    "prepublish", "prepublishOnly", "prepack", "postpack",
    "preuninstall", "postuninstall",
}

# Composer (PHP) lifecycle events that run automatically.
COMPOSER_INSTALL_TRIGGERS = {
    "pre-install-cmd", "post-install-cmd", "pre-update-cmd",
    "post-update-cmd", "pre-autoload-dump", "post-autoload-dump",
    "post-create-project-cmd", "pre-package-install",
    "post-package-install", "pre-package-update",
    "post-package-update",
}

# devcontainer lifecycle fields (the specification's closed set;
# every one ends in "Command").
DEVCONTAINER_LIFECYCLE = {
    "initializeCommand", "onCreateCommand", "updateContentCommand",
    "postCreateCommand", "postStartCommand", "postAttachCommand",
}

# VS Code task runOn values: "folderOpen" runs automatically when
# the folder opens; "default" runs only when invoked.
VSCODE_RUNON_KNOWN = {"folderOpen", "default"}

# Agent hook events (Claude Code settings hooks): the events a
# settings file can attach commands to. An event key outside this
# set carrying commands is an unrecognised trigger.
AGENT_HOOK_EVENTS = {
    "PreToolUse", "PostToolUse", "PostToolUseFailure",
    "UserPromptSubmit", "UserPromptExpansion", "SessionStart",
    "SessionEnd", "Notification", "Stop", "SubagentStart",
    "SubagentStop", "PreCompact", "PostCompact",
    "PermissionRequest", "PermissionDenied", "Elicitation",
    "ElicitationResult", "WorktreeCreate", "WorktreeRemove",
    "InstructionsLoaded", "ConfigChange", "CwdChanged",
    "FileChanged", "Setup", "TeammateIdle", "TaskCreated",
    "TaskCompleted",
}

# Git hook names (the githooks catalogue). A file with one of
# these names in a hooks directory runs on the named event; the
# ".sample" files git ships are inert and are excluded by name.
GIT_HOOKS = {
    "applypatch-msg", "pre-applypatch", "post-applypatch",
    "pre-commit", "pre-merge-commit", "prepare-commit-msg",
    "commit-msg", "post-commit", "pre-rebase", "post-checkout",
    "post-merge", "pre-push", "pre-auto-gc", "post-rewrite",
    "push-to-checkout", "proc-receive", "post-receive",
    "update", "pre-receive", "fsmonitor-watchman",
    "post-index-change",
}

# Programs whose first non-flag argument is a file they execute:
# a command naming one of these names a local unit.
INTERPRETERS = {
    "node", "python", "python3", "python2", "bash", "sh", "zsh",
    "dash", "perl", "ruby", "php", "wscript", "cscript", "deno",
    "bun", "pwsh", "powershell", "osascript", "lua", "tclsh",
}

# Programs that fetch a package from a registry and run it as the
# command itself: the named package is remote code the
# configuration reaches at trigger time.
PACKAGE_EXEC_PROGRAMS = {"npx", "uvx", "bunx", "pnpx"}
PACKAGE_EXEC_PAIRS = {("pipx", "run"), ("yarn", "dlx"),
                      ("pnpm", "dlx"), ("bun", "x")}

CODE_EXTS = {".py", ".js", ".mjs", ".cjs", ".ts", ".sh", ".bash",
             ".rb", ".pl", ".php", ".ps1", ".bat", ".cmd", ".jar",
             ".wsf", ".vbs", ".jse"}

# Windows libraries that ship in the system directory and resolve
# there by default: an import naming one of these, absent from
# the folder, is recorded as system-resolved, not unresolved.
# The set governs only the absent-import note; a same-folder file
# with one of these names is judged as a composite regardless,
# because the application directory precedes the system
# directory in the standard search order.
SYSTEM_DLLS = {
    "kernel32.dll", "kernelbase.dll", "ntdll.dll", "user32.dll",
    "gdi32.dll", "gdiplus.dll", "advapi32.dll", "shell32.dll",
    "shlwapi.dll", "ole32.dll", "oleaut32.dll", "rpcrt4.dll",
    "msvcrt.dll", "ucrtbase.dll", "vcruntime140.dll",
    "vcruntime140_1.dll", "msvcp140.dll", "ws2_32.dll",
    "wsock32.dll", "wininet.dll", "winhttp.dll", "urlmon.dll",
    "crypt32.dll", "bcrypt.dll", "ncrypt.dll", "setupapi.dll",
    "cfgmgr32.dll", "iphlpapi.dll", "dnsapi.dll", "secur32.dll",
    "comdlg32.dll", "comctl32.dll", "version.dll",
    "winspool.drv", "psapi.dll", "dbghelp.dll", "imagehlp.dll",
    "wintrust.dll", "msi.dll", "netapi32.dll", "userenv.dll",
    "dwmapi.dll", "uxtheme.dll", "winmm.dll", "imm32.dll",
    "msimg32.dll", "opengl32.dll", "glu32.dll", "d3d9.dll",
    "d3d11.dll", "d3d12.dll", "dxgi.dll", "xinput1_4.dll",
    "xinput9_1_0.dll", "dinput8.dll", "dsound.dll",
    "normaliz.dll", "powrprof.dll", "mswsock.dll", "cryptbase.dll",
    "bcryptprimitives.dll", "msasn1.dll", "cabinet.dll",
    "samlib.dll", "vault.dll", "sspicli.dll", "profapi.dll",
}

_MAX_CONFIG_BYTES = 4_000_000


def _member_rel(rel):
    """The member's own path inside a submission: a release path
    may carry container prefixes (archive.zip!dir/file), and the
    surface a file claims is read from its own name and folders."""
    return str(rel).split("!")[-1]


def _basename(rel):
    return os.path.basename(_member_rel(rel).replace("\\", "/"))


def _components(rel):
    return [c for c in _member_rel(rel).replace("\\", "/").split("/")
            if c not in ("", ".")]


def _unit(rel, kind, trigger, recognised=True, commands=(),
          local_targets=(), remote_targets=(), modules=(),
          parse_error=None, detail="", dialect="shell"):
    return {"surface": rel, "kind": kind, "trigger": trigger,
            "recognised": recognised,
            "commands": list(commands),
            "local_targets": list(local_targets),
            "remote_targets": list(remote_targets),
            "modules": list(modules),
            "parse_error": parse_error, "detail": detail,
            "dialect": dialect}


def _target(written, basenames):
    return {"target": written,
            "resolved": os.path.basename(
                str(written).replace("\\", "/")).lower() in basenames}


# ======================================================================
# JSON and JSONC parsing
# ======================================================================

def _strip_jsonc(text):
    """Remove comments and trailing commas outside strings, so
    the JSONC dialect VS Code configuration files use parses with
    the strict parser."""
    out = []
    i, n = 0, len(text)
    in_str = False
    while i < n:
        c = text[i]
        if in_str:
            out.append(c)
            if c == "\\" and i + 1 < n:
                out.append(text[i + 1])
                i += 2
                continue
            if c == '"':
                in_str = False
            i += 1
            continue
        if c == '"':
            in_str = True
            out.append(c)
            i += 1
            continue
        if c == "/" and i + 1 < n and text[i + 1] == "/":
            while i < n and text[i] != "\n":
                i += 1
            continue
        if c == "/" and i + 1 < n and text[i + 1] == "*":
            i += 2
            while i + 1 < n and text[i:i + 2] != "*/":
                i += 1
            i += 2
            continue
        if c == ",":
            j = i + 1
            while j < n and text[j] in " \t\r\n":
                j += 1
            if j < n and text[j] in "}]":
                i += 1
                continue
        out.append(c)
        i += 1
    return "".join(out)


def _parse_json(text, jsonc=False):
    """(object, error). Exactly one of the two is not None."""
    try:
        return json.loads(text), None
    except Exception as e:
        if not jsonc:
            return None, str(e)
    try:
        return json.loads(_strip_jsonc(text)), None
    except Exception as e:
        return None, str(e)


# ======================================================================
# Command analysis: what a command line names
# ======================================================================

def _looks_like_code_path(tok):
    if not tok or tok.startswith(("-", "$", "/", "~", "{")):
        return False
    if "://" in tok:
        return False
    ext = os.path.splitext(tok)[1].lower()
    return ext in CODE_EXTS


def _tokens(text):
    try:
        return shlex.split(text, posix=True)
    except ValueError:
        return text.split()


def _analyse_tokens(toks, basenames, out):
    """Fill out = {targets, remote, modules} from one argv."""
    if not toks:
        return
    prog = toks[0].lstrip("@")
    base = os.path.basename(prog.replace("\\", "/")).lower()
    if len(toks) >= 2 and (base, toks[1].lower()) in PACKAGE_EXEC_PAIRS:
        for tok in toks[2:]:
            if not tok.startswith("-"):
                out["remote"].append(
                    f"package fetched and run at trigger time: {tok} "
                    f"(via {base} {toks[1]})")
                return
        return
    if base in PACKAGE_EXEC_PROGRAMS:
        for tok in toks[1:]:
            if not tok.startswith("-"):
                out["remote"].append(
                    f"package fetched and run at trigger time: {tok} "
                    f"(via {base})")
                return
        return
    if "/" in prog and not prog.startswith(("/", "~")) and "$" not in prog:
        out["targets"].append(_target(prog, basenames))
    elif _looks_like_code_path(prog):
        out["targets"].append(_target(prog, basenames))
    if base in INTERPRETERS or base in ("cmd", "cmd.exe"):
        i = 1
        while i < len(toks):
            tok = toks[i]
            if tok == "-m" and i + 1 < len(toks):
                out["modules"].append(toks[i + 1])
                i += 2
                continue
            if tok in ("-c", "/c", "/C") and i + 1 < len(toks):
                # a shell string handed to a shell: it is judged
                # as a command in its own right by the caller
                out["shell_strings"].append(toks[i + 1])
                i += 2
                continue
            if tok.startswith("-"):
                i += 1
                continue
            if _looks_like_code_path(tok):
                out["targets"].append(_target(tok, basenames))
            break


def _analyse_shell(cmd, basenames):
    """Analyse one shell command string. Returns (targets,
    remote, modules, shell_strings)."""
    out = {"targets": [], "remote": [], "modules": [],
           "shell_strings": []}
    for seg in re.split(r"&&|\|\||;|\||\n", cmd):
        seg = seg.strip()
        if seg:
            _analyse_tokens(_tokens(seg), basenames, out)
    return out


def _analyse_argv(argv, basenames):
    out = {"targets": [], "remote": [], "modules": [],
           "shell_strings": []}
    _analyse_tokens([str(a) for a in argv], basenames, out)
    return out


def _fill_from_analysis(unit, analysis):
    unit["local_targets"].extend(analysis["targets"])
    unit["remote_targets"].extend(analysis["remote"])
    unit["modules"].extend(analysis["modules"])
    unit["commands"].extend(analysis["shell_strings"])


# ======================================================================
# Surfaces
# ======================================================================

def _units_package_json(rel, text, basenames):
    obj, err = _parse_json(text)
    if err is not None or not isinstance(obj, dict):
        return [_unit(rel, "npm-package", "package install",
                      parse_error=err or "top level is not an object",
                      detail="this file claims the npm package "
                             "surface but could not be parsed, so "
                             "its install-time commands could not "
                             "be inventoried")]
    units = []
    scripts = obj.get("scripts")
    if isinstance(scripts, dict):
        for key in sorted(scripts):
            if key not in NPM_INSTALL_TRIGGERS:
                continue
            val = scripts[key]
            if not isinstance(val, str):
                continue
            u = _unit(rel, "npm-scripts",
                      f"package install ({key})", commands=[val],
                      detail="npm runs this script automatically "
                             "at install time")
            _fill_from_analysis(u, _analyse_shell(val, basenames))
            units.append(u)
    binmap = obj.get("bin")
    bin_entries = []
    if isinstance(binmap, str):
        bin_entries = [(obj.get("name") or "command", binmap)]
    elif isinstance(binmap, dict):
        bin_entries = [(k, v) for k, v in binmap.items()
                       if isinstance(v, str)]
    for name, target in bin_entries:
        units.append(_unit(
            rel, "npm-bin", f"command shim (bin entry {name})",
            local_targets=[_target(target, basenames)],
            detail="installing the package places this file on "
                   "the PATH as a command; the file it names is "
                   "the unit that runs"))
    for field in ("dependencies", "devDependencies",
                  "peerDependencies", "optionalDependencies",
                  "bundledDependencies"):
        deps = obj.get(field)
        if not isinstance(deps, dict):
            continue
        for name, spec in deps.items():
            if not isinstance(spec, str):
                continue
            low = spec.lower()
            if low.startswith("file:"):
                units.append(_unit(
                    rel, "npm-dependency",
                    "package install (local dependency)",
                    local_targets=[_target(spec[5:], basenames)],
                    detail=f"dependency {name} is a local path; "
                           "its own install hooks run at install "
                           "time"))
            elif (low.startswith(("git+", "git://", "github:",
                                  "bitbucket:", "gitlab:", "gist:"))
                  or (low.startswith(("http://", "https://"))
                      and (".git" in low or "tarball" in low))):
                units.append(_unit(
                    rel, "npm-dependency",
                    "package install (git dependency prepare)",
                    remote_targets=[spec],
                    detail=f"dependency {name} is fetched from a "
                           "remote source at install time, and a "
                           "git dependency's own prepare script "
                           "runs at install time; neither the "
                           "fetched content nor its hooks are in "
                           "this submission"))
    return units


def _units_composer_json(rel, text, basenames):
    obj, err = _parse_json(text)
    if err is not None or not isinstance(obj, dict):
        return [_unit(rel, "composer-package", "package install",
                      parse_error=err or "top level is not an object",
                      detail="this file claims the Composer package "
                             "surface but could not be parsed, so "
                             "its install-time commands could not "
                             "be inventoried")]
    units = []
    scripts = obj.get("scripts")
    if isinstance(scripts, dict):
        for key in sorted(scripts):
            if key not in COMPOSER_INSTALL_TRIGGERS:
                continue
            vals = scripts[key]
            if isinstance(vals, str):
                vals = [vals]
            if not isinstance(vals, list):
                continue
            for val in vals:
                if not isinstance(val, str):
                    continue
                u = _unit(rel, "composer-scripts",
                          f"package install ({key})", commands=[val],
                          detail="Composer runs this script "
                                 "automatically at install or "
                                 "update time")
                _fill_from_analysis(u, _analyse_shell(val, basenames))
                units.append(u)
    return units


def _units_binding_gyp(rel, text, basenames):
    obj, err = _parse_json(text, jsonc=True)
    units = [_unit(rel, "binding-gyp", "native build (node-gyp, "
                    "at package install)",
                   detail="installing the package runs node-gyp, "
                          "which builds the native code this file "
                          "describes; the build itself is the "
                          "auto-execution surface, with no "
                          "manifest script anywhere")]
    if err is not None or not isinstance(obj, dict):
        units[0]["parse_error"] = err or "top level is not an object"
        return units
    for tgt in obj.get("targets") or []:
        if not isinstance(tgt, dict):
            continue
        for act in tgt.get("actions") or []:
            if not isinstance(act, dict):
                continue
            action = act.get("action")
            if isinstance(action, list):
                argv = [str(a) for a in action]
                u = _unit(rel, "binding-gyp",
                          "native build action (node-gyp, at "
                          "package install)",
                          commands=[" ".join(shlex.quote(a)
                                             for a in argv)],
                          detail="a binding.gyp action runs a "
                                 "command during the native build")
                _fill_from_analysis(u, _analyse_argv(argv, basenames))
                units.append(u)
            elif isinstance(action, str):
                u = _unit(rel, "binding-gyp",
                          "native build action (node-gyp, at "
                          "package install)", commands=[action],
                          detail="a binding.gyp action runs a "
                                 "command during the native build")
                _fill_from_analysis(u, _analyse_shell(action, basenames))
                units.append(u)
    return units


def _units_pth(rel, text, basenames):
    code_lines = []
    modules = []
    for line in text.splitlines():
        s = line.strip()
        if s.startswith(("import ", "import\t")) or \
                s.startswith("from ") and " import " in s:
            code_lines.append(s)
            m = re.match(r"(?:import|from)\s+([A-Za-z_][\w.]*)", s)
            if m:
                modules.append(m.group(1).split(".")[0])
    if not code_lines:
        return [_unit(rel, "pth", "interpreter start (site .pth)",
                      detail="this .pth file names paths only; "
                             "no line in it is code")]
    local_modules = {os.path.splitext(b)[0].lower()
                     for b in basenames if b.endswith(".py")}
    stdlib = getattr(sys, "stdlib_module_names", set())
    targets = []
    for mod in sorted(set(modules)):
        resolved = mod.lower() in stdlib or mod.lower() in local_modules
        targets.append({"target": f"module {mod}",
                        "resolved": resolved})
    return [_unit(rel, "pth", "interpreter start (site .pth)",
                  commands=code_lines, local_targets=targets,
                  modules=sorted(set(modules)), dialect="python",
                  detail="lines of a .pth file that begin with "
                         "import are executed by the interpreter "
                         "at every start; the modules they import "
                         "are the units that run")]


def _units_python_surface(rel, base):
    if base == "setup.py":
        return [_unit(rel, "setup-py", "package install and build "
                      "(setup.py execution)",
                      detail="building or installing the package "
                             "executes this file as Python; the "
                             "file itself is judged as a script "
                             "on its own record")]
    if base in ("sitecustomize.py", "usercustomize.py"):
        return [_unit(rel, "site-customize",
                      "interpreter start (site customization)",
                      detail="the interpreter imports this module "
                             "at every start; the file itself is "
                             "judged as a script on its own record")]
    if base == "build.rs":
        return [_unit(rel, "cargo-build-script",
                      "native build (Cargo build script)",
                      detail="Cargo compiles and runs this file "
                             "as part of every build of the "
                             "package; the file itself is judged "
                             "as text on its own record")]
    return []


def _units_pyproject(rel, data, basenames):
    try:
        import tomllib
        obj = tomllib.loads(data.decode("utf-8", "replace"))
    except Exception as e:
        return [_unit(rel, "pyproject", "python build (PEP 517)",
                      parse_error=str(e),
                      detail="this file claims the Python build "
                             "surface but could not be parsed, so "
                             "its build backend could not be "
                             "inventoried")]
    build = obj.get("build-system")
    if not isinstance(build, dict):
        return []
    backend = build.get("build-backend")
    if not backend and not build.get("backend-path"):
        return []
    targets = []
    for p in build.get("backend-path") or []:
        if isinstance(p, str):
            targets.append(_target(p, basenames))
    return [_unit(rel, "pyproject", "python build (PEP 517 build "
                  "backend)", local_targets=targets,
                  detail=f"the build backend is {backend!r}; a "
                         "backend named by backend-path is code "
                         "in this tree that runs at build time, "
                         "and a backend named only by module is "
                         "recorded here as the build's unit")]


def _command_of(task):
    cmd = task.get("command")
    if not isinstance(cmd, str):
        return None
    args = task.get("args")
    parts = []
    if isinstance(args, list):
        for a in args:
            if isinstance(a, str):
                parts.append(a)
            elif isinstance(a, dict) and isinstance(a.get("value"), str):
                parts.append(a["value"])
    if not parts:
        return cmd
    return cmd + " " + " ".join(
        shlex.quote(p) if " " in p else p for p in parts)


def _units_vscode_tasks(rel, text, basenames):
    obj, err = _parse_json(text, jsonc=True)
    if err is not None or not isinstance(obj, dict):
        return [_unit(rel, "vscode-tasks", "folder open",
                      parse_error=err or "top level is not an object",
                      detail="this file claims the VS Code tasks "
                             "surface but could not be parsed, so "
                             "its automatic tasks could not be "
                             "inventoried")]
    units = []
    for task in obj.get("tasks") or []:
        if not isinstance(task, dict):
            continue
        run_on = (task.get("runOptions") or {}).get("runOn", "default")
        cmd = _command_of(task)
        if run_on == "folderOpen":
            if cmd is None:
                continue
            u = _unit(rel, "vscode-tasks", "folder open (VS Code "
                      "task)", commands=[cmd],
                      detail="this task is marked runOn "
                             "folderOpen, so it runs when the "
                             "folder is opened, before any user "
                             "command")
            _fill_from_analysis(u, _analyse_shell(cmd, basenames))
            units.append(u)
        elif run_on not in VSCODE_RUNON_KNOWN:
            u = _unit(rel, "vscode-tasks",
                      f"task trigger runOn {run_on!r}",
                      recognised=False,
                      commands=[cmd] if cmd else [],
                      detail="the task declares a runOn value "
                             "outside the set this build "
                             "recognises, and it carries a "
                             "command; a trigger class the "
                             "inventory does not recognise caps "
                             "rather than passing silently")
            if cmd:
                _fill_from_analysis(u, _analyse_shell(cmd, basenames))
            units.append(u)
    return units


def _units_vscode_launch(rel, text, basenames):
    obj, err = _parse_json(text, jsonc=True)
    if err is not None or not isinstance(obj, dict):
        return [_unit(rel, "vscode-launch", "debug start",
                      parse_error=err or "top level is not an object",
                      detail="this file claims the VS Code launch "
                             "surface but could not be parsed, so "
                             "its configurations could not be "
                             "inventoried")]
    units = []
    for cfg in obj.get("configurations") or []:
        if not isinstance(cfg, dict):
            continue
        program = cfg.get("program") or cfg.get("runtimeExecutable")
        args = cfg.get("args") or []
        if not isinstance(args, list):
            args = []
        argv = []
        if isinstance(program, str):
            cleaned = re.sub(r"\$\{[^}]*\}", "", program)
            if "${" in program:
                # a variable-prefixed path (${workspaceFolder}/x)
                # is relative to the workspace, not the machine
                # root the stripped leading slash suggests
                cleaned = cleaned.lstrip("/")
            argv.append(cleaned)
        argv.extend(str(a) for a in args)
        if not argv and not cfg.get("module"):
            continue
        u = _unit(rel, "vscode-launch",
                  "debug start (VS Code launch configuration)",
                  detail="starting a debug session runs this "
                         "program with these arguments")
        if cfg.get("module"):
            u["modules"].append(str(cfg["module"]))
        if argv:
            _fill_from_analysis(u, _analyse_argv(argv, basenames))
            u["commands"].append(" ".join(
                shlex.quote(a) for a in argv))
        units.append(u)
    return units


def _devcontainer_commands(val, basenames):
    """(commands, analyses) for one devcontainer lifecycle
    value: a string, an argv list, or a map of named commands."""
    cmds, analyses = [], []
    if isinstance(val, str):
        cmds.append(val)
        analyses.append(_analyse_shell(val, basenames))
    elif isinstance(val, list):
        argv = [str(a) for a in val]
        cmds.append(" ".join(shlex.quote(a) for a in argv))
        analyses.append(_analyse_argv(argv, basenames))
    elif isinstance(val, dict):
        for sub in val.values():
            c, a = _devcontainer_commands(sub, basenames)
            cmds.extend(c)
            analyses.extend(a)
    return cmds, analyses


def _units_devcontainer(rel, text, basenames):
    obj, err = _parse_json(text, jsonc=True)
    if err is not None or not isinstance(obj, dict):
        return [_unit(rel, "devcontainer", "container lifecycle",
                      parse_error=err or "top level is not an object",
                      detail="this file claims the devcontainer "
                             "surface but could not be parsed, so "
                             "its lifecycle commands could not be "
                             "inventoried")]
    units = []
    for key in sorted(obj):
        val = obj[key]
        if key in DEVCONTAINER_LIFECYCLE:
            cmds, analyses = _devcontainer_commands(val, basenames)
            if not cmds:
                continue
            u = _unit(rel, "devcontainer",
                      f"container lifecycle ({key})", commands=cmds,
                      detail="the devcontainer runtime runs this "
                             "command automatically at the named "
                             "point of the container's life")
            for a in analyses:
                _fill_from_analysis(u, a)
            units.append(u)
        elif key.endswith("Command") and isinstance(val, (str, list, dict)):
            cmds, analyses = _devcontainer_commands(val, basenames)
            u = _unit(rel, "devcontainer",
                      f"container lifecycle ({key})",
                      recognised=False, commands=cmds,
                      detail="this key names a lifecycle command "
                             "outside the devcontainer lifecycle "
                             "set this build recognises; a trigger "
                             "class the inventory does not "
                             "recognise caps rather than passing "
                             "silently")
            for a in analyses:
                _fill_from_analysis(u, a)
            units.append(u)
    return units


def _units_kernel(rel, text, basenames):
    obj, err = _parse_json(text)
    if err is not None or not isinstance(obj, dict):
        return [_unit(rel, "jupyter-kernel", "kernel start",
                      parse_error=err or "top level is not an object",
                      detail="this file claims the Jupyter kernel "
                             "surface but could not be parsed, so "
                             "the command it starts could not be "
                             "inventoried")]
    argv = obj.get("argv")
    if not isinstance(argv, list) or not argv:
        return []
    argv = [str(a) for a in argv if not str(a).startswith("{")]
    u = _unit(rel, "jupyter-kernel", "kernel start (Jupyter)",
              commands=[" ".join(shlex.quote(a) for a in argv)],
              detail="starting this kernel runs this argv; a "
                     "script path in it is a local unit, and a "
                     "module named after -m is recorded as the "
                     "module the interpreter loads")
    _fill_from_analysis(u, _analyse_argv(argv, basenames))
    return [u]


def _hook_commands(node):
    """Every command string in one agent-hooks structure."""
    out = []
    if isinstance(node, dict):
        if isinstance(node.get("command"), str) and \
                node.get("type") in (None, "command"):
            out.append(node["command"])
        for v in node.values():
            out.extend(_hook_commands(v))
    elif isinstance(node, list):
        for v in node:
            out.extend(_hook_commands(v))
    return out


def _units_agent_config(rel, text, basenames):
    obj, err = _parse_json(text, jsonc=True)
    if err is not None or not isinstance(obj, dict):
        return []
    units = []
    for key in ("mcpServers", "servers"):
        servers = obj.get(key)
        if not isinstance(servers, dict):
            continue
        for name, srv in servers.items():
            if not isinstance(srv, dict):
                continue
            if isinstance(srv.get("command"), str):
                argv = [srv["command"]] + \
                    [str(a) for a in srv.get("args") or []]
                u = _unit(rel, "mcp-server",
                          "agent session start (MCP server "
                          "launch)",
                          commands=[" ".join(shlex.quote(a)
                                             for a in argv)],
                          detail=f"the agent client runs this "
                                 f"command to start the MCP "
                                 f"server {name!r} when a session "
                                 f"begins")
                _fill_from_analysis(u, _analyse_argv(argv, basenames))
                units.append(u)
            elif isinstance(srv.get("url"), str) or \
                    isinstance(srv.get("serverUrl"), str):
                url = srv.get("url") or srv.get("serverUrl")
                units.append(_unit(
                    rel, "mcp-server",
                    "agent session start (MCP server launch)",
                    remote_targets=[url],
                    detail=f"the MCP server {name!r} is a remote "
                           "service; the tools it serves are "
                           "content that is not in this "
                           "submission"))
    hooks = obj.get("hooks")
    if isinstance(hooks, dict):
        for event in sorted(hooks):
            cmds = _hook_commands(hooks[event])
            if not cmds:
                continue
            u = _unit(rel, "agent-hooks",
                      f"agent hook ({event})",
                      recognised=event in AGENT_HOOK_EVENTS,
                      commands=cmds,
                      detail="the agent runs these commands "
                             "automatically on the named event"
                      if event in AGENT_HOOK_EVENTS else
                      "this event key is outside the agent hook "
                      "event set this build recognises, and it "
                      "carries commands; a trigger class the "
                      "inventory does not recognise caps rather "
                      "than passing silently")
            for c in cmds:
                _fill_from_analysis(u, _analyse_shell(c, basenames))
            units.append(u)
    return units


def _units_git_hook(rel, base, text):
    return [_unit(rel, "git-hook", f"git hook ({base})",
                  commands=[text],
                  detail="git runs this file automatically on "
                         "the named repository event for every "
                         "clone that installs it; the file itself "
                         "is the unit, and its text is judged "
                         "with the script rules")]


def _units_npmrc(rel, text, basenames):
    units = []
    for line in text.splitlines():
        s = line.strip()
        if s.lower().startswith("onload-script") and "=" in s:
            target = s.split("=", 1)[1].strip().strip('"').strip("'")
            if target:
                units.append(_unit(
                    rel, "npmrc", "package manager load "
                    "(onload-script)",
                    local_targets=[_target(target, basenames)],
                    detail="npm loads and runs this script "
                           "whenever it starts"))
    return units


def _units_launchd(rel, data, basenames):
    try:
        obj = plistlib.loads(data)
    except Exception:
        return []
    if not isinstance(obj, dict):
        return []
    argv = None
    if isinstance(obj.get("ProgramArguments"), list):
        argv = [str(a) for a in obj["ProgramArguments"]]
    elif isinstance(obj.get("Program"), str):
        argv = [obj["Program"]]
    if not argv:
        return []
    comps = _components(rel)
    if not any(c in ("LaunchAgents", "LaunchDaemons") for c in comps) \
            and "RunAtLoad" not in obj and "KeepAlive" not in obj:
        return []
    u = _unit(rel, "launchd", "logon or service start (launchd)",
              commands=[" ".join(shlex.quote(a) for a in argv)],
              detail="launchd runs this program automatically "
                     "at load or login")
    _fill_from_analysis(u, _analyse_argv(argv, basenames))
    return [u]


def _units_systemd(rel, text, basenames):
    units = []
    for line in text.splitlines():
        s = line.strip()
        for key in ("ExecStart", "ExecStartPre", "ExecStartPost"):
            if s.startswith(key + "="):
                val = s[len(key) + 1:].strip()
                if not val:
                    continue
                argv = _tokens(val)
                if argv:
                    argv[0] = argv[0].lstrip("-@+!")
                u = _unit(rel, "systemd", "service start "
                          f"(systemd {key})",
                          commands=[" ".join(shlex.quote(a)
                                             for a in argv)],
                          detail="systemd runs this command "
                                 "automatically when the service "
                                 "starts")
                _fill_from_analysis(u, _analyse_argv(argv, basenames))
                units.append(u)
    return units


# ======================================================================
# The inventory entry point
# ======================================================================

def autoexec_units(rel, data, entry_basenames=()):
    """Every auto-execution unit one file declares. Returns a
    list of unit dicts (see the module docstring for the
    schema); an empty list means the file claims no
    auto-execution surface this build inventories."""
    member = _member_rel(rel)
    base = _basename(rel)
    comps = _components(rel)
    basenames = {str(b).lower() for b in entry_basenames}
    in_node_modules = "node_modules" in comps
    units = []
    if len(data) > _MAX_CONFIG_BYTES:
        if base in ("package.json", "composer.json", "binding.gyp",
                    "tasks.json", "launch.json", "devcontainer.json",
                    ".devcontainer.json", "kernel.json") or \
                base.endswith(".pth"):
            return [_unit(rel, "oversized-config", "auto-execution "
                          "surface", parse_error=f"the file is "
                          f"{len(data)} bytes, past the "
                          f"{_MAX_CONFIG_BYTES}-byte inventory "
                          f"limit, so its automatic commands "
                          f"could not be inventoried",
                          detail="a configuration surface too "
                                 "large to inventory is "
                                 "unaccounted, not inert")]
        return []
    try:
        text = data.decode("utf-8", "replace")
    except Exception:
        return []
    if "\x00" in text[:2000]:
        return []
    if base == "package.json" and not in_node_modules:
        units.extend(_units_package_json(rel, text, basenames))
    if base == "composer.json" and not in_node_modules:
        units.extend(_units_composer_json(rel, text, basenames))
    if base == "binding.gyp" and not in_node_modules:
        units.extend(_units_binding_gyp(rel, text, basenames))
    if base.endswith(".pth"):
        units.extend(_units_pth(rel, text, basenames))
    if base in ("setup.py", "sitecustomize.py", "usercustomize.py",
                "build.rs"):
        units.extend(_units_python_surface(rel, base))
    if base == "pyproject.toml":
        units.extend(_units_pyproject(rel, data, basenames))
    if base == "tasks.json" and ".vscode" in comps:
        units.extend(_units_vscode_tasks(rel, text, basenames))
    if base == "launch.json" and ".vscode" in comps:
        units.extend(_units_vscode_launch(rel, text, basenames))
    if base in ("devcontainer.json", ".devcontainer.json"):
        units.extend(_units_devcontainer(rel, text, basenames))
    if base == "kernel.json":
        units.extend(_units_kernel(rel, text, basenames))
    if base.endswith(".json"):
        units.extend(_units_agent_config(rel, text, basenames))
    if base in GIT_HOOKS and not base.endswith(".sample") and \
            any(c in ("hooks", ".githooks", ".husky", ".git")
                for c in comps[:-1]):
        units.extend(_units_git_hook(rel, base, text))
    if base == ".envrc":
        units.append(_unit(rel, "direnv", "directory enter "
                           "(direnv)", commands=[text],
                           detail="direnv runs this file "
                                  "automatically when the "
                                  "directory is entered; the "
                                  "file itself is the unit, and "
                                  "its text is judged with the "
                                  "script rules"))
    if base == ".npmrc":
        units.extend(_units_npmrc(rel, text, basenames))
    if base.endswith(".plist"):
        units.extend(_units_launchd(rel, data, basenames))
    if base.endswith(".service"):
        units.extend(_units_systemd(rel, text, basenames))
    return units


# ======================================================================
# PE import directories, for the sideload composite pass
# ======================================================================

def _delay_import_dlls(data, det):
    dirs = det.get("directories") or {}
    if "delayimport" not in dirs:
        return []
    rva, _size = dirs["delayimport"]
    sections = det.get("sections") or []

    def rva_to_off(r):
        for s in sections:
            span = max(s["virtual_size"], s["raw_size"])
            if s["virtual_address"] <= r < s["virtual_address"] + span:
                return s["raw_pointer"] + (r - s["virtual_address"])
        return r if r < len(data) else None

    off = rva_to_off(rva)
    if off is None:
        return []
    out = []
    for i in range(4096):
        doff = off + 32 * i
        if doff + 32 > len(data):
            break
        fields = struct.unpack_from("<IIIIIIII", data, doff)
        if not any(fields):
            break
        name_rva = fields[1]
        noff = rva_to_off(name_rva) if name_rva else None
        if noff is not None:
            name = data[noff:noff + 256].split(b"\x00")[0] \
                .decode("ascii", "replace")
            if name:
                out.append(name)
    return out


def pe_imports(data):
    """The libraries one PE loads, from its import and
    delay-import directories: {imports, delay_imports} of DLL
    names as written, or None when the file is not a parseable
    PE."""
    det = parse_pe_detailed(data)
    if not det.get("parsed"):
        return None
    return {"imports": sorted(det.get("imports") or {}),
            "delay_imports": sorted(_delay_import_dlls(data, det))}
