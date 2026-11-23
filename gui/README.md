# Event Zero Desktop GUIs

Two different desktop shells over one engine. Event Zero turns a
suspicious file into a plain English report anyone can act on, with every
claim tied to evidence found in the file itself.

Malware in. Plain English out. Evidence attached.

The tool is Event Zero. The flagship verdict feature is branded
**The Verdict** in both shells: it is the name of the verdict screen in
the navigation, the section title over the verdict band, and the feature
named in the About text.

The GUIs consume the engine only through its CLI and JSON output
(`python3 -m event_zero analyze|verdict <path> --out <file>.json`), run as
a subprocess. The sample is never executed, by the GUI or by the engine.
Both apps work fully offline, need no account, and send nothing anywhere.

## The two shells

| | Windows | macOS |
|---|---|---|
| File | `windows/event_zero_win.py` | `macos/event_zero_mac.py` |
| Design language | Windows 11 Fluent inspired: dark Mica-like base, NavigationView-style left rail, CommandBar top actions, InfoBar-style verdict band, rounded 8px controls, Windows blue accent `#4CC2FF` / `#0078D4`, Segoe UI stack | macOS HIG inspired: source-list sidebar with SF-style glyphs, unified toolbar, segmented ELI5 / Plain / Evidence control, vibrancy-like translucent sidebar, verdict pill in macOS system red / green, sheet-style Settings, SF Pro stack |
| Verdict band | Full width InfoBar band in Windows system red `#C42B1C` or green `#107C10` | Rounded verdict pill in macOS red `#FF3B30` or green `#34C759` |
| Layers | Tabs: ELI5, Files, Connections and IOCs, Full Report | Segmented control switches ELI5 / Plain / Evidence; the segment rewords the same evidence, it never omits any of it |

Shared behaviour, both apps:

- Pick or drag and drop a file or folder, run Analyze or Verdict (Verdict
  accepts an optional genuine reference to diff against).
- The verdict headline comes first, and every verdict band carries a
  scope sentence under it: how many files were checked, that the sample
  was never executed, and the names of anything that could not be fully
  checked. There is never a naked verdict. An unaccounted result names
  what was not checked.
- Per-file table, problems first, sortable by every column, with a
  Signer column.
- Real per-file progress for folder analysis. Cancel stops the run and
  produces a partial result that fails closed: YES: UNACCOUNTED, with the
  unchecked files named. Silence is never converted into a pass.
- Local history list (stored only on this machine, in
  `~/.eventzero/history` plus the app settings), recent files, and
  Export Text / Export JSON / Export PDF.
- A permanent offline indicator. The About dialog states the
  never-executes and offline facts. No account, no telemetry language,
  anywhere.

## Run

```bash
python3 -m venv .venv
.venv/bin/pip install PySide6        # Windows: .venv\Scripts\pip
.venv/bin/python gui/windows/event_zero_win.py     # Windows shell
.venv/bin/python gui/macos/event_zero_mac.py       # macOS shell
```

Engine auto-detect: the apps walk up from their own folder looking for
the `event_zero` package, so running from inside this repository just
works. Outside the repository, set:

- `EVENT_ZERO_HOME`: folder that contains the `event_zero` package.
- `EVENT_ZERO_PYTHON`: interpreter used to run the engine (optional).

If the engine is missing, the app still opens and says so in the status
line, with the fix named.

## Tests

Headless, using the Qt offscreen platform:

```bash
QT_QPA_PLATFORM=offscreen .venv/bin/python -m pytest gui/tests -q
```

Covers window construction for both apps, report JSON loading into both
UIs from `examples/gold/`, verdict banner text and colour logic, scope
sentences, problems-first file rows, the fail-closed partial verdict,
and ELI5 tab (Windows) / segment (macOS) switching.

## Packaging

### Windows: single .exe

```powershell
pip install PySide6 pyinstaller
pyinstaller --windowed --name EventZero `
  --icon path\to\event_zero.ico `
  --add-data "gui\common.py;gui" `
  gui\windows\event_zero_win.py
```

Ship the engine beside the shell or set `EVENT_ZERO_HOME` at install
time. For distribution beyond your own machines, sign the executable
(Authenticode) or package as MSIX so SmartScreen reputation attaches to
a stable publisher identity; an unsigned .exe from the internet will be
warned on, and the honest fix is signing, never instructions to disable
SmartScreen.

### macOS: .app and .dmg

PyInstaller route:

```bash
pip install PySide6 pyinstaller
pyinstaller --windowed --name "Event Zero" \
  --icon path/to/event_zero.icns \
  --osx-bundle-identifier com.eventzero.app \
  gui/macos/event_zero_mac.py
```

Info.plist notes: set `CFBundleName` and `CFBundleDisplayName` to
Event Zero, `CFBundleIdentifier` to your reverse-domain id,
`NSHighResolutionCapable` true, and a document type for report JSON if
you want Finder double-click to open reports in the app.

Notarization checklist (required for Gatekeeper-clean distribution):

1. Enrol in the Apple Developer Program; create a Developer ID
   Application certificate.
2. Build the .app, then sign inside out (every nested binary and dylib
   first, the bundle last) with the hardened runtime:
   `codesign --deep --force --options runtime --sign "Developer ID Application: NAME" "Event Zero.app"`.
   A Python sidecar or bundled interpreter must be signed the same way,
   with timestamps, or notarization fails on the nested code.
3. Create the .dmg: `hdiutil create -volname "Event Zero" -srcfolder "Event Zero.app" EventZero.dmg`.
4. Submit: `xcrun notarytool submit EventZero.dmg --keychain-profile PROFILE --wait`.
5. Staple the ticket: `xcrun stapler staple EventZero.dmg`.
6. Verify on a clean machine or VM: `spctl --assess --type open --context context:primary-signature -v EventZero.dmg`.

py2app is the alternative packager (`python setup.py py2app` with the
app script pointed at `gui/macos/event_zero_mac.py`); the signing and
notarization steps above are identical either way.

## Next step: flagship native shells

These PySide6 shells are v1, per the GUI research in
`~/workspace/research_notes/event-zero-native-gui-windows-macos-20261123-0619/report.md`.
The documented flagship path is two fully native shells, each driving a
signed, frozen Python sidecar of this same engine over a versioned JSON
contract:

- macOS: a SwiftUI shell (real unified toolbar, NavigationSplitView
  source list, system materials, Quick Look on evidence, sheets).
  Sidecar discipline: sign and notarize the sidecar inside the bundle,
  hardened runtime entitlements reconciled for a Python interpreter,
  Developer ID signing, notarization, stapled ticket, Sparkle with
  EdDSA-signed appcast for updates.
- Windows: a WinUI 3 shell (real Mica, custom TitleBar, NavigationView,
  InfoBar, Narrator through UI Automation). Sidecar discipline: MSIX
  packaging (Microsoft re-signs for Store distribution) or
  Authenticode / Azure Artifact Signing for direct distribution, one
  stable publisher identity so SmartScreen reputation accumulates.

Both shells must keep the verdict contract unchanged: headline first,
scope sentence always, three states (YES proven, YES unaccounted, NO
accounted), evidence one tap away, and a shell that stays usable, with
an honest notice, when the engine has crashed.
