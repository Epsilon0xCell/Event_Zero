# Event Zero

Offline malware analysis that turns a suspicious file into a plain-English report. The sample is read as bytes and is never executed. No Docker, no network, no API key.

## Quick start

```bash
git clone https://github.com/Epsilon0xCell/Event_Zero.git
cd Event_Zero
pip install -r requirements.txt
python3 -m event_zero analyze fake_malware --out report.txt
```

That is the whole setup. The report is written to `report.txt`, and the same text is printed to the terminal. Use a `.json` or `.md` suffix on `--out` to get that format instead:

```bash
python3 -m event_zero analyze /path/to/sample --out report.json
python3 -m event_zero analyze /path/to/sample --out report.md
python3 -m event_zero analyze /path/to/sample
```

The old command still works through a compatibility shim:

```bash
python3 autonomous_docker_malware_analyzer.py --file fake_malware --local
```

## What the report contains

Every run produces all twelve sections, with anything that could not be determined written in the Unknowns section rather than left out silently:

1. Identity and hashes (MD5, SHA-1, SHA-256, SHA-512), plus EICAR test file detection by its published SHA-256.
2. A plain-English summary of what the file is and what it does.
3. Format and architecture: real parsing for ELF, PE, Mach-O (including fat binaries), ZIP, PDF, and scripts, using LIEF when installed and a built-in standard library parser when it is not.
4. Sections and segments with per-section entropy, and a packing assessment.
5. Imported functions, each explained in plain English.
6. Strings: ASCII and UTF-16.
7. Decoded strings: Base64 candidates decoded and validated, and single-byte XOR brute force that only reports a decode when it reveals a real keyword in readable text.
8. Capabilities in the style of Mandiant capa: deterministic rules over imports, strings, decoded strings, and instructions, each mapped to a MITRE ATT&CK technique with its evidence shown.
9. Disassembly of the executable section with Capstone (x86, x86-64, ARM, ARM64), plus source-level analysis for Python, shell, PowerShell, JavaScript, batch, Perl, and Ruby scripts.
10. Indicators of compromise: URLs, IP addresses, domains, and file paths found in the file.
11. A risk verdict with the reasons for the score.
12. Unknowns: what static analysis could not determine, stated plainly.

## What 100 percent means here

Perfect decompilation of arbitrary packed or self-modifying malware back to its original source code is not possible, and this README does not claim it. Lost symbols, comments, and variable names cannot be recovered from bytes, and packed code only fully exists at runtime.

What Event Zero does guarantee, and what its tests check, is completeness of coverage: every sample produces a full report across all twelve sections above, no crashes on the tested formats, no silent gaps, and an explicit Unknowns list. Optional deeper decompilation with Ghidra headless (which needs a JDK 21 install and about 1.5 GB of disk) and an optional language model summary layer (`event_zero.llm.summarise`, bring your own callable) can be layered on top of the JSON report. Neither is required.

## Tests

```bash
pip install pytest
python3 -m pytest tests/ -q
```

The suite covers EICAR detection, hash correctness, the bundled Mach-O sample, a crafted PE built byte by byte in the test, a compiled ELF when gcc is present, a malicious Python script, XOR and Base64 obfuscated samples, a benign text file, report formats, and the command line end to end. Example reports generated from real runs are in `examples/`.

## The bundled sample

`fake_malware` is a harmless Mach-O 64-bit ARM64 test executable built for this analyzer. Its strings describe what it would do if run: write files under /tmp, create /tmp/persistence.sh, list processes, connect to 127.0.0.1 port 4444, and simulate resource-intensive work described in its output as a crypto mining simulation. Event Zero never executes it. Treat it as sample code and do not run it outside a controlled analysis environment.

## Safety

Only analyze files you are authorized to inspect. Static analysis here never runs the sample, but handle unknown files in an isolated environment as a matter of habit.

## License

Creative Commons Attribution-NonCommercial 4.0 International. See the LICENSE file.
