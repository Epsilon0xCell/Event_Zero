#!/usr/bin/env python3
"""Tests for Event Zero's local static analysis mode.

Standard library only. Run from the repository root:

    python3 -m unittest discover -s tests -v
"""

import hashlib
import json
import os
import subprocess
import sys
import tempfile
import unittest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
# There is no package to install, so I put the repo root on sys.path
# myself. That is what lets these tests import the analyzer as a top
# level module, and it only works while this file stays in tests/
# directly under the root.
sys.path.insert(0, REPO_ROOT)

from autonomous_docker_malware_analyzer import LocalStaticAnalyzer  # noqa: E402

EICAR = (b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*")
SCRIPT = os.path.join(REPO_ROOT, "autonomous_docker_malware_analyzer.py")
BUNDLED_SAMPLE = os.path.join(REPO_ROOT, "fake_malware")


class LocalAnalysisTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.analyzer = LocalStaticAnalyzer()

    def _write(self, name, data):
        path = os.path.join(self.tmp, name)
        with open(path, "wb") as f:
            f.write(data)
        return path

    # I pin the full EICAR hash in the test below instead of
    # recomputing it from the string, because the point is that the
    # analyzer recognises that exact published value, not just that
    # it hashes the same bytes the same way twice.
    def test_eicar_detected_by_hash(self):
        report = self.analyzer.analyze(self._write("eicar.com", EICAR))
        self.assertTrue(report["indicators"]["eicar_test_file"])
        self.assertEqual(
            report["hashes"]["sha256"],
            "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
        )

    def test_hashes_match_hashlib(self):
        data = b"some sample content for hashing" * 10
        report = self.analyzer.analyze(self._write("sample.bin", data))
        self.assertEqual(report["hashes"]["sha256"], hashlib.sha256(data).hexdigest())
        self.assertEqual(report["hashes"]["md5"], hashlib.md5(data).hexdigest())
        self.assertEqual(report["size_bytes"], len(data))

    def test_benign_text_has_no_keyword_hits(self):
        path = self._write("note.txt", b"A perfectly ordinary note. See https://example.com/docs for details.\n")
        report = self.analyzer.analyze(path)
        self.assertEqual(report["format"]["format"], "text")
        self.assertEqual(report["indicators"]["urls"], ["https://example.com/docs"])
        self.assertEqual(report["indicators"]["suspicious_keyword_hits"], {})

    def test_bundled_sample_is_macho_arm64(self):
        report = self.analyzer.analyze(BUNDLED_SAMPLE)
        self.assertEqual(report["format"]["format"], "Mach-O")
        self.assertEqual(report["format"]["architecture"], "ARM64")
        self.assertIn("__TEXT", report["format"]["segments"])
        self.assertTrue(any("libSystem" in lib
                            for lib in report["format"]["linked_libraries"]))
        # The bundled sample deliberately contains these planted strings.
        self.assertIn("192.168.1.100", report["indicators"]["ip_addresses"])

    def test_missing_file_raises(self):
        with self.assertRaises(FileNotFoundError):
            self.analyzer.analyze(os.path.join(self.tmp, "does-not-exist.bin"))


class CliSmokeTests(unittest.TestCase):
    def test_help_runs(self):
        result = subprocess.run([sys.executable, SCRIPT, "--help"],
                                capture_output=True, text=True)
        self.assertEqual(result.returncode, 0)
        self.assertIn("--local", result.stdout)

    def test_local_mode_cli_writes_report(self):
        with tempfile.TemporaryDirectory() as tmp:
            sample = os.path.join(tmp, "eicar.com")
            with open(sample, "wb") as f:
                f.write(EICAR)
            out = os.path.join(tmp, "report.json")
            result = subprocess.run(
                [sys.executable, SCRIPT, "--file", sample, "--local", "--output", out],
                capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            with open(out) as f:
                report = json.load(f)
            self.assertTrue(report["indicators"]["eicar_test_file"])

    # I strip the key from the environment for this child process
    # only. If the shell running the suite has GEMINI_API_KEY
    # exported, the child would otherwise take the autonomous path
    # and this test would end up testing Docker availability
    # instead of the clean failure I want to pin down.
    def test_autonomous_mode_without_key_fails_cleanly(self):
        env = dict(os.environ)
        env.pop("GEMINI_API_KEY", None)
        result = subprocess.run([sys.executable, SCRIPT, "--file", BUNDLED_SAMPLE],
                                capture_output=True, text=True, env=env)
        self.assertEqual(result.returncode, 1)
        self.assertIn("--local", result.stdout)
        self.assertNotIn("Traceback", result.stdout + result.stderr)


if __name__ == "__main__":
    unittest.main()
