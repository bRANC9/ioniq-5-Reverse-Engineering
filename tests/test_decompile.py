"""Offline tests for the Ghidra-driven decompile wrapper."""

from __future__ import annotations

import importlib.util
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

TOOL = Path(__file__).parents[1] / "tools/uk_fw/decompile.py"
SPEC = importlib.util.spec_from_file_location("decompile", TOOL)
DECOMPILE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(DECOMPILE)


class GhidraLookupTests(unittest.TestCase):
    def test_missing_ghidra_is_reported_with_the_override(self):
        with mock.patch.object(DECOMPILE, "DEFAULT_GHIDRA", Path("/nonexistent")), \
                mock.patch.dict(os.environ, {}, clear=True):
            with self.assertRaisesRegex(DECOMPILE.DecompileError, "IONIQ_GHIDRA"):
                DECOMPILE.find_ghidra(None)

    def test_override_wins_when_it_contains_analyzeheadless(self):
        with tempfile.TemporaryDirectory() as directory:
            ghidra = Path(directory)
            (ghidra / "support").mkdir()
            (ghidra / "support/analyzeHeadless").write_text("#!/bin/sh\n")
            self.assertEqual(DECOMPILE.find_ghidra(ghidra), ghidra)

    def test_output_must_stay_inside_the_project(self):
        with self.assertRaises(DECOMPILE.DecompileError):
            DECOMPILE.project_output(DECOMPILE.PROJECT.parent / "elsewhere")
        self.assertEqual(DECOMPILE.project_output(DECOMPILE.PROJECT / "work/x"),
                         DECOMPILE.PROJECT / "work/x")

    def test_environment_prefers_a_local_jdk(self):
        with tempfile.TemporaryDirectory() as directory:
            jdk = Path(directory)
            (jdk / "bin").mkdir()
            (jdk / "bin/java").write_text("#!/bin/sh\n")
            with mock.patch.object(DECOMPILE, "DEFAULT_JAVA_HOME", jdk), \
                    mock.patch.dict(os.environ, {}, clear=True):
                env = DECOMPILE.java_environment()
            self.assertEqual(env["JAVA_HOME"], str(jdk))


FAKE_HEADLESS = """#!/bin/sh
# Stand-in for analyzeHeadless: records its arguments and emits one function file.
printf '%s\\n' "$@" > "${FAKE_HEADLESS_ARGS:-/dev/null}"
out=""
next=0
for arg in "$@"; do
    if [ "$next" = "1" ]; then
        out="$arg"
        next=0
        continue
    fi
    case "$arg" in
        DecompileSymbols.java) next=1 ;;
    esac
done
if [ -n "$out" ] && [ -d "$out" ]; then
    printf '/* fake */\\nvoid FUN_00(void) {}\\n' > "$out/00000000_FUN_00.c"
fi
exit 0
"""


class DecompileRunTests(unittest.TestCase):
    """Drive the wrapper against a stub headless launcher."""

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.ghidra = self.root / "ghidra"
        (self.ghidra / "support").mkdir(parents=True)
        headless = self.ghidra / "support/analyzeHeadless"
        headless.write_text(FAKE_HEADLESS)
        headless.chmod(0o755)
        self.binary = self.root / "binary"
        self.binary.write_bytes(b"\x7fELF")
        self.out = DECOMPILE.PROJECT / "work/test-decompile-out"
        self.project = DECOMPILE.PROJECT / "work/test-decompile-project"
        self.args_log = self.root / "args.txt"

    def run_wrapper(self, **overrides):
        options = dict(binary=self.binary, select="0x190c70", out=self.out,
                       ghidra=self.ghidra, project_dir=self.project,
                       timeout=60, limit=0)
        options.update(overrides)
        with mock.patch.dict(os.environ, {"FAKE_HEADLESS_ARGS": str(self.args_log)}):
            return DECOMPILE.decompile(**options)

    def test_import_run_builds_the_expected_command(self):
        report = self.run_wrapper()
        self.assertEqual(report["functions"], 1)
        self.assertEqual(report["returncode"], 0)
        arguments = self.args_log.read_text().split()
        self.assertIn("-import", arguments)
        self.assertIn(str(self.binary.resolve()), arguments)
        self.assertIn("DecompileSymbols.java", arguments)
        self.assertIn("0x190c70", arguments)
        self.assertTrue(all("ghidra.log" != line for line in arguments))

    def test_reuse_and_analysis_timeout_flags(self):
        (self.project / "ioniq.rep").mkdir(parents=True, exist_ok=True)
        report = self.run_wrapper(reuse=True, analysis_timeout=120, discard=False)
        self.assertEqual(report["functions"], 1)
        arguments = self.args_log.read_text().split()
        self.assertIn("-process", arguments)

    def test_import_with_analysis_timeout_keeps_the_project(self):
        report = self.run_wrapper(analysis_timeout=90, discard=False)
        arguments = self.args_log.read_text().split()
        self.assertIn("-analysisTimeoutPerFile", arguments)
        self.assertIn("90", arguments)
        self.assertNotIn("-deleteProject", arguments)
        self.assertEqual(report["functions"], 1)

    def test_max_cpu_is_forwarded(self):
        report = self.run_wrapper(max_cpu=4)
        self.assertEqual(report["functions"], 1)
        arguments = self.args_log.read_text().split()
        self.assertIn("-max-cpu", arguments)
        self.assertIn("4", arguments)

    def test_missing_binary_is_refused(self):
        with self.assertRaises(DECOMPILE.DecompileError):
            self.run_wrapper(binary=self.root / "absent")


class ScriptContractTests(unittest.TestCase):
    def test_script_is_present_and_arguments_match_the_wrapper(self):
        script = DECOMPILE.SCRIPT_DIR / "DecompileSymbols.java"
        self.assertTrue(script.is_file())
        source = script.read_text()
        # The wrapper passes the output directory first and the selector second.
        self.assertIn("getScriptArgs()", source)
        self.assertIn("getDecompiledFunction().getC()", source)


if __name__ == "__main__":
    unittest.main()
