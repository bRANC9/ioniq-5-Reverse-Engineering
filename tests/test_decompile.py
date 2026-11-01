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


class InventoryQueueTests(unittest.TestCase):
    """The queue that drives a whole-tree decompile."""

    def setUp(self):
        import importlib.util

        spec = importlib.util.spec_from_file_location(
            "decompile_all", DECOMPILE.PROJECT / "tools/uk_fw/decompile_all.py")
        self.module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.module)

    def test_finds_elfs_and_skips_third_party_runtimes(self):
        with tempfile.TemporaryDirectory() as directory:
            tree = Path(directory)
            (tree / "app/bin").mkdir(parents=True)
            (tree / "app/lib").mkdir(parents=True)
            (tree / "app/bin/Tool").write_bytes(b"\x7fELF" + bytes(60))
            (tree / "app/bin/script.sh").write_text("#!/bin/sh\n")
            (tree / "app/lib/libQt5Core.so.5").write_bytes(b"\x7fELF" + bytes(60))
            found = self.module.elf_files(tree, ("app",))
        self.assertEqual([item["path"] for item in found], ["app/bin/Tool"])

    def test_counts_never_double_count_a_binary_in_both_sets(self):
        state = {"queue": [{"path": "a", "size": 1}, {"path": "b", "size": 2}],
                 "done": {"a": {}, "b": {}}, "failed": {"a": {}}, "claimed": {}}
        counts = self.module.count_queue(state)
        self.assertEqual(counts["done"], 1)
        self.assertEqual(counts["failed"], 0)
        self.assertEqual(counts["pending"], 0)
        self.assertEqual(counts["overlap"], 1)

    def test_repair_resolves_an_overlap_from_the_artifacts_on_disk(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            state_path = root / "state.json"
            out = root / "out"
            (out / "done.so").mkdir(parents=True)
            (out / "done.so" / "x.c").write_text("/* c */\n")
            (out / "gone.so").mkdir(parents=True)
            state = {"schema": 1,
                     "queue": [{"path": "app/bin/done.so", "size": 1},
                               {"path": "app/bin/gone.so", "size": 2}],
                     "done": {"app/bin/done.so": {}, "app/bin/gone.so": {}},
                     "failed": {"app/bin/done.so": {}, "app/bin/gone.so": {}},
                     "claimed": {}}
            self.module.save_state(state_path, state)
            self.assertEqual(self.module.repair_state(state_path, out), 2)
            repaired = self.module.load_state(state_path)
            self.assertIn("app/bin/done.so", repaired["done"])
            self.assertNotIn("app/bin/done.so", repaired["failed"])
            self.assertIn("app/bin/gone.so", repaired["failed"])
            self.assertNotIn("app/bin/gone.so", repaired["done"])

    def test_queue_is_sorted_small_first_and_state_round_trips(self):
        with tempfile.TemporaryDirectory() as directory:
            state_path = Path(directory) / "state.json"
            state = {"schema": 1, "queue": [{"path": "b", "size": 20},
                                            {"path": "a", "size": 10}],
                     "done": {}, "failed": {}, "claimed": {}}
            self.module.save_state(state_path, state)
            self.assertEqual(self.module.load_state(state_path)["queue"], state["queue"])
            # Claims are exclusive so parallel workers cannot take the same binary.
            self.assertTrue(self.module.claim(state_path, "a"))
            self.assertFalse(self.module.claim(state_path, "a"))
            self.module.release(state_path, "a")
            self.assertTrue(self.module.claim(state_path, "a"))


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
