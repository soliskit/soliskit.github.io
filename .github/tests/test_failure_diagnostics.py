import importlib.util
import json
import pathlib
import tempfile
import unittest
from unittest import mock

SPEC = importlib.util.spec_from_file_location(
    "failure_diagnostics",
    pathlib.Path(__file__).parents[1] / "scripts/failure_diagnostics.py",
)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class DiagnosticsTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = pathlib.Path(self.temp.name)
        self.source = self.root / "receipts"
        self.source.mkdir()
        self.target = self.root / "export"
        self.state = {
            "schema": 1,
            "head": "a" * 40,
            "run": "123",
            "attempt": "1",
            "verdict": "INCOMPLETE",
            "errors": ["RuntimeError: native stage not qualified: install-once"],
            "stages": [{"environment": {"GH_TOKEN": "not-for-export"}}],
        }
        self.write("supervisor.json", self.state)
        self.write(
            "install-once.json",
            {"rc": 1, "error": "install failed", "environment": {"secret": "omit"}},
        )
        (self.source / "install-once.stderr").write_text("connection refused\n")

    def write(self, name, value):
        (self.source / name).write_text(json.dumps(value))

    def export(self, environment=None):
        MODULE.export(self.source, self.target, environment or {})

    def refused(self):
        with self.assertRaises((ValueError, UnicodeError)):
            self.export()
        self.assertFalse(self.target.exists())

    def test_failure_only_separate_schema_and_no_environment(self):
        self.export()
        summary = json.loads((self.target / "summary.json").read_text())
        self.assertEqual(summary["verdict"], "INCOMPLETE")
        self.assertEqual(summary["kind"], "FAILURE_DIAGNOSTICS_NOT_RELEASE_EVIDENCE")
        stage = summary["stages"][0]
        self.assertEqual(stage["stage"], "install-once")
        self.assertEqual(stage["rc"], 1)
        self.assertTrue(stage["errorPresent"])
        self.assertEqual(stage["streams"]["stderr"]["bytes"], 19)
        self.assertEqual(list(self.target.iterdir()), [self.target / "summary.json"])
        self.assertNotIn("environment", (self.target / "summary.json").read_text())

    def test_success_cannot_be_exported_as_diagnostics(self):
        self.state["verdict"] = "QUALIFIED"
        self.write("supervisor.json", self.state)
        self.refused()

    def test_unknown_files_and_fields_are_not_copied(self):
        (self.source / "private-output.txt").write_text("not selected")
        self.state["unrecognized"] = {"anything": "not selected"}
        self.write("supervisor.json", self.state)
        self.export()
        self.assertFalse((self.target / "private-output.txt").exists())
        self.assertNotIn("unrecognized", (self.target / "summary.json").read_text())

    def test_no_symlinks_even_when_unselected(self):
        (self.source / "link").symlink_to(self.root)
        self.refused()

    def test_oversize_file_total_metadata_and_count_fail_closed(self):
        for limit in ("MAX_FILE", "MAX_TOTAL", "MAX_METADATA", "MAX_FILES"):
            with self.subTest(limit=limit), mock.patch.object(MODULE, limit, 1):
                self.refused()

    def test_arbitrary_secrets_and_nested_errors_never_exported(self):
        secret = "eyJhbGciOiJIUzI1NiJ9.eyJ1c2VyIjoiZCJ9.signature"
        self.state["errors"] = [{"environment": secret}]
        self.write("supervisor.json", self.state)
        self.write(
            "install-once.json",
            {
                "rc": 1,
                "error": secret,
                "environment": {"COOKIE": secret},
                "command": [secret],
            },
        )
        (self.source / "install-once.stderr").write_text(secret)
        self.export({"COOKIE": secret, "SESSION": secret, "AUTH": secret})
        text = (self.target / "summary.json").read_text()
        self.assertNotIn(secret, text)
        self.assertNotIn("eyJ", text)
        self.assertNotIn("sha256", text)

    def test_invalid_typed_metadata_refused(self):
        self.write("install-once.json", {"rc": {"secret": "nested"}})
        self.refused()

    def test_invalid_utf8_and_nonregular_files_refused(self):
        (self.source / "install-once.stderr").write_bytes(b"\xff")
        self.export()
        self.assertNotIn("ÿ", (self.target / "summary.json").read_text())
        import shutil

        shutil.rmtree(self.target)
        (self.source / "install-once.stderr").unlink()
        import os

        os.mkfifo(self.source / "pipe")
        self.refused()

    def test_missing_receipts_or_preexisting_destination_refused(self):
        (self.source / "supervisor.json").unlink()
        self.refused()
        self.write("supervisor.json", self.state)
        self.target.mkdir()
        with self.assertRaises(ValueError):
            self.export()
        self.assertEqual(list(self.target.iterdir()), [])

    def test_workflow_preserves_failure_and_release_boundary(self):
        text = (pathlib.Path(__file__).parents[1] / "workflows/pages.yml").read_text()
        diagnostics = text.split("      - name: Select safe failure diagnostics", 1)[1]
        diagnostics = diagnostics.split(
            "      - name: Package the exact checked release", 1
        )[0]
        self.assertIn("if: failure()", diagnostics)
        self.assertIn("steps.diagnostics.outcome == 'success'", diagnostics)
        self.assertIn("retention-days: 3", diagnostics)
        self.assertNotIn("continue-on-error", text)
        self.assertIn("name: failure-diagnostics-", diagnostics)
        self.assertIn("name: qualified-tetris-", text)
        self.assertIn("inputs.site_qualification_run != ''", text)
        self.assertIn("12 screenshots", text)


if __name__ == "__main__":
    unittest.main()
