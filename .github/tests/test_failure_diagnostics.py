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

    def nested(self, setup=None, native=None):
        (self.source / "privileged-setup").mkdir(exist_ok=True)
        self.write("hosted-browser-install-once.json", {"rc": 1})
        if setup is not None:
            self.write("privileged-setup/setup-final.json", setup)
        if native is not None:
            self.write("privileged-setup/fixed-browser-setup.json", native)

    def nested_output(self):
        self.export()
        stages = json.loads((self.target / "summary.json").read_text())["stages"]
        return next(x for x in stages if x["stage"] == "hosted-browser-install-once")[
            "setupResults"
        ]

    def test_nested_valid_typed_fields_only(self):
        self.nested(
            {
                "verdict": "INCOMPLETE",
                "interrupted": False,
                "errors": ["private failure"],
                "retentionErrors": [],
                "isolatedTemporaryRoot": "/private/random-path",
                "supervisorUid": 0,
                "deadlineMonotonic": 12345,
            },
            {
                "rc": 1,
                "timeout": True,
                "interrupted": False,
                "errors": ["private failure"],
                "receiptWriteError": "private failure",
                "cleanup": {
                    "groupAbsent": True,
                    "leaderRetained": False,
                    "term": True,
                    "kill": False,
                    "emergencyKill": False,
                    "noChildStarted": False,
                    "cleanupError": "private failure",
                    "group": 123,
                },
                "descendants": {
                    "allAbsent": True,
                    "term": False,
                    "kill": False,
                    "noChildStarted": False,
                    "error": "private failure",
                    "adoptedReaped": [123],
                },
            },
        )
        self.write("privileged-setup/SETUP_INVALIDATED.json", {"reason": "private"})
        result = self.nested_output()
        self.assertTrue(result["invalidated"])
        for name in ["setup", "native"]:
            self.assertEqual(result[name]["status"], "valid")
            self.assertTrue(result[name]["present"])
            self.assertTrue(result[name]["parsed"])
        self.assertEqual(
            result["setup"]["facts"],
            {
                "verdict": "INCOMPLETE",
                "interrupted": False,
                "errorPresent": True,
                "retentionErrorPresent": False,
            },
        )
        native = result["native"]["facts"]
        self.assertEqual(native["rc"], 1)
        self.assertTrue(native["timeout"])
        self.assertTrue(native["receiptWriteErrorPresent"])
        self.assertTrue(native["cleanup"]["errorPresent"])
        self.assertTrue(native["descendants"]["errorPresent"])
        text = json.dumps(result)
        for excluded in ["private", "random-path", "12345", "supervisorUid", 'group"']:
            self.assertNotIn(excluded, text)

    def test_nested_both_missing_still_reports_presence(self):
        self.nested()
        result = self.nested_output()
        for name in ["setup", "native"]:
            self.assertEqual(
                result[name], {"present": False, "parsed": False, "status": "missing"}
            )
        self.assertFalse(result["invalidated"])

    def test_nested_each_missing_preserves_other_facts(self):
        for missing in ["setup", "native"]:
            with self.subTest(missing=missing):
                paths = {}
                self.nested()
                if missing == "setup":
                    self.write("privileged-setup/fixed-browser-setup.json", {"rc": -9})
                else:
                    self.write(
                        "privileged-setup/setup-final.json", {"verdict": "INCOMPLETE"}
                    )
                paths = {
                    x.relative_to(self.source).as_posix(): x
                    for x in self.source.rglob("*.json")
                    if x.name
                    != (
                        "setup-final.json"
                        if missing == "setup"
                        else "fixed-browser-setup.json"
                    )
                }
                result = MODULE.setup_results(paths)
                self.assertEqual(result[missing]["status"], "missing")
                other = "native" if missing == "setup" else "setup"
                self.assertEqual(result[other]["status"], "valid")
                self.assertIn("facts", result[other])

    def test_nested_malformed_and_invalid_are_distinct_and_no_partial_facts(self):
        self.nested({"verdict": "INCOMPLETE"}, {"rc": True})
        (self.source / "privileged-setup/setup-final.json").write_bytes(b"\xff")
        result = self.nested_output()
        self.assertEqual(
            result["setup"], {"present": True, "parsed": False, "status": "malformed"}
        )
        self.assertEqual(
            result["native"], {"present": True, "parsed": True, "status": "invalid"}
        )

    def test_nested_invalid_type_matrix(self):
        for selector, record in [
            (MODULE.setup_facts, {}),
            (MODULE.setup_facts, {"verdict": "private value"}),
            (MODULE.setup_facts, {"verdict": "INCOMPLETE", "interrupted": "secret"}),
            (MODULE.native_facts, {"rc": 256}),
            (MODULE.native_facts, {"rc": -256}),
            (MODULE.native_facts, {"rc": "secret"}),
            (MODULE.native_facts, {"timeout": 0}),
            (MODULE.native_facts, {"interrupted": None}),
            (MODULE.native_facts, {"cleanup": []}),
            (MODULE.native_facts, {"descendants": {"allAbsent": "secret"}}),
        ]:
            with self.subTest(record=record), self.assertRaises(ValueError):
                selector(record)

    def test_nested_partial_native_does_not_invent_missing_flags(self):
        self.assertEqual(
            MODULE.native_facts({"rc": None}),
            {"rc": None, "errorPresent": False, "receiptWriteErrorPresent": False},
        )
        self.assertEqual(
            MODULE.setup_facts({"verdict": "PRIVILEGED_SETUP_NATIVE_COMPLETION_ONLY"})[
                "verdict"
            ],
            "PRIVILEGED_SETUP_NATIVE_COMPLETION_ONLY",
        )

    def test_nested_arbitrary_content_never_leaves_runner(self):
        secret = "arbitrary-unpatterned-value-unique"
        self.nested(
            {
                "verdict": "INCOMPLETE",
                "errors": [secret],
                "retentionErrors": [secret],
                "identity": secret,
                "isolatedTemporaryRoot": secret,
            },
            {
                "rc": 1,
                "error": secret,
                "errors": [secret],
                "receiptWriteError": secret,
                "environment": {"COOKIE": secret},
                "command": [secret],
                "cleanup": {"cleanupError": secret},
                "descendants": {"error": secret},
            },
        )
        self.export({"AUTH": secret})
        text = (self.target / "summary.json").read_text()
        self.assertNotIn(secret, text)
        self.assertNotIn("sha256", text)
        self.assertNotIn("identity", text)

    def test_nested_symlink_and_size_refused_before_selection(self):
        self.nested({"verdict": "INCOMPLETE"})
        path = self.source / "privileged-setup/setup-final.json"
        path.unlink()
        path.symlink_to(self.source / "supervisor.json")
        self.refused()
        path.unlink()
        path.write_text("x" * 1024)
        with mock.patch.object(MODULE, "MAX_FILE", 512):
            self.refused()

    def test_nested_receipts_do_not_add_unreached_outer_stage(self):
        self.nested({"verdict": "INCOMPLETE"}, {"rc": 1})
        (self.source / "hosted-browser-install-once.json").unlink()
        self.export()
        text = (self.target / "summary.json").read_text()
        self.assertNotIn("setupResults", text)

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
