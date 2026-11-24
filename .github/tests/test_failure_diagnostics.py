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

    def typed_phase(self, phase="dependency-preflight", status="installed"):
        self.nested()
        self.state["hostHead"] = "b" * 40
        self.write("supervisor.json", self.state)
        record = {
            "schema": 1,
            "phase": phase,
            "status": status,
            "identity": {
                "QUALIFICATION_HEAD": self.state["head"],
                "GITHUB_SHA": self.state["hostHead"],
                "GITHUB_RUN_ID": self.state["run"],
                "GITHUB_RUN_ATTEMPT": self.state["attempt"],
            },
            "elapsedSeconds": 1.25,
            "native": {"rc": 0, "timeout": False},
            "private": "not-selected",
        }
        if status == "not-started":
            record["native"] = None
        self.write("privileged-setup/" + phase + ".json", record)
        return record

    def typed_output(self):
        self.export()
        stages = json.loads((self.target / "summary.json").read_text())["stages"]
        return next(x for x in stages if x["stage"] == "hosted-browser-install-once")[
            "typedSetupResults"
        ]

    def preflight_check(self, name="package-status"):
        return {
            "name": name,
            "native": {
                "rc": 0,
                "timeout": False,
                "interrupted": False,
                "cleanup": {"groupAbsent": True},
                "descendants": {"allAbsent": True},
                "environment": {"PRIVATE_VALUE": "not-for-export"},
                "stdout": "not-for-export",
                "error": "",
            },
        }

    def test_fixed_preflight_checks_are_bound_and_allowlisted(self):
        record = self.typed_phase(status="parse-or-command-error")
        record["checks"] = [
            self.preflight_check(name) for name in MODULE.PREFLIGHT_CHECKS
        ]
        record["checks"][-1]["native"]["rc"] = 1
        facts = MODULE.phase_facts(record, "dependency-preflight", self.state)
        selected = facts["checkOutcomes"]
        self.assertEqual(selected["status"], "valid")
        self.assertEqual(
            [item["check"] for item in selected["checks"]],
            list(MODULE.PREFLIGHT_CHECKS),
        )
        self.assertEqual(selected["checks"][-1]["status"], "native-not-success")
        self.assertNotIn("not-for-export", json.dumps(selected))
        record["identity"]["GITHUB_RUN_ID"] = "999"
        with self.assertRaises(ValueError):
            MODULE.phase_facts(record, "dependency-preflight", self.state)

    def test_missing_or_invalid_preflight_checks_stay_unknown(self):
        check = self.preflight_check()
        variants = [
            None,
            [],
            "bad",
            [None],
            [self.preflight_check("other")],
            [check, check],
            [self.preflight_check("package-audit")],
        ]
        for native in [
            {},
            {"rc": True},
            {"rc": 1.0},
            {"rc": 999},
            {"rc": 1, "timeout": "false"},
        ]:
            variants.append([{"name": "package-status", "native": native}])
        for checks in variants:
            with self.subTest(checks=checks):
                self.assertEqual(
                    MODULE.preflight_check_facts({"checks": checks}),
                    {"status": "unknown"},
                )
        self.assertEqual(MODULE.preflight_check_facts({}), {"status": "unknown"})

    def test_preflight_native_flags_do_not_claim_installed_state(self):
        for mutation in [
            lambda n: n.update(rc=1),
            lambda n: n.update(timeout=True),
            lambda n: n.update(interrupted=True),
            lambda n: n.update(error="not-for-export"),
            lambda n: n["cleanup"].update(groupAbsent=False),
            lambda n: n["descendants"].update(allAbsent=False),
        ]:
            check = self.preflight_check()
            mutation(check["native"])
            result = MODULE.preflight_check_facts({"checks": [check]})
            self.assertEqual(result["status"], "valid")
            self.assertEqual(result["checks"][0]["status"], "native-not-success")
            self.assertNotIn("not-for-export", json.dumps(result))

    def test_typed_phases_bound_allowlisted_and_not_started(self):
        self.typed_phase(status="missing-or-unconfigured")
        self.typed_phase("browser-download", "not-started")
        result = self.typed_output()
        self.assertEqual(result["phaseOrder"], list(MODULE.SETUP_PHASES))
        preflight = result["phases"]["dependency-preflight"]
        self.assertEqual(preflight["status"], "valid")
        self.assertTrue(preflight["facts"]["identityMatched"])
        self.assertEqual(preflight["facts"]["status"], "missing-or-unconfigured")
        download = result["phases"]["browser-download"]["facts"]
        self.assertEqual(download["status"], "not-started")
        self.assertNotIn("native", download)
        self.assertNotIn("not-selected", json.dumps(result))

    def test_typed_unknown_missing_and_old_receipt_remain_unknown(self):
        self.nested(native={"rc": -15, "timeout": True})
        result = self.typed_output()
        for phase in MODULE.SETUP_PHASES:
            self.assertEqual(result["phases"][phase]["status"], "missing")

    def test_typed_identity_status_elapsed_and_native_fail_closed(self):
        cases = [
            ("schema", True),
            ("phase", "other"),
            ("identity", {}),
            ("status", "arbitrary-private-message"),
            ("status", []),
            ("status", {}),
            ("status", "downloaded"),
            ("elapsedSeconds", True),
            ("elapsedSeconds", float("nan")),
            ("elapsedSeconds", float("inf")),
            ("elapsedSeconds", 391),
            ("native", None),
            ("native", {"rc": "secret"}),
        ]
        for field, value in cases:
            with self.subTest(field=field, value=value):
                record = self.typed_phase()
                record[field] = value
                self.write("privileged-setup/dependency-preflight.json", record)
                paths = {
                    "privileged-setup/dependency-preflight.json": self.source
                    / "privileged-setup/dependency-preflight.json"
                }
                result = MODULE.typed_setup_results(paths, self.state)
                self.assertEqual(
                    result["phases"]["dependency-preflight"]["status"], "invalid"
                )
                self.assertNotIn("facts", result["phases"]["dependency-preflight"])

    def test_typed_each_closed_failure_status_and_download_success(self):
        for phase, status in [("browser-download", "downloaded")] + [
            ("dependency-preflight", status)
            for status in [
                "installed",
                "unsupported",
                "parse-or-command-error",
                "timeout",
                "failure",
            ]
        ]:
            with self.subTest(phase=phase, status=status):
                self.typed_phase(phase, status)
                paths = {
                    "privileged-setup/" + phase + ".json": self.source
                    / ("privileged-setup/" + phase + ".json")
                }
                result = MODULE.typed_setup_results(paths, self.state)
                self.assertEqual(result["phases"][phase]["status"], "valid")

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

    def phase(self, stdout=None, stderr=None, environment=None):
        self.nested({"verdict": "INCOMPLETE"}, {"rc": -15, "timeout": True})
        for suffix, value in [("stdout", stdout), ("stderr", stderr)]:
            if value is not None:
                (
                    self.source / ("privileged-setup/fixed-browser-setup." + suffix)
                ).write_bytes(value)
        self.export(environment)
        summary = json.loads((self.target / "summary.json").read_text())
        return next(
            x for x in summary["stages"] if x["stage"] == "hosted-browser-install-once"
        )["setupPhaseFacts"]

    def test_phase_package_markers_only_not_root_cause(self):
        result = self.phase(
            b"Get:1 https://private.invalid sensitive-package\nReading package lists...\n",
            b"E: Failed to fetch https://private.invalid\n",
        )
        self.assertTrue(result["packageSetupActivity"])
        self.assertFalse(result["browserDownloadActivity"])
        self.assertTrue(result["fetchErrorActivity"])
        self.assertEqual(result["classification"], "package-setup-markers-present")
        text = (self.target / "summary.json").read_text()
        for value in ["private.invalid", "sensitive-package", "https://", "sha256"]:
            self.assertNotIn(value, text)

    def test_phase_browser_markers(self):
        result = self.phase(
            b"Downloading Chromium 123 from https://private.invalid\n", b""
        )
        self.assertTrue(result["browserDownloadActivity"])
        self.assertFalse(result["packageSetupActivity"])
        self.assertEqual(result["classification"], "browser-download-markers-present")

    def test_phase_unknown_missing_unfamiliar_and_malformed(self):
        for stdout, stderr in [(None, None), (b"unfamiliar text", b""), (b"\xff", b"")]:
            with self.subTest(stdout=stdout):
                result = MODULE.setup_phase_facts({}, {}) if stdout is None else None
                if result is None:
                    directory = self.source / "privileged-setup"
                    directory.mkdir(exist_ok=True)
                    (directory / "fixed-browser-setup.stdout").write_bytes(stdout)
                    (directory / "fixed-browser-setup.stderr").write_bytes(stderr)
                    result = MODULE.setup_phase_facts(
                        {
                            x.relative_to(self.source).as_posix(): x
                            for x in directory.iterdir()
                        },
                        {},
                    )
                self.assertEqual(result["classification"], "unknown")

    def test_phase_secret_stream_does_not_supply_categories(self):
        secret = "unique-unpatterned-sensitive-value"
        result = self.phase(
            ("Downloading Chromium " + secret).encode(), b"", {"AUTH": secret}
        )
        self.assertIsNone(result["browserDownloadActivity"])
        self.assertEqual(result["classification"], "unknown")
        self.assertNotIn(secret, (self.target / "summary.json").read_text())

    def test_phase_patterned_secret_does_not_supply_categories(self):
        result = self.phase(
            b"Reading package lists\nauthorization: privatevalue\n", b""
        )
        self.assertIsNone(result["packageSetupActivity"])
        self.assertEqual(result["streams"]["stdout"]["status"], "unknown")

    def test_phase_mixed_markers_fixed_schema(self):
        result = self.phase(
            b"Reading package lists...\n", b"Downloading Chromium 123\n"
        )
        self.assertEqual(result["classification"], "mixed-phase-markers-present")
        self.assertEqual(
            set(result),
            {
                "packageSetupActivity",
                "browserDownloadActivity",
                "fetchErrorActivity",
                "classification",
                "streams",
            },
        )
        for key in [
            "packageSetupActivity",
            "browserDownloadActivity",
            "fetchErrorActivity",
        ]:
            self.assertIn(result[key], [True, False, None])
        self.assertEqual(set(result["streams"]), {"stdout", "stderr"})
        for stream in result["streams"].values():
            self.assertEqual(set(stream), {"present", "bytes", "status"})
            self.assertIs(type(stream["present"]), bool)
            self.assertIs(type(stream["bytes"]), int)
            self.assertIn(stream["status"], ["unknown", "classified"])

    def test_phase_secret_stdout_safe_stderr(self):
        result = self.phase(
            b"Reading package lists\nauthorization: privatevalue\n",
            b"Downloading Chromium 123\n",
        )
        self.assertIsNone(result["packageSetupActivity"])
        self.assertTrue(result["browserDownloadActivity"])
        self.assertEqual(result["classification"], "browser-download-markers-present")

    def test_phase_missing_stream_with_safe_marker(self):
        result = self.phase(b"Reading package lists...\n", None)
        self.assertTrue(result["packageSetupActivity"])
        self.assertIsNone(result["browserDownloadActivity"])
        self.assertEqual(result["classification"], "package-setup-markers-present")

    def test_phase_both_empty_streams_unknown(self):
        result = self.phase(b"", b"")
        self.assertFalse(result["packageSetupActivity"])
        self.assertFalse(result["browserDownloadActivity"])
        self.assertFalse(result["fetchErrorActivity"])
        self.assertEqual(result["classification"], "unknown")

    def test_phase_nested_stream_symlink_and_oversize_refused(self):
        self.nested()
        path = self.source / "privileged-setup/fixed-browser-setup.stdout"
        path.symlink_to(self.source / "install-once.stderr")
        self.refused()
        path.unlink()
        path.write_bytes(b"x" * 1024)
        with mock.patch.object(MODULE, "MAX_FILE", 512):
            self.refused()

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
