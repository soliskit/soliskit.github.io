"""Boundaries for the browser package installer. No package is installed here."""

import importlib.util
import json
import pathlib
import tempfile
import unittest

PATH = pathlib.Path(__file__).parents[1] / "scripts/install_browser_packages.py"
SPEC = importlib.util.spec_from_file_location("installer", PATH)
installer = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(installer)


def manifest(**changes):
    data = {
        "schema": 1,
        "platform": "ubuntu24.04-x64",
        "packages": ["libnss3", "fonts-liberation", "libgtk-4-1"],
    }
    data.update(changes)
    return data


class InstallerTests(unittest.TestCase):
    def load(self, data):
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / "manifest.json"
            path.write_text(data if isinstance(data, str) else json.dumps(data))
            return installer.load_packages(path)

    def test_accepts_the_pinned_shape(self):
        self.assertEqual(
            self.load(manifest()), ["libnss3", "fonts-liberation", "libgtk-4-1"]
        )

    def test_rejects_unexpected_content(self):
        for data in [
            manifest(schema=2),
            manifest(platform="ubuntu22.04-x64"),
            manifest(packages=[]),
            manifest(packages="libnss3"),
            manifest(packages=["--allow-unauthenticated"]),
            manifest(packages=["Libnss3"]),
            manifest(packages=["libnss3 libgtk-4-1"]),
            manifest(packages=["libnss3", "libnss3"]),
            manifest(packages=[f"pkg{n:03}" for n in range(101)]),
            manifest(packages=[5]),
            "[]",
            "not json",
        ]:
            with self.subTest(data=data), self.assertRaises((ValueError, TypeError)):
                self.load(data)

    def test_rejects_symlink_and_oversize(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            real = root / "real.json"
            real.write_text(json.dumps(manifest()))
            link = root / "link.json"
            link.symlink_to(real)
            with self.assertRaises(ValueError):
                installer.load_packages(link)
            big = root / "big.json"
            big.write_text(" " * (installer.MAX_BYTES + 1))
            with self.assertRaises(ValueError):
                installer.load_packages(big)

    def test_install_commands_are_exact(self):
        calls = []

        def fake(command, **options):
            calls.append((command, options))

        installer.install(["libnss3", "libgtk-4-1"], run=fake)
        prefix = ["sudo", "-n", "env", "DEBIAN_FRONTEND=noninteractive", "LC_ALL=C"]
        self.assertEqual(calls[0][0], [*prefix, "apt-get", "update"])
        self.assertEqual(
            calls[1][0],
            [
                *prefix,
                "apt-get",
                "install",
                "-y",
                "--no-install-recommends",
                "--",
                "libnss3",
                "libgtk-4-1",
            ],
        )
        for _, options in calls:
            self.assertIs(options["check"], True)
            self.assertEqual(set(options["env"]), {"PATH"})

    def test_requires_exactly_one_path(self):
        with self.assertRaises(ValueError):
            installer.main(["installer"])


if __name__ == "__main__":
    unittest.main()
