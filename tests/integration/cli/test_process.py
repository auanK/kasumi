"""Exercise the real executable, including the operating system argument boundary."""

import argparse
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


parser = argparse.ArgumentParser()
parser.add_argument("--binary", type=Path, required=True)
binary = parser.parse_args().binary.resolve()


class CliProcessTest(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix="cli-process-", dir=binary.parent)
        self.root = Path(self.directory.name).resolve()
        self.assertEqual(self.root.parent, binary.parent)
        self.addCleanup(self.directory.cleanup)
        self.environment = {
            name: value for name, value in os.environ.items()
            if not name.upper().startswith(("KASUMI_", "RCLONE_"))
        }
        self.environment.update(
            APPDATA=str(self.root), XDG_CONFIG_HOME=str(self.root), KASUMI_LANG="en",
            KASUMI_PASSWORD="process-test-password", KASUMI_PASSWORD2="process-test-salt",
        )

    def invoke(self, *arguments, input=None, expected=0):
        result = subprocess.run(
            [str(binary), *arguments], input=input, capture_output=True,
            cwd=self.root, env=self.environment, timeout=30,
        )
        self.assertEqual(result.returncode, expected, result.stdout + result.stderr)
        self.assertEqual(result.stderr, b"")
        self.assertRegex(result.stdout, rb"Duration: [0-9]+\.[0-9]{3} s\r?\n")
        self.assertEqual(result.stdout.count(b"Duration:"), 1)
        return result.stdout

    def test_unicode_profile_reaches_the_cli_unchanged(self):
        profile = "Programação-日本-😀"
        output = self.invoke("sync", profile, expected=1)
        # Profile validity remains the domain's responsibility; its spelling must survive argv.
        self.assertIn(f'Synchronizing "{profile}"'.encode(), output)

    def test_unicode_remote_operands_round_trip_in_real_processes(self):
        local, remote = self.root / "local", self.root / "remote"
        local.mkdir()
        filename = "álbum-日本-😀.txt"
        contents = "Unicode payload\n".encode()
        (local / filename).write_bytes(contents)
        self.invoke("config", input=f"n\ndemo\n{local}\n{remote}\nq\n".encode())
        self.invoke("sync", "demo")
        output = self.invoke("remote", "stat", "demo", filename)
        self.assertIn(filename.encode(), output)
        destination = self.root / "destino-日本-😀.txt"
        self.invoke("remote", "get", "demo", filename, str(destination))
        self.assertEqual(destination.read_bytes(), contents)


if __name__ == "__main__":
    unittest.main(argv=[sys.argv[0]], verbosity=2)
