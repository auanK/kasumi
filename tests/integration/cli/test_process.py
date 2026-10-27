"""Exercise the real executable, including the operating system argument boundary."""

import argparse
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import tomllib
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

    def invoke(self, *arguments, input=None, expected=0, environment=None):
        result = self.invoke_raw(
            *arguments, input=input, environment=environment,
        )
        self.assertEqual(result.returncode, expected, result.stdout + result.stderr)
        self.assertEqual(result.stderr, b"")
        self.assertRegex(
            result.stdout,
            rb"(?:Duration|Dura\xc3\xa7\xc3\xa3o): [0-9]+\.[0-9]{3} s\r?\n",
        )
        self.assertEqual(
            result.stdout.count(b"Duration:") +
            result.stdout.count("Duração:".encode()), 1,
        )
        return result.stdout

    def invoke_raw(self, *arguments, input=None, environment=None):
        result = subprocess.run(
            [str(binary), *arguments], input=input, capture_output=True,
            cwd=self.root,
            env=self.environment if environment is None else environment,
            timeout=30,
        )
        return result

    def test_help_version_and_invalid_grammar_have_no_side_effects(self):
        help_cases = (
            (("--help",), b"Usage: kasumi"),
            (("--version",), b"kasumi version"),
            (("sync", "--help"), b"Usage: kasumi sync"),
            (("remote", "contents", "--help"), b"Usage: kasumi remote contents"),
            (("config", "--help"), b"Usage: kasumi config"),
            (("--lang", "pt-BR", "remote", "contents", "--help"), b"Uso:"),
        )
        for arguments, marker in help_cases:
            with self.subTest(arguments=arguments):
                result = self.invoke_raw(*arguments)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stderr, b"")
                self.assertIn(marker, result.stdout)
                self.assertNotIn(b"Duration:", result.stdout)
                self.assertNotIn("Duração:".encode(), result.stdout)

        invalid_cases = (
            ("unknown-command",),
            ("remote", "contents"),
            ("remote", "get", "demo", "source"),
            ("sync", "demo", "--unknown"),
            ("sync", "demo", "--full", "--full"),
            ("sync", "demo", "--dry-run", "--initial"),
        )
        for arguments in invalid_cases:
            with self.subTest(arguments=arguments):
                result = self.invoke_raw(*arguments)
                self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
                self.assertEqual(result.stdout, b"")
                self.assertIn(b"[ERROR]", result.stderr)
                self.assertNotIn(b"Duration:", result.stdout + result.stderr)
                self.assertNotIn("Duração:".encode(), result.stdout + result.stderr)
        self.assertFalse((self.root / "kasumi").exists())

    def test_eof_cancels_config_without_creating_persistent_data(self):
        without_credentials = self.environment.copy()
        without_credentials.pop("KASUMI_PASSWORD")
        without_credentials.pop("KASUMI_PASSWORD2")
        local = str(self.root / "local")
        remote = str(self.root / "remote")
        inputs = (
            (b"", self.environment),
            (b"n\n", self.environment),
            (f"n\nnew\n{local}\n".encode(), self.environment),
            (f"n\nnew\n{local}\n{remote}\n".encode(), without_credentials),
            (b"c\n", self.environment),
        )
        for input_bytes, environment in inputs:
            with self.subTest(input=input_bytes):
                output = self.invoke(
                    "config", input=input_bytes, expected=130,
                    environment=environment,
                )
                self.assertIn(b"Operation cancelled by user.", output)
                self.assertFalse((self.root / "kasumi").exists())

    def test_interrupting_wizard_process_returns_130(self):
        if os.name == "nt":
            import ctypes
            import msvcrt
            import signal
            import time

            process = subprocess.Popen(
                [str(binary), "config"], stdin=subprocess.PIPE,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                cwd=self.root, env=self.environment,
                creationflags=subprocess.CREATE_NEW_PROCESS_GROUP,
            )
            output = bytearray()
            try:
                handle = ctypes.c_void_p(
                    msvcrt.get_osfhandle(process.stdout.fileno()),
                )
                available = ctypes.c_ulong()
                kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
                peek = kernel32.PeekNamedPipe
                peek.argtypes = [
                    ctypes.c_void_p, ctypes.c_void_p, ctypes.c_ulong,
                    ctypes.c_void_p, ctypes.POINTER(ctypes.c_ulong),
                    ctypes.c_void_p,
                ]
                peek.restype = ctypes.c_int
                deadline = time.monotonic() + 5
                while time.monotonic() < deadline:
                    if not peek(
                        handle, None, 0, None, ctypes.byref(available), None,
                    ):
                        raise ctypes.WinError(ctypes.get_last_error())
                    if available.value:
                        output += os.read(
                            process.stdout.fileno(), available.value,
                        )
                        if b"Quit" in output:
                            break
                    if process.poll() is not None:
                        self.fail("wizard exited before its menu appeared")
                    time.sleep(0.01)
                else:
                    self.fail("wizard menu was not observable")
                process.send_signal(signal.CTRL_C_EVENT)
                remaining, error = process.communicate(timeout=5)
                output += remaining
            finally:
                if process.poll() is None:
                    process.kill()
                process.communicate(timeout=5)
        else:
            import pty
            import select
            import signal

            master, slave = pty.openpty()
            process = subprocess.Popen(
                [str(binary), "config"], stdin=slave, stdout=slave,
                stderr=subprocess.PIPE, cwd=self.root, env=self.environment,
                start_new_session=True, close_fds=True,
            )
            os.close(slave)
            output = bytearray()
            try:
                ready, _, _ = select.select([master], [], [], 5)
                self.assertTrue(ready, "wizard menu was not observable")
                output += os.read(master, 4096)
                self.assertIn(b"Quit", output)
                os.kill(process.pid, signal.SIGINT)
                process.wait(timeout=5)
                while True:
                    ready, _, _ = select.select([master], [], [], 0.2)
                    if not ready:
                        break
                    try:
                        chunk = os.read(master, 4096)
                    except OSError:
                        break
                    if not chunk:
                        break
                    output += chunk
                _, error = process.communicate(timeout=5)
            finally:
                if process.poll() is None:
                    process.kill()
                process.communicate(timeout=5)
                os.close(master)

        self.assertEqual(process.returncode, 130, bytes(output) + error)
        self.assertEqual(error, b"")
        self.assertIn(b"Operation cancelled by user.", output)
        self.assertRegex(
            output,
            rb"Duration: [0-9]+\.[0-9]{3} s\r?\n",
        )
        self.assertFalse((self.root / "kasumi").exists())

    def test_unicode_profile_reaches_the_cli_unchanged(self):
        profile = "Programação-日本-😀"
        output = self.invoke("sync", profile, expected=1)
        # Profile validity remains the domain's responsibility; its spelling must survive argv.
        self.assertIn(f'Synchronizing "{profile}"'.encode(), output)

    def test_empty_wizard_quits_without_creating_profile_data(self):
        output = self.invoke("config", input=b"q\n")
        self.assertIn(b"No profiles registered.", output)
        for choice in (b"Edit", b"New", b"Clone", b"Delete", b"Rename", b"Quit"):
            self.assertIn(choice, output)
        self.assertFalse((self.root / "kasumi").exists())

    def test_profile_lifecycle_persists_across_processes(self):
        local = self.root / "local"
        remote = self.root / "remote"
        local.mkdir()
        sentinel = local / "keep.txt"
        sentinel.write_text("outside profile state", encoding="utf-8")
        local_snapshot = sentinel.read_bytes()
        create = f"n\ndemo\n{local}\n{remote}\nq\n".encode()
        created = self.invoke("config", input=create)

        data = self.root / "kasumi"
        config = data / "config.toml"
        source_dir = data / "profiles" / "demo"
        source_key = source_dir / "key.bin"
        source_db = source_dir / "db.sqlite"
        self.assertIn(b"Profile created.", created)
        self.assertFalse(remote.exists())
        self.assertTrue(source_key.is_file())
        self.assertTrue(source_db.is_file())
        profiles = tomllib.loads(config.read_text(encoding="utf-8"))["profiles"]
        self.assertEqual(Path(profiles["demo"]["local_dir"]), local)
        self.assertEqual(profiles["demo"]["remote_dir"], str(remote))
        listed = self.invoke("config", input=b"q\n")
        self.assertIn(b"- demo [Initialized]", listed)
        self.invoke("status", "demo", "--full")

        self.invoke("sync", "demo")
        self.invoke("remote", "contents", "demo", "--audit")
        listed = self.invoke("config", input=b"q\n")
        self.assertIn(b"- demo [Ready]", listed)
        remote_snapshot = self._tree_snapshot(remote)
        source_key_bytes = source_key.read_bytes()
        source_db_bytes = source_db.read_bytes()

        without_passwords = self.environment.copy()
        without_passwords.pop("KASUMI_PASSWORD")
        without_passwords.pop("KASUMI_PASSWORD2")
        cloned = self.invoke(
            "config", input=b"c\ndemo\ncopy\nq\n",
            environment=without_passwords,
        )
        clone_dir = data / "profiles" / "copy"
        clone_key = clone_dir / "key.bin"
        clone_db = clone_dir / "db.sqlite"
        self.assertIn(b'created from "demo"', cloned)
        self.assertNotIn(b"Password:", cloned)
        self.assertEqual(clone_key.read_bytes(), source_key_bytes)
        self.assertTrue(clone_db.is_file())
        self.assertFalse(source_db.samefile(clone_db))
        self.assertIn(b"- copy [Initialized]", cloned)
        profiles = tomllib.loads(config.read_text(encoding="utf-8"))["profiles"]
        self.assertEqual(profiles["copy"]["local_dir"], str(local))
        self.assertEqual(profiles["copy"]["remote_dir"], str(remote))
        for journal in (
            "transaction.bin.enc", "transaction.log.enc", "confirmed.enc",
            "retired.enc", ".transactions",
        ):
            self.assertFalse((clone_dir / journal).exists())
        self.assertEqual(source_db.read_bytes(), source_db_bytes)
        self.assertEqual(self._tree_snapshot(remote), remote_snapshot)

        new_local = self.root / "edited-local"
        new_remote = self.root / "edited-remote"
        edited = self.invoke(
            "config", input=f"e\ndemo\n{new_local}\n{new_remote}\nq\n".encode(),
        )
        self.assertIn(b"Profile 'demo' edited successfully.", edited)
        profiles = tomllib.loads(config.read_text(encoding="utf-8"))["profiles"]
        self.assertEqual(Path(profiles["demo"]["local_dir"]), new_local)
        self.assertEqual(profiles["demo"]["remote_dir"], str(new_remote))
        self.assertFalse(new_local.exists())
        self.assertFalse(new_remote.exists())

        source_identity = source_db.stat()
        renamed = self.invoke("config", input=b"r\ndemo\nrenamed\nq\n")
        renamed_dir = data / "profiles" / "renamed"
        renamed_db = renamed_dir / "db.sqlite"
        self.assertIn(b"Profile renamed", renamed)
        self.assertFalse(source_dir.exists())
        self.assertEqual(renamed_db.stat().st_ino, source_identity.st_ino)
        self.assertEqual(renamed_db.read_bytes(), source_db_bytes)
        self.assertEqual((renamed_dir / "key.bin").read_bytes(), source_key_bytes)

        deleted = self.invoke("config", input=b"d\ncopy\nq\n")
        self.assertIn(b"'copy' removed", deleted)
        self.assertFalse(clone_dir.exists())
        deleted = self.invoke("config", input=b"d\nrenamed\nq\n")
        self.assertIn(b"'renamed' removed", deleted)
        self.assertFalse(renamed_dir.exists())
        self.assertEqual(sentinel.read_bytes(), local_snapshot)
        self.assertEqual(self._tree_snapshot(remote), remote_snapshot)

    def test_wizard_presents_all_local_states_without_mutating_storage(self):
        data = self.root / "kasumi"
        root = data / "profiles"
        profiles = ("initialized", "ready", "pending", "problem")
        inputs = []
        for name in profiles:
            local = self.root / f"local-{name}"
            local.mkdir()
            if name in ("ready", "pending"):
                (local / f"{name}.txt").write_text(name, encoding="utf-8")
            remote = self.root / f"remote-{name}"
            inputs.extend(("n", name, str(local), str(remote)))
        self.invoke("config", input=("\n".join((*inputs, "q", ""))).encode())

        self.invoke("sync", "ready")
        self.invoke("sync", "pending")
        pending_db = root / "pending" / "db.sqlite"
        database = sqlite3.connect(pending_db)
        try:
            row = database.execute(
                "SELECT path, hash, size, mtime FROM nodes "
                "WHERE is_dir = 0 ORDER BY path LIMIT 1"
            ).fetchone()
            self.assertIsNotNone(row)
            database.execute(
                "INSERT INTO pending_materializations (path, hash, size, mtime) "
                "VALUES (?, ?, ?, ?)", row,
            )
            database.commit()
        finally:
            database.close()
        (self.root / "local-pending" / "pending.txt").unlink()
        (root / "problem" / "db.sqlite").write_bytes(b"not a SQLite database")

        persistent_before = self._tree_snapshot(data)
        remote_before = {
            name: self._tree_snapshot(self.root / f"remote-{name}")
            for name in profiles
        }
        output = self.invoke("--lang", "pt-BR", "config", input=b"q\n")
        self.assertIn("Perfis Kasumi".encode(), output)
        self.assertIn("- initialized [Initialized]".encode(), output)
        self.assertIn("- ready [Ready]".encode(), output)
        self.assertIn("- pending [Pending]".encode(), output)
        self.assertIn("- problem [Problem]".encode(), output)
        self.assertEqual(self._tree_snapshot(data), persistent_before)
        self.assertEqual(
            {name: self._tree_snapshot(self.root / f"remote-{name}") for name in profiles},
            remote_before,
        )

    def _tree_snapshot(self, directory):
        return {
            entry.relative_to(directory).as_posix(): (
                entry.is_dir(), entry.stat().st_size, entry.stat().st_mtime_ns,
                entry.read_bytes() if entry.is_file() else None,
            )
            for entry in sorted(directory.rglob("*"))
        } if directory.exists() else None

    def test_unicode_remote_operands_round_trip_in_real_processes(self):
        local, remote = self.root / "local", self.root / "remote"
        local.mkdir()
        filename = "--álbum-日本-😀.txt"
        contents = "Unicode payload\n".encode()
        (local / filename).write_bytes(contents)
        self.invoke("config", input=f"n\ndemo\n{local}\n{remote}\nq\n".encode())
        self.invoke("sync", "demo")
        output = self.invoke("remote", "stat", "demo", "--", filename)
        self.assertIn(filename.encode(), output)
        destination = self.root / "destino-日本-😀.txt"
        self.invoke("remote", "get", "demo", "--", filename, str(destination))
        self.assertEqual(destination.read_bytes(), contents)


if __name__ == "__main__":
    unittest.main(argv=[sys.argv[0]], verbosity=2)
