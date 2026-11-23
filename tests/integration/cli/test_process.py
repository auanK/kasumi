"""Exercise the real executable, including the operating system argument boundary."""

import argparse
import ctypes
import json
import os
from pathlib import Path
import re
import shutil
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
        self.addCleanup(self._cleanup_os_vault)
        self.environment = {
            name: value for name, value in os.environ.items()
            if name == "KASUMI_LINUX_VAULT_BACKEND"
            or not name.upper().startswith(("KASUMI_", "RCLONE_"))
        }
        self.environment.update(
            APPDATA=str(self.root), XDG_CONFIG_HOME=str(self.root), KASUMI_LANG="en",
            KASUMI_PASSWORD="process-test-password", KASUMI_PASSWORD2="process-test-salt",
        )

    def _cleanup_os_vault(self):
        profiles_dir = self.root / "kasumi" / "profiles"
        if not profiles_dir.is_dir():
            return
        if sys.platform == "win32":
            cred_delete = ctypes.windll.advapi32.CredDeleteW
            cred_delete.argtypes = [ctypes.c_wchar_p, ctypes.c_uint32, ctypes.c_uint32]
            cred_delete.restype = ctypes.c_int
            for entry in profiles_dir.iterdir():
                if entry.is_dir():
                    target = "kasumi:" + (entry / "key.bin").resolve().as_posix().lower()
                    cred_delete(target, 1, 0)
        elif (
            os.environ.get("DBUS_SESSION_BUS_ADDRESS")
            and os.environ.get("KASUMI_LINUX_VAULT_BACKEND") != "kwallet"
            and shutil.which("secret-tool")
        ):
            for entry in profiles_dir.iterdir():
                if entry.is_dir():
                    target = "kasumi:" + (entry / "key.bin").resolve().as_posix()
                    subprocess.run(
                        ["secret-tool", "clear", "target", target],
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL,
                        check=False,
                    )

    def invoke(self, *arguments, input=None, expected=0, environment=None):
        result = self.invoke_raw(
            *arguments, input=input, environment=environment,
        )
        self.assertEqual(result.returncode, expected, result.stdout + result.stderr)
        self.assertEqual(result.stderr, b"")
        command = (
            arguments[2]
            if len(arguments) >= 3 and arguments[0] == "--lang"
            else arguments[0]
        )
        if command not in ("config", "list", "show", "key"):
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
            timeout=60,
        )
        return result

    def test_help_version_and_invalid_grammar_have_no_side_effects(self):
        help_cases = (
            (("--help",), b"Usage: kasumi"),
            (("--version",), b"kasumi version"),
            (("sync", "--help"), b"Usage: kasumi sync"),
            (("repack", "--help"), b"Usage: kasumi repack"),
            (("remote", "contents", "--help"), b"Usage: kasumi remote contents"),
            (("config", "--help"), b"Usage: kasumi config"),
            (("--lang", "pt-BR", "repack", "--help"), b"Uso: kasumi repack"),
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
            ("list", "demo"),
            ("show",),
            ("show", "demo", "extra"),
            ("sync", "demo", "--unknown"),
            ("sync", "demo", "--full", "--full"),
            ("sync", "demo", "--dry-run", "--initial"),
            ("repack", "demo", "--unknown"),
            ("repack", "demo", "--full", "--full"),
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
            (f"n\nnew\n{local}\n{remote}\n\n".encode(), without_credentials),
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
                # CTRL_BREAK_EVENT targets the child process group on Windows.
                process.send_signal(signal.CTRL_BREAK_EVENT)
                process.wait(timeout=5)
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
            import time

            master, slave = pty.openpty()
            process = subprocess.Popen(
                [str(binary), "config"], stdin=slave, stdout=slave,
                stderr=subprocess.PIPE, cwd=self.root, env=self.environment,
                start_new_session=True, close_fds=True,
            )
            os.close(slave)
            output = bytearray()
            try:
                deadline = time.monotonic() + 5
                prompt = b"Quit\n\n> "

                def prompt_ready():
                    return prompt in output.replace(b"\r\n", b"\n")

                while not prompt_ready() and time.monotonic() < deadline:
                    ready, _, _ = select.select(
                        [master], [], [],
                        max(0.0, deadline - time.monotonic()),
                    )
                    if not ready:
                        break
                    try:
                        chunk = os.read(master, 4096)
                    except InterruptedError:
                        continue
                    except OSError:
                        break
                    if not chunk:
                        break
                    output += chunk
                    if process.poll() is not None and not prompt_ready():
                        self.fail(
                            "wizard exited before its prompt appeared: "
                            f"{bytes(output)!r}"
                        )
                self.assertIn(
                    prompt,
                    output.replace(b"\r\n", b"\n"),
                    f"wizard prompt was not observable: {bytes(output)!r}",
                )
                os.kill(process.pid, signal.SIGINT)
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    self.fail(
                        "wizard did not exit after SIGINT; "
                        f"captured PTY output: {bytes(output)!r}"
                    )
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
        self.assertFalse((self.root / "kasumi").exists())

    def test_unicode_profile_reaches_the_cli_unchanged(self):
        profile = "Programação-日本-😀"
        output = self.invoke("sync", profile, expected=1)
        # Profile validity remains the domain's responsibility; its spelling must survive argv.
        self.assertIn(f'Synchronizing "{profile}"'.encode(), output)

    def test_empty_wizard_quits_without_creating_profile_data(self):
        output = self.invoke("config", input=b"e\nc\nk\ns\nd\nr\nq\n")
        self.assertIn(b"No profiles registered.", output)
        self.assertIn(b"[n] New  [q] Quit", output)
        self.assertFalse((self.root / "kasumi").exists())

    def test_wizard_invalid_option_does_not_reprint_menu(self):
        local = self.root / "local"
        local.mkdir()
        remote = self.root / "remote"
        self.invoke("config", input=f"n\ndemo\n{local}\n{remote}\nfile\nq\n".encode())
        output = self.invoke("config", input=b"das\nfoo\nq\n")
        self.assertEqual(output.count(b"=== Kasumi Profiles ==="), 1)
        self.assertEqual(output.count(b"[e] Edit"), 1)
        self.assertEqual(output.count(b"[ERROR] Invalid option."), 2)

    def test_wizard_can_return_to_menu_without_changing_profiles(self):
        local = self.root / "local"
        local.mkdir()
        remote = self.root / "remote"
        self.invoke("config", input=f"n\ndemo\n{local}\n{remote}\nfile\nq\n".encode())
        config = self.root / "kasumi" / "config.toml"
        original = config.read_bytes()

        output = self.invoke(
            "config",
            input=(b"e\nmissing\n:back\nc\n:back\nk\n:back\ns\n:back\n"
                   b"d\n:back\nr\n:back\nn\n:back\n"
                   b"c\ndemo\n:back\ne\ndemo\n:back\ns\ndemo\n:back\nq\n"),
        )
        self.assertIn(b"Profile not found.", output)
        self.assertIn(b"Type :back to return to the menu.", output)
        self.assertEqual(config.read_bytes(), original)

    def test_profile_lifecycle_persists_across_processes(self):
        local = self.root / "local"
        remote = self.root / "remote"
        local.mkdir()
        sentinel = local / "keep.txt"
        sentinel.write_text("outside profile state", encoding="utf-8")
        local_snapshot = sentinel.read_bytes()
        create = f"n\ndemo\n{local}\n{remote}\n\nq\n".encode()
        created = self.invoke("config", input=create)

        data = self.root / "kasumi"
        config = data / "config.toml"
        source_dir = data / "profiles" / "demo"
        source_key = source_dir / "key.bin"
        source_db = source_dir / "db.sqlite"
        self.assertIn(b"Profile created.", created)
        self.assertFalse(remote.exists())
        self.assertFalse(source_key.exists())
        self.assertTrue(source_db.is_file())
        profiles = tomllib.loads(config.read_text(encoding="utf-8"))["profiles"]
        self.assertEqual(Path(profiles["demo"]["local_dir"]), local)
        self.assertEqual(profiles["demo"]["remote_dir"], str(remote))
        self.assertEqual(profiles["demo"]["key_storage"], "vault")
        before = self._tree_snapshot(data)
        names = self.invoke_raw("list")
        self.assertEqual(names.returncode, 0, names.stderr)
        self.assertEqual(names.stdout.splitlines(), [b"demo"])
        details = self.invoke_raw("show", "demo")
        self.assertEqual(details.returncode, 0, details.stderr)
        self.assertIn(str(local).encode(), details.stdout)
        self.assertIn(str(remote).encode(), details.stdout)
        self.assertIn(b"Key storage: vault", details.stdout)
        missing = self.invoke_raw("show", "absent")
        self.assertEqual(missing.returncode, 1)
        self.assertEqual(missing.stdout, b"")
        self.assertIn(b"[ERROR]", missing.stderr)
        self.assertEqual(self._tree_snapshot(data), before)
        self.assertFalse(remote.exists())
        listed = self.invoke("config", input=b"q\n")
        self.assertRegex(listed, rb"\bdemo\s+Initialized\b")
        self.invoke("status", "demo", "--full")

        self.invoke("sync", "demo")
        self.invoke("remote", "contents", "demo", "--audit")
        listed = self.invoke("config", input=b"q\n")
        self.assertRegex(listed, rb"\bdemo\s+Ready\b")
        remote_snapshot = self._tree_snapshot(remote)
        source_db_bytes = source_db.read_bytes()

        without_passwords = self.environment.copy()
        without_passwords.pop("KASUMI_PASSWORD")
        without_passwords.pop("KASUMI_PASSWORD2")
        cloned = self.invoke(
            "config", input=b"c\nabsent\ndemo\ncopy\nq\n",
            environment=without_passwords,
        )
        clone_dir = data / "profiles" / "copy"
        clone_key = clone_dir / "key.bin"
        clone_db = clone_dir / "db.sqlite"
        self.assertIn(b'created from "demo"', cloned)
        self.assertNotIn(b"Password:", cloned)
        self.assertFalse(clone_key.exists())
        self.assertTrue(clone_db.is_file())
        self.assertFalse(source_db.samefile(clone_db))
        self.assertRegex(cloned, rb"\bcopy\s+Initialized\b")
        profiles = tomllib.loads(config.read_text(encoding="utf-8"))["profiles"]
        self.assertEqual(profiles["copy"]["local_dir"], str(local))
        self.assertEqual(profiles["copy"]["remote_dir"], str(remote))
        self.assertEqual(profiles["copy"]["key_storage"], "vault")
        for journal in (
            "transaction.bin.enc", "transaction.log.enc", "confirmed.enc",
            "retired.enc", ".transactions",
        ):
            self.assertFalse((clone_dir / journal).exists())
        self.assertEqual(source_db.read_bytes(), source_db_bytes)
        self.assertEqual(self._tree_snapshot(remote), remote_snapshot)
        self.invoke("status", "copy", environment=without_passwords)

        new_local = self.root / "edited-local"
        new_remote = self.root / "edited-remote"
        before_edit = self._tree_snapshot(data)
        # Unchanged input, rejected changes, and EOF must preserve profile data.
        self.invoke("config", input=b"e\ndemo\n\n\nq\n")
        self.assertEqual(self._tree_snapshot(data), before_edit)
        for confirmation in ("", "n"):
            self.invoke("config", input=f"e\ndemo\n{new_local}\n{new_remote}\n{confirmation}\nq\n".encode())
            self.assertEqual(self._tree_snapshot(data), before_edit)
        self.invoke("config", input=f"e\ndemo\n{new_local}\n{new_remote}\n".encode(), expected=130)
        self.assertEqual(self._tree_snapshot(data), before_edit)
        edited = self.invoke(
            "config", input=f"e\ndemo\n{new_local}\n{new_remote}\ny\nq\n".encode(),
        )
        self.assertIn(b"Profile 'demo' edited successfully.", edited)
        profiles = tomllib.loads(config.read_text(encoding="utf-8"))["profiles"]
        self.assertEqual(Path(profiles["demo"]["local_dir"]), new_local)
        self.assertEqual(profiles["demo"]["remote_dir"], str(new_remote))
        self.assertFalse(new_local.exists())
        self.assertFalse(new_remote.exists())

        source_identity = source_db.stat()
        renamed = self.invoke("config", input=b"r\nabsent\ndemo\nrenamed\nq\n")
        renamed_dir = data / "profiles" / "renamed"
        renamed_db = renamed_dir / "db.sqlite"
        self.assertIn(b"Profile renamed", renamed)
        self.assertFalse(source_dir.exists())
        self.assertEqual(renamed_db.stat().st_ino, source_identity.st_ino)
        self.assertEqual(renamed_db.read_bytes(), source_db_bytes)
        self.assertFalse((renamed_dir / "key.bin").exists())

        before_delete = self._tree_snapshot(data)
        for confirmation in (b"", b"n"):
            self.invoke("config", input=b"d\ncopy\n" + confirmation + b"\nq\n")
            self.assertEqual(self._tree_snapshot(data), before_delete)
        deleted = self.invoke("config", input=b"d\ncopy\ny\nq\n")
        self.assertIn(b"'copy' removed", deleted)
        self.assertFalse(clone_dir.exists())
        deleted = self.invoke("config", input=b"d\nrenamed\ny\nq\n")
        self.assertIn(b"'renamed' removed", deleted)
        self.assertFalse(renamed_dir.exists())
        self.assertEqual(sentinel.read_bytes(), local_snapshot)
        self.assertEqual(self._tree_snapshot(remote), remote_snapshot)

        config.write_text("[invalid", encoding="utf-8")
        broken = self._tree_snapshot(data)
        for arguments in (("list",), ("show", "renamed")):
            result = self.invoke_raw(*arguments)
            self.assertEqual(result.returncode, 1)
            self.assertEqual(result.stdout, b"")
            self.assertIn(b"[ERROR]", result.stderr)
        self.assertEqual(self._tree_snapshot(data), broken)

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
            if name == "initialized":
                inputs.extend(("n", name, str(local), str(remote), ""))
            else:
                inputs.extend(
                    ("c", "initialized", name, "e", name, str(local), str(remote), "y")
                )
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
        self.assertRegex(output, rb"\binitialized\s+Initialized\b")
        self.assertRegex(output, rb"\bready\s+Ready\b")
        self.assertRegex(output, rb"\bpending\s+Pending\b")
        self.assertRegex(output, rb"\bproblem\s+Problem\b")
        for language, label, database_word in (
            ("en", b"Reason:", b"database"),
            ("pt-BR", b"Motivo:", b"banco"),
        ):
            shown = self.invoke_raw("--lang", language, "show", "problem")
            self.assertEqual(shown.returncode, 0, shown.stderr)
            self.assertIn(label, shown.stdout)
            self.assertIn(database_word, shown.stdout)
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
        self.invoke("config", input=f"n\ndemo\n{local}\n{remote}\n\nq\n".encode())
        self.invoke("sync", "demo")
        output = self.invoke("remote", "stat", "demo", "--", filename)
        self.assertIn(filename.encode(), output)
        destination = self.root / "destino-日本-😀.txt"
        self.invoke("remote", "get", "demo", "--", filename, str(destination))
        self.assertEqual(destination.read_bytes(), contents)

    def test_new_profile_selects_key_storage_before_password(self):
        environment = self.environment.copy()
        password = environment.pop("KASUMI_PASSWORD")
        salt = environment.pop("KASUMI_PASSWORD2")
        data = self.root / "kasumi"

        for mode in ("file", "memory"):
            with self.subTest(mode=mode):
                local = self.root / f"{mode}-local"
                remote = self.root / f"{mode}-remote"
                local.mkdir()
                output = self.invoke(
                    "config", environment=environment,
                    input=(f"n\n{mode}\n{local}\n{remote}\ninvalid\n{mode}\n"
                           f"{password}\n{password}\n{salt}\n{salt}\nq\n").encode(),
                )
                self.assertLess(output.index(b"Key storage mode"), output.index(b"Password:"))
                self.assertIn(b"Invalid key storage mode", output)
                self.assertIn(b"Profile created.", output)
                config = tomllib.loads((data / "config.toml").read_text(encoding="utf-8"))
                self.assertEqual(config["profiles"][mode]["key_storage"], mode)
                self.assertEqual((data / "profiles" / mode / "key.bin").is_file(), mode == "file")

    def test_key_storage_modes_and_manual_key_command(self):
        local, remote = self.root / "local", self.root / "remote"
        local.mkdir()
        (local / "item.txt").write_text("payload", encoding="utf-8")
        self.invoke("config", input=f"n\ndemo\n{local}\n{remote}\n\nq\n".encode())
        self.invoke("sync", "demo")

        config = self.root / "kasumi" / "config.toml"
        key_file = self.root / "kasumi" / "profiles" / "demo" / "key.bin"

        switched_file = self.invoke("config", input=b"s\ndemo\nfile\nq\n")
        self.assertIn(b"kasumi key demo", switched_file)
        self.assertEqual(
            tomllib.loads(config.read_text(encoding="utf-8"))["profiles"]["demo"]["key_storage"],
            "file",
        )

        missing = self.invoke("status", "demo", expected=1)
        self.assertIn(b"kasumi key", missing)

        rekey = self.invoke("key", "demo")
        self.assertIn(b"Key saved for profile 'demo'", rekey)
        self.assertTrue(key_file.is_file())
        self.invoke("status", "demo")

        switched_memory = self.invoke("config", input=b"s\ndemo\nmemory\nq\n")
        self.assertIn(b"set to 'memory'", switched_memory)
        self.assertEqual(
            tomllib.loads(config.read_text(encoding="utf-8"))["profiles"]["demo"]["key_storage"],
            "memory",
        )
        self.assertFalse(key_file.exists())

        (local / "item2.txt").write_text("payload-2", encoding="utf-8")
        self.invoke("sync", "demo")
        self.assertFalse(key_file.exists())

        without_passwords = self.environment.copy()
        without_passwords.pop("KASUMI_PASSWORD")
        without_passwords.pop("KASUMI_PASSWORD2")
        eof_sync = self.invoke_raw("sync", "demo", input=b"", environment=without_passwords)
        self.assertEqual(eof_sync.returncode, 130)

    def test_manual_key_command_and_wizard_guard_against_overwrite(self):
        local, remote = self.root / "local", self.root / "remote"
        local.mkdir()
        (local / "item.txt").write_text("payload", encoding="utf-8")
        self.invoke("config", input=f"n\ndemo\n{local}\n{remote}\nfile\nq\n".encode())
        self.invoke("sync", "demo")

        # Same key is idempotent and needs no confirmation.
        same = self.invoke("key", "demo", input=b"")
        self.assertIn(b"Key saved for profile 'demo'", same)

        other_env = self.environment.copy()
        other_env.update(
            KASUMI_PASSWORD="other-password-999",
            KASUMI_PASSWORD2="other-salt-value-999",
        )

        # Different key declined via prompt keeps the stored key intact.
        declined = self.invoke("key", "demo", input=b"n\n", expected=1, environment=other_env)
        self.assertIn(b"Replace stored key", declined)
        self.assertIn(b"Key replacement cancelled", declined)
        self.invoke("status", "demo")

        # EOF on confirmation prompt exits 130 and keeps the stored key intact.
        eof = self.invoke_raw("key", "demo", input=b"", environment=other_env)
        self.assertEqual(eof.returncode, 130)
        self.invoke("status", "demo")

        # Wizard [k] Key also guards against silent overwrite.
        wizard_declined = self.invoke("config", input=b"k\ndemo\nn\nq\n", environment=other_env)
        self.assertIn(b"Replace stored key", wizard_declined)
        self.assertNotIn(b"Key saved for profile 'demo'", wizard_declined)
        self.invoke("status", "demo")

        # Explicit confirmation replaces the key.
        confirmed = self.invoke("key", "demo", input=b"y\n", environment=other_env)
        self.assertIn(b"Key saved for profile 'demo'", confirmed)
        idempotent_new = self.invoke("key", "demo", input=b"", environment=other_env)
        self.assertIn(b"Key saved for profile 'demo'", idempotent_new)

    def test_repack_dry_run_and_execute_in_real_processes(self):
        import time

        local, remote = self.root / "local", self.root / "remote"
        local.mkdir()
        self.invoke("config", input=f"n\ndemo\n{local}\n{remote}\n\nq\n".encode())

        def write_settled(path: Path, payload: bytes):
            path.write_bytes(payload)
            settled = time.time() - 5.0
            os.utime(path, (settled, settled))

        write_settled(local / "one.txt", b"small file one payload")
        self.invoke("sync", "demo")
        write_settled(local / "two.txt", b"small file two payload")
        self.invoke("sync", "demo")

        dry = self.invoke("repack", "demo", "--dry-run", "--full")
        self.assertIn(b"Repack plan:", dry)
        self.assertIn(b"Repack dry-run completed", dry)
        self.assertIn(b"Inventory:", dry)

        repacked = self.invoke("repack", "demo", "--full")
        self.assertIn(b"[OK] Repack completed.", repacked)
        self.assertIn(b"Wire upload", repacked)
        self.assertIn(b"Published commit:", repacked)

        noop = self.invoke("repack", "demo")
        self.assertIn(b"Nothing to repack", noop)

        self.invoke("fsck", "demo")

    def test_repack_reclaim_dirty_in_real_processes(self):
        import time

        local, remote = self.root / "local", self.root / "remote"
        local.mkdir()
        self.invoke("config", input=f"n\ndemo\n{local}\n{remote}\n\nq\n".encode())

        def write_settled(path: Path, payload: bytes):
            path.write_bytes(payload)
            settled = time.time() - 5.0
            os.utime(path, (settled, settled))

        for index in range(16):
            write_settled(local / f"f{index:02d}.bin", bytes([index + 1]) * 184320)
        self.invoke("sync", "demo")

        (local / "f00.bin").unlink()
        self.invoke("sync", "demo")

        default_repack = self.invoke("repack", "demo", "--full")
        self.assertIn(b"Nothing to repack", default_repack)
        self.assertIn(b"1 dirty pack(s) detected; use --reclaim-dirty", default_repack)
        self.assertIn(b"Inventory: 1 existing pack(s)", default_repack)
        self.assertIn(b"1 dirty detected", default_repack)

        dry = self.invoke("repack", "demo", "--reclaim-dirty", "--dry-run")
        self.assertIn(b"Repack plan: 15 blob(s)", dry)
        self.assertIn(b"-> 1 new Micro-Pack(s).", dry)
        self.assertIn(b"Sources: 0 loose blob(s), 0 underfilled pack(s), 1 dirty pack(s).", dry)
        self.assertIn(b"Repack dry-run completed", dry)

        reclaimed = self.invoke("repack", "demo", "--reclaim-dirty", "--full")
        self.assertIn(b"[OK] Repack completed.", reclaimed)
        self.assertIn(b"Repacked 15 blob(s)", reclaimed)
        self.assertIn(b"into 1 new Micro-Pack(s).", reclaimed)
        self.assertIn(b"Sources: 0 loose blob(s), 0 underfilled pack(s), 1 dirty pack(s).", reclaimed)
        self.assertIn(b"Wire upload", reclaimed)
        self.assertIn(b"Published commit:", reclaimed)
        self.assertIn(b"kasumi gc", reclaimed)

        noop = self.invoke("repack", "demo", "--reclaim-dirty")
        self.assertIn(b"Nothing to repack", noop)
        self.assertNotIn(b"--reclaim-dirty", noop)

        self.invoke("fsck", "demo")

    def test_traceability_show_remote_summary_and_config_in_real_processes(self):
        local, remote = self.root / "local", self.root / "remote"
        local.mkdir()
        self.invoke("config", input=f"n\ndemo\n{local}\n{remote}\n\nq\n".encode())
        (local / "note.txt").write_text("traceability", encoding="utf-8")

        sync_out = self.invoke("sync", "demo")
        self.assertIn(b"[OK] Synchronization completed.", sync_out)

        self.invoke("fsck", "demo")

        # Verify offline show works when remote is unreachable.
        parked = self.root / "remote-parked"
        remote.rename(parked)
        try:
            shown = self.invoke("show", "demo")
            shown_full = self.invoke("show", "demo", "--full")
        finally:
            parked.rename(remote)

        self.assertIn(b"Accepted state:", shown)
        self.assertIn(b"Commit origin: sync", shown)
        self.assertIn(b"Last complete sync:", shown)
        self.assertIn(b"Last local attempt:", shown)
        self.assertIn(b"Recent local maintenance:", shown)
        self.assertIn(b"Recent local executions (2):", shown_full)

        summary = self.invoke("remote", "summary", "demo")
        summary_full = self.invoke("remote", "summary", "demo", "--full")
        self.assertIn(b"Recent operational activity (1):", summary)
        self.assertIn(b"fsck", summary_full)

        listed = self.invoke("config", input=b"q\n")
        self.assertIn(b"Last sync", listed)
        self.assertRegex(listed, rb"\bdemo\s+Ready\s+.*\(ok\)")

    def test_gc_dry_run_analyzes_without_mutating_or_publishing_activity(self):
        local, remote = self.root / "local", self.root / "remote"
        local.mkdir()
        self.invoke("config", input=f"n\ndemo\n{local}\n{remote}\n\nq\n".encode())
        (local / "item.txt").write_text("gc-dry-run-process", encoding="utf-8")
        self.invoke("sync", "demo")

        dry = self.invoke("gc", "demo", "--dry-run")
        self.assertIn(b"Simulating garbage collection", dry)
        self.assertIn(b"No garbage collection candidates found", dry)
        self.assertIn(b"Garbage collection dry-run completed: no objects removed.", dry)

        summary = self.invoke("remote", "summary", "demo")
        self.assertIn(b"Recent operational activity: none", summary)

    def test_quiet_suppresses_operational_stdout_while_keeping_errors(self):
        local, remote = self.root / "local", self.root / "remote"
        local.mkdir()
        self.invoke("config", input=f"n\ndemo\n{local}\n{remote}\n\nq\n".encode())
        (local / "item.txt").write_text("quiet-process", encoding="utf-8")

        quiet_sync = self.invoke_raw("sync", "demo", "--quiet")
        self.assertEqual(quiet_sync.returncode, 0, quiet_sync.stdout + quiet_sync.stderr)
        self.assertEqual(quiet_sync.stdout, b"")
        self.assertEqual(quiet_sync.stderr, b"")

        quiet_status = self.invoke_raw("status", "demo", "--quiet")
        self.assertEqual(quiet_status.returncode, 0)
        self.assertEqual(quiet_status.stdout, b"")
        self.assertEqual(quiet_status.stderr, b"")

        quiet_summary = self.invoke_raw("remote", "summary", "demo", "--quiet")
        self.assertEqual(quiet_summary.returncode, 0)
        self.assertEqual(quiet_summary.stderr, b"")
        self.assertIn(b"Remote summary", quiet_summary.stdout)
        self.assertNotIn(b"Duration:", quiet_summary.stdout)

        quiet_fail = self.invoke_raw("sync", "missing", "--quiet")
        self.assertEqual(quiet_fail.returncode, 1)
        self.assertIn(b"[ERROR]", quiet_fail.stdout)
        self.assertNotIn(b"Duration:", quiet_fail.stdout)

    def test_json_output_and_error_codes_in_real_processes(self):
        local, remote = self.root / "local", self.root / "remote"
        local.mkdir()
        self.invoke("config", input=f"n\ndemo\n{local}\n{remote}\n\nq\n".encode())
        (local / "keep.txt").write_text("json-keep", encoding="utf-8")

        def run_json(*args, expected=0):
            res = self.invoke_raw(*args)
            self.assertEqual(res.returncode, expected, res.stdout + res.stderr)
            self.assertEqual(res.stderr, b"")
            return json.loads(res.stdout.decode("utf-8"))

        listed = run_json("list", "--json")
        self.assertEqual(listed["schema_version"], 1)
        self.assertEqual(listed["command"], "list")
        self.assertTrue(listed["ok"])
        self.assertEqual(listed["data"]["profiles"], ["demo"])

        status_doc = run_json("status", "demo", "--json", "--quiet")
        self.assertEqual(status_doc["command"], "status")
        self.assertEqual(status_doc["data"]["action_counts"]["upload"], 1)

        sync_dry = run_json("sync", "demo", "--dry-run", "--json")
        self.assertEqual(sync_dry["command"], "sync")
        self.assertTrue(sync_dry["data"]["dry_run"])

        sync_doc = run_json("--lang", "pt-BR", "sync", "demo", "--json")
        self.assertEqual(sync_doc["command"], "sync")
        self.assertEqual(sync_doc["data"]["uploaded"], 1)
        self.assertTrue(sync_doc["data"]["published"])
        self.assertIn("duration_ms", sync_doc)

        fsck_doc = run_json("fsck", "demo", "--json")
        self.assertEqual(fsck_doc["command"], "fsck")
        self.assertGreaterEqual(fsck_doc["data"]["checked_objects"], 1)

        gc_dry = run_json("gc", "demo", "--dry-run", "--json")
        self.assertEqual(gc_dry["command"], "gc")
        self.assertTrue(gc_dry["data"]["dry_run"])
        self.assertEqual(gc_dry["data"]["removed_objects"], 0)

        repack_dry = run_json("repack", "demo", "--dry-run", "--json")
        self.assertEqual(repack_dry["command"], "repack")

        show_doc = run_json("show", "demo", "--full", "--json")
        self.assertEqual(show_doc["command"], "show")
        self.assertEqual(show_doc["data"]["state"], "ready")
        self.assertEqual(len(show_doc["data"]["accepted_commit"]["commit_id"]), 64)

        summary_doc = run_json("remote", "summary", "demo", "--full", "--json")
        self.assertEqual(summary_doc["command"], "remote summary")
        self.assertTrue(summary_doc["data"]["history_present"])

        missing_doc = run_json("--lang", "pt-BR", "show", "missing", "--json", expected=1)
        self.assertFalse(missing_doc["ok"])
        self.assertEqual(missing_doc["error"]["code"], "profile_not_found")

        bad_doc = run_json("remote", "heads", "demo", "--json", expected=1)
        self.assertEqual(bad_doc["error"]["code"], "invalid_arguments")

        # Exercise partial sync (exit 2) + resolve-missing JSON guard via a second client.
        local2 = self.root / "local2"
        local2.mkdir()
        (local / "lost.txt").write_text("json-lost-payload", encoding="utf-8")
        self.invoke("sync", "demo")

        contents_out = self.invoke("remote", "contents", "demo").decode("utf-8")
        lost_cid = None
        for block in contents_out.split("Content ID:")[1:]:
            if "lost.txt" in block:
                lost_cid = block.strip().splitlines()[0].strip()
                break
        self.assertIsNotNone(lost_cid, contents_out)
        (remote / lost_cid).unlink()

        self.invoke("config", input=f"n\nclient2\n{local2}\n{remote}\n\nq\n".encode())
        partial_doc = run_json("sync", "client2", "--json", expected=2)
        self.assertFalse(partial_doc["ok"])
        self.assertEqual(partial_doc["exit_code"], 2)
        self.assertEqual(partial_doc["error"]["code"], "partial_pending")
        self.assertTrue(partial_doc["data"]["partial"])
        self.assertEqual(partial_doc["data"]["pending_paths"], ["lost.txt"])

        rm_dry = run_json("resolve-missing", "client2", "--dry-run", "--json")
        self.assertTrue(rm_dry["data"]["dry_run"])
        self.assertEqual(rm_dry["data"]["resolved_paths"], ["lost.txt"])

        rm_guard = run_json("resolve-missing", "client2", "--json", expected=1)
        self.assertEqual(rm_guard["error"]["code"], "confirmation_required")
        self.assertEqual(rm_guard["data"]["resolved_paths"], ["lost.txt"])

        rm_confirm = run_json("resolve-missing", "client2", "--confirm", "--json")
        self.assertTrue(rm_confirm["ok"])
        self.assertEqual(rm_confirm["data"]["resolved_count"], 1)
        self.assertTrue(rm_confirm["data"]["published"])

        # Exercise sync --repair on a missing remote object still present locally.
        (local / "repair_me.bin").write_bytes(b"R" * (300 * 1024))
        self.invoke("sync", "demo")
        contents_after = self.invoke("remote", "contents", "demo").decode("utf-8")
        repair_cid = None
        for block in contents_after.split("Content ID:")[1:]:
            if "repair_me.bin" in block:
                repair_cid = block.strip().splitlines()[0].strip()
                break
        self.assertIsNotNone(repair_cid, contents_after)
        self.assertTrue((remote / repair_cid).exists())
        (remote / repair_cid).unlink()

        repair_doc = run_json("sync", "demo", "--repair", "--json")
        self.assertTrue(repair_doc["ok"])
        self.assertTrue(repair_doc["timestamp"].endswith("Z"))
        self.assertEqual(repair_doc["data"]["repaired"], 1)
        self.assertIn("1 repaired", repair_doc["data"]["summary"])
        self.assertFalse(repair_doc["data"]["published"])
        self.assertTrue((remote / repair_cid).exists())
        self.invoke("fsck", "demo")

        diag_doc = run_json("diagnostics", "--json")
        self.assertTrue(diag_doc["ok"])
        self.assertEqual(diag_doc["command"], "diagnostics")
        self.assertTrue(diag_doc["timestamp"].endswith("Z"))
        self.assertIn("overall=ok", diag_doc["data"]["summary"])
        self.assertTrue(diag_doc["data"]["config_exists"])
        self.assertTrue(diag_doc["data"]["overall_ok"])
        self.assertGreaterEqual(len(diag_doc["data"]["profiles"]), 1)
        self.assertIn("rclone", diag_doc["data"])

        diag_single = run_json("diagnostics", "demo", "--json")
        self.assertEqual(diag_single["profile"], "demo")
        self.assertEqual(len(diag_single["data"]["profiles"]), 1)
        self.assertEqual(diag_single["data"]["profiles"][0]["name"], "demo")
        self.assertTrue(diag_single["data"]["profiles"][0]["healthy"])

        diag_missing = run_json("diagnostics", "absent", "--json", expected=1)
        self.assertEqual(diag_missing["error"]["code"], "profile_not_found")

        # Verify --log-file in both NDJSON (--json) and clean UTF-8 text modes.
        ndjson_log = self.root / "logs" / "process.ndjson"
        run_json("diagnostics", "--json", "--log-file", str(ndjson_log))
        run_json("list", "--json", "--log-file", str(ndjson_log))
        ndjson_lines = [
            json.loads(line)
            for line in ndjson_log.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]
        self.assertEqual(len(ndjson_lines), 2)
        self.assertEqual(ndjson_lines[0]["command"], "diagnostics")
        self.assertTrue(ndjson_lines[0]["timestamp"].endswith("Z"))
        self.assertIn("overall=ok", ndjson_lines[0]["data"]["summary"])
        self.assertEqual(ndjson_lines[1]["command"], "list")
        self.assertTrue(ndjson_lines[1]["timestamp"].endswith("Z"))

        text_log = self.root / "logs" / "process.log"
        self.invoke("diagnostics", "demo", "--log-file", str(text_log))
        self.invoke("sync", "demo", "--log-file", str(text_log))
        self.invoke("list", "--log-file", str(text_log))
        text_contents = text_log.read_text(encoding="utf-8")
        self.assertNotIn("\x1b", text_contents)
        self.assertIn("] [OK] diagnostics demo | ", text_contents)
        self.assertIn("] [OK] sync demo | Everything in sync (", text_contents)
        self.assertIn("] [OK] list | completed", text_contents)

    def test_gc_safe_automation_min_age_and_busy_log(self):
        local, remote = self.root / "local", self.root / "remote"
        local.mkdir()
        self.invoke("config", input=f"n\ndemo\n{local}\n{remote}\n\nq\n".encode())
        (local / "live.txt").write_text("live-gc-safe", encoding="utf-8")
        self.invoke("sync", "demo")

        # Capture <history>/<gc>/<v1>/<writers> right after sync, before gc
        # creates the sibling <probes> directory (also 4 path segments deep).
        writer_dirs = [
            Path(root_dir)
            for root_dir, _dirs, _files in os.walk(remote)
            if len(Path(root_dir).relative_to(remote).parts) == 4
        ]
        self.assertEqual(len(writer_dirs), 1)
        writer_dir = writer_dirs[0]

        orphan_id = "a" * 64
        orphan_payload = b"orphan-grace-payload-bytes"
        (remote / orphan_id).write_bytes(orphan_payload)

        # Default 6h grace period defers freshly created orphan object.
        dry_proc = self.invoke_raw("gc", "demo", "--dry-run", "--json")
        self.assertEqual(dry_proc.returncode, 0, dry_proc.stdout + dry_proc.stderr)
        dry_doc = json.loads(dry_proc.stdout.decode("utf-8"))
        self.assertTrue(dry_doc["ok"])
        self.assertEqual(dry_doc["data"]["candidate_objects"], 0)
        self.assertEqual(dry_doc["data"]["deferred_recent_objects"], 1)
        self.assertEqual(dry_doc["data"]["min_age_hours"], 6)
        self.assertTrue((remote / orphan_id).exists())

        # Explicit --min-age 0 reclaims it cleanly and fsck stays green.
        gc_proc = self.invoke_raw("gc", "demo", "--min-age", "0", "--json")
        self.assertEqual(gc_proc.returncode, 0, gc_proc.stdout + gc_proc.stderr)
        gc_doc = json.loads(gc_proc.stdout.decode("utf-8"))
        self.assertTrue(gc_doc["ok"])
        self.assertEqual(gc_doc["data"]["candidate_objects"], 1)
        self.assertEqual(gc_doc["data"]["removed_objects"], 1)
        self.assertEqual(gc_doc["data"]["candidate_bytes"], len(orphan_payload))
        self.assertEqual(gc_doc["data"]["removed_bytes"], len(orphan_payload))
        self.assertEqual(gc_doc["data"]["min_age_hours"], 0)
        self.assertFalse((remote / orphan_id).exists())
        self.invoke("fsck", "demo")

        # Simulate active writer marker under <history>/<gc>/<v1>/<writers>/<token>
        # and verify [BUSY] text log + remote_busy code without mutating barrier.
        marker = writer_dir / ("0" * 32)
        marker.write_bytes(b"kasumi-gc-v1:writer:" + b"0" * 32)
        try:
            busy_log = self.root / "logs" / "busy.log"
            busy_res = self.invoke_raw(
                "gc", "demo", "--log-file", str(busy_log)
            )
            self.assertEqual(busy_res.returncode, 1)
            log_text = busy_log.read_text(encoding="utf-8")
            self.assertIn("] [BUSY] gc demo | [remote_busy]", log_text)
        finally:
            marker.unlink()

    def test_multi_barrier_diagnostics_and_targeted_removal_cli(self):
        local, remote = self.root / "local", self.root / "remote"
        local.mkdir()
        self.invoke("config", input=f"n\ndemo\n{local}\n{remote}\n\nq\n".encode())
        (local / "live.txt").write_text("multi-barrier-cli", encoding="utf-8")
        self.invoke("sync", "demo")

        writer_dirs = [
            Path(root_dir)
            for root_dir, _dirs, _files in os.walk(remote)
            if len(Path(root_dir).relative_to(remote).parts) == 4
        ]
        self.assertEqual(len(writer_dirs), 1)
        writer_dir = writer_dirs[0]
        # Run an empty live gc so the barriers directory is created under <gc>/<v1>
        self.invoke("gc", "demo")
        four_part_dirs = [
            Path(root_dir)
            for root_dir, _dirs, _files in os.walk(remote)
            if len(Path(root_dir).relative_to(remote).parts) == 4
        ]
        barrier_dirs = [d for d in four_part_dirs if d != writer_dir]
        self.assertEqual(len(barrier_dirs), 1)
        barriers_dir = barrier_dirs[0]
        t1 = "1" * 32
        t2 = "2" * 32
        (barriers_dir / t1).write_bytes(
            f"kasumi-gc-v1:barrier:{t1}\nstarted_at=1700000100\npid=1111\nmachine=node-one".encode(
                "utf-8"
            )
        )
        (barriers_dir / t2).write_bytes(
            f"kasumi-gc-v1:barrier:{t2}\nstarted_at=1700000200\npid=2222\nmachine=node-two".encode(
                "utf-8"
            )
        )

        writers_proc = self.invoke_raw("remote", "writers", "demo", "--json")
        self.assertEqual(
            writers_proc.returncode, 0, writers_proc.stdout + writers_proc.stderr
        )
        writers_json = json.loads(writers_proc.stdout.decode("utf-8"))
        self.assertTrue(writers_json["ok"])
        self.assertTrue(writers_json["data"]["barrier_present"])
        self.assertEqual(len(writers_json["data"]["barriers"]), 2)
        self.assertEqual(
            {b["machine_name"] for b in writers_json["data"]["barriers"]},
            {"node-one", "node-two"},
        )

        # Ambiguous remove-barrier rejects without deleting either barrier.
        ambig = self.invoke_raw(
            "gc", "remove-barrier", "demo", "--confirm-abandoned", "--json"
        )
        self.assertNotEqual(ambig.returncode, 0)
        self.assertTrue((barriers_dir / t1).exists())
        self.assertTrue((barriers_dir / t2).exists())

        # Targeted remove-barrier by token removes only t1.
        rm1_proc = self.invoke_raw(
            "gc", "remove-barrier", "demo", t1, "--confirm-abandoned", "--json"
        )
        self.assertEqual(
            rm1_proc.returncode, 0, rm1_proc.stdout + rm1_proc.stderr
        )
        rm1 = json.loads(rm1_proc.stdout.decode("utf-8"))
        self.assertTrue(rm1["ok"])
        self.assertEqual(rm1["data"]["outcome"], "removed")
        self.assertEqual(rm1["data"]["remaining_barriers_count"], 1)
        self.assertFalse((barriers_dir / t1).exists())
        self.assertTrue((barriers_dir / t2).exists())

        # Single remaining barrier is auto-removed without specifying its ID.
        rm2_proc = self.invoke_raw(
            "gc", "remove-barrier", "demo", "--confirm-abandoned", "--json"
        )
        self.assertEqual(
            rm2_proc.returncode, 0, rm2_proc.stdout + rm2_proc.stderr
        )
        rm2 = json.loads(rm2_proc.stdout.decode("utf-8"))
        self.assertTrue(rm2["ok"])
        self.assertEqual(rm2["data"]["outcome"], "removed")
        self.assertEqual(rm2["data"]["remaining_barriers_count"], 0)
        self.assertFalse((barriers_dir / t2).exists())


if __name__ == "__main__":
    unittest.main(argv=[sys.argv[0]], verbosity=2)
