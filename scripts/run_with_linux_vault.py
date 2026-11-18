#!/usr/bin/env python3
"""Run a command inside an isolated D-Bus session with an unlocked Linux OS vault."""

import argparse
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time


KWALLET_ENDPOINTS = (
    ("org.kde.ksecretd", "/ksecretd"),
    ("org.kde.kwalletd6", "/modules/kwalletd6"),
    ("org.kde.kwalletd5", "/modules/kwalletd5"),
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--backend",
        choices=("gnome", "kwallet"),
        default="gnome",
        help="Vault daemon to start and unlock inside dbus-run-session.",
    )
    parser.add_argument(
        "--kasumi-backend",
        choices=("auto", "secret-service", "kwallet"),
        default=None,
        help="Optional KASUMI_LINUX_VAULT_BACKEND value for the child command.",
    )
    parser.add_argument(
        "--inner",
        action="store_true",
        help=argparse.SUPPRESS,
    )
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    if args.command and args.command[0] == "--":
        args.command = args.command[1:]
    if not args.command:
        parser.error("missing command to execute")
    return args


def unlock_gnome_keyring() -> None:
    proc = subprocess.run(
        ["gnome-keyring-daemon", "--unlock", "--components=secrets"],
        input=b"kasumi-ci-vault\n",
        capture_output=True,
        check=True,
    )
    for raw_line in proc.stdout.decode("utf-8", errors="replace").splitlines():
        line = raw_line.split(";", 1)[0].strip()
        if "=" in line:
            key, value = line.split("=", 1)
            os.environ[key] = value


def unlock_kwallet() -> None:
    import dbus

    bus = dbus.SessionBus()
    daemon = bus.get_object("org.freedesktop.DBus", "/org/freedesktop/DBus")
    activatable = set(daemon.ListActivatableNames(dbus_interface="org.freedesktop.DBus"))
    if "org.kde.secretservicecompat" in activatable:
        bus.start_service_by_name("org.kde.secretservicecompat", 0)

    opened_any = False
    for service, path in KWALLET_ENDPOINTS:
        if not (bus.name_has_owner(service) or service in activatable):
            continue
        try:
            obj = bus.get_object(service, path)
            iface = dbus.Interface(obj, "org.kde.KWallet")
            iface.pamOpen("kdewallet", dbus.ByteArray(b"\x01" * 56), 0, signature="sayi")
            handle = iface.open("kdewallet", dbus.Int64(0), "kasumi-init", signature="sxs")
            if int(handle) > 0:
                opened_any = True
        except dbus.DBusException:
            continue

    if not opened_any:
        raise RuntimeError("failed to unlock any KDE Wallet D-Bus service")


def run_outer(args: argparse.Namespace) -> int:
    tmp_dir = tempfile.mkdtemp(prefix="kasumi-linux-vault-")
    try:
        root = Path(tmp_dir)
        home_dir = root / "home"
        config_dir = root / "config"
        data_dir = root / "data"
        runtime_dir = root / "runtime"
        for directory in (home_dir, config_dir, data_dir, runtime_dir):
            directory.mkdir(parents=True, exist_ok=True)
        os.chmod(runtime_dir, 0o700)

        env = os.environ.copy()
        env["HOME"] = str(home_dir)
        env["XDG_CONFIG_HOME"] = str(config_dir)
        env["XDG_DATA_HOME"] = str(data_dir)
        env["XDG_RUNTIME_DIR"] = str(runtime_dir)

        if args.kasumi_backend is not None:
            env["KASUMI_LINUX_VAULT_BACKEND"] = args.kasumi_backend
        elif args.backend == "kwallet":
            env["KASUMI_LINUX_VAULT_BACKEND"] = "kwallet"
        else:
            env.pop("KASUMI_LINUX_VAULT_BACKEND", None)

        if args.backend == "gnome":
            env["XDG_CURRENT_DESKTOP"] = "GNOME"
        else:
            env["QT_QPA_PLATFORM"] = "offscreen"
            env["XDG_CURRENT_DESKTOP"] = "KDE"
            (config_dir / "kwalletrc").write_text(
                "[Wallet]\n"
                "Enabled=true\n"
                "First Use=false\n"
                "Prompt on Open=false\n"
                "Close When Idle=false\n"
                "Default Wallet=kdewallet\n\n"
                "[org.kde.secretservicecompat]\n"
                "apiEnabled=true\n",
                encoding="utf-8",
            )

        inner_cmd = [
            "dbus-run-session",
            "--",
            sys.executable,
            str(Path(__file__).resolve()),
            "--inner",
            "--backend",
            args.backend,
            "--",
            *args.command,
        ]
        result = subprocess.run(inner_cmd, env=env, check=False)
        return result.returncode
    finally:
        for attempt in range(10):
            try:
                shutil.rmtree(tmp_dir)
                break
            except OSError:
                if attempt == 9:
                    shutil.rmtree(tmp_dir, ignore_errors=True)
                else:
                    time.sleep(0.05)


def run_inner(args: argparse.Namespace) -> int:
    if args.backend == "gnome":
        unlock_gnome_keyring()
    else:
        unlock_kwallet()
    result = subprocess.run(args.command, check=False)
    return result.returncode


def main() -> int:
    args = parse_args()
    if args.inner:
        return run_inner(args)
    return run_outer(args)


if __name__ == "__main__":
    raise SystemExit(main())
