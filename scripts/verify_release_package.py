#!/usr/bin/env python3
"""Check the minimal release archive, its checksum, executable, and version gate."""

from __future__ import annotations

import argparse
import hashlib
import re
import subprocess
import sys
import tarfile
import tempfile
import zipfile
from pathlib import Path, PurePosixPath


ROOT = Path(__file__).resolve().parents[1]
LEGAL_FILES = (
    "LICENSE",
    "THIRD_PARTY_NOTICES.md",
)


def project_version() -> str:
    cmake = (ROOT / "CMakeLists.txt").read_text(encoding="utf-8")
    match = re.search(
        r"(?im)^\s*project\(kasumi\s+VERSION\s+([0-9]+\.[0-9]+\.[0-9]+)",
        cmake,
    )
    if match is None:
        raise ValueError("could not read kasumi project version from CMakeLists.txt")
    return match.group(1)


def verify_release_ref(version: str, event_name: str, ref_type: str, ref_name: str) -> None:
    if event_name == "workflow_dispatch" and ref_type != "tag":
        print("Manual branch dispatch: tag check skipped; executable version is still checked.")
        return
    expected_tag = f"v{version}"
    if ref_type != "tag" or ref_name != expected_tag:
        raise ValueError(
            f"release tag mismatch: expected {expected_tag}, got {ref_name!r} ({ref_type})"
        )


def archive_members(archive: Path) -> list[str]:
    if archive.name.lower().endswith(".zip"):
        with zipfile.ZipFile(archive) as package:
            return package.namelist()
    if archive.name.lower().endswith((".tar.gz", ".tgz")):
        with tarfile.open(archive, "r:gz") as package:
            return package.getnames()
    raise ValueError(f"unsupported release archive: {archive.name}")


def normalized_member(name: str) -> str:
    return PurePosixPath(name.replace("\\", "/")).as_posix().removeprefix("./")


def extract_archive(archive: Path, destination: Path) -> None:
    if archive.name.lower().endswith(".zip"):
        with zipfile.ZipFile(archive) as package:
            for name in package.namelist():
                member = PurePosixPath(name.replace("\\", "/"))
                if member.is_absolute() or ".." in member.parts:
                    raise ValueError(f"unsafe archive path: {name}")
            package.extractall(destination)
        return
    with tarfile.open(archive, "r:gz") as package:
        for entry in package.getmembers():
            member = PurePosixPath(entry.name.replace("\\", "/"))
            if member.is_absolute() or ".." in member.parts:
                raise ValueError(f"unsafe archive path: {entry.name}")
        package.extractall(destination)


def verify_checksum(archive: Path, checksum: Path) -> None:
    fields = checksum.read_text(encoding="ascii").strip().split()
    if not fields or not re.fullmatch(r"[0-9a-fA-F]{64}", fields[0]):
        raise ValueError(f"invalid SHA-256 sidecar: {checksum}")
    if len(fields) > 1 and fields[1].lstrip("*") != archive.name:
        raise ValueError(f"checksum sidecar names a different archive: {fields[1]}")
    actual = hashlib.sha256(archive.read_bytes()).hexdigest()
    if actual.lower() != fields[0].lower():
        raise ValueError(f"SHA-256 mismatch for {archive.name}")


def verify_package(archive: Path, checksum: Path, version: str) -> None:
    members = {normalized_member(name) for name in archive_members(archive)}
    executable = "kasumi.exe" if archive.suffix.lower() == ".zip" else "kasumi"
    required = {*LEGAL_FILES, executable}
    missing = sorted(required - members)
    if missing:
        raise ValueError("archive is missing required root files: " + ", ".join(missing))

    verify_checksum(archive, checksum)
    with tempfile.TemporaryDirectory(prefix="kasumi-release-smoke-") as temporary:
        root = Path(temporary).resolve()
        extract_archive(archive, root)
        unexpected = sorted(members - required)
        if unexpected:
            raise ValueError("archive contains unexpected files: " + ", ".join(unexpected))
        binary = root / executable
        version_result = subprocess.run(
            [str(binary), "--version"], check=True, capture_output=True, text=True
        )
        actual_version = version_result.stdout.strip()
        if actual_version != f"kasumi version {version}":
            raise ValueError(
                f"executable reports {actual_version!r}, expected 'kasumi version {version}'"
            )
        subprocess.run([str(binary), "--help"], check=True, capture_output=True, text=True)
        if executable == "kasumi" and not (binary.stat().st_mode & 0o111):
            raise ValueError("Linux archive executable is missing its execute bit")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive", type=Path, required=True)
    parser.add_argument("--checksum", type=Path, required=True)
    parser.add_argument("--event-name", required=True)
    parser.add_argument("--ref-type", required=True)
    parser.add_argument("--ref-name", required=True)
    arguments = parser.parse_args()
    try:
        version = project_version()
        verify_release_ref(
            version, arguments.event_name, arguments.ref_type, arguments.ref_name
        )
        verify_package(arguments.archive, arguments.checksum, version)
    except (
        OSError,
        ValueError,
        subprocess.CalledProcessError,
        tarfile.TarError,
        zipfile.BadZipFile,
    ) as error:
        print(f"release package verification failed: {error}", file=sys.stderr)
        return 1
    print(f"verified {arguments.archive.name}: version {version}, CLI smoke, and SHA-256")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
