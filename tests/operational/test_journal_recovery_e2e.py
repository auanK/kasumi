#!/usr/bin/env python3
"""Abrupt-process recovery with real CLI profiles, encrypted journal and rclone.

Requires KASUMI_BUILD_JOURNAL_FAULT_TESTS=ON in a separate build. Production
builds and benchmark runs must leave it OFF. No sleeps, mock transport or cleanup.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import shutil
import sqlite3
import subprocess
import uuid

import benchmark_journal_e2e as bench


def tree(root):
    return {p.relative_to(root).as_posix():
            ("directory" if p.is_dir() else hashlib.sha256(p.read_bytes()).hexdigest())
            for p in root.rglob("*")}


def database(profile):
    path = profile / "db.sqlite"
    if not path.exists():
        return None
    with sqlite3.connect(path.as_uri() + "?mode=ro", uri=True) as connection:
        assert connection.execute("PRAGMA integrity_check").fetchall() == [("ok",)]
        return {"nodes": connection.execute(
                    "SELECT path,hash,size,is_dir FROM nodes ORDER BY path").fetchall(),
                "metadata": connection.execute(
                    "SELECT key,value FROM metadata ORDER BY key").fetchall(),
                "pending": connection.execute("SELECT * FROM pending_materializations").fetchall()}


def loaded(stderr):
    match = re.search(r"KASUMI_TEST_RECORD point=loaded phase=(\d+) operations=(\d+)\n"
                      r"((?:KASUMI_TEST_OP[^\n]*\n)*)", stderr)
    assert match, "normal recovery did not authenticate/load the journal"
    states = [int(value) for value in re.findall(r" state=(\d+)", match[3])]
    assert len(states) == int(match[2])
    return {"phase": int(match[1]), "states": states,
            "actions": [int(value) for value in re.findall(r" action=(\d+)", match[3])]}


def case(args, config, name, point, mixed=False, failure=None, corruption=None):
    trial = args.campaign / f"case-{args.case_index:02d}"
    trial.mkdir()
    for profile in ("publisher", "receiver"):
        (trial / profile).mkdir()
    target = bench.local_target(trial / "storage")
    env = bench.environment(trial, config, True)
    profiles = bench.create_profiles(args, trial, target, env)

    def sync(profile, label, settings=None):
        result = bench.run([str(args.binary), "sync", profile], env | (settings or {}),
                           trial / label, trial, start_new_session=os.name != "nt")
        if os.name == "nt" and result[0]["exit_code"] == 86:
            # Abrupt exit skips destructors: stop only this CLI's own RC child.
            app_pid = result[0]["pid"]
            subprocess.run(["powershell", "-NoProfile", "-Command",
                            f"Get-CimInstance Win32_Process -Filter 'ParentProcessId={app_pid}' | "
                            "Where-Object { $_.Name -eq 'rclone.exe' -and $_.CommandLine -match '\\brcd\\b' } | "
                            "ForEach-Object { Stop-Process -Id $_.ProcessId -Force }"], check=True,
                           capture_output=True)
        elif os.name != "nt" and result[0]["exit_code"] == 86:
            try:
                os.killpg(result[0]["pid"], signal.SIGKILL)
            except ProcessLookupError:
                pass
        return result

    initial = {"keep.txt": b"KEEP", "change.txt": b"OLD", "gone.txt": b"GONE",
               "conflict.txt": b"BASE", "old-dir/child.txt": b"CHILD"}
    for path, data in initial.items():
        destination = trial / "publisher" / path
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(data)
    profile = "publisher"
    if mixed:
        for owner in ("publisher", "receiver"):
            record, _, _ = sync(owner, "initial-" + owner)
            assert record["exit_code"] == 0, "fixture sync failed"
        (trial / "publisher/change.txt").write_bytes(b"NEW")
        (trial / "publisher/gone.txt").unlink()
        (trial / "publisher/old-dir/child.txt").unlink()
        (trial / "publisher/old-dir").rmdir()
        (trial / "publisher/new-dir").mkdir()
        (trial / "publisher/new-dir/added.txt").write_bytes(b"ADDED")
        old_mtime = (trial / "receiver/conflict.txt").stat().st_mtime
        (trial / "publisher/conflict.txt").write_bytes(b"REMOTE")
        os.utime(trial / "publisher/conflict.txt", (old_mtime + 60, old_mtime + 60))
        record, _, _ = sync("publisher", "publish-update")
        assert record["exit_code"] == 0
        (trial / "receiver/conflict.txt").write_bytes(b"LOCAL-CONCURRENT")
        os.utime(trial / "receiver/conflict.txt", (old_mtime - 60, old_mtime - 60))
        profile = "receiver"
    original = tree(trial / profile)
    accepted = database(profiles / profile)
    settings = {"KASUMI_TEST_JOURNAL_OBSERVE": "1"}
    if failure:
        settings["KASUMI_TEST_JOURNAL_FAIL"] = failure
    else:
        settings["KASUMI_TEST_JOURNAL_CRASH"] = point
    record, _, stderr = sync(profile, "interrupted", settings)
    if failure:
        assert record["exit_code"] not in (0, 2, 86), "persistence failure did not fail closed"
        assert "KASUMI_TEST_RECORD point=saved/1 phase=1" not in stderr
        assert record["trace"].get("speculative commit uploads", {}).get("calls", 0) == 0
    else:
        assert record["exit_code"] == 86 and f"KASUMI_TEST_CRASH point={point}" in stderr, \
            "not a deterministic abrupt crash"
    journal = profiles / profile / "transaction.bin.enc"
    retired_crash = point == "retired" or point.startswith("cleanup-file/")
    retirement_completion = retired_crash or point in ("clear-authorized", "cleanup-proof-removed")
    if point == "cleanup-proof-removed":
        retired_crash = True
    authority = journal.with_name(journal.name + ".cleared") if retired_crash else journal
    assert authority.exists(), "recovery authority lost"
    shutil.copytree(authority, trial / "journal-after-crash")
    snapshot = journal / "snapshot.enc"
    after_crash = tree(trial / profile)
    sqlite_after_crash = database(profiles / profile)
    early = point in ("saved/0", "prepared/0", "prepared/3", "before-FilesStaged", "saved/1") or failure
    if early:
        assert after_crash == original, "preparation changed user data"
        assert database(profiles / profile) == accepted, "database advanced before effects"
    backups = list((profiles / profile / ".transactions").rglob("*.backup"))
    if mixed and point == "before-FilesStaged":
        assert backups, "fixture did not exercise durable original backups"
    if corruption == "truncated":
        snapshot.write_bytes(snapshot.read_bytes()[:20])
    elif corruption == "authentication":
        data = bytearray(snapshot.read_bytes())
        data[-1] ^= 1
        snapshot.write_bytes(data)
    elif corruption in ("missing-backup", "corrupt-backup", "unused-missing-backup", "unused-corrupt-backup"):
        assert backups
        if corruption.startswith("unused-"):
            # Download may safely ignore a backup while its original is intact.
            selected_backup = next(p for p in backups if p.read_bytes() == b"OLD")
        else:
            # Rename requires backup validation even before application. Select
            # its authenticated slot, independently of filesystem enumeration.
            slot = re.search(r"action=0 state=2 original=1 slot=(\d+) path=conflict.txt", stderr)
            assert slot, "fixture did not prepare an original-preserving rename"
            selected_backup = next(p for p in backups if p.name == slot[1] + ".backup")
            assert selected_backup.read_bytes() == b"LOCAL-CONCURRENT"
        if corruption.endswith("missing-backup"):
            selected_backup.rename(selected_backup.with_suffix(".preserved"))
            assert not selected_backup.exists()
        else:
            selected_backup.write_bytes(b"CORRUPT")
            assert selected_backup.read_bytes() == b"CORRUPT"
        bench.write_json(trial / "corruption-evidence.json", {
            "selected_backup": str(selected_backup), "kind": corruption})
    preserved_journal = tree(authority)
    recovered, _, recovery_stderr = sync(profile, "recovery", {
        "KASUMI_TEST_JOURNAL_OBSERVE": "1", "KASUMI_TEST_JOURNAL_CRASH": "recovered"})
    after_recovery = tree(trial / profile)
    sqlite_after_recovery = database(profiles / profile)
    recovery_decision = None
    state = None if retirement_completion or corruption in ("truncated", "authentication", "incomplete-snapshot") else loaded(recovery_stderr)
    if (point.startswith("append-") and point.endswith("/0")) or point == "before-confirmation/1":
        assert state and state["phase"] == 0 and all(value == 0 for value in state["states"]), \
            "unconfirmed append advanced the authoritative checkpoint"
    if mixed and state:
        assert set(state["actions"]) == {0, 1, 2, 4, 5, 6}, "fixture did not produce the required mixed plan"
    if corruption in ("truncated", "authentication", "incomplete-snapshot", "missing-backup", "corrupt-backup"):
        assert recovered["exit_code"] not in (0, 2, 86), "corrupt authority accepted"
        assert journal.exists() and tree(journal) == preserved_journal
        assert tree(trial / profile) == after_crash and database(profiles / profile) == accepted
    else:
        assert recovered["exit_code"] == 86 and "KASUMI_TEST_CRASH point=recovered" in recovery_stderr
        decision = re.search(r"KASUMI_TEST_EVENT point=recovery/(\d+)", recovery_stderr)
        assert decision, "missing explicit recovery decision"
        recovery_decision = int(decision[1])
        resumable = int(decision[1]) == 3
        if resumable:
            assert state["phase"] <= 3 and all(action in (1, 3, 7, 8) for action in state["actions"])
            assert journal.exists() and tree(journal) == preserved_journal
        else:
            assert not journal.exists(), "completed rollback/roll-forward left journal"
        if state and state["phase"] <= 3:
            assert tree(trial / profile) == original, "rollback changed confirmed or concurrent data"
            assert database(profiles / profile) == accepted
        if args.expect_grouped and early and failure != "parent-sync" and point != "saved/1":
            assert state["phase"] == 0 and all(s == 0 for s in state["states"]), \
                "memory-only preparation became durable progress"
        repeated, _, repeated_stderr = sync(profile, "repeated-recovery", {
            "KASUMI_TEST_JOURNAL_OBSERVE": "1", "KASUMI_TEST_JOURNAL_CRASH": "recovered"})
        assert repeated["exit_code"] == 86 and "KASUMI_TEST_CRASH point=recovered" in repeated_stderr
        assert tree(trial / profile) == after_recovery
        assert database(profiles / profile) == sqlite_after_recovery
        resumed, _, _ = sync(profile, "resumed")
        assert resumed["exit_code"] == 0, "normal restart did not finish"
        assert not journal.exists(), "resumed sync left recovery authority pending"
        final = database(profiles / profile)
        assert final and not final["pending"]
        if mixed:
            assert (trial / "receiver/change.txt").read_bytes() == b"NEW"
            assert (trial / "receiver/new-dir/added.txt").read_bytes() == b"ADDED"
            assert not (trial / "receiver/gone.txt").exists()
            assert not (trial / "receiver/old-dir").exists()
            contents = [p.read_bytes() for p in (trial / "receiver").rglob("*") if p.is_file()]
            assert b"LOCAL-CONCURRENT" in contents and b"REMOTE" in contents and b"KEEP" in contents
        else:
            assert tree(trial / "publisher") == original
            receiver, _, _ = sync("receiver", "receiver-final")
            assert receiver["exit_code"] == 0
            assert tree(trial / "receiver") == original
            assert database(profiles / "receiver")["nodes"] == final["nodes"]
    result = {"case": name, "trial_path": str(trial), "point": point, "failure": failure, "corruption": corruption,
              "persisted": state, "journal_after_crash": preserved_journal,
              "sqlite_before": accepted, "sqlite_after_crash": sqlite_after_crash,
              "sqlite_after_recovery": sqlite_after_recovery,
              "sqlite_after_restart": database(profiles / profile),
              "before": original, "after_crash": after_crash,
              "after_recovery": after_recovery, "after_restart": tree(trial / profile),
              "recovery_decision": recovery_decision, "backup_count": len(backups),
              "interrupted_exit": record["exit_code"], "recovery_exit": recovered["exit_code"],
              "passed": True}
    bench.write_json(trial / "result.json", result)
    print(f"PASS {name}: persisted={state} backups={len(backups)}", flush=True)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", required=True, type=Path)
    parser.add_argument("--rclone", required=True)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--expect-grouped", action="store_true")
    args = parser.parse_args()
    args.binary = args.binary.resolve(strict=True)
    args.campaign = args.output.resolve() / ("fault-" + uuid.uuid4().hex)
    assert not args.campaign.is_relative_to(Path(__file__).resolve().parents[2])
    bench.private_directory(args.campaign)
    config = args.campaign / "rclone-private.conf"
    config.write_text("[journal_local]\ntype = local\n", encoding="utf-8")
    if os.name != "nt":
        with config.open("a", encoding="utf-8") as output:
            output.write("\n[journal_root]\ntype = alias\nremote = journal_local:/\n")
    print(f"campaign={args.campaign}", flush=True)
    cases = [("C1-started", "saved/0", False, None, None),
             ("C2-first", "prepared/0", True, None, None),
             ("C3-backups-C4-middle", "prepared/3", True, None, None),
             ("C4-last-C5-barrier", "before-FilesStaged", True, None, None),
             ("C7-staged", "saved/1", True, None, None),
             ("C8-applied", "saved/2", True, None, None)]
    cases += [("C6-" + failure, "", True, failure, None)
              for failure in ("write", "flush", "sync", "replace", "parent-sync")]
    cases += [("C9-phase-" + str(phase), "saved/" + str(phase), False, None, None)
              for phase in range(3, 13)]
    cases += [("C10-" + corruption, "saved/1", True, None, corruption)
              for corruption in ("truncated", "authentication", "missing-backup", "corrupt-backup",
                                 "unused-missing-backup", "unused-corrupt-backup")]
    cases += [("A-" + point, point + "/0", True, None, None)
              for point in ("append-header", "append-payload", "append-flush", "append-close", "append-sync")]
    cases += [("A-confirmation-" + point, point + "/1", True, None, None)
              for point in ("before-confirmation", "after-confirmation", "confirmed")]
    cases += [("A-local-" + str(index), "append-sync/" + str(index), True, None, None)
              for index in (1, 4, 9)]
    cases += [("D-initial-" + point.replace("/", "-"), point, False, None, "incomplete-snapshot")
              for point in ("before-snapshot", "temporary-write/0", "temporary-sync/0",
                            "before-snapshot-replace", "after-snapshot-replace")]
    cases += [("B-" + failure, "", True, failure, None) for failure in ("close",)]
    cases += [("cleanup-" + point, point, False, None, None) for point in ("before-clear", "retired")]
    cases += [("cleanup-file-" + str(index), "cleanup-file/" + str(index), False, None, None)
              for index in (0, 1)]
    cases += [("cleanup-" + point, point, False, None, None)
              for point in ("clear-authorized", "cleanup-proof-removed")]
    results = []
    for args.case_index, (name, point, mixed, failure, corruption) in enumerate(cases):
        try:
            results.append(case(args, config, name, point, mixed, failure, corruption))
        except Exception as error:
            bench.write_json(args.campaign / "failure.json", {"case": name, "error": str(error)})
            raise
        bench.write_json(args.campaign / "matrix.json", results)


if __name__ == "__main__":
    main()
