#!/usr/bin/env python3
"""Real CLI journal campaign; private profiles and artifacts stay outside the repo.

Example (Release build on PATH with its runtime DLLs):
  python tests/operational/benchmark_journal_e2e.py --binary build/kasumi.exe \
    --rclone-config /private/rclone.conf --output /private/journal-baselines

The output argument is a parent directory. Each invocation creates a new UUID
campaign, preserves every trial, and never deletes local or remote data.
"""

import argparse
import configparser
import csv
import ctypes
from datetime import datetime, timezone
import hashlib
import io
import json
import os
from pathlib import Path
import platform
import re
import secrets
import shutil
import sqlite3
import subprocess
import time
import tomllib
import uuid


TRACE = re.compile(r"^KASUMI_PERF name=(.+) calls=(\d+) total_us=(\d+)$")
METRICS = {
    "total_us": ("total sync", "total_us"),
    "transfer_phase_us": ("content transfer wall", "total_us"),
    "journal_us": ("journal save", "total_us"),
    "save_attempts": ("journal save", "calls"),
    "saves": ("journal durable saves", "calls"),
    "preparation_saves": ("journal preparation durable saves", "calls"),
    "preparation_written_bytes": ("journal preparation written bytes", "calls"),
    "serialized_bytes": ("journal serialized bytes total", "calls"),
    "encrypted_bytes": ("journal encrypted bytes total", "calls"),
    "written_bytes": ("journal written bytes total", "calls"),
    "framing_bytes": ("journal framing bytes total", "calls"),
    "snapshot_bytes": ("journal snapshot bytes", "calls"),
    "log_bytes": ("journal log bytes", "calls"),
    "confirmation_bytes": ("journal confirmation bytes", "calls"),
    "delta_calculation_us": ("journal delta calculation", "total_us"),
    "replay_us": ("journal replay", "total_us"),
    "clear_us": ("journal clear", "total_us"),
    "retirement_proof_bytes": ("journal retirement proof bytes", "calls"),
    "record_bytes_max": ("journal record serialized bytes", "calls"),
    "serialization_us": ("journal serialization", "total_us"),
    "encryption_us": ("journal encryption", "total_us"),
    "durable_write_us": ("journal durable write", "total_us"),
    "save_us_max": ("journal save maximum us", "calls"),
    "rc_requests": ("rc.http_requests_attempted", "calls"),
    "rc_failures": ("rc.http_requests_failed", "calls"),
    "download_peak_workers": ("content peak in-flight", "calls"),
    "configured_concurrency": ("configured content concurrency", "calls"),
}


def write_json(path, value):
    path.write_text(json.dumps(value, indent=2, ensure_ascii=False) + "\n",
                    encoding="utf-8")


def parse_trace(stderr):
    return {m[1]: {"calls": int(m[2]), "total_us": int(m[3])}
            for line in stderr.splitlines() if (m := TRACE.fullmatch(line))}


def file_path(index):
    return Path(f"group-{index // 100:04d}/leaf-{index % 100 // 20:02d}/file-{index:06d}.bin")


def payload(index, revision):
    return hashlib.shake_256(f"kasumi-journal-070:{index}:{revision}".encode()).digest(1024)


def manifest(count, updated=False):
    return {file_path(i).as_posix(): {
        "size": 1024,
        "sha256": hashlib.sha256(payload(i, int(updated and i % 10 == 0))).hexdigest(),
    } for i in range(count)}


def verify_tree(root, expected):
    actual = {p.relative_to(root).as_posix(): {
        "size": p.stat().st_size, "sha256": hashlib.sha256(p.read_bytes()).hexdigest()
    } for p in root.rglob("*") if p.is_file()}
    expected_dirs = {parent.as_posix() for name in expected
                     for parent in Path(name).parents if parent != Path(".")}
    actual_dirs = {p.relative_to(root).as_posix() for p in root.rglob("*") if p.is_dir()}
    if actual != expected or actual_dirs != expected_dirs:
        raise RuntimeError(f"tree integrity mismatch: {root}")
    return {"files": len(actual), "directories": len(actual_dirs),
            "manifest_sha256": hashlib.sha256(
                json.dumps(actual, sort_keys=True).encode()).hexdigest()}


def verify_database(profile, expected_files):
    database = profile / "db.sqlite"
    if not database.is_file():
        raise RuntimeError("official profile did not create SQLite")
    with sqlite3.connect(database.as_uri() + "?mode=ro", uri=True) as connection:
        integrity = connection.execute("PRAGMA integrity_check").fetchall()
        pending = connection.execute("SELECT COUNT(*) FROM pending_materializations").fetchone()[0]
        rows = connection.execute("SELECT path,hash,size,is_dir FROM nodes ORDER BY path").fetchall()
        metadata = connection.execute("SELECT key,value FROM metadata ORDER BY key").fetchall()
    if integrity != [("ok",)] or pending or sum(not row[3] for row in rows) != expected_files:
        raise RuntimeError("SQLite integrity/count/pending-materialization mismatch")
    expected_paths = {file_path(i).as_posix() for i in range(expected_files)}
    expected_directories = {""} | {parent.as_posix() for name in expected_paths
                                   for parent in Path(name).parents if parent != Path(".")}
    if ({row[0] for row in rows if not row[3]} != expected_paths or
            {row[0] for row in rows if row[3]} != expected_directories or
            any(row[2] != 1024 for row in rows if not row[3])):
        raise RuntimeError("SQLite paths/directories/sizes do not match the physical tree")
    if (profile / "transaction.bin.enc").exists() or (profile / "transaction.bin.enc.new").exists():
        raise RuntimeError("successful sync left a pending journal")
    return {"integrity_check": "ok", "pending_materializations": pending,
            "node_rows": len(rows), "nodes": rows, "metadata": metadata}


def process_counters(process):
    if os.name != "nt":
        return {}
    from ctypes import wintypes

    class IOCounters(ctypes.Structure):
        _fields_ = [(name, ctypes.c_ulonglong) for name in
                    ("read_operations", "write_operations", "other_operations",
                     "read_bytes", "write_bytes", "other_bytes")]

    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.GetProcessIoCounters.argtypes = [wintypes.HANDLE, ctypes.POINTER(IOCounters)]
    kernel.GetProcessTimes.argtypes = [wintypes.HANDLE] + [ctypes.POINTER(wintypes.FILETIME)] * 4
    counters = IOCounters()
    times = [wintypes.FILETIME() for _ in range(4)]
    result = {}
    if kernel.GetProcessIoCounters(int(process._handle), ctypes.byref(counters)):
        result["process_io"] = {name: getattr(counters, name) for name, _ in counters._fields_}
    if kernel.GetProcessTimes(int(process._handle), *(ctypes.byref(t) for t in times)):
        result["process_cpu_us"] = sum((t.dwHighDateTime << 32) | t.dwLowDateTime
                                       for t in times[2:]) // 10
    class MemoryCounters(ctypes.Structure):
        _fields_ = [("cb", wintypes.DWORD), ("page_faults", wintypes.DWORD)] + [
            (name, ctypes.c_size_t) for name in (
                "peak_working_set", "working_set", "peak_paged_pool", "paged_pool",
                "peak_nonpaged_pool", "nonpaged_pool", "pagefile", "peak_pagefile")]
    memory = MemoryCounters()
    memory.cb = ctypes.sizeof(memory)
    psapi = ctypes.WinDLL("psapi", use_last_error=True)
    psapi.GetProcessMemoryInfo.argtypes = [wintypes.HANDLE, ctypes.POINTER(MemoryCounters), wintypes.DWORD]
    if psapi.GetProcessMemoryInfo(int(process._handle), ctypes.byref(memory), memory.cb):
        result["peak_working_set_bytes"] = memory.peak_working_set
    return result


def run(command, environment, log, cwd, input_text=None, start_new_session=False):
    started = time.perf_counter_ns()
    with subprocess.Popen(command, env=environment, cwd=cwd, stdin=subprocess.PIPE,
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                          start_new_session=start_new_session,
                          text=True, encoding="utf-8", errors="replace") as process:
        stdout, stderr = process.communicate(input_text)
        counters = process_counters(process)
    elapsed = (time.perf_counter_ns() - started) // 1000
    log.with_suffix(".stdout.txt").write_text(stdout, encoding="utf-8")
    log.with_suffix(".stderr.txt").write_text(stderr, encoding="utf-8")
    trace = parse_trace(stderr)
    record = {"command": command, "pid": process.pid, "exit_code": process.returncode,
              "process_wall_us": elapsed, "trace": trace, **counters}
    write_json(log.with_suffix(".json"), record)
    return record, stdout, stderr


def private_directory(root):
    root.mkdir(parents=True, exist_ok=False)
    if os.name == "nt":
        identity = subprocess.check_output(["whoami", "/user", "/fo", "csv", "/nh"], text=True)
        sid = next(csv.reader(io.StringIO(identity)))[1]
        subprocess.run(["icacls", str(root), "/inheritance:r", "/grant:r",
                        f"*{sid}:(OI)(CI)F", "*S-1-5-18:(OI)(CI)F"],
                       check=True, capture_output=True)
    else:
        root.chmod(0o700)


def copy_rclone_config(source, destination):
    original = configparser.ConfigParser(interpolation=None)
    original.read_string(source.read_text(encoding="utf-8-sig"))
    isolated = configparser.ConfigParser(interpolation=None)
    chain = []
    name = "kasumi"
    while name:
        if name in isolated or name not in original:
            raise RuntimeError("invalid/cyclic kasumi remote configuration")
        section = dict(original[name])
        isolated[name] = section
        upstream = section.get("remote", "")
        chain.append({"name": name, "type": section.get("type"),
                      "configuration_sha256": hashlib.sha256(
                          json.dumps(section, sort_keys=True).encode()).hexdigest()})
        name = upstream.split(":", 1)[0] if ":" in upstream and not Path(upstream).is_absolute() else None
    if chain[-1]["type"] in ("local", "memory", "alias", "crypt"):
        raise RuntimeError("kasumi is not backed by a confirmed cloud provider")
    isolated["journal_local"] = {"type": "local"}
    if os.name != "nt":
        # The CLI accepts relative remote roots; rclone resolves this alias to /.
        isolated["journal_root"] = {"type": "alias", "remote": "journal_local:/"}
    with destination.open("w", encoding="utf-8") as output:
        isolated.write(output)
    return chain


def environment(root, config, traced):
    (root / "environment").mkdir(parents=True, exist_ok=True)
    result = {key: value for key, value in os.environ.items()
              if not key.upper().startswith(("KASUMI_", "RCLONE_"))}
    result.update(RCLONE_CONFIG=str(config), KASUMI_LANG="en", KASUMI_CONTENT_CONCURRENCY="8")
    result["APPDATA" if os.name == "nt" else "XDG_CONFIG_HOME"] = str(root / "environment")
    if traced:
        result["KASUMI_PERF_TRACE"] = "1"
    return result


def local_target(path):
    return ("journal_local:" + path.as_posix() if os.name == "nt" else
            "journal_root:" + path.as_posix().lstrip("/"))


def create_profiles(args, trial, target, env):
    env = env | {"KASUMI_PASSWORD": secrets.token_urlsafe(32),
                 "KASUMI_PASSWORD2": secrets.token_urlsafe(32)}
    commands = []
    for name in ("publisher", "receiver"):
        commands.extend(("n", name, str(trial / name), target))
    commands.append("q")
    record, _, _ = run([str(args.binary), "config"], env, trial / "create-profiles",
                       trial, "\n".join(commands) + "\n")
    app = trial / "environment" / "kasumi"
    if record["exit_code"] or not (app / "config.toml").is_file():
        raise RuntimeError("official wizard failed; inspect create-profiles logs")
    config = tomllib.loads((app / "config.toml").read_text(encoding="utf-8"))
    for name in ("publisher", "receiver"):
        profile = config["profiles"][name]
        if profile["remote_dir"] != target or Path(profile["local_dir"]) != trial / name:
            raise RuntimeError("official profile destination/isolation mismatch")
    publisher_key = app / "profiles" / "publisher" / "key.bin"
    receiver_key = app / "profiles" / "receiver" / "key.bin"
    if record["exit_code"] or publisher_key.read_bytes() != receiver_key.read_bytes():
        raise RuntimeError("official profile creation/key equality failed")
    return app / "profiles"


def inventory(args, target, env, trial, name, allow_missing=False):
    command = [args.rclone, "lsjson", target, "--recursive"]
    if not allow_missing:
        command.append("--files-only")
    record, stdout, _ = run(command, env, trial / name, trial)
    if allow_missing and record["exit_code"] == 3:
        return []
    if record["exit_code"]:
        raise RuntimeError(f"rclone namespace/authentication check failed: {name}")
    return sorted(json.loads(stdout), key=lambda item: item["Path"])


def measured_sync(args, trial, profile, operation, env, expected, profiles, context):
    record, _, _ = run([str(args.binary), "sync", profile], env, trial / operation, trial)
    result = context | {"operation": operation, "profile": profile, **record,
                        "valid": False}
    trace = record["trace"]
    if not args.trace_off:
        result.update({key: trace.get(name, {}).get(field, 0)
                       for key, (name, field) in METRICS.items()})
        result["operations"] = sum(value["calls"] for name, value in trace.items()
                                   if name.startswith("action/"))
        result["content_objects"] = sum(trace.get("action/" + action, {}).get("calls", 0)
                                        for action in ("Upload", "Download"))
        result["plaintext_content_bytes"] = result["content_objects"] * 1024
        result["rc_read_retries"] = trace.get("RC idempotent read retries", {}).get("calls", 0)
        result["rc_control_us"] = sum(value["total_us"] for name, value in trace.items()
                                      if re.fullmatch(r"rc/[^/]+/[^/]+", name) and name not in
                                      ("rc/operations/copyfile", "rc/sync/copy", "rc/job/batch"))
    try:
        if record["exit_code"]:
            raise RuntimeError(f"sync exit {record['exit_code']} (2 means partial)")
        if not args.trace_off:
            if "total sync" not in trace or "KASUMI_PERF outcome=success" not in (trial / operation).with_suffix(".stderr.txt").read_text(encoding="utf-8"):
                raise RuntimeError("missing successful performance trace")
            if result["saves"] != result["save_attempts"]:
                raise RuntimeError("save attempts/completions mismatch")
            if result["serialized_bytes"] != result["encrypted_bytes"] or result["written_bytes"] != result["serialized_bytes"] + result["framing_bytes"]:
                raise RuntimeError("journal byte accounting mismatch")
        result["tree_integrity"] = verify_tree(trial / profile, expected)
        result["sqlite"] = verify_database(profiles / profile, len(expected))
        if operation == "noop" and not args.trace_off and (result["operations"] or result["saves"]):
            raise RuntimeError("no-op unexpectedly mutated/checkpointed")
        result["valid"] = True
    except Exception as error:
        result["validation_error"] = str(error)
    write_json(trial / (operation + "-measurement.json"), result)
    with (args.campaign / "measurements.jsonl").open("a", encoding="utf-8") as output:
        output.write(json.dumps(result, ensure_ascii=False) + "\n")
    journal_status = ("journal=not-collected saves=not-collected" if args.trace_off else
                      f"journal={result['journal_us'] / 1e6:.3f}s saves={result['saves']}")
    print(f"{context['environment']} n{context['files']} trial{context['trial']:02d} "
          f"{operation}: exit={record['exit_code']} valid={result['valid']} "
          f"wall={record['process_wall_us'] / 1e6:.3f}s "
          f"{journal_status}", flush=True)
    if not result["valid"]:
        raise RuntimeError(result["validation_error"])
    return result


def trial_run(args, backend, count, repetition, config):
    trial = args.campaign / backend / f"n{count}" / f"trial{repetition:02d}"
    trial.mkdir(parents=True, exist_ok=False)
    for name in ("publisher", "receiver"):
        (trial / name).mkdir()
    target = (f"kasumi:audit/{args.campaign.name}/n{count}/trial{repetition:02d}" if backend == "remote"
              else local_target(trial / "storage"))
    if backend == "remote" and not re.fullmatch(r"kasumi:audit/journal-070-(?:group-)?[0-9a-f]{32}/n\d+/trial\d+", target):
        raise RuntimeError("unsafe remote namespace")
    env = environment(trial, config, not args.trace_off)
    write_json(trial / "ownership.json", {"campaign": args.campaign.name, "target": target,
                                         "environment": backend, "files": count, "trial": repetition})
    # Detect ownership/collisions before creating the empty remote directory.
    if inventory(args, target, env, trial, "namespace-before", allow_missing=True):
        raise RuntimeError("namespace already contains objects; refusing reuse")
    created, _, _ = run([args.rclone, "mkdir", target], env, trial / "namespace-mkdir", trial)
    if created["exit_code"] or inventory(args, target, env, trial, "namespace-empty"):
        raise RuntimeError("could not authenticate/create an empty exclusive namespace")
    for i in range(count):
        path = trial / "publisher" / file_path(i)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(payload(i, 0))
    initial = manifest(count)
    final = manifest(count, updated=True)
    write_json(trial / "initial-manifest.json", initial)
    write_json(trial / "final-manifest.json", final)
    profiles = create_profiles(args, trial, target, env)
    context = {"environment": backend, "files": count, "trial": repetition, "target": target}
    sync = lambda profile, operation, expected: measured_sync(
        args, trial, profile, operation, env, expected, profiles, context)
    sync("publisher", "upload", initial)
    published = inventory(args, target, env, trial, "published-objects")
    if not published:
        raise RuntimeError("upload did not publish storage")
    sync("receiver", "download", initial)
    before = verify_database(profiles / "receiver", count)
    before_objects = inventory(args, target, env, trial, "before-noop-objects")
    noop = sync("receiver", "noop", initial)
    after_objects = inventory(args, target, env, trial, "after-noop-objects")
    if before != noop["sqlite"] or before_objects != after_objects:
        raise RuntimeError("no-op changed accepted state or remote objects")
    for i in range(0, count, 10):
        (trial / "publisher" / file_path(i)).write_bytes(payload(i, 1))
    sync("publisher", "partial_upload", final)
    sync("receiver", "partial_download", final)
    publisher = verify_database(profiles / "publisher", count)
    receiver = verify_database(profiles / "receiver", count)
    if publisher["nodes"] != receiver["nodes"]:
        raise RuntimeError("publisher/receiver accepted nodes did not converge")
    final_objects = inventory(args, target, env, trial, "final-objects")
    write_json(trial / "verification.json", {
        "valid": True, "publisher": verify_tree(trial / "publisher", final),
        "receiver": verify_tree(trial / "receiver", final),
        "sqlite_nodes_equal": True, "noop_state_and_objects_unchanged": True,
        "remote_object_count": len(final_objects),
        "remote_object_bytes": sum(item["Size"] for item in final_objects),
    })


def self_check():
    trace = parse_trace("KASUMI_PERF name=journal save wall calls=3 total_us=25\n")
    assert trace == {"journal save wall": {"calls": 3, "total_us": 25}}
    assert len(payload(0, 0)) == 1024 and payload(0, 0) != payload(1, 0)
    for count in (100, 500, 1000, 2000):
        initial, final = manifest(count), manifest(count, True)
        assert sum(initial[p] != final[p] for p in initial) == count // 10
        assert len({v["sha256"] for v in initial.values()}) == count
    print("self-check passed")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path)
    parser.add_argument("--rclone", default=shutil.which("rclone"))
    parser.add_argument("--rclone-config", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--environment", choices=("local", "remote", "both"), default="both")
    parser.add_argument("--files", type=int, nargs="+", default=[100, 500, 1000, 2000])
    parser.add_argument("--trials", type=int, default=3)
    parser.add_argument("--trace-off", action="store_true", help="separate overhead control only")
    parser.add_argument("--group-commit", action="store_true", help="use a fresh journal-070-group namespace")
    parser.add_argument("--self-check", action="store_true")
    args = parser.parse_args()
    if args.self_check:
        self_check()
        return
    if not all((args.binary, args.rclone, args.rclone_config, args.output)) or args.trials < 1 or any(n < 100 or n % 100 for n in args.files):
        parser.error("binary, rclone config, output, positive trials and multiples of 100 are required")
    args.binary = args.binary.resolve(strict=True)
    source_config = args.rclone_config.resolve(strict=True)
    repository = Path(__file__).resolve().parents[2]
    args.campaign = args.output.resolve() / (
        ("journal-070-group-" if args.group_commit else "journal-070-") + uuid.uuid4().hex)
    if args.campaign.is_relative_to(repository):
        parser.error("campaign artifacts must be outside the repository")
    longest_staging_path = (args.campaign / "remote" / f"n{max(args.files)}" / "trial01" /
                            "environment/kasumi/profiles/publisher/.transactions" /
                            ("0" * 32) / "upload-batches" / str(max(args.files)) / ("0" * 64))
    if os.name == "nt" and len(str(longest_staging_path)) >= 260:
        parser.error("output parent is too long for the current Windows staging path; use a short dedicated path")
    if shutil.disk_usage(args.output.resolve().anchor).free < 2 * 1024**3:
        raise RuntimeError("less than 2 GiB available; refusing campaign")
    private_directory(args.campaign)
    print(f"campaign={args.campaign}", flush=True)
    config = args.campaign / "rclone-private.conf"
    source_hash = hashlib.sha256(source_config.read_bytes()).hexdigest()
    chain = copy_rclone_config(source_config, config)
    metadata = {
        "created_utc": datetime.now(timezone.utc).isoformat(),
        "campaign": args.campaign.name, "binary": str(args.binary),
        "binary_sha256": hashlib.sha256(args.binary.read_bytes()).hexdigest(),
        "commit": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=repository, text=True).strip(),
        "branch": subprocess.check_output(["git", "branch", "--show-current"], cwd=repository, text=True).strip(),
        "working_tree": subprocess.check_output(["git", "status", "--short"], cwd=repository, text=True),
        "rclone_version": subprocess.check_output([args.rclone, "version"], text=True),
        "platform": platform.platform(), "python": platform.python_version(),
        "remote_chain": chain, "content_concurrency": 8, "bytes_per_file": 1024,
        "files": args.files, "trials": args.trials, "environment": args.environment,
        "traced": not args.trace_off, "disk_free_bytes": shutil.disk_usage(args.campaign).free,
        "original_rclone_config_sha256": source_hash,
        "original_rclone_config_stat_before": {
            "size": source_config.stat().st_size, "mtime_ns": source_config.stat().st_mtime_ns},
    }
    write_json(args.campaign / "campaign.json", metadata)
    subprocess.run(["git", "diff", "--", "src/application/sync/journal.cpp"], cwd=repository,
                   stdout=(args.campaign / "instrumentation.diff").open("w", encoding="utf-8"), check=True)
    failures = []
    for backend in (("local", "remote") if args.environment == "both" else (args.environment,)):
        for count in args.files:
            for repetition in range(1, args.trials + 1):
                try:
                    trial_run(args, backend, count, repetition, config)
                except Exception as error:
                    failure = {"environment": backend, "files": count, "trial": repetition,
                               "error": str(error)}
                    failures.append(failure)
                    write_json(args.campaign / "failures.json", failures)
                    print(f"FAILED (state preserved): {failure}", flush=True)
                    break
    metadata["completed_utc"] = datetime.now(timezone.utc).isoformat()
    metadata["failures"] = failures
    metadata["original_rclone_config_sha256_after"] = hashlib.sha256(source_config.read_bytes()).hexdigest()
    metadata["original_rclone_config_unchanged"] = metadata["original_rclone_config_sha256_after"] == source_hash
    metadata["original_rclone_config_stat_after"] = {
        "size": source_config.stat().st_size, "mtime_ns": source_config.stat().st_mtime_ns}
    write_json(args.campaign / "campaign.json", metadata)
    print(f"finished campaign={args.campaign} failures={len(failures)}", flush=True)
    if failures or not metadata["original_rclone_config_unchanged"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
