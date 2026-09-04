#!/usr/bin/env python3
"""Run repeatable black-box Kasumi benchmarks through an rclone RC session."""

import argparse
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
import filecmp
import json
import os
from pathlib import Path
import re
import sqlite3
import subprocess
import tempfile
import threading
import time


MASTER_KEY = "0123456789abcdef" * 4
TRACE = re.compile(r"^KASUMI_PERF name=(.+) calls=(\d+) total_us=(\d+)$")


def write_config(root, local, remote):
    environment_root = root / "environment"
    app_data = environment_root / "kasumi"
    app_data.mkdir(parents=True)
    local.mkdir(parents=True)
    (app_data / "config.toml").write_text(
        "[profiles.perf]\n"
        f"local_dir = {json.dumps(str(local))}\n"
        f"remote_dir = {json.dumps(remote)}\n"
        "min_history_depth = 5\n"
        "min_history_age_hours = 6\n",
        encoding="utf-8",
    )
    return environment_root


def command_environment(environment_root, rclone_config, traced, content_concurrency):
    environment = os.environ.copy()
    environment["KASUMI_MASTER_KEY"] = MASTER_KEY
    if rclone_config:
        environment["RCLONE_CONFIG"] = str(rclone_config)
    if traced:
        environment["KASUMI_PERF_TRACE"] = "1"
    else:
        environment.pop("KASUMI_PERF_TRACE", None)
    environment["KASUMI_CONTENT_CONCURRENCY"] = str(content_concurrency)
    environment.setdefault("KASUMI_LANG", "en")
    if os.name == "nt":
        environment["APPDATA"] = str(environment_root)
    else:
        environment["XDG_CONFIG_HOME"] = str(environment_root)
    return environment


def sync(kasumi, local, environment, traced):
    started = time.perf_counter()
    result = subprocess.run(
        [str(kasumi), "sync", "perf"],
        cwd=local,
        env=environment,
        capture_output=True,
        text=True,
        timeout=600,
        check=False,
    )
    elapsed = time.perf_counter() - started
    if result.returncode != 0:
        raise RuntimeError(
            json.dumps(
                {
                    "kasumi_executable": str(kasumi),
                    "exit_code": result.returncode,
                    "stdout": result.stdout,
                    "stderr": result.stderr,
                },
                indent=2,
            )
        )
    metrics = {}
    if traced:
        for line in result.stderr.splitlines():
            match = TRACE.match(line)
            if match:
                metrics[match.group(1)] = {
                    "calls": int(match.group(2)),
                    "total_ms": int(match.group(3)) / 1000,
                }
    diagnostics = "\n".join(
        line
        for line in result.stderr.splitlines()
        if not line.startswith("KASUMI_PERF")
    )
    return elapsed, metrics, result.stdout, diagnostics


def preview(kasumi, local, environment):
    started = time.perf_counter()
    result = subprocess.run(
        [str(kasumi), "sync", "perf", "--dry-run"],
        cwd=local,
        env=environment,
        capture_output=True,
        text=True,
        timeout=600,
        check=False,
    )
    elapsed = time.perf_counter() - started
    if result.returncode != 0 or not (
        "Nothing to do" in result.stdout or "Nada a fazer" in result.stdout
    ):
        raise RuntimeError(
            json.dumps(
                {
                    "preview_exit_code": result.returncode,
                    "stdout": result.stdout,
                    "stderr": result.stderr,
                },
                indent=2,
            )
        )
    return elapsed, result.stdout


def create_payload(local, file_count, file_size):
    for index in range(file_count):
        size = (
            file_size[index % len(file_size)]
            if isinstance(file_size, tuple)
            else file_size
        )
        block = bytes(
            (offset + index) % 251
            for offset in range(min(size, 64 * 1024))
        )
        path = local / f"file-{index:03d}.bin"
        with path.open("wb") as output:
            remaining = size
            while remaining:
                chunk = block[:remaining]
                output.write(chunk)
                remaining -= len(chunk)


def create_distinct_payload(local, file_count):
    for index in range(file_count):
        (local / f"file-{index:04d}.bin").write_bytes(index.to_bytes(8, "little"))


def list_remote_objects(rclone, storage_location, rclone_config):
    environment = os.environ.copy()
    environment["RCLONE_CONFIG"] = str(rclone_config)
    result = subprocess.run(
        [
            str(rclone),
            "lsf",
            f"{storage_location.rstrip('/')}/objects",
            "--recursive",
            "--files-only",
        ],
        env=environment,
        capture_output=True,
        text=True,
        timeout=600,
        check=False,
    )
    if result.returncode != 0:
        raise RuntimeError(
            f"could not list benchmark objects: {result.stderr.strip()}"
        )
    return set(result.stdout.splitlines())


def read_local_state(environment_root):
    database = environment_root / "kasumi" / "profiles" / "perf" / "db.sqlite"
    with closing(
        sqlite3.connect(f"file:{database}?mode=ro", uri=True)
    ) as connection:
        metadata = dict(connection.execute("SELECT key, value FROM metadata"))
    return int(metadata["generation"]), metadata["commit_id"]


def verify_real_publication(
    before_objects, after_objects, before_state, after_state,
    require_content=True,
):
    generation, commit_id = after_state
    failures = []
    if generation <= before_state[0] or commit_id == before_state[1]:
        failures.append("local state did not advance")
    if not any(
        identifier.startswith(f"history/commits/{commit_id}/")
        for identifier in after_objects
    ):
        failures.append("published commit object is missing")
    if not any(
        identifier.startswith(f"history/heads/{commit_id}-")
        for identifier in after_objects
    ):
        failures.append("published head marker is missing")
    if require_content and not any(
        "/" not in identifier
        for identifier in after_objects - before_objects
    ):
        failures.append("published content object is missing")
    old_heads = {
        identifier
        for identifier in before_objects
        if identifier.startswith("history/heads/")
    }
    if old_heads & after_objects:
        failures.append("old parent marker was not cleaned up")
    if failures:
        raise RuntimeError("; ".join(failures))


def run_r11_state_scenario(
    kasumi, rclone, root, scenario_name, change, file_count, file_size,
    repetition, remote, remote_config, content_concurrency,
):
    name = f"{scenario_name}-rep{repetition}"
    scenario = root / name
    local = scenario / "local"
    if remote:
        storage_location = f"{remote.rstrip('/')}/{name}"
        rclone_config = remote_config
    else:
        storage = scenario / "storage"
        storage.mkdir(parents=True)
        rclone_config = scenario / "rclone.conf"
        rclone_config.write_text(
            "[bench]\n"
            "type = alias\n"
            f"remote = {storage.as_posix()}\n",
            encoding="utf-8",
        )
        storage_location = "bench:kasumi"

    environment_root = write_config(scenario, local, storage_location)
    environment = command_environment(
        environment_root, rclone_config, False, content_concurrency
    )
    environment["PATH"] = str(rclone.parent) + os.pathsep + environment["PATH"]
    sync(kasumi, local, environment, False)
    create_payload(local, file_count, file_size)
    if change == "delete":
        (local / "keep.bin").write_bytes(b"keep")
    sync(kasumi, local, environment, False)

    before_state = read_local_state(environment_root)
    before_objects = (
        list_remote_objects(rclone, storage_location, rclone_config)
        if remote else set()
    )
    if change == "delete":
        for path in local.glob("file-*.bin"):
            path.unlink()

    traced_environment = command_environment(
        environment_root, rclone_config, True, content_concurrency
    )
    traced_environment["PATH"] = environment["PATH"]
    elapsed, metrics, stdout, stderr = sync(
        kasumi, local, traced_environment, True
    )
    after_state = read_local_state(environment_root)
    if change == "delete":
        if after_state[0] <= before_state[0]:
            raise RuntimeError("delete did not advance local state")
        if remote:
            after_objects = list_remote_objects(
                rclone, storage_location, rclone_config
            )
            verify_real_publication(
                before_objects,
                after_objects,
                before_state,
                after_state,
                require_content=False,
            )
            verify_second_client(
                kasumi,
                rclone,
                scenario,
                local,
                storage_location,
                rclone_config,
                content_concurrency,
            )
    elif after_state != before_state:
        raise RuntimeError("no-op changed local state")

    preview_elapsed, preview_stdout = preview(kasumi, local, environment)
    journal_metric = metrics.get("journal save", {"calls": 0, "total_ms": 0})
    return {
        "kasumi_executable": str(kasumi),
        "scenario": scenario_name,
        "change": change,
        "repetition": repetition,
        "benchmark": "real-remote" if remote else "structural-alias",
        "files": file_count,
        "file_size_bytes": file_size,
        "elapsed_seconds": round(elapsed, 6),
        "exit_code": 0,
        "stdout": stdout,
        "stderr": stderr,
        "publication_verified": bool(remote and change == "delete"),
        "second_client_verified": bool(remote and change == "delete"),
        "immediate_preview_elapsed_seconds": round(preview_elapsed, 6),
        "immediate_preview_nothing_to_do": (
            "Nothing to do" in preview_stdout or "Nada a fazer" in preview_stdout
        ),
        "journal_saves": journal_metric["calls"],
        "journal_save_wall_seconds": round(
            journal_metric["total_ms"] / 1000, 6
        ),
        "journal_record_max_bytes": metrics.get(
            "journal record serialized bytes", {"calls": 0}
        )["calls"],
        "rc_requests": sum(
            value["calls"] for name, value in metrics.items()
            if name.startswith("rc/operations/")
            or name.startswith("rc/core/")
        ),
        "local_scan_wall_seconds": round(
            metrics.get("local filesystem scan", {"total_ms": 0})[
                "total_ms"
            ] / 1000,
            6,
        ),
        "remote_observation_wall_seconds": round(
            metrics.get("remote history observation", {"total_ms": 0})[
                "total_ms"
            ] / 1000,
            6,
        ),
        "initial_observation_wall_seconds": round(
            metrics.get("initial observation", {"total_ms": 0})["total_ms"]
            / 1000,
            6,
        ),
        "delete_remote_actions": metrics.get(
            "action/DeleteRemote", {"calls": 0}
        )["calls"],
        "delete_remote_directory_actions": metrics.get(
            "action/DeleteRemoteDirectory", {"calls": 0}
        )["calls"],
        "metrics": metrics,
    }


def run_r21_mutation_scenario(
    kasumi, rclone, root, scenario_name, change, file_count, file_size,
    repetition, remote, remote_config, content_concurrency,
):
    name = f"{scenario_name}-rep{repetition}"
    scenario = root / name
    local = scenario / "local"
    if remote:
        storage_location = f"{remote.rstrip('/')}/{name}"
        rclone_config = remote_config
    else:
        storage = scenario / "storage"
        storage.mkdir(parents=True)
        rclone_config = scenario / "rclone.conf"
        rclone_config.write_text(
            "[bench]\n"
            "type = alias\n"
            f"remote = {storage.as_posix()}\n",
            encoding="utf-8",
        )
        storage_location = "bench:kasumi"

    environment_root = write_config(scenario, local, storage_location)
    environment = command_environment(
        environment_root, rclone_config, False, content_concurrency
    )
    environment["PATH"] = str(rclone.parent) + os.pathsep + environment["PATH"]
    sync(kasumi, local, environment, False)
    create_payload(local, file_count, file_size)
    sync(kasumi, local, environment, False)
    before_state = read_local_state(environment_root)
    before_objects = list_remote_objects(
        rclone, storage_location, rclone_config
    )

    if change == "create":
        for index in range(file_count):
            size = file_size[index % len(file_size)] if isinstance(
                file_size, tuple
            ) else file_size
            (local / f"new-{index:05d}.bin").write_bytes(
                bytes([index % 251]) * size
            )
    elif change == "duplicate":
        for index in range(file_count):
            size = file_size[index % len(file_size)] if isinstance(
                file_size, tuple
            ) else file_size
            (local / f"duplicate-{index:05d}.bin").write_bytes(
                bytes([255]) * size
            )
    elif change == "delete":
        for index in range(file_count):
            (local / f"file-{index:03d}.bin").unlink()
    elif change == "rename":
        for index in range(file_count):
            (local / f"file-{index:03d}.bin").rename(
                local / f"renamed-{index:05d}.bin"
            )
    else:
        raise RuntimeError(f"unknown R21 mutation: {change}")

    traced_environment = command_environment(
        environment_root, rclone_config, True, content_concurrency
    )
    traced_environment["PATH"] = environment["PATH"]
    elapsed, metrics, stdout, stderr = sync(
        kasumi, local, traced_environment, True
    )
    after_state = read_local_state(environment_root)
    if after_state[0] <= before_state[0] or after_state[1] == before_state[1]:
        raise RuntimeError(f"{scenario_name}/{change} did not publish a state")
    after_objects = list_remote_objects(rclone, storage_location, rclone_config)
    verify_real_publication(
        before_objects,
        after_objects,
        before_state,
        after_state,
        require_content=change in ("create", "duplicate"),
    )

    preview_elapsed, preview_stdout = preview(kasumi, local, environment)
    second_client_elapsed = 0.0
    second_client_metrics = {}
    if remote:
        second_client_elapsed, second_client_metrics = verify_second_client(
            kasumi,
            rclone,
            scenario,
            local,
            storage_location,
            rclone_config,
            content_concurrency,
        )
    endpoint_metrics = {
        metric_name: value
        for metric_name, value in metrics.items()
        if metric_name.startswith("rc/operations/")
        or metric_name.startswith("rc/core/")
    }
    return {
        "kasumi_executable": str(kasumi),
        "scenario": scenario_name,
        "change": change,
        "repetition": repetition,
        "benchmark": "real-remote" if remote else "structural-alias",
        "files_before": file_count,
        "files_changed": file_count,
        "file_size_bytes": file_size,
        "elapsed_seconds": round(elapsed, 6),
        "exit_code": 0,
        "stdout": stdout,
        "stderr": stderr,
        "publication_verified": bool(remote),
        "structural_publication_verified": True,
        "second_client_verified": bool(remote),
        "second_client_elapsed_seconds": round(second_client_elapsed, 6),
        "second_client_content_gets": second_client_metrics.get(
            "rc/get_content", {"calls": 0}
        )["calls"],
        "second_client_content_peak_in_flight": second_client_metrics.get(
            "content peak in-flight", {"calls": 0}
        )["calls"],
        "second_client_content_downloads_reused": second_client_metrics.get(
            "content downloads reused", {"calls": 0}
        )["calls"],
        "second_client_plaintext_downloads_reused": second_client_metrics.get(
            "content plaintext reused", {"calls": 0}
        )["calls"],
        "second_client_download_decryption_seconds": round(
            second_client_metrics.get(
                "download decryption", {"total_ms": 0}
            )["total_ms"] / 1000,
            6,
        ),
        "second_client_download_plaintext_copy_seconds": round(
            second_client_metrics.get(
                "download plaintext copy", {"total_ms": 0}
            )["total_ms"] / 1000,
            6,
        ),
        "immediate_preview_elapsed_seconds": round(preview_elapsed, 6),
        "immediate_preview_nothing_to_do": (
            "Nothing to do" in preview_stdout or "Nada a fazer" in preview_stdout
        ),
        "local_scanner_invocations": metrics.get(
            "local scanner invocations", {"calls": 0}
        )["calls"],
        "local_scanner_avoided": metrics.get(
            "local scanner avoided", {"calls": 0}
        )["calls"],
        "usn_delta_records": metrics.get(
            "USN delta records", {"calls": 0}
        )["calls"],
        "usn_selective_fallbacks": metrics.get(
            "USN selective fallbacks", {"calls": 0}
        )["calls"],
        "local_scan_wall_seconds": round(
            metrics.get("local filesystem scan", {"total_ms": 0})[
                "total_ms"
            ] / 1000,
            6,
        ),
        "remote_observation_wall_seconds": round(
            metrics.get("remote history observation", {"total_ms": 0})[
                "total_ms"
            ] / 1000,
            6,
        ),
        "rc_requests": sum(value["calls"] for value in endpoint_metrics.values()),
        "delete_remote_actions": metrics.get(
            "action/DeleteRemote", {"calls": 0}
        )["calls"],
        "content_uploads_elided": metrics.get(
            "content uploads elided", {"calls": 0}
        )["calls"],
        "metrics": metrics,
    }


def verify_second_client(kasumi, rclone, scenario, local, remote, rclone_config,
                         content_concurrency):
    second_root = scenario / "second-client"
    second_local = second_root / "local"
    environment_root = write_config(second_root, second_local, remote)
    environment = command_environment(
        environment_root, rclone_config, True, content_concurrency
    )
    environment["PATH"] = str(rclone.parent) + os.pathsep + environment["PATH"]
    elapsed, metrics, _, _ = sync(kasumi, second_local, environment, True)
    expected = {
        path.relative_to(local) for path in local.rglob("*") if path.is_file()
    }
    actual = {
        path.relative_to(second_local)
        for path in second_local.rglob("*")
        if path.is_file()
    }
    if expected != actual or not all(
        filecmp.cmp(local / path, second_local / path, shallow=False)
        for path in expected
    ):
        raise RuntimeError("second client did not reconstruct the snapshot")
    return elapsed, metrics


def run_scenario(
    kasumi,
    rclone,
    root,
    scenario_name,
    file_count,
    file_size,
    latency_ms,
    remote,
    remote_config,
    content_concurrency,
    skip_second_client=False,
):
    scenario = root / scenario_name
    local = scenario / "local"
    if remote:
        storage_location = f"{remote.rstrip('/')}/{scenario_name}"
        rclone_config = remote_config
    else:
        storage = scenario / "storage"
        storage.mkdir(parents=True)
        rclone_config = scenario / "rclone.conf"
        rclone_config.write_text(
            "[bench]\n"
            "type = alias\n"
            f"remote = {storage.as_posix()}\n",
            encoding="utf-8",
        )
        storage_location = "bench:kasumi"
    environment_root = write_config(scenario, local, storage_location)
    environment = command_environment(
        environment_root, rclone_config, False, content_concurrency
    )
    environment["PATH"] = str(rclone.parent) + os.pathsep + environment["PATH"]
    sync(kasumi, local, environment, False)
    create_payload(local, file_count, file_size)
    before_state = read_local_state(environment_root)
    before_objects = (
        list_remote_objects(rclone, storage_location, rclone_config)
        if remote and file_count
        else set()
    )
    traced_environment = command_environment(
        environment_root, rclone_config, True, content_concurrency
    )
    traced_environment["PATH"] = environment["PATH"]
    traced_environment["KASUMI_PERF_RC_DELAY_MS"] = str(latency_ms)
    elapsed, metrics, stdout, stderr = sync(
        kasumi, local, traced_environment, True
    )
    second_client_elapsed = 0.0
    second_client_metrics = {}
    if remote and file_count:
        after_objects = list_remote_objects(
            rclone, storage_location, rclone_config
        )
        verify_real_publication(
            before_objects,
            after_objects,
            before_state,
            read_local_state(environment_root),
        )
        if not skip_second_client:
            second_client_elapsed, second_client_metrics = verify_second_client(
                kasumi,
                rclone,
                scenario,
                local,
                storage_location,
                rclone_config,
                content_concurrency,
            )
    preview_elapsed, preview_stdout = preview(kasumi, local, environment)
    endpoint_metrics = {
        metric_name: value
        for metric_name, value in metrics.items()
        if metric_name.startswith("rc/operations/")
        or metric_name.startswith("rc/core/")
    }
    if metrics.get("rc/list", {"calls": 0})["calls"]:
        raise RuntimeError("normal Sync performed a full recursive object list")
    put_metric = metrics.get("content PUT", {"calls": 0, "total_ms": 0})
    verification_metric = metrics.get(
        "content verification", {"calls": 0, "total_ms": 0}
    )
    transfer_metric = metrics.get(
        "content transfer wall", {"calls": 0, "total_ms": 0}
    )
    configured_concurrency = metrics.get(
        "configured content concurrency", {"calls": content_concurrency}
    )["calls"]
    inferred_concurrency = min(content_concurrency, file_count) if file_count else 0
    effective_concurrency = metrics.get(
        "content peak in-flight", {"calls": inferred_concurrency}
    )["calls"]
    completion_count = metrics.get(
        "content completion count", {"calls": 0}
    )["calls"]
    get_count = metrics.get("rc/get_content", {"calls": 0})["calls"]
    remote_hash_count = metrics.get("rc/operations/hashsumfile", {"calls": 0})[
        "calls"
    ]
    return {
        "kasumi_executable": str(kasumi),
        "scenario": scenario_name,
        "benchmark": "real-remote" if remote else "structural-alias",
        "files": file_count,
        "payload_bytes": sum(
            file_size[index % len(file_size)]
            if isinstance(file_size, tuple)
            else file_size
            for index in range(file_count)
        ),
        "elapsed_seconds": round(elapsed, 6),
        "artificial_latency_ms": latency_ms,
        "exit_code": 0,
        "stdout": stdout,
        "stderr": stderr,
        "publication_verified": bool(remote and file_count),
        "second_client_verified": bool(
            remote and file_count and not skip_second_client
        ),
        "second_client_elapsed_seconds": round(second_client_elapsed, 6),
        "second_client_content_gets": second_client_metrics.get(
            "rc/get_content", {"calls": 0}
        )["calls"],
        "second_client_content_peak_in_flight": second_client_metrics.get(
            "content peak in-flight", {"calls": 0}
        )["calls"],
        "immediate_preview_elapsed_seconds": round(preview_elapsed, 6),
        "immediate_preview_nothing_to_do": (
            "Nothing to do" in preview_stdout or "Nada a fazer" in preview_stdout
        ),
        "content_concurrency_bound": configured_concurrency,
        "effective_max_concurrent_remote_content_operations": effective_concurrency,
        "content_completion_count": completion_count,
        "upload_operations_serial": effective_concurrency <= 1,
        "put_content_count": put_metric["calls"],
        "get_readback_content_count": get_count,
        "remote_hash_verification_count": remote_hash_count,
        "total_content_transfer_wall_seconds": round(
            transfer_metric["total_ms"] / 1000, 6
        )
        if transfer_metric["calls"]
        else 0,
        "average_put_latency_ms": round(
            put_metric["total_ms"] / put_metric["calls"], 3
        )
        if put_metric["calls"]
        else 0,
        "average_verification_latency_ms": round(
            verification_metric["total_ms"] / verification_metric["calls"], 3
        )
        if verification_metric["calls"]
        else 0,
        "rc_requests": sum(
            value["calls"] for value in endpoint_metrics.values()
        ),
        "full_list": metrics.get("rc/list", {"calls": 0})["calls"],
        "scoped_list": metrics.get("rc/list_prefix", {"calls": 0})["calls"],
        "metrics": metrics,
    }


def run_history_depth(
    kasumi, rclone, root, depth, latency_ms, remote, remote_config, content_concurrency
):
    scenario_name = f"history-{depth}"
    scenario = root / scenario_name
    local = scenario / "local"
    if remote:
        storage_location = f"{remote.rstrip('/')}/{scenario_name}"
        rclone_config = remote_config
    else:
        storage = scenario / "storage"
        storage.mkdir(parents=True)
        rclone_config = scenario / "rclone.conf"
        rclone_config.write_text(
            "[bench]\n"
            "type = alias\n"
            f"remote = {storage.as_posix()}\n",
            encoding="utf-8",
        )
        storage_location = "bench:kasumi"
    environment_root = write_config(scenario, local, storage_location)
    environment = command_environment(
        environment_root, rclone_config, False, content_concurrency
    )
    environment["PATH"] = str(rclone.parent) + os.pathsep + environment["PATH"]
    sync(kasumi, local, environment, False)
    history_file = local / "history.bin"
    for generation in range(1, depth):
        history_file.write_bytes(generation.to_bytes(8, "little"))
        sync(kasumi, local, environment, False)

    traced_environment = command_environment(
        environment_root, rclone_config, True, content_concurrency
    )
    traced_environment["PATH"] = environment["PATH"]
    traced_environment["KASUMI_PERF_RC_DELAY_MS"] = str(latency_ms)

    elapsed, metrics, stdout, stderr = sync(
        kasumi, local, traced_environment, True
    )
    commit_get = metrics.get("rc/get_commit", {"calls": 0})["calls"]
    if commit_get != 0:
        raise RuntimeError(
            f"{scenario_name}/noop performed {commit_get} commit GETs"
        )
    return {
        "kasumi_executable": str(kasumi),
        "scenario": scenario_name,
        "benchmark": "real-remote" if remote else "structural-alias",
        "history_depth": depth,
        "elapsed_seconds": round(elapsed, 6),
        "artificial_latency_ms": latency_ms,
        "exit_code": 0,
        "stdout": stdout,
        "stderr": stderr,
        "operations_list": metrics.get(
            "rc/operations/list", {"calls": 0}
        )["calls"],
        "marker_get": metrics.get("rc/get_marker", {"calls": 0})["calls"],
        "commit_get": commit_get,
        "copyfile_download": metrics.get(
            "rclone copyfile download", {"calls": 0}
        )["calls"],
        "rc_requests": sum(
            value["calls"]
            for name, value in metrics.items()
            if name.startswith("rc/operations/") or name.startswith("rc/core/")
        ),
        "metrics": metrics,
    }


def run_content_scale(
    kasumi, rclone, root, content_count, latency_ms, remote, remote_config,
    content_concurrency
):
    scenario_name = f"content-scale-{content_count}"
    scenario = root / scenario_name
    local = scenario / "local"
    if remote:
        storage_location = f"{remote.rstrip('/')}/{scenario_name}"
        rclone_config = remote_config
    else:
        storage = scenario / "storage"
        storage.mkdir(parents=True)
        rclone_config = scenario / "rclone.conf"
        rclone_config.write_text(
            "[bench]\n"
            "type = alias\n"
            f"remote = {storage.as_posix()}\n",
            encoding="utf-8",
        )
        storage_location = "bench:kasumi"
    environment_root = write_config(scenario, local, storage_location)
    environment = command_environment(
        environment_root, rclone_config, False, content_concurrency
    )
    environment["PATH"] = str(rclone.parent) + os.pathsep + environment["PATH"]
    sync(kasumi, local, environment, False)
    create_distinct_payload(local, content_count)
    sync(kasumi, local, environment, False)

    traced_environment = command_environment(
        environment_root, rclone_config, True, content_concurrency
    )
    traced_environment["PATH"] = environment["PATH"]
    traced_environment["KASUMI_PERF_RC_DELAY_MS"] = str(latency_ms)

    def measure(change):
        elapsed, metrics, stdout, stderr = sync(
            kasumi, local, traced_environment, True
        )
        presence = metrics.get("rc/presence", {"calls": 0})["calls"]
        stat = metrics.get("rc/operations/stat", {"calls": 0})["calls"]
        scoped_list = metrics.get("rc/list_prefix", {"calls": 0})["calls"]
        marker_get = metrics.get("rc/get_marker", {"calls": 0})["calls"]
        commit_get = metrics.get("rc/get_commit", {"calls": 0})["calls"]
        uploads = metrics.get("rclone copyfile upload", {"calls": 0})["calls"]
        downloads = metrics.get("rclone copyfile download", {"calls": 0})["calls"]
        hashes = metrics.get("rc/operations/hashsumfile", {"calls": 0})["calls"]
        deletes = metrics.get("rc/operations/deletefile", {"calls": 0})["calls"]
        if presence or stat:
            raise RuntimeError(
                f"{scenario_name}/{change} performed content presence/stat"
            )
        if change == "noop" and commit_get != 0:
            raise RuntimeError(
                f"{scenario_name}/{change} performed {commit_get} commit GETs"
            )
        if change == "one-new-content" and (
            scoped_list != 2
            or marker_get != 1
            or commit_get != 0
            or uploads != 3
            or downloads != 1
            or hashes != 3
            or deletes != 1
        ):
            raise RuntimeError(
                f"{scenario_name}/{change} exceeded R9 endpoint budget"
            )
        return {
            "kasumi_executable": str(kasumi),
            "scenario": scenario_name,
            "change": change,
            "benchmark": "real-remote" if remote else "structural-alias",
            "existing_contents": content_count,
            "elapsed_seconds": round(elapsed, 6),
            "artificial_latency_ms": latency_ms,
            "exit_code": 0,
            "stdout": stdout,
            "stderr": stderr,
            "rc_requests": sum(
                value["calls"]
                for name, value in metrics.items()
                if name.startswith("rc/operations/")
                or name.startswith("rc/core/")
            ),
            "content_presence": presence,
            "operations_stat": stat,
            "full_list": metrics.get("rc/list", {"calls": 0})["calls"],
            "scoped_list": scoped_list,
            "marker_get": marker_get,
            "commit_get": commit_get,
            "copyfile_upload": uploads,
            "copyfile_download": downloads,
            "hashsumfile": hashes,
            "deletefile": deletes,
            "metrics": metrics,
        }

    results = [measure("noop")]
    if content_count == 1000:
        (local / "new.bin").write_bytes(b"new")
        results.append(measure("one-new-content"))
    return results


def persist_results(output, results):
    encoded = json.dumps(results, sort_keys=True)
    if output:
        output.parent.mkdir(parents=True, exist_ok=True)
        temporary = output.with_name(output.name + ".tmp")
        temporary.write_text(encoded, encoding="utf-8")
        os.replace(temporary, output)
    return encoded


def make_remote_client(scenario, name, remote, rclone, rclone_config,
                       content_concurrency):
    root = scenario / name
    local = root / "local"
    environment_root = write_config(root, local, remote)
    environment = command_environment(
        environment_root, rclone_config, True, content_concurrency
    )
    environment["PATH"] = str(rclone.parent) + os.pathsep + environment["PATH"]
    return local, environment


def capture_sync(kasumi, client):
    local, environment = client
    try:
        elapsed, metrics, stdout, stderr = sync(
            kasumi, local, environment, True
        )
        return {
            "success": True,
            "elapsed_seconds": round(elapsed, 6),
            "metrics": metrics,
            "stdout": stdout,
            "stderr": stderr,
        }
    except RuntimeError as error:
        return {"success": False, "error": str(error)}


def capture_gc(kasumi, client):
    local, environment = client
    started = time.perf_counter()
    result = subprocess.run(
        [str(kasumi), "gc", "perf"],
        cwd=local,
        env=environment,
        capture_output=True,
        text=True,
        timeout=600,
        check=False,
    )
    return {
        "success": result.returncode == 0,
        "elapsed_seconds": round(time.perf_counter() - started, 6),
        "exit_code": result.returncode,
        "stdout": result.stdout,
        "stderr": result.stderr,
    }


def run_parallel(*operations):
    ready = threading.Barrier(len(operations))

    def start(operation):
        ready.wait()
        return operation()

    with ThreadPoolExecutor(max_workers=len(operations)) as executor:
        futures = [executor.submit(start, operation) for operation in operations]
        return [future.result() for future in futures]


def local_snapshot(local):
    return {
        path.relative_to(local).as_posix(): path.read_bytes()
        for path in local.rglob("*")
        if path.is_file()
    }


def require_success(name, attempts):
    failures = [attempt for attempt in attempts if not attempt["success"]]
    if failures:
        raise RuntimeError(
            json.dumps({"scenario": name, "failures": failures}, indent=2)
        )


def converge_clients(kasumi, clients):
    for round_index in range(1, 4):
        for client in clients:
            require_success("convergence", [capture_sync(kasumi, client)])
        snapshots = [local_snapshot(client[0]) for client in clients]
        if all(snapshot == snapshots[0] for snapshot in snapshots[1:]):
            return snapshots[0], round_index
    raise RuntimeError("clients did not converge after three rounds")


def validate_concurrent_snapshot(name, snapshot):
    contents = set(snapshot.values())
    if name == "concurrent-disjoint-create":
        expected = {"left.bin": b"left", "right.bin": b"right"}
        valid = snapshot == expected
    elif name == "concurrent-same-file-edit":
        valid = {b"left-v2", b"right-v2"}.issubset(contents)
    elif name == "concurrent-rename-vs-edit":
        valid = {b"base-v1", b"edited-v2"}.issubset(contents)
    elif name == "concurrent-delete-vs-edit":
        valid = b"edited-v2" in contents
    elif name == "concurrent-gc-vs-sync":
        valid = snapshot == {
            "base.bin": b"base-v1",
            "during-gc.bin": b"during-gc",
        }
    else:
        raise RuntimeError(f"unknown concurrent scenario: {name}")
    if not valid:
        raise RuntimeError(
            f"{name} lost an expected version; paths={sorted(snapshot)}"
        )


def run_concurrent_sync_scenario(kasumi, rclone, root, name, remote,
                                 rclone_config, content_concurrency):
    scenario = root / name
    storage_location = f"{remote.rstrip('/')}/{name}"
    seed = make_remote_client(
        scenario, "seed", storage_location, rclone, rclone_config,
        content_concurrency
    )
    left = make_remote_client(
        scenario, "left", storage_location, rclone, rclone_config,
        content_concurrency
    )
    right = make_remote_client(
        scenario, "right", storage_location, rclone, rclone_config,
        content_concurrency
    )
    verifier = make_remote_client(
        scenario, "verifier", storage_location, rclone, rclone_config,
        content_concurrency
    )

    if name != "concurrent-disjoint-create":
        (seed[0] / "shared.bin").write_bytes(b"base-v1")
    require_success(name, [capture_sync(kasumi, seed)])
    materialization = run_parallel(
        lambda: capture_sync(kasumi, left),
        lambda: capture_sync(kasumi, right),
    )
    require_success(name, materialization)

    if name == "concurrent-disjoint-create":
        (left[0] / "left.bin").write_bytes(b"left")
        (right[0] / "right.bin").write_bytes(b"right")
    elif name == "concurrent-same-file-edit":
        (left[0] / "shared.bin").write_bytes(b"left-v2")
        (right[0] / "shared.bin").write_bytes(b"right-v2")
    elif name == "concurrent-rename-vs-edit":
        (left[0] / "shared.bin").rename(left[0] / "renamed.bin")
        (right[0] / "shared.bin").write_bytes(b"edited-v2")
    elif name == "concurrent-delete-vs-edit":
        (left[0] / "shared.bin").unlink()
        (right[0] / "shared.bin").write_bytes(b"edited-v2")

    concurrent = run_parallel(
        lambda: capture_sync(kasumi, left),
        lambda: capture_sync(kasumi, right),
    )
    require_success(name, concurrent)
    verifier_attempt = capture_sync(kasumi, verifier)
    require_success(name, [verifier_attempt])
    final, convergence_rounds = converge_clients(
        kasumi, (left, right, verifier)
    )
    validate_concurrent_snapshot(name, final)
    return {
        "scenario": name,
        "benchmark": "real-remote-concurrency",
        "content_concurrency_bound": content_concurrency,
        "concurrent_syncs": concurrent,
        "materializers": materialization,
        "verifier": verifier_attempt,
        "convergence_rounds": convergence_rounds,
        "final_paths": sorted(final),
        "publication_verified": True,
        "third_client_verified": True,
    }


def run_gc_sync_scenario(kasumi, rclone, root, remote, rclone_config,
                         content_concurrency):
    name = "concurrent-gc-vs-sync"
    scenario = root / name
    storage_location = f"{remote.rstrip('/')}/{name}"
    seed = make_remote_client(
        scenario, "seed", storage_location, rclone, rclone_config,
        content_concurrency
    )
    writer = make_remote_client(
        scenario, "writer", storage_location, rclone, rclone_config,
        content_concurrency
    )
    verifier = make_remote_client(
        scenario, "verifier", storage_location, rclone, rclone_config,
        content_concurrency
    )
    (seed[0] / "base.bin").write_bytes(b"base-v1")
    require_success(name, [capture_sync(kasumi, seed)])
    require_success(name, [capture_sync(kasumi, writer)])
    (writer[0] / "during-gc.bin").write_bytes(b"during-gc")

    concurrent = run_parallel(
        lambda: capture_sync(kasumi, writer),
        lambda: capture_gc(kasumi, seed),
    )
    require_success(name, [capture_sync(kasumi, writer)])
    completed_gc = capture_gc(kasumi, seed)
    require_success(name, [completed_gc])
    verifier_attempt = capture_sync(kasumi, verifier)
    require_success(name, [verifier_attempt])
    final, convergence_rounds = converge_clients(
        kasumi, (writer, verifier)
    )
    validate_concurrent_snapshot(name, final)
    return {
        "scenario": name,
        "benchmark": "real-remote-concurrency",
        "content_concurrency_bound": content_concurrency,
        "concurrent_sync": concurrent[0],
        "concurrent_gc": concurrent[1],
        "retry_gc": completed_gc,
        "verifier": verifier_attempt,
        "convergence_rounds": convergence_rounds,
        "final_paths": sorted(final),
        "publication_verified": True,
        "third_client_verified": True,
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--kasumi", required=True, type=Path)
    parser.add_argument("--rclone", required=True, type=Path)
    parser.add_argument("--scenario")
    parser.add_argument("--latency-ms", type=int, default=0)
    parser.add_argument("--remote")
    parser.add_argument("--rclone-config", type=Path)
    parser.add_argument("--content-concurrency", type=int, default=8)
    parser.add_argument("--skip-second-client", action="store_true")
    parser.add_argument("--repetitions", type=int, default=1)
    parser.add_argument("--output", type=Path)
    arguments = parser.parse_args()
    kasumi = arguments.kasumi.resolve()
    rclone = arguments.rclone.resolve()
    if arguments.remote and not arguments.rclone_config:
        parser.error("--remote requires --rclone-config")
    remote_config = (
        arguments.rclone_config.resolve() if arguments.rclone_config else None
    )
    base_scenarios = (
        ("noop", 0, 0),
        ("one-100k", 1, 100 * 1024),
        ("one-8m", 1, 8 * 1024 * 1024),
        ("eight-100k", 8, 100 * 1024),
        ("twenty-100k", 20, 100 * 1024),
        ("fifty-100k", 50, 100 * 1024),
    )
    r7_scenarios = (
        ("one-100k", 1, 100 * 1024),
        ("four-100k", 4, 100 * 1024),
        ("sixteen-100k", 16, 100 * 1024),
        ("sixty-four-100k", 64, 100 * 1024),
        ("one-hundred-ten-100k", 110, 100 * 1024),
    )
    large_scenario = ("one-hundred-ten-6m", 110, 6 * 1024 * 1024)
    r10a_scenarios = (
        (
            "r10a-heterogeneous-32m",
            130,
            tuple(size * 1024 for size in (64, 128, 256, 512, 320)),
        ),
        (
            "r10a-heterogeneous-241m",
            74,
            tuple(
                size * 1024 * 1024
                for size in (1, 2, 3, 4)
            ) + (13 * 1024 * 1024 // 2,),
        ),
        (
            "r10a-homogeneous-96m",
            16,
            6 * 1024 * 1024,
        ),
    )
    r10b_scenarios = (
        ("r10b-a-100x1m", 100, 1024 * 1024),
        ("r10b-b-100x256k", 100, 256 * 1024),
        ("r10b-c-50x2m", 50, 2 * 1024 * 1024),
        ("r10b-d-16x6m", 16, 6 * 1024 * 1024),
        ("r10b-e-4x25m", 4, 25 * 1024 * 1024),
        (
            "r10b-f-heterogeneous",
            64,
            tuple(size * 1024 for size in (64, 256, 1024, 2048, 6144)),
        ),
    )
    r11_state_scenarios = (
        ("r11-delete-1-10k", "delete", 1, 10 * 1024),
        ("r11-delete-10-10k", "delete", 10, 10 * 1024),
        ("r11-delete-100-10k", "delete", 100, 10 * 1024),
        ("r11-delete-1000-10k", "delete", 1000, 10 * 1024),
        ("r11-delete-100-1m", "delete", 100, 1024 * 1024),
        ("r11-noop-tiny", "noop", 1, 1024),
        ("r11-noop-100m", "noop", 1, 100 * 1024 * 1024),
        ("r11-noop-1g", "noop", 1, 1024 * 1024 * 1024),
        ("r11-noop-1000-small", "noop", 1000, 10 * 1024),
    )
    r11_upload_scenarios = (
        ("r11-upload-1x1m", 1, 1024 * 1024),
        ("r11-upload-100x1m", 100, 1024 * 1024),
        ("r11-upload-16x6m", 16, 6 * 1024 * 1024),
        ("r11-upload-1x1g", 1, 1024 * 1024 * 1024),
    )
    r21_mutation_scenarios = (
        ("r21-create-100", "create", 100, 1024),
        ("r21-delete-100", "delete", 100, 1024),
        ("r21-rename-100", "rename", 100, 1024),
        ("r23-duplicate-100", "duplicate", 100, 1024),
        ("r21-create-1000", "create", 1000, 1024),
        ("r21-delete-1000", "delete", 1000, 1024),
        ("r21-rename-1000", "rename", 1000, 1024),
        ("r23-duplicate-1000", "duplicate", 1000, 1024),
        ("r27-duplicate-4x6m", "duplicate", 4, 6 * 1024 * 1024),
        ("r27-duplicate-8x25m", "duplicate", 8, 25 * 1024 * 1024),
    )
    scenarios = base_scenarios
    history_depths = (1, 2, 3, 10, 50, 100)
    content_counts = ()
    state_scenarios = ()
    upload_scenarios = ()
    mutation_scenarios = ()
    concurrent_scenarios = ()
    if arguments.scenario == "r7":
        scenarios = r7_scenarios
        history_depths = ()
    elif arguments.scenario == "r10a":
        scenarios = r10a_scenarios
        history_depths = ()
    elif arguments.scenario == "r10b":
        scenarios = r10b_scenarios
        history_depths = ()
    elif arguments.scenario in ("r11", "r11-delete", "r11-noop"):
        scenarios = ()
        history_depths = ()
        state_scenarios = tuple(
            scenario for scenario in r11_state_scenarios
            if arguments.scenario == "r11"
            or scenario[1] == arguments.scenario.removeprefix("r11-")
        )
        if arguments.scenario == "r11":
            upload_scenarios = r11_upload_scenarios
    elif arguments.scenario == "r11-upload":
        scenarios = ()
        history_depths = ()
        upload_scenarios = r11_upload_scenarios
    elif arguments.scenario in ("r21", "r21-create", "r21-delete", "r21-rename"):
        scenarios = ()
        history_depths = ()
        mutation_scenarios = tuple(
            scenario for scenario in r21_mutation_scenarios
            if arguments.scenario == "r21"
            or scenario[1] == arguments.scenario.removeprefix("r21-")
        )
    elif arguments.scenario == large_scenario[0]:
        scenarios = (large_scenario,)
        history_depths = ()
    elif arguments.scenario == "r8":
        scenarios = ()
        history_depths = ()
        content_counts = (1, 10, 100, 1000)
    elif arguments.scenario == "concurrent":
        scenarios = ()
        history_depths = ()
        concurrent_scenarios = (
            "concurrent-disjoint-create",
            "concurrent-same-file-edit",
            "concurrent-rename-vs-edit",
            "concurrent-delete-vs-edit",
            "concurrent-gc-vs-sync",
        )
    elif arguments.scenario:
        scenarios = tuple(
            scenario
            for scenario in (
                *base_scenarios,
                *r7_scenarios,
                *r10a_scenarios,
                *r10b_scenarios,
            )
            if scenario[0] == arguments.scenario
        )[:1]
        history_depths = tuple(
            depth
            for depth in history_depths
            if f"history-{depth}" == arguments.scenario
        )
        state_scenarios = tuple(
            scenario for scenario in r11_state_scenarios
            if scenario[0] == arguments.scenario
        )
        upload_scenarios = tuple(
            scenario for scenario in r11_upload_scenarios
            if scenario[0] == arguments.scenario
        )
        mutation_scenarios = tuple(
            scenario for scenario in r21_mutation_scenarios
            if scenario[0] == arguments.scenario
        )
        concurrent_scenarios = tuple(
            scenario for scenario in (
                "concurrent-disjoint-create",
                "concurrent-same-file-edit",
                "concurrent-rename-vs-edit",
                "concurrent-delete-vs-edit",
                "concurrent-gc-vs-sync",
            )
            if scenario == arguments.scenario
        )
        if (not scenarios and not history_depths and not state_scenarios
                and not upload_scenarios and not mutation_scenarios
                and not concurrent_scenarios):
            parser.error(f"unknown scenario: {arguments.scenario}")
    if concurrent_scenarios and not arguments.remote:
        parser.error("concurrent scenarios require --remote")
    with tempfile.TemporaryDirectory(prefix="kasumi-perf-") as temporary:
        root = Path(temporary)
        results = []

        def record(name, operation):
            try:
                value = operation()
            except Exception as error:
                results.append({
                    "scenario": name,
                    "benchmark": "failed",
                    "exit_code": 1,
                    "error": str(error),
                })
                persist_results(arguments.output, results)
                raise
            if isinstance(value, list):
                results.extend(value)
            else:
                results.append(value)
            persist_results(arguments.output, results)

        for scenario in scenarios:
            record(
                scenario[0],
                lambda scenario=scenario: run_scenario(
                    kasumi,
                    rclone,
                    root,
                    *scenario,
                    arguments.latency_ms,
                    arguments.remote,
                    remote_config,
                    arguments.content_concurrency,
                    arguments.skip_second_client,
                ),
            )
        for depth in history_depths:
            record(
                f"history-{depth}",
                lambda depth=depth: run_history_depth(
                    kasumi,
                    rclone,
                    root,
                    depth,
                    arguments.latency_ms,
                    arguments.remote,
                    remote_config,
                    arguments.content_concurrency,
                ),
            )
        for content_count in content_counts:
            record(
                f"content-scale-{content_count}",
                lambda content_count=content_count: run_content_scale(
                    kasumi,
                    rclone,
                    root,
                    content_count,
                    arguments.latency_ms,
                    arguments.remote,
                    remote_config,
                    arguments.content_concurrency,
                ),
            )
        for repetition in range(1, arguments.repetitions + 1):
            for scenario in state_scenarios:
                record(
                    f"{scenario[0]}-rep{repetition}",
                    lambda scenario=scenario, repetition=repetition:
                    run_r11_state_scenario(
                        kasumi,
                        rclone,
                        root,
                        *scenario,
                        repetition,
                        arguments.remote,
                        remote_config,
                        arguments.content_concurrency,
                    ),
                )
            for scenario in upload_scenarios:
                record(
                    f"{scenario[0]}-rep{repetition}",
                    lambda scenario=scenario, repetition=repetition: run_scenario(
                        kasumi,
                        rclone,
                        root,
                        f"{scenario[0]}-rep{repetition}",
                        scenario[1],
                        scenario[2],
                        arguments.latency_ms,
                        arguments.remote,
                        remote_config,
                        arguments.content_concurrency,
                        arguments.skip_second_client,
                    ),
                )
            for scenario in mutation_scenarios:
                record(
                    f"{scenario[0]}-rep{repetition}",
                    lambda scenario=scenario, repetition=repetition:
                    run_r21_mutation_scenario(
                        kasumi,
                        rclone,
                        root,
                        *scenario,
                        repetition,
                        arguments.remote,
                        remote_config,
                        arguments.content_concurrency,
                    ),
                )
        for scenario in concurrent_scenarios:
            if scenario == "concurrent-gc-vs-sync":
                operation = lambda: run_gc_sync_scenario(
                    kasumi,
                    rclone,
                    root,
                    arguments.remote,
                    remote_config,
                    arguments.content_concurrency,
                )
            else:
                operation = lambda scenario=scenario: run_concurrent_sync_scenario(
                    kasumi,
                    rclone,
                    root,
                    scenario,
                    arguments.remote,
                    remote_config,
                    arguments.content_concurrency,
                )
            record(scenario, operation)
    encoded = persist_results(arguments.output, results)
    print(encoded)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
