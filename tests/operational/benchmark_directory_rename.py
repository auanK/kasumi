#!/usr/bin/env python3
"""Opt-in, real-Rclone-remote directory-rename characterization and RED test.

This script never deletes remote data. Each invocation creates a new UUID
namespace under kasumi:tests/bench/v0.9.2-directory-rename/ and leaves it in
place for inspection. It is intentionally not registered with ordinary CI.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import subprocess
import sys
import time
import uuid

from benchmark_rclone import (
    TRACE,
    command_environment,
    read_local_state,
    write_config,
)


REMOTE_ROOT = "kasumi:tests/bench"
RUN_PARENT = f"{REMOTE_ROOT}/v0.9.2-directory-rename"
SCENARIOS = (
    "pure-rename",
    "nested-rename",
    "rename-with-edit",
    "rename-with-additions",
    "duplicate-content",
    "receiver-edit",
    "changed-source",
)
CHUNK_SIZE = 4 * 1024 * 1024
CONTENT_CONCURRENCY = 4
TIMEOUT_SECONDS = 600
TEXT_FIXTURES = {
    "src/main.cpp": b"int main() { return 0; }\n",
    "src/engine.cpp": b"namespace engine { int run() { return 7; } }\n",
    "src/core/parser.cpp": b"namespace parser { bool parse() { return true; } }\n",
    "src/core/state.cpp": b"namespace state { int current = 3; }\n",
    "src/core/scheduler.cpp": b"namespace scheduler { void tick() {} }\n",
    "include/engine.hpp": b"#pragma once\nint run_engine();\n",
    "include/core/parser.hpp": b"#pragma once\nbool parse_input();\n",
    "include/core/state.hpp": b"#pragma once\nint current_state();\n",
    "tests/test_parser.cpp": b"void test_parser() {}\n",
    "tests/test_state.cpp": b"void test_state() {}\n",
    "README.md": b"# Kasumi rename fixture\nDeterministic remote regression data.\n",
}
BINARY_FIXTURES = {
    "assets/data.bin": 64 * 1024,
    "assets/nested/payload.bin": CHUNK_SIZE + 4097,
}
DUPLICATE_SIZE = 96 * 1024


class InfrastructureFailure(RuntimeError):
    pass


def save_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(value, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def run_rclone(rclone, config, *args, timeout=TIMEOUT_SECONDS):
    environment = os.environ.copy()
    environment["RCLONE_CONFIG"] = str(config)
    result = subprocess.run(
        [str(rclone), *map(str, args)],
        env=environment,
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )
    if result.returncode != 0:
        raise InfrastructureFailure(
            f"rclone {' '.join(map(str, args[:2]))} failed "
            f"(exit {result.returncode}): {result.stderr.strip()}"
        )
    return result


def resolve_rclone_config(rclone, requested):
    if requested:
        path = Path(requested).expanduser().resolve()
        if not path.is_file():
            raise InfrastructureFailure("the selected Rclone config is missing")
        return path
    result = subprocess.run(
        [str(rclone), "config", "file"],
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    if result.returncode != 0:
        raise InfrastructureFailure("could not resolve the active Rclone config")
    candidates = [line.strip() for line in result.stdout.splitlines() if line.strip()]
    if not candidates:
        raise InfrastructureFailure("Rclone did not report its config location")
    path = Path(candidates[-1]).expanduser().resolve()
    if not path.is_file():
        raise InfrastructureFailure("the active Rclone config file is missing")
    return path


def prepare_remote(rclone, config):
    remotes = run_rclone(rclone, config, "listremotes").stdout.splitlines()
    if "kasumi:" not in remotes:
        raise InfrastructureFailure("the required Rclone remote kasumi: is absent")
    # mkdir is idempotent and establishes the required parent if it is absent.
    run_rclone(rclone, config, "mkdir", f"{REMOTE_ROOT}/")
    run_rclone(
        rclone, config, "lsf", f"{REMOTE_ROOT}/", "--max-depth", "1"
    )
    run_rclone(rclone, config, "mkdir", f"{RUN_PARENT}/")
    return run_rclone(
        rclone, config, "lsf", f"{RUN_PARENT}/", "--dirs-only"
    ).stdout.splitlines()


def list_vault_objects(rclone, remote, config):
    return set(
        run_rclone(
            rclone, config, "lsf", remote, "--recursive", "--files-only"
        ).stdout.splitlines()
    )


def verify_remote_publication(rclone, remote, config, state, previous_state=None):
    if previous_state is not None and state[1] == previous_state[1]:
        raise InfrastructureFailure("the local accepted Commit ID did not advance")
    objects = list_vault_objects(rclone, remote, config)
    references = [path for path in objects if state[1] in path]
    if len(references) < 2:
        raise InfrastructureFailure(
            "the accepted Commit ID was not found in both remote commit and head objects"
        )
    return objects


def choose_run_id(existing):
    known = {entry.rstrip("/").casefold() for entry in existing}
    for _ in range(8):
        run_id = str(uuid.uuid4())
        if run_id.casefold() not in known:
            return run_id
    raise InfrastructureFailure("could not allocate a collision-free run UUID")


def metric_calls(run, name):
    entry = run["metrics"].get(name)
    return None if entry is None else entry["calls"]


def metric_seconds(run, name):
    entry = run["metrics"].get(name)
    return None if entry is None else entry["total_us"] / 1_000_000


def parse_metrics(stderr):
    result = {}
    for line in stderr.splitlines():
        match = TRACE.match(line)
        if match:
            result[match.group(1)] = {
                "calls": int(match.group(2)),
                "total_us": int(match.group(3)),
            }
    return result


def run_sync(kasumi, local, environment, trace_dir, label, initial=False):
    args = [str(kasumi), "sync", "perf"]
    if initial:
        args.append("--initial")
    started = time.perf_counter()
    result = subprocess.run(
        args,
        cwd=local,
        env=environment,
        capture_output=True,
        text=True,
        timeout=TIMEOUT_SECONDS,
        check=False,
    )
    elapsed = time.perf_counter() - started
    trace_dir.mkdir(parents=True, exist_ok=True)
    (trace_dir / f"{label}.stdout.log").write_text(
        result.stdout, encoding="utf-8"
    )
    (trace_dir / f"{label}.stderr.log").write_text(
        result.stderr, encoding="utf-8"
    )
    captured = {
        "success": result.returncode == 0,
        "exit_code": result.returncode,
        "elapsed_seconds": elapsed,
        "stdout": result.stdout,
        "stderr": result.stderr,
        "metrics": parse_metrics(result.stderr),
    }
    save_json(trace_dir / f"{label}.json", captured)
    if result.returncode != 0:
        raise InfrastructureFailure(
            f"{label} Sync failed with exit {result.returncode}; "
            f"see {trace_dir / f'{label}.stderr.log'}"
        )
    if "rc/get_content" not in captured["metrics"]:
        raise InfrastructureFailure(
            f"{label} lacks the explicitly seeded rc/get_content metric"
        )
    if "rc/put_content" not in captured["metrics"]:
        raise InfrastructureFailure(
            f"{label} lacks the explicitly seeded rc/put_content metric"
        )
    if "content batch PUT objects completed" not in captured["metrics"]:
        raise InfrastructureFailure(
            f"{label} lacks the explicitly seeded content batch PUT metric"
        )
    return captured


def file_manifest(root):
    if not root.is_dir():
        raise InfrastructureFailure(f"expected directory is missing: {root}")
    result = {}
    for path in sorted(root.rglob("*")):
        if path.is_symlink():
            raise InfrastructureFailure(f"unexpected symlink in fixture: {path}")
        if not path.is_file():
            continue
        digest = hashlib.sha256()
        size = 0
        with path.open("rb") as source:
            while True:
                block = source.read(1024 * 1024)
                if not block:
                    break
                size += len(block)
                digest.update(block)
        result[path.relative_to(root).as_posix()] = {
            "size": size,
            "sha256": digest.hexdigest(),
        }
    return result


def write_manifest(reports, name, manifest):
    save_json(reports / "manifests" / f"{name}.json", manifest)


def deterministic_bytes(label, size):
    return hashlib.shake_256(
        f"Kasumi v0.9.2 rename fixture:{label}".encode("utf-8")
    ).digest(size)


def create_fixture(project, duplicate_content=False):
    for relative, content in TEXT_FIXTURES.items():
        path = project / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)
    for relative, size in BINARY_FIXTURES.items():
        path = project / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(deterministic_bytes(relative, size))
    if duplicate_content:
        shared = deterministic_bytes("same duplicate object", DUPLICATE_SIZE)
        for relative in (
            "assets/duplicate-a.bin",
            "assets/nested/duplicate-b.bin",
        ):
            path = project / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(shared)


def make_client(root, local, remote, rclone, config):
    app_root = write_config(root, local, remote)
    environment = command_environment(
        app_root, config, True, CONTENT_CONCURRENCY
    )
    environment["PATH"] = str(rclone.parent) + os.pathsep + environment["PATH"]
    environment["KASUMI_LANG"] = "en"
    return app_root, (local, environment)


def project_tree(local, name):
    return local / name


def assert_tree_at(local, name, expected, reports, label):
    actual = file_manifest(project_tree(local, name))
    write_manifest(reports, label, actual)
    if actual != expected:
        missing = sorted(set(expected) - set(actual))
        extra = sorted(set(actual) - set(expected))
        changed = sorted(
            path for path in set(actual) & set(expected)
            if actual[path] != expected[path]
        )
        raise InfrastructureFailure(
            f"{label} content manifest mismatch: "
            f"missing={missing[:5]}, extra={extra[:5]}, changed={changed[:5]}"
        )
    return actual


def validate_direct_download_metric(run, label):
    content_gets = metric_calls(run, "rc/get_content")
    direct_copy = metric_calls(run, "rclone copyfile download")
    if direct_copy is None and content_gets:
        raise InfrastructureFailure(
            f"{label} has rc/get_content calls but no direct Rclone download metric"
        )
    if direct_copy is not None and content_gets and direct_copy < content_gets:
        raise InfrastructureFailure(
            f"{label} direct Rclone download count is below its Content GET count: "
            f"rc/get_content={content_gets}, "
            f"rclone copyfile download={direct_copy}"
        )
    return direct_copy


def summarize_sync(run):
    individual_puts = metric_calls(run, "rc/put_content")
    batch_puts = metric_calls(run, "content batch PUT objects completed")
    physical_puts = (
        individual_puts + batch_puts
        if individual_puts is not None and batch_puts is not None
        else None
    )
    content_gets = metric_calls(run, "rc/get_content")
    direct_downloads = metric_calls(run, "rclone copyfile download")
    control_get_metrics = {
        name: value["calls"]
        for name, value in run["metrics"].items()
        if name.startswith("rc/get_") and name != "rc/get_content"
    }
    return {
        "elapsed_seconds": round(run["elapsed_seconds"], 6),
        "logical_uploads": metric_calls(run, "action/Upload"),
        "logical_downloads": metric_calls(run, "action/Download"),
        "physical_content_puts": physical_puts,
        "individual_content_puts": individual_puts,
        "batch_content_puts": batch_puts,
        "physical_content_gets": content_gets,
        "rclone_copyfile_downloads": direct_downloads,
        "non_content_copyfile_downloads": (
            direct_downloads - content_gets
            if direct_downloads is not None and content_gets is not None
            else None
        ),
        "remote_history_commit_gets": metric_calls(
            run, "commit.get_batch_objects"
        ),
        "remote_history_batch_calls": metric_calls(
            run, "commit.get_batch_calls"
        ),
        "remote_control_get_metrics": control_get_metrics,
        "rclone_history_batch_downloads": metric_calls(
            run, "rclone batch download"
        ),
        "local_hash_cache_misses": metric_calls(
            run, "local hash cache misses"
        ),
        "local_hash_bytes": metric_calls(run, "local hash bytes"),
        "content_uploads_elided": metric_calls(run, "content uploads elided"),
        "content_transfer_wall_seconds": metric_seconds(
            run, "content transfer wall"
        ),
        "transaction_execution_seconds": metric_seconds(
            run, "transaction execution"
        ),
        "download_decryption_seconds": metric_seconds(
            run, "download decryption"
        ),
        "download_plaintext_copy_seconds": metric_seconds(
            run, "download plaintext copy"
        ),
        "final_local_validation_seconds": metric_seconds(
            run, "final local validation"
        ),
        "journal_durable_saves": metric_calls(run, "journal durable saves"),
        "journal_written_bytes": metric_calls(
            run, "journal written bytes total"
        ),
        "local_reuse_candidates_matched": metric_calls(
            run, "local reuse candidates matched"
        ),
        "local_reuse_moves_completed": metric_calls(
            run, "local reuse moves completed"
        ),
        "local_reuse_bytes_moved": metric_calls(
            run, "local reuse bytes moved"
        ),
        "physical_content_bytes": None,
    }


def action_calls(run):
    return {
        name: value["calls"]
        for name, value in run["metrics"].items()
        if name.startswith("action/") and value["calls"] > 0
    }


def check_noop(run, label):
    if metric_calls(run, "rc/get_content") != 0:
        raise InfrastructureFailure(f"{label} no-op performed Content GETs")
    if metric_calls(run, "rc/put_content") != 0:
        raise InfrastructureFailure(f"{label} no-op performed Content PUTs")
    if action_calls(run):
        raise InfrastructureFailure(
            f"{label} no-op planned logical mutations: {action_calls(run)}"
        )
    if not (
        "Everything in sync." in run["stdout"]
        or "Nothing to do" in run["stdout"]
    ):
        raise InfrastructureFailure(f"{label} Sync did not report a stable no-op")


def find_hash_anywhere(local, expected_hash):
    for directory in sorted(path for path in local.iterdir() if path.is_dir()):
        for path in directory.rglob("*"):
            if path.is_symlink() or not path.is_file():
                continue
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
            if digest == expected_hash:
                return path.relative_to(local).as_posix()
    return None


def run_scenario(kasumi, rclone, config, run_root, run_id, scenario_name):
    scenario_remote = f"{RUN_PARENT}/{run_id}/{scenario_name}"
    scenario_root = run_root / scenario_name
    reports = scenario_root / "reports"
    traces = reports / "traces"
    project_name = "ProjectOriginal"
    renamed_name = "ProjectRenamed"
    nested_rename = scenario_name == "nested-rename"
    rename_from = f"{project_name}/src" if nested_rename else project_name
    rename_to = (
        f"{project_name}/source-renamed" if nested_rename else renamed_name
    )
    result_root_name = project_name if nested_rename else renamed_name
    project_a = scenario_root / "client-a" / "local" / project_name
    a_root, client_a = make_client(
        scenario_root / "client-a",
        project_a.parent,
        scenario_remote,
        rclone,
        config,
    )
    create_fixture(project_a, duplicate_content=scenario_name == "duplicate-content")
    initial_manifest = file_manifest(project_a)
    write_manifest(reports, "a-before-sync", initial_manifest)
    expected_renamed = dict(initial_manifest)
    if nested_rename:
        expected_renamed = {
            ("source-renamed/" + path[len("src/"):] if path.startswith("src/") else path): item
            for path, item in initial_manifest.items()
        }
    project_b_local = scenario_root / "client-b" / "local"
    b_root, client_b = make_client(
        scenario_root / "client-b",
        project_b_local,
        scenario_remote,
        rclone,
        config,
    )

    run_rclone(rclone, config, "mkdir", f"{scenario_remote}/")
    a_initial = run_sync(
        kasumi, client_a[0], client_a[1], traces, "a-initial", initial=True
    )
    a_state = read_local_state(a_root)
    a_objects = verify_remote_publication(
        rclone, scenario_remote, config, a_state
    )
    if summarize_sync(a_initial)["physical_content_puts"] < 1:
        raise InfrastructureFailure(
            "A's initial Sync completed without a measured Content PUT"
        )
    assert_tree_at(
        client_a[0], project_name, initial_manifest, reports, "a-after-initial"
    )

    if any(project_b_local.iterdir()):
        raise InfrastructureFailure("client B did not start with an empty local tree")
    b_initial = run_sync(
        kasumi, client_b[0], client_b[1], traces, "b-initial", initial=True
    )
    b_initial_gets = metric_calls(b_initial, "rc/get_content")
    validate_direct_download_metric(b_initial, "B initial")
    if not b_initial_gets:
        raise InfrastructureFailure("B initial enrollment made no Content GETs")
    assert_tree_at(
        client_b[0], project_name, initial_manifest, reports, "b-after-initial"
    )
    before_rename_state = read_local_state(a_root)
    before_rename_objects = list_vault_objects(rclone, scenario_remote, config)

    edit_content = None
    if scenario_name == "receiver-edit":
        edit_content = deterministic_bytes("receiver independent edit", 233)
        edited_path = project_tree(client_b[0], project_name) / "README.md"
        edited_path.write_bytes(edit_content)
    elif scenario_name == "changed-source":
        edit_content = deterministic_bytes("receiver changed old source", 257)
        edited_path = project_tree(client_b[0], project_name) / "src" / "engine.cpp"
        edited_path.write_bytes(edit_content)

    old_a = project_tree(client_a[0], project_name)
    new_a = project_tree(client_a[0], renamed_name)
    if nested_rename:
        old_a = old_a / "src"
        new_a = project_tree(client_a[0], project_name) / "source-renamed"
    old_a.rename(new_a)
    if old_a.exists() or not new_a.is_dir():
        raise InfrastructureFailure("filesystem rename did not complete exactly")

    if scenario_name == "rename-with-edit":
        edited_path = new_a / "README.md"
        edited_path.write_bytes(
            deterministic_bytes("one publisher-side modified file", 311)
        )
        expected_renamed["README.md"] = {
            "size": 311,
            "sha256": hashlib.sha256(edited_path.read_bytes()).hexdigest(),
        }
    elif scenario_name == "rename-with-additions":
        for idx, rel in enumerate(
            ("added/alpha.txt", "added/beta.txt", "added/gamma.txt"), start=1
        ):
            added_path = new_a / rel
            added_path.parent.mkdir(parents=True, exist_ok=True)
            payload = deterministic_bytes(f"added-file-{idx}", 512 + idx * 37)
            added_path.write_bytes(payload)
            expected_renamed[rel] = {
                "size": len(payload),
                "sha256": hashlib.sha256(payload).hexdigest(),
            }
    renamed_a_root = project_tree(client_a[0], result_root_name)
    renamed_a_manifest = file_manifest(renamed_a_root)
    write_manifest(reports, "a-before-rename-sync", renamed_a_manifest)
    if renamed_a_manifest != expected_renamed:
        raise InfrastructureFailure("the A rename changed fixture bytes unexpectedly")

    b_old_path = project_tree(client_b[0], project_name)
    b_rename_source = b_old_path / "src" if nested_rename else b_old_path
    b_rename_destination = (
        b_old_path / "source-renamed"
        if nested_rename
        else project_tree(client_b[0], renamed_name)
    )
    if not b_old_path.is_dir():
        raise InfrastructureFailure("B lost its original tree before receiving")
    if b_rename_destination.exists():
        raise InfrastructureFailure("B already has the renamed directory")

    a_rename = run_sync(
        kasumi, client_a[0], client_a[1], traces, "a-rename"
    )
    a_after_state = read_local_state(a_root)
    a_after_objects = verify_remote_publication(
        rclone,
        scenario_remote,
        config,
        a_after_state,
        previous_state=before_rename_state,
    )
    actual_a_manifest = assert_tree_at(
        client_a[0], result_root_name, renamed_a_manifest, reports, "a-after-rename"
    )
    if actual_a_manifest != renamed_a_manifest:
        raise InfrastructureFailure("A's renamed content changed unexpectedly")

    b_rename = run_sync(
        kasumi, client_b[0], client_b[1], traces, "b-rename"
    )
    b_direct_gets = validate_direct_download_metric(b_rename, "B after rename")
    b_after_manifest = assert_tree_at(
        client_b[0], result_root_name, renamed_a_manifest, reports, "b-after-rename"
    )
    if b_after_manifest != actual_a_manifest:
        raise InfrastructureFailure("A and B renamed-tree manifests diverged")

    preserved_edit = None
    if edit_content is not None:
        preserved_edit = find_hash_anywhere(
            client_b[0], hashlib.sha256(edit_content).hexdigest()
        )
        if not preserved_edit:
            raise InfrastructureFailure(
                f"B's independent content was lost during reconciliation: {scenario_name}"
            )
    elif b_rename_source.exists():
        raise InfrastructureFailure("B retained the old directory after rename")
    if not b_rename_destination.is_dir():
        raise InfrastructureFailure("B is missing the renamed directory")

    result = {
        "scenario": scenario_name,
        "rename_from": rename_from,
        "rename_to": rename_to,
        "remote_vault": scenario_remote,
        "fixture_files": len(initial_manifest),
        "fixture_bytes": sum(item["size"] for item in initial_manifest.values()),
        "fixture_largest_file_bytes": max(
            item["size"] for item in initial_manifest.values()
        ),
        "remote_objects_after_initial": len(a_objects),
        "remote_objects_after_rename": len(a_after_objects),
        "remote_object_paths_added_after_rename": len(
            a_after_objects - before_rename_objects
        ),
        "client_a_initial": summarize_sync(a_initial),
        "client_b_initial": summarize_sync(b_initial),
        "client_a_after_rename": summarize_sync(a_rename),
        "client_b_after_rename": summarize_sync(b_rename),
        "client_b_post_rename_direct_rclone_gets": b_direct_gets,
        "content_correctness_passed": True,
        "client_a_manifest_equals_expected": actual_a_manifest
        == expected_renamed,
        "client_b_renamed_tree_equals_expected": b_after_manifest
        == expected_renamed,
        "old_directory_absent_on_b": not b_rename_source.exists(),
        "new_directory_present_on_b": b_rename_destination.is_dir(),
        "receiver_edit_preserved_path": preserved_edit,
        "metrics": {
            "a_initial": a_initial["metrics"],
            "b_initial": b_initial["metrics"],
            "a_after_rename": a_rename["metrics"],
            "b_after_rename": b_rename["metrics"],
        },
    }

    if scenario_name in (
        "pure-rename",
        "nested-rename",
        "rename-with-edit",
        "rename-with-additions",
        "duplicate-content",
    ):
        a_noop = run_sync(
            kasumi, client_a[0], client_a[1], traces, "a-noop"
        )
        check_noop(a_noop, "A")
        b_noop = run_sync(
            kasumi, client_b[0], client_b[1], traces, "b-noop"
        )
        check_noop(b_noop, "B")
        assert_tree_at(
            client_a[0], result_root_name, expected_renamed, reports, "a-after-noop"
        )
        assert_tree_at(
            client_b[0], result_root_name, expected_renamed, reports, "b-after-noop"
        )
        result["client_a_stable_noop"] = summarize_sync(a_noop)
        result["client_b_stable_noop"] = summarize_sync(b_noop)

    save_json(reports / "scenario.json", result)
    return result


def render_report(metadata, scenarios, errors):
    rows = []
    for scenario in scenarios:
        for key, label in (
            ("client_a_initial", "A initial"),
            ("client_b_initial", "B initial"),
            ("client_a_after_rename", "A after rename"),
            ("client_b_after_rename", "B after rename"),
        ):
            row = scenario[key]
            values = [
                scenario["scenario"],
                label,
                row["elapsed_seconds"],
                row["logical_uploads"],
                row["logical_downloads"],
                row["physical_content_puts"],
                row["physical_content_gets"],
                row["non_content_copyfile_downloads"],
                row["remote_history_commit_gets"],
                row["local_hash_cache_misses"],
                row["local_hash_bytes"],
                row["content_transfer_wall_seconds"],
                row["transaction_execution_seconds"],
            ]
            rows.append("| " + " | ".join(
                "N/A" if value is None else str(value) for value in values
            ) + " |")
    result = [
        "# Kasumi v0.9.2 directory rename Phase 1",
        "",
        "All remote data created by this run is preserved.",
        "",
        "## Environment",
        "",
        f"- Run UUID: {metadata['run_id']}",
        f"- Git SHA: {metadata['git_sha']}",
        f"- OS: {metadata['os']}",
        f"- Compiler/build: {metadata['compiler_build']}",
        f"- Kasumi executable: {metadata['kasumi']}",
        f"- Rclone: {metadata['rclone_version']}",
        f"- Remote provider: {metadata['provider']}",
        f"- Rclone config path: {metadata['rclone_config_path']} (contents withheld)",
        "",
        "## Reproduction",
        "",
        "Run python tests/operational/benchmark_directory_rename.py --kasumi <path> --rclone <path>.",
        "The script creates a fresh isolated vault per scenario and never deletes remote objects.",
        "Each client has a separate local tree, application-data root, SQLite state, lock, and transaction journal.",
        "",
        "## Measurements",
        "",
        "| Scenario | Sync | Elapsed seconds | Logical uploads | Logical downloads | Physical Content PUTs | Physical Content GETs | Other copyfile downloads | Commit batch objects | Hash misses | Bytes hashed | Content transfer wall seconds | Transaction execution seconds |",
        "|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|",
        *rows,
        "",
        "Physical byte counts are N/A; current Kasumi traces count Content transport calls, not payload bytes.",
        "Missing metrics remain N/A. total_us stages can overlap and are not additive wall time.",
        "",
        "## RED evidence",
        "",
    ]
    pure = next(
        (item for item in scenarios if item["scenario"] == "pure-rename"), None
    )
    if pure:
        gets = pure["client_b_after_rename"]["physical_content_gets"]
        direct_gets = pure["client_b_post_rename_direct_rclone_gets"]
        result.extend(
            [
                "Test: pure-rename / post_rename_B_physical_content_GETs == 0",
                "Expected: zero Content GETs after both clients already hold the same bytes.",
                f"Observed: {gets} Content GET calls; direct Rclone copyfile "
                f"download counter: {direct_gets if direct_gets is not None else 'N/A'}.",
                f"Filesystem correctness: {pure['content_correctness_passed']}; "
                "the renamed tree and contents matched on A and B.",
                (
                    "Assertion output: RED ASSERTION FAILURE: pure-rename "
                    "post_rename_B_physical_content_GETs expected 0, observed "
                    f"{gets}; all filesystem correctness assertions passed."
                    if gets > 0
                    else "The zero-GET assertion passed; the suspected behavior was not reproduced."
                ),
            ]
        )
    else:
        result.append("Pure-rename scenario was not selected in this run.")
    result.extend(["", "## Scenario details", ""])
    for item in scenarios:
        result.append(
            f"- {item['scenario']}: {item['fixture_files']} files, "
            f"{item['fixture_bytes']} bytes, largest file "
            f"{item['fixture_largest_file_bytes']} bytes; "
            f"vault {item['remote_vault']}."
        )
    result.extend(["", "## Infrastructure errors", ""])
    result.extend([f"- {error}" for error in errors] or ["- None"])
    result.extend(
        [
            "",
            "## Remote artifacts",
            "",
            f"Preserved namespace root: {RUN_PARENT}/{metadata['run_id']}/.",
            "No Rclone delete or purge command is used.",
            "",
        ]
    )
    return "\n".join(result)


def parse_args():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--kasumi", required=True, type=Path)
    parser.add_argument("--rclone", required=True, type=Path)
    parser.add_argument("--rclone-config", type=Path)
    parser.add_argument("--output-root", type=Path)
    parser.add_argument(
        "--scenario",
        action="append",
        choices=SCENARIOS,
        help="repeat to choose scenarios; default runs the required pure-rename case",
    )
    parser.add_argument("--git-sha", default="unknown")
    parser.add_argument("--compiler-build", default="unknown")
    parser.add_argument(
        "--provider", default="Google Drive (Rclone type drive)"
    )
    return parser.parse_args()


def main():
    args = parse_args()
    selected = args.scenario or ("pure-rename",)
    if len(selected) != len(set(selected)):
        raise InfrastructureFailure("scenario names must be unique in one run")
    kasumi = args.kasumi.expanduser().resolve()
    rclone = args.rclone.expanduser().resolve()
    if not kasumi.is_file() or not rclone.is_file():
        raise InfrastructureFailure("Kasumi or Rclone executable was not found")
    config = resolve_rclone_config(rclone, args.rclone_config)
    existing_runs = prepare_remote(rclone, config)
    run_id = choose_run_id(existing_runs)
    run_root = (
        args.output_root.expanduser().resolve()
        if args.output_root
        else Path(os.environ.get("TEMP", ".")) / f"kasumi-v092-rename-{run_id}"
    )
    if run_root.exists():
        raise InfrastructureFailure(f"local output root already exists: {run_root}")
    run_root.mkdir(parents=True)
    reports = run_root / "reports"
    reports.mkdir()
    metadata = {
        "run_id": run_id,
        "git_sha": args.git_sha,
        "os": platform.platform(),
        "python": sys.version.split()[0],
        "compiler_build": args.compiler_build,
        "kasumi": str(kasumi),
        "rclone": str(rclone),
        "rclone_version": run_rclone(rclone, config, "version").stdout.splitlines()[0],
        "rclone_config_path": str(config),
        "provider": args.provider,
        "remote_root": f"{RUN_PARENT}/{run_id}",
        "remote_artifacts_preserved": True,
        "physical_content_bytes": None,
    }
    save_json(reports / "metadata.json", metadata)
    scenarios = []
    errors = []
    for scenario_name in selected:
        try:
            outcome = run_scenario(
                kasumi, rclone, config, run_root, run_id, scenario_name
            )
            scenarios.append(outcome)
            save_json(reports / "measurements.json", scenarios)
            print(
                f"{scenario_name}: correctness passed; B post-rename GETs="
                f"{outcome['client_b_after_rename']['physical_content_gets']}",
                flush=True,
            )
        except Exception as error:
            message = f"{scenario_name}: {type(error).__name__}: {error}"
            errors.append(message)
            save_json(reports / "infrastructure-errors.json", errors)
            break

    (reports / "summary.md").write_text(
        render_report(metadata, scenarios, errors), encoding="utf-8"
    )
    print(f"Run UUID: {run_id}")
    print(f"Remote namespace: {RUN_PARENT}/{run_id}/")
    print(f"Evidence: {reports}")
    pure = next(
        (item for item in scenarios if item["scenario"] == "pure-rename"), None
    )
    if errors:
        print("INFRASTRUCTURE FAILURE: " + errors[0], file=sys.stderr)
        return 2
    if pure is None:
        print("Characterization scenario completed; pure-rename RED was not selected.")
        return 0
    get_count = pure["client_b_after_rename"]["physical_content_gets"]
    direct_count = pure["client_b_post_rename_direct_rclone_gets"]
    if direct_count is not None and get_count > direct_count:
        print(
            f"INFRASTRUCTURE FAILURE: Content GET count exceeds all direct "
            f"Rclone copyfile downloads ({get_count} vs {direct_count})",
            file=sys.stderr,
        )
        return 2
    if get_count > 0:
        print(
            "RED ASSERTION FAILURE: pure-rename post_rename_B_physical_content_GETs "
            f"expected 0, observed {get_count}; all filesystem correctness "
            "assertions passed.",
            file=sys.stderr,
        )
        return 1
    print("Zero-GET assertion passed; the suspected behavior was not reproduced.")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except InfrastructureFailure as error:
        print(f"INFRASTRUCTURE FAILURE: {error}", file=sys.stderr)
        raise SystemExit(2)
