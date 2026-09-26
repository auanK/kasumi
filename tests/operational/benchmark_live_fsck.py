#!/usr/bin/env python3
"""Dedicated benchmark and profiling harness for Kasumi fsck."""

import argparse
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import time
import uuid

MASTER_KEY = "0123456789abcdef" * 4  # 32-byte hex key


def log(msg: str):
    print(f"[{time.strftime('%X')}] {msg}", flush=True)


def run_cmd(cmd, env=None, cwd=None, check=True):
    started = time.perf_counter()
    res = subprocess.run(
        [str(c) for c in cmd],
        env=env,
        cwd=cwd,
        capture_output=True,
        text=True,
        check=False,
    )
    elapsed = time.perf_counter() - started
    if check and res.returncode != 0:
        raise RuntimeError(
            f"Command failed (code {res.returncode}): {' '.join(str(c) for c in cmd)}\n"
            f"STDOUT:\n{res.stdout}\nSTDERR:\n{res.stderr}"
        )
    return elapsed, res.returncode, res.stdout, res.stderr


def is_remote_local(remote: str) -> bool:
    if not remote:
        return True
    # If Windows absolute path like D:\path or D:/path, it's local
    if len(remote) >= 3 and remote[1] == ":" and remote[2] in ("\\", "/"):
        return True
    # If contains colon, it's an rclone remote like kasumi:path
    return ":" not in remote


def setup_environment(base_dir: Path, local_dir: Path, remote_dir: str, rclone_config: str | None = None, concurrency: int = 8):
    app_data = base_dir / "appdata" / "kasumi"
    app_data.mkdir(parents=True, exist_ok=True)
    local_dir.mkdir(parents=True, exist_ok=True)

    config_content = (
        "[profiles.test_audit]\n"
        f"local_dir = {json.dumps(str(local_dir))}\n"
        f"remote_dir = {json.dumps(remote_dir)}\n"
        "min_history_depth = 5\n"
        "min_history_age_hours = 6\n"
    )
    (app_data / "config.toml").write_text(config_content, encoding="utf-8")

    env = os.environ.copy()
    env["KASUMI_MASTER_KEY"] = MASTER_KEY
    env["KASUMI_PERF_TRACE"] = "1"
    env["KASUMI_LANG"] = "en"
    env["KASUMI_CONTENT_CONCURRENCY"] = str(concurrency)
    if rclone_config and os.path.exists(rclone_config):
        env["RCLONE_CONFIG"] = rclone_config
    else:
        try:
            rclone_conf_out = subprocess.check_output(["rclone", "config", "file"], text=True).strip()
            rclone_conf_path = rclone_conf_out.splitlines()[-1].strip()
            if os.path.exists(rclone_conf_path):
                env["RCLONE_CONFIG"] = rclone_conf_path
        except Exception:
            pass

    if os.name == "nt":
        env["APPDATA"] = str(base_dir / "appdata")
    else:
        env["XDG_CONFIG_HOME"] = str(base_dir / "appdata")
    return env


def generate_unique_files(target_dir: Path, count: int, size_bytes: int):
    target_dir.mkdir(parents=True, exist_ok=True)
    total_bytes = 0
    for i in range(count):
        file_path = target_dir / f"file_{i:04d}.bin"
        prefix = f"kasumi_fsck_unique_payload_{i:04d}_{uuid.uuid4().hex}_".encode("ascii")
        if size_bytes <= len(prefix):
            data = prefix[:size_bytes]
        else:
            data = prefix + os.urandom(size_bytes - len(prefix))
        file_path.write_bytes(data)
        total_bytes += len(data)
    return total_bytes


def parse_perf_trace(stderr_text: str):
    metrics = {}
    pattern = re.compile(r"^KASUMI_PERF\s+name=(.+?)\s+calls=(\d+)\s+total_us=(\d+)")
    outcome_pattern = re.compile(r"^KASUMI_PERF\s+outcome=([^\s]+)")
    outcome = "unknown"
    for line in stderr_text.splitlines():
        line = line.strip()
        m = pattern.match(line)
        if m:
            name, calls, total_us = m.group(1), int(m.group(2)), int(m.group(3))
            metrics[name] = {"calls": calls, "total_us": total_us}
        else:
            om = outcome_pattern.match(line)
            if om:
                outcome = om.group(1)
    return metrics, outcome


def classify_objects(file_paths_and_sizes):
    total_bytes = sum(size for _, size in file_paths_and_sizes)
    content_objects = 0
    commit_count = 0
    head_count = 0
    epoch_count = 0
    other_history = 0

    hex_chars = set("0123456789abcdefABCDEF")
    for path, size in file_paths_and_sizes:
        path = path.replace("\\", "/")
        if "/" not in path and len(path) == 64 and all(c in hex_chars for c in path):
            content_objects += 1
        else:
            name = path.split("/")[-1]
            if len(name) == 85 and name[20] == "-":
                epoch_count += 1
            elif len(name) == 129 and name[64] == "-":
                head_count += 1
            elif len(name) == 64 and all(c in hex_chars for c in name):
                commit_count += 1
            else:
                other_history += 1
    return {
        "remote_object_count": len(file_paths_and_sizes),
        "remote_bytes": total_bytes,
        "content_object_count": content_objects,
        "commit_count": commit_count,
        "head_count": head_count,
        "epoch_count": epoch_count,
        "other_history_count": other_history,
    }


def inspect_remote(remote: str, is_local: bool, env: dict):
    if is_local:
        root = Path(remote)
        if not root.exists():
            return {
                "remote_object_count": 0,
                "remote_bytes": 0,
                "content_object_count": 0,
                "commit_count": 0,
                "head_count": 0,
                "epoch_count": 0,
                "other_history_count": 0,
            }
        file_items = [
            (p.relative_to(root).as_posix(), p.stat().st_size)
            for p in root.rglob("*")
            if p.is_file()
        ]
        return classify_objects(file_items)
    else:
        # Run rclone lsjson -R
        _, _, stdout, _ = run_cmd(["rclone", "lsjson", "-R", remote], env=env, check=True)
        items = json.loads(stdout) if stdout.strip() else []
        files = [
            (it.get("Path", ""), it.get("Size", 0))
            for it in items
            if not it.get("IsDir", False)
        ]
        return classify_objects(files)


def cleanup_remote(remote: str, is_local: bool, env: dict):
    if is_local:
        p = Path(remote)
        if p.exists():
            shutil.rmtree(p, ignore_errors=True)
    else:
        # Only purge the specific child namespace, never a parent
        run_cmd(["rclone", "purge", remote], env=env, check=False)


def main():
    parser = argparse.ArgumentParser(description="Kasumi FSCK Live Benchmark & Profiler")
    parser.add_argument("--kasumi", default="build-msys2-ucrt64/kasumi.exe", help="Path to kasumi binary")
    parser.add_argument("--remote", required=True, help="Remote storage path (rclone remote or local dir)")
    parser.add_argument("--files", type=int, default=10, help="Number of files (F)")
    parser.add_argument("--history-commits", type=int, default=1, help="Reachable history commit count (H)")
    parser.add_argument("--file-size", type=int, default=4096, help="File size in bytes")
    parser.add_argument("--concurrency", type=int, default=8, help="Content concurrency setting (C)")
    parser.add_argument("--scenario", default="profile", help="Scenario label (e.g. O1, O5, O10, F25)")
    parser.add_argument("--output", help="Output JSON path")
    parser.add_argument("--work-dir", default="temp_benchmark_fsck", help="Scratch directory")
    parser.add_argument("--rclone-config", help="Explicit path to rclone.conf")
    parser.add_argument("--skip-cleanup", action="store_true", help="Skip post-run cleanup")
    args = parser.parse_args()

    kasumi_bin = Path(args.kasumi).resolve()
    if not kasumi_bin.exists():
        sys.exit(f"Executable not found: {kasumi_bin}")

    work_dir = Path(args.work_dir).resolve()
    if work_dir.exists():
        shutil.rmtree(work_dir, ignore_errors=True)
    work_dir.mkdir(parents=True, exist_ok=True)

    is_local = is_remote_local(args.remote)
    local_dir = work_dir / "local"
    env = setup_environment(work_dir, local_dir, args.remote, args.rclone_config, args.concurrency)

    print(f"[{time.strftime('%X')}] Starting scenario {args.scenario}: F={args.files}, H={args.history_commits}, C={args.concurrency}, file_size={args.file_size} bytes")
    print(f"[{time.strftime('%X')}] Remote: {args.remote} (is_local={is_local})")

    try:
        # Step 0: Ensure child remote namespace is clean and ready
        cleanup_remote(args.remote, is_local, env)
        if not is_local:
            run_cmd(["rclone", "mkdir", args.remote], env=env, check=True)
            run_cmd(["rclone", "mkdir", f"{args.remote}/history/heads"], env=env, check=True)
            run_cmd(["rclone", "mkdir", f"{args.remote}/history/commits"], env=env, check=True)
        else:
            Path(args.remote).mkdir(parents=True, exist_ok=True)

        # Step 1: Generate unique files
        print(f"[{time.strftime('%X')}] Generating {args.files} unique files of {args.file_size} bytes...")
        plaintext_bytes = generate_unique_files(local_dir, args.files, args.file_size)

        # Prepare alternate payload for file_0000 to oscillate and create valid historical commits
        file_0 = local_dir / "file_0000.bin"
        content_a = file_0.read_bytes()
        prefix_b = f"kasumi_fsck_unique_payload_0000_b_{uuid.uuid4().hex}_".encode("ascii")
        content_b = prefix_b + (os.urandom(args.file_size - len(prefix_b)) if args.file_size > len(prefix_b) else b"")
        content_b = content_b[:args.file_size]

        # Step 2: Setup sync iterations (history depth)
        total_sync_wall_seconds = 0.0
        for h in range(1, args.history_commits + 1):
            if h > 1:
                # Alternate content of file_0000 to trigger a new valid commit with full protocol sync
                file_0.write_bytes(content_b if (h % 2 == 0) else content_a)

            print(f"[{time.strftime('%X')}] Running setup sync {h}/{args.history_commits}...")
            sync_wall_seconds, sync_code, sync_out, sync_err = run_cmd(
                [kasumi_bin, "sync", "test_audit"], env=env, cwd=local_dir, check=True
            )
            total_sync_wall_seconds += sync_wall_seconds
            print(f"[{time.strftime('%X')}] Setup sync {h} completed in {sync_wall_seconds:.3f}s")

        # Step 3: Fixture validation
        print(f"[{time.strftime('%X')}] Validating fixture...")
        remote_info = inspect_remote(args.remote, is_local, env)
        print(f"[{time.strftime('%X')}] Remote info: {remote_info}")
        if remote_info["content_object_count"] < args.files:
            raise RuntimeError(
                f"Fixture mismatch: expected at least {args.files} content objects, found {remote_info['content_object_count']}"
            )
        if remote_info["commit_count"] < args.history_commits:
            raise RuntimeError(
                f"Fixture mismatch: expected at least {args.history_commits} physical commit variants, found {remote_info['commit_count']}"
            )

        # Step 4: Official FSCK measurement
        print(f"\n[{time.strftime('%X')}] === OFFICIAL FSCK MEASUREMENT ({args.scenario}) ===")
        fsck_wall_seconds, fsck_code, fsck_out, fsck_err = run_cmd(
            [kasumi_bin, "fsck", "test_audit"], env=env, cwd=local_dir, check=True
        )
        print(f"[{time.strftime('%X')}] FSCK completed in {fsck_wall_seconds:.3f}s (code {fsck_code})")

        # Step 5: Collect metrics
        metrics, outcome = parse_perf_trace(fsck_err)

        # Helper to extract metrics
        def get_m(name):
            return metrics.get(name, {"calls": 0, "total_us": 0})

        result_data = {
            "scenario": args.scenario,
            "F": args.files,
            "H": args.history_commits,
            "actual_reachable_commits": get_m("history.reachable_commits")["calls"] or args.history_commits,
            "logical_heads": get_m("history.logical_heads")["calls"],
            "anchors_used": get_m("history.anchors_used")["calls"],
            "C": args.concurrency,
            "file_size": args.file_size,
            "plaintext_bytes": plaintext_bytes,
            "configured_concurrency": get_m("fsck.audit_configured_concurrency")["calls"] or args.concurrency,
            "effective_worker_count": get_m("fsck.audit_worker_count")["calls"],
            "peak_in_flight": get_m("fsck.audit_peak_in_flight")["calls"],
            "completion_count": get_m("fsck.audit_completion_count")["calls"],
            "physical_content_count": remote_info["content_object_count"],
            "remote_object_count": remote_info["remote_object_count"],
            "remote_bytes": remote_info["remote_bytes"],
            "commit_count": remote_info["commit_count"],
            "head_count": remote_info["head_count"],
            "epoch_count": remote_info["epoch_count"],
            "setup_sync_wall_seconds": total_sync_wall_seconds,
            "fsck_wall_seconds": fsck_wall_seconds,
            "outcome": outcome,
            "checked_objects": get_m("fsck.audit_objects")["calls"],
            "repaired_objects": 0,
            "full_list_calls": get_m("history.full_list_calls")["calls"] or get_m("rc/list")["calls"] or get_m("content listing/audit")["calls"],
            "stage_walls_us": {
                "observation_total": get_m("fsck.collect_storage_state_duration_us")["total_us"],
                "physical_list": get_m("content listing/audit")["total_us"],
                "history_inventory_build": get_m("history listing")["total_us"],
                "commit_batch_fetch": get_m("commit batch fetch")["total_us"],
                "epoch_loading": get_m("epoch loading")["total_us"],
                "head_loading": get_m("head loading")["total_us"],
                "commit_loading": get_m("commit loading")["total_us"],
                "commit_decrypt_auth": get_m("commit decrypt/auth")["total_us"],
                "content_inventory_derivation": get_m("content inventory derivation")["total_us"],
                "history_resolution": get_m("history resolution")["total_us"],
                "history_validation": get_m("history validation")["total_us"],
                "local_tree": get_m("fsck.local_tree_duration_us")["total_us"],
                "inventory_analysis": get_m("fsck.inventory_analysis_duration_us")["total_us"],
                "referenced_audit": get_m("fsck.referenced_audit_duration_us")["total_us"],
                "fsck_total": get_m("fsck.total_duration_us")["total_us"],
            },
            "observation_counters": {
                "epoch_candidates_observed": get_m("epoch.candidates_observed")["calls"],
                "epoch_get_calls": get_m("epoch.get_calls")["calls"],
                "epoch_bytes_downloaded": get_m("epoch.bytes_downloaded")["calls"],
                "epoch_authenticated_count": get_m("epoch.authenticated_count")["calls"],
                "marker_variants_observed": get_m("marker.variants_observed")["calls"],
                "marker_get_calls": get_m("marker.get_calls")["calls"],
                "marker_bytes_downloaded": get_m("marker.bytes_downloaded")["calls"],
                "marker_authenticated_count": get_m("marker.authenticated_count")["calls"],
                "marker_invalid_count": get_m("marker.invalid_count")["calls"],
                "commit_variants_observed": get_m("commit.variants_observed")["calls"],
                "commit_get_batch_calls": get_m("commit.get_batch_calls")["calls"],
                "commit_get_batch_objects": get_m("commit.get_batch_objects")["calls"],
                "commit_individual_get_calls": get_m("commit.individual_get_calls")["calls"],
                "commit_decrypt_auth_count": get_m("commit.decrypt_auth_count")["calls"],
                "commit_authenticated_variants": get_m("commit.authenticated_variants")["calls"],
                "commit_ciphertext_bytes": get_m("commit.ciphertext_bytes")["calls"],
                "commit_plaintext_bytes": get_m("commit.plaintext_bytes_authenticated")["calls"],
                "commit_loaded_logical_commits": get_m("commit.loaded_logical_commits")["calls"],
                "history_full_list_calls": get_m("history.full_list_calls")["calls"],
                "history_reachable_commits": get_m("history.reachable_commits")["calls"],
                "history_logical_heads": get_m("history.logical_heads")["calls"],
                "history_anchors_used": get_m("history.anchors_used")["calls"],
                "content_physical_objects": get_m("content.physical_objects")["calls"],
                "content_referenced_ids": get_m("content.referenced_ids")["calls"],
            },
            "transport_calls": {
                "rc_list_calls": get_m("rc/list")["calls"] or get_m("rc.http_requests_by_endpoint.operations/list")["calls"],
                "rc_list_total_us": get_m("rc/list")["total_us"],
                "rc_get_epoch_calls": get_m("rc/get_epoch")["calls"],
                "rc_get_epoch_total_us": get_m("rc/get_epoch")["total_us"],
                "rc_get_marker_calls": get_m("rc/get_marker")["calls"],
                "rc_get_marker_total_us": get_m("rc/get_marker")["total_us"],
                "rc_get_commit_calls": get_m("rc/get_commit")["calls"],
                "rc_get_commit_total_us": get_m("rc/get_commit")["total_us"],
                "rclone_batch_download_calls": get_m("rclone batch download")["calls"],
                "rclone_batch_download_total_us": get_m("rclone batch download")["total_us"],
                "rclone_copy_batch_inputs": get_m("rclone.copy_batch_inputs_submitted")["calls"],
                "rclone_copy_batch_concurrency": get_m("rclone.copy_batch_concurrency_submitted")["calls"],
                "rclone_copy_batch_successes": get_m("rclone.copy_batch_reported_successes")["calls"],
                "rclone_copyfile_download_calls": get_m("rclone copyfile download")["calls"],
                "rclone_copyfile_download_total_us": get_m("rclone copyfile download")["total_us"],
                "http_operations_list_calls": get_m("rc.http_requests_by_endpoint.operations/list")["calls"],
                "http_operations_copyfile_calls": get_m("rc.http_requests_by_endpoint.operations/copyfile")["calls"],
                "http_sync_copy_calls": get_m("rc.http_requests_by_endpoint.sync/copy")["calls"],
                "http_requests_attempted": get_m("rc.http_requests_attempted")["calls"],
                "http_requests_completed": get_m("rc.http_requests_completed")["calls"],
                "http_requests_failed": get_m("rc.http_requests_failed")["calls"],
                "http_retries": get_m("RC idempotent read retries")["calls"],
            },
            "payload_audit": {
                "checked_objects": get_m("fsck.audit_objects")["calls"],
                "concurrency": args.concurrency,
                "worker_count": get_m("fsck.audit_worker_count")["calls"],
                "peak_in_flight": get_m("fsck.audit_peak_in_flight")["calls"],
                "referenced_audit_wall_us": get_m("fsck.referenced_audit_duration_us")["total_us"],
                "accumulated_get_us": get_m("fsck.referenced_get_duration_us")["total_us"],
                "accumulated_aead_us": get_m("fsck.referenced_aead_duration_us")["total_us"],
                "accumulated_blake3_us": get_m("fsck.referenced_blake3_duration_us")["total_us"],
                "downloaded_bytes": get_m("fsck.referenced_content_bytes_downloaded")["calls"],
            },
            "retry_count": get_m("rclone.retry_count")["calls"] + get_m("RC idempotent read retries")["calls"],
            "rate_limit_count": get_m("rclone.rate_limit_count")["calls"],
            "unexpected_transport_errors": get_m("rclone.unexpected_transport_errors")["calls"] + get_m("rc.http_requests_failed")["calls"],
            "all_perf_metrics": metrics,
        }

        print("\n--- MEASURED RESULTS ---")
        print(f"FSCK Wall: {fsck_wall_seconds:.3f} s")
        print(f"Physical List Calls: {result_data['full_list_calls']}")
        print(f"Observation Total Wall: {result_data['stage_walls_us']['observation_total'] / 1000.0:.2f} ms")
        print(f"  - Physical LIST: {result_data['stage_walls_us']['physical_list'] / 1000.0:.2f} ms")
        print(f"  - History Inventory Build: {result_data['stage_walls_us']['history_inventory_build'] / 1000.0:.2f} ms")
        print(f"  - Commit Batch Fetch: {result_data['stage_walls_us']['commit_batch_fetch'] / 1000.0:.2f} ms")
        print(f"  - Epoch Loading: {result_data['stage_walls_us']['epoch_loading'] / 1000.0:.2f} ms")
        print(f"  - Head Loading: {result_data['stage_walls_us']['head_loading'] / 1000.0:.2f} ms")
        print(f"  - Commit Loading (traversal+auth): {result_data['stage_walls_us']['commit_loading'] / 1000.0:.2f} ms")
        print(f"    - Commit Decrypt/Auth: {result_data['stage_walls_us']['commit_decrypt_auth'] / 1000.0:.2f} ms")
        print(f"  - Content Inventory Derivation: {result_data['stage_walls_us']['content_inventory_derivation'] / 1000.0:.2f} ms")
        print(f"  - History Resolution: {result_data['stage_walls_us']['history_resolution'] / 1000.0:.2f} ms")
        print(f"  - History Validation: {result_data['stage_walls_us']['history_validation'] / 1000.0:.2f} ms")
        print(f"Payload Audit Wall: {result_data['stage_walls_us']['referenced_audit'] / 1000.0:.2f} ms")
        print(f"History: Reachable Commits={result_data['actual_reachable_commits']}, Logical Heads={result_data['logical_heads']}")
        print(f"Transport calls: LIST={result_data['transport_calls']['rc_list_calls']}, Epoch GET={result_data['transport_calls']['rc_get_epoch_calls']}, Marker GET={result_data['transport_calls']['rc_get_marker_calls']}, Commit Batch={result_data['transport_calls']['rclone_batch_download_calls']}, Commit Indiv GET={result_data['observation_counters']['commit_individual_get_calls']}")

        if args.output:
            out_path = Path(args.output).resolve()
            out_path.parent.mkdir(parents=True, exist_ok=True)
            out_path.write_text(json.dumps(result_data, indent=2), encoding="utf-8")
            print(f"[{time.strftime('%X')}] Results written to: {out_path}")

        return result_data

    finally:
        if not args.skip_cleanup:
            print(f"[{time.strftime('%X')}] Cleaning up...")
            cleanup_remote(args.remote, is_local, env)
            shutil.rmtree(work_dir, ignore_errors=True)
            print(f"[{time.strftime('%X')}] Cleanup finished.")


if __name__ == "__main__":
    main()
