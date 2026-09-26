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
    pattern = re.compile(r"^KASUMI_PERF\s+name=([^\s]+)\s+calls=(\d+)\s+total_us=(\d+)")
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
    parser.add_argument("--file-size", type=int, default=4096, help="File size in bytes")
    parser.add_argument("--concurrency", type=int, default=8, help="Content concurrency setting (C)")
    parser.add_argument("--scenario", default="profile", help="Scenario label (e.g. L50, R10)")
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

    print(f"[{time.strftime('%X')}] Starting scenario {args.scenario}: F={args.files}, C={args.concurrency}, file_size={args.file_size} bytes")
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

        # Step 2: Setup sync
        print(f"[{time.strftime('%X')}] Running setup sync...")
        sync_wall_seconds, sync_code, sync_out, sync_err = run_cmd(
            [kasumi_bin, "sync", "test_audit"], env=env, cwd=local_dir, check=True
        )
        print(f"[{time.strftime('%X')}] Setup sync completed in {sync_wall_seconds:.3f}s")

        # Step 3: Fixture validation
        print(f"[{time.strftime('%X')}] Validating fixture...")
        remote_info = inspect_remote(args.remote, is_local, env)
        print(f"[{time.strftime('%X')}] Remote info: {remote_info}")
        if remote_info["content_object_count"] != args.files:
            raise RuntimeError(
                f"Fixture mismatch: expected {args.files} content objects, found {remote_info['content_object_count']}"
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
            "setup_sync_wall_seconds": sync_wall_seconds,
            "fsck_wall_seconds": fsck_wall_seconds,
            "outcome": outcome,
            "checked_objects": get_m("fsck.audit_objects")["calls"],
            "repaired_objects": 0,
            "total_get_count": get_m("fsck.audit_get_calls")["calls"] + get_m("reachability.audit_get_calls")["calls"],
            "total_get_bytes": get_m("fsck.encrypted_bytes_downloaded")["calls"] + get_m("reachability.encrypted_bytes_downloaded")["calls"],
            "reachability_audit_object_count": get_m("reachability.audit_objects")["calls"],
            "reachability_get_count": get_m("reachability.audit_get_calls")["calls"],
            "reachability_decrypt_count": get_m("reachability.audit_decrypt_calls")["calls"],
            "reachability_verify_count": get_m("reachability.audit_verify_calls")["calls"],
            "reachability_encrypted_bytes": get_m("reachability.encrypted_bytes_downloaded")["calls"],
            "reachability_plaintext_bytes": get_m("reachability.plaintext_bytes_verified")["calls"],
            "fsck_explicit_audit_object_count": get_m("fsck.audit_objects")["calls"],
            "fsck_explicit_get_count": get_m("fsck.audit_get_calls")["calls"],
            "fsck_explicit_decrypt_count": get_m("fsck.audit_decrypt_calls")["calls"],
            "fsck_explicit_verify_count": get_m("fsck.audit_verify_calls")["calls"],
            "fsck_encrypted_bytes": get_m("fsck.encrypted_bytes_downloaded")["calls"],
            "fsck_plaintext_bytes": get_m("fsck.plaintext_bytes_verified")["calls"],
            "full_list_calls": get_m("content listing/audit")["calls"],
            "timers_us": {
                "total": get_m("fsck.total_duration_us")["total_us"],
                "collect_storage_state": get_m("fsck.collect_storage_state_duration_us")["total_us"],
                "observation_list": get_m("content listing/audit")["total_us"],
                "physical_listing": get_m("fsck.physical_listing_duration_us")["total_us"],
                "local_tree": get_m("fsck.local_tree_duration_us")["total_us"],
                "inventory_analysis": get_m("fsck.inventory_analysis_duration_us")["total_us"],
                "workspace": get_m("fsck.workspace_duration_us")["total_us"],
                "reachability_get": get_m("reachability.audit_get_duration_us")["total_us"],
                "reachability_decrypt": get_m("reachability.audit_decrypt_duration_us")["total_us"],
                "reachability_verify": get_m("reachability.audit_verify_duration_us")["total_us"],
                "referenced_audit": get_m("fsck.referenced_audit_duration_us")["total_us"],
                "fsck_get": get_m("fsck.audit_get_duration_us")["total_us"],
                "fsck_decrypt": get_m("fsck.audit_decrypt_duration_us")["total_us"],
                "fsck_verify": get_m("fsck.audit_verify_duration_us")["total_us"],
            },
            "retry_count": get_m("rclone.retry_count")["calls"],
            "rate_limit_count": get_m("rclone.rate_limit_count")["calls"],
            "unexpected_transport_errors": get_m("rclone.unexpected_transport_errors")["calls"],
            "all_perf_metrics": metrics,
        }

        print("\n--- MEASURED RESULTS ---")
        print(f"FSCK Wall: {fsck_wall_seconds:.3f} s")
        print(f"Physical List Calls: {result_data['full_list_calls']}")
        print(f"Concurrency: C={args.concurrency}, Peak={result_data['peak_in_flight']}, Workers={result_data['effective_worker_count']}, Completions={result_data['completion_count']}")
        print(f"Checked Objects: {result_data['checked_objects']}")
        print(f"Explicit FSCK GETs: {result_data['fsck_explicit_get_count']}")
        print(f"Reachability Audits: {result_data['reachability_audit_object_count']}")
        print(f"Encrypted Bytes Downloaded: {result_data['fsck_encrypted_bytes']}")
        print(f"Plaintext Bytes Verified: {result_data['fsck_plaintext_bytes']}")
        print("Stage Timers (ms):")
        for k, v in result_data["timers_us"].items():
            print(f"  {k}: {v / 1000.0:.2f} ms")

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
