#!/usr/bin/env python3
"""Deterministic baseline-versus-optimized local synchronization benchmark.

Compares Kasumi baseline (2345452) vs hardened optimized (HEAD) across
standard ordinary Sync workloads and directory rename with isolated local storage.
"""

import argparse
import hashlib
import json
import os
import platform
import re
import statistics
import subprocess
import sys
import tempfile
import time
from pathlib import Path

MASTER_KEY = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
TRACE_PATTERN = re.compile(r"^KASUMI_PERF name=(.+) calls=(\d+) total_us=(\d+)$")

TEXT_FIXTURES = {
    "README.md": b"# Kasumi Performance Fixture\nDeterministic benchmark content.\n",
    "docs/architecture.md": b"Layered transaction journals and reconciliation protocols.\n" * 16,
    "src/engine.cpp": b"// Core engine implementation\nvoid sync() { /* ... */ }\n" * 32,
    "src/include/engine.hpp": b"#pragma once\nstruct State { int id; };\n" * 8,
    "config/settings.toml": b"[engine]\nconcurrency = 4\nretry_limit = 3\n",
}

BINARY_SIZES = {
    "assets/blob_large.bin": 4_198_401,
    "assets/chunk_64k.bin": 65_536,
    "assets/chunk_16k.bin": 16_384,
    "assets/small_a.bin": 1_024,
    "assets/small_b.bin": 2_048,
    "assets/nested/deep_blob.bin": 32_768,
    "cache/precomputed.bin": 8_192,
    "cache/index.bin": 4_096,
}


def deterministic_bytes(seed_str: str, size: int) -> bytes:
    hasher = hashlib.shake_256(seed_str.encode("utf-8"))
    return hasher.digest(size)


def write_fixture(root: Path, size_category: str):
    root.mkdir(parents=True, exist_ok=True)
    if size_category == "small":
        for rel_path, content in TEXT_FIXTURES.items():
            dest = root / rel_path
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_bytes(content)
        for rel_path, size in BINARY_SIZES.items():
            dest = root / rel_path
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_bytes(deterministic_bytes(f"small:{rel_path}", size))
    elif size_category == "medium":
        # 1,000 files:
        for idx in range(1000):
            folder = root / f"dir_{idx // 50:03d}"
            folder.mkdir(parents=True, exist_ok=True)
            file_path = folder / f"file_{idx:04d}.bin"
            size = 100 + (idx % 20) * 50
            file_path.write_bytes(deterministic_bytes(f"medium:{idx}", size))


def make_client(env_root: Path, local_dir: Path, storage_dir: Path) -> dict:
    app_data = env_root / "kasumi"
    app_data.mkdir(parents=True, exist_ok=True)
    local_dir.mkdir(parents=True, exist_ok=True)
    (app_data / "config.toml").write_text(
        "[profiles.perf]\n"
        f"local_dir = {json.dumps(str(local_dir))}\n"
        f"remote_dir = {json.dumps(str(storage_dir))}\n"
        "min_history_depth = 5\n"
        "min_history_age_hours = 6\n",
        encoding="utf-8",
    )
    env = os.environ.copy()
    env["KASUMI_MASTER_KEY"] = MASTER_KEY
    env["KASUMI_PERF_TRACE"] = "1"
    env["KASUMI_CONTENT_CONCURRENCY"] = "4"
    env["KASUMI_LANG"] = "en"
    if os.name == "nt":
        env["APPDATA"] = str(env_root)
    else:
        env["XDG_CONFIG_HOME"] = str(env_root)
    return env


def parse_metrics(stderr: str) -> dict:
    metrics = {}
    for line in stderr.splitlines():
        match = TRACE_PATTERN.match(line.strip())
        if match:
            metrics[match.group(1)] = {
                "calls": int(match.group(2)),
                "total_us": int(match.group(3)),
            }
    return metrics


def run_sync(binary: Path, local_dir: Path, env: dict, initial: bool = False, timeout: int = 900) -> dict:
    args = [str(binary), "sync", "perf"]
    if initial:
        args.append("--initial")
    start = time.perf_counter()
    proc = subprocess.run(
        args,
        cwd=local_dir,
        env=env,
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )
    elapsed = time.perf_counter() - start
    if proc.returncode != 0:
        raise RuntimeError(f"Sync failed with exit {proc.returncode}:\nSTDOUT:\n{proc.stdout}\nSTDERR:\n{proc.stderr}")
    metrics = parse_metrics(proc.stderr)
    return {
        "elapsed_seconds": elapsed,
        "metrics": metrics,
    }


def extract_datapoints(sync_res: dict) -> dict:
    m = sync_res["metrics"]
    def get_c(name):
        return m.get(name, {}).get("calls", 0)
    def get_s(name):
        return m.get(name, {}).get("total_us", 0) / 1_000_000.0

    return {
        "elapsed_seconds": sync_res["elapsed_seconds"],
        "reconciliation_seconds": get_s("reconciliation"),
        "transaction_prep_seconds": get_s("transaction preparation"),
        "transaction_exec_seconds": get_s("transaction execution"),
        "final_local_validation_seconds": get_s("final local validation"),
        "journal_durable_saves": get_c("journal durable saves"),
        "journal_written_bytes": get_c("journal written bytes total"),
        "physical_content_gets": get_c("rc/get_content") + get_c("transport get"),
        "physical_content_puts": get_c("rc/put_content") + get_c("transport put") + get_c("content batch PUT objects completed"),
        "local_reuse_candidates_matched": get_c("local reuse candidates matched"),
        "local_reuse_moves_completed": get_c("local reuse moves completed"),
        "local_hash_bytes": get_c("local hash bytes"),
    }


def execute_workload(binary: Path, workload: str, fixture_type: str, temp_base: Path) -> dict:
    storage = temp_base / "storage"
    storage.mkdir(parents=True, exist_ok=True)
    a_env_root = temp_base / "client_a_env"
    a_local = temp_base / "client_a_local"
    b_env_root = temp_base / "client_b_env"
    b_local = temp_base / "client_b_local"

    a_env = make_client(a_env_root, a_local, storage)
    b_env = make_client(b_env_root, b_local, storage)

    if workload == "initial-upload":
        write_fixture(a_local / "Project", fixture_type)
        res = run_sync(binary, a_local, a_env, initial=True)
        return extract_datapoints(res)

    elif workload == "initial-download":
        write_fixture(a_local / "Project", fixture_type)
        run_sync(binary, a_local, a_env, initial=True)
        res = run_sync(binary, b_local, b_env, initial=True)
        return extract_datapoints(res)

    elif workload == "stable-noop":
        write_fixture(a_local / "Project", fixture_type)
        run_sync(binary, a_local, a_env, initial=True)
        run_sync(binary, b_local, b_env, initial=True)
        # B sync again with no changes:
        res = run_sync(binary, b_local, b_env, initial=False)
        return extract_datapoints(res)

    elif workload == "modified-download":
        write_fixture(a_local / "Project", fixture_type)
        run_sync(binary, a_local, a_env, initial=True)
        run_sync(binary, b_local, b_env, initial=True)
        # A modifies one file:
        target_file = next((a_local / "Project").rglob("*.bin"))
        target_file.write_bytes(target_file.read_bytes() + b"_MODIFIED")
        run_sync(binary, a_local, a_env, initial=False)
        res = run_sync(binary, b_local, b_env, initial=False)
        return extract_datapoints(res)

    elif workload == "delete-only":
        write_fixture(a_local / "Project", fixture_type)
        run_sync(binary, a_local, a_env, initial=True)
        run_sync(binary, b_local, b_env, initial=True)
        # A deletes 2 files:
        files = list((a_local / "Project").rglob("*.bin"))[:2]
        for f in files:
            f.unlink()
        run_sync(binary, a_local, a_env, initial=False)
        res = run_sync(binary, b_local, b_env, initial=False)
        return extract_datapoints(res)

    elif workload == "mixed-normal-sync":
        write_fixture(a_local / "Project", fixture_type)
        run_sync(binary, a_local, a_env, initial=True)
        run_sync(binary, b_local, b_env, initial=True)
        # A adds 2, modifies 2, deletes 2 files (no rename):
        files = list((a_local / "Project").rglob("*.bin"))
        if len(files) >= 4:
            files[0].unlink()
            files[1].unlink()
            files[2].write_bytes(files[2].read_bytes() + b"_UPDATED_A")
            files[3].write_bytes(files[3].read_bytes() + b"_UPDATED_B")
        added_a = a_local / "Project" / "new_mixed_1.bin"
        added_b = a_local / "Project" / "new_mixed_2.bin"
        added_a.write_bytes(b"NEW_CONTENT_MIXED_1")
        added_b.write_bytes(b"NEW_CONTENT_MIXED_2")
        run_sync(binary, a_local, a_env, initial=False)
        res = run_sync(binary, b_local, b_env, initial=False)
        return extract_datapoints(res)

    elif workload == "pure-rename":
        write_fixture(a_local / "Project", fixture_type)
        run_sync(binary, a_local, a_env, initial=True)
        run_sync(binary, b_local, b_env, initial=True)
        # A renames Project to RenamedProject:
        (a_local / "Project").rename(a_local / "RenamedProject")
        run_sync(binary, a_local, a_env, initial=False)
        res = run_sync(binary, b_local, b_env, initial=False)
        return extract_datapoints(res)

    else:
        raise ValueError(f"Unknown workload: {workload}")


def compute_statistics(samples: list[dict]) -> dict:
    keys = samples[0].keys()
    stats = {}
    for k in keys:
        vals = [s[k] for s in samples]
        stats[k] = {
            "median": round(statistics.median(vals), 6),
            "min": round(min(vals), 6),
            "max": round(max(vals), 6),
            "raw": vals,
        }
    return stats


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--baseline", required=True, type=Path)
    parser.add_argument("--optimized", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--repetitions", default=5, type=int)
    args = parser.parse_args()

    workloads = [
        "stable-noop",
        "initial-upload",
        "initial-download",
        "modified-download",
        "delete-only",
        "mixed-normal-sync",
        "pure-rename",
    ]
    fixtures = ["small", "medium"]

    results = {
        "metadata": {
            "os": platform.platform(),
            "repetitions": args.repetitions,
            "baseline_binary": str(args.baseline),
            "optimized_binary": str(args.optimized),
            "timestamp": time.time(),
        },
        "workloads": {},
    }

    for fix in fixtures:
        for wl in workloads:
            wl_key = f"{fix}:{wl}"
            print(f"Running workload {wl_key}...", flush=True)

            # Warm-up run:
            with tempfile.TemporaryDirectory(prefix="kasumi-bench-warm-") as warm_dir:
                execute_workload(args.baseline, wl, fix, Path(warm_dir) / "baseline")
                execute_workload(args.optimized, wl, fix, Path(warm_dir) / "optimized")

            reps = args.repetitions if fix == "small" else (2 if wl == "pure-rename" else min(3, args.repetitions))
            # Measured repetitions:
            base_samples = []
            opt_samples = []
            for rep in range(reps):
                with tempfile.TemporaryDirectory(prefix="kasumi-bench-base-") as b_dir:
                    base_samples.append(execute_workload(args.baseline, wl, fix, Path(b_dir)))
                with tempfile.TemporaryDirectory(prefix="kasumi-bench-opt-") as o_dir:
                    opt_samples.append(execute_workload(args.optimized, wl, fix, Path(o_dir)))

            base_stats = compute_statistics(base_samples)
            opt_stats = compute_statistics(opt_samples)

            # Compute differences on elapsed_seconds:
            b_med = base_stats["elapsed_seconds"]["median"]
            o_med = opt_stats["elapsed_seconds"]["median"]
            abs_diff = round(o_med - b_med, 6)
            rel_diff_pct = round(((o_med - b_med) / b_med * 100.0) if b_med > 0 else 0.0, 2)

            results["workloads"][wl_key] = {
                "fixture": fix,
                "workload": wl,
                "samples": reps,
                "baseline": base_stats,
                "optimized": opt_stats,
                "elapsed_comparison": {
                    "baseline_median": b_med,
                    "optimized_median": o_med,
                    "absolute_diff_seconds": abs_diff,
                    "relative_diff_pct": rel_diff_pct,
                },
            }
            print(f"  -> base: {b_med:.4f}s, opt: {o_med:.4f}s (diff: {rel_diff_pct:+.2f}%)", flush=True)

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(results, indent=2), encoding="utf-8")
    print(f"\nBenchmark completed successfully. Results saved to {args.output}")


if __name__ == "__main__":
    main()
