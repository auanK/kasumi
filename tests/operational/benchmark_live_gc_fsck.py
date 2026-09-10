#!/usr/bin/env python3
"""Live benchmark for Kasumi GC and FSCK against real remote storage."""

import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time


MASTER_KEY = "0123456789abcdef" * 4  # 32-byte hex key


def run_cmd(cmd, env=None, cwd=None, check=True):
    print(f"[{time.strftime('%X')}] Running: {' '.join(str(c) for c in cmd)}")
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
        print(f"FAILED (code {res.returncode}):\nSTDOUT:\n{res.stdout}\nSTDERR:\n{res.stderr}")
        raise RuntimeError(f"Command failed: {' '.join(str(c) for c in cmd)}")
    return elapsed, res.returncode, res.stdout, res.stderr


def setup_environment(base_dir: Path, local_dir: Path, remote: str, concurrency: int):
    app_data = base_dir / "appdata" / "kasumi"
    app_data.mkdir(parents=True, exist_ok=True)
    local_dir.mkdir(parents=True, exist_ok=True)

    config_content = (
        "[profiles.test_gc]\n"
        f"local_dir = {json.dumps(str(local_dir))}\n"
        f"remote_dir = {json.dumps(remote)}\n"
        "min_history_depth = 5\n"
        "min_history_age_hours = 6\n"
    )
    (app_data / "config.toml").write_text(config_content, encoding="utf-8")

    env = os.environ.copy()
    env["KASUMI_MASTER_KEY"] = MASTER_KEY
    env["KASUMI_CONTENT_CONCURRENCY"] = str(concurrency)
    env["KASUMI_PERF_TRACE"] = "1"
    env["KASUMI_LANG"] = "en"
    try:
        rclone_conf_out = subprocess.check_output(["rclone", "config", "file"], text=True).strip()
        rclone_conf_path = rclone_conf_out.splitlines()[-1].strip()
        if os.path.exists(rclone_conf_path):
            env["RCLONE_CONFIG"] = rclone_conf_path
    except Exception as e:
        print(f"Warning: could not detect rclone config: {e}")
    if os.name == "nt":
        env["APPDATA"] = str(base_dir / "appdata")
    else:
        env["XDG_CONFIG_HOME"] = str(base_dir / "appdata")
    return env


def generate_files(target_dir: Path, count: int, size_bytes: int):
    print(f"[{time.strftime('%X')}] Generating {count} files of {size_bytes} bytes...")
    for i in range(count):
        file_path = target_dir / f"file_{i:04d}.bin"
        # Unique content per file so content hashes are distinct
        header = f"file_{i:04d}_kasumi_test_payload_".encode("ascii")
        padding = os.urandom(max(0, size_bytes - len(header)))
        file_path.write_bytes(header + padding)
    print(f"[{time.strftime('%X')}] {count} files generated.")


def delete_files(target_dir: Path, count: int):
    print(f"[{time.strftime('%X')}] Deleting {count} files...")
    deleted = 0
    for i in range(count):
        file_path = target_dir / f"file_{i:04d}.bin"
        if file_path.exists():
            file_path.unlink()
            deleted += 1
    print(f"[{time.strftime('%X')}] {deleted} files deleted locally.")


def main():
    parser = argparse.ArgumentParser(description="Kasumi GC & FSCK Live Benchmark")
    parser.add_argument("--kasumi", default="build/kasumi.exe", help="Path to kasumi executable")
    parser.add_argument("--remote", default="kasumi:kasumi/testes_gc", help="Remote storage path")
    parser.add_argument("--total-files", type=int, default=2000, help="Total files to seed (default 2000)")
    parser.add_argument("--delete-files", type=int, default=1000, help="Files to delete (default 1000)")
    parser.add_argument("--file-size", type=int, default=1024, help="File size in bytes (default 1024)")
    parser.add_argument("--concurrency", type=int, default=16, help="Transfer concurrency")
    parser.add_argument("--work-dir", default="temp_benchmark_gc", help="Local scratch directory")
    parser.add_argument("--skip-cleanup", action="store_true", help="Do not purge remote after test")
    args = parser.parse_args()

    kasumi_bin = Path(args.kasumi).resolve()
    if not kasumi_bin.exists():
        sys.exit(f"Executable not found: {kasumi_bin}")

    work_dir = Path(args.work_dir).resolve()
    if work_dir.exists():
        shutil.rmtree(work_dir, ignore_errors=True)
    work_dir.mkdir(parents=True, exist_ok=True)

    local_dir = work_dir / "local"
    env = setup_environment(work_dir, local_dir, args.remote, args.concurrency)

    results = []

    try:
        # Step 0: Ensure remote is clean and directory structure exists
        print(f"[{time.strftime('%X')}] Step 0: Preparing clean remote {args.remote}...")
        subprocess.run(["rclone", "delete", args.remote], capture_output=True, text=True)
        subprocess.run(["rclone", "mkdir", args.remote], capture_output=True, text=True)
        subprocess.run(["rclone", "mkdir", f"{args.remote}/history/heads"], capture_output=True, text=True)
        subprocess.run(["rclone", "mkdir", f"{args.remote}/history/commits"], capture_output=True, text=True)

        # Step 1: Generate initial files
        print(f"\n--- ETAPA 1: Gerar {args.total_files} arquivos de {args.file_size} bytes ---")
        generate_files(local_dir, args.total_files, args.file_size)

        # Step 2: Sync initial files
        print(f"\n--- ETAPA 2: Sync Inicial ({args.total_files} arquivos) ---")
        t_sync1, code, out, err = run_cmd([kasumi_bin, "sync", "test_gc"], env=env, cwd=local_dir)
        results.append(("Sync Inicial (2k arquivos)", t_sync1, f"OK (code {code})", out.strip()))

        # Step 3: Baseline FSCK (2k active files)
        print(f"\n--- ETAPA 3: FSCK Baseline (2k arquivos ativos) ---")
        t_fsck1, code, out, err = run_cmd([kasumi_bin, "fsck", "test_gc"], env=env, cwd=local_dir)
        results.append(("FSCK Baseline (2k arquivos)", t_fsck1, f"OK (code {code})", out.strip()))

        # Step 4: Baseline GC (2k files, Q=0, C=0)
        print(f"\n--- ETAPA 4: GC Baseline (Q=0, C=0, 2k arquivos) ---")
        t_gc1, code, out, err = run_cmd([kasumi_bin, "gc", "test_gc"], env=env, cwd=local_dir)
        results.append(("GC Baseline (Q=0, C=0)", t_gc1, f"OK (code {code})", out.strip()))

        # Step 5: Delete 1,000 files and Sync to create orphans
        print(f"\n--- ETAPA 5: Apagar {args.delete_files} arquivos e Sync ---")
        delete_files(local_dir, args.delete_files)
        t_sync2, code, out, err = run_cmd([kasumi_bin, "sync", "test_gc"], env=env, cwd=local_dir)
        results.append(("Sync Remoção (1k arquivos)", t_sync2, f"OK (code {code})", out.strip()))

        # Step 6: GC with 1,000 orphans
        print(f"\n--- ETAPA 6: GC com {args.delete_files} órfãos ---")
        t_gc2, code, out, err = run_cmd([kasumi_bin, "gc", "test_gc"], env=env, cwd=local_dir)
        results.append((f"GC Coleta ({args.delete_files} órfãos)", t_gc2, f"OK (code {code})", out.strip()))

        # Step 7: FSCK after GC (1,000 active files, 1,000 quarantined)
        print(f"\n--- ETAPA 7: FSCK pós-GC (1k arquivos ativos restantes) ---")
        t_fsck2, code, out, err = run_cmd([kasumi_bin, "fsck", "test_gc"], env=env, cwd=local_dir)
        results.append(("FSCK pós-GC (1k arquivos)", t_fsck2, f"OK (code {code})", out.strip()))

        # Step 8: Stable GC with Q=1000
        print(f"\n--- ETAPA 8: GC Estável com Q={args.delete_files}, C=0 ---")
        t_gc3, code, out, err = run_cmd([kasumi_bin, "gc", "test_gc"], env=env, cwd=local_dir)
        results.append(("GC Estável (Q=1k, C=0)", t_gc3, f"OK (code {code})", out.strip()))

    finally:
        if not args.skip_cleanup:
            print(f"\n[{time.strftime('%X')}] Limpando remoto {args.remote}...")
            subprocess.run(["rclone", "delete", args.remote], capture_output=True, text=True)
            print(f"[{time.strftime('%X')}] Limpeza remota concluída.")
        shutil.rmtree(work_dir, ignore_errors=True)

    # Print summary
    print("\n" + "=" * 70)
    print("RESUMO DO BENCHMARK (GC & FSCK)")
    print("=" * 70)
    print(f"{'Operação':<32} | {'Tempo (s)':<10} | {'Status':<12} | {'Detalhes'}")
    print("-" * 70)
    for op, elapsed, status, details in results:
        # shorten details for table
        first_line = details.splitlines()[-1] if details else ""
        print(f"{op:<32} | {elapsed:>10.2f} | {status:<12} | {first_line}")
    print("=" * 70)


if __name__ == "__main__":
    main()
