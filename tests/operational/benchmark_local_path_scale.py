#!/usr/bin/env python3
"""Measure scanner-only local path scaling at 1k, 10k, and 100k files."""

import argparse
import json
import os
from pathlib import Path
import platform
import re
import subprocess
import tempfile


PHASE_NAMES = ("cold", "warm", "delta", "re_warm")
TRACE_NAME = {
    "local filesystem scan wall": "scan_wall_us",
    "local fingerprint query wall": "fingerprint_wall_us",
    "local content hashing wall": "hash_wall_us",
    "local regular files observed": "regular_files",
    "local fingerprint queries": "fingerprint_queries",
    "local hash cache hits": "cache_hits",
    "local hash cache misses": "cache_misses",
    "local hash cache unsupported": "cache_unsupported",
    "local hash file calls": "hash_file_calls",
    "local hash bytes": "hash_bytes",
    "files changed during hash": "files_changed_during_hash",
}


def filesystem_name(path: Path) -> str:
    if os.name != "nt":
        return platform.system()
    try:
        import ctypes
        from ctypes import wintypes

        volume = ctypes.create_unicode_buffer(261)
        serial = wintypes.DWORD()
        max_component = wintypes.DWORD()
        flags = wintypes.DWORD()
        filesystem = ctypes.create_unicode_buffer(261)
        root = str(path.anchor or path).replace("/", "\\")
        ok = ctypes.windll.kernel32.GetVolumeInformationW(
            root,
            volume,
            len(volume),
            ctypes.byref(serial),
            ctypes.byref(max_component),
            ctypes.byref(flags),
            filesystem,
            len(filesystem),
        )
        if ok:
            return filesystem.value
    except (AttributeError, OSError):
        pass
    return "Windows filesystem (volume type unavailable)"


def create_tree(root: Path, files: int) -> None:
    root.mkdir(parents=True, exist_ok=True)
    payload = b"DATA"
    for index in range(files):
        (root / f"file-{index:06d}.bin").write_bytes(payload)


def parse_trace(stderr: str):
    phases = {}
    current = {}
    for line in stderr.splitlines():
        match = re.match(r"KASUMI_PERF name=(.*?) calls=(\d+) total_us=(-?\d+)", line)
        if match:
            name, calls, total_us = match.groups()
            current[name] = {"calls": int(calls), "total_us": int(total_us)}
            continue
        match = re.match(r"KASUMI_PERF outcome=(\S+)", line)
        if match:
            outcome = match.group(1)
            phases[outcome] = current
            current = {}
    return phases


def normalize_metrics(trace):
    metrics = {key: 0 for key in TRACE_NAME.values()}
    for name, values in trace.items():
        key = TRACE_NAME.get(name)
        if key is None:
            continue
        if key.endswith("_us"):
            metrics[key] = values["total_us"]
        else:
            metrics[key] = values["calls"]
    return metrics


def aggregate_filesystems(scenarios):
    filesystems = {scenario["filesystem"] for scenario in scenarios
                   if scenario.get("filesystem")}
    if not filesystems:
        return "unknown"
    return next(iter(filesystems)) if len(filesystems) == 1 else "mixed"


def parse_probe(stdout: str, stderr: str, files: int):
    phases = {}
    validation = None
    for line in stdout.splitlines():
        fields = line.split("|")
        if fields[0] == "PHASE" and len(fields) == 8:
            name = fields[1].removeprefix("path-scale-")
            if name == "rewarm":
                name = "re_warm"
            phases[name] = {
                "probe_wall_us": int(fields[2]),
                "snapshot_rows": int(fields[3]),
                "cache_rows": int(fields[4]),
                "working_set_bytes": int(fields[5]),
                "peak_working_set_bytes": int(fields[6]),
                "private_bytes": int(fields[7]),
            }
        elif fields[0] == "VALIDATION" and len(fields) == 5:
            validation = {
                "cold_equals_warm": fields[1] == "1",
                "delta_changes_one_file": fields[2] == "1",
                "rewarm_equals_delta": fields[3] == "1",
                "strong_fingerprint_supported": fields[4] == "1",
            }
    traces = parse_trace(stderr)
    outcome_for_phase = {
        "cold": "path-scale-cold",
        "warm": "path-scale-warm",
        "delta": "path-scale-delta",
        "re_warm": "path-scale-rewarm",
    }
    for phase, result in phases.items():
        result["metrics"] = normalize_metrics(traces.get(outcome_for_phase[phase], {}))
        result["wall_us"] = result["metrics"]["scan_wall_us"] or result["probe_wall_us"]
        result["wall_s"] = result["wall_us"] / 1_000_000
        result["us_per_path"] = result["wall_us"] / files
        result["fingerprint_percent"] = (
            100 * result["metrics"]["fingerprint_wall_us"] / result["wall_us"]
            if result["wall_us"]
            else 0
        )
    return phases, validation


def run_scenario(binary: Path, files: int, timeout: int):
    name = f"{files // 1000}k-small-paths"
    with tempfile.TemporaryDirectory(prefix="kasumi-r13-scan-") as temporary:
        root = Path(temporary) / name
        create_tree(root, files)
        scenario_filesystem = filesystem_name(root)
        environment = os.environ.copy()
        environment["KASUMI_PERF_TRACE"] = "1"
        try:
            process = subprocess.run(
                [str(binary), str(root)],
                capture_output=True,
                text=True,
                env=environment,
                timeout=timeout,
                check=False,
            )
        except subprocess.TimeoutExpired as error:
            return {
                "name": name,
                "files": files,
                "bytes_per_file": 4,
                "filesystem": scenario_filesystem,
                "status": "not_completed",
                "reason": f"timeout after {timeout}s: {error}",
            }
        if process.returncode != 0:
            return {
                "name": name,
                "files": files,
                "bytes_per_file": 4,
                "filesystem": scenario_filesystem,
                "status": "not_completed",
                "reason": process.stderr.strip() or f"exit code {process.returncode}",
                "returncode": process.returncode,
                "stdout": process.stdout,
                "stderr": process.stderr,
            }
        phases, validation = parse_probe(process.stdout, process.stderr, files)
        return {
            "name": name,
            "files": files,
            "bytes_per_file": 4,
            "filesystem": scenario_filesystem,
            "status": "measured",
            "phases": phases,
            "validation": validation,
            "stdout": process.stdout,
            "stderr": process.stderr,
        }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--benchmark", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--timeout", type=int, default=600)
    args = parser.parse_args()
    previous = {}
    if args.output.exists():
        try:
            previous = json.loads(args.output.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            previous = {}
    scenarios = [run_scenario(args.benchmark, files, args.timeout)
                 for files in (1000, 10000, 100000)]
    result = {
        "status": "measured" if all(s["status"] == "measured" for s in scenarios) else "partial",
        "harness": "scanner-only",
        "filesystem": aggregate_filesystems(scenarios),
        "filesystem_source": "scenario_temp_root",
        "os": platform.platform(),
        "bytes_per_file": 4,
        "memory_method": "release_previous_scan_result_before_phase_sample",
        "max_retained_scan_results_after_phase": 1,
        "scenarios": scenarios,
    }
    if "timing_reference" in previous:
        result["timing_reference"] = previous["timing_reference"]
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2), encoding="utf-8")


if __name__ == "__main__":
    main()
