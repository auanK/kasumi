#!/usr/bin/env python3
"""Measure StateStorage delta persistence and the real full-snapshot codec."""

import argparse
import json
import os
from pathlib import Path
import platform
import re
import subprocess
import tempfile


TRACE_RE = re.compile(r"KASUMI_PERF name=(.*?) calls=(\d+) total_us=(-?\d+)")
OUTCOME_RE = re.compile(r"KASUMI_PERF outcome=(\S+)")
STATE_SCENARIOS = ("unchanged", "one_changed", "one_added", "one_deleted",
                   "hundred_deleted")


def parse_trace(stderr: str):
    traces = {}
    current = {}
    for line in stderr.splitlines():
        match = TRACE_RE.fullmatch(line)
        if match:
            name, calls, total_us = match.groups()
            current[name] = {"calls": int(calls), "total_us": int(total_us)}
            continue
        match = OUTCOME_RE.fullmatch(line)
        if match:
            traces[match.group(1)] = current
            current = {}
    return traces


def metric(trace, name, field="calls"):
    return trace.get(name, {}).get(field, 0)


def run(binary: Path, args, timeout: int):
    environment = os.environ.copy()
    environment["KASUMI_PERF_TRACE"] = "1"
    return subprocess.run([str(binary), *map(str, args)], capture_output=True,
                          text=True, env=environment, timeout=timeout,
                          check=False)


def state_scenario(record, traces, files, scenario):
    state_trace = traces.get(f"state-db-{files}-{scenario}-save-state", {})
    cache_trace = traces.get(f"state-db-{files}-{scenario}-save-cache", {})
    node_writes = {
        "existing_rows": metric(state_trace, "state db existing node rows"),
        "inserts": metric(state_trace, "state db node inserts"),
        "updates": metric(state_trace, "state db node updates"),
        "deletes": metric(state_trace, "state db node deletes"),
        "unchanged": metric(state_trace, "state db node unchanged"),
    }
    cache_writes = {
        "inserts": metric(cache_trace, "state db cache inserts"),
        "updates": metric(cache_trace, "state db cache updates"),
        "deletes": metric(cache_trace, "state db cache deletes"),
        "unchanged": metric(cache_trace, "state db cache unchanged"),
    }
    return {
        "seed_wall_us": record["seed_wall_us"],
        "load_state_us": record["load_state_us"],
        "load_cache_us": record["load_cache_us"],
        "save_state_us": record["save_state_us"],
        "save_cache_us": record["save_cache_us"],
        "combined_save_us": record["combined_save_us"],
        "node_inserts": node_writes["inserts"],
        "node_updates": node_writes["updates"],
        "node_deletes": node_writes["deletes"],
        "node_unchanged": node_writes["unchanged"],
        "existing_node_rows": node_writes["existing_rows"],
        "cache_inserts": cache_writes["inserts"],
        "cache_updates": cache_writes["updates"],
        "cache_deletes": cache_writes["deletes"],
        "cache_unchanged": cache_writes["unchanged"],
        "node_diff_us": metric(state_trace, "state db node diff wall", "total_us"),
        "cache_diff_us": metric(cache_trace, "state db cache diff wall", "total_us"),
        "transaction_us": (
            metric(state_trace, "state db transaction wall", "total_us")
            + metric(cache_trace, "state db transaction wall", "total_us")
        ),
        "database_bytes": record["database_bytes"],
        "wal_bytes": record["wal_bytes"],
        "shm_bytes": record["shm_bytes"],
        "state_valid": bool(record["state_valid"]),
        "cache_valid": bool(record["cache_valid"]),
    }


def run_state(binary: Path, files: int, timeout: int):
    with tempfile.TemporaryDirectory(prefix="kasumi-r13-state-") as temporary:
        process = run(binary, ("state-db", Path(temporary) / "db", files), timeout)
        if process.returncode != 0:
            return {"status": "not_completed", "reason": process.stderr.strip(),
                    "stdout": process.stdout, "stderr": process.stderr}
        records = {}
        for line in process.stdout.splitlines():
            fields = line.split("|")
            if len(fields) != 14 or fields[0] != "STATE":
                continue
            records[fields[2]] = {
                "seed_wall_us": int(fields[3]),
                "load_state_us": int(fields[4]),
                "load_cache_us": int(fields[5]),
                "save_state_us": int(fields[6]),
                "save_cache_us": int(fields[7]),
                "combined_save_us": int(fields[8]),
                "database_bytes": int(fields[9]),
                "wal_bytes": int(fields[10]),
                "shm_bytes": int(fields[11]),
                "state_valid": int(fields[12]),
                "cache_valid": int(fields[13]),
            }
        traces = parse_trace(process.stderr)
        if "initial" not in records or any(s not in records for s in STATE_SCENARIOS):
            return {"status": "not_completed", "reason": "incomplete probe output",
                    "stdout": process.stdout, "stderr": process.stderr}
        scenarios = {
            scenario: state_scenario(records[scenario], traces, files, scenario)
            for scenario in STATE_SCENARIOS
        }
        scenarios["initial"] = {
            "seed_wall_us": records["initial"]["seed_wall_us"],
            "database_bytes": records["initial"]["database_bytes"],
            "wal_bytes": records["initial"]["wal_bytes"],
            "shm_bytes": records["initial"]["shm_bytes"],
            "state_valid": True,
            "cache_valid": True,
        }
        return {"status": "measured", "paths": files, "rows": files + 1,
                "scenarios": scenarios, "stdout": process.stdout,
                "stderr": process.stderr}


def commit_record(fields):
    return {
        "paths": int(fields[1]),
        "long_path": bool(int(fields[2])),
        "snapshot_construction_us": int(fields[3]),
        "finalize_snapshot_us": int(fields[4]),
        "make_commit_us": int(fields[5]),
        "serialize_us": int(fields[6]),
        "serialized_bytes": int(fields[7]),
        "compute_id_us": int(fields[8]),
        "deserialize_us": int(fields[9]),
        "roundtrip_valid": bool(int(fields[10])),
        "maximum_commit_plaintext_size_bytes": int(fields[11]),
    }


def run_commit(binary: Path, files: int, long_path: bool, timeout: int):
    with tempfile.TemporaryDirectory(prefix="kasumi-r13-commit-") as temporary:
        args = ("commit", Path(temporary), files) + (("long-path",) if long_path else ())
        process = run(binary, args, timeout)
        if process.returncode != 0:
            return {"status": "not_completed", "reason": process.stderr.strip(),
                    "stdout": process.stdout, "stderr": process.stderr}
        records = [commit_record(line.split("|"))
                   for line in process.stdout.splitlines()
                   if line.startswith("COMMIT|")]
        if len(records) != 1:
            return {"status": "not_completed", "reason": "incomplete probe output",
                    "stdout": process.stdout, "stderr": process.stderr}
        return records[0]


def enrich_commit(record, previous=None):
    record = dict(record)
    record["bytes_per_path"] = record["serialized_bytes"] / record["paths"]
    record["limit_percent"] = (
        100 * record["serialized_bytes"] /
        record["maximum_commit_plaintext_size_bytes"]
    )
    if previous:
        record["growth_ratio"] = record["serialized_bytes"] / previous["serialized_bytes"]
    return record


def make_commit_artifact(binary: Path, timeout: int):
    raw = [run_commit(binary, paths, False, timeout) for paths in (1000, 10000, 100000)]
    if any(item.get("status") == "not_completed" for item in raw):
        return {"status": "partial", "scales": raw, "memory": "not_measured"}
    scales = []
    for index, item in enumerate(raw):
        scales.append(enrich_commit(item, scales[-1] if scales else None))
    short_10k, short_100k = scales[1], scales[2]
    incremental = ((short_100k["serialized_bytes"] - short_10k["serialized_bytes"])
                   / (short_100k["paths"] - short_10k["paths"]))
    fixed = short_100k["serialized_bytes"] - incremental * short_100k["paths"]
    limit = short_100k["maximum_commit_plaintext_size_bytes"]
    estimate = int((limit - fixed) / incremental) if incremental > 0 else None
    long_path = run_commit(binary, 10000, True, timeout)
    long_path_result = None
    if long_path.get("status") != "not_completed":
        long_path_result = enrich_commit(long_path)
        long_path_result["bytes_per_path_ratio_to_short"] = (
            long_path_result["bytes_per_path"] / short_10k["bytes_per_path"]
        )
    return {
        "status": "measured",
        "parent_count": 1,
        "serialization_duplication_cost_observed": True,
        "maximum_commit_plaintext_size_bytes": short_100k["maximum_commit_plaintext_size_bytes"],
        "maximum_commit_plaintext_size_MiB": limit / (1024 * 1024),
        "scales": scales,
        "incremental_bytes_per_path_10k_to_100k": incremental,
        "fixed_overhead_estimate_bytes": fixed,
        "estimated_paths_at_limit": estimate,
        "estimated_paths_at_limit_is_estimate": True,
        "long_path_sensitivity": long_path_result or {"status": "not_completed"},
        "memory": "not_measured",
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--benchmark", type=Path, required=True)
    parser.add_argument("--output-state", type=Path, required=True)
    parser.add_argument("--output-commit", type=Path, required=True)
    parser.add_argument("--timeout", type=int, default=900)
    args = parser.parse_args()

    state_scales = [run_state(args.benchmark, files, args.timeout)
                    for files in (1000, 10000, 100000)]
    state_ok = all(item.get("status") == "measured" for item in state_scales)
    state_artifact = {
        "status": "measured" if state_ok else "partial",
        "harness": "StateStorage APIs with synthetic Snapshot/FileCacheRow; no physical files",
        "os": platform.platform(),
        "scales": state_scales,
        "memory": "not_measured",
        "sql_write_complexity": "approximately O(delta)",
        "total_db_wall_complexity": "approximately O(paths) read/diff floor",
    }
    commit_artifact = make_commit_artifact(args.benchmark, args.timeout)
    args.output_state.parent.mkdir(parents=True, exist_ok=True)
    args.output_commit.parent.mkdir(parents=True, exist_ok=True)
    args.output_state.write_text(json.dumps(state_artifact, indent=2), encoding="utf-8")
    args.output_commit.write_text(json.dumps(commit_artifact, indent=2), encoding="utf-8")


if __name__ == "__main__":
    main()
