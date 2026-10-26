#!/usr/bin/env python3
"""Collect GC measurements from fresh fixtures; retain every run and failure."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import statistics
import subprocess
import time


TRACE = re.compile(r"KASUMI_PERF name=(.+) calls=([0-9]+) total_us=([0-9]+)")
TIMES = ("fixture_us", "gc_wall_us", "fsck_us", "cleanup_us")
METRICS = {
    **{name: "total_us" for name in (
        "gc.total_us", "gc.preparing_us", "gc.analyzing_us", "gc.applying_us",
        "gc.finalizing_us", "gc.analysis_list_us", "gc.first_observation_us",
        "gc.content_classification_us", "gc.plan_build_us", "gc.plan_validation_us",
        "gc.barrier_acquisition_us", "gc.barrier_ownership_check_us",
        "gc.pre_apply_ownership_us", "gc.barrier_cleanup_us", "gc.remove_us")},
    **{name: "calls" for name in (
        "gc.physical_object_count", "gc.physical_content_count",
        "gc.protected_content_count", "gc.protected_object_count",
        "gc.candidate_content_count", "gc.candidate_variant_count",
        "gc.analysis_get_calls", "gc.analysis_list_calls", "gc.analysis_presence_calls",
        "gc.content_get_calls", "gc.apply_get_calls", "gc.apply_list_calls",
        "gc.apply_presence_calls", "gc.candidate_remove_attempts",
        "gc.candidate_remove_acknowledged", "gc.confirmed_removed",
        "gc.candidate_remove_errors", "gc.barrier_cleanup_errors", "gc.errors",
        "gc.history_reconstructions", "gc.barrier_ownership_verifications",
        "gc.barrier_physical_hash_attempts", "gc.barrier_get_fallbacks",
        "transport get", "transport list", "transport list prefix", "transport presence",
        "transport remove", "transport put", "rc.http_requests_attempted",
        "rc.http_requests_completed", "rc.http_requests_failed",
        "rc.http_requests_by_endpoint.operations/deletefile",
        "rc.http_requests_by_endpoint.operations/copyfile",
        "rc.http_requests_by_endpoint.operations/hashsumfile",
        "rc.http_requests_by_endpoint.operations/list",
        "rc.http_requests_by_endpoint.operations/stat", "RC idempotent read retries")},
}


def metric(result, name, field="calls"):
    return result.get("metrics", {}).get(name, {}).get(field)


def parse_result(stdout, stderr, returncode):
    result = {"status": "partial", "returncode": returncode, "measurement": None,
              "metrics": {}, "errors": []}
    outcomes = []
    for line in stderr.splitlines():
        match = TRACE.fullmatch(line)
        if match:
            name, calls, duration = match.groups()
            if name in result["metrics"]:
                result["errors"].append("duplicate trace metric")
            else:
                result["metrics"][name] = {"calls": int(calls), "total_us": int(duration)}
        elif line.startswith("KASUMI_PERF outcome="):
            outcomes.append(line.removeprefix("KASUMI_PERF outcome="))
        elif line.startswith("KASUMI_PERF "):
            result["errors"].append("invalid or truncated trace line")
    for line in stdout.splitlines():
        if line.startswith("GC_BENCHMARK "):
            try:
                value = json.loads(line.removeprefix("GC_BENCHMARK "))
                if not isinstance(value, dict) or result["measurement"] is not None:
                    raise ValueError("invalid or duplicate summary")
                result["measurement"] = value
            except (ValueError, TypeError):
                result["errors"].append("invalid or truncated summary")
    measurement = result["measurement"]
    if measurement is None:
        result["errors"].append("summary unavailable")
    else:
        for name in (*TIMES, "requested_candidates", "confirmed_removed"):
            value = measurement.get(name)
            if type(value) is not int or value < 0:
                result["errors"].append(f"{name} unavailable or invalid")
        if (measurement.get("schema") != 1 or measurement.get("status") != "success"
                or measurement.get("cleanup_confirmed") is not True
                or measurement.get("fsck_passed") is not True
                or measurement.get("confirmed_removed") != measurement.get("requested_candidates")):
            result["errors"].append("incomplete or failed fixture, GC, FSCK or cleanup")
        acknowledged = metric(result, "gc.candidate_remove_acknowledged")
        if acknowledged is not None and acknowledged != measurement.get("confirmed_removed"):
            result["errors"].append("acknowledgement counter disagrees with result")
    if outcomes != ["success"] or metric(result, "gc.total_us", "total_us") is None:
        result["errors"].append("complete successful GC trace unavailable")
    if returncode != 0 or (measurement and measurement.get("status") == "failed"):
        result["status"] = "failed"
    elif not result["errors"]:
        result["status"] = "success"
    acknowledged = metric(result, "gc.candidate_remove_acknowledged")
    duration = metric(result, "gc.applying_us", "total_us")
    result["delete_throughput_per_second"] = (
        acknowledged * 1_000_000 / duration
        if acknowledged is not None and duration else None)
    return result


def statistics_for(values):
    values = [value for value in values if value is not None]
    if not values:
        return None
    return {"min": min(values), "median": statistics.median(values),
            "max": max(values), "samples": len(values)}


def validate_remote_parent(value):
    remote, separator, directory = value.partition(":")
    parts = directory.split("/")
    if (not separator or len(remote) < 2 or re.search(r"[\\/\s<>]", remote)
            or any(not part or part in (".", "..") or part.casefold() == "programming"
                   or part != part.strip() for part in parts)
            or any(ord(c) < 32 or ord(c) == 127 or c in "\\:<>" for c in directory)):
        raise ValueError("remote parent must be a concrete subdirectory outside Programming")
    return value


def summarize(runs):
    scenarios = []
    for count in sorted({run["requested_candidates"] for run in runs}):
        selected = [run for run in runs if run["requested_candidates"] == count]
        successful = [run for run in selected if run["status"] == "success"]
        fields = {name: statistics_for([run["measurement"].get(name) for run in successful])
                  for name in (*TIMES, "peak_rss_before_gc_kib", "peak_rss_after_gc_kib")}
        fields.update({name: statistics_for([metric(run, name, field) for run in successful])
                       for name, field in METRICS.items()})
        fields["delete_throughput_per_second"] = statistics_for(
            [run["delete_throughput_per_second"] for run in successful])
        scenarios.append({"candidates": count, "successful_samples": len(successful),
                          "failed_or_partial_samples": len(selected) - len(successful),
                          "measurements": fields})
    return scenarios


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True, help="new local directory")
    parser.add_argument("--candidates", type=int, nargs="+", default=[0, 100, 1000, 5000, 20000])
    parser.add_argument("--samples", type=int, default=2)
    parser.add_argument("--timeout", type=int, default=3600)
    parser.add_argument("--remote-parent", type=validate_remote_parent)
    parser.add_argument("--confirm-disposable-parent", action="store_true")
    parser.add_argument("--confirm-large-remote", action="store_true")
    args = parser.parse_args()
    if (args.samples < 1 or args.timeout < 1 or not args.binary.is_file()
            or any(count < 0 or count > 20000 for count in args.candidates)):
        parser.error("binary, samples, timeout or candidate count is invalid")
    if args.remote_parent and not args.confirm_disposable_parent:
        parser.error("remote writes require --confirm-disposable-parent")
    if args.remote_parent and max(args.candidates) >= 20000 and not args.confirm_large_remote:
        parser.error("20000 remote objects require --confirm-large-remote after cost review")
    args.output = args.output.resolve()
    args.output.mkdir(parents=False, exist_ok=False)
    binary = args.binary.resolve()
    report = {"schema": 1, "binary": str(binary),
              "binary_sha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
              "backend": "rclone" if args.remote_parent else "local",
              "remote_parent": args.remote_parent, "backend_retries": None, "runs": []}
    environment = os.environ.copy()
    environment.pop("KASUMI_PERF_TRACE", None)
    for count in args.candidates:
        for sample in range(1, args.samples + 1):
            workspace = args.output / f"n{count}-sample{sample}"
            command = [str(binary), "--workspace", str(workspace), "--candidates", str(count)]
            if args.remote_parent:
                command += ["--remote-parent", args.remote_parent, "--confirm-disposable-parent"]
                if args.confirm_large_remote:
                    command.append("--confirm-large-remote")
            started = time.perf_counter()
            stdout_path = workspace.with_suffix(".stdout.log")
            stderr_path = workspace.with_suffix(".stderr.log")
            with stdout_path.open("wb") as stdout_file, stderr_path.open("wb") as stderr_file:
                try:
                    completed = subprocess.run(command, stdout=stdout_file, stderr=stderr_file,
                                               env=environment, timeout=args.timeout, check=False)
                    returncode = completed.returncode
                except subprocess.TimeoutExpired:
                    returncode = None
            wall_us = round((time.perf_counter() - started) * 1_000_000)
            stdout = stdout_path.read_text(encoding="utf-8", errors="replace")
            stderr = stderr_path.read_text(encoding="utf-8", errors="replace")
            result = parse_result(stdout, stderr, returncode)
            result.update(requested_candidates=count, sample=sample, process_wall_us=wall_us,
                          workspace=str(workspace))
            report["runs"].append(result)
            report["scenarios"] = summarize(report["runs"])
            (args.output / "results.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
            print(f'N={count} sample={sample} status={result["status"]} '
                  f'gc_wall_us={(result["measurement"] or {}).get("gc_wall_us")}', flush=True)
            if result["status"] != "success":
                print("Campaign stopped; workspace, key and namespace preserved. No cleanup or retry.", flush=True)
                return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
