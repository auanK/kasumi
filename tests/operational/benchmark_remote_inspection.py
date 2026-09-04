#!/usr/bin/env python3
"""Benchmark cold, warm and incremental remote history inspection."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import statistics
import subprocess
import tempfile
import time


MASTER_KEY = "0123456789abcdef" * 4
TRACE = re.compile(r"^KASUMI_PERF name=(.+) calls=(\d+) total_us=(\d+)$")
COMMIT_COUNT = re.compile(
    r"^(?:Remote commits|Commits remotos) \((\d+)\)$", re.MULTILINE
)


def digest_file(path):
    if not path.is_file():
        return None
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def digest_tree(root):
    digest = hashlib.sha256()
    if not root.exists():
        return digest.hexdigest()
    for path in sorted(item for item in root.rglob("*") if item.is_file()):
        digest.update(path.relative_to(root).as_posix().encode("utf-8"))
        digest.update(bytes.fromhex(digest_file(path)))
    return digest.hexdigest()


def write_profile(root, local, storage):
    app_data = root / "environment" / "kasumi"
    app_data.mkdir(parents=True, exist_ok=True)
    local.mkdir(parents=True, exist_ok=True)
    if isinstance(storage, Path):
        storage.mkdir(parents=True, exist_ok=True)
    (app_data / "config.toml").write_text(
        "[profiles.perf]\n"
        f"local_dir = {json.dumps(str(local))}\n"
        f"remote_dir = {json.dumps(str(storage))}\n"
        "min_history_depth = 5\n"
        "min_history_age_hours = 6\n",
        encoding="utf-8",
    )
    return app_data


def command_environment(root, traced, rclone_config=None):
    environment = os.environ.copy()
    environment["KASUMI_MASTER_KEY"] = MASTER_KEY
    environment.setdefault("KASUMI_LANG", "en")
    if traced:
        environment["KASUMI_PERF_TRACE"] = "1"
    else:
        environment.pop("KASUMI_PERF_TRACE", None)
    if rclone_config:
        environment["RCLONE_CONFIG"] = str(rclone_config)
    if os.name == "nt":
        environment["APPDATA"] = str(root / "environment")
    else:
        environment["XDG_CONFIG_HOME"] = str(root / "environment")
    return environment


def run_command(kasumi, arguments, local, environment, timeout):
    result = subprocess.run(
        [str(kasumi), *arguments],
        cwd=local,
        env=environment,
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )
    if result.returncode != 0:
        raise RuntimeError(
            json.dumps(
                {
                    "command": arguments,
                    "exit_code": result.returncode,
                    "stdout": result.stdout,
                    "stderr": result.stderr,
                },
                indent=2,
            )
        )
    return result


def publish_commits(kasumi, root, local, start, count, timeout, rclone_config):
    environment = command_environment(root, False, rclone_config)
    payload = local / "payload.txt"
    for index in range(start, start + count):
        payload.write_text(f"revision {index}\n", encoding="utf-8")
        run_command(kasumi, ["sync", "perf"], local, environment, timeout)


def rclone_digest(storage, rclone_config, timeout):
    environment = os.environ.copy()
    if rclone_config:
        environment["RCLONE_CONFIG"] = str(rclone_config)
    result = subprocess.run(
        [
            "rclone",
            "lsjson",
            f"{storage.rstrip('/')}/objects",
            "--recursive",
            "--files-only",
            "--hash",
        ],
        env=environment,
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )
    if result.returncode != 0:
        raise RuntimeError(
            "não foi possível autenticar o inventário remoto: " + result.stderr
        )
    items = json.loads(result.stdout)
    inventory = sorted(
        (item["Path"], item["Size"], item.get("Hashes", {}).get("sha256"))
        for item in items
    )
    if any(not item[2] for item in inventory):
        raise RuntimeError("o remote não forneceu SHA-256 para todos os objetos")
    listing = json.dumps(inventory, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(listing).hexdigest()


def prepare_remote(storage, rclone_config, timeout):
    environment = os.environ.copy()
    if rclone_config:
        environment["RCLONE_CONFIG"] = str(rclone_config)
    result = subprocess.run(
        ["rclone", "mkdir", f"{storage.rstrip('/')}/objects"],
        env=environment,
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )
    if result.returncode != 0:
        raise RuntimeError("não foi possível preparar o remote: " + result.stderr)


def copy_seed_to_remote(seed_storage, storage, rclone_config, timeout):
    environment = os.environ.copy()
    if rclone_config:
        environment["RCLONE_CONFIG"] = str(rclone_config)
    result = subprocess.run(
        [
            "rclone",
            "copy",
            str(seed_storage),
            f"{storage.rstrip('/')}",
            "--transfers",
            "1",
            "--checkers",
            "1",
        ],
        env=environment,
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )
    if result.returncode != 0:
        raise RuntimeError("não foi possível copiar o seed: " + result.stderr)


def protected_state(app_data, local, storage, rclone_config, timeout):
    profile = app_data / "profiles" / "perf"
    return {
        "config": digest_file(app_data / "config.toml"),
        "database": digest_file(profile / "db.sqlite"),
        "local": digest_tree(local),
        "remote": (
            digest_tree(storage)
            if isinstance(storage, Path)
            else rclone_digest(storage, rclone_config, timeout)
        ),
    }


def parse_metrics(stderr):
    metrics = {}
    for line in stderr.splitlines():
        match = TRACE.fullmatch(line)
        if match:
            metrics[match.group(1)] = {
                "calls": int(match.group(2)),
                "total_us": int(match.group(3)),
            }
    return metrics


def inspect_phase(
    kasumi,
    root,
    local,
    storage,
    app_data,
    expected_commits,
    expected_gets,
    expected_batches,
    expected_cache_change,
    timeout,
    rclone_config,
):
    cache = app_data / "profiles" / "perf" / "inspection-history-v1.cache"
    before = protected_state(app_data, local, storage, rclone_config, timeout)
    cache_before = digest_file(cache)
    started = time.perf_counter()
    result = run_command(
        kasumi,
        ["remote", "commits", "perf"],
        local,
        command_environment(root, True, rclone_config),
        timeout,
    )
    elapsed = time.perf_counter() - started
    after = protected_state(app_data, local, storage, rclone_config, timeout)
    cache_after = digest_file(cache)
    metrics = parse_metrics(result.stderr)
    reported = COMMIT_COUNT.search(result.stdout)
    commit_gets = metrics.get("rc/get_commit", {"calls": 0})["calls"]
    batch_downloads = metrics.get("rclone batch download", {"calls": 0})["calls"]
    failures = []
    if before != after:
        failures.append("a inspeção alterou configuração, banco, local ou remoto")
    if not reported or int(reported.group(1)) != expected_commits:
        failures.append("a quantidade apresentada de commits está incorreta")
    if commit_gets != expected_gets:
        failures.append(
            f"GETs de commit: esperado {expected_gets}, observado {commit_gets}"
        )
    if batch_downloads != expected_batches:
        failures.append(
            "lotes de commit: "
            f"esperado {expected_batches}, observado {batch_downloads}"
        )
    if (cache_before != cache_after) != expected_cache_change:
        failures.append("a política de atualização do cache não foi preservada")
    if "[Rede]" in result.stdout or "[Rede]" in result.stderr:
        failures.append("a saída contém mensagem [Rede]")
    if failures:
        raise RuntimeError(
            "; ".join(failures)
            + "; métricas="
            + json.dumps(metrics, ensure_ascii=False)
        )
    return {
        "elapsed_seconds": round(elapsed, 6),
        "reported_commits": expected_commits,
        "commit_gets": commit_gets,
        "expected_commit_gets": expected_gets,
        "batch_downloads": batch_downloads,
        "expected_batch_downloads": expected_batches,
        "cache_changed": cache_before != cache_after,
        "protected_state_unchanged": True,
        "metrics": metrics,
    }


def run_scenario(
    kasumi, commits, delta, repetition, timeout, remote, rclone_config
):
    with tempfile.TemporaryDirectory(prefix="kasumi-inspection-benchmark-") as temp:
        root = Path(temp)
        local = root / "local"
        seed_storage = root / "storage"
        app_data = write_profile(root, local, seed_storage)
        publish_commits(kasumi, root, local, 0, commits, timeout, None)
        if remote:
            storage = (
                f"{remote.rstrip('/')}/n{commits}-r{repetition}-{time.time_ns()}"
            )
            prepare_remote(storage, rclone_config, timeout)
            copy_seed_to_remote(seed_storage, storage, rclone_config, timeout)
            write_profile(root, local, storage)
        else:
            storage = seed_storage
        cache = app_data / "profiles" / "perf" / "inspection-history-v1.cache"
        cache.unlink(missing_ok=True)
        native_batch = remote is not None

        cold = inspect_phase(
            kasumi,
            root,
            local,
            storage,
            app_data,
            commits,
            0 if native_batch else commits,
            1 if native_batch else 0,
            True,
            timeout,
            rclone_config,
        )
        warm = inspect_phase(
            kasumi,
            root,
            local,
            storage,
            app_data,
            commits,
            0,
            0,
            False,
            timeout,
            rclone_config,
        )

        publish_commits(kasumi, root, local, commits, delta, timeout, rclone_config)
        total = commits + delta
        incremental = inspect_phase(
            kasumi,
            root,
            local,
            storage,
            app_data,
            total,
            delta,
            0,
            True,
            timeout,
            rclone_config,
        )
        re_warm = inspect_phase(
            kasumi,
            root,
            local,
            storage,
            app_data,
            total,
            0,
            0,
            False,
            timeout,
            rclone_config,
        )

        cache.write_bytes(b"invalid inspection cache")
        corrupted = inspect_phase(
            kasumi,
            root,
            local,
            storage,
            app_data,
            total,
            0 if native_batch else total,
            1 if native_batch else 0,
            True,
            timeout,
            rclone_config,
        )
        return {
            "commits": commits,
            "delta": delta,
            "repetition": repetition,
            "storage": str(storage),
            "status": "pass",
            "phases": {
                "cold": cold,
                "warm": warm,
                "delta": incremental,
                "re_warm": re_warm,
                "corrupted_cache": corrupted,
            },
        }


def summaries(scenarios):
    result = []
    for commits in sorted({scenario["commits"] for scenario in scenarios}):
        selected = [item for item in scenarios if item["commits"] == commits]
        result.append(
            {
                "commits": commits,
                "repetitions": len(selected),
                "median_seconds": {
                    phase: round(
                        statistics.median(
                            item["phases"][phase]["elapsed_seconds"]
                            for item in selected
                        ),
                        6,
                    )
                    for phase in selected[0]["phases"]
                },
            }
        )
    return result


def parse_scales(value):
    scales = sorted({int(item) for item in value.split(",")})
    if not scales or scales[0] < 1:
        raise argparse.ArgumentTypeError("commits deve conter inteiros positivos")
    return scales


def make_artifact(status, kasumi, request, scenarios):
    return {
        "status": status,
        "kasumi": str(kasumi),
        "request": request,
        "policy": {
            "cold_commit_reads": "1 lote no rclone; N GETs no transporte local",
            "warm_commit_gets": 0,
            "delta_commit_gets": "delta",
            "re_warm_commit_gets": 0,
            "corrupted_cache_commit_reads": (
                "1 lote no rclone; N + delta GETs no transporte local"
            ),
            "timings_are_release_comparison_data_not_absolute_gates": True,
        },
        "summaries": summaries(scenarios),
        "scenarios": scenarios,
    }


def save_artifact(path, artifact):
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(artifact, indent=2), encoding="utf-8")
    temporary.replace(path)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--kasumi", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument(
        "--commits", type=parse_scales, default=parse_scales("8,64,256")
    )
    parser.add_argument("--delta", type=int, default=3)
    parser.add_argument("--repetitions", type=int, default=1)
    parser.add_argument("--timeout", type=int, default=600)
    parser.add_argument("--remote")
    parser.add_argument("--rclone-config", type=Path)
    arguments = parser.parse_args()
    if arguments.delta < 1 or arguments.repetitions < 1:
        parser.error("delta e repetições devem ser positivos")

    kasumi = arguments.kasumi.resolve()
    rclone_config = (
        arguments.rclone_config.resolve() if arguments.rclone_config else None
    )
    request = {
        "commits": arguments.commits,
        "delta": arguments.delta,
        "repetitions": arguments.repetitions,
        "remote": arguments.remote,
    }
    scenarios = []
    if arguments.output.exists():
        previous = json.loads(arguments.output.read_text(encoding="utf-8"))
        if previous.get("request") != request:
            parser.error("o checkpoint existente pertence a outra execução")
        scenarios = previous.get("scenarios", [])
    completed = {
        (scenario["commits"], scenario["repetition"]) for scenario in scenarios
    }
    total = len(arguments.commits) * arguments.repetitions
    for commits in arguments.commits:
        for repetition in range(1, arguments.repetitions + 1):
            if (commits, repetition) in completed:
                continue
            print(
                f"iniciando commits={commits} repetição={repetition} "
                f"({len(scenarios) + 1}/{total})",
                flush=True,
            )
            scenarios.append(
                run_scenario(
                    kasumi,
                    commits,
                    arguments.delta,
                    repetition,
                    arguments.timeout,
                    arguments.remote,
                    rclone_config,
                )
            )
            save_artifact(
                arguments.output,
                make_artifact("running", kasumi, request, scenarios),
            )
            print(
                f"concluído commits={commits} repetição={repetition}",
                flush=True,
            )
    artifact = make_artifact("pass", kasumi, request, scenarios)
    save_artifact(arguments.output, artifact)
    print(
        json.dumps(
            {"status": artifact["status"], "summaries": artifact["summaries"]},
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
