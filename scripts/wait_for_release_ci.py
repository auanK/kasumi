"""Gate packaging on completed Actions jobs for the checked-out commit."""

import json
import os
import subprocess
import time


REQUIRED = (".github/workflows/ci-ubuntu.yml", ".github/workflows/ci-windows.yml")
IMAGE = ".github/workflows/ci-image.yml"


def list_items(repository, endpoint, field):
    output = subprocess.check_output(
        ["gh", "api", "--paginate", "--slurp", f"repos/{repository}/{endpoint}"],
        text=True,
    )
    return [item for page in json.loads(output) for item in page[field]]


def check_ci(repository, sha):
    runs = list_items(repository, f"actions/runs?head_sha={sha}&per_page=100", "workflow_runs")
    latest = {}
    for run in runs:
        path = run["path"]
        if path not in (*REQUIRED, IMAGE) or run["head_sha"] != sha:
            continue
        if (run["head_repository"] or {}).get("full_name") != repository:
            continue
        # Branch pushes and manual CI runs test this revision directly.
        # PR checks can instead test a synthetic merge commit.
        if run["event"] not in ("push", "workflow_dispatch", "schedule"):
            continue
        if path not in latest or run["run_number"] > latest[path]["run_number"]:
            latest[path] = run

    pending = [path for path in REQUIRED if path not in latest]
    for path, run in latest.items():
        if run["status"] != "completed":
            pending.append(f'{path} ({run["status"]})')
        elif run["conclusion"] != "success":
            raise SystemExit(f'{path}: {run["conclusion"]} - {run["html_url"]}')
    if pending:
        return pending

    for path, run in latest.items():
        jobs = list_items(repository, f'actions/runs/{run["id"]}/jobs?filter=latest&per_page=100', "jobs")
        if not jobs:
            raise SystemExit(f'{path}: no jobs reported - {run["html_url"]}')
        for job in jobs:
            if job["status"] != "completed" or job["conclusion"] != "success":
                raise SystemExit(f'{path}: {job["name"]} did not pass - {job["html_url"]}')
        print(f'{path}: {len(jobs)} jobs passed - {run["html_url"]}', flush=True)
    return []


if __name__ == "__main__":
    sha = subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip()
    while pending := check_ci(os.environ["GITHUB_REPOSITORY"], sha):
        print(f'Waiting for CI on {sha}: {", ".join(pending)}', flush=True)
        time.sleep(30)
