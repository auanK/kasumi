#!/usr/bin/env python3
"""Preparation checkpoint regression using the real CLI and rclone local backend.

Runs the existing integrity-checked E2E campaign at N=100 and N=200 before
asserting either performance property. Artifacts are preserved on RED and GREEN.
"""

import argparse
import json
from pathlib import Path
import subprocess
import sys
import unittest


class JournalPreparationE2E(unittest.TestCase):
    samples = []

    def test_checkpoints_are_bounded_by_transaction_barriers(self):
        for operation in ("upload", "download", "partial_upload", "partial_download"):
            rows = [row for row in self.samples if row["operation"] == operation]
            observed = [row["trace"]["journal preparation durable saves"]["calls"]
                        for row in rows]
            with self.subTest(operation=operation):
                self.assertEqual(observed, [2, 2],
                                 f"{operation}: operations={[r['operations'] for r in rows]}, "
                                 f"preparation saves={observed}; allowed=2 (Started + FilesStaged)")

    def test_preparation_write_growth_is_linear(self):
        for operation in ("upload", "download"):
            rows = sorted((row for row in self.samples if row["operation"] == operation),
                          key=lambda row: row["operations"])
            written = [row["trace"]["journal preparation written bytes"]["calls"]
                       for row in rows]
            growth = written[1] / written[0]
            operation_growth = rows[1]["operations"] / rows[0]["operations"]
            with self.subTest(operation=operation):
                # Allow fixed record overhead and modest encoding differences,
                # but reject repeated full-plan preparation writes (~N squared).
                self.assertLessEqual(growth, operation_growth * 1.25,
                                     f"{operation}: preparation bytes={written}, "
                                     f"growth={growth:.3f}; allowed<={operation_growth * 1.25:.3f}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", required=True, type=Path)
    parser.add_argument("--rclone-config", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--rclone", required=True)
    args = parser.parse_args()
    command = [sys.executable, str(Path(__file__).with_name("benchmark_journal_e2e.py")),
               "--binary", str(args.binary), "--rclone-config", str(args.rclone_config),
               "--rclone", args.rclone, "--output", str(args.output),
               "--environment", "local", "--files", "100", "200", "--trials", "1"]
    process = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                             text=True, encoding="utf-8")
    print(process.stdout, end="", flush=True)
    print(process.stderr, end="", file=sys.stderr, flush=True)
    campaign_line = next((line for line in process.stdout.splitlines()
                          if line.startswith("campaign=")), None)
    if campaign_line is None:
        raise RuntimeError("campaign did not start; not a performance RED")
    campaign = Path(campaign_line.split("=", 1)[1])
    metadata = json.loads((campaign / "campaign.json").read_text(encoding="utf-8"))
    rows = [json.loads(line) for line in (campaign / "measurements.jsonl").read_text(
        encoding="utf-8").splitlines()]
    if process.returncode or metadata["failures"] or len(rows) != 10 or not all(r["valid"] for r in rows):
        raise RuntimeError("campaign/environment/integrity failure; not a performance RED")
    JournalPreparationE2E.samples = rows
    result = unittest.TextTestRunner(verbosity=2).run(
        unittest.defaultTestLoader.loadTestsFromTestCase(JournalPreparationE2E))
    (campaign / "preparation-test-result.json").write_text(json.dumps({
        "passed": result.wasSuccessful(), "tests": result.testsRun,
        "failures": [message for _, message in result.failures],
        "command": command,
    }, indent=2) + "\n", encoding="utf-8")
    raise SystemExit(0 if result.wasSuccessful() else 1)


if __name__ == "__main__":
    main()
