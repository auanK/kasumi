"""Contracts for the GC benchmark collector; no storage access."""

import importlib.util
import json
from pathlib import Path
import unittest


SCRIPT = Path(__file__).resolve().parents[2] / "operational" / "benchmark_gc.py"


def collector():
    spec = importlib.util.spec_from_file_location("benchmark_gc", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def summary(**overrides):
    value = {"schema": 1, "backend": "local", "requested_candidates": 3,
             "status": "success", "fixture_us": 9000, "gc_wall_us": 150,
             "fsck_us": 20, "cleanup_us": 8000, "cleanup_confirmed": True,
             "fsck_passed": True, "confirmed_removed": 3}
    value.update(overrides)
    return "GC_BENCHMARK " + json.dumps(value) + "\n"


TRACE = ("KASUMI_PERF name=gc.total_us calls=1 total_us=100\n"
         "KASUMI_PERF name=gc.remove_us calls=3 total_us=50\n"
         "KASUMI_PERF name=gc.candidate_remove_acknowledged calls=3 total_us=0\n"
         "KASUMI_PERF outcome=success\n")


class GcBenchmarkCollectorTest(unittest.TestCase):
    def test_valid_metrics_and_fixture_gc_cleanup_are_separate(self):
        module = collector()
        result = module.parse_result(summary(), TRACE, 0)
        self.assertEqual(result["status"], "success")
        self.assertEqual(module.metric(result, "gc.total_us", "total_us"), 100)
        self.assertEqual(result["measurement"]["fixture_us"], 9000)
        self.assertEqual(result["measurement"]["gc_wall_us"], 150)
        self.assertEqual(result["measurement"]["cleanup_us"], 8000)

    def test_missing_metric_is_unavailable_not_zero(self):
        module = collector()
        result = module.parse_result(summary(), TRACE, 0)
        self.assertIsNone(module.metric(result, "gc.nonexistent"))
        self.assertEqual(result["status"], "success")

    def test_truncated_trace_preserves_valid_partial_metrics(self):
        module = collector()
        result = module.parse_result(summary(), TRACE.split("KASUMI_PERF outcome")[0]
                                     + "KASUMI_PERF name=gc.plan_build_us calls=", 0)
        self.assertEqual(result["status"], "partial")
        self.assertEqual(module.metric(result, "gc.total_us", "total_us"), 100)
        self.assertIsNone(module.metric(result, "gc.plan_build_us"))

    def test_failed_process_cannot_be_reported_as_success(self):
        module = collector()
        result = module.parse_result(summary(), TRACE, 7)
        self.assertEqual(result["status"], "failed")
        self.assertEqual(result["returncode"], 7)
        self.assertEqual(module.metric(result, "gc.remove_us", "calls"), 3)

    def test_invalid_numbers_are_not_coerced_to_zero(self):
        for value in ("-1", "NaN", "1.5", "invalid"):
            with self.subTest(value=value):
                module = collector()
                invalid = TRACE.replace("total_us=50", "total_us=" + value)
                result = module.parse_result(summary(), invalid, 0)
                self.assertNotEqual(result["status"], "success")
                self.assertIsNone(module.metric(result, "gc.remove_us"))

    def test_missing_summary_missing_outcome_and_invalid_timing_are_incomplete(self):
        for stdout, stderr in (("", TRACE), (summary(), ""),
                               (summary(fixture_us=-1), TRACE),
                               (summary(gc_wall_us=True), TRACE),
                               (summary(cleanup_us=None), TRACE),
                               (summary(cleanup_confirmed=False), TRACE),
                               (summary(confirmed_removed=2), TRACE)):
            with self.subTest(stdout=stdout, stderr=stderr):
                self.assertNotEqual(collector().parse_result(stdout, stderr, 0)["status"], "success")

    def test_partial_failure_keeps_diagnostic_and_acknowledgements(self):
        module = collector()
        failed_trace = TRACE.replace("outcome=success", "outcome=failure")
        stdout = summary(status="failed", confirmed_removed=2, cleanup_us=None,
                         cleanup_confirmed=False, first_failed_identifier="candidate-3",
                         mutation_state=2, native_code=10060)
        result = module.parse_result(stdout, failed_trace, 1)
        self.assertEqual(result["status"], "failed")
        self.assertEqual(result["measurement"]["confirmed_removed"], 2)
        self.assertEqual(result["measurement"]["first_failed_identifier"], "candidate-3")
        self.assertEqual(result["measurement"]["native_code"], 10060)

    def test_summary_statistics_ignore_unavailable_values(self):
        self.assertEqual(collector().statistics_for([None, 2, 6]),
                         {"min": 2, "median": 4.0, "max": 6, "samples": 2})
        self.assertIsNone(collector().statistics_for([None]))

    def test_remote_requires_concrete_safe_parent(self):
        module = collector()
        self.assertEqual(module.validate_remote_parent("kasumi:kasumi-benchmarks-gc-v090"),
                         "kasumi:kasumi-benchmarks-gc-v090")
        for value in ("kasumi:", "kasumi:/", "kasumi:<insira_aqui>",
                      "kasumi:Programming", "kasumi:Programming/subdir",
                      "kasumi:test/../Programming", "kasumi:test\\vault", "C:/vault"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                module.validate_remote_parent(value)


if __name__ == "__main__":
    unittest.main()
