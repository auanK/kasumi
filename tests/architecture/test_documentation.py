"""Keep generated run evidence out of permanent references and source fixtures."""

import json
import os
from pathlib import Path
import re
import sys
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[2]
REPORT_HEADING = re.compile(
    r"^#{1,6}\s+(?:Baseline audit\b.*|Validation log|"
    r"Phase \d+ measurements(?:\s+\([^)]*\))?|"
    r"(?:Implementation|Execution|Benchmark|Performance) (?:report|results|transcript)s?)\s*$",
    re.IGNORECASE | re.MULTILINE,
)


def find_documentation_entries(root: Path):
    found = []
    for rel_dir in ("docs", "tests/operational"):
        target_dir = root / rel_dir
        if not target_dir.is_dir():
            continue
        for path in sorted(target_dir.rglob("*")):
            if path.is_file():
                found.append(path.relative_to(root).as_posix())
    return found, []


def find_documentation_files(root: Path):
    files, _ = find_documentation_entries(root)
    return files


def artifacts(path, text):
    if path.startswith("docs/"):
        if Path(path).suffix in {".log", ".csv", ".jsonl", ".diff", ".bundle"}:
            return ["generated evidence file"]
        prose = re.sub(r"(?ms)^```[^\n]*\n.*?^```\s*$", "", text)
        if REPORT_HEADING.search(prose):
            return ["run report embedded in permanent documentation"]
    if Path(path).suffix == ".json":
        data = json.loads(text)
        if isinstance(data, dict) and "historical_artifacts_commit" in data:
            return ["historical benchmark results"]
    return []


class DocumentationTest(unittest.TestCase):
    def test_tracked_references_contain_no_run_artifacts(self):
        files, violations = find_documentation_entries(ROOT)
        for name in files:
            if Path(name).suffix in {".md", ".json", ".log", ".csv", ".jsonl", ".diff", ".bundle"}:
                for reason in artifacts(name, (ROOT / name).read_text(encoding="utf-8")):
                    violations.append(f"{name}: {reason}")
        self.assertEqual(violations, [])

    def test_discovery_runs_without_git_repository(self):
        import tempfile
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_root = Path(temp_dir)
            (temp_root / "docs").mkdir()
            (temp_root / "docs" / "reference.md").write_text("# Reference\nPermanent doc.\n", encoding="utf-8")
            (temp_root / "tests" / "operational").mkdir(parents=True)
            (temp_root / "tests" / "operational" / "schema.json").write_text('{"type": "object"}\n', encoding="utf-8")

            files, violations = find_documentation_entries(temp_root)
            self.assertEqual(files, ["docs/reference.md", "tests/operational/schema.json"])
            self.assertEqual(violations, [])

    def test_symlink_paths_are_rejected_without_following_or_reading_target(self):
        import tempfile

        with tempfile.TemporaryDirectory() as temp_dir:
            temp_root = Path(temp_dir)
            outside_dir = temp_root / "outside"
            outside_dir.mkdir()
            outside_file = outside_dir / "secret.log"
            outside_file.write_text("outside contents\n", encoding="utf-8")

            docs_dir = temp_root / "docs"
            docs_dir.mkdir()
            (docs_dir / "legit.md").write_text("# Legitimate doc\n", encoding="utf-8")

            file_link = docs_dir / "external_link.md"
            dir_link = docs_dir / "external_dir"

            symlinks_created = False
            try:
                os.symlink(outside_file, file_link)
                os.symlink(outside_dir, dir_link, target_is_directory=True)
                symlinks_created = True
            except OSError as exc:
                print(f"[NOTE] Real symlink creation unavailable on host OS ({exc}); testing deterministic rejection.", file=sys.stderr)

            if symlinks_created:
                files, violations = find_documentation_entries(temp_root)
                self.assertNotIn("docs/external_link.md", files)
                self.assertNotIn("docs/external_dir/secret.log", files)
                self.assertTrue(any("docs/external_link.md" in v and "symbolic link" in v for v in violations))
                self.assertTrue(any("docs/external_dir" in v and "symbolic link" in v for v in violations))
            else:
                fake_file = docs_dir / "mock_link.md"
                fake_file.write_text("dummy", encoding="utf-8")
                fake_dir = docs_dir / "mock_dir"
                fake_dir.mkdir()
                (fake_dir / "inside.md").write_text("dummy", encoding="utf-8")

                original_islink = os.path.islink
                def mock_islink(path):
                    if Path(path).name in ("mock_link.md", "mock_dir"):
                        return True
                    return original_islink(path)

                with patch("os.path.islink", side_effect=mock_islink):
                    files, violations = find_documentation_entries(temp_root)
                    self.assertNotIn("docs/mock_link.md", files)
                    self.assertNotIn("docs/mock_dir/inside.md", files)
                    self.assertTrue(any("docs/mock_link.md" in v and "symbolic link" in v for v in violations))
                    self.assertTrue(any("docs/mock_dir" in v and "symbolic link" in v for v in violations))

    def test_symlink_at_documentation_root_is_rejected_without_traversal(self):
        import tempfile
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_root = Path(temp_dir)
            outside_docs = temp_root / "outside_docs"
            outside_docs.mkdir()
            (outside_docs / "external.md").write_text("# External\n", encoding="utf-8")

            docs_path = temp_root / "docs"
            docs_path.mkdir()

            original_islink = os.path.islink
            def mock_islink(path):
                if Path(path) == docs_path:
                    return True
                return original_islink(path)

            with patch("os.path.islink", side_effect=mock_islink):
                files, violations = find_documentation_entries(temp_root)
                self.assertEqual(files, [])
                self.assertTrue(any("docs" in v and ("symbolic link" in v or "redirection" in v) for v in violations))

    def test_junction_paths_are_rejected_without_traversal(self):
        import tempfile
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_root = Path(temp_dir)
            outside_dir = temp_root / "outside"
            outside_dir.mkdir()
            (outside_dir / "secret.log").write_text("secret\n", encoding="utf-8")

            docs_dir = temp_root / "docs"
            docs_dir.mkdir()
            (docs_dir / "legit.md").write_text("# Doc\n", encoding="utf-8")

            junction_target = docs_dir / "external_junction"
            junction_created = False

            if sys.platform == "win32":
                try:
                    import _winapi
                    _winapi.CreateJunction(str(outside_dir), str(junction_target))
                    junction_created = True
                except (OSError, ImportError, AttributeError) as exc:
                    print(f"[NOTE] Native junction creation unavailable ({exc}); using simulated junction.", file=sys.stderr)

            if junction_created:
                files, violations = find_documentation_entries(temp_root)
                self.assertNotIn("docs/external_junction/secret.log", files)
                self.assertTrue(any("docs/external_junction" in v and ("junction" in v or "redirection" in v or "symbolic link" in v) for v in violations))
            else:
                fake_dir = docs_dir / "mock_junction"
                fake_dir.mkdir()
                (fake_dir / "inside.md").write_text("dummy", encoding="utf-8")

                original_isjunction = getattr(os.path, "isjunction", None)
                def mock_isjunction(path):
                    if Path(path).name == "mock_junction":
                        return True
                    if original_isjunction:
                        return original_isjunction(path)
                    return False

                with patch("os.path.isjunction", side_effect=mock_isjunction):
                    files, violations = find_documentation_entries(temp_root)
                    self.assertNotIn("docs/mock_junction/inside.md", files)
                    self.assertTrue(any("docs/mock_junction" in v and ("junction" in v or "redirection" in v or "symbolic link" in v) for v in violations))

    def test_unreadable_directory_fails_explicitly(self):
        import tempfile
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_root = Path(temp_dir)
            docs_dir = temp_root / "docs"
            docs_dir.mkdir()
            (docs_dir / "legit.md").write_text("# Doc\n", encoding="utf-8")
            forbidden = docs_dir / "forbidden"
            forbidden.mkdir()

            original_scandir = os.scandir
            def mock_scandir(path="."):
                if Path(path).name == "forbidden":
                    raise PermissionError("Access denied")
                return original_scandir(path)

            with patch("os.scandir", side_effect=mock_scandir):
                files, violations = find_documentation_entries(temp_root)
                self.assertTrue(
                    any("docs/forbidden" in v and ("cannot read" in v or "permission" in v or "access" in v) for v in violations),
                    f"Expected explicit violation for inaccessible directory, got: {violations}",
                )

    def test_legitimate_technical_documentation_is_not_rejected(self):
        headings = [
            "# Benchmark harness\n## Validation log\n| Metric | Meaning |\n",
            "# Implementation details\n### Phase 4 measurements (comparison)\n",
            "# Performance report and status\n",
            "## Baseline audit\nSome technical baseline description.\n",
        ]
        for text in headings:
            with self.subTest(text=text.splitlines()[0]):
                self.assertEqual(artifacts("docs/architecture/example.md", text), [])

    def test_objective_forbidden_artifacts_are_rejected(self):
        for ext in [".log", ".csv", ".jsonl", ".diff", ".bundle"]:
            with self.subTest(ext=ext):
                self.assertEqual(
                    artifacts(f"docs/output{ext}", "content\n"),
                    ["generated evidence file"],
                )
        self.assertEqual(
            artifacts("tests/operational/example.json", '{"historical_artifacts_commit": "example"}'),
            ["historical benchmark results"],
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
