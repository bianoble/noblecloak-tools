"""Repo bootstrap layout tests (T1 task 1).

Verifies the top-level directory structure and README exist and that the
README documents the privacy model, a quick start, and links to the public
docs site, per the noblecloak-tools epic.
"""
import pathlib
import unittest

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]


class TestRepoLayout(unittest.TestCase):
    def test_required_directories_exist(self):
        required_dirs = [
            "spec",
            "fixtures",
            "scripts",
            "tests",
            "tests/python",
            "tests/powershell",
            ".github/workflows",
        ]
        for rel in required_dirs:
            with self.subTest(rel=rel):
                path = REPO_ROOT / rel
                self.assertTrue(path.is_dir(), f"expected directory {rel} to exist")

    def test_required_files_exist(self):
        required_files = ["README.md", "LICENSE", ".gitignore"]
        for rel in required_files:
            with self.subTest(rel=rel):
                path = REPO_ROOT / rel
                self.assertTrue(path.is_file(), f"expected file {rel} to exist")

    def test_readme_has_required_sections(self):
        readme = (REPO_ROOT / "README.md").read_text(encoding="utf-8")
        self.assertIn("Privacy model", readme)
        self.assertIn("Quick start", readme)
        self.assertIn("docs.noblecloak.com", readme)
        self.assertIn("GitHub org: bianoble", readme)


if __name__ == "__main__":
    unittest.main()
