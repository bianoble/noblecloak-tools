"""Golden fixture manifest tests (T1 task 3).

Every fixtures/{google,entra}/<scenario>/ directory must have the right
shape, and every golden output must itself be a valid DEF document.
"""
import json
import pathlib
import sys
import unittest

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
FIXTURES_ROOT = REPO_ROOT / "fixtures"

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

from def_validator import validate_def_file

EXPECTED_VENDORS = ("google", "entra")

# Scenarios required for both vendors.
COMMON_SCENARIOS = {
    "scenario-basic",
    "scenario-duplicate-grants",
    "scenario-unicode-appnames",
    "scenario-empty-grants",
    "scenario-blank-identity-fields",
}

NO_PSEUDONYMIZE_SCENARIO = "scenario-no-pseudonymize"


def _scenario_dirs(vendor: str):
    vendor_root = FIXTURES_ROOT / vendor
    if not vendor_root.is_dir():
        return []
    return sorted(p for p in vendor_root.iterdir() if p.is_dir())


class TestFixtureManifest(unittest.TestCase):
    def test_both_vendor_directories_exist(self):
        for vendor in EXPECTED_VENDORS:
            with self.subTest(vendor=vendor):
                self.assertTrue((FIXTURES_ROOT / vendor).is_dir())

    def test_every_scenario_has_required_shape(self):
        found_any = False
        for vendor in EXPECTED_VENDORS:
            for scenario_dir in _scenario_dirs(vendor):
                found_any = True
                with self.subTest(vendor=vendor, scenario=scenario_dir.name):
                    self.assertTrue((scenario_dir / "input").is_dir())
                    self.assertTrue((scenario_dir / "salt.txt").is_file())
                    self.assertTrue(
                        (scenario_dir / "golden" / "discover-export.ndjson").is_file()
                    )
        self.assertTrue(found_any, "expected at least one fixture scenario to exist")

    def test_common_scenarios_present_for_each_vendor(self):
        for vendor in EXPECTED_VENDORS:
            names = {p.name for p in _scenario_dirs(vendor)}
            for scenario in COMMON_SCENARIOS:
                with self.subTest(vendor=vendor, scenario=scenario):
                    self.assertIn(scenario, names)

    def test_golden_header_vendor_matches_parent_directory(self):
        for vendor in EXPECTED_VENDORS:
            for scenario_dir in _scenario_dirs(vendor):
                golden = scenario_dir / "golden" / "discover-export.ndjson"
                with self.subTest(vendor=vendor, scenario=scenario_dir.name):
                    first_line = golden.read_text(encoding="utf-8").split("\n", 1)[0]
                    header = json.loads(first_line)
                    self.assertEqual(header["vendor"], vendor)

    def test_pseudonymized_flag_matches_scenario_name(self):
        for vendor in EXPECTED_VENDORS:
            for scenario_dir in _scenario_dirs(vendor):
                golden = scenario_dir / "golden" / "discover-export.ndjson"
                first_line = golden.read_text(encoding="utf-8").split("\n", 1)[0]
                header = json.loads(first_line)
                expected = scenario_dir.name != NO_PSEUDONYMIZE_SCENARIO
                with self.subTest(vendor=vendor, scenario=scenario_dir.name):
                    self.assertEqual(header["pseudonymized"], expected)

    def test_every_golden_file_is_a_valid_def_document(self):
        for vendor in EXPECTED_VENDORS:
            for scenario_dir in _scenario_dirs(vendor):
                golden = scenario_dir / "golden" / "discover-export.ndjson"
                with self.subTest(vendor=vendor, scenario=scenario_dir.name):
                    validate_def_file(golden)  # must not raise


if __name__ == "__main__":
    unittest.main()
