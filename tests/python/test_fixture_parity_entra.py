"""Fixture-parity tests for `nc-export.py entra` file mode (T1 task 5)."""
import pathlib
import sys
import tempfile
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

from fixture_runner import entra_scenarios, run_entra_scenario


class TestFixtureParityEntra(unittest.TestCase):
    def test_every_scenario_matches_golden_byte_for_byte(self):
        scenarios = entra_scenarios()
        self.assertTrue(scenarios, "expected at least one entra fixture scenario")
        for scenario_dir in scenarios:
            with self.subTest(scenario=scenario_dir.name):
                with tempfile.TemporaryDirectory() as tmp:
                    out_dir = pathlib.Path(tmp) / "out"
                    result = run_entra_scenario(scenario_dir, out_dir)
                    self.assertEqual(result.returncode, 0, result.stderr)

                    golden = (scenario_dir / "golden" / "discover-export.ndjson").read_bytes()
                    produced = (out_dir / "discover-export.ndjson").read_bytes()
                    self.assertEqual(produced, golden)


if __name__ == "__main__":
    unittest.main()
