"""Determinism tests for nc-export.py (T1 task 6).

Running the same input with the same --salt-file twice must produce
byte-identical output, both runs to each other and to golden.
"""
import pathlib
import sys
import tempfile
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

from fixture_runner import entra_scenarios, google_scenarios, run_entra_scenario, run_google_scenario


class TestDeterminism(unittest.TestCase):
    def test_google_scenarios_produce_identical_output_across_two_runs(self):
        for scenario_dir in google_scenarios():
            with self.subTest(scenario=scenario_dir.name):
                with tempfile.TemporaryDirectory() as tmp:
                    out1 = pathlib.Path(tmp) / "out1"
                    out2 = pathlib.Path(tmp) / "out2"
                    r1 = run_google_scenario(scenario_dir, out1)
                    r2 = run_google_scenario(scenario_dir, out2)
                    self.assertEqual(r1.returncode, 0, r1.stderr)
                    self.assertEqual(r2.returncode, 0, r2.stderr)

                    bytes1 = (out1 / "discover-export.ndjson").read_bytes()
                    bytes2 = (out2 / "discover-export.ndjson").read_bytes()
                    golden = (scenario_dir / "golden" / "discover-export.ndjson").read_bytes()

                    self.assertEqual(bytes1, bytes2)
                    self.assertEqual(bytes1, golden)

    def test_entra_scenarios_produce_identical_output_across_two_runs(self):
        for scenario_dir in entra_scenarios():
            with self.subTest(scenario=scenario_dir.name):
                with tempfile.TemporaryDirectory() as tmp:
                    out1 = pathlib.Path(tmp) / "out1"
                    out2 = pathlib.Path(tmp) / "out2"
                    r1 = run_entra_scenario(scenario_dir, out1)
                    r2 = run_entra_scenario(scenario_dir, out2)
                    self.assertEqual(r1.returncode, 0, r1.stderr)
                    self.assertEqual(r2.returncode, 0, r2.stderr)

                    bytes1 = (out1 / "discover-export.ndjson").read_bytes()
                    bytes2 = (out2 / "discover-export.ndjson").read_bytes()
                    golden = (scenario_dir / "golden" / "discover-export.ndjson").read_bytes()

                    self.assertEqual(bytes1, bytes2)
                    self.assertEqual(bytes1, golden)


if __name__ == "__main__":
    unittest.main()
