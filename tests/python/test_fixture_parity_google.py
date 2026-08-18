"""Fixture-parity tests for `nc-export.py google` (T1 task 4).

For every fixtures/google/<scenario>/, running nc-export.py against the
scenario's input (with its salt fixed) must reproduce golden/discover-export.ndjson
byte-for-byte.

There is no golden mapping.csv fixture (fixtures/MANIFEST.md only pins
discover-export.ndjson), so mapping.csv is instead checked algorithmically:
every row's userRef must equal HMAC-SHA256(salt, email)[:16] prefixed with
"user_", and the set of userRefs in mapping.csv must equal the set of
userRefs used in the grant lines.
"""
import csv
import hashlib
import hmac
import json
import pathlib
import sys
import tempfile
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

from fixture_runner import NO_PSEUDONYMIZE_SCENARIOS, google_scenarios, run_google_scenario


def user_ref_for(salt_hex: str, email: str) -> str:
    digest = hmac.new(bytes.fromhex(salt_hex), email.strip().lower().encode("utf-8"), hashlib.sha256).hexdigest()
    return "user_" + digest[:16]


class TestFixtureParityGoogle(unittest.TestCase):
    def test_every_scenario_matches_golden_byte_for_byte(self):
        scenarios = google_scenarios()
        self.assertTrue(scenarios, "expected at least one google fixture scenario")
        for scenario_dir in scenarios:
            with self.subTest(scenario=scenario_dir.name):
                with tempfile.TemporaryDirectory() as tmp:
                    out_dir = pathlib.Path(tmp) / "out"
                    result = run_google_scenario(scenario_dir, out_dir)
                    self.assertEqual(result.returncode, 0, result.stderr)

                    golden = (scenario_dir / "golden" / "discover-export.ndjson").read_bytes()
                    produced = (out_dir / "discover-export.ndjson").read_bytes()
                    self.assertEqual(produced, golden)

    def test_pseudonymized_scenarios_write_correct_mapping_csv(self):
        for scenario_dir in google_scenarios():
            if scenario_dir.name in NO_PSEUDONYMIZE_SCENARIOS:
                continue
            with self.subTest(scenario=scenario_dir.name):
                with tempfile.TemporaryDirectory() as tmp:
                    out_dir = pathlib.Path(tmp) / "out"
                    result = run_google_scenario(scenario_dir, out_dir)
                    self.assertEqual(result.returncode, 0, result.stderr)

                    salt_hex = (scenario_dir / "salt.txt").read_text(encoding="utf-8").strip()
                    with (out_dir / "mapping.csv").open(encoding="utf-8") as fh:
                        mapping_rows = list(csv.DictReader(fh))
                    for row in mapping_rows:
                        self.assertEqual(row["userRef"], user_ref_for(salt_hex, row["email"]))

                    grant_lines = (out_dir / "discover-export.ndjson").read_text(encoding="utf-8").splitlines()[1:]
                    refs_in_grants = {json.loads(line)["userRef"] for line in grant_lines}
                    refs_in_mapping = {row["userRef"] for row in mapping_rows}
                    self.assertEqual(refs_in_mapping, refs_in_grants)

    def test_no_pseudonymize_scenario_writes_no_mapping_or_salt_file(self):
        for scenario_dir in google_scenarios():
            if scenario_dir.name not in NO_PSEUDONYMIZE_SCENARIOS:
                continue
            with self.subTest(scenario=scenario_dir.name):
                with tempfile.TemporaryDirectory() as tmp:
                    out_dir = pathlib.Path(tmp) / "out"
                    result = run_google_scenario(scenario_dir, out_dir)
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertFalse((out_dir / "mapping.csv").exists())
                    self.assertFalse((out_dir / "salt.txt").exists())


if __name__ == "__main__":
    unittest.main()
