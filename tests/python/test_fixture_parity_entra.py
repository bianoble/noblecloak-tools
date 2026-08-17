"""Fixture-parity tests for `nc-export.py entra` file mode (T1 task 5)."""
import csv
import hashlib
import hmac
import json
import pathlib
import sys
import tempfile
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

from fixture_runner import NO_PSEUDONYMIZE_SCENARIOS, entra_scenarios, run_entra_scenario


def user_ref_for(salt_hex: str, email: str) -> str:
    digest = hmac.new(bytes.fromhex(salt_hex), email.strip().lower().encode("utf-8"), hashlib.sha256).hexdigest()
    return "user_" + digest[:16]


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

    def test_pseudonymized_scenarios_write_correct_mapping_csv(self):
        # Mirrors test_fixture_parity_google.py's mapping.csv check (T1 gap
        # from the coverage review): entra-side end-to-end mapping.csv
        # correctness, including that an "AllPrincipals" grant (userRef
        # null) contributes no row.
        for scenario_dir in entra_scenarios():
            if scenario_dir.name in NO_PSEUDONYMIZE_SCENARIOS:
                continue
            with self.subTest(scenario=scenario_dir.name):
                with tempfile.TemporaryDirectory() as tmp:
                    out_dir = pathlib.Path(tmp) / "out"
                    result = run_entra_scenario(scenario_dir, out_dir)
                    self.assertEqual(result.returncode, 0, result.stderr)

                    salt_hex = (scenario_dir / "salt.txt").read_text(encoding="utf-8").strip()
                    with (out_dir / "mapping.csv").open(encoding="utf-8") as fh:
                        mapping_rows = list(csv.DictReader(fh))
                    for row in mapping_rows:
                        self.assertEqual(row["userRef"], user_ref_for(salt_hex, row["email"]))

                    grant_lines = (out_dir / "discover-export.ndjson").read_text(encoding="utf-8").splitlines()[1:]
                    grants = [json.loads(line) for line in grant_lines]
                    refs_in_grants = {g["userRef"] for g in grants if g["userRef"] is not None}
                    refs_in_mapping = {row["userRef"] for row in mapping_rows}
                    self.assertEqual(refs_in_mapping, refs_in_grants)

                    # AllPrincipals grants (userRef null) must never appear
                    # in mapping.csv -- there is no user to map.
                    self.assertNotIn("", refs_in_mapping)
                    self.assertNotIn(None, {row.get("userRef") for row in mapping_rows})


if __name__ == "__main__":
    unittest.main()
