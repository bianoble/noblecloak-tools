"""Cross-language byte-identical parity gate (T1 task 9).

The epic's success criterion is that nc-export.py entra and
nc-export-entra.ps1 produce byte-identical DEF output from the same
input and salt -- this is what "deliberate duplication enforced by a
parity gate" means literally. Each script is independently checked
against golden/ elsewhere (tests/python/test_fixture_parity_entra.py,
tests/powershell/NcExportEntra.Tests.ps1); this test additionally checks
the two implementations against *each other*, which is a strictly
stronger guarantee than each matching golden separately.
"""
import pathlib
import shutil
import subprocess
import sys
import tempfile
import unittest

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
NC_EXPORT = REPO_ROOT / "scripts" / "nc-export.py"
NC_EXPORT_ENTRA_PS1 = REPO_ROOT / "scripts" / "nc-export-entra.ps1"
FIXTURES_ROOT = REPO_ROOT / "fixtures" / "entra"
GOLDEN_GENERATED_AT = "2026-08-17T00:00:00Z"

SCENARIOS = ["scenario-basic", "scenario-duplicate-grants", "scenario-unicode-appnames", "scenario-no-firstseen"]

PWSH = shutil.which("pwsh")


def run_python(scenario_dir: pathlib.Path, out_dir: pathlib.Path) -> subprocess.CompletedProcess:
    input_dir = scenario_dir / "input"
    args = [
        sys.executable, str(NC_EXPORT), "entra",
        "--users-json", str(input_dir / "users.json"),
        "--service-principals-json", str(input_dir / "servicePrincipals.json"),
        "--grants-json", str(input_dir / "oauth2PermissionGrants.json"),
        "--out-dir", str(out_dir),
        "--salt-file", str(scenario_dir / "salt.txt"),
        "--generated-at", GOLDEN_GENERATED_AT,
    ]
    return subprocess.run(args, capture_output=True, text=True)


def run_powershell(scenario_dir: pathlib.Path, out_dir: pathlib.Path) -> subprocess.CompletedProcess:
    input_dir = scenario_dir / "input"
    args = [
        PWSH, "-NoProfile", "-File", str(NC_EXPORT_ENTRA_PS1),
        "-UsersJson", str(input_dir / "users.json"),
        "-ServicePrincipalsJson", str(input_dir / "servicePrincipals.json"),
        "-GrantsJson", str(input_dir / "oauth2PermissionGrants.json"),
        "-OutDir", str(out_dir),
        "-SaltFile", str(scenario_dir / "salt.txt"),
        "-GeneratedAt", GOLDEN_GENERATED_AT,
    ]
    return subprocess.run(args, capture_output=True, text=True)


@unittest.skipIf(PWSH is None, "pwsh not found on PATH; cannot run the PowerShell side of the parity check")
class TestCrossLanguageParity(unittest.TestCase):
    def test_python_and_powershell_produce_byte_identical_output(self):
        for scenario in SCENARIOS:
            scenario_dir = FIXTURES_ROOT / scenario
            with self.subTest(scenario=scenario):
                with tempfile.TemporaryDirectory() as tmp:
                    py_out = pathlib.Path(tmp) / "py"
                    ps_out = pathlib.Path(tmp) / "ps"

                    py_result = run_python(scenario_dir, py_out)
                    self.assertEqual(py_result.returncode, 0, py_result.stderr)

                    ps_result = run_powershell(scenario_dir, ps_out)
                    self.assertEqual(ps_result.returncode, 0, ps_result.stderr)

                    py_bytes = (py_out / "discover-export.ndjson").read_bytes()
                    ps_bytes = (ps_out / "discover-export.ndjson").read_bytes()
                    self.assertEqual(
                        py_bytes,
                        ps_bytes,
                        f"nc-export.py entra and nc-export-entra.ps1 diverged for {scenario}",
                    )


if __name__ == "__main__":
    unittest.main()
