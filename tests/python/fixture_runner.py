"""Shared helper for running nc-export.py against a fixtures/ scenario.

Used by the fixture-parity tests for both google and entra file mode, and
by the cross-language parity tests in tests/parity/.
"""
import pathlib
import subprocess
import sys

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
NC_EXPORT = REPO_ROOT / "scripts" / "nc-export.py"

# Scenarios where the golden output was generated with pseudonymized=false;
# these must be run with --no-pseudonymize and without a fixed salt file.
NO_PSEUDONYMIZE_SCENARIOS = {"scenario-no-pseudonymize"}

# Fixed generatedAt used when authoring every golden fixture (see
# fixtures/MANIFEST.md) -- must be passed so output is byte-identical.
GOLDEN_GENERATED_AT = "2026-08-17T00:00:00Z"


def run_google_scenario(scenario_dir: pathlib.Path, out_dir: pathlib.Path) -> subprocess.CompletedProcess:
    input_dir = scenario_dir / "input"
    audit_csv = input_dir / "oauth-token-audit.csv"
    users_csv = input_dir / "users.csv"
    salt_file = scenario_dir / "salt.txt"

    args = [
        sys.executable, str(NC_EXPORT), "google",
        "--audit-csv", str(audit_csv),
        "--out-dir", str(out_dir),
        "--generated-at", GOLDEN_GENERATED_AT,
    ]
    if users_csv.is_file():
        args += ["--users-csv", str(users_csv)]

    if scenario_dir.name in NO_PSEUDONYMIZE_SCENARIOS:
        args += ["--no-pseudonymize"]
    else:
        args += ["--salt-file", str(salt_file)]

    return subprocess.run(args, capture_output=True, text=True)


def run_entra_scenario(scenario_dir: pathlib.Path, out_dir: pathlib.Path) -> subprocess.CompletedProcess:
    input_dir = scenario_dir / "input"
    salt_file = scenario_dir / "salt.txt"
    app_role_assignments = input_dir / "appRoleAssignments.json"

    args = [
        sys.executable, str(NC_EXPORT), "entra",
        "--users-json", str(input_dir / "users.json"),
        "--service-principals-json", str(input_dir / "servicePrincipals.json"),
        "--grants-json", str(input_dir / "oauth2PermissionGrants.json"),
        "--out-dir", str(out_dir),
        "--generated-at", GOLDEN_GENERATED_AT,
    ]
    if app_role_assignments.is_file():
        args += ["--app-role-assignments-json", str(app_role_assignments)]

    if scenario_dir.name in NO_PSEUDONYMIZE_SCENARIOS:
        args += ["--no-pseudonymize"]
    else:
        args += ["--salt-file", str(salt_file)]

    return subprocess.run(args, capture_output=True, text=True)


def google_scenarios():
    root = REPO_ROOT / "fixtures" / "google"
    return sorted(p for p in root.iterdir() if p.is_dir())


def entra_scenarios():
    root = REPO_ROOT / "fixtures" / "entra"
    return sorted(p for p in root.iterdir() if p.is_dir())
