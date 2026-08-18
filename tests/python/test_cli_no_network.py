"""Zero-network guarantee tests for nc-export.py (T1 task 6).

Two independent checks:
  1. Dynamic: monkeypatch the socket-opening primitives so any attempt to
     use them raises, then run every fixture scenario in-process and
     assert nothing raised.
  2. Static: AST-parse the script and assert it never imports a
     networking module at all, as a belt-and-suspenders guard against a
     code path the dynamic check didn't happen to exercise.
"""
import ast
import http.client
import pathlib
import socket
import sys
import tempfile
import unittest
import urllib.request

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
NC_EXPORT_PATH = REPO_ROOT / "scripts" / "nc-export.py"

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from _load_nc_export import load_nc_export  # noqa: E402
from fixture_runner import (  # noqa: E402
    GOLDEN_GENERATED_AT,
    NO_PSEUDONYMIZE_SCENARIOS,
    entra_scenarios,
    google_scenarios,
)

FORBIDDEN_MODULES = {"socket", "urllib.request", "http.client", "requests", "httpx", "ftplib", "smtplib"}


class TestStaticNoNetworkImports(unittest.TestCase):
    def test_script_never_imports_a_networking_module(self):
        tree = ast.parse(NC_EXPORT_PATH.read_text(encoding="utf-8"), filename=str(NC_EXPORT_PATH))
        imported = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    imported.add(alias.name)
            elif isinstance(node, ast.ImportFrom) and node.module:
                imported.add(node.module)

        offending = imported & FORBIDDEN_MODULES
        self.assertFalse(offending, f"nc-export.py imports networking module(s): {offending}")


def _blocked_connect(*args, **kwargs):
    raise AssertionError("network I/O attempted during nc-export.py execution")


class TestDynamicNoNetworkCalls(unittest.TestCase):
    def setUp(self):
        self._orig_socket_connect = socket.socket.connect
        self._orig_urlopen = urllib.request.urlopen
        self._orig_http_connect = http.client.HTTPConnection.connect

        socket.socket.connect = _blocked_connect
        urllib.request.urlopen = _blocked_connect
        http.client.HTTPConnection.connect = _blocked_connect

        self.addCleanup(self._restore)
        self.nc_export = load_nc_export()

    def _restore(self):
        socket.socket.connect = self._orig_socket_connect
        urllib.request.urlopen = self._orig_urlopen
        http.client.HTTPConnection.connect = self._orig_http_connect

    def test_every_google_scenario_runs_with_no_network_calls(self):
        for scenario_dir in google_scenarios():
            with self.subTest(scenario=scenario_dir.name):
                with tempfile.TemporaryDirectory() as tmp:
                    out_dir = pathlib.Path(tmp) / "out"
                    input_dir = scenario_dir / "input"
                    argv = [
                        "google",
                        "--audit-csv", str(input_dir / "oauth-token-audit.csv"),
                        "--out-dir", str(out_dir),
                        "--generated-at", GOLDEN_GENERATED_AT,
                    ]
                    users_csv = input_dir / "users.csv"
                    if users_csv.is_file():
                        argv += ["--users-csv", str(users_csv)]
                    if scenario_dir.name in NO_PSEUDONYMIZE_SCENARIOS:
                        argv += ["--no-pseudonymize"]
                    else:
                        argv += ["--salt-file", str(scenario_dir / "salt.txt")]

                    exit_code = self.nc_export.main(argv)
                    self.assertEqual(exit_code, 0)

    def test_every_entra_scenario_runs_with_no_network_calls(self):
        for scenario_dir in entra_scenarios():
            with self.subTest(scenario=scenario_dir.name):
                with tempfile.TemporaryDirectory() as tmp:
                    out_dir = pathlib.Path(tmp) / "out"
                    input_dir = scenario_dir / "input"
                    argv = [
                        "entra",
                        "--users-json", str(input_dir / "users.json"),
                        "--service-principals-json", str(input_dir / "servicePrincipals.json"),
                        "--grants-json", str(input_dir / "oauth2PermissionGrants.json"),
                        "--out-dir", str(out_dir),
                        "--generated-at", GOLDEN_GENERATED_AT,
                        "--salt-file", str(scenario_dir / "salt.txt"),
                    ]
                    exit_code = self.nc_export.main(argv)
                    self.assertEqual(exit_code, 0)


if __name__ == "__main__":
    unittest.main()
