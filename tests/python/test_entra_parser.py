"""CLI-level tests for `nc-export.py entra` file mode (T1 task 5)."""
import json
import pathlib
import subprocess
import sys
import tempfile
import unittest

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
NC_EXPORT = REPO_ROOT / "scripts" / "nc-export.py"
SALT = "81bdd6b7e58dcc75c410d1b37007f5e6a9143673784d3d42b326663ea4d0dcd1"


def run(args, cwd):
    return subprocess.run(
        [sys.executable, str(NC_EXPORT), *args],
        cwd=cwd,
        capture_output=True,
        text=True,
    )


def write_json(path: pathlib.Path, obj):
    path.write_text(json.dumps(obj, ensure_ascii=False), encoding="utf-8")


class TestEntraParser(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.tmp = pathlib.Path(self._tmp.name)
        self.out_dir = self.tmp / "out"
        self.salt_file = self.tmp / "salt.txt"
        self.salt_file.write_text(SALT + "\n", encoding="utf-8")

        self.users_path = self.tmp / "users.json"
        self.sps_path = self.tmp / "servicePrincipals.json"
        self.grants_path = self.tmp / "oauth2PermissionGrants.json"

    def _run_entra(self, extra_args=None):
        args = [
            "entra",
            "--users-json", str(self.users_path),
            "--service-principals-json", str(self.sps_path),
            "--grants-json", str(self.grants_path),
            "--out-dir", str(self.out_dir),
            "--salt-file", str(self.salt_file),
        ]
        if extra_args:
            args += extra_args
        return run(args, cwd=self.tmp)

    def test_valid_triplet_resolves_appid_and_splits_scopes(self):
        write_json(self.users_path, {"value": [
            {"id": "u1", "userPrincipalName": "alice@contoso.com", "displayName": "Alice"},
            {"id": "u2", "userPrincipalName": "bob@contoso.com", "displayName": "Bob"},
        ]})
        write_json(self.sps_path, {"value": [
            {"id": "sp1", "appId": "aaaa1111-aaaa-1111-aaaa-111111111111", "displayName": "Slack"},
        ]})
        write_json(self.grants_path, {"value": [
            {"id": "g1", "clientId": "sp1", "principalId": "u1", "resourceId": "r1",
             "scope": "User.Read Mail.Read", "createdDateTime": "2026-01-10T00:00:00Z"},
        ]})

        result = self._run_entra()
        self.assertEqual(result.returncode, 0, result.stderr)
        lines = (self.out_dir / "discover-export.ndjson").read_text(encoding="utf-8").splitlines()
        header = json.loads(lines[0])
        self.assertEqual(header["userCountTotal"], 2)
        grant = json.loads(lines[1])
        self.assertEqual(grant["clientId"], "aaaa1111-aaaa-1111-aaaa-111111111111")
        self.assertNotEqual(grant["clientId"], "sp1")
        self.assertEqual(grant["scopes"], ["Mail.Read", "User.Read"])

    def test_missing_file_errors_naming_it(self):
        write_json(self.users_path, {"value": []})
        write_json(self.sps_path, {"value": []})
        # grants_path deliberately not written
        result = self._run_entra()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(str(self.grants_path), result.stderr)

    def test_truncated_json_errors_naming_file_no_partial_output(self):
        write_json(self.users_path, {"value": []})
        write_json(self.sps_path, {"value": []})
        self.grants_path.write_text('{"value": [', encoding="utf-8")  # truncated
        result = self._run_entra()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(str(self.grants_path), result.stderr)
        self.assertFalse(self.out_dir.exists())

    def test_grant_referencing_unknown_service_principal_is_skipped_with_warning(self):
        write_json(self.users_path, {"value": [
            {"id": "u1", "userPrincipalName": "alice@contoso.com", "displayName": "Alice"},
        ]})
        write_json(self.sps_path, {"value": []})  # no service principals at all
        write_json(self.grants_path, {"value": [
            {"id": "g1", "clientId": "sp-unknown", "principalId": "u1", "resourceId": "r1",
             "scope": "User.Read", "createdDateTime": "2026-01-10T00:00:00Z"},
        ]})
        result = self._run_entra()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("warning", result.stderr.lower())
        lines = (self.out_dir / "discover-export.ndjson").read_text(encoding="utf-8").splitlines()
        self.assertEqual(len(lines), 1)  # header only, grant skipped

    def test_grant_with_no_created_date_time_has_null_first_seen(self):
        write_json(self.users_path, {"value": [
            {"id": "u1", "userPrincipalName": "dave@contoso.com", "displayName": "Dave"},
        ]})
        write_json(self.sps_path, {"value": [
            {"id": "sp1", "appId": "cccc3333-cccc-3333-cccc-333333333333", "displayName": "Notion"},
        ]})
        write_json(self.grants_path, {"value": [
            {"id": "g1", "clientId": "sp1", "principalId": "u1", "resourceId": "r1", "scope": "Files.Read"},
        ]})
        result = self._run_entra()
        self.assertEqual(result.returncode, 0, result.stderr)
        grant = json.loads(
            (self.out_dir / "discover-export.ndjson").read_text(encoding="utf-8").splitlines()[1]
        )
        self.assertIsNone(grant["firstSeen"])

    def test_grant_with_no_scope_key_at_all_has_empty_scopes(self):
        # A grant row that omits "scope" entirely (e.g. a trimmed $select
        # query, or an app-only grant) is valid input, not malformed --
        # cross-language parity requires the PowerShell implementation to
        # tolerate this the same way this Python parser does.
        write_json(self.users_path, {"value": [
            {"id": "u1", "userPrincipalName": "henry@contoso.com", "displayName": "Henry"},
        ]})
        write_json(self.sps_path, {"value": [
            {"id": "sp1", "appId": "ffff6666-ffff-6666-ffff-666666666666", "displayName": "Asana"},
        ]})
        write_json(self.grants_path, {"value": [
            {"id": "g1", "clientId": "sp1", "principalId": "u1", "resourceId": "r1",
             "createdDateTime": "2026-05-01T00:00:00Z"},
        ]})
        result = self._run_entra()
        self.assertEqual(result.returncode, 0, result.stderr)
        grant = json.loads(
            (self.out_dir / "discover-export.ndjson").read_text(encoding="utf-8").splitlines()[1]
        )
        self.assertEqual(grant["scopes"], [])

    def test_duplicate_grants_same_user_and_client_are_deduped_scopes_unioned(self):
        write_json(self.users_path, {"value": [
            {"id": "u1", "userPrincipalName": "erin@contoso.com", "displayName": "Erin"},
        ]})
        write_json(self.sps_path, {"value": [
            {"id": "sp1", "appId": "dddd4444-dddd-4444-dddd-444444444444", "displayName": "Figma"},
        ]})
        write_json(self.grants_path, {"value": [
            {"id": "g1", "clientId": "sp1", "principalId": "u1", "resourceId": "r1",
             "scope": "User.Read", "createdDateTime": "2026-03-01T00:00:00Z"},
            {"id": "g2", "clientId": "sp1", "principalId": "u1", "resourceId": "r1",
             "scope": "User.Read Files.Read", "createdDateTime": "2026-03-20T00:00:00Z"},
        ]})
        result = self._run_entra()
        self.assertEqual(result.returncode, 0, result.stderr)
        lines = (self.out_dir / "discover-export.ndjson").read_text(encoding="utf-8").splitlines()
        self.assertEqual(len(lines), 2)  # header + 1 deduped grant
        grant = json.loads(lines[1])
        self.assertEqual(grant["scopes"], ["Files.Read", "User.Read"])
        self.assertEqual(grant["firstSeen"], "2026-03-01T00:00:00Z")

    def test_unicode_app_display_name_round_trips(self):
        name = "Café Analytics™ 日本語アプリ"
        write_json(self.users_path, {"value": [
            {"id": "u1", "userPrincipalName": "frank@contoso.com", "displayName": "Frank"},
        ]})
        write_json(self.sps_path, {"value": [
            {"id": "sp1", "appId": "eeee5555-eeee-5555-eeee-555555555555", "displayName": name},
        ]})
        write_json(self.grants_path, {"value": [
            {"id": "g1", "clientId": "sp1", "principalId": "u1", "resourceId": "r1",
             "scope": "User.Read", "createdDateTime": "2026-04-01T00:00:00Z"},
        ]})
        result = self._run_entra()
        self.assertEqual(result.returncode, 0, result.stderr)
        raw = (self.out_dir / "discover-export.ndjson").read_bytes()
        self.assertIn(name.encode("utf-8"), raw)
        self.assertNotIn(b"\\u", raw)

    def test_empty_grants_array_gives_header_only_output_with_user_count(self):
        write_json(self.users_path, {"value": [
            {"id": "u1", "userPrincipalName": "grace@contoso.com", "displayName": "Grace"},
        ]})
        write_json(self.sps_path, {"value": []})
        write_json(self.grants_path, {"value": []})
        result = self._run_entra()
        self.assertEqual(result.returncode, 0, result.stderr)
        lines = (self.out_dir / "discover-export.ndjson").read_text(encoding="utf-8").splitlines()
        self.assertEqual(len(lines), 1)
        header = json.loads(lines[0])
        self.assertEqual(header["userCountTotal"], 1)


if __name__ == "__main__":
    unittest.main()
