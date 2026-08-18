"""Error-handling polish tests (brief item #7).

(a) load_or_generate_salt wraps file I/O + hex decoding in the same
    ExportError pattern used elsewhere (no raw tracebacks).
(b) main() has a top-level catch-all: any *unexpected* exception is still
    re-emitted through the "error: ..." stderr contract, exit 1, no
    traceback.
(e) When users or grants parse to zero records, a prominent warning is
    printed (exit code stays 0 -- an empty tenant is legitimate).
"""
import json
import pathlib
import subprocess
import sys
import tempfile
import unittest

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
NC_EXPORT = REPO_ROOT / "scripts" / "nc-export.py"

AUDIT_HEADER = "time,actorEmail,clientId,displayText,scopes\n"


def run(args, cwd):
    return subprocess.run(
        [sys.executable, str(NC_EXPORT), *args],
        cwd=cwd,
        capture_output=True,
        text=True,
    )


def write(path: pathlib.Path, content: str):
    path.write_text(content, encoding="utf-8")


def write_json(path: pathlib.Path, obj):
    path.write_text(json.dumps(obj, ensure_ascii=False), encoding="utf-8")


class TestSaltFileErrorHandling(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.tmp = pathlib.Path(self._tmp.name)
        self.out_dir = self.tmp / "out"
        self.audit_csv = self.tmp / "audit.csv"
        write(
            self.audit_csv,
            AUDIT_HEADER
            + "2026-01-05T10:00:00Z,alice@example.com,111-aaa.apps.googleusercontent.com,Slack,"
            "https://www.googleapis.com/auth/drive.readonly\n",
        )

    def test_missing_salt_file_errors_via_clean_stderr_contract(self):
        missing_salt = self.tmp / "does-not-exist.txt"
        result = run(
            [
                "google",
                "--audit-csv", str(self.audit_csv),
                "--out-dir", str(self.out_dir),
                "--salt-file", str(missing_salt),
            ],
            cwd=self.tmp,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertTrue(result.stderr.startswith("error:"), result.stderr)
        self.assertNotIn("Traceback", result.stderr)
        self.assertIn(str(missing_salt), result.stderr)
        self.assertFalse(self.out_dir.exists())

    def test_salt_file_with_invalid_hex_errors_via_clean_stderr_contract(self):
        bad_salt = self.tmp / "salt.txt"
        write(bad_salt, "not-valid-hex\n")
        result = run(
            [
                "google",
                "--audit-csv", str(self.audit_csv),
                "--out-dir", str(self.out_dir),
                "--salt-file", str(bad_salt),
            ],
            cwd=self.tmp,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertTrue(result.stderr.startswith("error:"), result.stderr)
        self.assertNotIn("Traceback", result.stderr)
        self.assertFalse(self.out_dir.exists())


class TestMainCatchAll(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.tmp = pathlib.Path(self._tmp.name)
        self.out_dir = self.tmp / "out"

    def test_unexpected_exception_is_reported_through_stderr_contract_not_a_traceback(self):
        # A grant entry that is a bare int (not an object) makes
        # grant.get(...) raise AttributeError deep inside parsing -- a
        # class of bug an ExportError-only guard wouldn't catch. main()'s
        # catch-all must still turn this into a clean one-line message.
        users_path = self.tmp / "users.json"
        sps_path = self.tmp / "servicePrincipals.json"
        grants_path = self.tmp / "oauth2PermissionGrants.json"
        write_json(users_path, {"value": [{"id": "u1", "userPrincipalName": "a@b.com"}]})
        write_json(sps_path, {"value": []})
        write_json(grants_path, {"value": [5]})  # malformed: not an object

        result = run(
            [
                "entra",
                "--users-json", str(users_path),
                "--service-principals-json", str(sps_path),
                "--grants-json", str(grants_path),
                "--out-dir", str(self.out_dir),
            ],
            cwd=self.tmp,
        )
        self.assertEqual(result.returncode, 1)
        self.assertTrue(result.stderr.startswith("error:"), result.stderr)
        self.assertNotIn("Traceback", result.stderr)
        self.assertFalse(self.out_dir.exists())
        self.assertNotIn("nothing has been sent anywhere", result.stdout.lower())


class TestEmptyResultWarning(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.tmp = pathlib.Path(self._tmp.name)
        self.out_dir = self.tmp / "out"

    def test_zero_users_prints_prominent_warning_but_still_exits_zero(self):
        audit = self.tmp / "audit.csv"
        write(
            audit,
            AUDIT_HEADER
            + "2026-01-05T10:00:00Z,alice@example.com,111-aaa.apps.googleusercontent.com,Slack,"
            "https://www.googleapis.com/auth/drive.readonly\n",
        )
        users_csv = self.tmp / "users.csv"
        write(users_csv, "email\n")  # header only, zero users

        result = run(
            [
                "google",
                "--audit-csv", str(audit),
                "--users-csv", str(users_csv),
                "--out-dir", str(self.out_dir),
            ],
            cwd=self.tmp,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("0 users", result.stderr)
        self.assertIn("permission", result.stderr.lower())

    def test_zero_grants_prints_prominent_warning_but_still_exits_zero(self):
        audit = self.tmp / "audit.csv"
        write(audit, AUDIT_HEADER)  # header only, zero grant rows

        result = run(
            [
                "google",
                "--audit-csv", str(audit),
                "--out-dir", str(self.out_dir),
            ],
            cwd=self.tmp,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("0 grants", result.stderr)
        self.assertIn("permission", result.stderr.lower())

    def test_nonzero_users_and_grants_print_no_empty_result_warning(self):
        audit = self.tmp / "audit.csv"
        write(
            audit,
            AUDIT_HEADER
            + "2026-01-05T10:00:00Z,alice@example.com,111-aaa.apps.googleusercontent.com,Slack,"
            "https://www.googleapis.com/auth/drive.readonly\n",
        )
        result = run(
            [
                "google",
                "--audit-csv", str(audit),
                "--out-dir", str(self.out_dir),
            ],
            cwd=self.tmp,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn("0 users", result.stderr)
        self.assertNotIn("0 grants", result.stderr)


if __name__ == "__main__":
    unittest.main()
