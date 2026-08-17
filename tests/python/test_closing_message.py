"""Closing-message tests for nc-export.py (brief item #3).

Brief: "Ends with an explicit 'nothing has been sent anywhere — review
discover-export.ndjson, then upload it in the Discover app' message."
This is a trust/UX requirement, not cosmetic -- the whole point of the
tool's privacy model is that the operator can see, in plain text on a
successful run, that nothing left the machine.
"""
import pathlib
import subprocess
import sys
import tempfile
import unittest

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
NC_EXPORT = REPO_ROOT / "scripts" / "nc-export.py"

AUDIT_HEADER = "time,actorEmail,clientId,displayText,scopes\n"
SALT = "a0891513aba11b839e9a5072e4e8fc3de92477b14428a45f67ad7aba856063f5"

# The substrings a human (or a reviewer grepping the transcript) should be
# able to find on a successful run. Checked individually rather than as one
# giant literal so minor punctuation choices don't make the test brittle.
REQUIRED_PHRASES = (
    "nothing has been sent anywhere",
    "review discover-export.ndjson",
    "upload it in the discover app",
)


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
    import json

    path.write_text(json.dumps(obj, ensure_ascii=False), encoding="utf-8")


class TestClosingMessage(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.tmp = pathlib.Path(self._tmp.name)
        self.out_dir = self.tmp / "out"
        self.salt_file = self.tmp / "salt.txt"
        write(self.salt_file, SALT + "\n")

    def test_google_success_prints_closing_message_to_stdout(self):
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
                "--salt-file", str(self.salt_file),
            ],
            cwd=self.tmp,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        stdout_lower = result.stdout.lower()
        for phrase in REQUIRED_PHRASES:
            self.assertIn(phrase, stdout_lower, f"missing {phrase!r} in stdout: {result.stdout!r}")

    def test_entra_success_prints_closing_message_to_stdout(self):
        users_path = self.tmp / "users.json"
        sps_path = self.tmp / "servicePrincipals.json"
        grants_path = self.tmp / "oauth2PermissionGrants.json"
        write_json(users_path, {"value": [
            {"id": "u1", "userPrincipalName": "alice@contoso.com", "displayName": "Alice"},
        ]})
        write_json(sps_path, {"value": [
            {"id": "sp1", "appId": "aaaa1111-aaaa-1111-aaaa-111111111111", "displayName": "Slack"},
        ]})
        write_json(grants_path, {"value": [
            {"id": "g1", "clientId": "sp1", "principalId": "u1", "resourceId": "r1",
             "scope": "User.Read", "createdDateTime": "2026-01-10T00:00:00Z"},
        ]})
        result = run(
            [
                "entra",
                "--users-json", str(users_path),
                "--service-principals-json", str(sps_path),
                "--grants-json", str(grants_path),
                "--out-dir", str(self.out_dir),
                "--salt-file", str(self.salt_file),
            ],
            cwd=self.tmp,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        stdout_lower = result.stdout.lower()
        for phrase in REQUIRED_PHRASES:
            self.assertIn(phrase, stdout_lower, f"missing {phrase!r} in stdout: {result.stdout!r}")

    def test_skipped_rows_summary_line_printed_even_when_zero(self):
        # Brief item #3: both scripts print a loud "Skipped rows: N"
        # summary line to stdout, even when N is 0, immediately before the
        # closing message.
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
                "--salt-file", str(self.salt_file),
            ],
            cwd=self.tmp,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("Skipped rows: 0", result.stdout)

    def test_skipped_rows_summary_line_reflects_actual_skip_count(self):
        audit = self.tmp / "audit.csv"
        write(
            audit,
            AUDIT_HEADER
            + "2026-01-05T10:00:00Z,,111-aaa.apps.googleusercontent.com,Slack,"
            "https://www.googleapis.com/auth/drive.readonly\n"
            "2026-02-10T09:30:00Z,bob@example.com,222-bbb.apps.googleusercontent.com,Zoom,"
            "https://www.googleapis.com/auth/calendar.readonly\n",
        )
        result = run(
            [
                "google",
                "--audit-csv", str(audit),
                "--out-dir", str(self.out_dir),
                "--salt-file", str(self.salt_file),
            ],
            cwd=self.tmp,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("Skipped rows: 1", result.stdout)

    def test_error_path_does_not_print_closing_message(self):
        path = self.tmp / "audit.csv"
        write(path, "time,actorEmail,clientId,displayText\nfoo,bar,baz,qux\n")  # missing "scopes"
        result = run(
            [
                "google",
                "--audit-csv", str(path),
                "--out-dir", str(self.out_dir),
                "--salt-file", str(self.salt_file),
            ],
            cwd=self.tmp,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn("nothing has been sent anywhere", result.stdout.lower())


if __name__ == "__main__":
    unittest.main()
