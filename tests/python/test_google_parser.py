"""CLI-level tests for `nc-export.py google` (T1 task 4).

Exercises the public contract (argv, exit code, stderr, files written) with
small hand-built CSVs in a temp directory, rather than reaching into
internals, so the tests stay valid across implementation refactors.
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
SALT = "a0891513aba11b839e9a5072e4e8fc3de92477b14428a45f67ad7aba856063f5"


def run(args, cwd):
    return subprocess.run(
        [sys.executable, str(NC_EXPORT), *args],
        cwd=cwd,
        capture_output=True,
        text=True,
    )


def write(path: pathlib.Path, content: str):
    path.write_text(content, encoding="utf-8")


class TestGoogleParser(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.tmp = pathlib.Path(self._tmp.name)
        self.out_dir = self.tmp / "out"
        self.salt_file = self.tmp / "salt.txt"
        write(self.salt_file, SALT + "\n")

    def _audit(self, rows_csv: str) -> pathlib.Path:
        path = self.tmp / "audit.csv"
        write(path, AUDIT_HEADER + rows_csv)
        return path

    def _users(self, emails) -> pathlib.Path:
        path = self.tmp / "users.csv"
        write(path, "email\n" + "\n".join(emails) + "\n")
        return path

    def test_well_formed_input_produces_correct_counts(self):
        audit = self._audit(
            "2026-01-05T10:00:00Z,alice@example.com,111-aaa.apps.googleusercontent.com,Slack,"
            "https://www.googleapis.com/auth/drive.readonly\n"
            "2026-02-10T09:30:00Z,bob@example.com,222-bbb.apps.googleusercontent.com,Zoom,"
            "https://www.googleapis.com/auth/calendar.readonly\n"
        )
        users = self._users(["alice@example.com", "bob@example.com", "carol@example.com"])
        result = run(
            [
                "google",
                "--audit-csv", str(audit),
                "--users-csv", str(users),
                "--out-dir", str(self.out_dir),
                "--salt-file", str(self.salt_file),
            ],
            cwd=self.tmp,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        lines = (self.out_dir / "discover-export.ndjson").read_text(encoding="utf-8").splitlines()
        header = json.loads(lines[0])
        self.assertEqual(header["userCountTotal"], 3)
        self.assertEqual(len(lines), 3)  # header + 2 grants

    def test_missing_required_column_errors_clearly(self):
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
        self.assertIn("scopes", result.stderr)
        self.assertFalse(self.out_dir.exists())

    def test_ragged_row_skipped_with_warning_others_processed(self):
        audit = self._audit(
            "2026-01-05T10:00:00Z,,111-aaa.apps.googleusercontent.com,Slack,"
            "https://www.googleapis.com/auth/drive.readonly\n"
            "2026-02-10T09:30:00Z,bob@example.com,222-bbb.apps.googleusercontent.com,Zoom,"
            "https://www.googleapis.com/auth/calendar.readonly\n"
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
        self.assertIn("warning", result.stderr.lower())
        lines = (self.out_dir / "discover-export.ndjson").read_text(encoding="utf-8").splitlines()
        self.assertEqual(len(lines), 2)  # header + 1 valid grant

    def test_row_with_whitespace_only_actor_email_is_skipped_with_warning(self):
        audit = self._audit(
            "2026-01-05T10:00:00Z,   ,111-aaa.apps.googleusercontent.com,Slack,"
            "https://www.googleapis.com/auth/drive.readonly\n"
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
        self.assertIn("warning", result.stderr.lower())
        lines = (self.out_dir / "discover-export.ndjson").read_text(encoding="utf-8").splitlines()
        self.assertEqual(len(lines), 1)  # header only, row skipped
        header = json.loads(lines[0])
        self.assertEqual(header["skippedRows"], 1)

    def test_row_with_whitespace_only_client_id_is_skipped_with_warning(self):
        audit = self._audit(
            "2026-01-05T10:00:00Z,alice@example.com,   ,Slack,"
            "https://www.googleapis.com/auth/drive.readonly\n"
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
        self.assertIn("warning", result.stderr.lower())
        lines = (self.out_dir / "discover-export.ndjson").read_text(encoding="utf-8").splitlines()
        self.assertEqual(len(lines), 1)

    def test_row_with_whitespace_only_display_text_is_skipped_with_warning(self):
        audit = self._audit(
            "2026-01-05T10:00:00Z,alice@example.com,111-aaa.apps.googleusercontent.com,   ,"
            "https://www.googleapis.com/auth/drive.readonly\n"
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
        self.assertIn("warning", result.stderr.lower())
        lines = (self.out_dir / "discover-export.ndjson").read_text(encoding="utf-8").splitlines()
        self.assertEqual(len(lines), 1)

    def test_row_with_empty_scopes_value_is_kept_with_empty_scopes_array(self):
        # spec/discover-export-format-v1.md: grant.scopes "May be empty."
        # A genuinely empty scopes cell is valid input, not a malformed
        # row -- it must not be dropped the way a missing actorEmail is.
        audit = self._audit(
            "2026-01-05T10:00:00Z,alice@example.com,111-aaa.apps.googleusercontent.com,Slack,\n"
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
        self.assertNotIn("warning", result.stderr.lower())
        lines = (self.out_dir / "discover-export.ndjson").read_text(encoding="utf-8").splitlines()
        self.assertEqual(len(lines), 2)  # header + 1 grant, not skipped
        grant = json.loads(lines[1])
        self.assertEqual(grant["clientId"], "111-aaa.apps.googleusercontent.com")
        self.assertEqual(grant["appDisplayName"], "Slack")
        self.assertEqual(grant["scopes"], [])

    def test_header_only_csv_produces_header_only_output(self):
        audit = self._audit("")
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
        lines = (self.out_dir / "discover-export.ndjson").read_text(encoding="utf-8").splitlines()
        self.assertEqual(len(lines), 1)

    def test_completely_empty_file_errors_clearly(self):
        path = self.tmp / "audit.csv"
        write(path, "")
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
        self.assertTrue(result.stderr.strip())

    def test_duplicate_rows_deduped_scopes_unioned_first_last_seen(self):
        audit = self._audit(
            "2026-06-01T08:00:00Z,heidi@example.com,777-ggg.apps.googleusercontent.com,Trello,"
            "https://www.googleapis.com/auth/drive.readonly\n"
            "2026-06-15T08:00:00Z,heidi@example.com,777-ggg.apps.googleusercontent.com,Trello,"
            "https://www.googleapis.com/auth/drive.readonly https://www.googleapis.com/auth/calendar.readonly\n"
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
        lines = (self.out_dir / "discover-export.ndjson").read_text(encoding="utf-8").splitlines()
        self.assertEqual(len(lines), 2)  # header + 1 deduped grant
        grant = json.loads(lines[1])
        self.assertEqual(
            grant["scopes"],
            sorted([
                "https://www.googleapis.com/auth/drive.readonly",
                "https://www.googleapis.com/auth/calendar.readonly",
            ]),
        )
        self.assertEqual(grant["firstSeen"], "2026-06-01T08:00:00Z")
        self.assertEqual(grant["lastUsed"], "2026-06-15T08:00:00Z")

    def test_no_users_csv_gives_null_user_count_total_but_succeeds(self):
        audit = self._audit(
            "2026-03-01T00:00:00Z,dave@example.com,333-ccc.apps.googleusercontent.com,Notion,"
            "https://www.googleapis.com/auth/drive.file\n"
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
        header = json.loads(
            (self.out_dir / "discover-export.ndjson").read_text(encoding="utf-8").splitlines()[0]
        )
        self.assertIsNone(header["userCountTotal"])

    def test_unicode_app_display_name_round_trips(self):
        name = "Café Analytics™ 日本語アプリ"
        audit = self._audit(
            f"2026-04-01T00:00:00Z,ren@example.com,555-eee.apps.googleusercontent.com,{name},"
            "https://www.googleapis.com/auth/drive.readonly\n"
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
        raw = (self.out_dir / "discover-export.ndjson").read_bytes()
        self.assertIn(name.encode("utf-8"), raw)
        self.assertNotIn(b"\\u", raw)


if __name__ == "__main__":
    unittest.main()
