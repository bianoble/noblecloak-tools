"""Pseudonymization unit + CLI tests (T1 task 6)."""
import csv
import json
import pathlib
import platform
import stat
import subprocess
import sys
import tempfile
import unittest

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
NC_EXPORT = REPO_ROOT / "scripts" / "nc-export.py"

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from _load_nc_export import load_nc_export  # noqa: E402

nc_export = load_nc_export()

# Fixed test vector, independent of any fixture: pin the exact derivation.
FIXED_SALT_HEX = "00112233445566778899aabbccddeeff00112233445566778899aabbccddee"
FIXED_EMAIL = "test.user@example.com"
EXPECTED_USER_REF = "user_d172a84870a7ba01"


class TestDeriveUserRefUnit(unittest.TestCase):
    def test_fixed_salt_and_email_match_pinned_golden_value(self):
        salt_bytes = bytes.fromhex(FIXED_SALT_HEX)
        self.assertEqual(
            nc_export.derive_user_ref(salt_bytes, FIXED_EMAIL, pseudonymized=True),
            EXPECTED_USER_REF,
        )

    def test_uppercase_and_padded_email_normalizes_to_same_ref(self):
        salt_bytes = bytes.fromhex(FIXED_SALT_HEX)
        self.assertEqual(
            nc_export.derive_user_ref(salt_bytes, "  Test.User@Example.com  ", pseudonymized=True),
            EXPECTED_USER_REF,
        )


def write(path: pathlib.Path, content: str):
    path.write_text(content, encoding="utf-8")


def run(args, cwd):
    return subprocess.run(
        [sys.executable, str(NC_EXPORT), *args],
        cwd=cwd,
        capture_output=True,
        text=True,
    )


class TestPseudonymizeCli(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.tmp = pathlib.Path(self._tmp.name)
        self.out_dir = self.tmp / "out"
        self.audit_csv = self.tmp / "audit.csv"
        write(
            self.audit_csv,
            "time,actorEmail,clientId,displayText,scopes\n"
            "2026-01-05T10:00:00Z,alice@example.com,111-aaa.apps.googleusercontent.com,Slack,"
            "https://www.googleapis.com/auth/drive.readonly\n",
        )
        self.salt_file = self.tmp / "salt.txt"
        write(self.salt_file, FIXED_SALT_HEX + "\n")

    def test_no_pseudonymize_uses_raw_email_and_writes_no_side_files(self):
        result = run(
            [
                "google",
                "--audit-csv", str(self.audit_csv),
                "--out-dir", str(self.out_dir),
                "--no-pseudonymize",
            ],
            cwd=self.tmp,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        lines = (self.out_dir / "discover-export.ndjson").read_text(encoding="utf-8").splitlines()
        header = json.loads(lines[0])
        self.assertFalse(header["pseudonymized"])
        grant = json.loads(lines[1])
        self.assertEqual(grant["userRef"], "alice@example.com")
        self.assertFalse((self.out_dir / "mapping.csv").exists())
        self.assertFalse((self.out_dir / "salt.txt").exists())

    def test_default_mode_writes_mapping_and_salt_files(self):
        result = run(
            [
                "google",
                "--audit-csv", str(self.audit_csv),
                "--out-dir", str(self.out_dir),
                "--salt-file", str(self.salt_file),
            ],
            cwd=self.tmp,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        header = json.loads(
            (self.out_dir / "discover-export.ndjson").read_text(encoding="utf-8").splitlines()[0]
        )
        self.assertTrue(header["pseudonymized"])

        salt_contents = (self.out_dir / "salt.txt").read_text(encoding="utf-8").strip()
        self.assertEqual(salt_contents, FIXED_SALT_HEX)

        with (self.out_dir / "mapping.csv").open(encoding="utf-8") as fh:
            rows = list(csv.DictReader(fh))
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["email"], "alice@example.com")
        # userRef must match the HMAC derivation with the salt actually used.
        self.assertEqual(
            rows[0]["userRef"],
            nc_export.derive_user_ref(bytes.fromhex(FIXED_SALT_HEX), "alice@example.com", True),
        )

    @unittest.skipIf(platform.system() == "Windows", "POSIX file mode bits only")
    def test_mapping_and_salt_files_are_owner_only(self):
        result = run(
            [
                "google",
                "--audit-csv", str(self.audit_csv),
                "--out-dir", str(self.out_dir),
                "--salt-file", str(self.salt_file),
            ],
            cwd=self.tmp,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        for name in ("mapping.csv", "salt.txt"):
            mode = stat.S_IMODE((self.out_dir / name).stat().st_mode)
            self.assertEqual(mode, 0o600, f"{name} had mode {oct(mode)}")


if __name__ == "__main__":
    unittest.main()
