"""Unit tests for the DEF (Discover Export Format) validator harness.

These operate on plain in-memory dicts so they can be written and run
before the spec prose exists — the spec is authored afterward to match
what these tests pin down.
"""
import pathlib
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

from def_validator import DefValidationError, validate_grant, validate_header


def make_header(**overrides):
    header = {
        "kind": "discover-export",
        "version": "1",
        "vendor": "google",
        "generatedAt": "2026-08-17T12:00:00Z",
        "pseudonymized": True,
        "hashAlgo": "hmac-sha256",
        "script": "nc-export.py",
        "exportWindow": None,
        "userCountTotal": None,
        "skippedRows": 0,
    }
    header.update(overrides)
    return header


def make_grant(**overrides):
    grant = {
        "userRef": "user_0123456789abcdef",
        "consentType": "Principal",
        "clientId": "123456789.apps.googleusercontent.com",
        "appDisplayName": "Some App",
        "scopes": ["https://www.googleapis.com/auth/drive.readonly"],
        "firstSeen": "2026-01-01T00:00:00Z",
        "lastUsed": None,
    }
    grant.update(overrides)
    return grant


def make_allprincipals_grant(**overrides):
    grant = make_grant(userRef=None, consentType="AllPrincipals")
    grant.update(overrides)
    return grant


class TestValidateHeader(unittest.TestCase):
    def test_valid_header_passes(self):
        validate_header(make_header())  # must not raise

    def test_rejects_unknown_vendor(self):
        with self.assertRaises(DefValidationError):
            validate_header(make_header(vendor="okta"))

    def test_rejects_wrong_hash_algo(self):
        with self.assertRaises(DefValidationError):
            validate_header(make_header(hashAlgo="sha256"))

    def test_rejects_missing_required_field_and_names_it(self):
        for field in [
            "kind",
            "version",
            "vendor",
            "generatedAt",
            "pseudonymized",
            "hashAlgo",
            "script",
            "skippedRows",
        ]:
            with self.subTest(field=field):
                header = make_header()
                del header[field]
                with self.assertRaises(DefValidationError) as ctx:
                    validate_header(header)
                self.assertIn(field, str(ctx.exception))

    def test_nullable_export_window_and_user_count_accepted(self):
        validate_header(make_header(exportWindow=None, userCountTotal=None))  # ok

    def test_populated_export_window_and_user_count_accepted(self):
        validate_header(
            make_header(
                exportWindow={"start": "2026-01-01T00:00:00Z", "end": "2026-08-01T00:00:00Z"},
                userCountTotal=42,
            )
        )

    def test_zero_skipped_rows_accepted(self):
        validate_header(make_header(skippedRows=0))  # ok

    def test_positive_skipped_rows_accepted(self):
        validate_header(make_header(skippedRows=7))  # ok

    def test_rejects_null_skipped_rows(self):
        with self.assertRaises(DefValidationError):
            validate_header(make_header(skippedRows=None))

    def test_rejects_negative_skipped_rows(self):
        with self.assertRaises(DefValidationError):
            validate_header(make_header(skippedRows=-1))


class TestValidateGrant(unittest.TestCase):
    def test_valid_grant_passes(self):
        validate_grant(make_grant(), pseudonymized=True)  # must not raise

    def test_rejects_missing_required_field_and_names_it(self):
        for field in ["userRef", "consentType", "clientId", "appDisplayName", "scopes", "firstSeen"]:
            with self.subTest(field=field):
                grant = make_grant()
                del grant[field]
                with self.assertRaises(DefValidationError) as ctx:
                    validate_grant(grant, pseudonymized=True)
                self.assertIn(field, str(ctx.exception))

    def test_null_last_used_accepted(self):
        validate_grant(make_grant(lastUsed=None), pseudonymized=True)  # ok

    def test_pseudonymized_user_ref_must_match_hash_format(self):
        with self.assertRaises(DefValidationError):
            validate_grant(make_grant(userRef="not-a-hash"), pseudonymized=True)

    def test_pseudonymized_user_ref_rejects_email(self):
        with self.assertRaises(DefValidationError):
            validate_grant(make_grant(userRef="alice@example.com"), pseudonymized=True)

    def test_non_pseudonymized_user_ref_accepts_raw_email(self):
        validate_grant(make_grant(userRef="alice@example.com"), pseudonymized=False)  # ok

    def test_rejects_unknown_consent_type(self):
        with self.assertRaises(DefValidationError):
            validate_grant(make_grant(consentType="Bogus"), pseudonymized=True)

    def test_allprincipals_grant_with_null_user_ref_accepted(self):
        validate_grant(make_allprincipals_grant(), pseudonymized=True)  # ok
        validate_grant(make_allprincipals_grant(), pseudonymized=False)  # ok

    def test_allprincipals_grant_rejects_non_null_user_ref(self):
        with self.assertRaises(DefValidationError):
            validate_grant(
                make_allprincipals_grant(userRef="user_0123456789abcdef"), pseudonymized=True
            )

    def test_principal_grant_rejects_null_user_ref(self):
        with self.assertRaises(DefValidationError):
            validate_grant(make_grant(userRef=None), pseudonymized=True)


if __name__ == "__main__":
    unittest.main()
