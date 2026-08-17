"""Validator for the Discover Export Format (DEF) v1.

Pure, dependency-free validation logic shared by:
  - the DEF spec's own unit tests (test_def_validator.py)
  - golden-fixture validation (test_fixture_manifest.py)
  - fixture-parity tests for both export scripts

See spec/discover-export-format-v1.md for the authoritative format
definition; this module enforces exactly what that spec pins down.
"""
from __future__ import annotations

import json
import re

VALID_VENDORS = {"google", "entra"}
VALID_HASH_ALGO = "hmac-sha256"
DEF_KIND = "discover-export"
DEF_VERSION = "1"

HEADER_REQUIRED_FIELDS = (
    "kind",
    "version",
    "vendor",
    "generatedAt",
    "pseudonymized",
    "hashAlgo",
    "script",
    "exportWindow",
    "userCountTotal",
)

GRANT_REQUIRED_FIELDS = (
    "userRef",
    "clientId",
    "appDisplayName",
    "scopes",
    "firstSeen",
    "lastUsed",
)

# HMAC-SHA256 digest, hex-encoded, truncated to the first 16 hex chars,
# prefixed with "user_" — see spec section "userRef derivation".
USER_REF_HASH_RE = re.compile(r"^user_[0-9a-f]{16}$")


class DefValidationError(ValueError):
    """Raised when a DEF header or grant line fails validation."""


def validate_header(header: dict) -> None:
    for field in HEADER_REQUIRED_FIELDS:
        if field not in header:
            raise DefValidationError(f"header missing required field: {field}")

    if header["kind"] != DEF_KIND:
        raise DefValidationError(f"header.kind must be {DEF_KIND!r}, got {header['kind']!r}")

    if header["version"] != DEF_VERSION:
        raise DefValidationError(
            f"header.version must be {DEF_VERSION!r}, got {header['version']!r}"
        )

    if header["vendor"] not in VALID_VENDORS:
        raise DefValidationError(
            f"header.vendor must be one of {sorted(VALID_VENDORS)}, got {header['vendor']!r}"
        )

    if header["hashAlgo"] != VALID_HASH_ALGO:
        raise DefValidationError(
            f"header.hashAlgo must be {VALID_HASH_ALGO!r}, got {header['hashAlgo']!r}"
        )

    if not isinstance(header["pseudonymized"], bool):
        raise DefValidationError("header.pseudonymized must be a boolean")

    if not isinstance(header["generatedAt"], str) or not header["generatedAt"]:
        raise DefValidationError("header.generatedAt must be a non-empty string")

    if not isinstance(header["script"], str) or not header["script"]:
        raise DefValidationError("header.script must be a non-empty string")

    if header["userCountTotal"] is not None and not isinstance(header["userCountTotal"], int):
        raise DefValidationError("header.userCountTotal must be null or an integer")


def validate_grant(grant: dict, pseudonymized: bool) -> None:
    for field in GRANT_REQUIRED_FIELDS:
        if field not in grant:
            raise DefValidationError(f"grant missing required field: {field}")

    user_ref = grant["userRef"]
    if not isinstance(user_ref, str) or not user_ref:
        raise DefValidationError("grant.userRef must be a non-empty string")

    if pseudonymized:
        if not USER_REF_HASH_RE.match(user_ref):
            raise DefValidationError(
                f"grant.userRef {user_ref!r} does not match hashed format "
                f"^user_[0-9a-f]{{16}}$ required when header.pseudonymized is true"
            )

    if not isinstance(grant["clientId"], str) or not grant["clientId"]:
        raise DefValidationError("grant.clientId must be a non-empty string")

    if not isinstance(grant["appDisplayName"], str) or not grant["appDisplayName"]:
        raise DefValidationError("grant.appDisplayName must be a non-empty string")

    if not isinstance(grant["scopes"], list) or not all(
        isinstance(s, str) for s in grant["scopes"]
    ):
        raise DefValidationError("grant.scopes must be an array of strings")

    if grant["firstSeen"] is not None and not isinstance(grant["firstSeen"], str):
        raise DefValidationError("grant.firstSeen must be null or a string")

    if grant["lastUsed"] is not None and not isinstance(grant["lastUsed"], str):
        raise DefValidationError("grant.lastUsed must be null or a string")


def validate_def_lines(lines: list[dict]) -> None:
    """Validate a full DEF document expressed as a list of parsed JSON objects.

    lines[0] is the header; every subsequent element is a grant line.
    """
    if not lines:
        raise DefValidationError("empty DEF document: a header line is required")

    header = lines[0]
    validate_header(header)

    for index, grant in enumerate(lines[1:], start=1):
        try:
            validate_grant(grant, pseudonymized=header["pseudonymized"])
        except DefValidationError as exc:
            raise DefValidationError(f"grant line {index}: {exc}") from exc


def validate_def_file(path) -> None:
    """Validate a DEF NDJSON file on disk, line by line."""
    with open(path, "r", encoding="utf-8") as fh:
        raw_lines = [line for line in fh.read().split("\n") if line != ""]

    parsed = [json.loads(line) for line in raw_lines]
    validate_def_lines(parsed)
