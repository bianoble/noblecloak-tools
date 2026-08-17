#!/usr/bin/env python3
"""nc-export.py -- offline, zero-network export to the Discover Export Format (DEF) v1.

Reads a Google Workspace OAuth Token Audit CSV (and optionally a Users
CSV) or a Microsoft Entra ID users/servicePrincipals/oauth2PermissionGrants
JSON triplet (and optionally an appRoleAssignments JSON export), and
writes a pseudonymized (by default) DEF v1 NDJSON file.

See spec/discover-export-format-v1.md for the exact output format this
script must produce, and fixtures/ for golden input/output pairs.

This script performs no network I/O. It only reads the local files named
on the command line and writes to --out-dir.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import hmac
import json
import os
import secrets
import stat
import sys
from typing import Optional

DEF_KIND = "discover-export"
DEF_VERSION = "1"
HASH_ALGO = "hmac-sha256"

# Printed to stdout after a successful run. This is the core trust/UX
# guarantee of the tool -- the operator gets explicit, on-screen
# confirmation that nothing left the machine. Kept identical (same text)
# to the closing message nc-export-entra.ps1 prints -- see
# spec/discover-export-format-v1.md and README.md's privacy model.
CLOSING_MESSAGE = (
    "Nothing has been sent anywhere. Review discover-export.ndjson, "
    "then upload it in the Discover app."
)

HEADER_KEYS = [
    "kind",
    "version",
    "vendor",
    "generatedAt",
    "pseudonymized",
    "hashAlgo",
    "script",
    "exportWindow",
    "userCountTotal",
    "skippedRows",
]

GRANT_KEYS = [
    "userRef",
    "consentType",
    "clientId",
    "appDisplayName",
    "scopes",
    "firstSeen",
    "lastUsed",
]

GOOGLE_AUDIT_REQUIRED_COLUMNS = ["time", "actorEmail", "clientId", "displayText", "scopes"]
# scopes is intentionally excluded here: per spec/discover-export-format-v1.md
# grant.scopes "May be empty" -- an empty scopes cell is valid input, not a
# malformed row, and must not be skipped the way a missing actorEmail is.
GOOGLE_AUDIT_REQUIRED_NONEMPTY_COLUMNS = ["time", "actorEmail", "clientId", "displayText"]
GOOGLE_USERS_REQUIRED_COLUMNS = ["email"]

OWNER_ONLY_MODE = stat.S_IRUSR | stat.S_IWUSR  # 0600


class ExportError(Exception):
    """Raised for any user-facing export failure (bad input, missing file, ...)."""


def normalize_email(email: str) -> str:
    return email.strip().lower()


def _is_blank(value) -> bool:
    """True when value is missing (None) or, if a string, empty/whitespace-only."""
    if value is None:
        return True
    if not isinstance(value, str):
        return False
    return value.strip() == ""


def derive_user_ref(salt_bytes: bytes, email: str, pseudonymized: bool) -> str:
    normalized = normalize_email(email)
    if not pseudonymized:
        return normalized
    digest = hmac.new(salt_bytes, normalized.encode("utf-8"), hashlib.sha256).hexdigest()
    return "user_" + digest[:16]


def dedupe_grants(raw_grants: list[dict]) -> list[dict]:
    """Collapse raw (event-level) grant rows into one entry per (email, clientId) --
    or, for an "AllPrincipals" row (no associated user), per clientId alone.

    Each raw grant dict has keys: email (str|None), clientId, appDisplayName,
    consentType ("Principal"|"AllPrincipals"), scopes (list[str]),
    firstSeen (str|None), lastUsed (str|None).

    Returns a list of dicts with the same shape, `scopes` deduplicated and
    sorted, `firstSeen`/`lastUsed` reduced to min/max of the non-null
    values seen. A "Principal" row and an "AllPrincipals" row for the same
    clientId are never merged with each other -- they key differently.
    """
    grouped: dict[tuple[str, str], dict] = {}
    for raw in raw_grants:
        if raw.get("consentType") == "AllPrincipals":
            key = ("\x00ALLPRINCIPALS\x00", raw["clientId"])
        else:
            key = (normalize_email(raw["email"]), raw["clientId"])

        entry = grouped.get(key)
        if entry is None:
            entry = {
                "email": raw.get("email"),
                "clientId": raw["clientId"],
                "appDisplayName": raw["appDisplayName"],
                "consentType": raw.get("consentType", "Principal"),
                "scopes": set(),
                "firstSeen": None,
                "lastUsed": None,
            }
            grouped[key] = entry

        entry["scopes"].update(raw["scopes"])

        first_seen = raw.get("firstSeen")
        if first_seen is not None and (entry["firstSeen"] is None or first_seen < entry["firstSeen"]):
            entry["firstSeen"] = first_seen

        last_used = raw.get("lastUsed")
        if last_used is not None and (entry["lastUsed"] is None or last_used > entry["lastUsed"]):
            entry["lastUsed"] = last_used

    return list(grouped.values())


def build_grant_objects(grouped_grants: list[dict], salt_bytes: bytes, pseudonymized: bool) -> list[dict]:
    grants = []
    for entry in grouped_grants:
        if entry["consentType"] == "AllPrincipals":
            user_ref = None
        else:
            user_ref = derive_user_ref(salt_bytes, entry["email"], pseudonymized)
        grants.append(
            {
                "userRef": user_ref,
                "email": entry["email"],
                "clientId": entry["clientId"],
                "appDisplayName": entry["appDisplayName"],
                "consentType": entry["consentType"],
                "scopes": sorted(entry["scopes"]),
                "firstSeen": entry["firstSeen"],
                "lastUsed": entry["lastUsed"],
            }
        )
    # A null userRef ("AllPrincipals") sorts as if it were "" -- see
    # spec/discover-export-format-v1.md "Grant line ordering".
    grants.sort(key=lambda g: (g["userRef"] or "", g["clientId"]))
    return grants


def dump_line(obj: dict, keys: list[str]) -> str:
    ordered = {k: obj[k] for k in keys}
    return json.dumps(ordered, ensure_ascii=False, separators=(", ", ": "))


# ---------------------------------------------------------------------------
# Google parsing
# ---------------------------------------------------------------------------


def parse_google_audit_csv(path: str) -> tuple[list[dict], list[str]]:
    """Parse a Google OAuth Token Audit CSV.

    Returns (raw_grants, warnings). Raises ExportError for a missing
    required column or a completely empty (headerless) file. A row with a
    missing, explicit-empty, or whitespace-only required value is skipped
    with a warning rather than raising.
    """
    try:
        fh = open(path, "r", encoding="utf-8", newline="")
    except OSError as exc:
        raise ExportError(f"cannot open audit CSV {path!r}: {exc}") from exc

    with fh:
        reader = csv.DictReader(fh)
        if reader.fieldnames is None:
            raise ExportError(f"audit CSV {path!r} has no header row")

        missing = [c for c in GOOGLE_AUDIT_REQUIRED_COLUMNS if c not in reader.fieldnames]
        if missing:
            raise ExportError(
                f"audit CSV {path!r} is missing required column(s): {', '.join(missing)}"
            )

        raw_grants: list[dict] = []
        warnings: list[str] = []
        for row_number, row in enumerate(reader, start=2):  # header is line 1
            values = {col: row.get(col) for col in GOOGLE_AUDIT_REQUIRED_COLUMNS}
            missing_values = [
                col
                for col in GOOGLE_AUDIT_REQUIRED_NONEMPTY_COLUMNS
                if (values.get(col) or "").strip() == ""
            ]
            if missing_values:
                warnings.append(
                    f"skipping malformed row {row_number} in {path!r}: "
                    f"missing/blank value(s) for {', '.join(missing_values)}"
                )
                continue

            scopes_value = values.get("scopes") or ""
            scopes = [s for s in scopes_value.split(" ") if s]
            raw_grants.append(
                {
                    "email": values["actorEmail"],
                    "clientId": values["clientId"],
                    "appDisplayName": values["displayText"],
                    "consentType": "Principal",
                    "scopes": scopes,
                    "firstSeen": values["time"],
                    "lastUsed": values["time"],
                }
            )

        return raw_grants, warnings


def _read_json(path: str) -> dict:
    try:
        with open(path, "r", encoding="utf-8") as fh:
            content = fh.read()
    except OSError as exc:
        raise ExportError(f"cannot open {path!r}: {exc}") from exc

    try:
        return json.loads(content)
    except json.JSONDecodeError as exc:
        raise ExportError(f"invalid JSON in {path!r}: {exc}") from exc


def _graph_values(document: dict, path: str) -> list[dict]:
    values = document.get("value")
    if not isinstance(values, list):
        raise ExportError(f"{path!r} is not a Graph list response (missing a top-level \"value\" array)")
    return values


def parse_app_role_assignments(
    path: str, users_by_id: dict[str, dict], sps_by_id: dict[str, dict]
) -> tuple[list[dict], list[str]]:
    """Parse an optional appRoleAssignments.json Graph list-response export.

    Produces raw grants in the same shape as the oauth2PermissionGrants
    path, so both feed the same dedupe_grants()/build_grant_objects()
    pass -- see spec/discover-export-format-v1.md "Grant sources".
    Returns (raw_grants, warnings).
    """
    doc = _read_json(path)
    assignments = _graph_values(doc, path)

    warnings: list[str] = []
    raw_grants: list[dict] = []
    for index, assignment in enumerate(assignments, start=1):
        principal_id = assignment.get("principalId")
        resource_id = assignment.get("resourceId")
        app_role_id = assignment.get("appRoleId")

        sp = sps_by_id.get(resource_id)
        if sp is None:
            warnings.append(
                f"skipping app role assignment {index} in {path!r}: "
                f"resourceId {resource_id!r} not found among service principals"
            )
            continue

        app_id = sp.get("appId")
        if _is_blank(app_id):
            warnings.append(
                f"skipping app role assignment {index} in {path!r}: "
                f"servicePrincipal {resource_id!r} has a missing/blank appId"
            )
            continue

        display_name = sp.get("displayName")
        if _is_blank(display_name):
            warnings.append(
                f"skipping app role assignment {index} in {path!r}: "
                f"servicePrincipal {resource_id!r} has a missing/blank displayName"
            )
            continue

        user = users_by_id.get(principal_id)
        if user is None:
            warnings.append(
                f"skipping app role assignment {index} in {path!r}: "
                f"principalId {principal_id!r} not found among users"
            )
            continue

        upn = user.get("userPrincipalName")
        if _is_blank(upn):
            warnings.append(
                f"skipping app role assignment {index} in {path!r}: "
                f"user {principal_id!r} has a missing/blank userPrincipalName"
            )
            continue

        roles_by_id = {
            role["id"]: role.get("value")
            for role in (sp.get("appRoles") or [])
            if isinstance(role, dict) and isinstance(role.get("id"), str)
        }
        role_value = roles_by_id.get(app_role_id)
        if _is_blank(role_value):
            role_value = app_role_id if not _is_blank(app_role_id) else "unknown"

        raw_grants.append(
            {
                "email": upn,
                "clientId": app_id,
                "appDisplayName": display_name,
                "consentType": "Principal",
                "scopes": [f"appRole:{role_value}"],
                "firstSeen": assignment.get("createdDateTime"),
                "lastUsed": None,
            }
        )

    return raw_grants, warnings


def parse_entra_triplet(
    users_path: str,
    service_principals_path: str,
    grants_path: str,
    app_role_assignments_path: Optional[str] = None,
) -> tuple[int, list[dict], list[str]]:
    """Parse a users/servicePrincipals/oauth2PermissionGrants Graph JSON triplet,
    plus an optional appRoleAssignments export.

    Returns (user_count_total, raw_grants, warnings). raw_grants have the
    same shape dedupe_grants() expects: email, clientId, appDisplayName,
    consentType, scopes, firstSeen, lastUsed.
    """
    users_doc = _read_json(users_path)
    sps_doc = _read_json(service_principals_path)
    grants_doc = _read_json(grants_path)

    users = _graph_values(users_doc, users_path)
    service_principals = _graph_values(sps_doc, service_principals_path)
    grants = _graph_values(grants_doc, grants_path)

    users_by_id = {u["id"]: u for u in users if "id" in u}
    sps_by_id = {sp["id"]: sp for sp in service_principals if "id" in sp}

    warnings: list[str] = []
    raw_grants: list[dict] = []
    for index, grant in enumerate(grants, start=1):
        client_object_id = grant.get("clientId")
        principal_id = grant.get("principalId")
        consent_type = "AllPrincipals" if grant.get("consentType") == "AllPrincipals" else "Principal"

        sp = sps_by_id.get(client_object_id)
        if sp is None:
            warnings.append(
                f"skipping grant {index} in {grants_path!r}: "
                f"clientId {client_object_id!r} not found in {service_principals_path!r}"
            )
            continue

        app_id = sp.get("appId")
        if _is_blank(app_id):
            warnings.append(
                f"skipping grant {index} in {grants_path!r}: "
                f"servicePrincipal {client_object_id!r} has a missing/blank appId"
            )
            continue

        display_name = sp.get("displayName")
        if _is_blank(display_name):
            warnings.append(
                f"skipping grant {index} in {grants_path!r}: "
                f"servicePrincipal {client_object_id!r} has a missing/blank displayName"
            )
            continue

        scope_string = grant.get("scope") or ""
        scopes = [s for s in scope_string.split(" ") if s]

        if consent_type == "AllPrincipals":
            # Tenant-wide admin consent: no associated user, never skipped,
            # never counted in skippedRows -- see spec "Grant object".
            raw_grants.append(
                {
                    "email": None,
                    "clientId": app_id,
                    "appDisplayName": display_name,
                    "consentType": "AllPrincipals",
                    "scopes": scopes,
                    "firstSeen": grant.get("createdDateTime"),
                    "lastUsed": None,
                }
            )
            continue

        user = users_by_id.get(principal_id)
        if user is None:
            warnings.append(
                f"skipping grant {index} in {grants_path!r}: "
                f"principalId {principal_id!r} not found in {users_path!r}"
            )
            continue

        upn = user.get("userPrincipalName")
        if _is_blank(upn):
            warnings.append(
                f"skipping grant {index} in {grants_path!r}: "
                f"user {principal_id!r} has a missing/blank userPrincipalName"
            )
            continue

        raw_grants.append(
            {
                "email": upn,
                "clientId": app_id,
                "appDisplayName": display_name,
                "consentType": "Principal",
                "scopes": scopes,
                "firstSeen": grant.get("createdDateTime"),
                "lastUsed": None,
            }
        )

    if app_role_assignments_path is not None:
        ar_raw_grants, ar_warnings = parse_app_role_assignments(
            app_role_assignments_path, users_by_id, sps_by_id
        )
        raw_grants.extend(ar_raw_grants)
        warnings.extend(ar_warnings)

    return len(users), raw_grants, warnings


def parse_google_users_csv(path: str) -> int:
    """Return the distinct user count from a Google Users CSV."""
    try:
        fh = open(path, "r", encoding="utf-8", newline="")
    except OSError as exc:
        raise ExportError(f"cannot open users CSV {path!r}: {exc}") from exc

    with fh:
        reader = csv.DictReader(fh)
        if reader.fieldnames is None:
            raise ExportError(f"users CSV {path!r} has no header row")

        missing = [c for c in GOOGLE_USERS_REQUIRED_COLUMNS if c not in reader.fieldnames]
        if missing:
            raise ExportError(
                f"users CSV {path!r} is missing required column(s): {', '.join(missing)}"
            )

        emails = {normalize_email(row["email"]) for row in reader if row.get("email")}
        return len(emails)


# ---------------------------------------------------------------------------
# Salt + output writing (shared across vendors)
# ---------------------------------------------------------------------------


def load_or_generate_salt(salt_file: Optional[str]) -> bytes:
    if salt_file is not None:
        try:
            with open(salt_file, "r", encoding="utf-8") as fh:
                salt_hex = fh.read().strip()
            return bytes.fromhex(salt_hex)
        except OSError as exc:
            raise ExportError(f"cannot open salt file {salt_file!r}: {exc}") from exc
        except ValueError as exc:
            raise ExportError(f"salt file {salt_file!r} does not contain valid hex: {exc}") from exc
    return secrets.token_bytes(32)


def write_outputs(
    out_dir: str,
    vendor: str,
    script_name: str,
    pseudonymized: bool,
    user_count_total: Optional[int],
    export_window,
    grant_objects: list[dict],
    salt_bytes: bytes,
    generated_at: str,
    skipped_rows: int,
) -> None:
    os.makedirs(out_dir, exist_ok=True)

    header = {
        "kind": DEF_KIND,
        "version": DEF_VERSION,
        "vendor": vendor,
        "generatedAt": generated_at,
        "pseudonymized": pseudonymized,
        "hashAlgo": HASH_ALGO,
        "script": script_name,
        "exportWindow": export_window,
        "userCountTotal": user_count_total,
        "skippedRows": skipped_rows,
    }

    lines = [dump_line(header, HEADER_KEYS)]
    for grant in grant_objects:
        lines.append(dump_line(grant, GRANT_KEYS))

    ndjson_path = os.path.join(out_dir, "discover-export.ndjson")
    with open(ndjson_path, "w", encoding="utf-8", newline="\n") as fh:
        fh.write("\n".join(lines) + "\n")

    if pseudonymized:
        salt_path = os.path.join(out_dir, "salt.txt")
        with open(salt_path, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(salt_bytes.hex() + "\n")
        os.chmod(salt_path, OWNER_ONLY_MODE)

        seen_emails = {}
        for grant in grant_objects:
            if grant["userRef"] is None:  # "AllPrincipals": no user to map
                continue
            seen_emails[grant["userRef"]] = grant["email"]

        mapping_path = os.path.join(out_dir, "mapping.csv")
        with open(mapping_path, "w", encoding="utf-8", newline="") as fh:
            writer = csv.writer(fh, lineterminator="\n")
            writer.writerow(["userRef", "email"])
            for user_ref, email in sorted(seen_emails.items()):
                writer.writerow([user_ref, normalize_email(email)])
        os.chmod(mapping_path, OWNER_ONLY_MODE)


def _generated_at() -> str:
    import datetime

    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _warn_if_empty_result(user_count_total: Optional[int], grant_objects: list[dict]) -> None:
    """Loud, non-fatal warning: a zero-record result may be a permission/consent
    problem, not a genuinely empty tenant -- see spec "Skipped-row / empty-result
    signals". Still exits 0; an empty tenant is a legitimate outcome.
    """
    if user_count_total == 0:
        print(
            "warning: 0 users were found in the source data -- this may indicate "
            "a permission or consent problem, not an empty tenant",
            file=sys.stderr,
        )
    if not grant_objects:
        print(
            "warning: 0 grants were found in the source data -- this may indicate "
            "a permission or consent problem, not an empty tenant",
            file=sys.stderr,
        )


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def run_google(args: argparse.Namespace) -> None:
    raw_grants, warnings = parse_google_audit_csv(args.audit_csv)
    for warning in warnings:
        print(f"warning: {warning}", file=sys.stderr)

    user_count_total = None
    if args.users_csv is not None:
        user_count_total = parse_google_users_csv(args.users_csv)

    pseudonymized = not args.no_pseudonymize
    salt_bytes = load_or_generate_salt(args.salt_file) if pseudonymized else b""

    grouped = dedupe_grants(raw_grants)
    grant_objects = build_grant_objects(grouped, salt_bytes, pseudonymized)

    _warn_if_empty_result(user_count_total, grant_objects)

    write_outputs(
        out_dir=args.out_dir,
        vendor="google",
        script_name="nc-export.py",
        pseudonymized=pseudonymized,
        user_count_total=user_count_total,
        export_window=None,
        grant_objects=grant_objects,
        salt_bytes=salt_bytes,
        generated_at=args.generated_at or _generated_at(),
        skipped_rows=len(warnings),
    )

    print(f"Skipped rows: {len(warnings)}")
    print(CLOSING_MESSAGE)


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="nc-export.py",
        description="Export a Google Workspace or Entra ID OAuth grant inventory to DEF v1.",
    )
    subparsers = parser.add_subparsers(dest="vendor", required=True)

    google = subparsers.add_parser("google", help="Export from a Google Workspace audit CSV export.")
    google.add_argument("--audit-csv", required=True, help="Path to the OAuth Token Audit Activity CSV export.")
    google.add_argument("--users-csv", default=None, help="Optional path to a Users CSV export.")
    google.add_argument("--out-dir", required=True, help="Directory to write DEF output into.")
    google.add_argument("--salt-file", default=None, help="Path to a fixed hex salt (for reproducible output).")
    google.add_argument(
        "--no-pseudonymize",
        action="store_true",
        help="Write raw email addresses as userRef instead of HMAC-SHA256 pseudonyms.",
    )
    google.add_argument(
        "--generated-at",
        default=None,
        help=argparse.SUPPRESS,  # reproducible-output override, used by the test suite
    )
    google.set_defaults(func=run_google)

    entra = subparsers.add_parser(
        "entra", help="Export from Microsoft Entra ID (file mode; live mode is PowerShell-only)."
    )
    entra.add_argument("--users-json", required=True, help="Path to a Graph users list-response JSON export.")
    entra.add_argument(
        "--service-principals-json", required=True, help="Path to a Graph servicePrincipals list-response JSON export."
    )
    entra.add_argument(
        "--grants-json", required=True, help="Path to a Graph oauth2PermissionGrants list-response JSON export."
    )
    entra.add_argument(
        "--app-role-assignments-json",
        default=None,
        help=(
            "Optional path to a Graph appRoleAssignments list-response JSON export. "
            "When omitted, app-role assignments are simply not included (back-compatible)."
        ),
    )
    entra.add_argument("--out-dir", required=True, help="Directory to write DEF output into.")
    entra.add_argument("--salt-file", default=None, help="Path to a fixed hex salt (for reproducible output).")
    entra.add_argument(
        "--no-pseudonymize",
        action="store_true",
        help="Write raw UPNs as userRef instead of HMAC-SHA256 pseudonyms.",
    )
    entra.add_argument(
        "--generated-at",
        default=None,
        help=argparse.SUPPRESS,  # reproducible-output override, used by the test suite
    )
    entra.set_defaults(func=run_entra)

    return parser


def run_entra(args: argparse.Namespace) -> None:
    user_count_total, raw_grants, warnings = parse_entra_triplet(
        args.users_json,
        args.service_principals_json,
        args.grants_json,
        args.app_role_assignments_json,
    )
    for warning in warnings:
        print(f"warning: {warning}", file=sys.stderr)

    pseudonymized = not args.no_pseudonymize
    salt_bytes = load_or_generate_salt(args.salt_file) if pseudonymized else b""

    grouped = dedupe_grants(raw_grants)
    grant_objects = build_grant_objects(grouped, salt_bytes, pseudonymized)

    _warn_if_empty_result(user_count_total, grant_objects)

    write_outputs(
        out_dir=args.out_dir,
        vendor="entra",
        script_name="nc-export-entra",
        pseudonymized=pseudonymized,
        user_count_total=user_count_total,
        export_window=None,
        grant_objects=grant_objects,
        salt_bytes=salt_bytes,
        generated_at=args.generated_at or _generated_at(),
        skipped_rows=len(warnings),
    )

    print(f"Skipped rows: {len(warnings)}")
    print(CLOSING_MESSAGE)


def main(argv: Optional[list[str]] = None) -> int:
    parser = build_arg_parser()
    args = parser.parse_args(argv)
    try:
        args.func(args)
    except ExportError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    except Exception as exc:  # noqa: BLE001 -- last-resort guard: never surface a raw traceback
        print(f"error: unexpected error: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
