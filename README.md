# noblecloak-tools

Offline, zero-network export scripts that turn a Google Workspace or
Microsoft Entra ID OAuth-grant inventory into the [Discover Export Format
(DEF)](spec/discover-export-format-v1.md) — a small, pseudonymized NDJSON
file you hand to [NobleCloak Discover](https://docs.noblecloak.com) for
shadow-AI and third-party-app risk analysis.

GitHub org: bianoble

## Privacy model

- **Runs entirely on your machine.** `nc-export.py` and
  `nc-export-entra.ps1` never open a network socket in file mode. They read
  the audit exports you already have (or, for Entra, the live Graph API
  calls *you* initiate) and write NDJSON straight to local disk.
- **Pseudonymized by default.** Every user identifier is replaced with an
  HMAC-SHA256-derived `userRef` before it leaves your machine. The salt is
  generated locally, written once to `salt.txt`, and never transmitted.
  Pass `--no-pseudonymize` (Python) / `-NoPseudonymize` (PowerShell) only
  if your organization has decided raw email identifiers are acceptable to
  share.
- **A local mapping file, not a leak.** The `userRef -> email` mapping is
  written to `mapping.csv` next to the export, with owner-only file
  permissions. It stays on your machine; only the pseudonymized
  `discover-export.ndjson` is meant to be shared with NobleCloak Discover.
- **Nothing silently dropped.** Coverage-honesty fields (`exportWindow`,
  `userCountTotal`) are explicit and nullable rather than guessed, so a
  partial export is never mistaken for a complete one.
- **Explicit confirmation, every run.** Both scripts end a successful run
  by printing a `Skipped rows: N` summary line (always printed, even when
  `N` is `0`, so silent data loss is never invisible) immediately followed
  by "Nothing has been sent anywhere. Review discover-export.ndjson, then
  upload it in the Discover app." to stdout — so you don't have to take
  the privacy model on faith. A row with a missing, blank, or unresolvable
  identity field (email/UPN, client ID, app name) is skipped with a
  warning rather than silently mangled or dropped without a trace, and an
  entirely empty result (zero users or zero grants) prints a loud warning
  in case it signals a permission problem rather than a genuinely empty
  tenant.

Full format details: [`spec/discover-export-format-v1.md`](spec/discover-export-format-v1.md).

## Quick start

### Google Workspace

1. Export the Admin Console **Reports > OAuth Token Audit Activity** log to
   CSV, and (optionally) a **Users** CSV for an accurate `userCountTotal`.
2. Run:

   ```sh
   python3 scripts/nc-export.py google \
     --audit-csv oauth-token-audit.csv \
     --users-csv users.csv \
     --out-dir ./out
   ```
3. Share `./out/discover-export.ndjson` with NobleCloak Discover. Keep
   `./out/salt.txt` and `./out/mapping.csv` local.

### Microsoft Entra ID

**File mode** (offline, from exported Graph JSON):

```sh
pwsh scripts/nc-export-entra.ps1 \
  -UsersJson users.json \
  -ServicePrincipalsJson servicePrincipals.json \
  -GrantsJson oauth2PermissionGrants.json \
  -OutDir ./out
```

Or with the Python implementation of the same file-mode path:

```sh
python3 scripts/nc-export.py entra \
  --users-json users.json \
  --service-principals-json servicePrincipals.json \
  --grants-json oauth2PermissionGrants.json \
  --out-dir ./out
```

Both accept an **optional fourth input**, an exported
`appRoleAssignments.json` (`-AppRoleAssignmentsJson` / `--app-role-assignments-json`),
to additionally include app-role assignment grants alongside
`oauth2PermissionGrants`. Omit it and the feature is simply off —
this input is entirely back-compatible.

**Live mode** (calls Microsoft Graph directly via the `Microsoft.Graph`
PowerShell SDK):

```sh
pwsh scripts/nc-export-entra.ps1 -OutDir ./out
```

Live mode requests exactly these read-only scopes, and no others:

- `User.Read.All`
- `Application.Read.All`
- `Directory.Read.All`

This list is pinned in the script header and checked against this README
by `tests/powershell/NcExportEntraLive.Tests.ps1`, so the two can't drift
silently. Live mode also verifies, after consent, that all three scopes
were actually granted — and fails loudly (rather than silently exporting
a partial result) if any are missing. It additionally fetches app-role
assignments per service principal (`/servicePrincipals/{id}/appRoleAssignedTo`,
paged, filtered to `principalType 'User'`).

An Entra `oauth2PermissionGrants` row with `consentType: "AllPrincipals"`
(a tenant-wide admin consent grant, with no associated user) is emitted
as its own grant line with `userRef: null` and `consentType: "AllPrincipals"`
— never skipped, never counted toward `skippedRows`, never written to
`mapping.csv`.

Both modes write the same [DEF](spec/discover-export-format-v1.md) shape
as the Python/Google path, and `nc-export.py entra` (file mode only) is
kept byte-identical to `nc-export-entra.ps1` by CI — see
[`tests/parity`](tests/parity).

## Repository layout

| Path | Contents |
|---|---|
| `spec/` | The Discover Export Format (DEF) specification. |
| `scripts/` | The export scripts: `nc-export.py`, `nc-export-entra.ps1`. |
| `fixtures/` | Golden input/output scenarios used by every test suite. |
| `tests/python/` | Python unit + fixture-parity tests (`unittest`). |
| `tests/powershell/` | PowerShell unit + fixture-parity tests (Pester). |
| `tests/parity/` | Cross-language byte-identical parity tests. |
| `.github/workflows/` | CI (per-language) and the tagged-release workflow. |

## Development

Both languages' test runners are stdlib-only — no `pip install` or `npm
install` needed. Run everything CI runs, in one shot:

```sh
scripts/dev/ci-check.sh
```

This runs the Python unit + fixture-parity suites (`tests/python`,
`tests/parity`) and, if `pwsh` is on `PATH`, the PowerShell suite
(`tests/powershell`). It's a straight local reproduction of
[`ci-python.yml`, `ci-powershell.yml`, and `ci-parity.yml`](.github/workflows/) —
see the script for the exact commands.

## Docs

More background, threat model, and integration guidance:
https://docs.noblecloak.com
