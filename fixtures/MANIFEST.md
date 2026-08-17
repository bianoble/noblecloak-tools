# Fixture manifest

Golden input/output scenarios used by every test suite in this repo
(`tests/python`, `tests/powershell`, `tests/parity`). Every scenario
directory has the shape:

```
fixtures/<vendor>/<scenario>/
  input/            vendor-specific source files (CSV for google, JSON for entra)
  salt.txt          hex-encoded HMAC salt fixed for this scenario, for determinism
  golden/discover-export.ndjson   the expected DEF v1 output
```

Golden files are hand-authored against
[`spec/discover-export-format-v1.md`](../spec/discover-export-format-v1.md)
and validated structurally by `tests/python/test_fixture_manifest.py`.
They are the single oracle both `nc-export.py` and `nc-export-entra.ps1`
are checked against — see `tests/python/test_fixture_parity_*.py`,
`tests/powershell/NcExportEntra.Tests.ps1`, and
`tests/parity/test_cross_language_parity.py`.

## Scenarios

| Scenario | google | entra | Exercises |
|---|---|---|---|
| `scenario-basic` | yes | yes | Straightforward multi-user, multi-app export. |
| `scenario-duplicate-grants` | yes | yes | Same (user, clientId) seen more than once — dedup, scope union, firstSeen=min/lastUsed=max. |
| `scenario-unicode-appnames` | yes | yes | Non-ASCII app display names round-trip byte-for-byte, unescaped. |
| `scenario-empty-grants` | yes | yes | Zero grant rows in the source; header-only NDJSON output; `userCountTotal` still populated from the users source; triggers the "0 grants" empty-result warning. |
| `scenario-blank-identity-fields` | yes | yes | Missing-key/explicit-null/whitespace-only identity fields (Google: `actorEmail`/`clientId`/`displayText`; Entra: `userPrincipalName`/`appId`/`displayName`) are skipped with a warning and counted in `skippedRows`, never crash, never produce an empty-string `userRef`. |
| `scenario-no-users-file` | yes | no | No `--users-csv` given; `userCountTotal` is `null`. |
| `scenario-no-pseudonymize` | yes | no | `--no-pseudonymize`; `userRef` is the raw email, `pseudonymized: false`, no `mapping.csv`/`salt.txt` written by the script. |
| `scenario-no-firstseen` | no | yes | A grant with no `createdDateTime` — `firstSeen` is `null` (documents the Graph property gap). |
| `scenario-fractional-seconds` | no | yes | `createdDateTime` with 7-digit fractional seconds (real Graph shape, e.g. `2022-05-04T13:22:56.7315339Z`) — must round-trip byte-for-byte, not get truncated to whole seconds. |
| `scenario-allprincipals-grant` | no | yes | An `oauth2PermissionGrants` row with `consentType: "AllPrincipals"` (tenant-wide admin consent, `principalId` null) — emitted with `userRef: null`, not skipped, not counted in `skippedRows`, not written to `mapping.csv`. |
| `scenario-app-role-assignments` | no | yes | Optional `appRoleAssignments.json` fourth input — one assignment merges (scope union) into an existing `oauth2PermissionGrants`-derived grant line for the same (user, clientId); another resolves a role whose GUID isn't in the resource SP's `appRoles` collection, falling back to the raw GUID. |

## Version lockstep

| Component | Version |
|---|---|
| DEF spec | v1 (`spec/discover-export-format-v1.md`) |
| Fixture set | 1 (this manifest) |

Fixtures are versioned in lockstep with the DEF spec: a spec change that
alters output shape requires regenerating every golden file in the same
change, and bumping both version markers together. Consumers outside this
repo (e.g. `bianoble-discover`'s ingestion path) that pin against these
fixtures should pin against a released tag — see the repo's `release.yml`
workflow, which publishes a SHA-256 checksum of `spec/discover-export-format-v1.md`
alongside each tagged release so a fixture-set/spec mismatch is detectable
without diffing the whole file.
