# Discover Export Format (DEF) v1

DEF is the interchange format produced by `nc-export.py` and
`nc-export-entra.ps1` and consumed by NobleCloak Discover
(`bianoble-discover`). It is deliberately small, vendor-agnostic, and
line-delimited so it can be produced offline from an admin console export
with no SDKs beyond each language's standard library.

## Container format

- **Encoding:** UTF-8, no byte-order mark.
- **Line endings:** `\n` only (no `\r\n`), including the final line.
- **Shape:** newline-delimited JSON (NDJSON). Each line is one JSON object.
  - **Line 1** is the **header** (see below).
  - **Every subsequent line** is one **grant** record.
- **No trailing blank lines**, no comments, no non-JSON lines.
- **Byte-identical output is a requirement, not a nicety.** Producers MUST
  emit object keys in the exact order given below, MUST NOT escape
  non-ASCII characters (`ensure_ascii=False` in Python terms — a `é` in an
  app name is written as `é`, not `é`), and MUST NOT add whitespace
  beyond the single space after `:` and `,` that standard `json.dumps`
  produces. This is what makes it possible for the Python and PowerShell
  implementations to be checked byte-for-byte identical by CI.

## Header object

The first line of a DEF file. All fields are required keys; some are
nullable.

| Key | Type | Nullable | Notes |
|---|---|---|---|
| `kind` | string | no | Always the literal `"discover-export"`. |
| `version` | string | no | Always the literal `"1"` for this spec version. |
| `vendor` | string | no | `"google"` or `"entra"` — a closed enum. This intentionally mirrors the `auditConnectorEnum` pinned in `bianoble-discover/packages/discover-db/src/schema/scans.ts`; adding a vendor here requires updating both. |
| `generatedAt` | string | no | ISO-8601 UTC timestamp, e.g. `"2026-08-17T12:00:00Z"`, taken when the export script finished writing. |
| `pseudonymized` | boolean | no | `true` unless the operator explicitly opted out (`--no-pseudonymize` / `-NoPseudonymize`). |
| `hashAlgo` | string | no | Always the literal `"hmac-sha256"`, **even when `pseudonymized` is `false`** — it documents which algorithm *would* be used, keeping the header shape constant across both modes. |
| `script` | string | no | Identifies the producing *capability*, not necessarily the literal invoking filename: `"nc-export.py"` for the Google path (only one implementation exists), and `"nc-export-entra"` for the Entra path — used by **both** `nc-export.py entra` and `nc-export-entra.ps1`, since those two implementations are required to be byte-identical for the same input and this field must not be the thing that breaks that. |
| `exportWindow` | object or null | yes | `{"start": <ISO-8601>, "end": <ISO-8601>}` when the source data has a known time bound (e.g. the admin console audit log's retention window), otherwise `null`. Coverage-honesty field: a script MUST NOT guess this. |
| `userCountTotal` | integer or null | yes | Total distinct users in the source directory, when known (e.g. from a Users export/API call). `null` when no independent user count was available — this is normal, not an error, and MUST NOT be silently filled in from the grants seen. |
| `skippedRows` | integer | no | Count of source grant rows dropped (skipped, with a warning printed to stderr) while building this export — e.g. a Google audit CSV row missing a required value, or an Entra grant whose service principal or user could not be resolved or had a missing/blank identity field. **Never** `null` — always an integer, `0` when nothing was skipped. Does **not** count `"AllPrincipals"` grant lines (see below) — those are emitted, not skipped. Producers MUST also print this count to stdout as part of the closing summary (see "Side files" / script behavior), even when it is `0`, so an operator never has to infer silent data loss from a byte count. |

Key order in the emitted JSON object is exactly the table order above.

## Grant object

Every line after the header. Represents one (user, OAuth client)
authorization relationship, already deduplicated (see below) — except for
`"AllPrincipals"` grant lines, which represent a tenant-wide admin consent
grant with no associated user.

| Key | Type | Nullable | Notes |
|---|---|---|---|
| `userRef` | string | yes (only when `consentType` is `"AllPrincipals"`) | See "userRef derivation" below. |
| `consentType` | string | no | `"Principal"` or `"AllPrincipals"` — a closed enum. `"Principal"` is the ordinary per-user grant case. `"AllPrincipals"` marks an Entra `oauth2PermissionGrants` row where a tenant admin granted consent for an entire directory (`principalId` is `null` in the source) rather than one user; Google grants are always `"Principal"` (Google's audit log has no tenant-wide-consent concept). This field is a v1 addition: conceptually it is *optional* for a DEF consumer to understand — an implementation that predates it can treat an absent key as `"Principal"` implied — but **both current producers (`nc-export.py`, `nc-export-entra.ps1`) always emit it**, since the fixed-key-order/byte-identical requirement above means a producer cannot conditionally omit a key. |
| `clientId` | string | no | The vendor's stable OAuth client identifier (Google: the OAuth client ID string from the audit log; Entra: the service principal's `appId`, never its internal `objectId`). |
| `appDisplayName` | string | no | Human-readable app name, taken verbatim from the source (UTF-8, unescaped). |
| `scopes` | array of strings | no | The union of every OAuth scope seen for this (user, clientId) pair. May be empty. An app-role assignment (see "Grant sources" below) contributes a scope of the form `"appRole:<role value>"` (or `"appRole:<appRoleId GUID>"` when the role's display value can't be resolved). |
| `firstSeen` | string or null | yes | ISO-8601 timestamp of the earliest evidence of this grant, or `null` when the source has no such timestamp (e.g. Entra's `oauth2PermissionGrants` has no `createdDateTime` on older grants). Producers MUST pass this value through **verbatim** from the source (including fractional-second precision, e.g. `"2022-05-04T13:22:56.7315339Z"`) — never reformat, round, or truncate it. |
| `lastUsed` | string or null | yes | ISO-8601 timestamp of the most recent evidence of use, or `null` when unavailable. |

Key order in the emitted JSON object is exactly the table order above.

## `userRef` derivation

When `header.pseudonymized` is `true` (the default):

```
userRef = "user_" + hex(HMAC-SHA256(key = salt_bytes, message = normalized_email))[:16]
```

- `normalized_email` = the user's email/UPN, **lowercased and trimmed** of
  leading/trailing whitespace, encoded as UTF-8 bytes.
- `salt_bytes` = 32 cryptographically random bytes, generated locally by
  the script at run time, hex-encoded and written once to `salt.txt` (see
  "Side files" below). One salt per invocation — every `userRef` in a
  given export was derived with the same salt.
- The result: lowercase hex digest of the HMAC, truncated to its first 16
  hex characters, prefixed with `user_`. Matches `^user_[0-9a-f]{16}$`.

When `header.pseudonymized` is `false` (`--no-pseudonymize` /
`-NoPseudonymize`), `userRef` is the normalized email/UPN string itself
(lowercased, trimmed) — no hashing, no salt file, no mapping file.

`"AllPrincipals"` grant lines have no associated user at all: `userRef` is
always `null` for them, regardless of `pseudonymized`.

## Deduplication semantics

Source audit logs are typically one row per (user, client, scope, event)
— a single OAuth grant can appear many times. Producers MUST collapse
rows into one grant line per **(user, clientId)** pair — or, for
`"AllPrincipals"` grants, per **clientId** alone, since there is no user
to key on:

- **`scopes`**: the union (deduplicated) of every scope seen for that
  pair, sorted lexicographically by Unicode code point (i.e. ordinal
  string sort — `"A" < "a"`, ASCII order). This keeps the array
  deterministic and byte-identical across implementations regardless of
  source row order.
- **`firstSeen`**: the minimum of all non-null timestamps seen for that
  pair; `null` only if every source row had a null/missing timestamp.
- **`lastUsed`**: the maximum of all non-null timestamps seen for that
  pair; `null` only if every source row had a null/missing timestamp.
- **`appDisplayName`**: the display name as seen on any row for that
  `clientId` (source data is expected to be consistent per client).

A `"Principal"` grant and an `"AllPrincipals"` grant for the same
`clientId` are **never** merged with each other (they key differently —
one includes the user, the other doesn't) — they appear as two separate
grant lines.

## Grant line ordering

After deduplication, grant lines are emitted sorted ascending by the tuple
`(userRef, clientId)`, both compared as plain Unicode code-point string
sort, **treating a `null` `userRef` as the empty string `""`** for
ordering purposes only (this never collides with a real `userRef`, which
is always non-empty). In practice this means `"AllPrincipals"` grant
lines sort before every `"Principal"` grant line for a given salt, since
`""` is a prefix of (and therefore orders before) every non-empty
`userRef`. This — combined with the deterministic `userRef` derivation
and the sorted `scopes` array — is what makes two independent, correct
implementations produce byte-identical output from the same input and
salt.

## Grant sources

A grant line can be built from more than one kind of source row, as long
as the (user, clientId) dedup/merge semantics above are applied uniformly
across all of them:

- **OAuth2 permission grants** (Google audit log rows; Entra
  `oauth2PermissionGrants`) — the baseline case described above.
- **App role assignments** (Entra `appRoleAssignments`, optional —
  see `nc-export.py entra --app-role-assignments-json` / `-AppRoleAssignmentsJson`
  in `nc-export-entra.ps1`) — one row per (user, resource app) app-role
  grant. Mapped as: `userRef` from `principalId` → the assigned user;
  `clientId`/`appDisplayName` from the **resource** service principal
  (`resourceId`, never the assignment's own `id`); `scopes` = a single
  `["appRole:<role value>"]` entry, resolving `appRoleId` against the
  resource service principal's `appRoles` collection (falling back to the
  raw `appRoleId` GUID if the role can't be resolved); `firstSeen` =
  `createdDateTime`; `lastUsed` = `null`. An app-role row for the same
  (user, clientId) pair as an OAuth2 permission grant is merged into the
  same grant line (scope union), not emitted as a separate line. This
  input is entirely optional and back-compatible: when absent, this
  source contributes nothing and the feature is simply off.

## Side files (pseudonymized mode only)

When `pseudonymized` is `true`, the script additionally writes, next to
`discover-export.ndjson`:

- **`salt.txt`** — the hex-encoded salt used for this run, and nothing
  else (no trailing newline requirement beyond a single `\n`).
- **`mapping.csv`** — one row per distinct user: `userRef,email` header
  followed by data rows. This file, along with `salt.txt`, is what lets
  the operator re-identify a `userRef` locally; neither file is meant to
  leave the machine that produced them. `"AllPrincipals"` grants
  contribute no row to `mapping.csv` (there is no user to map).

Both files are written with owner-only permissions (mode `0600`) on
POSIX systems. When `pseudonymized` is `false`, **neither file is
written at all**.

## Skipped-row / empty-result signals (script behavior, not file format)

These are behavioral requirements on the two producer scripts, not part
of the NDJSON file shape:

- Both scripts print a summary line to stdout after a successful run —
  e.g. `Skipped rows: 3` (or `Skipped rows: 0`) — reporting the same
  count as `header.skippedRows`, immediately followed by the existing
  "Nothing has been sent anywhere..." closing message.
- If the resolved user count (`userCountTotal`, when known) or the final
  grant count is `0`, both scripts print a prominent warning to stderr
  that an empty result may indicate a permission/consent problem rather
  than a genuinely empty tenant. The script still exits `0` — an empty
  tenant is a legitimate outcome, not an error.

## Vendor enum

`vendor` is a closed enum: `"google"` and `"entra"` only, matching
`auditConnectorEnum` in `bianoble-discover`. This is enforced by every
implementation and by `tests/python/def_validator.py`.
