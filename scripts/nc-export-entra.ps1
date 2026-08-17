#!/usr/bin/env pwsh
<#
.SYNOPSIS
    Exports a Microsoft Entra ID OAuth grant inventory to Discover Export
    Format (DEF) v1.

.DESCRIPTION
    File mode (offline, zero network calls): pass -UsersJson,
    -ServicePrincipalsJson, and -GrantsJson pointing at exported Microsoft
    Graph list-response JSON (each a {"value": [...]} document) for
    /users, /servicePrincipals, and /oauth2PermissionGrants respectively.
    Optionally also pass -AppRoleAssignmentsJson (a Graph appRoleAssignments
    list-response export) to additionally include app-role grants -- this
    input is optional and back-compatible: omit it and the feature is
    simply off.

    Live mode: omit all three of -UsersJson/-ServicePrincipalsJson/-GrantsJson.
    The script calls Microsoft Graph directly via the Microsoft.Graph
    PowerShell SDK (Connect-MgGraph / Invoke-MgGraphRequest), requesting
    exactly the read-only scopes below, then feeds the same conversion path
    file mode uses -- there is exactly one place grants become DEF grant
    lines. Live mode additionally fetches app-role assignments per service
    principal (paged, filtered to principalType 'User').

    Live-mode scopes (read-only; must match spec/discover-export-format-v1.md
    and README.md -- see tests/powershell/NcExportEntraLive.Tests.ps1 for
    the drift check):
        User.Read.All
        Application.Read.All
        Directory.Read.All

    See spec/discover-export-format-v1.md for the exact output format.
    This script performs no network I/O in file mode.
#>
[CmdletBinding()]
param(
    [string]$UsersJson,
    [string]$ServicePrincipalsJson,
    [string]$GrantsJson,
    [string]$AppRoleAssignmentsJson,
    [string]$OutDir,
    [string]$SaltFile,
    [switch]$NoPseudonymize,
    [string]$GeneratedAt
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:LiveModeScopes = @('User.Read.All', 'Application.Read.All', 'Directory.Read.All')

# Printed to stdout after a successful run. This is the core trust/UX
# guarantee of the tool -- the operator gets explicit, on-screen
# confirmation that nothing left the machine. Kept identical (same text)
# to the closing message nc-export.py prints -- see
# spec/discover-export-format-v1.md and README.md's privacy model.
$script:ClosingMessage = 'Nothing has been sent anywhere. Review discover-export.ndjson, then upload it in the Discover app.'

# ---------------------------------------------------------------------------
# JSON serialization (hand-rolled to guarantee byte-identical output with
# nc-export.py: fixed key order, no ASCII-escaping of non-ASCII characters,
# "key": value with a single space after the colon, ", " between members).
# ---------------------------------------------------------------------------

function ConvertTo-JsonStringLiteral {
    param([string]$Value)
    $sb = [System.Text.StringBuilder]::new()
    [void]$sb.Append('"')
    foreach ($ch in $Value.ToCharArray()) {
        if ($ch -eq '"') {
            [void]$sb.Append('\"')
        } elseif ($ch -eq '\') {
            [void]$sb.Append('\\')
        } elseif ($ch -eq "`n") {
            [void]$sb.Append('\n')
        } elseif ($ch -eq "`r") {
            [void]$sb.Append('\r')
        } elseif ($ch -eq "`t") {
            [void]$sb.Append('\t')
        } else {
            $code = [int]$ch
            if ($code -lt 0x20) {
                [void]$sb.Append(('\u{0:x4}' -f $code))
            } else {
                [void]$sb.Append($ch)
            }
        }
    }
    [void]$sb.Append('"')
    return $sb.ToString()
}

function ConvertTo-JsonValue {
    param($Value)
    if ($null -eq $Value) { return 'null' }
    if ($Value -is [bool]) { if ($Value) { return 'true' } else { return 'false' } }
    if ($Value -is [int] -or $Value -is [long]) { return [string]$Value }
    if ($Value -is [string]) { return ConvertTo-JsonStringLiteral $Value }
    if ($Value -is [System.Collections.Specialized.OrderedDictionary] -or $Value -is [System.Collections.IDictionary]) {
        $parts = foreach ($k in $Value.Keys) { (ConvertTo-JsonStringLiteral $k) + ': ' + (ConvertTo-JsonValue $Value[$k]) }
        return '{' + ($parts -join ', ') + '}'
    }
    if ($Value -is [System.Collections.IEnumerable]) {
        $parts = foreach ($item in $Value) { ConvertTo-JsonValue $item }
        return '[' + ($parts -join ', ') + ']'
    }
    throw "unsupported value type for JSON serialization: $($Value.GetType())"
}

function ConvertTo-DefLine {
    param([System.Collections.Specialized.OrderedDictionary]$Obj, [string[]]$Keys)
    $parts = foreach ($k in $Keys) { (ConvertTo-JsonStringLiteral $k) + ': ' + (ConvertTo-JsonValue $Obj[$k]) }
    return '{' + ($parts -join ', ') + '}'
}

# ---------------------------------------------------------------------------
# JSON parsing that preserves raw string values verbatim (no [datetime]
# auto-coercion). ConvertFrom-Json (even with -AsHashtable) auto-detects
# ISO-8601-looking strings and silently turns them into [datetime] objects,
# which then re-serialize with second-level precision, truncating the
# fractional seconds real Graph timestamps carry (e.g.
# "2022-05-04T13:22:56.7315339Z" -> "2022-05-04T13:22:56Z"). That would
# break byte-parity with nc-export.py, which passes such strings through
# untouched. System.Text.Json.JsonDocument does no such coercion -- walk
# it by hand instead.
# ---------------------------------------------------------------------------

function ConvertFrom-JsonElement {
    param($Element)
    switch ($Element.ValueKind) {
        'Object' {
            $obj = [ordered]@{}
            foreach ($prop in $Element.EnumerateObject()) {
                $obj[$prop.Name] = ConvertFrom-JsonElement $prop.Value
            }
            return [pscustomobject]$obj
        }
        'Array' {
            $items = foreach ($item in $Element.EnumerateArray()) { ConvertFrom-JsonElement $item }
            # Comma-protected -- see the note on Sort-StringsOrdinal below.
            return ,@($items)
        }
        'String' { return $Element.GetString() }
        'Number' {
            $asLong = 0L
            if ($Element.TryGetInt64([ref]$asLong)) { return $asLong }
            return $Element.GetDouble()
        }
        'True' { return $true }
        'False' { return $false }
        'Null' { return $null }
        default { throw "unsupported JSON value kind: $($Element.ValueKind)" }
    }
}

function Read-EntraJsonFile {
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "cannot open '$Path': file not found"
    }
    $raw = Get-Content -LiteralPath $Path -Raw
    $doc = $null
    try {
        $doc = [System.Text.Json.JsonDocument]::Parse($raw)
        return ConvertFrom-JsonElement $doc.RootElement
    } catch {
        throw "invalid JSON in '$Path': $($_.Exception.Message)"
    } finally {
        if ($doc) { $doc.Dispose() }
    }
}

# ---------------------------------------------------------------------------
# Pseudonymization
# ---------------------------------------------------------------------------

function Get-NormalizedEmail {
    param([string]$Email)
    return $Email.Trim().ToLowerInvariant()
}

function ConvertFrom-HexString {
    param([string]$Hex)
    $len = $Hex.Length / 2
    $bytes = [byte[]]::new($len)
    for ($i = 0; $i -lt $len; $i++) {
        $bytes[$i] = [Convert]::ToByte($Hex.Substring($i * 2, 2), 16)
    }
    # Comma-protected: PowerShell unwraps a single-element array to its
    # scalar element when returned through the pipeline unless told not to.
    return ,$bytes
}

function ConvertTo-HexString {
    param([byte[]]$Bytes)
    return -join ($Bytes | ForEach-Object { $_.ToString('x2') })
}

function Get-UserRef {
    param([byte[]]$SaltBytes, [string]$Email, [bool]$Pseudonymized)
    $normalized = Get-NormalizedEmail $Email
    if (-not $Pseudonymized) { return $normalized }
    $hmac = [System.Security.Cryptography.HMACSHA256]::new($SaltBytes)
    try {
        $hash = $hmac.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($normalized))
    } finally {
        $hmac.Dispose()
    }
    return 'user_' + (ConvertTo-HexString $hash).Substring(0, 16)
}

function Get-OrCreateSalt {
    param([string]$SaltFile)
    if ($SaltFile) {
        if (-not (Test-Path -LiteralPath $SaltFile -PathType Leaf)) {
            throw "cannot open salt file '$SaltFile': file not found"
        }
        $hex = (Get-Content -LiteralPath $SaltFile -Raw).Trim()
        return ConvertFrom-HexString $hex
    }
    $bytes = [byte[]]::new(32)
    [System.Security.Cryptography.RandomNumberGenerator]::Fill($bytes)
    return ,$bytes
}

function Sort-StringsOrdinal {
    param([string[]]$Items)
    $arr = @($Items)
    [Array]::Sort($arr, [StringComparer]::Ordinal)
    # Comma-protected: without it, a 1-element $arr (e.g. a single OAuth
    # scope) would unwrap to a bare string on return, silently turning a
    # DEF "scopes" array into a scalar in the output JSON.
    return ,$arr
}

# ---------------------------------------------------------------------------
# Small helpers shared by the grant-resolution and app-role-resolution paths
# ---------------------------------------------------------------------------

function Test-NonBlankString {
    <# True only for a non-null string with at least one non-whitespace
       character. Set-StrictMode makes even reading a missing property
       throw, so every property read in this script goes through
       Get-PropertyOrNull first -- this is what makes a missing key,
       an explicit JSON null, and a whitespace-only value all collapse
       to the same "blank" outcome instead of a StrictMode crash. #>
    param($Value)
    if ($null -eq $Value) { return $false }
    if ($Value -isnot [string]) { return $false }
    return -not [string]::IsNullOrWhiteSpace($Value)
}

function Get-PropertyOrNull {
    param($Object, [string]$Name)
    if ($null -eq $Object) { return $null }
    if ($Object.PSObject.Properties.Name -contains $Name) { return $Object.$Name }
    return $null
}

function Build-IdIndex {
    <# id -> object lookup for a Graph "value" array, skipping any entry
       with a missing/blank "id". #>
    param([array]$Items)
    $index = @{}
    foreach ($item in $Items) {
        $id = Get-PropertyOrNull $item 'id'
        if (Test-NonBlankString $id) { $index[$id] = $item }
    }
    return $index
}

function ConvertTo-Iso8601String {
    <#
    Defensive pass-through: Read-EntraJsonFile already preserves raw JSON
    strings verbatim (no [datetime] coercion), so file-mode timestamps
    reach here as plain strings already. Live mode's Invoke-MgGraphRequest
    is outside this script's control and may hand back a [datetime] for
    some fields -- if so, round-trip it losslessly enough to stay a valid
    ISO-8601 string rather than crash. This is the single place any
    datetime-shaped value becomes the string DEF requires.
    #>
    param($Value)
    if ($null -eq $Value) { return $null }
    if ($Value -is [datetime]) { return $Value.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ') }
    return [string]$Value
}

# ---------------------------------------------------------------------------
# Dedup + grant object construction (vendor-agnostic given raw grants)
# ---------------------------------------------------------------------------

function ConvertTo-DedupedGrants {
    <# Collapses raw grant rows into one entry per (email, clientId) -- or,
       for an "AllPrincipals" row (no associated user), per clientId alone.
       A "Principal" row and an "AllPrincipals" row for the same clientId
       are never merged -- they key differently. #>
    param([array]$RawGrants)
    $grouped = [ordered]@{}
    foreach ($raw in $RawGrants) {
        if ($raw.ConsentType -eq 'AllPrincipals') {
            $key = "`0ALLPRINCIPALS`0" + $raw.ClientId
        } else {
            $key = (Get-NormalizedEmail $raw.Email) + "`0" + $raw.ClientId
        }
        if (-not $grouped.Contains($key)) {
            $grouped[$key] = [ordered]@{
                Email          = $raw.Email
                ClientId       = $raw.ClientId
                AppDisplayName = $raw.AppDisplayName
                ConsentType    = $raw.ConsentType
                Scopes         = [System.Collections.Generic.HashSet[string]]::new()
                FirstSeen      = $null
                LastUsed       = $null
            }
        }
        $entry = $grouped[$key]
        foreach ($s in $raw.Scopes) { [void]$entry.Scopes.Add($s) }

        if ($null -ne $raw.FirstSeen) {
            if ($null -eq $entry.FirstSeen -or [string]::CompareOrdinal($raw.FirstSeen, $entry.FirstSeen) -lt 0) {
                $entry.FirstSeen = $raw.FirstSeen
            }
        }
        if ($null -ne $raw.LastUsed) {
            if ($null -eq $entry.LastUsed -or [string]::CompareOrdinal($raw.LastUsed, $entry.LastUsed) -gt 0) {
                $entry.LastUsed = $raw.LastUsed
            }
        }
    }
    # Comma-protected -- see the note on Sort-StringsOrdinal above.
    return ,@($grouped.Values)
}

function ConvertTo-GrantObjects {
    param([array]$GroupedGrants, [byte[]]$SaltBytes, [bool]$Pseudonymized)
    $grants = foreach ($entry in $GroupedGrants) {
        $userRef = if ($entry.ConsentType -eq 'AllPrincipals') {
            $null
        } else {
            Get-UserRef -SaltBytes $SaltBytes -Email $entry.Email -Pseudonymized $Pseudonymized
        }
        [pscustomobject]@{
            userRef        = $userRef
            email          = $entry.Email
            clientId       = $entry.ClientId
            appDisplayName = $entry.AppDisplayName
            consentType    = $entry.ConsentType
            scopes         = Sort-StringsOrdinal -Items @($entry.Scopes)
            firstSeen      = $entry.FirstSeen
            lastUsed       = $entry.LastUsed
        }
    }
    $arr = @($grants)
    $comparer = [System.Comparison[object]] {
        param($a, $b)
        # A null userRef ("AllPrincipals") sorts as if it were "" -- see
        # spec/discover-export-format-v1.md "Grant line ordering".
        # [string]::CompareOrdinal already treats a null argument as
        # less than any non-null string, which is exactly that rule.
        $c = [string]::CompareOrdinal($a.userRef, $b.userRef)
        if ($c -ne 0) { return $c }
        return [string]::CompareOrdinal($a.clientId, $b.clientId)
    }
    [Array]::Sort($arr, $comparer)
    # Comma-protected -- see the note on Sort-StringsOrdinal above.
    return ,$arr
}

# ---------------------------------------------------------------------------
# Entra file mode
# ---------------------------------------------------------------------------

function Get-GraphValues {
    param($Document, [string]$Path)
    if ($null -eq $Document -or -not ($Document.PSObject.Properties.Name -contains 'value')) {
        throw "'$Path' is not a Graph list response (missing a top-level `"value`" array)"
    }
    # Comma-protected -- see the note on Sort-StringsOrdinal above. Without
    # it, a "value" array with exactly one user/servicePrincipal/grant
    # would unwrap to a bare object, breaking both .Count and foreach.
    return ,@($Document.value)
}

function Resolve-EntraGrants {
    <#
    The single place raw Graph users/servicePrincipals/oauth2PermissionGrants
    arrays turn into DEF-shaped raw grants. Both file mode
    (Read-EntraFileTriplet) and live mode (Get-EntraLiveExport) call this
    -- there is no second, parallel parsing implementation.
    #>
    param([array]$Users, [array]$ServicePrincipals, [array]$Grants, [string]$SourceLabel)

    $usersById = Build-IdIndex -Items $Users
    $spsById = Build-IdIndex -Items $ServicePrincipals

    $warnings = [System.Collections.Generic.List[string]]::new()
    $rawGrants = [System.Collections.Generic.List[object]]::new()
    $index = 0
    # Deliberately no break/continue here: functions defined by a
    # dot-sourced script can lose loop-label association when invoked
    # from inside a test runner's own scriptblock nesting (see
    # https://github.com/pester/Pester/issues/2669), so branch with
    # if/elseif instead of early-exiting the loop.
    foreach ($grant in $Grants) {
        $index++
        $clientObjectId = Get-PropertyOrNull $grant 'clientId'
        $principalId = Get-PropertyOrNull $grant 'principalId'
        $consentTypeRaw = Get-PropertyOrNull $grant 'consentType'
        $consentType = if ($consentTypeRaw -eq 'AllPrincipals') { 'AllPrincipals' } else { 'Principal' }

        $sp = $null
        if (Test-NonBlankString $clientObjectId) { $sp = $spsById[$clientObjectId] }
        $appId = Get-PropertyOrNull $sp 'appId'
        $displayName = Get-PropertyOrNull $sp 'displayName'

        $user = $null
        $upn = $null
        if ($consentType -ne 'AllPrincipals') {
            if (Test-NonBlankString $principalId) { $user = $usersById[$principalId] }
            $upn = Get-PropertyOrNull $user 'userPrincipalName'
        }

        if (-not $sp) {
            $warnings.Add("skipping grant $index in $SourceLabel : clientId '$clientObjectId' not found among servicePrincipals")
        } elseif (-not (Test-NonBlankString $appId)) {
            $warnings.Add("skipping grant $index in $SourceLabel : servicePrincipal '$clientObjectId' has a missing/blank appId")
        } elseif (-not (Test-NonBlankString $displayName)) {
            $warnings.Add("skipping grant $index in $SourceLabel : servicePrincipal '$clientObjectId' has a missing/blank displayName")
        } elseif ($consentType -ne 'AllPrincipals' -and -not $user) {
            $warnings.Add("skipping grant $index in $SourceLabel : principalId '$principalId' not found among users")
        } elseif ($consentType -ne 'AllPrincipals' -and -not (Test-NonBlankString $upn)) {
            $warnings.Add("skipping grant $index in $SourceLabel : user '$principalId' has a missing/blank userPrincipalName")
        } else {
            $scopeVal = Get-PropertyOrNull $grant 'scope'
            $scopeString = if ($scopeVal) { $scopeVal } else { '' }
            $scopes = @($scopeString -split ' ' | Where-Object { $_ -ne '' })
            $createdDateTime = ConvertTo-Iso8601String (Get-PropertyOrNull $grant 'createdDateTime')

            $rawGrants.Add([pscustomobject]@{
                Email          = if ($consentType -eq 'AllPrincipals') { $null } else { $upn }
                ClientId       = $appId
                AppDisplayName = $displayName
                ConsentType    = $consentType
                Scopes         = $scopes
                FirstSeen      = $createdDateTime
                LastUsed       = $null
            })
        }
    }

    return [pscustomobject]@{
        UserCountTotal = $Users.Count
        RawGrants      = @($rawGrants)
        Warnings       = @($warnings)
    }
}

function Resolve-AppRoleAssignments {
    <#
    Optional fourth grant source (spec "Grant sources"). Maps a Graph
    appRoleAssignment (id, principalId, resourceId, appRoleId,
    createdDateTime, principalType) to a DEF-shaped raw grant: userRef
    from principalId -> user; clientId/appDisplayName from the RESOURCE
    service principal (resourceId, not the assignment's own id); scopes =
    ["appRole:<role value>"], resolving appRoleId against the resource
    service principal's appRoles collection (falling back to the raw
    GUID). Both file mode (Read-EntraFileTriplet) and live mode
    (Get-EntraLiveExport) call this -- there is no second implementation.
    #>
    param([array]$Assignments, [hashtable]$UsersById, [hashtable]$SpsById, [string]$SourceLabel)

    $warnings = [System.Collections.Generic.List[string]]::new()
    $rawGrants = [System.Collections.Generic.List[object]]::new()
    $index = 0
    foreach ($assignment in $Assignments) {
        $index++
        $principalId = Get-PropertyOrNull $assignment 'principalId'
        $resourceId = Get-PropertyOrNull $assignment 'resourceId'
        $appRoleId = Get-PropertyOrNull $assignment 'appRoleId'

        $sp = $null
        if (Test-NonBlankString $resourceId) { $sp = $SpsById[$resourceId] }
        $appId = Get-PropertyOrNull $sp 'appId'
        $displayName = Get-PropertyOrNull $sp 'displayName'

        $user = $null
        if (Test-NonBlankString $principalId) { $user = $UsersById[$principalId] }
        $upn = Get-PropertyOrNull $user 'userPrincipalName'

        if (-not $sp) {
            $warnings.Add("skipping app role assignment $index in $SourceLabel : resourceId '$resourceId' not found among servicePrincipals")
        } elseif (-not (Test-NonBlankString $appId)) {
            $warnings.Add("skipping app role assignment $index in $SourceLabel : servicePrincipal '$resourceId' has a missing/blank appId")
        } elseif (-not (Test-NonBlankString $displayName)) {
            $warnings.Add("skipping app role assignment $index in $SourceLabel : servicePrincipal '$resourceId' has a missing/blank displayName")
        } elseif (-not $user) {
            $warnings.Add("skipping app role assignment $index in $SourceLabel : principalId '$principalId' not found among users")
        } elseif (-not (Test-NonBlankString $upn)) {
            $warnings.Add("skipping app role assignment $index in $SourceLabel : user '$principalId' has a missing/blank userPrincipalName")
        } else {
            $roleValue = $null
            $appRoles = Get-PropertyOrNull $sp 'appRoles'
            if ($appRoles) {
                foreach ($role in @($appRoles)) {
                    $roleId = Get-PropertyOrNull $role 'id'
                    if ($roleId -eq $appRoleId) {
                        $candidate = Get-PropertyOrNull $role 'value'
                        if (Test-NonBlankString $candidate) { $roleValue = $candidate }
                        break
                    }
                }
            }
            if (-not (Test-NonBlankString $roleValue)) {
                $roleValue = if (Test-NonBlankString $appRoleId) { $appRoleId } else { 'unknown' }
            }

            $rawGrants.Add([pscustomobject]@{
                Email          = $upn
                ClientId       = $appId
                AppDisplayName = $displayName
                ConsentType    = 'Principal'
                Scopes         = @("appRole:$roleValue")
                FirstSeen      = ConvertTo-Iso8601String (Get-PropertyOrNull $assignment 'createdDateTime')
                LastUsed       = $null
            })
        }
    }

    return [pscustomobject]@{
        RawGrants = @($rawGrants)
        Warnings  = @($warnings)
    }
}

function Read-EntraFileTriplet {
    param([string]$UsersPath, [string]$ServicePrincipalsPath, [string]$GrantsPath, [string]$AppRoleAssignmentsPath)

    $usersDoc = Read-EntraJsonFile -Path $UsersPath
    $spDoc = Read-EntraJsonFile -Path $ServicePrincipalsPath
    $grantsDoc = Read-EntraJsonFile -Path $GrantsPath

    $users = Get-GraphValues -Document $usersDoc -Path $UsersPath
    $sps = Get-GraphValues -Document $spDoc -Path $ServicePrincipalsPath
    $grants = Get-GraphValues -Document $grantsDoc -Path $GrantsPath

    $result = Resolve-EntraGrants -Users $users -ServicePrincipals $sps -Grants $grants -SourceLabel "'$GrantsPath'"

    if ($AppRoleAssignmentsPath) {
        $arDoc = Read-EntraJsonFile -Path $AppRoleAssignmentsPath
        $assignments = Get-GraphValues -Document $arDoc -Path $AppRoleAssignmentsPath
        $usersById = Build-IdIndex -Items $users
        $spsById = Build-IdIndex -Items $sps
        $arResult = Resolve-AppRoleAssignments -Assignments $assignments -UsersById $usersById -SpsById $spsById -SourceLabel "'$AppRoleAssignmentsPath'"
        $result = [pscustomobject]@{
            UserCountTotal = $result.UserCountTotal
            RawGrants      = @($result.RawGrants) + @($arResult.RawGrants)
            Warnings       = @($result.Warnings) + @($arResult.Warnings)
        }
    }

    return $result
}

# ---------------------------------------------------------------------------
# Entra live mode (Microsoft Graph via the Microsoft.Graph PowerShell SDK)
# ---------------------------------------------------------------------------

function Get-GraphNextLink {
    <# Set-StrictMode -Version Latest throws on a missing property accessed
       via dot/index notation, and the last page of a Graph collection has
       no "@odata.nextLink" at all -- so check before reading it. #>
    param($Page)
    if ($Page.PSObject.Properties.Name -contains '@odata.nextLink') {
        return $Page.'@odata.nextLink'
    }
    return $null
}

function Get-EntraLiveExport {
    Connect-MgGraph -Scopes $script:LiveModeScopes -NoWelcome | Out-Null

    # Fail loudly rather than silently exporting a partial/empty result if
    # the interactive consent the operator (or their admin) granted didn't
    # cover everything we asked for.
    $context = Get-MgContext
    $grantedScopes = @()
    if ($context -and $context.Scopes) { $grantedScopes = @($context.Scopes) }
    $missingScopes = @($script:LiveModeScopes | Where-Object { $grantedScopes -notcontains $_ })
    if ($missingScopes.Count -gt 0) {
        throw "Graph consent is missing required scope(s): $($missingScopes -join ', ') -- re-consent with the scopes listed in README.md"
    }

    $users = @()
    $usersUri = 'https://graph.microsoft.com/v1.0/users?$select=id,userPrincipalName,displayName&$top=999'
    while ($usersUri) {
        $page = Invoke-MgGraphRequest -Method GET -Uri $usersUri
        $users += @($page.value)
        $usersUri = Get-GraphNextLink -Page $page
    }

    $servicePrincipals = @()
    $spUri = 'https://graph.microsoft.com/v1.0/servicePrincipals?$select=id,appId,displayName,appRoles&$top=999'
    while ($spUri) {
        $page = Invoke-MgGraphRequest -Method GET -Uri $spUri
        $servicePrincipals += @($page.value)
        $spUri = Get-GraphNextLink -Page $page
    }

    $grants = @()
    $grantsUri = 'https://graph.microsoft.com/v1.0/oauth2PermissionGrants?$top=999'
    while ($grantsUri) {
        $page = Invoke-MgGraphRequest -Method GET -Uri $grantsUri
        $grants += @($page.value)
        $grantsUri = Get-GraphNextLink -Page $page
    }

    # Same conversion path as file mode: hand the materialized arrays to
    # Resolve-EntraGrants -- there is exactly one place Graph data becomes
    # DEF-shaped raw grants, used by both file mode and live mode.
    $result = Resolve-EntraGrants -Users $users -ServicePrincipals $servicePrincipals -Grants $grants -SourceLabel 'the live Graph response'

    # App-role assignments: one /servicePrincipals/{id}/appRoleAssignedTo
    # call per resource service principal, paged, filtered to
    # principalType 'User' (groups/other service principals aren't
    # something a DEF userRef can represent).
    $usersById = Build-IdIndex -Items $users
    $spsById = Build-IdIndex -Items $servicePrincipals
    $appRoleAssignments = [System.Collections.Generic.List[object]]::new()
    foreach ($sp in $servicePrincipals) {
        $spId = Get-PropertyOrNull $sp 'id'
        if (-not (Test-NonBlankString $spId)) { continue }
        $arUri = "https://graph.microsoft.com/v1.0/servicePrincipals/$spId/appRoleAssignedTo?`$top=999"
        while ($arUri) {
            $page = Invoke-MgGraphRequest -Method GET -Uri $arUri
            foreach ($assignment in @($page.value)) {
                $principalType = Get-PropertyOrNull $assignment 'principalType'
                if ($principalType -eq 'User') { $appRoleAssignments.Add($assignment) }
            }
            $arUri = Get-GraphNextLink -Page $page
        }
    }

    $arResult = Resolve-AppRoleAssignments -Assignments @($appRoleAssignments) -UsersById $usersById -SpsById $spsById -SourceLabel 'the live Graph appRoleAssignedTo response'

    return [pscustomobject]@{
        UserCountTotal = $result.UserCountTotal
        RawGrants      = @($result.RawGrants) + @($arResult.RawGrants)
        Warnings       = @($result.Warnings) + @($arResult.Warnings)
    }
}

# ---------------------------------------------------------------------------
# Output writing
# ---------------------------------------------------------------------------

function Write-EmptyResultWarningIfNeeded {
    <# Loud, non-fatal warning: a zero-record result may be a
       permission/consent problem, not a genuinely empty tenant -- see
       spec "Skipped-row / empty-result signals". Still exits 0. #>
    param($UserCountTotal, [array]$GrantObjects)
    if ($null -ne $UserCountTotal -and $UserCountTotal -eq 0) {
        Write-Warning '0 users were found in the source data -- this may indicate a permission or consent problem, not an empty tenant'
    }
    if (@($GrantObjects).Count -eq 0) {
        Write-Warning '0 grants were found in the source data -- this may indicate a permission or consent problem, not an empty tenant'
    }
}

function Write-DefOutput {
    param(
        [string]$OutDir,
        [string]$Vendor,
        [string]$ScriptName,
        [bool]$Pseudonymized,
        $UserCountTotal,
        $ExportWindow,
        [array]$GrantObjects,
        [byte[]]$SaltBytes,
        [string]$GeneratedAtValue,
        [int]$SkippedRows
    )
    New-Item -ItemType Directory -Path $OutDir -Force | Out-Null

    $header = [ordered]@{
        kind            = 'discover-export'
        version         = '1'
        vendor          = $Vendor
        generatedAt     = $GeneratedAtValue
        pseudonymized   = $Pseudonymized
        hashAlgo        = 'hmac-sha256'
        script          = $ScriptName
        exportWindow    = $ExportWindow
        userCountTotal  = $UserCountTotal
        skippedRows     = $SkippedRows
    }
    $headerKeys = @('kind', 'version', 'vendor', 'generatedAt', 'pseudonymized', 'hashAlgo', 'script', 'exportWindow', 'userCountTotal', 'skippedRows')
    $grantKeys = @('userRef', 'consentType', 'clientId', 'appDisplayName', 'scopes', 'firstSeen', 'lastUsed')

    $lines = [System.Collections.Generic.List[string]]::new()
    $lines.Add((ConvertTo-DefLine -Obj $header -Keys $headerKeys))
    foreach ($grant in $GrantObjects) {
        $grantOrdered = [ordered]@{
            userRef        = $grant.userRef
            consentType    = $grant.consentType
            clientId       = $grant.clientId
            appDisplayName = $grant.appDisplayName
            scopes         = $grant.scopes
            firstSeen      = $grant.firstSeen
            lastUsed       = $grant.lastUsed
        }
        $lines.Add((ConvertTo-DefLine -Obj $grantOrdered -Keys $grantKeys))
    }

    $utf8NoBom = [System.Text.UTF8Encoding]::new($false)
    $ndjsonPath = Join-Path $OutDir 'discover-export.ndjson'
    [System.IO.File]::WriteAllText($ndjsonPath, (($lines -join "`n") + "`n"), $utf8NoBom)

    if ($Pseudonymized) {
        $saltPath = Join-Path $OutDir 'salt.txt'
        [System.IO.File]::WriteAllText($saltPath, ((ConvertTo-HexString $SaltBytes) + "`n"), $utf8NoBom)

        $seen = [ordered]@{}
        foreach ($grant in $GrantObjects) {
            if ($null -eq $grant.userRef) { continue }  # "AllPrincipals": no user to map
            $seen[$grant.userRef] = (Get-NormalizedEmail $grant.email)
        }
        $keys = @($seen.Keys)
        [Array]::Sort($keys, [StringComparer]::Ordinal)

        $mappingLines = [System.Collections.Generic.List[string]]::new()
        $mappingLines.Add('userRef,email')
        foreach ($key in $keys) { $mappingLines.Add("$key,$($seen[$key])") }

        $mappingPath = Join-Path $OutDir 'mapping.csv'
        [System.IO.File]::WriteAllText($mappingPath, (($mappingLines -join "`n") + "`n"), $utf8NoBom)

        if (-not $IsWindows) {
            $ownerReadWrite = [System.IO.UnixFileMode]::UserRead -bor [System.IO.UnixFileMode]::UserWrite
            [System.IO.File]::SetUnixFileMode($saltPath, $ownerReadWrite)
            [System.IO.File]::SetUnixFileMode($mappingPath, $ownerReadWrite)
        }
    }
}

# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

function Start-NcExportEntra {
    param(
        [string]$UsersJson,
        [string]$ServicePrincipalsJson,
        [string]$GrantsJson,
        [string]$AppRoleAssignmentsJson,
        [string]$OutDir,
        [string]$SaltFile,
        [switch]$NoPseudonymize,
        [string]$GeneratedAt
    )
    try {
        if (-not $OutDir) { throw '-OutDir is required' }

        $fileModeParamCount = @($UsersJson, $ServicePrincipalsJson, $GrantsJson) | Where-Object { $_ } | Measure-Object | Select-Object -ExpandProperty Count

        if ($fileModeParamCount -eq 3) {
            $result = Read-EntraFileTriplet -UsersPath $UsersJson -ServicePrincipalsPath $ServicePrincipalsJson -GrantsPath $GrantsJson -AppRoleAssignmentsPath $AppRoleAssignmentsJson
        } elseif ($fileModeParamCount -eq 0) {
            $result = Get-EntraLiveExport
        } else {
            throw 'provide all of -UsersJson/-ServicePrincipalsJson/-GrantsJson for file mode, or none of them for live mode'
        }

        foreach ($w in $result.Warnings) { Write-Warning $w }

        $pseudonymized = -not $NoPseudonymize
        $saltBytes = if ($pseudonymized) { Get-OrCreateSalt -SaltFile $SaltFile } else { [byte[]]@() }

        $grouped = ConvertTo-DedupedGrants -RawGrants $result.RawGrants
        $grantObjects = ConvertTo-GrantObjects -GroupedGrants $grouped -SaltBytes $saltBytes -Pseudonymized $pseudonymized

        Write-EmptyResultWarningIfNeeded -UserCountTotal $result.UserCountTotal -GrantObjects $grantObjects

        $generatedAtValue = if ($GeneratedAt) { $GeneratedAt } else { (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ') }
        $skippedRows = @($result.Warnings).Count

        Write-DefOutput -OutDir $OutDir -Vendor 'entra' -ScriptName 'nc-export-entra' -Pseudonymized $pseudonymized `
            -UserCountTotal $result.UserCountTotal -ExportWindow $null -GrantObjects $grantObjects -SaltBytes $saltBytes `
            -GeneratedAtValue $generatedAtValue -SkippedRows $skippedRows

        [Console]::WriteLine("Skipped rows: $skippedRows")
        [Console]::WriteLine($script:ClosingMessage)

        return 0
    } catch {
        [Console]::Error.WriteLine("error: $($_.Exception.Message)")
        return 1
    }
}

if ($MyInvocation.InvocationName -ne '.') {
    exit (Start-NcExportEntra @PSBoundParameters)
}
