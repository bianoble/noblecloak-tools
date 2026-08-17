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

    Live mode: omit all three of the above. The script calls Microsoft
    Graph directly via the Microsoft.Graph PowerShell SDK
    (Connect-MgGraph / Invoke-MgGraphRequest), requesting exactly the
    read-only scopes below, then feeds the same conversion path file mode
    uses -- there is exactly one place grants become DEF grant lines.

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
    [string]$OutDir,
    [string]$SaltFile,
    [switch]$NoPseudonymize,
    [string]$GeneratedAt
)

Set-StrictMode -Version Latest

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
# Dedup + grant object construction (vendor-agnostic given raw grants)
# ---------------------------------------------------------------------------

function ConvertTo-DedupedGrants {
    param([array]$RawGrants)
    $grouped = [ordered]@{}
    foreach ($raw in $RawGrants) {
        $key = (Get-NormalizedEmail $raw.Email) + "`0" + $raw.ClientId
        if (-not $grouped.Contains($key)) {
            $grouped[$key] = [ordered]@{
                Email          = $raw.Email
                ClientId       = $raw.ClientId
                AppDisplayName = $raw.AppDisplayName
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
        [pscustomobject]@{
            userRef        = Get-UserRef -SaltBytes $SaltBytes -Email $entry.Email -Pseudonymized $Pseudonymized
            email          = $entry.Email
            clientId       = $entry.ClientId
            appDisplayName = $entry.AppDisplayName
            scopes         = Sort-StringsOrdinal -Items @($entry.Scopes)
            firstSeen      = $entry.FirstSeen
            lastUsed       = $entry.LastUsed
        }
    }
    $arr = @($grants)
    $comparer = [System.Comparison[object]] {
        param($a, $b)
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

function Read-EntraJsonFile {
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "cannot open '$Path': file not found"
    }
    $raw = Get-Content -LiteralPath $Path -Raw
    try {
        return $raw | ConvertFrom-Json -Depth 20
    } catch {
        throw "invalid JSON in '$Path': $($_.Exception.Message)"
    }
}

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

function ConvertTo-Iso8601String {
    <#
    ConvertFrom-Json auto-detects ISO-8601-looking strings and silently
    turns them into [datetime] objects. DEF timestamps must stay strings,
    so undo that coercion for any field that went through this.
    #>
    param($Value)
    if ($null -eq $Value) { return $null }
    if ($Value -is [datetime]) { return $Value.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ') }
    return [string]$Value
}

function Resolve-EntraGrants {
    <#
    The single place raw Graph users/servicePrincipals/oauth2PermissionGrants
    arrays turn into DEF-shaped raw grants. Both file mode
    (Read-EntraFileTriplet) and live mode (Get-EntraLiveExport) call this
    -- there is no second, parallel parsing implementation.
    #>
    param([array]$Users, [array]$ServicePrincipals, [array]$Grants, [string]$SourceLabel)

    $usersById = @{}
    foreach ($u in $Users) { if ($u.id) { $usersById[$u.id] = $u } }
    $spsById = @{}
    foreach ($sp in $ServicePrincipals) { if ($sp.id) { $spsById[$sp.id] = $sp } }

    $warnings = [System.Collections.Generic.List[string]]::new()
    $rawGrants = [System.Collections.Generic.List[object]]::new()
    $index = 0
    # Deliberately no break/continue here: functions defined by a
    # dot-sourced script can lose loop-label association when invoked
    # from inside a test runner's own scriptblock nesting (see
    # https://github.com/pester/Pester/issues/2669), so branch with
    # if/else instead of early-exiting the loop.
    foreach ($grant in $Grants) {
        $index++
        $sp = $spsById[$grant.clientId]
        $user = $null
        if ($sp) { $user = $usersById[$grant.principalId] }

        if (-not $sp) {
            $warnings.Add("skipping grant $index in $SourceLabel : clientId '$($grant.clientId)' not found among servicePrincipals")
        } elseif (-not $user) {
            $warnings.Add("skipping grant $index in $SourceLabel : principalId '$($grant.principalId)' not found among users")
        } else {
            $scopeString = if ($grant.PSObject.Properties.Name -contains 'scope' -and $grant.scope) { $grant.scope } else { '' }
            $scopes = @($scopeString -split ' ' | Where-Object { $_ -ne '' })
            $createdDateTime = if ($grant.PSObject.Properties.Name -contains 'createdDateTime') { ConvertTo-Iso8601String $grant.createdDateTime } else { $null }

            $rawGrants.Add([pscustomobject]@{
                Email          = $user.userPrincipalName
                ClientId       = $sp.appId
                AppDisplayName = $sp.displayName
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

function Read-EntraFileTriplet {
    param([string]$UsersPath, [string]$ServicePrincipalsPath, [string]$GrantsPath)

    $usersDoc = Read-EntraJsonFile -Path $UsersPath
    $spDoc = Read-EntraJsonFile -Path $ServicePrincipalsPath
    $grantsDoc = Read-EntraJsonFile -Path $GrantsPath

    $users = Get-GraphValues -Document $usersDoc -Path $UsersPath
    $sps = Get-GraphValues -Document $spDoc -Path $ServicePrincipalsPath
    $grants = Get-GraphValues -Document $grantsDoc -Path $GrantsPath

    return Resolve-EntraGrants -Users $users -ServicePrincipals $sps -Grants $grants -SourceLabel "'$GrantsPath'"
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

    $users = @()
    $usersUri = 'https://graph.microsoft.com/v1.0/users?$select=id,userPrincipalName,displayName&$top=999'
    while ($usersUri) {
        $page = Invoke-MgGraphRequest -Method GET -Uri $usersUri
        $users += @($page.value)
        $usersUri = Get-GraphNextLink -Page $page
    }

    $servicePrincipals = @()
    $spUri = 'https://graph.microsoft.com/v1.0/servicePrincipals?$select=id,appId,displayName&$top=999'
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
    return Resolve-EntraGrants -Users $users -ServicePrincipals $servicePrincipals -Grants $grants -SourceLabel 'the live Graph response'
}

# ---------------------------------------------------------------------------
# Output writing
# ---------------------------------------------------------------------------

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
        [string]$GeneratedAtValue
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
    }
    $headerKeys = @('kind', 'version', 'vendor', 'generatedAt', 'pseudonymized', 'hashAlgo', 'script', 'exportWindow', 'userCountTotal')
    $grantKeys = @('userRef', 'clientId', 'appDisplayName', 'scopes', 'firstSeen', 'lastUsed')

    $lines = [System.Collections.Generic.List[string]]::new()
    $lines.Add((ConvertTo-DefLine -Obj $header -Keys $headerKeys))
    foreach ($grant in $GrantObjects) {
        $grantOrdered = [ordered]@{
            userRef        = $grant.userRef
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
        [string]$OutDir,
        [string]$SaltFile,
        [switch]$NoPseudonymize,
        [string]$GeneratedAt
    )
    try {
        if (-not $OutDir) { throw '-OutDir is required' }

        $fileModeParamCount = @($UsersJson, $ServicePrincipalsJson, $GrantsJson) | Where-Object { $_ } | Measure-Object | Select-Object -ExpandProperty Count

        if ($fileModeParamCount -eq 3) {
            $result = Read-EntraFileTriplet -UsersPath $UsersJson -ServicePrincipalsPath $ServicePrincipalsJson -GrantsPath $GrantsJson
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

        $generatedAtValue = if ($GeneratedAt) { $GeneratedAt } else { (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ') }

        Write-DefOutput -OutDir $OutDir -Vendor 'entra' -ScriptName 'nc-export-entra' -Pseudonymized $pseudonymized `
            -UserCountTotal $result.UserCountTotal -ExportWindow $null -GrantObjects $grantObjects -SaltBytes $saltBytes -GeneratedAtValue $generatedAtValue

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
