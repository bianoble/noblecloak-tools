#Requires -Modules Pester

<#
Live-Graph-mode tests for nc-export-entra.ps1 (T1 task 8).

See tests/powershell/NcExportEntra.Tests.ps1 for why script dot-sourcing
and shared variables live inside a single top-level BeforeAll rather than
at file (Discovery-time) scope.
#>

BeforeAll {
    $script:RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..' '..')).Path
    $script:ScriptPath = Join-Path $script:RepoRoot 'scripts' 'nc-export-entra.ps1'
    $script:ScriptSource = Get-Content -LiteralPath $script:ScriptPath -Raw
    $script:ReadmePath = Join-Path $script:RepoRoot 'README.md'
    $script:ReadmeSource = Get-Content -LiteralPath $script:ReadmePath -Raw
    $script:SpecSource = Get-Content -LiteralPath (Join-Path $script:RepoRoot 'spec' 'discover-export-format-v1.md') -Raw

    . $script:ScriptPath

    function Connect-MgGraph { param([string[]]$Scopes, [switch]$NoWelcome) }
    function Invoke-MgGraphRequest { param([string]$Method, [string]$Uri) }
    function Get-MgContext { }

    # Default: fully consented. Individual tests override with their own
    # Mock Get-MgContext for the missing-scope case.
    Mock Get-MgContext { return [pscustomobject]@{ Scopes = @('User.Read.All', 'Application.Read.All', 'Directory.Read.All') } }
}

Describe 'nc-export-entra.ps1 live mode scopes' {
    It 'calls Connect-MgGraph with exactly the documented read-only scopes' {
        Mock Connect-MgGraph { } -ParameterFilter {
            $null -eq (Compare-Object $Scopes @('User.Read.All', 'Application.Read.All', 'Directory.Read.All'))
        }
        Mock Invoke-MgGraphRequest { return [pscustomobject]@{ value = @() } }

        $outDir = Join-Path ([System.IO.Path]::GetTempPath()) ([System.Guid]::NewGuid().ToString())
        try {
            $code = Start-NcExportEntra -OutDir $outDir -GeneratedAt '2026-08-17T00:00:00Z'
            $code | Should -Be 0
            Should -Invoke Connect-MgGraph -Times 1
        } finally {
            if (Test-Path $outDir) { Remove-Item -Recurse -Force $outDir }
        }
    }
}

Describe 'nc-export-entra.ps1 live mode scope verification' {
    It 'fails loudly (non-zero exit, no output) when Graph consent is missing a required scope' {
        # Brief item 7(d): after Connect-MgGraph, compare granted scopes
        # (Get-MgContext).Scopes against requested and fail loudly on
        # missing ones, rather than silently exporting a partial result.
        Mock Connect-MgGraph { }
        Mock Get-MgContext { return [pscustomobject]@{ Scopes = @('User.Read.All') } }
        Mock Invoke-MgGraphRequest { return [pscustomobject]@{ value = @() } }

        $outDir = Join-Path ([System.IO.Path]::GetTempPath()) ([System.Guid]::NewGuid().ToString())
        $sw = [System.IO.StringWriter]::new()
        $origErr = [Console]::Error
        try {
            [Console]::SetError($sw)
            $code = Start-NcExportEntra -OutDir $outDir -GeneratedAt '2026-08-17T00:00:00Z'
        } finally {
            [Console]::SetError($origErr)
        }
        try {
            $code | Should -Not -Be 0
            $sw.ToString() | Should -Match 'Application\.Read\.All'
            (Test-Path $outDir) | Should -Be $false
        } finally {
            if (Test-Path $outDir) { Remove-Item -Recurse -Force $outDir }
        }
    }
}

Describe 'nc-export-entra.ps1 live mode / docs scope drift' {
    It 'declares the same scope list in the script source as documented in README.md' {
        # Static check: catches script/docs drift without needing a live tenant.
        $expectedScopeLiteral = [regex]::Escape("@('User.Read.All', 'Application.Read.All', 'Directory.Read.All')")
        $script:ScriptSource | Should -Match $expectedScopeLiteral
        $script:ReadmeSource | Should -Match 'User\.Read\.All'
        $script:ReadmeSource | Should -Match 'Application\.Read\.All'
        $script:ReadmeSource | Should -Match 'Directory\.Read\.All'
    }
}

Describe 'nc-export-entra.ps1 live mode shares the file-mode conversion path' {
    It 'has exactly one grant-resolution implementation (Resolve-EntraGrants), used by both modes' {
        $defCount = ([regex]::Matches($script:ScriptSource, 'function Resolve-EntraGrants')).Count
        $defCount | Should -Be 1

        $script:ScriptSource | Should -Match 'Get-EntraLiveExport[\s\S]*?Resolve-EntraGrants'
        $script:ScriptSource | Should -Match 'Read-EntraFileTriplet[\s\S]*?Resolve-EntraGrants'
    }

    It 'materializes the same users/servicePrincipals/oauth2PermissionGrants shape as file mode' {
        Mock Connect-MgGraph { }
        Mock Invoke-MgGraphRequest {
            param($Method, $Uri)
            if ($Uri -like '*appRoleAssignedTo*') {
                return [pscustomobject]@{ value = @() }
            } elseif ($Uri -like '*/users*') {
                return [pscustomobject]@{ value = @(
                    [pscustomobject]@{ id = 'u1'; userPrincipalName = 'alice@contoso.com'; displayName = 'Alice' }
                ) }
            } elseif ($Uri -like '*servicePrincipals*') {
                return [pscustomobject]@{ value = @(
                    [pscustomobject]@{ id = 'sp1'; appId = 'aaaa1111-aaaa-1111-aaaa-111111111111'; displayName = 'Slack' }
                ) }
            } else {
                return [pscustomobject]@{ value = @(
                    [pscustomobject]@{ id = 'g1'; clientId = 'sp1'; principalId = 'u1'; resourceId = 'r1'; scope = 'User.Read'; createdDateTime = '2026-01-10T00:00:00Z' }
                ) }
            }
        }

        $outDir = Join-Path ([System.IO.Path]::GetTempPath()) ([System.Guid]::NewGuid().ToString())
        try {
            $code = Start-NcExportEntra -OutDir $outDir -SaltFile (Join-Path $script:RepoRoot 'fixtures' 'entra' 'scenario-basic' 'salt.txt') -GeneratedAt '2026-08-17T00:00:00Z'
            $code | Should -Be 0
            $lines = Get-Content -LiteralPath (Join-Path $outDir 'discover-export.ndjson')
            $header = $lines[0] | ConvertFrom-Json
            $header.userCountTotal | Should -Be 1
            $header.vendor | Should -Be 'entra'
            $grant = $lines[1] | ConvertFrom-Json
            $grant.clientId | Should -Be 'aaaa1111-aaaa-1111-aaaa-111111111111'
            $grant.scopes | Should -Be @('User.Read')
        } finally {
            if (Test-Path $outDir) { Remove-Item -Recurse -Force $outDir }
        }
    }
}

Describe 'nc-export-entra.ps1 live mode app role assignments' {
    It 'fetches appRoleAssignedTo per service principal, filters to principalType User, and merges into grants' {
        # Brief item 5: PS live mode additionally fetches app role
        # assignments via /servicePrincipals/{id}/appRoleAssignedTo, paged,
        # filtered to principalType 'User', and merges them with the
        # oauth2PermissionGrants-derived grants via the same dedupe path.
        Mock Connect-MgGraph { }
        Mock Invoke-MgGraphRequest {
            param($Method, $Uri)
            if ($Uri -like '*servicePrincipals/sp1/appRoleAssignedTo*') {
                return [pscustomobject]@{ value = @(
                    [pscustomobject]@{ id = 'ara1'; principalId = 'u1'; resourceId = 'sp1'; appRoleId = 'role-guid'; createdDateTime = '2026-04-01T00:00:00Z'; principalType = 'User' }
                    [pscustomobject]@{ id = 'ara2'; principalId = 'group1'; resourceId = 'sp1'; appRoleId = 'role-guid'; createdDateTime = '2026-04-02T00:00:00Z'; principalType = 'Group' }
                ) }
            } elseif ($Uri -like '*/users*') {
                return [pscustomobject]@{ value = @(
                    [pscustomobject]@{ id = 'u1'; userPrincipalName = 'alice@contoso.com'; displayName = 'Alice' }
                ) }
            } elseif ($Uri -like '*servicePrincipals*') {
                return [pscustomobject]@{ value = @(
                    [pscustomobject]@{ id = 'sp1'; appId = 'aaaa1111-aaaa-1111-aaaa-111111111111'; displayName = 'Slack'; appRoles = @(
                        [pscustomobject]@{ id = 'role-guid'; value = 'Reader' }
                    ) }
                ) }
            } else {
                return [pscustomobject]@{ value = @() }
            }
        }

        $outDir = Join-Path ([System.IO.Path]::GetTempPath()) ([System.Guid]::NewGuid().ToString())
        try {
            $code = Start-NcExportEntra -OutDir $outDir -SaltFile (Join-Path $script:RepoRoot 'fixtures' 'entra' 'scenario-basic' 'salt.txt') -GeneratedAt '2026-08-17T00:00:00Z'
            $code | Should -Be 0
            $lines = Get-Content -LiteralPath (Join-Path $outDir 'discover-export.ndjson')
            $lines.Count | Should -Be 2  # header + 1 grant (the Group-typed assignment must be filtered out)
            $grant = $lines[1] | ConvertFrom-Json
            $grant.clientId | Should -Be 'aaaa1111-aaaa-1111-aaaa-111111111111'
            $grant.scopes | Should -Be @('appRole:Reader')
        } finally {
            if (Test-Path $outDir) { Remove-Item -Recurse -Force $outDir }
        }
    }
}
