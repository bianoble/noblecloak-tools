#Requires -Modules Pester

<#
File-mode tests for nc-export-entra.ps1 (T1 task 7).

The script is dot-sourced so its functions (in particular
Start-NcExportEntra) are callable directly with in-process return codes,
rather than exit codes from a spawned process -- this is what lets the
live-mode tests (task 8) Mock Connect-MgGraph / Invoke-MgGraphRequest.
#>

# $Scenarios must be computed at file (discovery-time) scope because
# Pester's -ForEach on It is evaluated during the discovery pass, before
# any BeforeAll runs.
$Scenarios = Get-ChildItem -Path (Join-Path $PSScriptRoot '..' '..' 'fixtures' 'entra') -Directory | Sort-Object Name

# Everything else lives in ONE top-level BeforeAll, and is recomputed
# there from $PSScriptRoot rather than read from an outer top-level
# variable: dot-sourcing a script via a variable that was assigned
# *outside* BeforeAll breaks in both Pester 5 (the variable resolves to
# $null at Run time) and Pester 6 (a spurious "break/continue statement
# ... escaped from your code" -- see pester/Pester#2669). A variable
# assigned *inside* BeforeAll itself does not have this problem.
BeforeAll {
    $repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..' '..')).Path
    $script:FixturesRoot = Join-Path $repoRoot 'fixtures' 'entra'
    $script:GoldenGeneratedAt = '2026-08-17T00:00:00Z'

    . (Join-Path $repoRoot 'scripts' 'nc-export-entra.ps1')

    function Invoke-EntraFileScenario {
        param([string]$ScenarioDir, [string]$OutDir, [switch]$NoPseudonymize)
        $inputDir = Join-Path $ScenarioDir 'input'
        $params = @{
            UsersJson              = Join-Path $inputDir 'users.json'
            ServicePrincipalsJson  = Join-Path $inputDir 'servicePrincipals.json'
            GrantsJson             = Join-Path $inputDir 'oauth2PermissionGrants.json'
            OutDir                 = $OutDir
            GeneratedAt            = $script:GoldenGeneratedAt
        }
        $appRoleAssignmentsPath = Join-Path $inputDir 'appRoleAssignments.json'
        if (Test-Path -LiteralPath $appRoleAssignmentsPath -PathType Leaf) {
            $params['AppRoleAssignmentsJson'] = $appRoleAssignmentsPath
        }
        if ($NoPseudonymize) {
            $params['NoPseudonymize'] = $true
        } else {
            $params['SaltFile'] = Join-Path $ScenarioDir 'salt.txt'
        }
        return Start-NcExportEntra @params
    }
}

Describe 'nc-export-entra.ps1 file mode parity' {
    It 'reproduces golden/discover-export.ndjson byte-for-byte for <_.Name>' -ForEach $Scenarios {
        $scenarioDir = $_.FullName
        $outDir = Join-Path ([System.IO.Path]::GetTempPath()) ([System.Guid]::NewGuid().ToString())
        try {
            $code = Invoke-EntraFileScenario -ScenarioDir $scenarioDir -OutDir $outDir
            $code | Should -Be 0

            $goldenBytes = [System.IO.File]::ReadAllBytes((Join-Path $scenarioDir 'golden/discover-export.ndjson'))
            $producedBytes = [System.IO.File]::ReadAllBytes((Join-Path $outDir 'discover-export.ndjson'))
            [System.Convert]::ToBase64String($producedBytes) | Should -Be ([System.Convert]::ToBase64String($goldenBytes))
        } finally {
            if (Test-Path $outDir) { Remove-Item -Recurse -Force $outDir }
        }
    }
}

Describe 'nc-export-entra.ps1 -NoPseudonymize' {
    It 'uses the raw UPN as userRef and writes no side files' {
        $scenarioDir = Join-Path $script:FixturesRoot 'scenario-basic'
        $outDir = Join-Path ([System.IO.Path]::GetTempPath()) ([System.Guid]::NewGuid().ToString())
        try {
            $code = Invoke-EntraFileScenario -ScenarioDir $scenarioDir -OutDir $outDir -NoPseudonymize
            $code | Should -Be 0

            $lines = Get-Content -LiteralPath (Join-Path $outDir 'discover-export.ndjson')
            $header = $lines[0] | ConvertFrom-Json
            $header.pseudonymized | Should -Be $false

            $grant = $lines[1] | ConvertFrom-Json
            # Grants sort ordinally by (userRef, clientId); with
            # -NoPseudonymize, userRef is the raw email, and
            # 'alice@...' sorts before 'bob@...'.
            $grant.userRef | Should -Be 'alice@contoso.com'

            (Join-Path $outDir 'mapping.csv') | Should -Not -Exist
            (Join-Path $outDir 'salt.txt') | Should -Not -Exist
        } finally {
            if (Test-Path $outDir) { Remove-Item -Recurse -Force $outDir }
        }
    }
}

Describe 'nc-export-entra.ps1 grant with no scope property' {
    It 'does not throw under StrictMode when a grant record omits the "scope" key entirely, and yields empty scopes' {
        # Cross-language parity: nc-export.py's parse_entra_triplet() uses
        # grant.get("scope") or "" and tolerates a missing key. A Graph
        # record trimmed by $select, or an app-only grant, plausibly omits
        # "scope" entirely -- this must not crash under
        # Set-StrictMode -Version Latest (line 40).
        $tmpDir = Join-Path ([System.IO.Path]::GetTempPath()) ([System.Guid]::NewGuid().ToString())
        New-Item -ItemType Directory -Path $tmpDir | Out-Null
        try {
            $usersPath = Join-Path $tmpDir 'users.json'
            $spsPath = Join-Path $tmpDir 'servicePrincipals.json'
            $grantsPath = Join-Path $tmpDir 'oauth2PermissionGrants.json'
            $outDir = Join-Path $tmpDir 'out'

            @{ value = @(@{ id = 'u1'; userPrincipalName = 'henry@contoso.com'; displayName = 'Henry' }) } |
                ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $usersPath
            @{ value = @(@{ id = 'sp1'; appId = 'ffff6666-ffff-6666-ffff-666666666666'; displayName = 'Asana' }) } |
                ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $spsPath
            # Deliberately no "scope" key at all (not even $null / "").
            @{ value = @(@{ id = 'g1'; clientId = 'sp1'; principalId = 'u1'; resourceId = 'r1'; createdDateTime = '2026-05-01T00:00:00Z' }) } |
                ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $grantsPath

            $code = Start-NcExportEntra -UsersJson $usersPath -ServicePrincipalsJson $spsPath -GrantsJson $grantsPath `
                -OutDir $outDir -SaltFile (Join-Path $script:FixturesRoot 'scenario-basic' 'salt.txt') `
                -GeneratedAt $script:GoldenGeneratedAt
            $code | Should -Be 0

            $lines = Get-Content -LiteralPath (Join-Path $outDir 'discover-export.ndjson')
            $grant = $lines[1] | ConvertFrom-Json
            @($grant.scopes).Count | Should -Be 0
        } finally {
            if (Test-Path $tmpDir) { Remove-Item -Recurse -Force $tmpDir }
        }
    }
}

Describe 'nc-export-entra.ps1 blank/missing/null identity fields' {
    BeforeAll {
        function New-BlankFieldScenario {
            <# Builds a users/servicePrincipals/oauth2PermissionGrants triplet
               with exactly one grant whose referenced user or service
               principal has the given field mutated to $Missing (key
               entirely absent), $null (explicit JSON null), or whitespace. #>
            param([string]$TmpDir, [string]$Field, [string]$Mode)

            $user = [ordered]@{ id = 'u1'; userPrincipalName = 'ivy@contoso.com'; displayName = 'Ivy' }
            $sp = [ordered]@{ id = 'sp1'; appId = 'aaaa1111-aaaa-1111-aaaa-111111111111'; displayName = 'Slack' }

            switch ($Mode) {
                'missing' { $target = if ($Field -eq 'userPrincipalName') { $user } else { $sp }; $target.Remove($Field) }
                'null'    { $target = if ($Field -eq 'userPrincipalName') { $user } else { $sp }; $target[$Field] = $null }
                'blank'   { $target = if ($Field -eq 'userPrincipalName') { $user } else { $sp }; $target[$Field] = '   ' }
            }

            $usersPath = Join-Path $TmpDir 'users.json'
            $spsPath = Join-Path $TmpDir 'servicePrincipals.json'
            $grantsPath = Join-Path $TmpDir 'oauth2PermissionGrants.json'
            @{ value = @($user) } | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $usersPath
            @{ value = @($sp) } | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $spsPath
            @{ value = @(@{ id = 'g1'; clientId = 'sp1'; principalId = 'u1'; resourceId = 'r1'; scope = 'User.Read'; createdDateTime = '2026-01-10T00:00:00Z' }) } |
                ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $grantsPath

            return @{ UsersPath = $usersPath; ServicePrincipalsPath = $spsPath; GrantsPath = $grantsPath }
        }
    }

    It 'skips (no crash under StrictMode) for <_.Field>/<_.Mode>' -ForEach @(
        @{ Field = 'userPrincipalName'; Mode = 'missing' }
        @{ Field = 'userPrincipalName'; Mode = 'null' }
        @{ Field = 'userPrincipalName'; Mode = 'blank' }
        @{ Field = 'appId'; Mode = 'missing' }
        @{ Field = 'appId'; Mode = 'null' }
        @{ Field = 'appId'; Mode = 'blank' }
        @{ Field = 'displayName'; Mode = 'missing' }
        @{ Field = 'displayName'; Mode = 'null' }
        @{ Field = 'displayName'; Mode = 'blank' }
    ) {
        $tmpDir = Join-Path ([System.IO.Path]::GetTempPath()) ([System.Guid]::NewGuid().ToString())
        New-Item -ItemType Directory -Path $tmpDir | Out-Null
        try {
            $paths = New-BlankFieldScenario -TmpDir $tmpDir -Field $Field -Mode $Mode
            $outDir = Join-Path $tmpDir 'out'
            $code = Start-NcExportEntra -UsersJson $paths.UsersPath -ServicePrincipalsJson $paths.ServicePrincipalsPath `
                -GrantsJson $paths.GrantsPath -OutDir $outDir `
                -SaltFile (Join-Path $script:FixturesRoot 'scenario-basic' 'salt.txt') -GeneratedAt $script:GoldenGeneratedAt
            $code | Should -Be 0

            $lines = @(Get-Content -LiteralPath (Join-Path $outDir 'discover-export.ndjson'))
            $lines.Count | Should -Be 1  # header only -- the one grant was skipped
            $header = $lines[0] | ConvertFrom-Json
            $header.skippedRows | Should -Be 1
        } finally {
            if (Test-Path $tmpDir) { Remove-Item -Recurse -Force $tmpDir }
        }
    }
}

Describe 'nc-export-entra.ps1 AllPrincipals grants' {
    It 'emits an AllPrincipals grant with null userRef, not skipped, not counted in skippedRows, not in mapping.csv' {
        $tmpDir = Join-Path ([System.IO.Path]::GetTempPath()) ([System.Guid]::NewGuid().ToString())
        New-Item -ItemType Directory -Path $tmpDir | Out-Null
        try {
            $usersPath = Join-Path $tmpDir 'users.json'
            $spsPath = Join-Path $tmpDir 'servicePrincipals.json'
            $grantsPath = Join-Path $tmpDir 'oauth2PermissionGrants.json'
            $outDir = Join-Path $tmpDir 'out'

            @{ value = @(@{ id = 'u1'; userPrincipalName = 'jack@contoso.com'; displayName = 'Jack' }) } |
                ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $usersPath
            @{ value = @(@{ id = 'sp1'; appId = 'bbbb2222-bbbb-2222-bbbb-222222222222'; displayName = 'Zoom' }) } |
                ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $spsPath
            @{ value = @(@{ id = 'g1'; clientId = 'sp1'; principalId = $null; resourceId = 'r1'; consentType = 'AllPrincipals'; scope = 'User.Read'; createdDateTime = '2026-02-15T00:00:00Z' }) } |
                ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $grantsPath

            $code = Start-NcExportEntra -UsersJson $usersPath -ServicePrincipalsJson $spsPath -GrantsJson $grantsPath `
                -OutDir $outDir -SaltFile (Join-Path $script:FixturesRoot 'scenario-basic' 'salt.txt') `
                -GeneratedAt $script:GoldenGeneratedAt
            $code | Should -Be 0

            $lines = @(Get-Content -LiteralPath (Join-Path $outDir 'discover-export.ndjson'))
            $lines.Count | Should -Be 2
            $header = $lines[0] | ConvertFrom-Json
            $header.skippedRows | Should -Be 0
            $grant = $lines[1] | ConvertFrom-Json
            $grant.userRef | Should -Be $null
            $grant.consentType | Should -Be 'AllPrincipals'

            $mapping = @(Get-Content -LiteralPath (Join-Path $outDir 'mapping.csv'))
            $mapping.Count | Should -Be 1  # header row only, no data row
        } finally {
            if (Test-Path $tmpDir) { Remove-Item -Recurse -Force $tmpDir }
        }
    }
}

Describe 'nc-export-entra.ps1 closing message' {
    It 'prints the "nothing has been sent anywhere" closing message to stdout on a successful run' {
        # Brief item #4: "Same pseudonymization, same three output files,
        # same closing message." This is the core trust/UX guarantee of
        # the tool -- the operator gets explicit, on-screen confirmation
        # that nothing left the machine.
        $scenarioDir = Join-Path $script:FixturesRoot 'scenario-basic'
        $outDir = Join-Path ([System.IO.Path]::GetTempPath()) ([System.Guid]::NewGuid().ToString())
        $sw = [System.IO.StringWriter]::new()
        $origOut = [Console]::Out
        try {
            [Console]::SetOut($sw)
            $code = Invoke-EntraFileScenario -ScenarioDir $scenarioDir -OutDir $outDir
        } finally {
            [Console]::SetOut($origOut)
        }
        try {
            $code | Should -Be 0
            $stdout = $sw.ToString().ToLowerInvariant()
            $stdout | Should -Match 'nothing has been sent anywhere'
            $stdout | Should -Match 'review discover-export\.ndjson'
            $stdout | Should -Match 'upload it in the discover app'
            $stdout | Should -Match 'skipped rows: 0'
        } finally {
            if (Test-Path $outDir) { Remove-Item -Recurse -Force $outDir }
        }
    }
}

Describe 'nc-export-entra.ps1 determinism' {
    It 'produces byte-identical output across two runs with the same salt file' {
        $scenarioDir = Join-Path $script:FixturesRoot 'scenario-duplicate-grants'
        $out1 = Join-Path ([System.IO.Path]::GetTempPath()) ([System.Guid]::NewGuid().ToString())
        $out2 = Join-Path ([System.IO.Path]::GetTempPath()) ([System.Guid]::NewGuid().ToString())
        try {
            (Invoke-EntraFileScenario -ScenarioDir $scenarioDir -OutDir $out1) | Should -Be 0
            (Invoke-EntraFileScenario -ScenarioDir $scenarioDir -OutDir $out2) | Should -Be 0

            $bytes1 = [System.IO.File]::ReadAllBytes((Join-Path $out1 'discover-export.ndjson'))
            $bytes2 = [System.IO.File]::ReadAllBytes((Join-Path $out2 'discover-export.ndjson'))
            [System.Convert]::ToBase64String($bytes1) | Should -Be ([System.Convert]::ToBase64String($bytes2))
        } finally {
            foreach ($d in @($out1, $out2)) { if (Test-Path $d) { Remove-Item -Recurse -Force $d } }
        }
    }
}

Describe 'nc-export-entra.ps1 file mode makes zero live Graph calls' {
    It 'never invokes Connect-MgGraph or Invoke-MgGraphRequest' {
        function Connect-MgGraph { param([string[]]$Scopes) }
        function Invoke-MgGraphRequest { param([string]$Uri) }
        Mock Connect-MgGraph { }
        Mock Invoke-MgGraphRequest { }

        $scenarioDir = Join-Path $script:FixturesRoot 'scenario-basic'
        $outDir = Join-Path ([System.IO.Path]::GetTempPath()) ([System.Guid]::NewGuid().ToString())
        try {
            $code = Invoke-EntraFileScenario -ScenarioDir $scenarioDir -OutDir $outDir
            $code | Should -Be 0
            Should -Invoke Connect-MgGraph -Times 0
            Should -Invoke Invoke-MgGraphRequest -Times 0
        } finally {
            if (Test-Path $outDir) { Remove-Item -Recurse -Force $outDir }
        }
    }
}
