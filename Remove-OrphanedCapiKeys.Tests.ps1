BeforeAll {
    . (Join-Path $PSScriptRoot 'Remove-OrphanedCapiKeys.ps1')
}

Describe 'scaffold' {
    It 'loads the script without running main' {
        $true | Should -BeTrue
    }
}

Describe 'Get-DefaultNamePattern' {
    It 'matches a bare GUID' {
        'f81d4fae-7dec-11d0-a765-00a0c91e6bf6' | Should -Match (Get-DefaultNamePattern)
    }
    It 'matches a brace-wrapped GUID' {
        '{f81d4fae-7dec-11d0-a765-00a0c91e6bf6}' | Should -Match (Get-DefaultNamePattern)
    }
    It 'does not match a descriptive system name' {
        'iisConfigurationKey' | Should -Not -Match (Get-DefaultNamePattern)
    }
}

Describe 'Get-DefaultSkipList' {
    It 'protects the well-known system containers' {
        $list = Get-DefaultSkipList
        foreach ($n in 'iisConfigurationKey','iisWasKey','NetFrameworkConfigurationKey','TSSecKeySet1') {
            $list | Should -Contain $n
        }
    }
}

Describe 'Get-KeyContainerDisposition' {
    BeforeAll {
        $script:now = [datetime]'2026-07-01T00:00:00Z'
        function New-Container {
            param($Friendly, $Unique, $AgeDays = 30, $Scope = 'User')
            [pscustomobject]@{
                FriendlyName      = $Friendly
                UniqueName        = $Unique
                Scope             = $Scope
                Provider          = 'Microsoft Enhanced Cryptographic Provider v1.0'
                FilePath          = "/fake/$Unique"
                FileLastWriteTime = $script:now.AddDays(-$AgeDays)
            }
        }
        $guid = 'f81d4fae-7dec-11d0-a765-00a0c91e6bf6'
        $script:params = @{
            SkipList    = (Get-DefaultSkipList)
            NamePattern = (Get-DefaultNamePattern)
            MinAgeDays  = 1
            Now         = $script:now
        }
    }

    It 'keeps a referenced container' {
        $c = New-Container -Friendly $guid -Unique 'ABC123'
        $keep = @{ 'abc123' = 'THUMB Subject=CN=x [LocalMachine/My]' }  # different case on purpose
        $r = Get-KeyContainerDisposition -Containers @($c) -KeepMap $keep @script:params
        $r.Status | Should -Be 'Referenced'
        $r.ReferencedBy | Should -Match 'CN=x'
    }
    It 'keeps a system-key name even when unreferenced' {
        $c = New-Container -Friendly 'iisConfigurationKey' -Unique 'U1'
        (Get-KeyContainerDisposition -Containers @($c) -KeepMap @{} @script:params).Status |
            Should -Be 'SystemKey'
    }
    It 'keeps a non-GUID name' {
        $c = New-Container -Friendly 'SomeAppKey' -Unique 'U2'
        (Get-KeyContainerDisposition -Containers @($c) -KeepMap @{} @script:params).Status |
            Should -Be 'NonMatchingName'
    }
    It 'keeps a too-new GUID key' {
        $c = New-Container -Friendly $guid -Unique 'U3' -AgeDays 0
        (Get-KeyContainerDisposition -Containers @($c) -KeepMap @{} @script:params).Status |
            Should -Be 'TooNew'
    }
    It 'keeps a key with unknown age' {
        $c = New-Container -Friendly $guid -Unique 'U4'
        $c.FileLastWriteTime = $null
        (Get-KeyContainerDisposition -Containers @($c) -KeepMap @{} @script:params).Status |
            Should -Be 'TooNew'
    }
    It 'flags an old unreferenced GUID key as OrphanCandidate' {
        $c = New-Container -Friendly $guid -Unique 'U5' -AgeDays 30
        (Get-KeyContainerDisposition -Containers @($c) -KeepMap @{} @script:params).Status |
            Should -Be 'OrphanCandidate'
    }
    It 'reference beats skip-list (precedence)' {
        $c = New-Container -Friendly 'iisConfigurationKey' -Unique 'U6'
        $r = Get-KeyContainerDisposition -Containers @($c) -KeepMap @{ 'u6' = 'ref' } @script:params
        $r.Status | Should -Be 'Referenced'
    }
}

Describe 'Format-KeyDisposition' {
    BeforeAll {
        $script:disp = @(
            [pscustomobject]@{ Scope='User'; FriendlyName='g1'; UniqueName='U1'; Provider='p'; FilePath='/f/U1'; FileLastWriteTime=[datetime]'2026-01-01'; Status='OrphanCandidate'; ReferencedBy=$null }
            [pscustomobject]@{ Scope='User'; FriendlyName='iisConfigurationKey'; UniqueName='U2'; Provider='p'; FilePath='/f/U2'; FileLastWriteTime=[datetime]'2026-01-01'; Status='SystemKey'; ReferencedBy=$null }
        )
    }
    It 'derives WouldDelete for candidates in dry-run' {
        $rows = Format-KeyDisposition -Dispositions $script:disp -Show Both
        ($rows | Where-Object UniqueName -eq 'U1').Action | Should -Be 'WouldDelete'
        ($rows | Where-Object UniqueName -eq 'U2').Action | Should -Be 'WouldKeep'
    }
    It 'applies execution results when provided' {
        $rows = Format-KeyDisposition -Dispositions $script:disp -Show Both -ResultMap @{ 'u1' = 'Deleted' }
        ($rows | Where-Object UniqueName -eq 'U1').Action | Should -Be 'Deleted'
    }
    It 'filters ToDelete' {
        $rows = Format-KeyDisposition -Dispositions $script:disp -Show ToDelete
        $rows.Count | Should -Be 1
        $rows[0].UniqueName | Should -Be 'U1'
    }
    It 'filters ToKeep' {
        $rows = Format-KeyDisposition -Dispositions $script:disp -Show ToKeep
        $rows.Count | Should -Be 1
        $rows[0].UniqueName | Should -Be 'U2'
    }
}

Describe 'Get-CapiKeyContainerFilePath' {
    It 'builds a machine path under ProgramData' {
        $p = Get-CapiKeyContainerFilePath -Scope 'Machine' -UniqueName 'abc_def' -ProgramData 'C:\PD' -AppData 'C:\AD' -UserSid 'S-1-5-21'
        $p | Should -Be 'C:\PD\Microsoft\Crypto\RSA\MachineKeys\abc_def'
    }
    It 'builds a user path under AppData\<SID>' {
        $p = Get-CapiKeyContainerFilePath -Scope 'User' -UniqueName 'xyz' -ProgramData 'C:\PD' -AppData 'C:\AD' -UserSid 'S-1-5-21'
        $p | Should -Be 'C:\AD\Microsoft\Crypto\RSA\S-1-5-21\xyz'
    }
}

Describe 'Get-CapiKeyContainer' -Tag 'Windows' {
    It 'returns containers with friendly and unique names' -Skip:(-not $IsWindows) {
        $c = Get-CapiKeyContainer -Scope 'User'
        if ($c) { $c[0].FriendlyName | Should -Not -BeNullOrEmpty; $c[0].UniqueName | Should -Not -BeNullOrEmpty }
    }
}

Describe 'Get-CertificateKeyReference' -Tag 'Windows' {
    It 'returns a KeepMap and GapCount' -Skip:(-not $IsWindows) {
        $r = Get-CertificateKeyReference -Scope 'Both'
        $r.KeepMap | Should -BeOfType [hashtable]
        $r.GapCount | Should -BeGreaterOrEqual 0
    }
}

Describe 'New-BackupManifestRow' {
    It 'captures the identifying fields' {
        $c = [pscustomobject]@{ FriendlyName='g'; UniqueName='U'; Scope='User'; Provider='p'; FilePath='/f/U' }
        $row = New-BackupManifestRow -Container $c -BackupFilePath '/b/U' -Timestamp ([datetime]'2026-07-01')
        $row.UniqueName   | Should -Be 'U'
        $row.OriginalPath | Should -Be '/f/U'
        $row.BackupPath   | Should -Be '/b/U'
    }
}

Describe 'Remove-CapiKeyContainer' -Tag 'Windows' {
    It 'is Windows-only' -Skip:($IsWindows) {
        { Remove-CapiKeyContainer -Container ([pscustomobject]@{}) -BackupPath (Get-Location) } |
            Should -Throw
    }
}

Describe 'Invoke-OrphanedCapiKeyCleanup' {
    BeforeAll {
        $guid = 'f81d4fae-7dec-11d0-a765-00a0c91e6bf6'
        $script:fakeContainers = {
            param($Scope)
            @([pscustomobject]@{
                FriendlyName='f81d4fae-7dec-11d0-a765-00a0c91e6bf6'; UniqueName='ORPH1'; Scope='User'
                Provider='Microsoft Enhanced Cryptographic Provider v1.0'; ProviderType=1
                FilePath='/fake/ORPH1'; FileLastWriteTime=((Get-Date).AddDays(-30))
            },
            [pscustomobject]@{
                FriendlyName='f81d4fae-7dec-11d0-a765-00a0c91e6bf7'; UniqueName='KEEP1'; Scope='User'
                Provider='Microsoft Enhanced Cryptographic Provider v1.0'; ProviderType=1
                FilePath='/fake/KEEP1'; FileLastWriteTime=((Get-Date).AddDays(-30))
            })
        }
        $script:keepWithRef = { param($Scope) [pscustomobject]@{ KeepMap = @{ 'keep1' = 'ref' }; GapCount = 0; Gaps = @() } }
        $script:keepWithGap = { param($Scope) [pscustomobject]@{ KeepMap = @{}; GapCount = 2; Gaps = @('a','b') } }
    }

    It 'dry-run flags orphan, keeps referenced, and never deletes' {
        $deleted = @()
        $rows = Invoke-OrphanedCapiKeyCleanup -Scope User `
            -ContainerProvider $script:fakeContainers -KeepSetProvider $script:keepWithRef `
            -Deleter { param($c,$b) $deleted += $c.UniqueName; 'Deleted' } -PassThru
        ($rows | Where-Object UniqueName -eq 'ORPH1').Action | Should -Be 'WouldDelete'
        ($rows | Where-Object UniqueName -eq 'KEEP1').Action | Should -Be 'WouldKeep'
        $deleted.Count | Should -Be 0
    }

    It 'aborts on keep-set gap under -Execute without override' {
        { Invoke-OrphanedCapiKeyCleanup -Scope User -Execute `
            -ContainerProvider $script:fakeContainers -KeepSetProvider $script:keepWithGap `
            -Deleter { param($c,$b) 'Deleted' } -PassThru } | Should -Throw '*keep-set*'
    }

    It 'executes deletion only for orphan candidates' {
        $deleted = New-Object System.Collections.ArrayList
        $rows = Invoke-OrphanedCapiKeyCleanup -Scope User -Execute `
            -ContainerProvider $script:fakeContainers -KeepSetProvider $script:keepWithRef `
            -Deleter { param($c,$b) [void]$deleted.Add($c.UniqueName); 'Deleted' } -PassThru
        $deleted | Should -Be @('ORPH1')
        ($rows | Where-Object UniqueName -eq 'ORPH1').Action | Should -Be 'Deleted'
    }

    It 'aborts machine scope without elevation' {
        { Invoke-OrphanedCapiKeyCleanup -Scope Machine `
            -ContainerProvider $script:fakeContainers -KeepSetProvider $script:keepWithRef `
            -Deleter { param($c,$b) 'Deleted' } -IsElevatedOverride $false -PassThru } |
            Should -Throw '*elevation*'
    }
}
