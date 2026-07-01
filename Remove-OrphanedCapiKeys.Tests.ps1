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
