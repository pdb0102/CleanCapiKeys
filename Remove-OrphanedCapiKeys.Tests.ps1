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
