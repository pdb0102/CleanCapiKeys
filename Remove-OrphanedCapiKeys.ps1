#requires -Version 5.1
<#
.SYNOPSIS
  Finds and optionally deletes orphaned legacy CAPI RSA key containers.
.DESCRIPTION
  Dry-run by default. See README.md for the full safety model.
#>
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [ValidateSet('Machine', 'User', 'Both')] [string] $Scope = 'Both',
    [switch] $Execute,
    [ValidateSet('ToDelete', 'ToKeep', 'Both')] [string] $Show = 'Both',
    [string] $NamePattern,
    [int] $MinAgeDays = 1,
    [string] $BackupPath,
    [string[]] $AdditionalSkip = @(),
    [string] $ReportPath,
    [switch] $IgnoreKeepSetGaps
)

function Get-DefaultNamePattern {
    # Bare or brace-wrapped GUID, whole-string.
    return '^\{?[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}\}?$'
}

function Get-DefaultSkipList {
    # Well-known cert-less CAPI machine containers that must never be deleted.
    return @(
        'iisConfigurationKey',
        'iisWasKey',
        'NetFrameworkConfigurationKey',
        'TSSecKeySet1',
        'iisRsaProviderKeyContainer',
        'PVKKeyContainer',
        'MS_DPAPI_MACHINEKEY'
    )
}

function Get-KeyContainerDisposition {
    <#
      Pure function. Assigns a Status to each container. Everything defaults to keep;
      only 'OrphanCandidate' is deletable. Precedence:
      Referenced > SystemKey > NonMatchingName > TooNew > OrphanCandidate.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [AllowEmptyCollection()] [object[]] $Containers,
        [Parameter(Mandatory)] [hashtable] $KeepMap,      # key = lowercased unique name -> referencedBy string
        [Parameter(Mandatory)] [string[]] $SkipList,
        [Parameter(Mandatory)] [string] $NamePattern,
        [Parameter(Mandatory)] [int] $MinAgeDays,
        [Parameter(Mandatory)] [datetime] $Now
    )
    foreach ($c in $Containers) {
        $status = $null
        $referencedBy = $null
        $key = if ($null -ne $c.UniqueName) { $c.UniqueName.ToLowerInvariant() } else { '' }

        if ($KeepMap.ContainsKey($key)) {
            $status = 'Referenced'
            $referencedBy = $KeepMap[$key]
        }
        elseif ($SkipList | Where-Object { $c.FriendlyName -like $_ }) {
            $status = 'SystemKey'
        }
        elseif ($c.FriendlyName -notmatch $NamePattern) {
            $status = 'NonMatchingName'
        }
        elseif ($null -eq $c.FileLastWriteTime) {
            $status = 'TooNew'   # cannot verify age -> fail safe to keep
        }
        elseif (($Now - $c.FileLastWriteTime).TotalDays -lt $MinAgeDays) {
            $status = 'TooNew'
        }
        else {
            $status = 'OrphanCandidate'
        }

        [pscustomobject]@{
            Scope             = $c.Scope
            FriendlyName      = $c.FriendlyName
            UniqueName        = $c.UniqueName
            Provider          = $c.Provider
            FilePath          = $c.FilePath
            FileLastWriteTime = $c.FileLastWriteTime
            Status            = $status
            ReferencedBy      = $referencedBy
        }
    }
}

function Format-KeyDisposition {
    <#
      Pure function. Turns disposition objects into report rows with a derived Action,
      and filters them according to -Show.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [AllowEmptyCollection()] [object[]] $Dispositions,
        [ValidateSet('ToDelete', 'ToKeep', 'Both')] [string] $Show = 'Both',
        [hashtable] $ResultMap = @{}   # key = lowercased unique name -> 'Deleted'|'Failed'
    )
    $deleteActions = @('WouldDelete', 'Deleted', 'Failed')
    $rows = foreach ($d in $Dispositions) {
        $key = if ($null -ne $d.UniqueName) { $d.UniqueName.ToLowerInvariant() } else { '' }
        $action =
            if ($d.Status -ne 'OrphanCandidate') { 'WouldKeep' }
            elseif ($ResultMap.ContainsKey($key)) { $ResultMap[$key] }
            else { 'WouldDelete' }

        $ageDays = if ($null -ne $d.FileLastWriteTime) {
            [math]::Round(((Get-Date) - $d.FileLastWriteTime).TotalDays, 1)
        } else { $null }

        [pscustomobject]@{
            Scope        = $d.Scope
            FriendlyName = $d.FriendlyName
            UniqueName   = $d.UniqueName
            FilePath     = $d.FilePath
            FileAgeDays  = $ageDays
            Status       = $d.Status
            ReferencedBy = $d.ReferencedBy
            Action       = $action
        }
    }
    switch ($Show) {
        'ToDelete' { $rows | Where-Object { $_.Action -in $deleteActions } }
        'ToKeep'   { $rows | Where-Object { $_.Action -eq 'WouldKeep' } }
        default    { $rows }
    }
}

function Test-IsWindowsHost {
    # $IsWindows is $null on Windows PowerShell 5.1 (treat as Windows there).
    return ($PSVersionTable.PSVersion.Major -lt 6) -or $IsWindows
}

function Get-CapiKeyContainerFilePath {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [ValidateSet('Machine','User')] [string] $Scope,
        [Parameter(Mandatory)] [string] $UniqueName,
        [Parameter(Mandatory)] [string] $ProgramData,
        [Parameter(Mandatory)] [string] $AppData,
        [string] $UserSid
    )
    # Build with explicit backslashes so paths are correct regardless of the host OS.
    if ($Scope -eq 'Machine') {
        return ($ProgramData.TrimEnd('\') + '\Microsoft\Crypto\RSA\MachineKeys\' + $UniqueName)
    }
    return ($AppData.TrimEnd('\') + '\Microsoft\Crypto\RSA\' + $UserSid + '\' + $UniqueName)
}

$script:CapiInteropLoaded = $false
function Initialize-CapiInterop {
    if ($script:CapiInteropLoaded) { return }
    Add-Type -Namespace 'CapiCleanup' -Name 'Native' -MemberDefinition @'
[DllImport("advapi32.dll", CharSet=CharSet.Ansi, SetLastError=true)]
public static extern bool CryptAcquireContext(out IntPtr hProv, string pszContainer, string pszProvider, uint dwProvType, uint dwFlags);
[DllImport("advapi32.dll", CharSet=CharSet.Ansi, SetLastError=true)]
public static extern bool CryptGetProvParam(IntPtr hProv, uint dwParam, byte[] pbData, ref uint pdwDataLen, uint dwFlags);
[DllImport("advapi32.dll", SetLastError=true)]
public static extern bool CryptReleaseContext(IntPtr hProv, uint dwFlags);
'@
    $script:CapiInteropLoaded = $true
}

function Get-CapiKeyContainer {
    <#
      Enumerates legacy CAPI RSA containers for a single scope ('Machine' or 'User')
      across the common RSA CSP provider types, de-duplicating by unique name.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)] [ValidateSet('Machine','User')] [string] $Scope)

    if (-not (Test-IsWindowsHost)) { throw 'Get-CapiKeyContainer is Windows-only.' }
    Initialize-CapiInterop

    $PP_ENUMCONTAINERS   = 2
    $PP_UNIQUE_CONTAINER = 36
    $CRYPT_FIRST         = 1
    $CRYPT_NEXT          = 2
    $CRYPT_VERIFYCONTEXT = [uint32]'0xF0000000'
    $CRYPT_MACHINE_KEYSET= [uint32]'0x20'
    $CRYPT_SILENT        = [uint32]'0x40'

    $providers = @(
        @{ Name = 'Microsoft Enhanced Cryptographic Provider v1.0';        Type = 1  }
        @{ Name = 'Microsoft Strong Cryptographic Provider';               Type = 1  }
        @{ Name = 'Microsoft Base Cryptographic Provider v1.0';            Type = 1  }
        @{ Name = 'Microsoft Enhanced RSA and AES Cryptographic Provider'; Type = 24 }
        @{ Name = 'Microsoft RSA SChannel Cryptographic Provider';         Type = 12 }
    )
    $machineFlag = if ($Scope -eq 'Machine') { $CRYPT_MACHINE_KEYSET } else { [uint32]0 }
    $programData = $env:ProgramData
    $appData     = $env:APPDATA
    $userSid     = ([System.Security.Principal.WindowsIdentity]::GetCurrent()).User.Value

    $seen = @{}
    foreach ($prov in $providers) {
        $hProv = [IntPtr]::Zero
        $ok = [CapiCleanup.Native]::CryptAcquireContext([ref]$hProv, $null, $prov.Name, $prov.Type,
                    ($CRYPT_VERIFYCONTEXT -bor $machineFlag -bor $CRYPT_SILENT))
        if (-not $ok) { continue }   # provider not present on this box
        try {
            $flag = $CRYPT_FIRST
            while ($true) {
                $len = [uint32]0
                if (-not [CapiCleanup.Native]::CryptGetProvParam($hProv, $PP_ENUMCONTAINERS, $null, [ref]$len, $flag)) { break }
                $buf = New-Object byte[] $len
                if (-not [CapiCleanup.Native]::CryptGetProvParam($hProv, $PP_ENUMCONTAINERS, $buf, [ref]$len, $flag)) { break }
                $flag = $CRYPT_NEXT
                $name = [System.Text.Encoding]::ASCII.GetString($buf, 0, [Math]::Max(0, $len - 1)).Trim([char]0)
                if ([string]::IsNullOrWhiteSpace($name)) { continue }

                # Resolve the unique (on-disk) name for this container.
                $hCont = [IntPtr]::Zero
                $uOk = [CapiCleanup.Native]::CryptAcquireContext([ref]$hCont, $name, $prov.Name, $prov.Type,
                            ($machineFlag -bor $CRYPT_SILENT))
                if (-not $uOk) { continue }
                try {
                    $ulen = [uint32]0
                    [void][CapiCleanup.Native]::CryptGetProvParam($hCont, $PP_UNIQUE_CONTAINER, $null, [ref]$ulen, 0)
                    $ubuf = New-Object byte[] $ulen
                    if (-not [CapiCleanup.Native]::CryptGetProvParam($hCont, $PP_UNIQUE_CONTAINER, $ubuf, [ref]$ulen, 0)) { continue }
                    $unique = [System.Text.Encoding]::ASCII.GetString($ubuf, 0, [Math]::Max(0, $ulen - 1)).Trim([char]0)
                }
                finally { [void][CapiCleanup.Native]::CryptReleaseContext($hCont, 0) }

                if ([string]::IsNullOrWhiteSpace($unique) -or $seen.ContainsKey($unique.ToLowerInvariant())) { continue }
                $seen[$unique.ToLowerInvariant()] = $true

                $path = Get-CapiKeyContainerFilePath -Scope $Scope -UniqueName $unique -ProgramData $programData -AppData $appData -UserSid $userSid
                $lwt  = if (Test-Path -LiteralPath $path) { (Get-Item -LiteralPath $path).LastWriteTimeUtc } else { $null }

                [pscustomobject]@{
                    FriendlyName      = $name
                    UniqueName        = $unique
                    Scope             = $Scope
                    Provider          = $prov.Name
                    ProviderType      = $prov.Type
                    FilePath          = $path
                    FileLastWriteTime = $lwt
                }
            }
        }
        finally { [void][CapiCleanup.Native]::CryptReleaseContext($hProv, 0) }
    }
}

# Entry point (skipped when dot-sourced by tests)
if ($MyInvocation.InvocationName -ne '.') {
    Invoke-OrphanedCapiKeyCleanup @PSBoundParameters
}
