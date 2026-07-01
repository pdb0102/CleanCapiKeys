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

function Get-CertificateKeyReference {
    <#
      Builds the keep-map from all cert stores in the requested scope(s), plus the REQUEST
      (pending enrollment) store. Returns @{ KeepMap = <hashtable>; GapCount = <int>;
      Gaps = <string[]> }. GapCount counts private-key certs whose CAPI unique container
      name could not be resolved (keep-set may be incomplete -> caller must be conservative).
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)] [ValidateSet('Machine','User','Both')] [string] $Scope)

    if (-not (Test-IsWindowsHost)) { throw 'Get-CertificateKeyReference is Windows-only.' }

    $locations = switch ($Scope) {
        'Machine' { ,[System.Security.Cryptography.X509Certificates.StoreLocation]::LocalMachine }
        'User'    { ,[System.Security.Cryptography.X509Certificates.StoreLocation]::CurrentUser }
        'Both'    { [System.Security.Cryptography.X509Certificates.StoreLocation]::LocalMachine,
                    [System.Security.Cryptography.X509Certificates.StoreLocation]::CurrentUser }
    }
    # Over-inclusive: every standard store plus the enrollment-request store.
    $storeNames = @('My','REQUEST','Root','CertificateAuthority','TrustedPeople','TrustedPublisher','AddressBook','AuthRoot','Disallowed')

    $keep = @{}
    $gaps = New-Object System.Collections.Generic.List[string]

    foreach ($loc in $locations) {
        foreach ($sn in $storeNames) {
            try {
                $store = New-Object System.Security.Cryptography.X509Certificates.X509Store($sn, $loc)
                $store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadOnly -bor
                            [System.Security.Cryptography.X509Certificates.OpenFlags]::OpenExistingOnly)
            } catch { continue }  # store may not exist in this location
            try {
                foreach ($cert in $store.Certificates) {
                    if (-not $cert.HasPrivateKey) { continue }
                    try {
                        $rsa = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($cert)
                        if ($rsa -is [System.Security.Cryptography.RSACryptoServiceProvider]) {
                            $unique = $rsa.CspKeyContainerInfo.UniqueKeyContainerName
                            if ($unique) {
                                $keep[$unique.ToLowerInvariant()] =
                                    "$($cert.Thumbprint) $($cert.Subject) [$loc/$sn]"
                            } else {
                                $gaps.Add("$($cert.Thumbprint) [$loc/$sn] (no unique name)")
                            }
                        }
                        # else: CNG key -> not in Crypto\RSA -> not a gap, skip.
                    } catch {
                        $gaps.Add("$($cert.Thumbprint) [$loc/$sn] ($($_.Exception.Message))")
                    }
                }
            } finally { $store.Close() }
        }
    }
    return [pscustomobject]@{ KeepMap = $keep; GapCount = $gaps.Count; Gaps = $gaps.ToArray() }
}

function New-BackupManifestRow {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [object] $Container,
        [Parameter(Mandatory)] [string] $BackupFilePath,
        [Parameter(Mandatory)] [datetime] $Timestamp
    )
    [pscustomobject]@{
        Timestamp    = $Timestamp.ToString('o')
        Scope        = $Container.Scope
        FriendlyName = $Container.FriendlyName
        UniqueName   = $Container.UniqueName
        Provider     = $Container.Provider
        OriginalPath = $Container.FilePath
        BackupPath   = $BackupFilePath
    }
}

function Remove-CapiKeyContainer {
    <#
      Backs up the key file, then deletes the container via CRYPT_DELETEKEYSET, falling
      back to a raw file delete. Returns 'Deleted' or 'Failed' (or 'Skipped' if ShouldProcess
      declines). Writes a manifest row into <BackupPath>\manifest.csv.
    #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory)] [object] $Container,
        [Parameter(Mandatory)] [string] $BackupPath
    )
    if (-not (Test-IsWindowsHost)) { throw 'Remove-CapiKeyContainer is Windows-only.' }
    Initialize-CapiInterop

    $CRYPT_DELETEKEYSET   = [uint32]'0x10'
    $CRYPT_MACHINE_KEYSET = [uint32]'0x20'
    $CRYPT_SILENT         = [uint32]'0x40'
    $machineFlag = if ($Container.Scope -eq 'Machine') { $CRYPT_MACHINE_KEYSET } else { [uint32]0 }

    if (-not (Test-Path -LiteralPath $BackupPath)) {
        New-Item -ItemType Directory -Path $BackupPath -Force | Out-Null
    }

    # 1) Back up the file first.
    $backupFile = Join-Path $BackupPath $Container.UniqueName
    if (Test-Path -LiteralPath $Container.FilePath) {
        Copy-Item -LiteralPath $Container.FilePath -Destination $backupFile -Force -ErrorAction Stop
    }
    $row = New-BackupManifestRow -Container $Container -BackupFilePath $backupFile -Timestamp (Get-Date)
    $row | Export-Csv -Path (Join-Path $BackupPath 'manifest.csv') -Append -NoTypeInformation

    if (-not $PSCmdlet.ShouldProcess("$($Container.FriendlyName) [$($Container.Scope)]", 'Delete key container')) {
        return 'Skipped'
    }

    # 2) API delete.
    $hProv = [IntPtr]::Zero
    $deleted = [CapiCleanup.Native]::CryptAcquireContext([ref]$hProv, $Container.FriendlyName,
                    $Container.Provider, [uint32]$Container.ProviderType,
                    ($CRYPT_DELETEKEYSET -bor $machineFlag -bor $CRYPT_SILENT))

    # 3) Fallback: raw file delete if API failed or file remains.
    if (-not $deleted -or (Test-Path -LiteralPath $Container.FilePath)) {
        try { Remove-Item -LiteralPath $Container.FilePath -Force -ErrorAction Stop; $deleted = $true }
        catch { $deleted = $false }
    }
    return $(if ($deleted) { 'Deleted' } else { 'Failed' })
}

# Entry point (skipped when dot-sourced by tests)
if ($MyInvocation.InvocationName -ne '.') {
    Invoke-OrphanedCapiKeyCleanup @PSBoundParameters
}
