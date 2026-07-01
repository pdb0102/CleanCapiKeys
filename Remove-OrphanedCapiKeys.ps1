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

# Entry point (skipped when dot-sourced by tests)
if ($MyInvocation.InvocationName -ne '.') {
    Invoke-OrphanedCapiKeyCleanup @PSBoundParameters
}
