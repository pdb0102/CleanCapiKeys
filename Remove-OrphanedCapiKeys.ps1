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

# --- functions are added in later tasks ---

# Entry point (skipped when dot-sourced by tests)
if ($MyInvocation.InvocationName -ne '.') {
    Invoke-OrphanedCapiKeyCleanup @PSBoundParameters
}
