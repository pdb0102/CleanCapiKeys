# Remove-OrphanedCapiKeys Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers-extended-cc:subagent-driven-development (recommended) or superpowers-extended-cc:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a PowerShell script that finds and (optionally) deletes legacy CAPI RSA key containers left orphaned by `new X509Certificate2(pfx, pwd)` leaks, safely, with a dry-run default, authored and unit-tested from macOS.

**Architecture:** One script `Remove-OrphanedCapiKeys.ps1` composed of small functions: a **pure, OS-agnostic classifier** (unit-tested on the Mac via Pester), Windows-only CryptoAPI P/Invoke for container enumeration and deletion, a certificate keep-set builder, backup+delete, reporting, and an injectable orchestrator. Dependency injection lets the whole orchestration and reporting flow be tested on macOS with fakes; the thin Windows-only functions are exercised via dry-run on the target box.

**Tech Stack:** PowerShell (Windows PowerShell 5.1 on target; PowerShell 7 / pwsh on the Mac for dev), Pester 5 for tests, `Add-Type` C# P/Invoke against `advapi32` CryptoAPI.

**User decisions (already made):**
- Language: PowerShell.
- Store scope: **both** LocalMachine and CurrentUser.
- Key subsystem: **legacy CAPI only** (`Microsoft\Crypto\RSA`); CNG out of scope.
- Pending-request keys (`REQUEST` store) are **protected** (treated as in-use).
- Orphan signature: GUID friendly name from default `X509Certificate2` import.
- Ship a **built-in system-key skip-list**.
- Enumeration via **P/Invoke CryptoAPI** (yields friendly + unique names).
- Dry-run is the default; deletion requires explicit `-Execute`.

---

## File Structure

- `Remove-OrphanedCapiKeys.ps1` — the whole tool: param block, all functions, dot-source-guarded entry point.
- `Remove-OrphanedCapiKeys.Tests.ps1` — Pester 5 tests. Mac-runnable tests for pure functions; Windows-only tests tagged and skipped off-Windows.
- `README.md` — usage, safety model, and the "verify on Windows" runbook.
- `docs/superpowers/specs/2026-07-01-capi-orphaned-key-cleanup-design.md` — the approved design (already committed).

**Testability contract:** the script is a library of functions plus a guarded entry point:
```powershell
if ($MyInvocation.InvocationName -ne '.') { Invoke-OrphanedCapiKeyCleanup @PSBoundParameters }
```
Dot-sourcing (what Pester does) sets `$MyInvocation.InvocationName` to `.`, so tests load the functions without running `main`. No script param is `Mandatory`, so dot-sourcing binds defaults cleanly.

---

### Task 0: Dev environment + repo scaffold

**Goal:** Install PowerShell 7 + Pester on this Mac and create the two empty source files so tests can run locally.

**Files:**
- Create: `Remove-OrphanedCapiKeys.ps1` (skeleton)
- Create: `Remove-OrphanedCapiKeys.Tests.ps1` (skeleton)

**Acceptance Criteria:**
- [ ] `pwsh` runs and reports version 7.x
- [ ] `Import-Module Pester` succeeds with Pester >= 5
- [ ] Both source files exist and parse without error

**Verify:** `pwsh -NoProfile -c '$PSVersionTable.PSVersion.ToString(); (Get-Module -ListAvailable Pester | Select-Object -First 1).Version.ToString()'` → prints `7.x` and `5.x`

**Steps:**

- [ ] **Step 1: Install PowerShell 7 (asks for consent — this installs software)**

```bash
brew install --cask powershell
pwsh -NoProfile -c '$PSVersionTable.PSVersion.ToString()'
```
Expected: prints something like `7.4.6`.

- [ ] **Step 2: Install Pester 5 for the current user**

```bash
pwsh -NoProfile -c "Install-Module Pester -Scope CurrentUser -MinimumVersion 5.0 -Force -SkipPublisherCheck; (Get-Module -ListAvailable Pester | Select-Object -First 1).Version.ToString()"
```
Expected: prints `5.x`.

- [ ] **Step 3: Create the script skeleton**

`Remove-OrphanedCapiKeys.ps1`:
```powershell
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

# --- functions are added in later tasks ---

# Entry point (skipped when dot-sourced by tests)
if ($MyInvocation.InvocationName -ne '.') {
    Invoke-OrphanedCapiKeyCleanup @PSBoundParameters
}
```

`Remove-OrphanedCapiKeys.Tests.ps1`:
```powershell
BeforeAll {
    . (Join-Path $PSScriptRoot 'Remove-OrphanedCapiKeys.ps1')
}

Describe 'scaffold' {
    It 'loads the script without running main' {
        $true | Should -BeTrue
    }
}
```

- [ ] **Step 4: Run the scaffold test**

Run: `pwsh -NoProfile -c "Invoke-Pester -Path ./Remove-OrphanedCapiKeys.Tests.ps1 -Output Detailed"`
Expected: 1 test, PASS. (The dot-source guard prevents `Invoke-OrphanedCapiKeyCleanup` from being called even though it doesn't exist yet.)

- [ ] **Step 5: Commit**

```bash
git add Remove-OrphanedCapiKeys.ps1 Remove-OrphanedCapiKeys.Tests.ps1
git commit -m "chore: scaffold script + Pester harness"
```

---

### Task 1: Default configuration (GUID pattern + system skip-list)

**Goal:** Provide the default GUID name pattern and the built-in system-key skip-list as pure functions, with tests proving the defaults classify correctly.

**Files:**
- Modify: `Remove-OrphanedCapiKeys.ps1` (add `Get-DefaultNamePattern`, `Get-DefaultSkipList`)
- Modify: `Remove-OrphanedCapiKeys.Tests.ps1`

**Acceptance Criteria:**
- [ ] `Get-DefaultNamePattern` returns a regex matching bare and brace-wrapped GUIDs, and NOT matching `iisConfigurationKey`
- [ ] `Get-DefaultSkipList` contains the well-known IIS/ASP.NET/RDP names

**Verify:** `pwsh -NoProfile -c "Invoke-Pester -Path ./Remove-OrphanedCapiKeys.Tests.ps1 -Output Detailed"` → all pass

**Steps:**

- [ ] **Step 1: Write failing tests**

Append to `Remove-OrphanedCapiKeys.Tests.ps1`:
```powershell
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
```

- [ ] **Step 2: Run tests to confirm they fail**

Run: `pwsh -NoProfile -c "Invoke-Pester -Path ./Remove-OrphanedCapiKeys.Tests.ps1"`
Expected: FAIL — `Get-DefaultNamePattern` not recognized.

- [ ] **Step 3: Implement the functions**

Add to `Remove-OrphanedCapiKeys.ps1` (above the entry-point guard):
```powershell
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
```

- [ ] **Step 4: Run tests to confirm pass**

Run: `pwsh -NoProfile -c "Invoke-Pester -Path ./Remove-OrphanedCapiKeys.Tests.ps1"`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add Remove-OrphanedCapiKeys.ps1 Remove-OrphanedCapiKeys.Tests.ps1
git commit -m "feat: default GUID pattern and system-key skip-list"
```

---

### Task 2: Pure classifier `Get-KeyContainerDisposition`

**Goal:** Implement the OS-agnostic decision core that assigns each container a status, and cover every branch with Mac-runnable tests. This is the safety-critical heart of the tool.

**Files:**
- Modify: `Remove-OrphanedCapiKeys.ps1` (add `Get-KeyContainerDisposition`)
- Modify: `Remove-OrphanedCapiKeys.Tests.ps1`

**Acceptance Criteria:**
- [ ] Referenced container (unique name in keep-map) → `Referenced`, with `ReferencedBy` populated
- [ ] Skip-list friendly name → `SystemKey` even if unreferenced
- [ ] Non-GUID friendly name → `NonMatchingName`
- [ ] File younger than `MinAgeDays` → `TooNew`
- [ ] Null/unknown `FileLastWriteTime` → `TooNew` (fail safe = keep)
- [ ] Otherwise → `OrphanCandidate` (the only deletable status)
- [ ] Precedence is exactly: Referenced > SystemKey > NonMatchingName > TooNew > OrphanCandidate
- [ ] Keep-map lookup is case-insensitive on the unique name

**Verify:** `pwsh -NoProfile -c "Invoke-Pester -Path ./Remove-OrphanedCapiKeys.Tests.ps1 -Output Detailed"` → all pass

**Steps:**

- [ ] **Step 1: Write failing tests**

Append to `Remove-OrphanedCapiKeys.Tests.ps1`:
```powershell
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
```

- [ ] **Step 2: Run tests to confirm they fail**

Run: `pwsh -NoProfile -c "Invoke-Pester -Path ./Remove-OrphanedCapiKeys.Tests.ps1"`
Expected: FAIL — `Get-KeyContainerDisposition` not recognized.

- [ ] **Step 3: Implement the classifier**

Add to `Remove-OrphanedCapiKeys.ps1`:
```powershell
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
```

- [ ] **Step 4: Run tests to confirm pass**

Run: `pwsh -NoProfile -c "Invoke-Pester -Path ./Remove-OrphanedCapiKeys.Tests.ps1"`
Expected: PASS (all classifier cases green).

- [ ] **Step 5: Commit**

```bash
git add Remove-OrphanedCapiKeys.ps1 Remove-OrphanedCapiKeys.Tests.ps1
git commit -m "feat: pure key-container classifier with full test coverage"
```

---

### Task 3: Reporting `Format-KeyDisposition` (pure) + CSV/`-Show` filter

**Goal:** Turn dispositions into display/report rows with a derived `Action`, honoring `-Show`, and write CSV — all OS-agnostic and tested on the Mac.

**Files:**
- Modify: `Remove-OrphanedCapiKeys.ps1` (add `Format-KeyDisposition`)
- Modify: `Remove-OrphanedCapiKeys.Tests.ps1`

**Acceptance Criteria:**
- [ ] Each row gets `Action`: `OrphanCandidate` → `WouldDelete` (dry-run) or `Deleted`/`Failed` (from an execution-result map); all keep statuses → `WouldKeep`
- [ ] `-Show ToDelete` returns only `WouldDelete`/`Deleted`/`Failed` rows; `ToKeep` only keep rows; `Both` all
- [ ] Returns a stable column set suitable for `Export-Csv`

**Verify:** `pwsh -NoProfile -c "Invoke-Pester -Path ./Remove-OrphanedCapiKeys.Tests.ps1 -Output Detailed"` → all pass

**Steps:**

- [ ] **Step 1: Write failing tests**

Append:
```powershell
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
```

- [ ] **Step 2: Run to confirm fail**

Run: `pwsh -NoProfile -c "Invoke-Pester -Path ./Remove-OrphanedCapiKeys.Tests.ps1"`
Expected: FAIL — `Format-KeyDisposition` not recognized.

- [ ] **Step 3: Implement**

Add to `Remove-OrphanedCapiKeys.ps1`:
```powershell
function Format-KeyDisposition {
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
```

- [ ] **Step 4: Run to confirm pass**

Run: `pwsh -NoProfile -c "Invoke-Pester -Path ./Remove-OrphanedCapiKeys.Tests.ps1"`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add Remove-OrphanedCapiKeys.ps1 Remove-OrphanedCapiKeys.Tests.ps1
git commit -m "feat: disposition reporting with -Show filter and CSV rows"
```

---

### Task 4: Windows CryptoAPI enumeration `Get-CapiKeyContainer`

**Goal:** Enumerate CAPI containers for a scope via P/Invoke, returning friendly name, unique name (= filename), provider, scope, and resolved file path. Windows-only; guarded and skip-tagged off-Windows.

**Files:**
- Modify: `Remove-OrphanedCapiKeys.ps1` (add `Get-CapiKeyContainerFilePath`, `Get-CapiKeyContainer`, and the `Add-Type` interop block)
- Modify: `Remove-OrphanedCapiKeys.Tests.ps1`

**Acceptance Criteria:**
- [ ] On non-Windows, calling `Get-CapiKeyContainer` throws a clear "Windows only" error
- [ ] `Get-CapiKeyContainerFilePath` (pure) builds the correct Machine and User paths — tested on Mac
- [ ] Windows path (tagged `Windows`) enumerates containers with both names populated — verified via dry-run on the target box

**Verify (Mac):** `pwsh -NoProfile -c "Invoke-Pester -Path ./Remove-OrphanedCapiKeys.Tests.ps1 -Output Detailed"` → passes; Windows-tagged tests report as skipped
**Verify (parse):** `pwsh -NoProfile -c "\$e=\$null; [void][System.Management.Automation.Language.Parser]::ParseFile((Resolve-Path ./Remove-OrphanedCapiKeys.ps1),[ref]\$null,[ref]\$e); if(\$e){\$e; exit 1}else{'OK'}"` → `OK`

**Steps:**

- [ ] **Step 1: Write the pure path-builder test (Mac) + a Windows-tagged enumeration test**

Append:
```powershell
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
```

- [ ] **Step 2: Run to confirm fail**

Run: `pwsh -NoProfile -c "Invoke-Pester -Path ./Remove-OrphanedCapiKeys.Tests.ps1"`
Expected: FAIL — `Get-CapiKeyContainerFilePath` not recognized.

- [ ] **Step 3: Implement path builder, interop, and enumeration**

Add to `Remove-OrphanedCapiKeys.ps1`:
```powershell
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
    if ($Scope -eq 'Machine') {
        return (Join-Path (Join-Path $ProgramData 'Microsoft\Crypto\RSA\MachineKeys') $UniqueName)
    }
    return (Join-Path (Join-Path (Join-Path $AppData 'Microsoft\Crypto\RSA') $UserSid) $UniqueName)
}

$script:CapiInteropLoaded = $false
function Initialize-CapiInterop {
    if ($script:CapiInteropLoaded) { return }
    Add-Type -Namespace 'CapiCleanup' -Name 'Native' -PassThru -MemberDefinition @'
[DllImport("advapi32.dll", CharSet=CharSet.Ansi, SetLastError=true)]
public static extern bool CryptAcquireContext(out IntPtr hProv, string pszContainer, string pszProvider, uint dwProvType, uint dwFlags);
[DllImport("advapi32.dll", CharSet=CharSet.Ansi, SetLastError=true)]
public static extern bool CryptGetProvParam(IntPtr hProv, uint dwParam, byte[] pbData, ref uint pdwDataLen, uint dwFlags);
[DllImport("advapi32.dll", SetLastError=true)]
public static extern bool CryptReleaseContext(IntPtr hProv, uint dwFlags);
'@ | Out-Null
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
```

- [ ] **Step 4: Run tests (Mac) + parse check**

Run: `pwsh -NoProfile -c "Invoke-Pester -Path ./Remove-OrphanedCapiKeys.Tests.ps1 -Output Detailed"`
Expected: path-builder tests PASS; `Get-CapiKeyContainer` Windows test SKIPPED.
Run the parse check from **Verify (parse)** above → `OK`.

- [ ] **Step 5: Commit**

```bash
git add Remove-OrphanedCapiKeys.ps1 Remove-OrphanedCapiKeys.Tests.ps1
git commit -m "feat: CryptoAPI container enumeration (Windows) + pure path builder"
```

---

### Task 5: Certificate keep-set builder `Get-CertificateKeyReference`

**Goal:** Build the keep-map from every cert store (both scopes), resolving each private-key cert's `UniqueKeyContainerName`, and count unresolved private-key certs as keep-set gaps. Windows-only.

**Files:**
- Modify: `Remove-OrphanedCapiKeys.ps1` (add `Get-CertificateKeyReference`)
- Modify: `Remove-OrphanedCapiKeys.Tests.ps1`

**Acceptance Criteria:**
- [ ] Returns an object with `KeepMap` (lowercased unique name → referencedBy) and `GapCount`
- [ ] Iterates `LocalMachine` and `CurrentUser` and includes the `REQUEST` store
- [ ] CNG keys are skipped silently (not a gap); unreadable CAPI private keys increment `GapCount`
- [ ] On non-Windows, throws a clear "Windows only" error

**Verify (Mac):** `pwsh -NoProfile -c "Invoke-Pester -Path ./Remove-OrphanedCapiKeys.Tests.ps1"` → Windows-tagged test skipped, suite green
**Verify (parse):** parse check → `OK`

**Steps:**

- [ ] **Step 1: Write a Windows-tagged test**

Append:
```powershell
Describe 'Get-CertificateKeyReference' -Tag 'Windows' {
    It 'returns a KeepMap and GapCount' -Skip:(-not $IsWindows) {
        $r = Get-CertificateKeyReference -Scope 'Both'
        $r.KeepMap | Should -BeOfType [hashtable]
        $r.GapCount | Should -BeGreaterOrEqual 0
    }
}
```

- [ ] **Step 2: Run to confirm the new test is present and skipped**

Run: `pwsh -NoProfile -c "Invoke-Pester -Path ./Remove-OrphanedCapiKeys.Tests.ps1"`
Expected: suite green; new test SKIPPED on Mac.

- [ ] **Step 3: Implement**

Add to `Remove-OrphanedCapiKeys.ps1`:
```powershell
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
```

- [ ] **Step 4: Run tests + parse check**

Run: `pwsh -NoProfile -c "Invoke-Pester -Path ./Remove-OrphanedCapiKeys.Tests.ps1"` → green (Windows test skipped).
Run the parse check → `OK`.

- [ ] **Step 5: Commit**

```bash
git add Remove-OrphanedCapiKeys.ps1 Remove-OrphanedCapiKeys.Tests.ps1
git commit -m "feat: certificate keep-set builder with keep-set-gap detection"
```

---

### Task 6: Backup + deletion `Remove-CapiKeyContainer` (+ pure manifest row)

**Goal:** Back up a key file and delete its container via `CRYPT_DELETEKEYSET`, with file-delete fallback. The manifest-row builder is pure and Mac-tested.

**Files:**
- Modify: `Remove-OrphanedCapiKeys.ps1` (add `New-BackupManifestRow`, `Remove-CapiKeyContainer`)
- Modify: `Remove-OrphanedCapiKeys.Tests.ps1`

**Acceptance Criteria:**
- [ ] `New-BackupManifestRow` (pure) returns a row with FriendlyName, UniqueName, Scope, Provider, OriginalPath, BackupPath, Timestamp — Mac-tested
- [ ] `Remove-CapiKeyContainer` copies the file to backup before any deletion
- [ ] Deletion tries the API first, then file delete; returns `Deleted` or `Failed`
- [ ] On non-Windows, throws a clear "Windows only" error

**Verify (Mac):** `pwsh -NoProfile -c "Invoke-Pester -Path ./Remove-OrphanedCapiKeys.Tests.ps1"` → manifest test passes; Windows delete test skipped
**Verify (parse):** parse check → `OK`

**Steps:**

- [ ] **Step 1: Write the pure manifest test + a Windows-tagged guard test**

Append:
```powershell
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
```

- [ ] **Step 2: Run to confirm fail**

Run: `pwsh -NoProfile -c "Invoke-Pester -Path ./Remove-OrphanedCapiKeys.Tests.ps1"`
Expected: FAIL — `New-BackupManifestRow` not recognized.

- [ ] **Step 3: Implement**

Add to `Remove-OrphanedCapiKeys.ps1`:
```powershell
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
      back to a raw file delete. Returns 'Deleted' or 'Failed'. Writes a manifest row into
      <BackupPath>\manifest.csv.
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
```

- [ ] **Step 4: Run tests + parse check**

Run: `pwsh -NoProfile -c "Invoke-Pester -Path ./Remove-OrphanedCapiKeys.Tests.ps1"` → manifest test PASS; Windows delete test SKIPPED.
Run the parse check → `OK`.

- [ ] **Step 5: Commit**

```bash
git add Remove-OrphanedCapiKeys.ps1 Remove-OrphanedCapiKeys.Tests.ps1
git commit -m "feat: backup-then-delete with API delete + file fallback"
```

---

### Task 7: Orchestrator `Invoke-OrphanedCapiKeyCleanup` (injectable, Mac-testable)

**Goal:** Wire everything: preconditions (elevation, keep-set-gap gate), enumeration, keep-set, classification, reporting, and gated deletion. Dependencies are injectable so the full dry-run flow is tested on the Mac with fakes.

**Files:**
- Modify: `Remove-OrphanedCapiKeys.ps1` (add `Invoke-OrphanedCapiKeyCleanup`)
- Modify: `Remove-OrphanedCapiKeys.Tests.ps1`

**Acceptance Criteria:**
- [ ] Accepts `-ContainerProvider` and `-KeepSetProvider` script blocks (default to the Windows functions) so it runs on the Mac with fakes
- [ ] Dry-run (no `-Execute`) never calls the deleter and returns rows with `WouldDelete`/`WouldKeep`
- [ ] With `-Execute` and a gap and no `-IgnoreKeepSetGaps`, it aborts without deleting
- [ ] With `-Execute` it invokes the injected deleter only for `OrphanCandidate` rows
- [ ] Machine scope without elevation aborts (elevation check is injectable/overridable for the test)

**Verify:** `pwsh -NoProfile -c "Invoke-Pester -Path ./Remove-OrphanedCapiKeys.Tests.ps1 -Output Detailed"` → all pass

**Steps:**

- [ ] **Step 1: Write failing orchestration tests (Mac, using fakes)**

Append:
```powershell
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
```

- [ ] **Step 2: Run to confirm fail**

Run: `pwsh -NoProfile -c "Invoke-Pester -Path ./Remove-OrphanedCapiKeys.Tests.ps1"`
Expected: FAIL — `Invoke-OrphanedCapiKeyCleanup` not recognized.

- [ ] **Step 3: Implement the orchestrator**

Add to `Remove-OrphanedCapiKeys.ps1` (above the entry-point guard):
```powershell
function Test-IsElevated {
    if (-not (Test-IsWindowsHost)) { return $false }
    $id = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    return (New-Object System.Security.Principal.WindowsPrincipal($id)).IsInRole(
        [System.Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Invoke-OrphanedCapiKeyCleanup {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [ValidateSet('Machine','User','Both')] [string] $Scope = 'Both',
        [switch] $Execute,
        [ValidateSet('ToDelete','ToKeep','Both')] [string] $Show = 'Both',
        [string] $NamePattern,
        [int] $MinAgeDays = 1,
        [string] $BackupPath,
        [string[]] $AdditionalSkip = @(),
        [string] $ReportPath,
        [switch] $IgnoreKeepSetGaps,
        # Injectable seams (default to real Windows implementations):
        [scriptblock] $ContainerProvider = { param($s) Get-CapiKeyContainer -Scope $s },
        [scriptblock] $KeepSetProvider   = { param($s) Get-CertificateKeyReference -Scope $s },
        [scriptblock] $Deleter           = { param($c, $b) Remove-CapiKeyContainer -Container $c -BackupPath $b },
        [nullable[bool]] $IsElevatedOverride = $null,
        [switch] $PassThru
    )
    if (-not $NamePattern) { $NamePattern = Get-DefaultNamePattern }
    if (-not $BackupPath)  { $BackupPath  = Join-Path (Get-Location) ("CapiKeyBackup-" + (Get-Date -Format 'yyyyMMdd-HHmmss')) }
    if (-not $ReportPath)  { $ReportPath  = Join-Path (Get-Location) ("CapiKeyReport-" + (Get-Date -Format 'yyyyMMdd-HHmmss') + ".csv") }
    $skipList = (Get-DefaultSkipList) + $AdditionalSkip

    $scopesToScan = if ($Scope -eq 'Both') { @('Machine','User') } else { @($Scope) }

    # Precondition: Machine scope requires elevation.
    $elevated = if ($null -ne $IsElevatedOverride) { [bool]$IsElevatedOverride } else { Test-IsElevated }
    if (($scopesToScan -contains 'Machine') -and -not $elevated) {
        throw 'Machine scope requires elevation (run as Administrator). Aborting.'
    }

    # Enumerate containers and build the keep-set.
    $containers = foreach ($s in $scopesToScan) { & $ContainerProvider $s }
    $containers = @($containers)
    $keep = & $KeepSetProvider $Scope

    if ($keep.GapCount -gt 0) {
        Write-Warning "Keep-set may be incomplete: $($keep.GapCount) private-key cert(s) could not be resolved."
        if ($Execute -and -not $IgnoreKeepSetGaps) {
            throw "Refusing to delete: keep-set gap of $($keep.GapCount). Re-run with -IgnoreKeepSetGaps to override."
        }
    }

    $dispositions = Get-KeyContainerDisposition -Containers $containers -KeepMap $keep.KeepMap `
        -SkipList $skipList -NamePattern $NamePattern -MinAgeDays $MinAgeDays -Now (Get-Date)

    # Execute deletions for orphan candidates.
    $resultMap = @{}
    if ($Execute) {
        foreach ($d in ($dispositions | Where-Object Status -eq 'OrphanCandidate')) {
            $container = $containers | Where-Object { $_.UniqueName -eq $d.UniqueName } | Select-Object -First 1
            $resultMap[$d.UniqueName.ToLowerInvariant()] = (& $Deleter $container $BackupPath)
        }
    }

    $rows = Format-KeyDisposition -Dispositions $dispositions -Show $Show -ResultMap $resultMap
    $rows | Export-Csv -Path $ReportPath -NoTypeInformation
    $rows | Format-Table -AutoSize | Out-Host

    $mode = if ($Execute) { 'EXECUTE' } else { 'DRY-RUN' }
    $summary = $rows | Group-Object Action | ForEach-Object { "$($_.Name)=$($_.Count)" }
    Write-Host "[$mode] $($summary -join '  ')  Report: $ReportPath"

    if ($PassThru) { return $rows }
}
```

- [ ] **Step 4: Run tests to confirm pass**

Run: `pwsh -NoProfile -c "Invoke-Pester -Path ./Remove-OrphanedCapiKeys.Tests.ps1 -Output Detailed"`
Expected: PASS (all orchestration cases green).

- [ ] **Step 5: Commit**

```bash
git add Remove-OrphanedCapiKeys.ps1 Remove-OrphanedCapiKeys.Tests.ps1
git commit -m "feat: injectable orchestrator with dry-run default and gap gate"
```

---

### Task 8: Full-suite green + syntax lint + README runbook

**Goal:** Run the entire test suite, confirm the script parses, and document usage, the safety model, and the "verify on Windows" runbook.

**Files:**
- Create: `README.md`
- Modify (if lint finds issues): `Remove-OrphanedCapiKeys.ps1`

**Acceptance Criteria:**
- [ ] Full Pester suite passes on the Mac (Windows-tagged tests skipped, everything else green)
- [ ] Script parses with zero parser errors
- [ ] README documents every parameter, the four keep-layers, and the first-run-on-Windows steps (including the two assumptions to verify)

**Verify:** `pwsh -NoProfile -c "Invoke-Pester -Path ./Remove-OrphanedCapiKeys.Tests.ps1 -Output Detailed"` → 0 failed; then the parse check → `OK`

**Steps:**

- [ ] **Step 1: Run the whole suite**

Run: `pwsh -NoProfile -c "Invoke-Pester -Path ./Remove-OrphanedCapiKeys.Tests.ps1 -Output Detailed"`
Expected: 0 failed. Note the skipped Windows-tagged tests.

- [ ] **Step 2: Parse check**

Run: `pwsh -NoProfile -c "\$e=\$null; [void][System.Management.Automation.Language.Parser]::ParseFile((Resolve-Path ./Remove-OrphanedCapiKeys.ps1),[ref]\$null,[ref]\$e); if(\$e){\$e; exit 1}else{'OK'}"`
Expected: `OK`.

- [ ] **Step 3: Optional deeper lint (best-effort)**

```bash
pwsh -NoProfile -c "Install-Module PSScriptAnalyzer -Scope CurrentUser -Force -SkipPublisherCheck; Invoke-ScriptAnalyzer -Path ./Remove-OrphanedCapiKeys.ps1 -Severity Warning,Error | Format-Table -AutoSize"
```
Address any Error-level findings; Warnings at discretion.

- [ ] **Step 4: Write README.md**

`README.md`:
```markdown
# Remove-OrphanedCapiKeys

Finds and (optionally) deletes **legacy CAPI RSA key containers** left orphaned by
`new X509Certificate2(pfx, password)` calls that persist a key without ever cleaning it up.

**Dry-run by default.** Nothing is deleted unless you pass `-Execute`.

## Usage

```powershell
# See what WOULD be deleted (safe, default). Machine scope needs an elevated shell.
.\Remove-OrphanedCapiKeys.ps1 -Scope Both -Show Both

# Only the deletion candidates
.\Remove-OrphanedCapiKeys.ps1 -Scope Both -Show ToDelete

# Actually delete (backs up every key first), older than 7 days
.\Remove-OrphanedCapiKeys.ps1 -Scope Both -Execute -MinAgeDays 7
```

## Parameters

| Parameter | Default | Meaning |
|---|---|---|
| `-Scope` | `Both` | `Machine`, `User`, or `Both`. Machine requires elevation. |
| `-Execute` | off | Perform deletions. Absent = dry-run. |
| `-Show` | `Both` | `ToDelete`, `ToKeep`, or `Both` in the report. |
| `-NamePattern` | GUID regex | A container's friendly name must match to be eligible. |
| `-MinAgeDays` | `1` | Never touch a key file younger than this. |
| `-BackupPath` | `.\CapiKeyBackup-<ts>` | Every deleted key is copied here first, with `manifest.csv`. |
| `-AdditionalSkip` | — | Extra friendly names/patterns to protect. |
| `-ReportPath` | `.\CapiKeyReport-<ts>.csv` | CSV report output. |
| `-IgnoreKeepSetGaps` | off | Required to `-Execute` if some private-key certs can't be read. |

## Safety model — four independent keep-layers

A container is deleted only if it clears **all** of these:
1. **Not referenced** by any certificate or pending request (any store, both scopes).
2. **Not** on the system-key skip-list (`iisConfigurationKey`, `TSSecKeySet1`, …).
3. Its friendly name **matches** `-NamePattern` (default: a GUID — the leak's signature).
4. Its key file is **older** than `-MinAgeDays`.

Plus: dry-run default, backup-before-delete, and a hard stop if the keep-set is incomplete.

## First run on the target Windows box (runbook)

1. Copy both `.ps1` files over. Open an **elevated** PowerShell for machine scope.
2. Run a dry-run: `.\Remove-OrphanedCapiKeys.ps1 -Scope Both -Show Both`. Review `CapiKeyReport-*.csv`.
3. **Verify assumption A:** in the report, confirm `FriendlyName` for machine containers shows
   the **GUID** (not a mangled hash). If names look mangled, `PP_ENUMCONTAINERS` returned unique
   names on this box — adjust `-NamePattern` accordingly before executing.
4. **Verify assumption B:** confirm the leaked containers' friendly names are bare GUIDs; tune
   `-NamePattern` from what you see.
5. Confirm nothing you rely on is in the `ToDelete` set. Then run with `-Execute` (start with a
   high `-MinAgeDays`, e.g. 7). Keys are backed up under `-BackupPath`; restore by copying files
   back if needed.

## Development (macOS)

The pure logic is tested with Pester on macOS:
```bash
pwsh -NoProfile -c "Invoke-Pester -Path ./Remove-OrphanedCapiKeys.Tests.ps1 -Output Detailed"
```
Windows-only tests (CryptoAPI enumeration, cert stores, deletion) are tagged `Windows` and
skipped off-Windows; verify those via dry-run on the target box.
```

- [ ] **Step 5: Commit**

```bash
git add README.md Remove-OrphanedCapiKeys.ps1
git commit -m "docs: README with usage, safety model, and Windows runbook"
```

---

## Self-Review

**Spec coverage:**
- Both scopes → `Scope Both`, `Get-CapiKeyContainer`/`Get-CertificateKeyReference` iterate both (Tasks 4,5,7). ✓
- Legacy CAPI only → RSA CSP providers + `RSACryptoServiceProvider` filter (Tasks 4,5). ✓
- Protect REQUEST-store keys → `REQUEST` in `$storeNames` (Task 5). ✓
- GUID signature → default `-NamePattern` + classifier layer (Tasks 1,2). ✓
- Skip-list → `Get-DefaultSkipList` + classifier (Tasks 1,2). ✓
- P/Invoke enumeration → `Get-CapiKeyContainer` (Task 4). ✓
- Dry-run default → `-Execute` off; orchestrator never calls deleter without it (Task 7). ✓
- Backup + age filter + gap guard → Tasks 6,2,7. ✓
- Mac testability → pure funcs (Tasks 1,2,3) + injectable orchestrator (Task 7). ✓
- Reporting `-Show` ToDelete/ToKeep/Both → Task 3. ✓

**Placeholder scan:** No TBD/TODO; every code step contains complete code.

**Type consistency:** Container objects carry `FriendlyName, UniqueName, Scope, Provider, ProviderType, FilePath, FileLastWriteTime` consistently across Tasks 4/6/7; `KeepMap` is a lowercased-unique-name hashtable everywhere; disposition rows carry `Status`; report rows add `Action`. Deleter signature `($container, $backupPath)` matches injection in Task 7. ✓
