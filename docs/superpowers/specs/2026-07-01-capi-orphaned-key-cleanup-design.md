# Remove-OrphanedCapiKeys — Design

**Date:** 2026-07-01
**Status:** Approved (design phase)
**Target platform:** Windows (script authored/tested from macOS; cannot run against the target box)

## Problem

A Windows system runs code that leaves **legacy CAPI RSA private-key containers** behind
with no associated certificate. The root cause is C# code doing
`new X509Certificate2(pfx, password)` without `X509KeyStorageFlags.EphemeralKeySet` (and
without ever adding the cert to a store): the private key is imported into a **persisted**
CAPI container on disk, given a **GUID friendly name** by CAPI, and never cleaned up. Over
time these accumulate.

We want a PowerShell script that enumerates key containers, determines which are referenced
by a certificate (or a pending request), and deletes the unreferenced GUID-named leftovers —
**safely**, with a dry-run default, on a system we cannot test against directly.

## Scope decisions (locked)

| Decision | Choice |
|---|---|
| Language | PowerShell |
| Store locations | **Both** LocalMachine and CurrentUser |
| Key subsystem | **Legacy CAPI only** (`Microsoft\Crypto\RSA`); CNG (`Crypto\Keys`) out of scope |
| Pending-request keys | **Protected** — keys referenced by the `REQUEST` store are treated as in-use |
| Orphan signature | GUID friendly name from default `X509Certificate2` import |
| System-key skip-list | **Yes**, built-in |
| Enumeration engine | **P/Invoke CryptoAPI** (yields friendly + unique names) |

## Why the filename mapping is reliable

A CAPI container has a **friendly** name and a **unique** name (`PP_UNIQUE_CONTAINER`). On
disk the key file is named by the **unique** name, never the friendly one:

- Machine keys: `C:\ProgramData\Microsoft\Crypto\RSA\MachineKeys\<md5hash>_<MachineGuid>`
- User keys: `%APPDATA%\Microsoft\Crypto\RSA\<User-SID>\<unique>`

.NET exposes the unique name per certificate via
`((RSACryptoServiceProvider)cert.PrivateKey).CspKeyContainerInfo.UniqueKeyContainerName`,
which equals the filename. So all matching is **filename-to-filename** (compared
case-insensitively) — no friendly-name guessing.

## Key safety insight

Not every legitimate machine key has a certificate. `MachineKeys` also holds
intentionally cert-less system containers (`iisConfigurationKey`, `iisWasKey`,
`NetFrameworkConfigurationKey`, `TSSecKeySet1`, etc.). A naive "no cert → orphan" rule would
delete these and break IIS/RDP. The design defends against this with **four independent
layers**, any one of which keeps a container: cert/request reference, name skip-list,
required GUID name pattern, and minimum age — plus dry-run default and backup-before-delete.

## Architecture

Single script `Remove-OrphanedCapiKeys.ps1` + one Pester test file
`Remove-OrphanedCapiKeys.Tests.ps1`.

### Data flow
```
Enumerate containers (P/Invoke)           Build KEEP set (cert stores)
  Machine + CurrentUser                     Machine + CurrentUser, ALL store names
  → {FriendlyName, UniqueName(=file),        → certs/requests with private key
     Provider, Scope}                        → UniqueKeyContainerName (lowercased)
                     \                      /
                      → CLASSIFY each container (pure function) →
   status ∈ Referenced | SystemKey | NonMatchingName | TooNew | OrphanCandidate
                      → REPORT (console + CSV + transcript) →
                      → if -Execute: backup file, CryptAcquireContext(CRYPT_DELETEKEYSET)
```

## Components

### 1. Parameters / interface
- `-Scope Machine|User|Both` (default **Both**)
- `-Execute` switch — **absent = dry-run** (default). Deletion happens only with this flag.
- `-Show ToDelete|ToKeep|Both` (default **Both**)
- `-NamePattern <regex>` — friendly name **must** match to be eligible; default = GUID pattern
  (`^\{?[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}\}?$`, tunable from first dry-run)
- `-MinAgeDays <int>` (default **1**) — never touch a key younger than this
- `-BackupPath <dir>` (default `.\CapiKeyBackup-<timestamp>`) — key file copied here before delete, with a manifest
- `-AdditionalSkip <string[]>` — extend the built-in skip-list
- `-ReportPath <csv>` (default timestamped) + `Start-Transcript` log
- `-IgnoreKeepSetGaps` — required to `-Execute` when the keep-set may be incomplete (see §3 guard)
- `[CmdletBinding(SupportsShouldProcess)]` so native `-WhatIf/-Confirm` also work

### 2. Enumeration (P/Invoke, Windows-only)
`Add-Type` C# wrapping `CryptAcquireContext`, `CryptGetProvParam(PP_ENUMCONTAINERS=2)`,
`PP_UNIQUE_CONTAINER=36`, `CryptReleaseContext`. Iterate common RSA CSP provider types
(Microsoft Enhanced, Strong, Base, Enhanced RSA+AES, RSA SChannel), with
`CRYPT_MACHINE_KEYSET` for Machine and without for User; **dedupe by unique name**. For each
enumerated friendly name, acquire its context and read `PP_UNIQUE_CONTAINER` to get the
filename. Emits `{FriendlyName, UniqueName, Provider, Scope, FilePath}`.

### 3. KEEP set (protective core)
Enumerate **every** store name under `LocalMachine` and `CurrentUser` (My, `REQUEST`, and the
rest — over-inclusive is the safe direction). For each cert with `HasPrivateKey`, resolve the
CAPI `UniqueKeyContainerName` (CNG keys throw → skipped; they don't map to `Crypto\RSA`).
Collect lowercased unique names into KEEP, retaining the referencing cert
(thumbprint/subject) for the report.

**Keep-set gap guard:** if any private-key cert's unique name cannot be resolved (permissions,
etc.), the keep-set may be incomplete. Emit a loud warning and **refuse to `-Execute`** unless
`-IgnoreKeepSetGaps` is supplied. Deleting on an incomplete keep-set is the dangerous
direction, so uncertainty defaults to keep.

### 4. Classification — pure function (OS-agnostic, unit-testable on macOS)
`Get-KeyContainerDisposition` takes plain arrays/objects (containers, keep-set, skip-list,
name pattern, min age, "now") and returns a status per container. Precedence, first match
wins, everything defaults to **keep**:
1. `UniqueName ∈ KEEP` → **Referenced**
2. `FriendlyName` matches skip-list → **SystemKey**
3. `FriendlyName` does not match `-NamePattern` → **NonMatchingName**
4. file age `< MinAgeDays` → **TooNew**
5. else → **OrphanCandidate** (only deletable status)

Built-in skip-list: `iisConfigurationKey`, `iisWasKey`, `NetFrameworkConfigurationKey`,
`TSSecKeySet1`, and other well-known IIS/ASP.NET/RDP system container names.

### 5. Deletion + backup (only OrphanCandidates, only with -Execute)
Having the friendly name + provider from enumeration, delete via
`CryptAcquireContext(container, provider, CRYPT_DELETEKEYSET [| CRYPT_MACHINE_KEYSET])`,
falling back to file delete if the API call fails. Before each delete, copy the on-disk key
file into `-BackupPath` and append a manifest row (FriendlyName, UniqueName, Scope, Provider,
original path, timestamp) so any mistake is a copy-back.

### 6. Reporting
Console table + CSV with columns: `Scope, FriendlyName, UniqueName, FilePath, FileAgeDays,
Status, ReferencedBy (thumbprint/subject), Action (WouldDelete|WouldKeep|Deleted|Skipped)`.
`-Show` filters console output to ToDelete / ToKeep / Both. Summary counts by status.
Everything captured to a transcript log.

### 7. Preconditions
- Machine scope requires elevation → `WindowsPrincipal.IsInRole(Administrator)`; exit with
  guidance if not elevated.
- User scope only ever touches the **running user's** SID folder.
- Any per-container API error → log and treat as **keep**.

## Testing strategy

The classifier (§4) is pure and OS-agnostic → Pester tests run under PowerShell Core **on the
Mac**, covering at minimum:
- referenced key → kept
- GUID-named unreferenced key → OrphanCandidate
- system-key name → kept even if unreferenced
- non-GUID name → kept
- key younger than MinAgeDays → kept
- keep-set-gap guard blocks execute without override

Windows-only P/Invoke + store enumeration stay thin and are exercised via **dry-run on the
real box** before any `-Execute`.

## Assumptions to verify on Windows during first dry-run
1. For **machine** keys, `PP_ENUMCONTAINERS` returns the GUID **friendly** name (not the
   mangled unique name). If it returns unique names instead, adjust the `-NamePattern` default
   and the classification input accordingly.
2. The leaked containers' friendly names are bare GUIDs — tune `-NamePattern` from the first
   dry-run output.

## Out of scope
- CNG keys (`Microsoft\Crypto\Keys`).
- Other users' CurrentUser stores / SID folders.
- Fixing the upstream C# leak (documented as the recommended real fix: pass
  `X509KeyStorageFlags.EphemeralKeySet`, or dispose/remove the container after use).
