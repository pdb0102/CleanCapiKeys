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

The pure logic is tested with Pester on macOS (install PowerShell 7 via `brew install powershell`):
```bash
pwsh -NoProfile -c "Invoke-Pester -Path ./Remove-OrphanedCapiKeys.Tests.ps1 -Output Detailed"
```
Windows-only tests (CryptoAPI enumeration, cert stores, deletion) are tagged `Windows` and
skipped off-Windows; verify those via dry-run on the target box.
