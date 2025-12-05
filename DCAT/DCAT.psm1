# DCAT.psm1 – Defender Control & Audit Toolkit
# ============================================
# This module is designed to:
#   1) Show current Defender configuration (Get-DCATStatus)
#   2) Compare current config vs a JSON preset and compute a score (Get-DCATCompliance / Get-DCATScore)
#   3) Apply a hardening preset from JSON (Set-DCATHardening)
#   4) Backup + restore original Defender config (New-DCATBackup / Get-DCATBackup / Restore-DCATBackup)
#   5) Create per-run safety snapshots before hardening (New-DCATRestorePoint / Restore-DCATRestorePoint)
#   6) Compare original backup vs current config (Get-DCATBackupDiff)
#
# Typical usage:
#   Import-Module .\DCAT -Force
#
#   # 1) Initial score
#   Get-DCATScore -Preset CISLevel1
#
#   # 2) Safe dry-run of hardening
#   Set-DCATHardening -Preset CISLevel1 -WhatIf
#
#   # 3) Apply hardening
#   Set-DCATHardening -Preset CISLevel1
#
#   # 4) New score + breakdown
#   Get-DCATScore -Preset CISLevel1
#
#   # 5) View backup and rollback
#   Get-DCATBackup
#   Restore-DCATBackup -WhatIf   # preview
#   Restore-DCATBackup           # apply
#
#   # 6) Per-run restore snapshot (auto + manual)
#   New-DCATRestorePoint -Preset MicrosoftStrict
#   Restore-DCATRestorePoint -Latest
#
#   # 7) Compare original backup vs current config
#   Get-DCATBackupDiff

# -------------------------------------------------------------------
# Module paths
# -------------------------------------------------------------------
$ModuleRoot  = $PSScriptRoot
$PresetsPath = Join-Path $ModuleRoot 'Presets'

# Use a global-ish path so backup & snapshots survive module folder changes
$script:BackupFile   = Join-Path $env:ProgramData 'DCAT\DCAT-Original-Backup.json'
$script:SnapshotDir  = Join-Path $env:ProgramData 'DCAT\Snapshots'

# -------------------------------------------------------------------
# 1. Get-DCATStatus – show key Defender settings
# -------------------------------------------------------------------
function Get-DCATStatus {
    <#
    .SYNOPSIS
        Shows a condensed view of important Defender settings.
    #>

    # Collect current Defender status and preferences
    $s = Get-MpComputerStatus
    $p = Get-MpPreference

    # Tamper Protection (stored in registry on some builds)
    $tamper = $null
    try {
        $regPath = 'HKLM:\SOFTWARE\Microsoft\Windows Defender\Features'
        $tamper  = (Get-ItemProperty -Path $regPath -ErrorAction SilentlyContinue).TamperProtection
    }
    catch {
        $tamper = $null
    }

    [PSCustomObject]@{
        ComputerName         = $env:COMPUTERNAME
        RealTimeProtection   = $s.RealTimeProtectionEnabled
        PUAProtection        = $p.PUAProtection
        SubmitSamplesConsent = $p.SubmitSamplesConsent
        MAPSReporting        = $p.MAPSReporting
        CloudBlockLevel      = $p.CloudBlockLevel
        CloudExtendedTimeout = $p.CloudExtendedTimeout
        NetworkProtection    = $p.EnableNetworkProtection
        TamperProtection     = $tamper
        ASRRuleCount         = $p.AttackSurfaceReductionRules_Ids.Count
        ScanCPU              = $p.ScanAvgCPULoadFactor
        BlockAtFirstSeen     = -not $p.DisableBlockAtFirstSeen
    }
}

# -------------------------------------------------------------------
# 1a. New-DCATBackup – create first-time backup of original config
# -------------------------------------------------------------------
function New-DCATBackup {
    <#
    .SYNOPSIS
        Creates a one-time backup of the original Defender config.
    .DESCRIPTION
        The backup is stored at:
            $env:ProgramData\DCAT\DCAT-Original-Backup.json
        and is based on Get-DCATStatus output, plus BackupDate.
    #>
    [CmdletBinding()]
    param()

    $backupDir = Split-Path $script:BackupFile -Parent
    if (-not (Test-Path $backupDir)) {
        New-Item -Path $backupDir -ItemType Directory -Force | Out-Null
    }

    if (Test-Path $script:BackupFile) {
        $existing = Get-Item $script:BackupFile
        Write-Host "DCAT backup already exists (created $($existing.CreationTime))" -ForegroundColor Cyan
        return
    }

    Write-Host "Creating first-time backup of your original Defender config..." -ForegroundColor Yellow
    $original = Get-DCATStatus

    $original | Add-Member -NotePropertyName 'BackupDate' -NotePropertyValue (Get-Date) -Force

    $original | ConvertTo-Json -Depth 10 | Out-File $script:BackupFile -Encoding UTF8 -Force
    Write-Host "Original config backed up to:`n   $script:BackupFile" -ForegroundColor Green
}

# -------------------------------------------------------------------
# 1b. Get-DCATBackup – view stored backup
# -------------------------------------------------------------------
function Get-DCATBackup {
    <#
    .SYNOPSIS
        Displays the stored original Defender configuration backup.
    #>
    [CmdletBinding()]
    param()

    if (-not (Test-Path $script:BackupFile)) {
        Write-Warning "No backup found. Run New-DCATBackup or apply a preset to create it."
        return
    }

    Get-Content $script:BackupFile -Raw | ConvertFrom-Json | Format-List
}

# -------------------------------------------------------------------
# 1c. Restore-DCATBackup – rollback to original config
# -------------------------------------------------------------------
function Restore-DCATBackup {
    <#
    .SYNOPSIS
        Restores Defender configuration from the original DCAT backup.

    .DESCRIPTION
        Uses the backup captured by New-DCATBackup (Get-DCATStatus snapshot).
        Only fields that map cleanly to Set-MpPreference are restored:
            - PUAProtection
            - SubmitSamplesConsent
            - MAPSReporting
            - CloudBlockLevel
            - CloudExtendedTimeout
            - NetworkProtection (→ EnableNetworkProtection)
            - ScanCPU (→ ScanAvgCPULoadFactor)
            - BlockAtFirstSeen (→ DisableBlockAtFirstSeen)
        RealTimeProtection / TamperProtection / ASRRuleCount are not changed.
    #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [switch]$Force
    )

    if (-not (Test-Path $script:BackupFile)) {
        throw "No DCAT backup found at $script:BackupFile. Cannot restore."
    }

    $backup = Get-Content $script:BackupFile -Raw | ConvertFrom-Json

    $backupDate = $backup.BackupDate
    if (-not $PSCmdlet.ShouldProcess("Microsoft Defender", "Restore original config from backup dated $backupDate")) {
        return
    }

    if (-not $Force) {
        $confirm = Read-Host "This will overwrite key Defender settings. Type YES to continue"
        if ($confirm -ne 'YES') {
            Write-Host "Restore cancelled." -ForegroundColor Yellow
            return
        }
    }

    Write-Host "Restoring your original Defender configuration..." -ForegroundColor Yellow

    $mpParams = @{}

    if ($null -ne $backup.PUAProtection)        { $mpParams['PUAProtection']           = [int]$backup.PUAProtection }
    if ($null -ne $backup.SubmitSamplesConsent) { $mpParams['SubmitSamplesConsent']    = [int]$backup.SubmitSamplesConsent }
    if ($null -ne $backup.MAPSReporting)        { $mpParams['MAPSReporting']           = [int]$backup.MAPSReporting }
    if ($null -ne $backup.CloudBlockLevel)      { $mpParams['CloudBlockLevel']         = $backup.CloudBlockLevel }
    if ($null -ne $backup.CloudExtendedTimeout) { $mpParams['CloudExtendedTimeout']    = [int]$backup.CloudExtendedTimeout }
    if ($null -ne $backup.NetworkProtection)    { $mpParams['EnableNetworkProtection'] = [int]$backup.NetworkProtection }
    if ($null -ne $backup.ScanCPU)              { $mpParams['ScanAvgCPULoadFactor']    = [int]$backup.ScanCPU }

    if ($null -ne $backup.BlockAtFirstSeen) {
        # BlockAtFirstSeen is a boolean in status, but MpPreference uses DisableBlockAtFirstSeen (inverse).
        $mpParams['DisableBlockAtFirstSeen'] = -not [bool]$backup.BlockAtFirstSeen
    }

    if ($mpParams.Count -eq 0) {
        Write-Warning "Backup file exists but contains no restorable MpPreference fields."
        return
    }

    try {
        Set-MpPreference @mpParams -Force -ErrorAction Stop
        Write-Host "Original configuration restored successfully!" -ForegroundColor Green
        Write-Host "Reboot recommended for full effect." -ForegroundColor Cyan
    }
    catch {
        Write-Warning "Failed to restore some Defender settings: $_"
    }
}

# -------------------------------------------------------------------
# 1d. New-DCATRestorePoint – per-run safety snapshot
# -------------------------------------------------------------------
function New-DCATRestorePoint {
    <#
    .SYNOPSIS
        Creates a per-run safety snapshot of the current Defender config.

    .DESCRIPTION
        Stored under:
            $env:ProgramData\DCAT\Snapshots\DCAT-RestorePoint-<Preset>-<timestamp>.json

        Uses Get-DCATStatus output plus:
            - SnapshotDate
            - Preset (if provided)
    #>
    [CmdletBinding()]
    param(
        [string]$Preset
    )

    if (-not (Test-Path $script:SnapshotDir)) {
        New-Item -Path $script:SnapshotDir -ItemType Directory -Force | Out-Null
    }

    $stamp    = Get-Date -Format 'yyyyMMdd-HHmmss'
    $suffix   = if ($Preset) { "$Preset-$stamp" } else { $stamp }
    $fileName = "DCAT-RestorePoint-$suffix.json"
    $path     = Join-Path $script:SnapshotDir $fileName

    $snap = Get-DCATStatus
    $snap | Add-Member -NotePropertyName 'SnapshotDate' -NotePropertyValue (Get-Date) -Force
    if ($Preset) {
        $snap | Add-Member -NotePropertyName 'Preset' -NotePropertyValue $Preset -Force
    }

    $snap | ConvertTo-Json -Depth 10 | Out-File $path -Encoding UTF8 -Force
    Write-Host "DCAT restore snapshot created at:`n   $path" -ForegroundColor Green

    return $path
}

# -------------------------------------------------------------------
# 1e. Restore-DCATRestorePoint – restore from latest or specific snapshot
# -------------------------------------------------------------------
function Restore-DCATRestorePoint {
    <#
    .SYNOPSIS
        Restores Defender settings from a DCAT restore snapshot.

    .DESCRIPTION
        - By default restores from the most recent snapshot in:
              $env:ProgramData\DCAT\Snapshots
        - Or you can supply a specific JSON file path with -Path.
        - Uses the same mapping as Restore-DCATBackup.
    #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [string]$Path,
        [switch]$Latest,
        [switch]$Force
    )

    if (-not (Test-Path $script:SnapshotDir)) {
        throw "No restore snapshot directory found at $script:SnapshotDir."
    }

    $targetPath = $null

    if ($Path) {
        if (-not (Test-Path $Path)) {
            throw "Specified restore snapshot not found: $Path"
        }
        $targetPath = $Path
    }
    else {
        # Default or -Latest: pick the newest snapshot
        $files = Get-ChildItem -Path $script:SnapshotDir -Filter 'DCAT-RestorePoint-*.json' -ErrorAction SilentlyContinue |
                 Sort-Object LastWriteTime -Descending

        if (-not $files -or $files.Count -eq 0) {
            throw "No restore snapshots found in $script:SnapshotDir."
        }

        $targetPath = $files[0].FullName
    }

    $snap = Get-Content $targetPath -Raw | ConvertFrom-Json
    $snapDate = $snap.SnapshotDate
    $snapPreset = $snap.Preset

    $label = if ($snapPreset) {
        "restore snapshot for preset '$snapPreset' taken $snapDate"
    } else {
        "restore snapshot taken $snapDate"
    }

    if (-not $PSCmdlet.ShouldProcess("Microsoft Defender", "Restore from $label")) {
        return
    }

    if (-not $Force) {
        $confirm = Read-Host "This will overwrite key Defender settings from $targetPath. Type YES to continue"
        if ($confirm -ne 'YES') {
            Write-Host "Restore cancelled." -ForegroundColor Yellow
            return
        }
    }

    Write-Host "Restoring Defender configuration from snapshot:`n   $targetPath" -ForegroundColor Yellow

    $mpParams = @{}

    if ($null -ne $snap.PUAProtection)        { $mpParams['PUAProtection']           = [int]$snap.PUAProtection }
    if ($null -ne $snap.SubmitSamplesConsent) { $mpParams['SubmitSamplesConsent']    = [int]$snap.SubmitSamplesConsent }
    if ($null -ne $snap.MAPSReporting)        { $mpParams['MAPSReporting']           = [int]$snap.MAPSReporting }
    if ($null -ne $snap.CloudBlockLevel)      { $mpParams['CloudBlockLevel']         = $snap.CloudBlockLevel }
    if ($null -ne $snap.CloudExtendedTimeout) { $mpParams['CloudExtendedTimeout']    = [int]$snap.CloudExtendedTimeout }
    if ($null -ne $snap.NetworkProtection)    { $mpParams['EnableNetworkProtection'] = [int]$snap.NetworkProtection }
    if ($null -ne $snap.ScanCPU)              { $mpParams['ScanAvgCPULoadFactor']    = [int]$snap.ScanCPU }

    if ($null -ne $snap.BlockAtFirstSeen) {
        $mpParams['DisableBlockAtFirstSeen'] = -not [bool]$snap.BlockAtFirstSeen
    }

    if ($mpParams.Count -eq 0) {
        Write-Warning "Snapshot file exists but contains no restorable MpPreference fields."
        return
    }

    try {
        Set-MpPreference @mpParams -Force -ErrorAction Stop
        Write-Host "Restore snapshot applied successfully." -ForegroundColor Green
        Write-Host "Reboot recommended for full effect." -ForegroundColor Cyan
    }
    catch {
        Write-Warning "Failed to restore some Defender settings from snapshot: $_"
    }
}

# -------------------------------------------------------------------
# 1f. Get-DCATBackupDiff – compare original backup vs current
# -------------------------------------------------------------------
function Get-DCATBackupDiff {
    <#
    .SYNOPSIS
        Compares the original DCAT backup vs current Defender status.

    .DESCRIPTION
        Produces a table with:
            Setting, BackupValue, CurrentValue, Changed (bool)
        Based on Get-DCATStatus fields.
    #>
    [CmdletBinding()]
    param()

    if (-not (Test-Path $script:BackupFile)) {
        Write-Warning "No DCAT backup found at $script:BackupFile. Run New-DCATBackup or apply a preset to create it."
        return
    }

    $backup  = Get-Content $script:BackupFile -Raw | ConvertFrom-Json
    $current = Get-DCATStatus

    $fields = @(
        'RealTimeProtection',
        'PUAProtection',
        'SubmitSamplesConsent',
        'MAPSReporting',
        'CloudBlockLevel',
        'CloudExtendedTimeout',
        'NetworkProtection',
        'ScanCPU',
        'BlockAtFirstSeen',
        'TamperProtection',
        'ASRRuleCount'
    )

    $diff = foreach ($name in $fields) {
        $b = $backup.$name
        $c = $current.$name

        # Normalize for comparison (stringify)
        $bKey = if ($null -eq $b) { '<null>' } else { $b.ToString() }
        $cKey = if ($null -eq $c) { '<null>' } else { $c.ToString() }

        [PSCustomObject]@{
            Setting      = $name
            BackupValue  = $b
            CurrentValue = $c
            Changed      = ($bKey -ne $cKey)
        }
    }

    Write-Host "DCAT Backup vs Current comparison:" -ForegroundColor Cyan

    $diff |
        Sort-Object -Property Changed, Setting -Descending |
        Format-Table Setting, BackupValue, CurrentValue, Changed -AutoSize

    return $diff
}

# -------------------------------------------------------------------
# 2. Get-DCATCompliance – core scoring logic + breakdown
# -------------------------------------------------------------------
function Get-DCATCompliance {
    <#
    .SYNOPSIS
        Compares current Defender config against a JSON preset and computes a score.
    #>

    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('MicrosoftStrict','CISLevel1','CISLevel2','DCATParanoid')]
        [string]$Preset
    )

    # --- helpers (only used inside this function) --------------------

    function Normalize-CloudBlockLevel {
        param($value)

        if ($null -eq $value) { return 0 }

        $s = $value.ToString()
        switch ($s.ToLower()) {
            'high'       { return 2 }
            'highplus'   { return 2 }
            'block'      { return 2 }
            'default'    { return 0 }
            '0'          { return 0 }
            '1'          { return 1 }
            '2'          { return 2 }
            default {
                if ($s -match '^\d+$') {
                    return [int]$s
                }
                else {
                    return 0
                }
            }
        }
    }

    function Compare-DCATExclusions {
        param(
            $expected,
            $actual
        )

        $exp = @()
        if ($expected -ne $null) {
            $exp = @($expected) | Where-Object { $_ -ne $null -and $_ -ne '' }
        }

        $act = @()
        if ($actual -ne $null) {
            $act = @($actual) | Where-Object { $_ -ne $null -and $_ -ne '' }
        }

        # Both effectively empty → treated as "no exclusions" → PASS
        if ($exp.Count -eq 0 -and $act.Count -eq 0) {
            return $true
        }

        # Compare sets case-insensitively
        if ($exp.Count -ne $act.Count) { return $false }

        $expKey = ($exp | ForEach-Object { $_.ToString().ToLower() } | Sort-Object) -join ','
        $actKey = ($act | ForEach-Object { $_.ToString().ToLower() } | Sort-Object) -join ','

        return ($expKey -eq $actKey)
    }

    # Read current Defender config
    $pref   = Get-MpPreference
    $status = Get-MpComputerStatus

    # Load preset JSON
    $file = Join-Path $PresetsPath "$Preset.json"
    if (-not (Test-Path $file)) {
        throw "Preset not found: $file"
    }

    $cfg = Get-Content $file -Raw | ConvertFrom-Json
    $mp  = $cfg.MpPreferences

    # Score accumulators
    $score    = 0.0
    $maxScore = 0.0

    # Breakdown list
    $items = @()

    # -------------------------------------------------------------------
    # Scalar checks (weights noted in comments)
    # -------------------------------------------------------------------

    if ($null -ne $mp.PUAProtection) {
        $w   = 10
        $ok  = ($pref.PUAProtection -eq $mp.PUAProtection)
        $maxScore += $w
        if ($ok) { $score += $w }
        $items += [PSCustomObject]@{
            Setting  = 'PUAProtection'
            Weight   = $w
            Expected = $mp.PUAProtection
            Actual   = $pref.PUAProtection
            Passed   = $ok
        }
    }

    if ($null -ne $mp.SubmitSamplesConsent) {
        $w   = 5
        $ok  = ($pref.SubmitSamplesConsent -eq $mp.SubmitSamplesConsent)
        $maxScore += $w
        if ($ok) { $score += $w }
        $items += [PSCustomObject]@{
            Setting  = 'SubmitSamplesConsent'
            Weight   = $w
            Expected = $mp.SubmitSamplesConsent
            Actual   = $pref.SubmitSamplesConsent
            Passed   = $ok
        }
    }

    if ($null -ne $mp.MAPSReporting) {
        $w   = 5
        $ok  = ($pref.MAPSReporting -eq $mp.MAPSReporting)
        $maxScore += $w
        if ($ok) { $score += $w }
        $items += [PSCustomObject]@{
            Setting  = 'MAPSReporting'
            Weight   = $w
            Expected = $mp.MAPSReporting
            Actual   = $pref.MAPSReporting
            Passed   = $ok
        }
    }

    if ($mp.CloudBlockLevel) {
        $w = 20

        $expNorm = Normalize-CloudBlockLevel $mp.CloudBlockLevel
        $actNorm = Normalize-CloudBlockLevel $pref.CloudBlockLevel

        # Treat "actual >= expected" as compliant (never penalize stricter)
        $ok  = ($actNorm -ge $expNorm)

        $maxScore += $w
        if ($ok) { $score += $w }

        $items += [PSCustomObject]@{
            Setting  = 'CloudBlockLevel'
            Weight   = $w
            Expected = $mp.CloudBlockLevel
            Actual   = $pref.CloudBlockLevel
            Passed   = $ok
        }
    }

    if ($null -ne $mp.CloudExtendedTimeout) {
        # actual <= baseline is acceptable
        $w   = 10
        $ok  = ($pref.CloudExtendedTimeout -le $mp.CloudExtendedTimeout)
        $maxScore += $w
        if ($ok) { $score += $w }
        $items += [PSCustomObject]@{
            Setting  = 'CloudExtendedTimeout'
            Weight   = $w
            Expected = $mp.CloudExtendedTimeout
            Actual   = $pref.CloudExtendedTimeout
            Passed   = $ok
        }
    }

    if ($null -ne $mp.EnableNetworkProtection) {
        $w   = 15
        $ok  = ($pref.EnableNetworkProtection -eq $mp.EnableNetworkProtection)
        $maxScore += $w
        if ($ok) { $score += $w }
        $items += [PSCustomObject]@{
            Setting  = 'EnableNetworkProtection'
            Weight   = $w
            Expected = $mp.EnableNetworkProtection
            Actual   = $pref.EnableNetworkProtection
            Passed   = $ok
        }
    }

    if ($null -ne $mp.EnableControlledFolderAccess) {
        $w   = 10
        $ok  = ($pref.EnableControlledFolderAccess -eq $mp.EnableControlledFolderAccess)
        $maxScore += $w
        if ($ok) { $score += $w }
        $items += [PSCustomObject]@{
            Setting  = 'EnableControlledFolderAccess'
            Weight   = $w
            Expected = $mp.EnableControlledFolderAccess
            Actual   = $pref.EnableControlledFolderAccess
            Passed   = $ok
        }
    }

    if ($null -ne $mp.ScanAvgCPULoadFactor) {
        # actual <= baseline is acceptable
        $w   = 5
        $ok  = ($pref.ScanAvgCPULoadFactor -le $mp.ScanAvgCPULoadFactor)
        $maxScore += $w
        if ($ok) { $score += $w }
        $items += [PSCustomObject]@{
            Setting  = 'ScanAvgCPULoadFactor'
            Weight   = $w
            Expected = $mp.ScanAvgCPULoadFactor
            Actual   = $pref.ScanAvgCPULoadFactor
            Passed   = $ok
        }
    }

    if ($null -ne $mp.DisableBlockAtFirstSeen) {
        $w   = 5
        $ok  = ($pref.DisableBlockAtFirstSeen -eq $mp.DisableBlockAtFirstSeen)
        $maxScore += $w
        if ($ok) { $score += $w }
        $items += [PSCustomObject]@{
            Setting  = 'DisableBlockAtFirstSeen'
            Weight   = $w
            Expected = $mp.DisableBlockAtFirstSeen
            Actual   = $pref.DisableBlockAtFirstSeen
            Passed   = $ok
        }
    }

    if ($null -ne $mp.RealTimeProtection) {
        $w   = 10
        $ok  = ($status.RealTimeProtectionEnabled -eq $mp.RealTimeProtection)
        $maxScore += $w
        if ($ok) { $score += $w }
        $items += [PSCustomObject]@{
            Setting  = 'RealTimeProtection'
            Weight   = $w
            Expected = $mp.RealTimeProtection
            Actual   = $status.RealTimeProtectionEnabled
            Passed   = $ok
        }
    }

    # -------------------------------------------------------------------
    # Extra knobs (used by MicrosoftStrict and others)
    # -------------------------------------------------------------------
    $extraScalarProps = @(
        'AllowNetworkProtectionOnWinServer',
        'AllowDatagramProcessingOnWinServer',
        'AttackSurfaceReductionOnlyExclusions',
        'ControlledFolderAccess_Exclusions',
        'EngineUpdatesChannel',
        'PlatformUpdatesChannel',
        'SignatureUpdateInterval',
        'MeteredConnectionUpdates',
        'HighThreatDefaultAction',
        'ModerateThreatDefaultAction',
        'LowThreatDefaultAction',
        'SevereThreatDefaultAction'
    )

    foreach ($name in $extraScalarProps) {
        if ($null -ne $mp.$name) {
            $w        = 3
            $expected = $mp.$name
            $actual   = $pref.$name

            if ($name -eq 'AttackSurfaceReductionOnlyExclusions' -or
                $name -eq 'ControlledFolderAccess_Exclusions') {

                # Special handling: treat null vs empty as equal = "no exclusions"
                $ok = Compare-DCATExclusions $expected $actual
            }
            else {
                $ok = ($actual -eq $expected)
            }

            $maxScore += $w
            if ($ok) { $score += $w }

            $items += [PSCustomObject]@{
                Setting  = $name
                Weight   = $w
                Expected = $expected
                Actual   = $actual
                Passed   = $ok
            }
        }
    }

    # -------------------------------------------------------------------
    # ASR rules: per-rule partial credit based on ID+action match
    # -------------------------------------------------------------------
    if ($mp.AttackSurfaceReductionRules_Ids -and $mp.AttackSurfaceReductionRules_Actions) {
        $expected = @{}
        for ($i = 0; $i -lt $mp.AttackSurfaceReductionRules_Ids.Count; $i++) {
            $id  = $mp.AttackSurfaceReductionRules_Ids[$i]
            $act = $mp.AttackSurfaceReductionRules_Actions[$i]
            $expected[$id] = $act
        }

        $current = @{}
        if ($pref.AttackSurfaceReductionRules_Ids -and $pref.AttackSurfaceReductionRules_Actions) {
            for ($i = 0; $i -lt $pref.AttackSurfaceReductionRules_Ids.Count; $i++) {
                $id  = $pref.AttackSurfaceReductionRules_Ids[$i]
                $act = $pref.AttackSurfaceReductionRules_Actions[$i]
                $current[$id] = $act
            }
        }

        $asrWeight     = 25.0
        $perRuleWeight = if ($expected.Count -gt 0) { $asrWeight / $expected.Count } else { 0 }

        foreach ($id in $expected.Keys) {
            $w        = $perRuleWeight
            $exp      = $expected[$id]
            $act      = if ($current.ContainsKey($id)) { $current[$id] } else { $null }
            $ok       = ($act -eq $exp)

            $maxScore += $w
            if ($ok) { $score += $w }

            $items += [PSCustomObject]@{
                Setting  = "ASR:$id"
                Weight   = [math]::Round($w,2)
                Expected = $exp
                Actual   = $act
                Passed   = $ok
            }
        }
    }

    # -------------------------------------------------------------------
    # Final percentage & grade
    # -------------------------------------------------------------------
    if ($maxScore -le 0) {
        $percent = 0
    }
    else {
        $percent = [math]::Round(($score / $maxScore) * 100, 0)
    }

    # Fixed grading (single grade, no array)
    if     ($percent -ge 97) { $grade = 'A+' }
    elseif ($percent -ge 93) { $grade = 'A'  }
    elseif ($percent -ge 90) { $grade = 'A-' }
    elseif ($percent -ge 87) { $grade = 'B+' }
    elseif ($percent -ge 83) { $grade = 'B'  }
    elseif ($percent -ge 80) { $grade = 'B-' }
    elseif ($percent -ge 77) { $grade = 'C+' }
    elseif ($percent -ge 73) { $grade = 'C'  }
    elseif ($percent -ge 70) { $grade = 'C-' }
    elseif ($percent -ge 60) { $grade = 'D'  }
    else                     { $grade = 'F'  }

    [PSCustomObject]@{
        ComputerName = $env:COMPUTERNAME
        Preset       = $Preset
        DCATScore    = $percent
        Grade        = $grade
        EvaluatedOn  = Get-Date
        Breakdown    = $items
    }
}

# -------------------------------------------------------------------
# 3. Get-DCATScore – summary + breakdown table
# -------------------------------------------------------------------
function Get-DCATScore {
    <#
    .SYNOPSIS
        Returns score/grade and also prints a breakdown table.
    #>

    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('MicrosoftStrict','CISLevel1','CISLevel2','DCATParanoid')]
        [string]$Preset
    )

    $result = Get-DCATCompliance -Preset $Preset

    # 1) Output summary object (for pipeline use)
    $summary = $result | Select-Object ComputerName, Preset, DCATScore, Grade, EvaluatedOn
    $summary

    # 2) Output formatted breakdown table for interactive users
    if ($result.Breakdown -and $result.Breakdown.Count -gt 0) {
        Write-Host ""
        Write-Host "DCAT Score Breakdown:" -ForegroundColor Cyan
        $result.Breakdown |
            Sort-Object Passed, Setting |
            Format-Table Setting, Weight, Expected, Actual, Passed -AutoSize
    }
}

# -------------------------------------------------------------------
# 4. Set-DCATHardening – apply JSON preset (MpPreferences + Registry)
# -------------------------------------------------------------------
function Set-DCATHardening {
    <#
    .SYNOPSIS
        Applies a Defender hardening preset from the Presets folder.

    .DESCRIPTION
        Reads <Preset>.json, then:
            - Applies MpPreferences (Set-MpPreference)
            - Applies Registry keys from the "Registry" section
        Use -WhatIf to see changes without applying them.
    #>

    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('MicrosoftStrict','CISLevel1','CISLevel2','DCATParanoid')]
        [string]$Preset,

        [switch]$WhatIf
    )

    # Load preset JSON
    $file = Join-Path $PresetsPath "$Preset.json"
    if (-not (Test-Path $file)) {
        throw "Preset not found: $file"
    }

    $cfg = Get-Content $file -Raw | ConvertFrom-Json

    Write-Host "Applying preset: $($cfg.Name)" -ForegroundColor Cyan

    # Create a per-run restore snapshot before making changes (non-WhatIf only)
    if (-not $WhatIf) {
        try {
            New-DCATRestorePoint -Preset $Preset | Out-Null
        }
        catch {
            Write-Warning "DCAT: Failed to create restore snapshot before hardening: $_"
        }
    }

    # -------------------- MpPreferences ------------------------------
    if ($cfg.MpPreferences) {
        $mp = $cfg.MpPreferences

        # 4a) Apply ASR rules (IDs + Actions) together
        if ($mp.AttackSurfaceReductionRules_Ids -and $mp.AttackSurfaceReductionRules_Actions) {
            $asrParams = @{
                AttackSurfaceReductionRules_Ids     = $mp.AttackSurfaceReductionRules_Ids
                AttackSurfaceReductionRules_Actions = $mp.AttackSurfaceReductionRules_Actions
            }

            if ($WhatIf) {
                Write-Host "[WHATIF] Set-MpPreference (ASR rules):" -ForegroundColor Yellow
                Write-Host ("         Ids:     " + ($asrParams.AttackSurfaceReductionRules_Ids -join ',')) -ForegroundColor Yellow
                Write-Host ("         Actions: " + ($asrParams.AttackSurfaceReductionRules_Actions -join ',')) -ForegroundColor Yellow
            }
            else {
                try {
                    Set-MpPreference @asrParams -Force -ErrorAction Stop
                    Write-Host "Applied ASR rules." -ForegroundColor Green
                }
                catch {
                    Write-Warning ("Failed to apply ASR rules: " + $_)
                }
            }
        }

        # 4b) Apply remaining MpPreferences in one shot (skip null/empty collections)
        $mpParams = @{}
        foreach ($prop in $mp.PSObject.Properties) {
            if ($prop.Name -in @(
                'AttackSurfaceReductionRules_Ids',
                'AttackSurfaceReductionRules_Actions',
                'RealTimeProtection'  # no direct Set-MpPreference switch
            )) {
                continue
            }

            $value = $prop.Value

            # Skip null values completely
            if ($null -eq $value) {
                continue
            }

            # If it's a collection (array/list) and not a string:
            #   - remove any null elements
            #   - skip if it becomes empty
            if ($value -is [System.Collections.IEnumerable] -and -not ($value -is [string])) {
                $clean = @($value | Where-Object { $_ -ne $null })
                if ($clean.Count -eq 0) {
                    continue
                }
                $value = $clean
            }

            $mpParams[$prop.Name] = $value
        }

        if ($mpParams.Count -gt 0) {
            if ($WhatIf) {
                Write-Host "[WHATIF] Set-MpPreference (MpPreferences from preset):" -ForegroundColor Yellow
                foreach ($kv in $mpParams.GetEnumerator()) {
                    $val = $kv.Value
                    if ($val -is [array]) { $val = $val -join ',' }
                    Write-Host ("         -" + $kv.Key + " " + $val) -ForegroundColor Yellow
                }
            }
            else {
                try {
                    Set-MpPreference @mpParams -Force -ErrorAction Stop
                    Write-Host "Applied MpPreferences." -ForegroundColor Green
                }
                catch {
                    Write-Warning ("Some MpPreferences settings failed: " + $_)
                }
            }
        }
    }

    # -------------------- Registry section ---------------------------
    # JSON shape expected:
    #   "Registry": {
    #     "HKLM\\Path\\To\\Key": {
    #        "ValueName1": 1,
    #        "ValueName2": "string"
    #     }
    #   }
    if ($cfg.Registry) {
        foreach ($pathProp in $cfg.Registry.PSObject.Properties) {
            $rawPath = $pathProp.Name
            $values  = $pathProp.Value

            # Convert bare HKLM\... into a proper Registry:: path
            $path = $rawPath
            if ($path -like 'HKLM\*' -or $path -like 'HKEY_LOCAL_MACHINE\*') {
                $path = "Registry::$path"
            }

            foreach ($valueProp in $values.PSObject.Properties) {
                $name  = $valueProp.Name
                $value = $valueProp.Value

                # Simple type inference: int = DWord, string = String
                $type = if ($value -is [string]) { 'String' } else { 'DWord' }

                if ($WhatIf) {
                    Write-Host "[WHATIF] REGISTRY: $rawPath\$name = $value ($type)" -ForegroundColor Yellow
                }
                else {
                    try {
                        New-Item -Path $path -Force | Out-Null
                        New-ItemProperty -Path $path -Name $name -Value $value -PropertyType $type -Force | Out-Null
                        Write-Host "Applied registry: $rawPath\$name = $value" -ForegroundColor Green
                    }
                    catch {
                        Write-Warning ("Registry failed: $rawPath\$name - " + $_)
                    }
                }
            }
        }
    }

    # Final status
    if ($WhatIf) {
        Write-Host "`nWhatIf: No changes were made." -ForegroundColor Cyan
    }
    else {
        Write-Host "`nPreset [$Preset] applied. A reboot may be required for all changes to take effect." -ForegroundColor Green
    }
}

# -------------------------------------------------------------------
# Auto-create original backup on first module load (runs once ever)
# -------------------------------------------------------------------
if (-not (Test-Path $script:BackupFile)) {
    try {
        New-DCATBackup
    }
    catch {
        Write-Warning "DCAT: Failed to create initial backup: $_"
    }
}
function Export-DCATReport {
    <#
    .SYNOPSIS
        Exports a JSON + HTML Defender hardening report (DCAT-Report).

    .DESCRIPTION
        Generates:
          - A JSON report (default: .\DCAT-Report.json)
          - An HTML report (default: .\DCAT-Report.html)

        Content includes:
          - Score & grade for the selected preset
          - Detailed breakdown table
          - Machine audit (Get-DCATStatus)
          - ASR coverage matrix (baseline vs current)
          - What changed vs original backup + when
          - Reboot status (from Get-MpComputerStatus and OS last boot time)
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('MicrosoftStrict','CISLevel1','CISLevel2','DCATParanoid')]
        [string]$Preset,

        [string]$HtmlPath = 'DCAT-Report.html',
        [string]$JsonPath = 'DCAT-Report.json'
    )

    # --- local helper: build HTML table --------------------------------
    function New-DCATHtmlTable {
        param(
            [string]$Title,
            [object[]]$Rows,
            [string[]]$Columns
        )

        $html = @()
        $html += "<h2>$Title</h2>"

        if (-not $Rows -or $Rows.Count -eq 0) {
            $html += "<p><em>No data.</em></p>"
            return $html
        }

        $html += '<table>'
        $html += '<thead><tr>'
        foreach ($col in $Columns) {
            $html += "<th>$col</th>"
        }
        $html += '</tr></thead>'
        $html += '<tbody>'

        foreach ($row in $Rows) {
            $html += '<tr>'
            foreach ($col in $Columns) {
                $val = $null
                if ($row -is [System.Collections.IDictionary]) {
                    $val = $row[$col]
                }
                else {
                    $val = $row.$col
                }

                if ($null -eq $val) {
                    $text = '&nbsp;'
                }
                else {
                    $text = "$val"
                    # basic HTML escaping
                    $text = $text -replace '&','&amp;' -replace '<','&lt;' -replace '>','&gt;'
                }

                $html += "<td>$text</td>"
            }
            $html += '</tr>'
        }

        $html += '</tbody></table>'
        return $html
    }

    # --- collect core data ---------------------------------------------
    $now         = Get-Date
    $scoreResult = Get-DCATCompliance -Preset $Preset
    $status      = Get-DCATStatus
    $pref        = Get-MpPreference
    $mpStatus    = Get-MpComputerStatus

    $os = $null
    try {
        $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction SilentlyContinue
    } catch {
        $os = $null
    }

    $backup = $null
    if (Test-Path $script:BackupFile) {
        $backup = Get-Content $script:BackupFile -Raw | ConvertFrom-Json
    }

    # --- ASR coverage matrix (baseline vs current) ---------------------
    $presetFile = Join-Path $PresetsPath "$Preset.json"
    if (-not (Test-Path $presetFile)) {
        throw "Preset not found: $presetFile"
    }

    $cfgBaseline = Get-Content $presetFile -Raw | ConvertFrom-Json
    $mpBaseline  = $cfgBaseline.MpPreferences

    $expectedMap = @{}
    if ($mpBaseline.AttackSurfaceReductionRules_Ids -and $mpBaseline.AttackSurfaceReductionRules_Actions) {
        for ($i = 0; $i -lt $mpBaseline.AttackSurfaceReductionRules_Ids.Count; $i++) {
            $id  = $mpBaseline.AttackSurfaceReductionRules_Ids[$i]
            $act = $mpBaseline.AttackSurfaceReductionRules_Actions[$i]
            $expectedMap[$id] = $act
        }
    }

    $currentMap = @{}
    if ($pref.AttackSurfaceReductionRules_Ids -and $pref.AttackSurfaceReductionRules_Actions) {
        for ($i = 0; $i -lt $pref.AttackSurfaceReductionRules_Ids.Count; $i++) {
            $id  = $pref.AttackSurfaceReductionRules_Ids[$i]
            $act = $pref.AttackSurfaceReductionRules_Actions[$i]
            $currentMap[$id] = $act
        }
    }

    $allAsrIds = @($expectedMap.Keys + $currentMap.Keys) | Sort-Object -Unique

    $asrCoverage = foreach ($id in $allAsrIds) {
        $exp = if ($expectedMap.ContainsKey($id)) { $expectedMap[$id] } else { $null }
        $act = if ($currentMap.ContainsKey($id))  { $currentMap[$id] } else { $null }

        [PSCustomObject]@{
            RuleId         = $id
            InBaseline     = $expectedMap.ContainsKey($id)
            InCurrent      = $currentMap.ContainsKey($id)
            ExpectedAction = $exp
            ActualAction   = $act
            Passed         = ($exp -ne $null -and $act -eq $exp)
        }
    }

    # --- What changed + when (vs original backup) ----------------------
    $backupDiff = $null
    if ($backup) {
        $fields = @(
            'RealTimeProtection',
            'PUAProtection',
            'SubmitSamplesConsent',
            'MAPSReporting',
            'CloudBlockLevel',
            'CloudExtendedTimeout',
            'NetworkProtection',
            'ScanCPU',
            'BlockAtFirstSeen',
            'TamperProtection',
            'ASRRuleCount'
        )

        $currentStatus = $status

        $backupDiff = foreach ($name in $fields) {
            $b = $backup.$name
            $c = $currentStatus.$name

            $bKey = if ($null -eq $b) { '<null>' } else { $b.ToString() }
            $cKey = if ($null -eq $c) { '<null>' } else { $c.ToString() }

            [PSCustomObject]@{
                Setting      = $name
                BackupValue  = $b
                CurrentValue = $c
                Changed      = ($bKey -ne $cKey)
            }
        }
    }

    # --- Reboot status -------------------------------------------------
    $rebootText  = 'Unknown (RebootRequired not available).'
    $needsReboot = $null

    if ($mpStatus -and $mpStatus.PSObject.Properties.Match('RebootRequired').Count -gt 0) {
        $needsReboot = $mpStatus.RebootRequired
        if ($needsReboot) {
            $rebootText = 'Yes - reboot is required.'
        }
        else {
            $rebootText = 'No reboot currently required by Defender.'
        }
    }

    $lastBoot = $null
    if ($os -and $os.PSObject.Properties.Match('LastBootUpTime').Count -gt 0) {
        $lastBoot = $os.LastBootUpTime
    }

    # --- Build JSON report object -------------------------------------
    $report = [PSCustomObject]@{
        GeneratedOn      = $now
        ComputerName     = $env:COMPUTERNAME
        Preset           = $Preset
        Score            = $scoreResult.DCATScore
        Grade            = $scoreResult.Grade
        BackupDate       = if ($backup) { $backup.BackupDate } else { $null }
        RebootRequired   = $needsReboot
        LastBootUpTime   = $lastBoot
        Status           = $status
        MpComputerStatus = $mpStatus
        Breakdown        = $scoreResult.Breakdown
        ASRCoverage      = $asrCoverage
        BackupDiff       = $backupDiff
    }

    # --- Build HTML ----------------------------------------------------
    $html = @()
    $html += '<!DOCTYPE html>'
    $html += '<html>'
    $html += '<head>'
    $html += '<meta charset="utf-8" />'
    $html += "<title>DCAT Report - $($env:COMPUTERNAME) - $Preset</title>"
    $html += @"
<style>
body {
    font-family: Segoe UI, Arial, sans-serif;
    margin: 20px;
    background: #f9fafb;
}
h1 {
    border-bottom: 1px solid #ccc;
    padding-bottom: 4px;
}
h2 {
    margin-top: 24px;
}
table {
    border-collapse: collapse;
    width: 100%;
    margin-bottom: 20px;
    background: #fff;
}
th, td {
    border: 1px solid #ddd;
    padding: 6px 8px;
    font-size: 12px;
}
th {
    background: #f3f3f3;
    text-align: left;
}
tr:nth-child(even) {
    background: #fafafa;
}
.badge {
    display: inline-block;
    padding: 2px 8px;
    border-radius: 4px;
    background: #0078d4;
    color: #fff;
    font-size: 11px;
}
.badge-ok {
    background: #107c10;
}
.badge-warn {
    background: #d83b01;
}
.meta {
    margin-bottom: 16px;
    font-size: 12px;
    color: #555;
}
.section-note {
    font-size: 11px;
    color: #777;
    margin-bottom: 8px;
}
</style>
"@
    $html += '</head>'
    $html += '<body>'

    $html += "<h1>DCAT Defender Hardening Report</h1>"
    $html += "<div class='meta'>Generated on $now<br/>Computer: $($env:COMPUTERNAME)<br/>Preset: $Preset</div>"

    $html += "<p>Score: <strong>$($scoreResult.DCATScore)</strong> / 100 &nbsp;&nbsp; Grade: <span class='badge'>$($scoreResult.Grade)</span></p>"

    $html += "<p><strong>Reboot status:</strong> $rebootText"
    if ($lastBoot) {
        $html += "<br/><strong>Last boot:</strong> $lastBoot"
    }
    $html += "</p>"

    if ($backup) {
        $html += "<p><strong>Original DCAT backup date:</strong> $($backup.BackupDate)</p>"
    }
    else {
        $html += "<p><strong>Original DCAT backup:</strong> Not available.</p>"
    }

    # Machine audit
    $html += New-DCATHtmlTable -Title 'Machine Audit (DCAT Status)' -Rows @($status) -Columns @(
        'RealTimeProtection',
        'PUAProtection',
        'SubmitSamplesConsent',
        'MAPSReporting',
        'CloudBlockLevel',
        'CloudExtendedTimeout',
        'NetworkProtection',
        'ScanCPU',
        'BlockAtFirstSeen',
        'TamperProtection',
        'ASRRuleCount'
    )

    # Breakdown (score components)
    $html += New-DCATHtmlTable -Title 'Score Breakdown' -Rows $scoreResult.Breakdown -Columns @(
        'Setting','Weight','Expected','Actual','Passed'
    )

    # ASR coverage matrix
    $html += "<div class='section-note'>ASR coverage matrix based on preset vs current system Attack Surface Reduction rules.</div>"
    $html += New-DCATHtmlTable -Title 'ASR Coverage Matrix' -Rows $asrCoverage -Columns @(
        'RuleId','InBaseline','InCurrent','ExpectedAction','ActualAction','Passed'
    )

    # What changed + when (vs original backup)
    if ($backupDiff) {
        $changedOnly = $backupDiff | Where-Object { $_.Changed }
        $html += "<div class='section-note'>Comparison of original DCAT backup vs current status.</div>"
        $html += New-DCATHtmlTable -Title 'What Changed Since Original Backup' -Rows $changedOnly -Columns @(
            'Setting','BackupValue','CurrentValue','Changed'
        )
    }
    else {
        $html += "<h2>What Changed Since Original Backup</h2>"
        $html += "<p><em>No original DCAT backup found; change tracking is not available.</em></p>"
    }

    $html += '</body>'
    $html += '</html>'

    # --- Safe directory creation for HTML/JSON ------------------------
    function Ensure-DCATPathDir {
        param([string]$Path)

        $dir = Split-Path $Path -Parent
        if ([string]::IsNullOrWhiteSpace($dir)) { return $true }

        if (-not (Test-Path $dir)) {
            try {
                New-Item -ItemType Directory -Path $dir -Force | Out-Null
                return $true
            } catch {
                Write-Warning "Failed to create directory: $dir -> $_"
                return $false
            }
        }
        return $true
    }

    $okHtml = Ensure-DCATPathDir -Path $HtmlPath
    $okJson = Ensure-DCATPathDir -Path $JsonPath

    $success = $false

    # --- Write JSON ---------------------------------------------------
    if ($okJson) {
        try {
            $report | ConvertTo-Json -Depth 10 |
                Out-File -FilePath $JsonPath -Encoding UTF8 -Force
            $success = $true
        } catch {
            Write-Warning "Failed to export JSON report: $_"
        }
    }
    else {
        Write-Warning "Cannot export JSON: Folder missing."
    }

    # --- Write HTML ---------------------------------------------------
    if ($okHtml) {
        try {
            $html -join "`r`n" |
                Out-File -FilePath $HtmlPath -Encoding UTF8 -Force
            $success = $true
        } catch {
            Write-Warning "Failed to export HTML report: $_"
        }
    }
    else {
        Write-Warning "Cannot export HTML: Folder missing."
    }

    # --- Final status -------------------------------------------------
    if ($success) {
        Write-Host ""
        Write-Host "DCAT report generated:" -ForegroundColor Green
        Write-Host "  HTML: $HtmlPath"
        Write-Host "  JSON: $JsonPath"
    }
    else {
        Write-Warning "DCAT report FAILED - no files exported."
    }
}

# -------------------------------------------------------------------
# Export public functions
# -------------------------------------------------------------------
Export-ModuleMember -Function `
    Get-DCATStatus, `
    Get-DCATCompliance, `
    Get-DCATScore, `
    Set-DCATHardening, `
    New-DCATBackup, `
    Get-DCATBackup, `
    Restore-DCATBackup, `
    New-DCATRestorePoint, `
    Restore-DCATRestorePoint, `
    Get-DCATBackupDiff, `
    Export-DCATReport

