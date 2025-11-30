# DCAT.psm1 – Defender Control & Audit Toolkit (v0.1.0)

#requires -Version 5.1

$script:DCATPresetsPath = Join-Path $PSScriptRoot 'Presets'

function Get-DCATStatus {
    <#
    .SYNOPSIS
        Collect key Defender configuration values from the local machine.
    #>
    [CmdletBinding()]
    param()

    $mpStatus     = Get-MpComputerStatus
    $mpPreference = Get-MpPreference

    # Some settings (like TamperProtection) live in registry
    $tamper = $null
    try {
        $tamper = (Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows Defender\Features' -Name 'TamperProtection' -ErrorAction Stop).TamperProtection
    } catch {
        # Ignore if not present
    }

    [PSCustomObject]@{
        ComputerName              = $env:COMPUTERNAME

        # Core AV
        RealTimeProtectionEnabled = $mpStatus.RealTimeProtectionEnabled
        DisableRealtimeMonitoring = $mpPreference.DisableRealtimeMonitoring
        PUAProtection             = $mpPreference.PUAProtection
        MAPSReporting             = $mpPreference.MAPSReporting
        SubmitSamplesConsent      = $mpPreference.SubmitSamplesConsent

        # Cloud / network
        CloudBlockLevel           = $mpPreference.CloudBlockLevel
        CloudExtendedTimeout      = $mpPreference.CloudExtendedTimeout
        EnableNetworkProtection   = $mpPreference.EnableNetworkProtection

        # Other
        SignatureUpdateInterval   = $mpPreference.SignatureUpdateInterval
        TamperProtection          = $tamper

        # ASR – simple count for v0.1
        ASRRuleCount              = $mpPreference.AttackSurfaceReductionRules_Ids.Count
    }
}

function Get-DCATStatus {
    <#
    .SYNOPSIS
        Collect key Defender configuration values from the local machine.
    #>
    [CmdletBinding()]
    param()

    $mpStatus     = Get-MpComputerStatus
    $mpPreference = Get-MpPreference

    # Some settings (like TamperProtection) live in registry
    $tamper = $null
    try {
        $tamper = (Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows Defender\Features' -Name 'TamperProtection' -ErrorAction Stop).TamperProtection
    } catch { }

    [PSCustomObject]@{
        ComputerName              = $env:COMPUTERNAME

        # Core AV
        RealTimeProtectionEnabled = $mpStatus.RealTimeProtectionEnabled
        DisableRealtimeMonitoring = $mpPreference.DisableRealtimeMonitoring
        PUAProtection             = $mpPreference.PUAProtection
        MAPSReporting             = $mpPreference.MAPSReporting
        SubmitSamplesConsent      = $mpPreference.SubmitSamplesConsent

        # Cloud / network
        CloudBlockLevel           = $mpPreference.CloudBlockLevel
        CloudExtendedTimeout      = $mpPreference.CloudExtendedTimeout
        EnableNetworkProtection   = $mpPreference.EnableNetworkProtection

        # Other
        SignatureUpdateInterval   = $mpPreference.SignatureUpdateInterval
        TamperProtection          = $tamper

        # ASR – simple count for v1
        ASRRuleCount              = $mpPreference.AttackSurfaceReductionRules_Ids.Count
    }
}

function Get-DCATPresetConfig {
    <#
    .SYNOPSIS
        Load a preset JSON definition.

    .PARAMETER Name
        Preset name (CISLevel1, CISLevel2, STIG, DoD)
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('CISLevel1','CISLevel2','STIG','DoD')]
        [string]$Name
    )

    $path = Join-Path $script:DCATPresetsPath "$Name.json"
    if (-not (Test-Path $path)) {
        throw "Preset definition not found at $path"
    }

    (Get-Content -Path $path -Raw) | ConvertFrom-Json
}

function Get-DCATCompliance {
    <#
    .SYNOPSIS
        Compare local Defender settings against a DCAT preset and compute a score.

    .PARAMETER Preset
        Preset name: CISLevel1, CISLevel2, STIG, DoD
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('CISLevel1','CISLevel2','STIG','DoD')]
        [string]$Preset
    )

    $status       = Get-DCATStatus
    $presetConfig = Get-DCATPresetConfig -Name $Preset

    $rules   = $presetConfig.Rules
    $details = @()
    $score   = 0
    $max     = 0

    foreach ($rule in $rules) {
        $key      = $rule.Key
        $expected = $rule.Expected
        $weight   = [int]$rule.Weight
        $actual   = $status.$key

        $compliant = $false
        $reason    = $null

        if ($null -eq $actual) {
            $reason = "Setting not found on this system"
        } elseif ($actual -eq $expected) {
            $compliant = $true
            $reason    = "Matched expected value"
        } else {
            $reason = "Expected '$expected' but found '$actual'"
        }

        if ($weight -lt 0) { $weight = 0 }
        $max += $weight
        if ($compliant) { $score += $weight }

        $details += [PSCustomObject]@{
            Setting   = $key
            Expected  = $expected
            Actual    = $actual
            Weight    = $weight
            Compliant = $compliant
            Reason    = $reason
        }
    }

    $percent = if ($max -eq 0) { 0 } else { [math]::Round(($score / $max) * 100, 0) }

    [PSCustomObject]@{
        ComputerName = $status.ComputerName
        Preset       = $Preset
        DCATScore    = $percent
        TotalWeight  = $max
        PassedWeight = $score
        Details      = $details
    }
}

function Get-DCATScore {
    <#
    .SYNOPSIS
        Shortcut to get just the score for a given preset.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('CISLevel1','CISLevel2','STIG','DoD')]
        [string]$Preset
    )

    $c = Get-DCATCompliance -Preset $Preset
    $grade = switch ($c.DCATScore) {
        {$_ -ge 95} { 'A+' }
        {$_ -ge 85} { 'A'  }
        {$_ -ge 70} { 'B'  }
        default     { 'C'  }
    }

    [PSCustomObject]@{
        ComputerName = $c.ComputerName
        Preset       = $Preset
        DCATScore    = $c.DCATScore
        Grade        = $grade
        EvaluatedOn  = Get-Date
    }
}

function Set-DCATHardening {
    <#
    .SYNOPSIS
        Apply a DCAT preset to the local machine using Set-MpPreference and registry.

    .PARAMETER Preset
        Preset name: CISLevel1, CISLevel2, STIG, DoD

    .PARAMETER WhatIf
        Show what would be changed without applying it.
    #>
    [CmdletBinding()]

    param(
        [Parameter(Mandatory)]
        [ValidateSet('CISLevel1','CISLevel2','STIG','DoD')]
        [string]$Preset,

        [switch]$WhatIf
    )

    $config = Get-DCATPresetConfig -Name $Preset

    if ($PSCmdlet.ShouldProcess("Microsoft Defender", "Apply $($config.Name) preset")) {

        # MpPreferences -> Set-MpPreference
        if ($config.MpPreferences) {
    $config.MpPreferences.PSObject.Properties | ForEach-Object {
        $key = $_.Name
        $val = $_.Value

        if ($WhatIf) {
            Write-Host "[WHATIF] Set-MpPreference -$key $val"
        } else {
            try {
                $params = @{}
                $params[$key] = $val
                Set-MpPreference @params -ErrorAction Stop
            } catch {
                Write-Warning "Failed to set $key : $_"
            }
        }
    }
}


        # Registry section (optional for future)
        if ($config.Registry) {
            $config.Registry.PSObject.Properties | ForEach-Object {
                $regPath = $_.Name
                $_.Value.PSObject.Properties | ForEach-Object {
                    $name  = $_.Name
                    $value = $_.Value
                    if ($WhatIf) {
                        Write-Host "[WHATIF] Set-ItemProperty -Path '$regPath' -Name $name -Value $value"
                    } else {
                        try {
                            New-Item -Path $regPath -Force | Out-Null
                            Set-ItemProperty -Path $regPath -Name $name -Value $value -Force
                        } catch {
                            Write-Warning "Failed to set registry $regPath\$name : $_"
                        }
                    }
                }
            }
        }

        if (-not $WhatIf) {
            Write-Host "$($config.Name) preset applied." -ForegroundColor Green
        }
    }
}
function Get-DCATCompliance {
    <#
    .SYNOPSIS
        Compare local Defender settings against a DCAT preset and compute a score.

    .PARAMETER Preset
        Preset name: CISLevel1, CISLevel2, STIG, DoD
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('CISLevel1','CISLevel2','STIG','DoD')]
        [string]$Preset
    )

    $status       = Get-DCATStatus
    $presetConfig = Get-DCATPresetConfig -Name $Preset

    $rules   = $presetConfig.Rules
    $details = @()
    $score   = 0
    $max     = 0

    foreach ($rule in $rules) {
        $key      = $rule.Key
        $expected = $rule.Expected
        $weight   = [int]$rule.Weight
        $actual   = $status.$key

        $compliant = $false
        $reason    = $null

        if ($null -eq $actual) {
            $reason = "Setting not found on this system"
        }
        elseif ($actual -eq $expected) {
            $compliant = $true
            $reason    = "Matched expected value"
        }
        else {
            $reason = "Expected '$expected' but found '$actual'"
        }

        if ($weight -lt 0) { $weight = 0 }

        $max += $weight
        if ($compliant) { $score += $weight }

        $details += [PSCustomObject]@{
            Setting   = $key
            Expected  = $expected
            Actual    = $actual
            Weight    = $weight
            Compliant = $compliant
            Reason    = $reason
        }
    }

    $percent = if ($max -eq 0) { 0 } else { [math]::Round(($score / $max) * 100, 0) }

    [PSCustomObject]@{
        ComputerName = $status.ComputerName
        Preset       = $Preset
        DCATScore    = $percent
        TotalWeight  = $max
        PassedWeight = $score
        Details      = $details
    }
}

Export-ModuleMember -Function Get-DCATStatus,Get-DCATPresetConfig,Get-DCATCompliance,Get-DCATScore,Set-DCATHardening
