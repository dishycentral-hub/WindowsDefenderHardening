# DCAT – Defender Control & Audit Toolkit (v0.1.0)

DCAT is a PowerShell module for **auditing**, **scoring**, and **hardening**
Microsoft Defender using JSON-based baselines (CIS Level 1/2, STIG, DoD-style).

## Features (v0.1)

- `Get-DCATStatus` – collect key Defender settings
- `Get-DCATCompliance` – compare status vs a preset (CISLevel1, CISLevel2, STIG, DoD)
- `Get-DCATScore` – friendly score + grade per preset
- `Set-DCATHardening` – apply a preset using `Set-MpPreference`

## Install (dev mode)

```powershell
git clone https://github.com/<yourname>/DCAT.git
cd .\DCAT
Import-Module .\DCAT -Force
