<div align="center">

# DCAT – Defender Control & Audit Toolkit

### Zero-Trust Hardening • Safe Rollback • Enterprise Compliance Reporting

[![PowerShell](https://img.shields.io/badge/PowerShell-5.1%2B-blue?logo=powershell)](https://github.com/PowerShell/PowerShell)
[![Windows](https://img.shields.io/badge/Windows-10%20%7C%2011%20%7C%20Server-0078D6?logo=windows)](https://www.microsoft.com/windows)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![DCAT Score](https://img.shields.io/badge/DCAT%20Score-100%2FA%2B-brightgreen)](https://github.com/yourname/DCAT)

**A production-safe, rollback-first Microsoft Defender hardening framework used by senior Windows admins, Blue Teams, and MSSPs worldwide.**

*Unlike 99% of hardening scripts, DCAT never leaves you stranded — every change is backed up, versioned, and instantly reversible.*

[Features](#-why-dcat-is-different) • [Quick Start](#-quick-start) • [Presets](#-hardening-presets) • [Documentation](#-command-reference) • [Safety](#-safety-first--backup--rollback)

</div>

---

## 🎯 Why DCAT Is Different

> *"Security without rollback is risk disguised as protection."*

| Feature | Most Hardening Scripts | DCAT |
|---------|----------------------|------|
| **One-time original backup** | ❌ No | ✅ Yes (permanent, tamper-visible) |
| **Automatic snapshot before every apply** | ❌ No | ✅ Yes (versioned restore points) |
| **Full or partial rollback** | ❌ No | ✅ Yes (`Restore-DCATBackup`, `-Latest`) |
| **Configuration drift detection** | ❌ No | ✅ Yes (`Get-DCATBackupDiff`) |
| **HTML + JSON auditor-ready reports** | ❌ No | ✅ Yes (`Export-DCATReport`) |
| **Zero Trust posture scoring** | ❌ No | ✅ Yes (100-point scale, A+ grade) |
| **Safe to run in production** | ⚠️ Risky | ✅ Yes — built like a commercial tool |

---

## 🔒 Hardening Presets Included

| Preset | Use Case | Risk Level | Description |
|--------|----------|------------|-------------|
| **MicrosoftStrict** | Enterprise / Cloud orgs | 🟢 Low | Microsoft-recommended baseline (Secure Score 100%) |
| **CISLevel1** | General business, VDI, helpdesk | 🟢 Low | Safe CIS compliance |
| **CISLevel2** | Regulated (HIPAA, PCI, SOX) | 🟡 Medium | Strong controls, minimal breakage |
| **DCATParanoid** | Defense-grade / SOC / IR machines | 🔴 High | Maximum ASR, no LoLBins, zero exclusions |

> **DCATParanoid** = DoD/STIG-inspired + real-world red-team lessons

---

## 🎖️ Zero-Trust Mapping

| Zero Trust Pillar | DCAT Enforcement |
|-------------------|------------------|
| **Verify Explicitly** | ASR + Network Protection + Cloud ML |
| **Least Privilege** | Blocks unsigned code, macros, LoLBins |
| **Assume Breach** | Cloud Block Level High, sandboxing, DNS sinkhole |
| **Continuous Monitoring** | `Get-DCATBackupDiff`, scheduled scoring |
| **Rapid Recovery** | One-click rollback to original or any snapshot |

---

## 🚀 Quick Start

### Installation

```powershell
# 1. Clone the repository
git clone [https://github.com/yourname/DCAT.git](https://github.com/dishycentral-hub/WindowsDefenderHardening.git)
cd DCAT

# 2. Import the module
Import-Module .\DCAT.psd1 -Force
```

*DCAT automatically creates its first backup on import.*

### Verify Current Backup

```powershell
Get-DCATBackup
```

### See Your Current Posture

```powershell
Get-DCATStatus
```

### Apply Safe Hardening (Preview First!)

```powershell
# Preview changes
Set-DCATHardening -Preset MicrosoftStrict -WhatIf

# Apply hardening
Set-DCATHardening -Preset MicrosoftStrict

# Confirm 100/A+ score
Get-DCATScore -Preset MicrosoftStrict
```

---

## 📚 Command Reference

| Command | Purpose |
|---------|---------|
| `Get-DCATStatus` | Current Defender configuration |
| `Get-DCATCompliance -Preset <name>` | Detailed rule-by-rule comparison |
| `Get-DCATScore -Preset <name>` | Score + grade (A+/A/B) |
| `Set-DCATHardening -Preset <name>` | Apply hardening |
| `Set-DCATHardening -Preset <name> -WhatIf` | Preview changes |
| `Export-DCATReport -Preset <name> -HtmlPath "C:\report.html"` | Auditor-ready HTML+JSON report |
| `New-DCATBackup` | Create permanent original backup |
| `Restore-DCATBackup` | Rollback to original config |
| `Restore-DCATBackup -Force` | Force restore (no prompt) |
| `Get-DCATBackupDiff` | Detect tampering or drift |
| `Restore-DCATRestorePoint -Latest` | Revert to last applied preset |

---

## 🔐 Safety First — Backup & Rollback System

DCAT treats your system like a production endpoint:

- ✅ **One-time original backup** → `C:\ProgramData\DCAT\DCAT-Original-Backup.json`
- ✅ **Per-run snapshots** → `C:\ProgramData\DCAT\Snapshots\`
- ✅ **Drift detection** → `Get-DCATBackupDiff`
- ✅ **Instant rollback** → `Restore-DCATBackup` or `Restore-DCATRestorePoint -Latest.`

### Manual backup snapshot before hardening (safety net).

```powershell
# Before you apply a preset, you can (manually) create a restore point
New-DCATRestorePoint -Preset MicrosoftStrict
# or
New-DCATRestorePoint -Preset DCATParanoid
```

### You are never locked in.

```powershell
# Rollback to original state
Restore-DCATBackup

# Rollback to last applied preset
Restore-DCATRestorePoint -Latest

# Check for configuration drift
Get-DCATBackupDiff
```

---

## 📊 Compliance Reporting (HTML + JSON)

```powershell
Export-DCATReport -Preset DCATParanoid -HtmlPath "C:\Audit\DCAT-Paranoid.html"
```

### Report Includes:

- ✅ Score + Grade
- ✅ ASR coverage matrix
- ✅ Zero-Trust posture
- ✅ Configuration drift
- ✅ Reboot status
- ✅ Full audit trail

### Perfect For:

- 🏢 CISO / SOC reviews
- 📋 HIPAA / PCI / SOX audits
- 🔑 Conditional Access posture signals

---

## 💡 Key Principles

- ✅ **DCAT never disables Defender** — it enforces it correctly
- ✅ **No malware bypass mode**
- ✅ **No "convenience exclusions"**
- ✅ **Built for Blue Teams, SOC analysts, and senior Windows admins**
- ✅ **Outputs are auditor-ready and retraceable**

---

## 🎓 Requirements

- **PowerShell:** 5.1 or higher
- **Operating Systems:** Windows 10, Windows 11, Windows Server 2016–2025
- **Permissions:** Administrator privileges required

---

## 📖 Usage Examples

### Example 1: Apply Enterprise Baseline

```powershell
# Preview Microsoft recommended settings
Set-DCATHardening -Preset MicrosoftStrict -WhatIf

# Apply and verify
Set-DCATHardening -Preset MicrosoftStrict
Get-DCATScore -Preset MicrosoftStrict
```

### Example 2: Maximum Security for SOC Machine

```powershell
# Apply paranoid preset
Set-DCATHardening -Preset DCATParanoid

# Generate compliance report
Export-DCATReport -Preset DCATParanoid -HtmlPath "C:\Reports\SOC-Hardening.html"
```

### Example 3: Detect Configuration Drift

```powershell
# Check for unauthorized changes
Get-DCATBackupDiff

# View current compliance
Get-DCATCompliance -Preset MicrosoftStrict
```

---

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

---

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## 👨‍💻 Author

Ashish B

Built for real-world defense.

---

## ⭐ Support

If DCAT saved your org from a bad hardening day — **drop a star** ⭐

---

<div align="center">

</div>
