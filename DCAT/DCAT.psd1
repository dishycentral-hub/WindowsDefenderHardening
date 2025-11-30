@{
    RootModule        = 'DCAT.psm1'
    ModuleVersion     = '1.0.0'
    GUID              = 'f10c7737-56d4-48c6-a300-eb2555183331'
    Author            = 'Your Name'
    CompanyName       = 'Independent'
    Copyright         = '(c) 2025 Your Name'
    Description       = 'Defender Control and Audit Toolkit'
    PowerShellVersion = '5.1'

    FunctionsToExport = @(
        'Set-DCATHardening',
        'Get-DCATScore',
        'Invoke-DCATRemoteAudit'
    )

    PrivateData = @{
        PSData = @{
            LicenseUri = 'https://opensource.org/licenses/MIT'
            ProjectUri = 'https://github.com/YourGithubUser/DCAT'
            Tags       = @('Defender','Security','Hardening','CIS','Windows')
        }
    }
}
