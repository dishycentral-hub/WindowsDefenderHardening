@{
    RootModule         = 'DCAT.psm1'
    ModuleVersion      = '1.3.1'
    GUID               = 'f47ac10b-58cc-4372-a567-0e02b2c3d479'
    Author             = 'Your Name'
    CompanyName        = 'Independent'
    Copyright          = '(c) 2025 Your Name. All rights reserved.'
    Description        = 'DCAT – Defender Control & Audit Toolkit | Rule-by-rule compliance, hardening, scoring'

    PowerShellVersion  = '5.1'
    CompatiblePSEditions = 'Desktop','Core'

    # Export EVERY function – never miss one again
    FunctionsToExport  = '*'

    PrivateData        = @{
        PSData = @{
            Tags       = 'Defender','Security','Compliance','CIS','Hardening','Audit','PowerShell'
            LicenseUri = 'https://github.com/YourName/DCAT/blob/main/LICENSE'
            ProjectUri = 'https://github.com/YourName/DCAT'
        }
    }
}