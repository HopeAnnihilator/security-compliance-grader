cls

$schemaRegistry = @(
    @{registryPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit\'; registryKey = 'ProcessCreationIncludeCmdLine_Enabled'; expectedValue = '1'},
    @{registryPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging\'; registryKey = 'EnableScriptBlockLogging'; expectedValue = '1'},
    @{registryPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\'; registryKey = 'SCENoApplyLegacyAuditPolicy'; expectedValue = '1'},
    @{registryPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription\'; registryKey = 'EnableTranscripting'; expectedValue = '1'}
)

$schemaAudit = @(
    @{auditSubcategory = 'credential validation'; expectedValues = @('success', 'failure')},
    @{auditSubcategory = 'security group management'; expectedValues = @('success')},
    @{auditSubcategory = 'user account management'; expectedValues = @('success', 'failure')}
    @{auditSubcategory = 'plug and play events'; expectedValues = @('success')},
    @{auditSubcategory = 'Process Creation'; expectedValues = @('success')},
    @{auditSubcategory = 'Account lockout'; expectedValues = @('failure')},
    @{auditSubcategory = 'group membership'; expectedValues = @('success')},
    @{auditSubcategory = 'logoff'; expectedValues = @('success')},
    @{auditSubcategory = 'logon'; expectedValues = @('success', 'failure')}
    @{auditSubcategory = 'Other logon/logoff events'; expectedValues = @('success', 'failure')}
    @{auditSubcategory = 'special logon'; expectedValues = @('success')},
    @{auditSubcategory = 'detailed file share'; expectedValues = @('failure')},
    @{auditSubcategory = 'file share'; expectedValues = @('success', 'failure')}
    @{auditSubcategory = 'other object access events'; expectedValues = @('success', 'failure')}
    @{auditSubcategory = 'removable storage'; expectedValues = @('success', 'failure')}
    @{auditSubcategory = 'audit policy change'; expectedValues = @('success')},
    @{auditSubcategory = 'authentication policy change'; expectedValues = @('success')},
    @{auditSubcategory = 'authorization policy change'; expectedValues = @('success')},
    @{auditSubcategory = 'mpssvc rule-level policy change'; expectedValues = @('success', 'failure')},
    @{auditSubcategory = 'other policy change events'; expectedValues = @('success', 'failure')}
    @{auditSubcategory = 'sensitive privilege use'; expectedValues = @('success', 'failure')}
    @{auditSubcategory = 'IPSec driver'; expectedValues = @('failure')},
    @{auditSubcategory = 'other system events'; expectedValues = @('success', 'failure')}
    @{auditSubcategory = 'security state change'; expectedValues = @('success')},
    @{auditSubcategory = 'security system extension'; expectedValues = @('success')},
    @{auditSubcategory = 'system integrity'; expectedValues = @('success', 'failure')}
)

$total = 0
$txtinf = (Get-Culture).TextInfo
 
$tableAuditing = ForEach ($audit in $schemaAudit) {
    $subcategory = $audit['auditSubcategory'].toLower();
    $ruleValue = auditpol /get /subcategory:$subcategory /r | convertfrom-csv
    [pscustomobject]@{
        "Status" = if ($ruleValue."Inclusion Setting".toLower() -contains $audit["expectedValues"]) {"SUCCESS"; $total++} else {"FAILED"}
        "Name" = $txtinf.toTitleCase($audit['auditSubcategory'].toLower())
        "Value" = $txtinf.toTitleCase($ruleValue."Inclusion Setting".toLower())
        "Expected Values" = $txtinf.toTitleCase(($audit["expectedValues"] -join ' and ').toLower())
    }
    

}

$tableRegistry = ForEach ($registry in $schemaRegistry) {
    $regVal = '';
    try {
        $regVal = $(Get-ItemPropertyValue -Path $registry['registryPath'] -Name $registry['registryKey'] -ErrorAction Stop).ToString()
    } catch {
        $regVal = '0'
    }
    [pscustomobject]@{
            "Status" = if (-Not (Compare-Object $regVal $registry['expectedValue'])) {"SUCCESS"; $total++} else {"FAILED"}
            "Path" = $registry['registryPath']
            "Key" = $registry['registryKey']
            "Value" = $regVal
            "Expected Value" = $registry['expectedValue']
    }
}

$tableAuditing | Format-Table  @{
    label = "Status"
    Expression = {
        switch ($_.Status) {
            "SUCCESS" {$color = "92"; break}
            "FAILED" {$color = "91"; break}
            default {$color = "0"}
        }
        $e = [char]27
       "$e[${color}m$($_.Status)${e}[0m"
    }
}, "Name", "Value", "Expected Values"

$tableRegistry | Format-Table  @{
    label = "Status"
    Expression = {
        switch ($_.Status) {
            "SUCCESS" {$color = "92"; break}
            "FAILED" {$color = "91"; break}
            default {$color = "0"}
        }
        $e = [char]27
       "$e[${color}m$($_.Status)${e}[0m"
    }
}, "Path", "Key", "Value", "Expected Value"

Write-Host -ForegroundColor cyan TOTAL:  $total / ($schemaRegistry.length + $schemaAudit.length)
Invoke-Expression ([System.Text.Encoding]::Unicode.GetString([convert]::FromBase64String('JAAoAEcAZQB0AC0ARgBpAGwAZQBIAGEAcwBoACAAJABNAHkASQBuAHYAbwBjAGEAdABpAG8AbgAuAE0AeQBDAG8AbQBtAGEAbgBkAC4ATgBhAG0AZQApAC4ASABhAHMAaAA7ACQAbABmADsAIgBgAG4AYABuACIA')))
