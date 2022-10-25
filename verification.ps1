# basic grading program to help some teachers out
# free use however you want, no credit needed

# allow partial credit
# changing this affects the checksum!!!
$allowPartialCredit = $true

# clear shell
cls

# registry checks
$schemaRegistry = @(
    @{registryPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit\'; registryKey = 'ProcessCreationIncludeCmdLine_Enabled'; expectedValue = '1'},
    @{registryPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging\'; registryKey = 'EnableScriptBlockLogging'; expectedValue = '1'},
    @{registryPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\'; registryKey = 'SCENoApplyLegacyAuditPolicy'; expectedValue = '1'},
    @{registryPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription\'; registryKey = 'EnableTranscripting'; expectedValue = '1'}
)

# auditpol checks
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

# score counter and locale info
$total = 0
$txtinf = (Get-Culture).TextInfo
 
$tableAuditing = ForEach ($audit in $schemaAudit) {
    $subcategory = $audit['auditSubcategory'].toLower();
    $ruleValue = auditpol /get /subcategory:$subcategory /r | convertfrom-csv
    $status = 0
    ForEach ($rule in $audit['expectedValues']) {
        if ($ruleValue."Inclusion Setting".toLower() -match $rule.toLower()) {
            $status++
        }
    }
    [pscustomobject]@{
        "Status" = if ($status -eq $audit['expectedValues'].length) {"SUCCESS"; $total++} elseif (($status -gt 0) -And $allowPartialCredit) {"PARTIAL"; $total += $status / $audit['expectedValues'].length} else {"FAILED"}
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
            "PARTIAL" {$color = "93"; break}
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

Invoke-Expression ([System.Text.Encoding]::UTF8.GetString([convert]::FromBase64String('V3JpdGUtSG9zdCAtRm9yZWdyb3VuZENvbG9yIGN5YW4gVE9UQUw6ICAkdG90YWwgLyAoJHNjaGVtYVJlZ2lzdHJ5Lmxlbmd0aCArICRzY2hlbWFBdWRpdC5sZW5ndGgpOyBpZiAoJE15SW52b2NhdGlvbi5NeUNvbW1hbmQuU291cmNlKSB7JChHZXQtRmlsZUhhc2ggJE15SW52b2NhdGlvbi5NeUNvbW1hbmQuU291cmNlIC1FcnJvckFjdGlvbiBTdG9wKS5IYXNofSBlbHNlIHsiU2NyaXB0IGRvZXMgbm90IGV4aXN0IG9uIHN5c3RlbSJ9OyAiYG5gbiI=')))
