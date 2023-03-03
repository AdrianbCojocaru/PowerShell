
#Region ===============================[Metadata]==============================

<#PSScriptInfo

.VERSION 1.0

.GUID 729233be-b088-452e-b200-1b545dfe1bb4

.Date 04-Feb-2023

.AUTHOR adrianbcojocaru@gmail.com

#>

<#

.DESCRIPTION
  Checks ReAgent.xml for issues that may cause WinRE error to occur when a BitLocker encryption is attempted

.EXAMPLE
  ### destination group already exists:
  Test-ReAgentxml.ps1

#>

#EndRegion ============================[Metadata]==============================



try {
    if (Test-Path "$env:SystemRoot\system32\Recovery\ReAgent.xml") {
        $ReAgent = Get-Content "$env:SystemRoot\system32\Recovery\ReAgent.xml"
        [xml]$ReAgentxml = $ReAgent
        if ($ReAgentxml.WindowsRE.WinreBCD.id -eq '{00000000-0000-0000-0000-000000000000}') {
        (Get-Item "$env:SystemRoot\system32\Recovery\ReAgent.xml").LastWriteTime.Date.ToString()
            $Global:ExitCode = 100
        }
    }
    else {
        $Global:ExitCode = 101
    }
}
catch {
    $Global:ExitCode = 102
}
finally {
    Exit $Global:ExitCode
}