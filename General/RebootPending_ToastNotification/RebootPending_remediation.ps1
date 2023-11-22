<#
  .DESCRIPTION
    Creates  a Scheduled Task for notifying the user to reboot if the devcie uptime is greater than the predefined max uptime.
    This script will only run from the proactive remediation if the device uptime is greater than 5 days.
    The task schedule will pop-up a toast notification every 1 hour for 2 days asking the user to reboot. It will expire in 3 days.
    The files needed to pop-up the notification (that will run from a scheduled task) are downloaded from blob storage.
    Hash check performed after download.

  .OUTPUTS
    N/A

  .NOTES
    Author: adrian.cojocaru
    Modified date: 24-Oct-2023
    Version 1.0
#>

$ProgressPreference = 'SilentlyContinue'
$RebootScriptFolderPath = "$env:APPDATA\ToastNotificationScriptSource"
[bool]$MyCompanyScriptRebootSameHash = $false
[string]$MyCompanyScriptRebootHash = '20776FFA24EB6E270876D186420047C931B0857B6D334C240685EF10F33573B9'
[string]$MyCompanyScriptRebootUrl = 'https://MyCompanydwmemautomation.blob.core.windows.net/dwc/RebootNoSnooze.ps1?GPAY99w%2Fg%3D'
$MyCompanyScriptRebootPath = "$RebootScriptFolderPath\RebootNoSnooze.ps1"
[bool]$MyCompanyXMLRebootSameHash = $false
[string]$MyCompanyXMLRebootHash = '810F19D0340EB869B4B50E43293C6393EEF50A130D2A44B2B04864162D936E21'
[string]$MyCompanyXMLRebootUrl = 'https://MyCompanydwmemautomation.blob.core.windows.net/dwc/RebootNoSnooze.xml?i1M1rheAhTO1Sw%3D'
$MyCompanyXMLRebootPath = "$RebootScriptFolderPath\RebootNoSnooze.xml"


#EndRegion ===============================[Variables]=============================
#endregion

#Region ===============================[Main]=============================
if (-not (Get-ScheduledTask -TaskName MyCompanyDeviceUptime*)) {
  # another task should not exists . Only in cases where this script is replaced and intune triggers the remediation again
  if (-not (Test-Path $RebootScriptFolderPath)) { New-Item -Path $RebootScriptFolderPath -ItemType Directory }

  if (Test-Path $MyCompanyScriptRebootPath) {
    if ((Get-FileHash $MyCompanyScriptRebootPath -Algorithm SHA256).Hash -eq $MyCompanyScriptRebootHash) { $MyCompanyScriptRebootSameHash = $true }
  }
  # If no hash match download the file and calculate its hash again
  if (-not $MyCompanyScriptRebootSameHash) {
    Start-BitsTransfer $MyCompanyScriptRebootUrl -Destination $MyCompanyScriptRebootPath
    if ((Get-FileHash $MyCompanyScriptRebootPath -Algorithm SHA256).Hash -eq $MyCompanyScriptRebootHash) { $MyCompanyScriptRebootSameHash = $true }
  }
  if (-not $MyCompanyScriptRebootSameHash) { throw "MyCompanyScriptRebootHash don't match after download" }

  if (Test-Path $MyCompanyXMLRebootPath) {
    if ((Get-FileHash $MyCompanyXMLRebootPath -Algorithm SHA256).Hash -eq $MyCompanyXMLRebootHash) { $MyCompanyXMLRebootSameHash = $true }
  }
  # If no hash match download the file and calculate its hash again
  if (-not $MyCompanyXMLRebootSameHash) {
    Start-BitsTransfer $MyCompanyXMLRebootUrl -Destination $MyCompanyXMLRebootPath
    if ((Get-FileHash $MyCompanyXMLRebootPath -Algorithm SHA256).Hash -eq $MyCompanyXMLRebootHash) { $MyCompanyXMLRebootSameHash = $true }
  }
  if (-not $MyCompanyXMLRebootSameHash) { throw "MyCompanyXMLRebootHash don't match after download" }
  ####
  #>

  $CurrentDateObj = Get-Date
  $CurrentDateStr = Get-Date -Format  "yyyyMMddTHHmm" 
  $TriggerDateStr = Get-Date -Date $CurrentDateObj.AddMinutes(2) -Format  "HH:mm tt" 
  $DeadlineDateObj = $CurrentDateObj.AddDays(2)
  $ExpireDateObj = $CurrentDateObj.AddDays(3)
  $ExpireDateStr = Get-Date $ExpireDateObj -Format "yyyy-MM-ddTHH:mm"
  $DeadlineDateStr = Get-Date -Date $DeadlineDateObj -Format "yyyy-MM-dd"
  (Get-Content -Path "$MyCompanyXMLRebootPath").Replace('3333-11-06', $DeadlineDateStr) | Set-Content -Path "$MyCompanyXMLRebootPath"
  
  ## Scheduled Task 1 - scheduled forced reboot
  $ActionArgs = "vbscript:Execute(`"CreateObject(`"`"WScript.Shell`"`").Run `"`"powershell -ExecutionPolicy Bypass & '$RebootScriptFolderPath\RebootNoSnooze.ps1'`"`", 0:close`")"
  $TaskAction = New-ScheduledTaskAction -Execute 'mshta' -Argument $ActionArgs 
  #$TaskSettings = New-ScheduledTaskSettingsSet -DeleteExpiredTaskAfter (New-TimeSpan -Minutes 30)
  $TaskTrigger = New-ScheduledTaskTrigger  -Daily -At "$TriggerDateStr"
  $Task = New-ScheduledTask -Action $TaskAction -Trigger $TaskTrigger
  Register-ScheduledTask -TaskName "MyCompanyDeviceUptime$CurrentDateStr" -InputObject $Task -Force
  $Task = Get-ScheduledTask -TaskName "MyCompanyDeviceUptime$CurrentDateStr"
  $Task.Triggers.Repetition.Interval = "PT1H"
  $Task.Triggers.Repetition.Duration = "P2D"
  $Task.Triggers[0].EndBoundary = $ExpireDateStr
  $Task.Settings.DeleteExpiredTaskAfter = "P1D"
  $Task | Set-ScheduledTask
  
  ## Scheduled Task 2 - instant reboot
  ## This TS is needed as shutdown.exe or Restart-Computer do not work if the user is not a local admin
  $ActionArgs = '/r /t 0 /d p:4:4444 /c "Toast Notification Reboot Button TS"'
  $TaskAction = New-ScheduledTaskAction -Execute 'shutdown' -Argument $ActionArgs 
  #$TaskSettings = New-ScheduledTaskSettingsSet -DeleteExpiredTaskAfter (New-TimeSpan -Minutes 30)
  $CIMTriggerClass = Get-CimClass -ClassName MSFT_TaskEventTrigger -Namespace Root/Microsoft/Windows/TaskScheduler:MSFT_TaskEventTrigger
  $trigger = New-CimInstance -CimClass $CIMTriggerClass -ClientOnly
  $trigger.Subscription = 
  @"
  <QueryList><Query Id="0" Path="Application"><Select Path="Application">*[System[Provider[@Name='Microsoft-Windows-AAD'] and EventID=9997999]]</Select></Query></QueryList>
"@
  $trigger.Enabled = $True 
  
  $Task = New-ScheduledTask -Action $TaskAction -Trigger $trigger
  Register-ScheduledTask -TaskName "MyCompanyDeviceReboot$CurrentDateStr" -InputObject $Task -Force
  $Task = Get-ScheduledTask -TaskName "MyCompanyDeviceReboot$CurrentDateStr"
  $Task.Triggers[0].EndBoundary = $ExpireDateStr
  $Task.Settings.DeleteExpiredTaskAfter = "P1D"
  $Task | Set-ScheduledTask
}

#EndRegion ===============================[Main]=============================
