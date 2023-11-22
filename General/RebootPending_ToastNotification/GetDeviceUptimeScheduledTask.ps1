<#
  .DESCRIPTION
    Detection for PMIDeviceUptime* Task Sequence

  .OUTPUTS
    Device uptime | Reboot deadline | NrOfSchdTasks TaskName LastRunTime LastTaskResult NextRunTime ExpirationTime"

  .NOTES
    Author: adrian.cojocaru
    Modified date: 24-Oct-2023
    Version 1.0
#>

[string]$TSOutput = ''
$PMIDeviceUptimeTS =  (Get-ScheduledTask PMIDeviceUptime* |  Get-ScheduledTaskInfo)
[int]$TSCount = ($PMIDeviceUptimeTS | Measure-Object).count
$PMIDeviceUptimeTS | ForEach-Object {
    $ExpirationTime = (Get-ScheduledTask $_.TaskName).Triggers[0].EndBoundary
    $TSOutput += "| Name = $($_.TaskName) LastRunTime = $($_.LastRunTime) LastTaskResult = $($_.LastTaskResult) NextRunTime = $($_.NextRunTime) ExpirationTime = $ExpirationTime"
}
$UpTime = (get-date) - (Get-CimInstance Win32_OperatingSystem).LastBootUpTime
$UpTimeStr = "$($UpTime.Days)d $($UpTime.Hours)h $($UpTime.Minutes)m"

$PMIXMLRebootPath = "$env:APPDATA\ToastNotificationScriptSource\RebootNoSnooze.xml"
if (Test-Path $PMIXMLRebootPath) {
  $XmlObj = Select-Xml -Path $PMIXMLRebootPath -XPath "/Configuration/Option"
  $XmlDeadline = $XmlObj.node[10].value
}

"Uptime: $UpTimeStr | Deadline: $XmlDeadline | NrOfSchdTasks: $TSCount $TSOutput"