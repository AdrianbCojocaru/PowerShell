$UpTime = (get-date) - (Get-CimInstance Win32_OperatingSystem).LastBootUpTime
$UpTimeStr = "$($UpTime.Days)d $($UpTime.Hours)h $($UpTime.Minutes)m"
Write-Output "$UpTimeStr"
if ($UpTime.Days -ge 5) { Exit 1 } else { Exit 0 }