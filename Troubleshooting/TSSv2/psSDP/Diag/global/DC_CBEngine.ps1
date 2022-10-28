﻿#************************************************
#  DC_CBengine.sp1
#  Author:        Wilson Souza
#  Date Created:  03/09/2016
#  Date Modified: 08/29/2016
#  Description:   This script collects MAB related logs
#************************************************

Import-LocalizedData -BindingVariable LocalsCollectDPMLogs -FileName DC_CBEngine -UICulture en-us

#Azure Installation
$WindowsAzureBackup = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows Azure Backup\Setup").InstallPath
$DPMInstall         = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Microsoft Data Protection Manager\db').sqlserver
$OutputBase         = "Result\" + $ComputerName + "_CBENGINE_online_job_history_.txt" 
$date = (get-date).AddDays(-15)

#Loading Azure PowerShell Module
& ($WindowsAzureBackup+'bin\WABModuleInitScript.ps1')

if ($WindowsAzureBackup)
{
	#MABs online job
	if ($WindowsAzureBackup -and !$DPMInstall)
	{

		$count=0
		while ($count -ne 10)
		{
			$Jobhistorylist = Get-OBJob 100000000 | Where-Object { $_.JobStatus.StartTime -gt $date}
			if (!$Jobhistorylist) { Start-Sleep 2; $count++} else { break }
		}

		$Jobhistorylist = $Jobhistorylist + (Get-OBJob)

		''                                                                                                                                                                                                                                             | Out-File $OutputBase
		'JobType      Start (UTC Time)         End (UTC Time)           State                  Data Transfer (MB)   Name                                   JobId                                  DetailedErrorCode   ErrorCode    ErrorParameterInfo' | Out-File $OutputBase -Append -Width 500
		'----------   ----------------------   ----------------------   --------------------   ------------------   ------------------------------------   ------------------------------------   -----------------   ----------   ------------------' | Out-File $OutputBase -Append -Width 500
 
		foreach ($jobhistory in $Jobhistorylist)
		{

		    $jobTYpe     = $Jobhistory.jobtype
			$jobstate    = @($jobhistory.jobstatus.datasourcestatus.jobstate)
			$JobStartTm  = $jobhistory.JobStatus.StartTime
			$JobEndTm    = $jobhistory.JobStatus.endTime
		    $JobFiles    = $jobhistory.JobStatus.DatasourceStatus.fileprogress.total
			$jobTransfer = @($jobhistory.JobStatus.DatasourceStatus.byteprogress.progress)
		    $JobName     = @($jobhistory.JobStatus.DatasourceStatus.datasource.DataSourceName)
			$JobDEC      = $jobhistory.JobStatus.ErrorInfo.DetailedErrorCode
			$JobErr      = $jobhistory.JobStatus.errorinfo.ErrorCode
			$JobErrParm  = $jobhistory.JobStatus.errorinfo.ErrorParamList.name + ' ' + $jobhistory.JobStatus.errorinfo.ErrorParamList.value
			$JobID       = $jobhistory.JobId

		    if ($null -eq $jobhistory.JobStatus.DatasourceStatus)
			{
				if ($jobhistory.jobstatus.jobstate -eq 'Abort') { $Jobstatus = 'Failed' } else { $Jobstatus = $Jobstate[$count]}
				('{0,-10}   {1,-22}   {2,-22}   {3,-20}   {4,18:N2}   {5,-36}   {6}   {7,17:X}   {8,10}   {9} ' -f $jobtype, $JobStartTm, $JobEndTm, $Jobstatus , "---", "---", $JobID, $JobDEC, $JobErr, $JobErrParm ) | Out-File $OutputBase -Append -Width 500
		    }
		    else
			{
    			$count = 0
		        while ($count -ne $jobstate.count)
			    {
				    if ($Jobstate[$count] -eq 'Abort') { $Jobstatus = 'Failed' } else { $Jobstatus = $Jobstate[$count]}
					if ($jobTransfer[$count] -ne 0) { $JobTransferMB = $jobTransfer[$count]/1024/1024 } else {  $JobTransferMB = 0 } 
    			    ('{0,-10}   {1,-22}   {2,-22}   {3,-20}   {4,18:N2}   {5,-36}   {6}   {7,17:X}   {8,10}   {9}   ' -f $jobtype, $JobStartTm, $JobEndTm, $Jobstatus, $JobTransferMB, $JobName[$count], $JobID, $JobDEC, $JobErr, $JobErrParm ) | Out-File $OutputBase -Append -Width 500
			    	$count++
		        }
			}
		}
	}

	#DPM online job
	If ($WindowsAzureBackup -and $DPMInstall)
	{
		$count=0
		while ($count -ne 10)
		{
			$Jobhistorylist  = @(Get-DPMJob (&hostname) -type CloudBackup -From (get-date).AddDays(-15) | Sort-Object starttime)
			if (!$Jobhistorylist) { Start-Sleep 2; $count++} else { break }
		}

		''                                                                                                                                                                                                                                                     | Out-File $OutputBase -Append -Width 500
		'JobType       Start (UTC Time)         End (UTC Time)           State       Data Transfer (MB)   Production Server                      Name                                   DPM/CBENGINE TaskID                    DetailedErrorCode   ErrorCode'  | Out-File $OutputBase -Append -Width 500
		'-----------   ----------------------   ----------------------   ---------   ------------------   ------------------------------------   ------------------------------------   ------------------------------------   -----------------   ----------' | Out-File $OutputBase -Append -Width 500
		foreach ($jobhistory in $Jobhistorylist)
		{
			$jobTYpe     = $Jobhistory.jobtype
			$jobstatus   = $jobhistory.status
		    $JobStartTm  = $jobhistory.StartTime
			$JobEndTm    = $jobhistory.endTime
			#$JobFiles    = $jobhistory.JobStatus.DatasourceStatus.fileprogress.total
			$jobTransfer = $jobhistory.DataSize
			$JobName     = $jobhistory.DataSources
			$JobServer   = $jobhistory.Tasks.ProductionServerName
			[xml]$Error  = $Jobhistory.tasks.errorinfoxml
			$JobDEC      = $error.ErrorInfo.DetailedCode
			[int]$JobErr = $error.ErrorInfo.ErrorCode
			#$JobErrParm  = $jobhistory.JobStatus.errorinfo.ErrorParamList.name + ' ' + $jobhistory.JobStatus.errorinfo.ErrorParamList.value
			$JobID       = $jobhistory.Tasks.taskid.Guid
			if ($jobTransfer -ne 0) { $JobTransferMB = $jobTransfer/1024/1024 } else {  $JobTransferMB = 0 } 
		    ('{0,-11}   {1,-22}   {2,-22}   {3,-9}   {4,18:N2}   {5,-36}   {6,-36}   {7}   {8,17:x}   {9,10:x}' -f $jobtype, $JobStartTm, $JobEndTm, $Jobstatus, $JobTransferMB, $JobServer, $JobName, $JobID, $JobDEC, $JobErr) | Out-File $OutputBase -Append -Width 500
		}
	}


    # Collect CBENGINE logs
	$CBEngineLogFolder = Join-Path $WindowsAzureBackup "Temp\"
	$OutputBase = $ComputerName + "_CBENGINE" 
	CompressCollectFilesForTimePeriod -filesToCollect ($CBEngineLogFolder + "\*.errlog") -DestinationFileName ($OutputBase) -sectionDescription $LocalsCollectDPMLogs.ID_DPM_INFORMATION -fileDescription $LocalsCollectDPMLogs.ID_DPM_ErrorLogs_Files -NumberOfDays 7	

   	$CBEngineConfigFolder = Join-Path $WindowsAzureBackup "Bin\"
    $OutputBase = "$ComputerName$Prefix" + "_cbengine.exe.config"
   	Copy-Item ($CBEngineConfigFolder + 'cbengine.exe.config') $OutputBase | out-null
    CollectFiles -filesToCollect $OutputBase -fileDescription "cbengine.exe.config"  -sectionDescription $LocalsCollectDPMLogs.ID_DPM_INFORMATION 
				
   	$CBEngineConfigFolder = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows Azure Backup\Config").ScratchLocation
    $OutputBase = "$ComputerName$Prefix" + "_CBSettings.xml"
   	Format-XML ([xml](get-content ($CBEngineConfigFolder + '\CBSettings.xml'))) -indent 4 | out-file $OutputBase | out-null
    CollectFiles -filesToCollect $OutputBase -fileDescription "CBSettings.xml"  -sectionDescription $LocalsCollectDPMLogs.ID_DPM_INFORMATION 

    $CBEngineConfigFolder = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows Azure Backup\Config").ScratchLocation
   	Get-ChildItem $CBEngineConfigFolder -recurse | Out-File ("Result\" + $computername + "_CBENGINE_Scratch_Folder.txt")

   	"Microsoft Azure Recovery Services Agent Version.: " + (Get-ChildItem ($WindowsAzureBackup  + 'bin\cbengine.exe')).VersionInfo.FileVersion            | Out-File ("Result\" + $computername + "_CBENGINE_AgentInfo.txt") 
    "Microsoft Azure MachineID.......................: " + (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows Azure Backup\Config').MachineId  | Out-File ("Result\" + $computername + "_CBENGINE_AgentInfo.txt") -Append -Width 500
   	"Microsoft Azure ResourceID......................: " + (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows Azure Backup\Config').ResourceId | Out-File ("Result\" + $computername + "_CBENGINE_AgentInfo.txt") -Append -Width 500
    "Microsoft Azure DisableThreadTimeout value......: " + $threadtimeout                                                                       | Out-File ("Result\" + $computername + "_CBENGINE_AgentInfo.txt") -Append -Width 500


	if($debug -eq $true){[void]$shell.popup("Run DC_DPMEventLogs.ps1")}

    # CBENGINE Event Logs

    if (IsDPMInstalled)
    {
	    copy-item $Env:systemroot\System32\winevt\Logs\CloudBackup.evtx ("Result\" + $computername + "_evt_CloudBackup.evtx")
	    Get-WinEvent -path "$Env:systemroot\System32\winevt\Logs\CloudBackup.evtx" > ("Result\" + $computername + "_evt_CloudBackup.txt")
    }
    else
    {
       if ($OSVersion.major -gt 4)
       {
	       $EventLogList = Get-ChildItem HKLM:\System\CurrentControlSet\Services\Eventlog | split-path -leaf | Where-Object { $_ -ne 'Application' -and $_ -ne 'DPM Alerts'-and $_ -ne 'System'}
   	       Foreach ($List in $EventLogList)
	       {
		       $EventLog += '-s "' + $List + '" '
           }	
 	       $command = ".\dumpevt.exe Result\" + $computername + "_evt_ " + $eventlog	
	       invoke-expression -command $command
	       copy-item $Env:systemroot\System32\winevt\Logs\CloudBackup.evtx ("Result\" + $computername + "_evt_CloudBackup.evtx")
	       Get-WinEvent -path "$Env:systemroot\System32\winevt\Logs\CloudBackup.evtx" > ("Result\" + $computername + "_evt_CloudBackup.txt")
       }
       else
       {
    	   $EventLogNames = @(Get-ChildItem HKLM:\System\CurrentControlSet\Services\Eventlog | split-path -leaf | Where-Object { $_ -eq 'Application' -or $_ -eq 'DPM Alerts'-or $_ -eq 'System' })	
       }
    }

    .\TS_GetEvents.ps1 -EventLogNames $EventLogNames -Days 10 -OutputFormats ("CSV","evtx","txt")
}


# SIG # Begin signature block
# MIInrgYJKoZIhvcNAQcCoIInnzCCJ5sCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCBR0RyvQt3ziD8G
# tFqFVVybfBHTLikqLmUkNga8R3NCwKCCDXYwggX0MIID3KADAgECAhMzAAACy7d1
# OfsCcUI2AAAAAALLMA0GCSqGSIb3DQEBCwUAMH4xCzAJBgNVBAYTAlVTMRMwEQYD
# VQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMTH01pY3Jvc29mdCBDb2RlIFNpZ25p
# bmcgUENBIDIwMTEwHhcNMjIwNTEyMjA0NTU5WhcNMjMwNTExMjA0NTU5WjB0MQsw
# CQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9u
# ZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMR4wHAYDVQQDExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIB
# AQC3sN0WcdGpGXPZIb5iNfFB0xZ8rnJvYnxD6Uf2BHXglpbTEfoe+mO//oLWkRxA
# wppditsSVOD0oglKbtnh9Wp2DARLcxbGaW4YanOWSB1LyLRpHnnQ5POlh2U5trg4
# 3gQjvlNZlQB3lL+zrPtbNvMA7E0Wkmo+Z6YFnsf7aek+KGzaGboAeFO4uKZjQXY5
# RmMzE70Bwaz7hvA05jDURdRKH0i/1yK96TDuP7JyRFLOvA3UXNWz00R9w7ppMDcN
# lXtrmbPigv3xE9FfpfmJRtiOZQKd73K72Wujmj6/Su3+DBTpOq7NgdntW2lJfX3X
# a6oe4F9Pk9xRhkwHsk7Ju9E/AgMBAAGjggFzMIIBbzAfBgNVHSUEGDAWBgorBgEE
# AYI3TAgBBggrBgEFBQcDAzAdBgNVHQ4EFgQUrg/nt/gj+BBLd1jZWYhok7v5/w4w
# RQYDVR0RBD4wPKQ6MDgxHjAcBgNVBAsTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEW
# MBQGA1UEBRMNMjMwMDEyKzQ3MDUyODAfBgNVHSMEGDAWgBRIbmTlUAXTgqoXNzci
# tW2oynUClTBUBgNVHR8ETTBLMEmgR6BFhkNodHRwOi8vd3d3Lm1pY3Jvc29mdC5j
# b20vcGtpb3BzL2NybC9NaWNDb2RTaWdQQ0EyMDExXzIwMTEtMDctMDguY3JsMGEG
# CCsGAQUFBwEBBFUwUzBRBggrBgEFBQcwAoZFaHR0cDovL3d3dy5taWNyb3NvZnQu
# Y29tL3BraW9wcy9jZXJ0cy9NaWNDb2RTaWdQQ0EyMDExXzIwMTEtMDctMDguY3J0
# MAwGA1UdEwEB/wQCMAAwDQYJKoZIhvcNAQELBQADggIBAJL5t6pVjIRlQ8j4dAFJ
# ZnMke3rRHeQDOPFxswM47HRvgQa2E1jea2aYiMk1WmdqWnYw1bal4IzRlSVf4czf
# zx2vjOIOiaGllW2ByHkfKApngOzJmAQ8F15xSHPRvNMmvpC3PFLvKMf3y5SyPJxh
# 922TTq0q5epJv1SgZDWlUlHL/Ex1nX8kzBRhHvc6D6F5la+oAO4A3o/ZC05OOgm4
# EJxZP9MqUi5iid2dw4Jg/HvtDpCcLj1GLIhCDaebKegajCJlMhhxnDXrGFLJfX8j
# 7k7LUvrZDsQniJZ3D66K+3SZTLhvwK7dMGVFuUUJUfDifrlCTjKG9mxsPDllfyck
# 4zGnRZv8Jw9RgE1zAghnU14L0vVUNOzi/4bE7wIsiRyIcCcVoXRneBA3n/frLXvd
# jDsbb2lpGu78+s1zbO5N0bhHWq4j5WMutrspBxEhqG2PSBjC5Ypi+jhtfu3+x76N
# mBvsyKuxx9+Hm/ALnlzKxr4KyMR3/z4IRMzA1QyppNk65Ui+jB14g+w4vole33M1
# pVqVckrmSebUkmjnCshCiH12IFgHZF7gRwE4YZrJ7QjxZeoZqHaKsQLRMp653beB
# fHfeva9zJPhBSdVcCW7x9q0c2HVPLJHX9YCUU714I+qtLpDGrdbZxD9mikPqL/To
# /1lDZ0ch8FtePhME7houuoPcMIIHejCCBWKgAwIBAgIKYQ6Q0gAAAAAAAzANBgkq
# hkiG9w0BAQsFADCBiDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24x
# EDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlv
# bjEyMDAGA1UEAxMpTWljcm9zb2Z0IFJvb3QgQ2VydGlmaWNhdGUgQXV0aG9yaXR5
# IDIwMTEwHhcNMTEwNzA4MjA1OTA5WhcNMjYwNzA4MjEwOTA5WjB+MQswCQYDVQQG
# EwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwG
# A1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSgwJgYDVQQDEx9NaWNyb3NvZnQg
# Q29kZSBTaWduaW5nIFBDQSAyMDExMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIIC
# CgKCAgEAq/D6chAcLq3YbqqCEE00uvK2WCGfQhsqa+laUKq4BjgaBEm6f8MMHt03
# a8YS2AvwOMKZBrDIOdUBFDFC04kNeWSHfpRgJGyvnkmc6Whe0t+bU7IKLMOv2akr
# rnoJr9eWWcpgGgXpZnboMlImEi/nqwhQz7NEt13YxC4Ddato88tt8zpcoRb0Rrrg
# OGSsbmQ1eKagYw8t00CT+OPeBw3VXHmlSSnnDb6gE3e+lD3v++MrWhAfTVYoonpy
# 4BI6t0le2O3tQ5GD2Xuye4Yb2T6xjF3oiU+EGvKhL1nkkDstrjNYxbc+/jLTswM9
# sbKvkjh+0p2ALPVOVpEhNSXDOW5kf1O6nA+tGSOEy/S6A4aN91/w0FK/jJSHvMAh
# dCVfGCi2zCcoOCWYOUo2z3yxkq4cI6epZuxhH2rhKEmdX4jiJV3TIUs+UsS1Vz8k
# A/DRelsv1SPjcF0PUUZ3s/gA4bysAoJf28AVs70b1FVL5zmhD+kjSbwYuER8ReTB
# w3J64HLnJN+/RpnF78IcV9uDjexNSTCnq47f7Fufr/zdsGbiwZeBe+3W7UvnSSmn
# Eyimp31ngOaKYnhfsi+E11ecXL93KCjx7W3DKI8sj0A3T8HhhUSJxAlMxdSlQy90
# lfdu+HggWCwTXWCVmj5PM4TasIgX3p5O9JawvEagbJjS4NaIjAsCAwEAAaOCAe0w
# ggHpMBAGCSsGAQQBgjcVAQQDAgEAMB0GA1UdDgQWBBRIbmTlUAXTgqoXNzcitW2o
# ynUClTAZBgkrBgEEAYI3FAIEDB4KAFMAdQBiAEMAQTALBgNVHQ8EBAMCAYYwDwYD
# VR0TAQH/BAUwAwEB/zAfBgNVHSMEGDAWgBRyLToCMZBDuRQFTuHqp8cx0SOJNDBa
# BgNVHR8EUzBRME+gTaBLhklodHRwOi8vY3JsLm1pY3Jvc29mdC5jb20vcGtpL2Ny
# bC9wcm9kdWN0cy9NaWNSb29DZXJBdXQyMDExXzIwMTFfMDNfMjIuY3JsMF4GCCsG
# AQUFBwEBBFIwUDBOBggrBgEFBQcwAoZCaHR0cDovL3d3dy5taWNyb3NvZnQuY29t
# L3BraS9jZXJ0cy9NaWNSb29DZXJBdXQyMDExXzIwMTFfMDNfMjIuY3J0MIGfBgNV
# HSAEgZcwgZQwgZEGCSsGAQQBgjcuAzCBgzA/BggrBgEFBQcCARYzaHR0cDovL3d3
# dy5taWNyb3NvZnQuY29tL3BraW9wcy9kb2NzL3ByaW1hcnljcHMuaHRtMEAGCCsG
# AQUFBwICMDQeMiAdAEwAZQBnAGEAbABfAHAAbwBsAGkAYwB5AF8AcwB0AGEAdABl
# AG0AZQBuAHQALiAdMA0GCSqGSIb3DQEBCwUAA4ICAQBn8oalmOBUeRou09h0ZyKb
# C5YR4WOSmUKWfdJ5DJDBZV8uLD74w3LRbYP+vj/oCso7v0epo/Np22O/IjWll11l
# hJB9i0ZQVdgMknzSGksc8zxCi1LQsP1r4z4HLimb5j0bpdS1HXeUOeLpZMlEPXh6
# I/MTfaaQdION9MsmAkYqwooQu6SpBQyb7Wj6aC6VoCo/KmtYSWMfCWluWpiW5IP0
# wI/zRive/DvQvTXvbiWu5a8n7dDd8w6vmSiXmE0OPQvyCInWH8MyGOLwxS3OW560
# STkKxgrCxq2u5bLZ2xWIUUVYODJxJxp/sfQn+N4sOiBpmLJZiWhub6e3dMNABQam
# ASooPoI/E01mC8CzTfXhj38cbxV9Rad25UAqZaPDXVJihsMdYzaXht/a8/jyFqGa
# J+HNpZfQ7l1jQeNbB5yHPgZ3BtEGsXUfFL5hYbXw3MYbBL7fQccOKO7eZS/sl/ah
# XJbYANahRr1Z85elCUtIEJmAH9AAKcWxm6U/RXceNcbSoqKfenoi+kiVH6v7RyOA
# 9Z74v2u3S5fi63V4GuzqN5l5GEv/1rMjaHXmr/r8i+sLgOppO6/8MO0ETI7f33Vt
# Y5E90Z1WTk+/gFcioXgRMiF670EKsT/7qMykXcGhiJtXcVZOSEXAQsmbdlsKgEhr
# /Xmfwb1tbWrJUnMTDXpQzTGCGY4wghmKAgEBMIGVMH4xCzAJBgNVBAYTAlVTMRMw
# EQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVN
# aWNyb3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMTH01pY3Jvc29mdCBDb2RlIFNp
# Z25pbmcgUENBIDIwMTECEzMAAALLt3U5+wJxQjYAAAAAAsswDQYJYIZIAWUDBAIB
# BQCggbAwGQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQwHAYKKwYBBAGCNwIBCzEO
# MAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEILLejlovP1H4LtrDBjw+9Zub
# AfZ98/Zw6BSjpasFVwv3MEQGCisGAQQBgjcCAQwxNjA0oBSAEgBNAGkAYwByAG8A
# cwBvAGYAdKEcgBpodHRwczovL3d3dy5taWNyb3NvZnQuY29tIDANBgkqhkiG9w0B
# AQEFAASCAQARVD+Wncscn15h+ps4AjsEOtcmSgXp7Kf/tPGqgc7x5cVDjE4Biwjm
# LQZS4R6QqNYwoJFjdKin3Q5v1ani/9IE0S+VFga34KDujo2GVojxg7cUrtrph9Od
# xzH2+3w3urm7xPc7XuOfr30q+x+BjaLhMSddMhhlj+LHy6fQjZx7svr7JXXBFLHp
# 7y1vg82LAjg27KqS9Y1kY2/x/chGEOQmXcRa5wl8Am5vLZszdptRH3gvQzkKbpHY
# cFFObeMwKp/r0RxZnf7SIC+7uAyjVxNvJaXPbNUEtB+Oe+cBb94n0+9cGtRteSFl
# qYQnKvfDTpBgAlMiGyag6mn7jQ/rXHuQoYIXFjCCFxIGCisGAQQBgjcDAwExghcC
# MIIW/gYJKoZIhvcNAQcCoIIW7zCCFusCAQMxDzANBglghkgBZQMEAgEFADCCAVkG
# CyqGSIb3DQEJEAEEoIIBSASCAUQwggFAAgEBBgorBgEEAYRZCgMBMDEwDQYJYIZI
# AWUDBAIBBQAEIGRclOg4X28kPC6kWoK9QC47H53mMR83GG6znPsJ3qm6AgZi3ohP
# 3gEYEzIwMjIwODAxMDczNTI0Ljc2OFowBIACAfSggdikgdUwgdIxCzAJBgNVBAYT
# AlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYD
# VQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xLTArBgNVBAsTJE1pY3Jvc29mdCBJ
# cmVsYW5kIE9wZXJhdGlvbnMgTGltaXRlZDEmMCQGA1UECxMdVGhhbGVzIFRTUyBF
# U046RDA4Mi00QkZELUVFQkExJTAjBgNVBAMTHE1pY3Jvc29mdCBUaW1lLVN0YW1w
# IFNlcnZpY2WgghFlMIIHFDCCBPygAwIBAgITMwAAAY/zUajrWnLdzAABAAABjzAN
# BgkqhkiG9w0BAQsFADB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3Rv
# bjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0
# aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAxMDAeFw0y
# MTEwMjgxOTI3NDZaFw0yMzAxMjYxOTI3NDZaMIHSMQswCQYDVQQGEwJVUzETMBEG
# A1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWlj
# cm9zb2Z0IENvcnBvcmF0aW9uMS0wKwYDVQQLEyRNaWNyb3NvZnQgSXJlbGFuZCBP
# cGVyYXRpb25zIExpbWl0ZWQxJjAkBgNVBAsTHVRoYWxlcyBUU1MgRVNOOkQwODIt
# NEJGRC1FRUJBMSUwIwYDVQQDExxNaWNyb3NvZnQgVGltZS1TdGFtcCBTZXJ2aWNl
# MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAmVc+/rXPFx6Fk4+CpLru
# bDrLTa3QuAHRVXuy+zsxXwkogkT0a+XWuBabwHyqj8RRiZQQvdvbOq5NRExOeHia
# CtkUsQ02ESAe9Cz+loBNtsfCq846u3otWHCJlqkvDrSr7mMBqwcRY7cfhAGfLvlp
# MSojoAnk7Rej+jcJnYxIeN34F3h9JwANY360oGYCIS7pLOosWV+bxug9uiTZYE/X
# clyYNF6XdzZ/zD/4U5pxT4MZQmzBGvDs+8cDdA/stZfj/ry+i0XUYNFPhuqc+UKk
# wm/XNHB+CDsGQl+ZS0GcbUUun4VPThHJm6mRAwL5y8zptWEIocbTeRSTmZnUa2iY
# H2EOBV7eCjx0Sdb6kLc1xdFRckDeQGR4J1yFyybuZsUP8x0dOsEEoLQuOhuKlDLQ
# Eg7D6ZxmZJnS8B03ewk/SpVLqsb66U2qyF4BwDt1uZkjEZ7finIoUgSz4B7fWLYI
# eO2OCYxIE0XvwsVop9PvTXTZtGPzzmHU753GarKyuM6oa/qaTzYvrAfUb7KYhvVQ
# KxGUPkL9+eKiM7G0qenJCFrXzZPwRWoccAR33PhNEuuzzKZFJ4DeaTCLg/8uK0Q4
# QjFRef5n4H+2KQIEibZ7zIeBX3jgsrICbzzSm0QX3SRVmZH//Aqp8YxkwcoI1WCB
# izv84z9eqwRBdQ4HYcNbQMMCAwEAAaOCATYwggEyMB0GA1UdDgQWBBTzBuZ0a65J
# zuKhzoWb25f7NyNxvDAfBgNVHSMEGDAWgBSfpxVdAF5iXYP05dJlpxtTNRnpcjBf
# BgNVHR8EWDBWMFSgUqBQhk5odHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpb3Bz
# L2NybC9NaWNyb3NvZnQlMjBUaW1lLVN0YW1wJTIwUENBJTIwMjAxMCgxKS5jcmww
# bAYIKwYBBQUHAQEEYDBeMFwGCCsGAQUFBzAChlBodHRwOi8vd3d3Lm1pY3Jvc29m
# dC5jb20vcGtpb3BzL2NlcnRzL01pY3Jvc29mdCUyMFRpbWUtU3RhbXAlMjBQQ0El
# MjAyMDEwKDEpLmNydDAMBgNVHRMBAf8EAjAAMBMGA1UdJQQMMAoGCCsGAQUFBwMI
# MA0GCSqGSIb3DQEBCwUAA4ICAQDNf9Oo9zyhC5n1jC8iU7NJY39FizjhxZwJbJY/
# Ytwn63plMlTSaBperan566fuRojGJSv3EwZs+RruOU2T/ZRDx4VHesLHtclE8GmM
# M1qTMaZPL8I2FrRmf5Oop4GqcxNdNECBClVZmn0KzFdPMqRa5/0R6CmgqJh0muvI
# mikgHubvohsavPEyyHQa94HD4/LNKd/YIaCKKPz9SA5fAa4phQ4Evz2auY9SUluI
# d5MK9H5cjWVwBxCvYAD+1CW9z7GshJlNjqBvWtKO6J0Aemfg6z28g7qc7G/tCtrl
# H4/y27y+stuwWXNvwdsSd1lvB4M63AuMl9Yp6au/XFknGzJPF6n/uWR6JhQvzh40
# ILgeThLmYhf8z+aDb4r2OBLG1P2B6aCTW2YQkt7TpUnzI0cKGr213CbKtGk/OOIH
# SsDOxasmeGJ+FiUJCiV15wh3aZT/VT/PkL9E4hDBAwGt49G88gSCO0x9jfdDZWdW
# GbELXlSmA3EP4eTYq7RrolY04G8fGtF0pzuZu43A29zaI9lIr5ulKRz8EoQHU6cu
# 0PxUw0B9H8cAkvQxaMumRZ/4fCbqNb4TcPkPcWOI24QYlvpbtT9p31flYElmc5wj
# GplAky/nkJcT0HZENXenxWtPvt4gcoqppeJPA3S/1D57KL3667epIr0yV290E2ot
# ZbAW8DCCB3EwggVZoAMCAQICEzMAAAAVxedrngKbSZkAAAAAABUwDQYJKoZIhvcN
# AQELBQAwgYgxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYD
# VQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xMjAw
# BgNVBAMTKU1pY3Jvc29mdCBSb290IENlcnRpZmljYXRlIEF1dGhvcml0eSAyMDEw
# MB4XDTIxMDkzMDE4MjIyNVoXDTMwMDkzMDE4MzIyNVowfDELMAkGA1UEBhMCVVMx
# EzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoT
# FU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUt
# U3RhbXAgUENBIDIwMTAwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQDk
# 4aZM57RyIQt5osvXJHm9DtWC0/3unAcH0qlsTnXIyjVX9gF/bErg4r25PhdgM/9c
# T8dm95VTcVrifkpa/rg2Z4VGIwy1jRPPdzLAEBjoYH1qUoNEt6aORmsHFPPFdvWG
# UNzBRMhxXFExN6AKOG6N7dcP2CZTfDlhAnrEqv1yaa8dq6z2Nr41JmTamDu6Gnsz
# rYBbfowQHJ1S/rboYiXcag/PXfT+jlPP1uyFVk3v3byNpOORj7I5LFGc6XBpDco2
# LXCOMcg1KL3jtIckw+DJj361VI/c+gVVmG1oO5pGve2krnopN6zL64NF50ZuyjLV
# wIYwXE8s4mKyzbnijYjklqwBSru+cakXW2dg3viSkR4dPf0gz3N9QZpGdc3EXzTd
# EonW/aUgfX782Z5F37ZyL9t9X4C626p+Nuw2TPYrbqgSUei/BQOj0XOmTTd0lBw0
# gg/wEPK3Rxjtp+iZfD9M269ewvPV2HM9Q07BMzlMjgK8QmguEOqEUUbi0b1qGFph
# AXPKZ6Je1yh2AuIzGHLXpyDwwvoSCtdjbwzJNmSLW6CmgyFdXzB0kZSU2LlQ+QuJ
# YfM2BjUYhEfb3BvR/bLUHMVr9lxSUV0S2yW6r1AFemzFER1y7435UsSFF5PAPBXb
# GjfHCBUYP3irRbb1Hode2o+eFnJpxq57t7c+auIurQIDAQABo4IB3TCCAdkwEgYJ
# KwYBBAGCNxUBBAUCAwEAATAjBgkrBgEEAYI3FQIEFgQUKqdS/mTEmr6CkTxGNSnP
# EP8vBO4wHQYDVR0OBBYEFJ+nFV0AXmJdg/Tl0mWnG1M1GelyMFwGA1UdIARVMFMw
# UQYMKwYBBAGCN0yDfQEBMEEwPwYIKwYBBQUHAgEWM2h0dHA6Ly93d3cubWljcm9z
# b2Z0LmNvbS9wa2lvcHMvRG9jcy9SZXBvc2l0b3J5Lmh0bTATBgNVHSUEDDAKBggr
# BgEFBQcDCDAZBgkrBgEEAYI3FAIEDB4KAFMAdQBiAEMAQTALBgNVHQ8EBAMCAYYw
# DwYDVR0TAQH/BAUwAwEB/zAfBgNVHSMEGDAWgBTV9lbLj+iiXGJo0T2UkFvXzpoY
# xDBWBgNVHR8ETzBNMEugSaBHhkVodHRwOi8vY3JsLm1pY3Jvc29mdC5jb20vcGtp
# L2NybC9wcm9kdWN0cy9NaWNSb29DZXJBdXRfMjAxMC0wNi0yMy5jcmwwWgYIKwYB
# BQUHAQEETjBMMEoGCCsGAQUFBzAChj5odHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20v
# cGtpL2NlcnRzL01pY1Jvb0NlckF1dF8yMDEwLTA2LTIzLmNydDANBgkqhkiG9w0B
# AQsFAAOCAgEAnVV9/Cqt4SwfZwExJFvhnnJL/Klv6lwUtj5OR2R4sQaTlz0xM7U5
# 18JxNj/aZGx80HU5bbsPMeTCj/ts0aGUGCLu6WZnOlNN3Zi6th542DYunKmCVgAD
# sAW+iehp4LoJ7nvfam++Kctu2D9IdQHZGN5tggz1bSNU5HhTdSRXud2f8449xvNo
# 32X2pFaq95W2KFUn0CS9QKC/GbYSEhFdPSfgQJY4rPf5KYnDvBewVIVCs/wMnosZ
# iefwC2qBwoEZQhlSdYo2wh3DYXMuLGt7bj8sCXgU6ZGyqVvfSaN0DLzskYDSPeZK
# PmY7T7uG+jIa2Zb0j/aRAfbOxnT99kxybxCrdTDFNLB62FD+CljdQDzHVG2dY3RI
# LLFORy3BFARxv2T5JL5zbcqOCb2zAVdJVGTZc9d/HltEAY5aGZFrDZ+kKNxnGSgk
# ujhLmm77IVRrakURR6nxt67I6IleT53S0Ex2tVdUCbFpAUR+fKFhbHP+CrvsQWY9
# af3LwUFJfn6Tvsv4O+S3Fb+0zj6lMVGEvL8CwYKiexcdFYmNcP7ntdAoGokLjzba
# ukz5m/8K6TT4JDVnK+ANuOaMmdbhIurwJ0I9JZTmdHRbatGePu1+oDEzfbzL6Xu/
# OHBE0ZDxyKs6ijoIYn/ZcGNTTY3ugm2lBRDBcQZqELQdVTNYs6FwZvKhggLUMIIC
# PQIBATCCAQChgdikgdUwgdIxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5n
# dG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9y
# YXRpb24xLTArBgNVBAsTJE1pY3Jvc29mdCBJcmVsYW5kIE9wZXJhdGlvbnMgTGlt
# aXRlZDEmMCQGA1UECxMdVGhhbGVzIFRTUyBFU046RDA4Mi00QkZELUVFQkExJTAj
# BgNVBAMTHE1pY3Jvc29mdCBUaW1lLVN0YW1wIFNlcnZpY2WiIwoBATAHBgUrDgMC
# GgMVAD5NL4IEdudIBwdGoCaV0WBbQZpqoIGDMIGApH4wfDELMAkGA1UEBhMCVVMx
# EzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoT
# FU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUt
# U3RhbXAgUENBIDIwMTAwDQYJKoZIhvcNAQEFBQACBQDmkZg6MCIYDzIwMjIwODAx
# MDgwOTMwWhgPMjAyMjA4MDIwODA5MzBaMHQwOgYKKwYBBAGEWQoEATEsMCowCgIF
# AOaRmDoCAQAwBwIBAAICEbAwBwIBAAICEXEwCgIFAOaS6boCAQAwNgYKKwYBBAGE
# WQoEAjEoMCYwDAYKKwYBBAGEWQoDAqAKMAgCAQACAwehIKEKMAgCAQACAwGGoDAN
# BgkqhkiG9w0BAQUFAAOBgQAhp8Aod4IrqWSzJRIvhdfsjjJ0NJWgA/ZOXoGxuTHB
# Nc+n4eD9raE8WV172xcQru+BQW4ecbLSElX8gQ88qDD0qPr3S/FY/5drB43kpsZb
# 3smIRpvR0AhUrfQV/szgrx7+5TBOZSinvdOPsft4KHAzsWahf7BfumsXJdtpt6+W
# nzGCBA0wggQJAgEBMIGTMHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5n
# dG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9y
# YXRpb24xJjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEwAhMz
# AAABj/NRqOtact3MAAEAAAGPMA0GCWCGSAFlAwQCAQUAoIIBSjAaBgkqhkiG9w0B
# CQMxDQYLKoZIhvcNAQkQAQQwLwYJKoZIhvcNAQkEMSIEIHDKiZSMT/QmT+H7cP7n
# Fsw88pzYxtW7AfmDjyiMSaMdMIH6BgsqhkiG9w0BCRACLzGB6jCB5zCB5DCBvQQg
# l3IFT+LGxguVjiKm22ItmO6dFDWW8nShu6O6g8yFxx8wgZgwgYCkfjB8MQswCQYD
# VQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEe
# MBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSYwJAYDVQQDEx1NaWNyb3Nv
# ZnQgVGltZS1TdGFtcCBQQ0EgMjAxMAITMwAAAY/zUajrWnLdzAABAAABjzAiBCDK
# yRgnJWWXshnmgygiJTZnJFpENKNV36rl3eKKIz0TKjANBgkqhkiG9w0BAQsFAASC
# AgAGH2a3z/rRvsnp6uV8b8mPuUqoIdAUb5oLlqwxVXXioUwhw0EHuWGAkbtHIB8g
# J02WVste9zSqMz5gweDHiJl2xEYn1Q8Qts35xFi9SSU94lwwZGaOWLMkgkixHlk4
# YGSDmvSTJ2dHY+UELmifRgSkp4mRTsMNuo2y7V1JHyFSk6c2KnFrYDC1oC4R35rU
# Wj9vOglsXj8FeUKVOHRfJEzAoOWJxTtGp62EirnHf7CrI8q/ytrr6kH7ablbfo6X
# Pmprw0dxUSQAx8HaArAldY5EsSSFWZgRyUFnj4PAW3fTF5UvDDPcvKoO3yHz6lL0
# lCQAABNRC0l3LJ7UZAcjbv8CQ9MvfHD7rH3r+f3EXErLisbWAIDCPKJbq0XjYUpz
# 8gCT3KwWd/btMs/Zsx3zG+0Q0l9z+0xxAv/chQVHhcMWpEtn1Zkpp32D+EI3lR1G
# FC+uiY75MUFmTOdSPcauKmmyHVs9Ivl4lMV6d6aHE2RHgC6iP42ldxyGMEEo/UVb
# JBOXjZK3IsgxMEvsLcbi07Xg7go/B5yOSDddEWFaIo8PUC8IuwRq/EZyw/SgSAHa
# P3T5W+DH4xUDMeHnkzTXNvNSR/ADnHo5IR9GhXvHJc80sBfisRSlTDtLrWuZTrpW
# 5Mm+EYA2Nt+P2PLzQeiA6l8Q+kMA+3m8/TYeBY9IGeWgtw==
# SIG # End signature block
