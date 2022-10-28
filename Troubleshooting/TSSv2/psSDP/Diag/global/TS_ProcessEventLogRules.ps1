# 2019-03-17 WalterE added Trap #_#
Trap [Exception]
	{
	 # Handle exception and throw it to the stdout log file. Then continue with function and script.
		 WriteTo-ErrorDebugReport -ErrorRecord $_
		 $Script:ExceptionMessage = $_
		 "[info]: Exception occurred."  | WriteTo-StdOut
		 "[info]: Exception.Message $ExceptionMessage."  | WriteTo-StdOut 
		 $Error.Clear()
		 continue
	}

Import-LocalizedData -BindingVariable ScriptStrings

Function GetEventLogAlertGenerated
{

      $EventLogAlertXMLFileName = Join-Path $PWD.Path ($Computername + "_EventLogAlerts.XML")

      
      if ($EventLogAlertXMLFileName)
      {
            "Processing Event Log Alerts from " + (Split-Path $EventLogAlertXMLFileName -Leaf) | WriteTo-StdOut -ShortFormat
      
            [xml] $XMLEventAlerts = Get-Content -Path $EventLogAlertXMLFileName
            $EventLogAlerts = @()

            if($null -ne $XMLEventAlerts)
            {
                  $XMLEventAlerts.SelectNodes("//Alert") | ForEach-Object -Process {
                        $EventLogAlert = New-Object PSObject
                        $EventLogAlert | Add-Member -MemberType NoteProperty -Name "EventLogName" -Value $_.EventLog
                        $EventLogAlert | Add-Member -MemberType NoteProperty -Name "Id" -Value $_.Id
                        $EventLogAlert | Add-Member -MemberType NoteProperty -Name "Type" -Value $_.Type
                        $EventLogAlert | Add-Member -MemberType NoteProperty -Name "Source" -Value $_.Source
                        $EventLogAlert | Add-Member -MemberType NoteProperty -Name "DaysToMonitor" -Value $_.DaysToMonitor
                        $EventLogAlert | Add-Member -MemberType NoteProperty -Name "EventCount" -Value $_.EventCount
                        $EventLogAlert | Add-Member -MemberType NoteProperty -Name "LastOccurrenceDate" -Value $_.LastOccurrence
                        $EventLogAlert | Add-Member -MemberType NoteProperty -Name "FirstOccurenceDate" -Value $_.FirstOccurence
                        $EventLogAlert | Add-Member -MemberType NoteProperty -Name "LastOccurrenceMessage" -Value $_.LastOccurrenceMessage

                        $EventLogAlerts += $EventLogAlert
                  }
            }
            return $EventLogAlerts
      }
      else
      {
            "$EventLogAlertXMLFileName does not exist. No Event Log alerts generated"  | WriteTo-StdOut -ShortFormat
      }
}

$EventLogAlerts = GetEventLogAlertGenerated

Function CheckEventIDExist([string]$EventId,[string]$EventSource,[string]$EventLogName,$EventLogAlertList= $null,[psobject]$EventInformationCollected)
{
	if($null -ne $EventLogAlertList)
	{
		foreach($EventLogAlert in $EventLogAlertList)
		{
			if(($EventLogAlert.Id -eq $EventId) -and ($EventLogAlert.EventLogName -eq $EventLogName)-and 
			($EventLogAlert.Source -eq $EventSource))
			{
				$EventInformationCollected | Add-Member -MemberType NoteProperty -Name "Event Log Name" -Value $EventLogAlert.EventLogName
				$EventInformationCollected | Add-Member -MemberType NoteProperty -Name "Event ID" -Value $EventLogAlert.Id
				$EventInformationCollected | Add-Member -MemberType NoteProperty -Name "Source" -Value $EventLogAlert.Source
				$EventInformationCollected | Add-Member -MemberType NoteProperty -Name "Number of Occurrences" -Value $EventLogAlert.EventCount
				$EventInformationCollected | Add-Member -MemberType NoteProperty -Name "Number of Days" -Value $EventLogAlert.DaysToMonitor
				$EventInformationCollected | Add-Member -MemberType NoteProperty -Name "Last event" -Value $EventLogAlert.LastOccurrenceDate
				$EventInformationCollected | Add-Member -MemberType NoteProperty -Name "Last Event Log Message" -Value $EventLogAlert.LastOccurrenceMessage
				return $true
			}
		}
	}
	return $false
}


#************************************ Functions of Rule 6301************************************#
Function Rule6301AppliesToSystem
{
	return ($OSVersion.Major -eq 5) -and ($OSVersion.Minor -eq 2)
}

Function Rule6301CheckEventID333AndHotFix970054([psobject]$InformationCollected)
{
	$IsFireRule = $false
	if(CheckEventIDExist -EventId 333 -EventLogName 'System' -EventSource 'Application Popup' -EventLogAlertList $EventLogAlerts -EventInformationCollected $InformationCollected)
	{
		$Win32OS= Get-CimInstance Win32_OperatingSystem
		if($null -ne $Win32OS)
		{
			$IsHotFix970054Installed = $false
			$NtoskrnlPath = Join-Path $Env:windir "System32\ntoskrnl.exe"
			if($Win32OS.CSDVersion -eq 'Service Pack 1')
			{
				$IsHotFix970054Installed = CheckMinimalFileVersion $NtoskrnlPath 5 2 3790 3328
			}
			elseif($Win32OS.CSDVersion -eq 'Service Pack 2')
			{
				$IsHotFix970054Installed = CheckMinimalFileVersion $NtoskrnlPath 5 2 3790 4497
			}
			if($IsHotFix970054Installed)
			{
				$RegistryFlushErrorSubsideTypeKey = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager"
				if(Test-Path $RegistryFlushErrorSubsideTypeKey)
				{
					if($null -eq ((Get-ItemProperty $RegistryFlushErrorSubsideTypeKey).RegistryFlushErrorSubsideType))
					{
						$IsFireRule = $true
					}
				}
			}
			else
			{
				$IsFireRule = $true
			}
		}
	}
	return $IsFireRule
}


# [Idea ID 6301]
Function CheckRule6301
{
	$Rule6301RootCauseDetected = $false
	$Rule6301InformationCollected = new-object PSObject
	$Rule6301RootCauseName = "RC_EventID333Check"
	$Rule6301RuleApplicable = Rule6301AppliesToSystem

	# **************
	# Detection Logic
	# **************
	if ($Rule6301RuleApplicable)
	{
		$Rule6301RootCauseDetected = Rule6301CheckEventID333AndHotFix970054 -InformationCollected $Rule6301InformationCollected
	}
		
	# *********************
	# Root Cause processing
	# *********************
	if ($Rule6301RuleApplicable)
	{
		if ($Rule6301RootCauseDetected)
		{
			# Red/ Yellow Light
			Update-DiagRootCause -id $Rule6301RootCauseName -Detected $true
			Add-GenericMessage -Id $Rule6301RootCauseName -InformationCollected $Rule6301InformationCollected
		}
		else
		{
			# Green Light
			Update-DiagRootCause -id $Rule6301RootCauseName -Detected $false
		}
	}
}

#***********************************************************************************************#

#************************************ Functions of Rule b2c02cd5-4183-40a8-b25b-ee0597432811************************************#

Function Ruleb2c02cd5418340a8b25bee0597432811AppliesToSystem
{
	return ((($OSVersion.Major -eq 5)-and ($OSVersion.Minor -eq 2)) -or # Windows Server 2003
	(($OSVersion.Major -eq 6)-and ($OSVersion.Minor -eq 0))) # Windows Server 2008
}

Function Ruleb2c02cd5418340a8b25bee0597432811CheckEventID4689AndHotFix([psobject]$InformationCollected)
{
	$IsFireRule = $false
	$ComsvcsdllPath = Join-Path $Env:windir "System32\comsvcs.dll"
	$IsHotFixInstalled = CheckMinimalFileVersion $ComsvcsdllPath 2001 12 4720 4045
	if(!$IsHotFixInstalled)
	{
		if(CheckEventIDExist -EventId 4689 -EventLogName 'Application' -EventSource 'COM+' -EventLogAlertList $EventLogAlerts -EventInformationCollected $InformationCollected)
		{
			$IsFireRule = $true
		}
	}
	return $IsFireRule
}

Function CheckRuleb2c02cd5418340a8b25bee0597432811
{
	$Ruleb2c02cd5418340a8b25bee0597432811RuleApplicable = Ruleb2c02cd5418340a8b25bee0597432811AppliesToSystem
	$Ruleb2c02cd5418340a8b25bee0597432811RootCauseDetected = $false
	$Ruleb2c02cd5418340a8b25bee0597432811RootCauseName = "RC_EventID4689Check"
	$Ruleb2c02cd5418340a8b25bee0597432811InformationCollected = new-object PSObject

	# **************
	# Detection Logic
	# **************
	if ($Ruleb2c02cd5418340a8b25bee0597432811RuleApplicable)
	{
		$Ruleb2c02cd5418340a8b25bee0597432811RootCauseDetected = Ruleb2c02cd5418340a8b25bee0597432811CheckEventID4689AndHotFix -InformationCollected $Ruleb2c02cd5418340a8b25bee0597432811InformationCollected
	}
		
	# *********************
	# Root Cause processing
	# *********************
	if ($Ruleb2c02cd5418340a8b25bee0597432811RuleApplicable)
	{
		if ($Ruleb2c02cd5418340a8b25bee0597432811RootCauseDetected)
		{
			# Red/ Yellow Light
			Update-DiagRootCause -id $Ruleb2c02cd5418340a8b25bee0597432811RootCauseName -Detected $true
			Add-GenericMessage -Id $Ruleb2c02cd5418340a8b25bee0597432811RootCauseName -InformationCollected $Ruleb2c02cd5418340a8b25bee0597432811InformationCollected
		}
		else
		{
			# Green Light
			Update-DiagRootCause -id $Ruleb2c02cd5418340a8b25bee0597432811RootCauseName -Detected $false
		}
	}
}
#***********************************************************************************************#

#************************************ Functions of Rule 81ad63ea-48df-4066-8051-91f3323672a8************************************#
#************************************************
# Version 1.0.1
# Date: 7/16/2013
# Author: v-maam
# Description:  [KSE Rule] [ Windows V3] WinRM does not accept HTTP authorization requests that are larger than 16 KB
# Rule number:  81ad63ea-48df-4066-8051-91f3323672a8
# Rule URL:  https://kse.microsoft.com/Contribute/Idea/96ad45c3-eb18-4f41-ad94-b36ab175d26b
#************************************************

Function Rule6822AppliesToSystem
{
	#Add your logic here to specify on which environments this rule will appy
	return (($OSVersion.Build -eq 6001) -and ($OSVersion.Build -eq 6002)) # Windows Vista sp1/sp2 or Windows Server 2008 sp1/sp2
}

# [Rule 6822]
Function CheckRule6822
{
	Display-DefaultActivity -Rule -RuleNumber 81ad63ea-48df-4066-8051-91f3323672a8

	$Rule6822Applicable = $false
	$Rule6822RootCauseDetected = $false
	$Rule6822RootCauseName = "RC_WinRMHTTPRequestSizeCheck"
	$Rule6822InformationCollected = new-object PSObject

	# **************
	# Detection Logic
	# **************
	if(Rule6822AppliesToSystem)
	{
		$Rule6822Applicable = $true

		if(CheckEventIDExist -EventId 6 -EventLogName 'System' -EventSource 'Microsoft-Windows-Security-Kerberos' -EventLogAlertList $EventLogAlerts -EventInformationCollected $Rule6822InformationCollected)
		{
			$IsHotFix971244Installed = $false
			$WSManHttpConfigPath = Join-Path $Env:Windir "System32\WSManHTTPConfig.exe"
			if(Test-Path $WSManHttpConfigPath)
			{
				if($OSVersion.Build -eq 6001)
				{
					$IsHotFix971244Installed = CheckMinimalFileVersion $WSManHttpConfigPath 6 0 6001 22432
				}
				else
				{
					$IsHotFix971244Installed = CheckMinimalFileVersion $WSManHttpConfigPath 6 0 6002 22135
				}
			}

			$IsWinRMServiceRunning = $null -ne (Get-Service WinRM | Where-Object {$_.Status -eq "Running"})

			if((-not $IsHotFix971244Installed) -and (-not $IsWinRMServiceRunning))
			{
				$Rule6822RootCauseDetected = $true
			}
		}
	}

	# *********************
	# Root Cause processing
	# *********************
	if ($Rule6822Applicable)
	{
		if ($Rule6822RootCauseDetected)
		{
			# Red/ Yellow Light
			Update-DiagRootCause -id $Rule6822RootCauseName -Detected $true
			Add-GenericMessage -Id $Rule6822RootCauseName -InformationCollected $Rule6822InformationCollected
		}
		else
		{
			# Green Light
			Update-DiagRootCause -id $Rule6822RootCauseName -Detected $false
		}
	}
}

#************************************ End Functions of Rule 81ad63ea-48df-4066-8051-91f3323672a8************************************#

# Check Rule 6301 [Windows] Many events with ID 333 are added to the System log on a Windows Server 2003-based computer
CheckRule6301

#Check the comsvcs.dll is lower than 2001.12.4720.4045 and Event Id 4689 is in Application log
CheckRuleb2c02cd5418340a8b25bee0597432811

# Start to check the Rule 81ad63ea-48df-4066-8051-91f3323672a8
CheckRule6822


# SIG # Begin signature block
# MIInrgYJKoZIhvcNAQcCoIInnzCCJ5sCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCD3bDJM8COQfyJQ
# uy0888+Ua70P7kStOBw7I/zlzDgmt6CCDXYwggX0MIID3KADAgECAhMzAAACy7d1
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
# MAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIL+sw8LENAVKuxgaBTSnKMYE
# 2m1mD3XAWtCS6UgsoH8/MEQGCisGAQQBgjcCAQwxNjA0oBSAEgBNAGkAYwByAG8A
# cwBvAGYAdKEcgBpodHRwczovL3d3dy5taWNyb3NvZnQuY29tIDANBgkqhkiG9w0B
# AQEFAASCAQCSmE5lEZ8Itzllg++dfGzJqQrEFe6Ifi87pjhN2ckISOYZXMnM3cDB
# jKLqMM6IYsMn4sSWujMY5LHuSDiRuhq8YpA1ragjtiTxpoKXdWSZ5fjavINMfBIa
# MXnXK9twZfn49C+fkp9DaPl2JVGm3M/aicSKEuymdXeRee74aonCSIRDU3/PUrnc
# RZDT5+ByLRJQMIhm3Novns8k7XYCwndfy0nddUzzxNQdBlS1Q3GsL6TmC3V5wG9J
# rCQaNjFEbLu/k9uhJVcENcthnuTp89T7Wz7f7sCpzmqT1wwNrDZV44+nx+BCvKyu
# FddxxY7JK2OSSOg8j8ZTt6ZvRAX/7GWLoYIXFjCCFxIGCisGAQQBgjcDAwExghcC
# MIIW/gYJKoZIhvcNAQcCoIIW7zCCFusCAQMxDzANBglghkgBZQMEAgEFADCCAVkG
# CyqGSIb3DQEJEAEEoIIBSASCAUQwggFAAgEBBgorBgEEAYRZCgMBMDEwDQYJYIZI
# AWUDBAIBBQAEIKCN2o327Po4S9dV6o6HQHZPRL1bBSO1w3ShrfgfLFB9AgZi3n80
# 53IYEzIwMjIwODAxMDc0MzA1LjQ2MVowBIACAfSggdikgdUwgdIxCzAJBgNVBAYT
# AlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYD
# VQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xLTArBgNVBAsTJE1pY3Jvc29mdCBJ
# cmVsYW5kIE9wZXJhdGlvbnMgTGltaXRlZDEmMCQGA1UECxMdVGhhbGVzIFRTUyBF
# U046M0JENC00QjgwLTY5QzMxJTAjBgNVBAMTHE1pY3Jvc29mdCBUaW1lLVN0YW1w
# IFNlcnZpY2WgghFlMIIHFDCCBPygAwIBAgITMwAAAYm0v4YwhBxLjwABAAABiTAN
# BgkqhkiG9w0BAQsFADB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3Rv
# bjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0
# aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAxMDAeFw0y
# MTEwMjgxOTI3NDFaFw0yMzAxMjYxOTI3NDFaMIHSMQswCQYDVQQGEwJVUzETMBEG
# A1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWlj
# cm9zb2Z0IENvcnBvcmF0aW9uMS0wKwYDVQQLEyRNaWNyb3NvZnQgSXJlbGFuZCBP
# cGVyYXRpb25zIExpbWl0ZWQxJjAkBgNVBAsTHVRoYWxlcyBUU1MgRVNOOjNCRDQt
# NEI4MC02OUMzMSUwIwYDVQQDExxNaWNyb3NvZnQgVGltZS1TdGFtcCBTZXJ2aWNl
# MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAvQZXxZFma6plmuOyvNpV
# 8xONOwcYolZG/BjyZWGSk5JOGaLyrKId5VxVHWHlsmJE4SvnzsdpsKmVx8otONve
# IUFvSceEZp8VXmu5m1fu8L7c+3lwXcibjccqtEvtQslokQVx0r+L54abrNDarwFG
# 73IaRidIS1i9c+unJ8oYyhDRLrCysFAVxyQhPNZkWK7Z8/VGukaKLAWHXCh/+R53
# h42gFL+9/mAALxzCXXuofi8f/XKCm7xNwVc1hONCCz6oq94AufzVNkkIW4brUQgY
# pCcJm9U0XNmQvtropYDn9UtY8YQ0NKenXPtdgLHdQ8Nnv3igErKLrWI0a5n5jjdK
# fwk+8mvakqdZmlOseeOS1XspQNJAK1uZllAITcnQZOcO5ofjOQ33ujWckAXdz+/x
# 3o7l4AU/TSOMzGZMwhUdtVwC3dSbItpSVFgnjM2COEJ9zgCadvOirGDLN471jZI2
# jClkjsJTdgPk343TQA4JFvds/unZq0uLr+niZ3X44OBx2x+gVlln2c4UbZXNueA4
# yS1TJGbbJFIILAmTUA9Auj5eISGTbNiyWx79HnCOTar39QEKozm4LnTmDXy0/KI/
# H/nYZGKuTHfckP28wQS06rD+fDS5xLwcRMCW92DkHXmtbhGyRilBOL5LxZelQfxt
# 54wl4WUC0AdAEolPekODwO8CAwEAAaOCATYwggEyMB0GA1UdDgQWBBSXbx+zR1p4
# IIAeguA6rHKkrfl7UDAfBgNVHSMEGDAWgBSfpxVdAF5iXYP05dJlpxtTNRnpcjBf
# BgNVHR8EWDBWMFSgUqBQhk5odHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpb3Bz
# L2NybC9NaWNyb3NvZnQlMjBUaW1lLVN0YW1wJTIwUENBJTIwMjAxMCgxKS5jcmww
# bAYIKwYBBQUHAQEEYDBeMFwGCCsGAQUFBzAChlBodHRwOi8vd3d3Lm1pY3Jvc29m
# dC5jb20vcGtpb3BzL2NlcnRzL01pY3Jvc29mdCUyMFRpbWUtU3RhbXAlMjBQQ0El
# MjAyMDEwKDEpLmNydDAMBgNVHRMBAf8EAjAAMBMGA1UdJQQMMAoGCCsGAQUFBwMI
# MA0GCSqGSIb3DQEBCwUAA4ICAQCOtLdpWUI4KwfLLrfaKrLB92DqbAspGWM41TaO
# 4Jl+sHxPo522uu3GKQCjmkRWreHtlfyy9kOk7LWax3k3ke8Gtfetfbh7qH0LeV2X
# OWg39BOnHf6mTcZq7FYSZZch1JDQjc98+Odlow+oWih0Dbt4CV/e19ZcE+1n1zzW
# kskUEd0f5jPIUis33p+vkY8szduAtCcIcPFUhI8Hb5alPUAPMjGzwKb7NIKbnf8j
# 8cP18As5IveckF0oh1cw63RY/vPK62LDYdpi7WnG2ObvngfWVKtwiwTI4jHj2cO9
# q37HDe/PPl216gSpUZh0ap24mKmMDfcKp1N4mEdsxz4oseOrPYeFsHHWJFJ6Aivv
# qn70KTeJpp5r+DxSqbeSy0mxIUOq/lAaUxgNSQVUX26t8r+fcikofKv23WHrtRV3
# t7rVTsB9YzrRaiikmz68K5HWdt9MqULxPQPo+ppZ0LRqkOae466+UKRY0JxWtdrM
# c5vHlHZfnqjawj/RsM2S6Q6fa9T9CnY1Nz7DYBG3yZJyCPFsrgU05s9ljqfsSptp
# FdUh9R4ce+L71SWDLM2x/1MFLLHAMbXsEp8KloEGtaDULnxtfS2tYhfuKGqRXoEf
# DPAMnIdTvQPh3GHQ4SjkkBARHL0MY75alhGTKHWjC2aLVOo8obKIBk8hfnFDUf/E
# yVw4uTCCB3EwggVZoAMCAQICEzMAAAAVxedrngKbSZkAAAAAABUwDQYJKoZIhvcN
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
# aXRlZDEmMCQGA1UECxMdVGhhbGVzIFRTUyBFU046M0JENC00QjgwLTY5QzMxJTAj
# BgNVBAMTHE1pY3Jvc29mdCBUaW1lLVN0YW1wIFNlcnZpY2WiIwoBATAHBgUrDgMC
# GgMVACGlCa3ketyeuey7bJNpWkMuiCcQoIGDMIGApH4wfDELMAkGA1UEBhMCVVMx
# EzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoT
# FU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUt
# U3RhbXAgUENBIDIwMTAwDQYJKoZIhvcNAQEFBQACBQDmkY8xMCIYDzIwMjIwODAx
# MDczMDU3WhgPMjAyMjA4MDIwNzMwNTdaMHQwOgYKKwYBBAGEWQoEATEsMCowCgIF
# AOaRjzECAQAwBwIBAAICJRswBwIBAAICEXMwCgIFAOaS4LECAQAwNgYKKwYBBAGE
# WQoEAjEoMCYwDAYKKwYBBAGEWQoDAqAKMAgCAQACAwehIKEKMAgCAQACAwGGoDAN
# BgkqhkiG9w0BAQUFAAOBgQArnk4S9bEdxCdv6lvAqDJLnushxbjSdiB7sVOCFegm
# 1hIyiOlgngN4YIZy5wYXFTnbUcThdirf/aWO9Kgq7ym54onCUb8XY9R6vBbJz4h4
# 5T/wMIKNVGo2pIyBEGyYLgmsXSYP5pIvgzFhbGvfTynStAvFB//Ows/cSog4V5qO
# JTGCBA0wggQJAgEBMIGTMHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5n
# dG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9y
# YXRpb24xJjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEwAhMz
# AAABibS/hjCEHEuPAAEAAAGJMA0GCWCGSAFlAwQCAQUAoIIBSjAaBgkqhkiG9w0B
# CQMxDQYLKoZIhvcNAQkQAQQwLwYJKoZIhvcNAQkEMSIEIHRzuxsd0yQASDvk+abL
# zEFM4quPLbXpJsdApziHm0fFMIH6BgsqhkiG9w0BCRACLzGB6jCB5zCB5DCBvQQg
# ZndHMdxQV1VsbpWHOTHqWEycvcRJm7cY69l/UmT8j0UwgZgwgYCkfjB8MQswCQYD
# VQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEe
# MBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSYwJAYDVQQDEx1NaWNyb3Nv
# ZnQgVGltZS1TdGFtcCBQQ0EgMjAxMAITMwAAAYm0v4YwhBxLjwABAAABiTAiBCAk
# t45JlrVvo3nFtAGQW8QKtuen+cccumsnztg/aYVKETANBgkqhkiG9w0BAQsFAASC
# AgC6j2YGxgke3iae33oSRx0x4Y2eCsrzIkymptNad6YSa8x+BxZue52o1anNnLoz
# PnIjhiUpKm0mhNAOAlyrS0R6f1FULeXIjPWqU6VCAXPcIOeknxM+nJkJyw5l1aH5
# swfVHKi4/CM3/f6npn0TgivuILnHkjuYaO4cCV+e4Rgal9oH3wX8/eT9CFXtpcVW
# SEjc7pJHyfL6tbaD3XEvMwTs/q1ByV2FWdduTcsorsIMBim/NvwRl5Q0s7X+8Lmf
# Q08y8bbfjy30y5HfYxmxcgzolzwp2eKR31MvNWE3YwKTr3pFgfHEAQuJI2kVkUxB
# Xsvgeyvio9xdy4+RaT7iUNkPk/EsP9fYZkJllQK+KjGiea4b9EjsZQhHqi+mSuGm
# BysdBBAbybFsN9BJXcQTGApenXtE05A3qZ3GV79hBgwJeLX55bE0VCTty4WwzI+h
# VoE5GF4DWFlifLYC1/Z0e/oEboyK+pDHsVxqP2gPGtvY6Kh8eWcGKbaDOA+SqyZ6
# E/FV3j7ERQoafuFisxp0FOzuqgNXFt2f8lb1Vnsa2SFpGXlsCWjtZxXfQlq+JZqW
# 5JOb5jzpebjUlLm6zVyiygPM0WKjjCPvTj5n1YTL801Y2v9udxrAnSZkRRVBOBJ3
# jsucnE3gz5ZToguevWMPO9NicFOOi/q9TukQUNCEe/tMWg==
# SIG # End signature block
