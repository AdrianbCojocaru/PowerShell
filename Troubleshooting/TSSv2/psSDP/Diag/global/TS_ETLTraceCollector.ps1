#************************************************
# TS_ETLTraceCollector.ps1
# Version 1.2.2
# Date: 10-31-2010
# Author: Andre Teixeira - andret@microsoft.com
# Description: This script is a universal ETL Trace collector. Caller has to inform a Data Collector Set XML for the ETL and additional data. 
#              Script will collect ETL information after asking customer to reproduce the issue.
#************************************************

PARAM(	[string] $DataCollectorSetXMLName = "", 
		$OutputFileName,
		[string] $ComponentName = "Component",
		$FileDescription = "ETL trace file", 
		$SectionDescription = "ETL Traces", 
		[string] $ReproTitle = "",
		[string] $ReproDescription = "",
		[string] $StopTitle = "",
		[string] $StopDescription = "",
		[switch] $DoNotPromptUser,
		[switch] $StartTrace,
		[switch] $StopTrace,
		$DataCollectorSetObject = $null,
		[switch] $DisableRootCauseDetected,
		[string] $DestinationFolder = ($PWD.Path + "\Perfmon")
		)

Import-LocalizedData -BindingVariable EvtTraceStrings
Write-DiagProgress -Activity ($EvtTraceStrings.ID_ETLTraceEnable -replace "%Component%", $ComponentName) -Status ($EvtTraceStrings.ID_ETLTraceEnableDesc -replace "%Component%", $ComponentName)

if ($ReproTitle -eq "")
{
	$ReproTitle = $EvtTraceStrings.ID_ETLTraceReproTitle
}
if ($ReproDescription -eq "")
{
	$ReproDescription = $EvtTraceStrings.ID_ETLTraceReproDescription
}
if ($StopTitle -eq "")
{
	$StopTitle = $EvtTraceStrings.ID_ETLTraceStopTitle
}
if ($StopDescription -eq "")
{
	$StopDescription = $EvtTraceStrings.ID_ETLTraceStopDescription
}


Function StartDataCollectorSetFromXML(
	[string] $PathToXML,
	[string] $DestinationFolder)
{
	if (Test-Path $PathToXML) 
	{
	
		trap [Exception] 
		{
			WriteTo-ErrorDebugReport -ErrorRecord $_ -ScriptErrorText ("Starting Data Collector Set $PathToXML")
			if ($null -ne $_.Exception) {"[Exception]: $($_.Exception.Message)"}			
			continue
		}

		$Error.Clear()
		
		"Obtaining DSC XML Content..." | WriteTo-StdOut -ShortFormat
		[xml] $DataCollectorXML = Get-Content $PathToXML
		$DataCollectorXML.DataCollectorSet.RootPath = $DestinationFolder
		"Root Path: $DestinationFolder" | WriteTo-StdOut -ShortFormat
		if ($OutputFileName -is [array])
		{
			$X = 0
			foreach ($TraceCollectorSet in $DataCollectorXML.DataCollectorSet.TraceDataCollector)
			{
				if ($TraceCollectorSet.FileName -ne "NtKernel")
				{
					if ($X -lt $OutputFileName.Length)
					{
						$FileName = $OutputFileName[$X]
						$TraceCollectorSet.FileName = $FileName
						$CollectionName = $TraceCollectorSet.Name
						$SectionName = $TraceCollectorSet.Name
						"Setting Output to TraceDataCollector [$CollectionName] to [$FileName]" | WriteTo-StdOut -ShortFormat
					}
					else
					{
						"Error: OutputFileName contains less members than TraceCollectorSet sections." | WriteTo-StdOut -ShortFormat
					}
					$X++
				}
			}
		}
		else
		{
			foreach ($TraceCollectorSet in $DataCollectorXML.DataCollectorSet.TraceDataCollector)
			{
				if ($TraceCollectorSet.FileName -ne "NtKernel")
				{
					$TraceCollectorSet.FileName = $OutputFileName
					"Setting Output to [$OutputFileName]" | WriteTo-StdOut -ShortFormat
				}
			}
		}
		$Name = $DataCollectorXML.DataCollectorSet.Name
		"DSC Name: $Name" | WriteTo-StdOut -ShortFormat
		"Creating PLA Object and Setting Up DataCollector" | WriteTo-StdOut -ShortFormat
		
		$DataCollectorSet = New-Object -ComObject PLA.DatacollectorSet
		
		$DataCollectorSet.SetXml($DataCollectorXML.get_InnerXml()) | WriteTo-StdOut -ShortFormat

		$DataCollectorSet.Commit($Name, $null , 0x0003) | WriteTo-StdOut -ShortFormat
		
		$DataCollectorSet.Query($Name,$null) | WriteTo-StdOut -ShortFormat

		"Starting DCS" | WriteTo-StdOut -ShortFormat
		$DataCollectorSet.start($false) | WriteTo-StdOut -ShortFormat
		
		If (($null -ne $DataCollectorSet) -and ($null -ne $DataCollectorSet.status))
		{
			if ($DataCollectorSet.Status -eq 0)
			{
				"DCS was not started. Trying again in 5 seconds"  | WriteTo-StdOut -ShortFormat
				#Timming issue. Wait 5 seconds and try again
				Start-Sleep -Seconds 5
				if ($DataCollectorSet.Status -eq 0)
				{
					$DataCollectorSet.start($false)
				}
				
				if ($DataCollectorSet.Status -ne 1)
				{
					"DCS Current Status is " + $DataCollectorSet.Status | WriteTo-StdOut -ShortFormat
				}
				else
				{
					"DCS is now started"  | WriteTo-StdOut -ShortFormat
				}
			}
			return $DataCollectorSet
		} 
		else 
		{
			"An error has ocurred to create the following Data Collector Set:"  | WriteTo-StdOut -ShortFormat
			"Name: $Name"  | WriteTo-StdOut -ShortFormat
			"XML: $PathToXML"  | WriteTo-StdOut -ShortFormat
		}

	} else {
		$PathToXML + " does not exist. Exiting..." | WriteTo-StdOut -ShortFormat
	}
}

Function StopDataCollectorSet ($DataCollectorSet)
{
	trap [Exception] 
	{
		WriteTo-ErrorDebugReport -ErrorRecord $_ -ScriptErrorText ("Stopping DataCollectorSet")
		continue
	}

	"Stopping Data Collector Set. Current Status is: " + $DataCollectorSet.Status | writeto-stdout -ShortFormat

	if ($null -ne $DataCollectorSet.Status)
	{
		trap [Exception] 
		{
			WriteTo-ErrorDebugReport -ErrorRecord $_ -ScriptErrorText ("Stopping DataCollectorSet")
			continue
		}
		
		$retries = 0
		do 
		{
			trap [Exception] 
			{
				continue
			}
			
			$retries++
			Start-Sleep -Milliseconds 500
			if ($DataCollectorSet.Status -ne 0) 
			{
				$DataCollectorSet.Stop($false)
			}
			
		} while (($DataCollectorSet.Status -ne 0) -and ($retries -lt 900)) #Wait for up to 7.5 minutes for the report to finish
		
		if ($retries -lt 900)
		{
			"Data Collector Set was stopped. Current Status is: " + $DataCollectorSet.Status | writeto-stdout -ShortFormat
		}
		else
		{
			"Current Status of Data Collector Set is: " + $DataCollectorSet.Status | writeto-stdout -ShortFormat
		}

		$OutputLocation = $DataCollectorSet.OutputLocation
		"Deleting DataCollectorSet..." | writeto-stdout -ShortFormat
		$DataCollectorSet.Delete()
		return $OutputLocation
	}
}

Function CleanDataCollectorSetTrace 
{	
	"Diagnostic package ends unexpectedly. Stopping DataCollectorSet [ToBeDetermined]" | WriteTo-StdOut -ShortFormat
	trap [Exception] 
	{		
		continue
	}
	$DataCollectorSet = New-Object -ComObject PLA.DatacollectorSet	
	$DCSName = "ToBeDetermined"
	$DataCollectorSet.Query($DCSName,$null) | WriteTo-StdOut -ShortFormat
	"Current Status is: " + $DataCollectorSet.Status | writeto-stdout -ShortFormat
	if ($null -ne $DataCollectorSet.Status)
	{
		trap [Exception] 
		{			
			continue
		}
		
		$retries = 0
		do 
		{
			trap [Exception] 
			{
				continue
			}
			
			$retries++
			Start-Sleep -Milliseconds 500
			if ($DataCollectorSet.Status -ne 0) 
			{
				$DataCollectorSet.Stop($false)
			}
			
		} while (($DataCollectorSet.Status -ne 0) -and ($retries -lt 900)) #Wait for up to 7.5 minutes for the report to finish		

		if ($retries -lt 900)
		{
			"Data Collector Set was stopped. Current Status is: " + $DataCollectorSet.Status | writeto-stdout -ShortFormat
		}
		else
		{
			"Current Status of Data Collector Set is: " + $DataCollectorSet.Status | writeto-stdout -ShortFormat
		}
		
		$OutputLocation = $DataCollectorSet.OutputLocation
		if(Test-Path -Path $OutputLocation)
		{
			"Delete DataCollectorSet output folder [$OutputLocation]" | writeto-stdout -ShortFormat
			Remove-Item -Path $OutputLocation -Recurse -Force -Confirm:$false 
		}
		"Deleting DataCollectorSet..." | writeto-stdout -ShortFormat
		$DataCollectorSet.Delete()
	}
}

if ($DataCollectorSetXMLName.Length -gt 0)
{
	if (Test-Path -Path $DataCollectorSetXMLName)
	{
		$DataCollectorSetXMLName = [System.IO.Path]::GetFullPath($DataCollectorSetXMLName)
	}	
	
	
	if ((Test-Path ($DestinationFolder)) -ne $true) 
	{ 
		$null = mkdir $DestinationFolder 
	} 

	if (-not ($DoNotPromptUser.IsPresent))
	{
		$Results = Get-DiagInput -Id "ETLTraceCollectorStopper" -Parameter @{"Title"=$ReproTitle; "Description"=$ReproDescription}
	}

	if (-not ($StopTrace.IsPresent))
	{
		$TraceTimeStarted = Get-Date

		$DataCollectorSet = StartDataCollectorSetFromXML -DestinationFolder $DestinationFolder -PathToXML $DataCollectorSetXMLName
		if (($null -ne $DataCollectorSet) -and (-not ($DataCollectorSet -is [System.__ComObject])))
		{
			#Probably an array
			$ArrayDCS = $DataCollectorSet
			foreach ($Member in $ArrayDCS)
			{
				if ($Member -is [System.__ComObject])
				{
					$DataCollectorSet = $Member
				}
			}
		}	
	}
}
if ($null -ne $DataCollectorSetObject)
{
	$DataCollectorSet = $DataCollectorSetObject 
}

if ($DataCollectorSet -is [System.__ComObject])
{	
	$DataCollectorSetName = $DataCollectorSet.Name
	
	if ((-not ($StopTrace.IsPresent)) -and ($null -ne $DataCollectorSet))
	{
		"Starting Monitoring Session for DCS $DataCollectorSetName" | WriteTo-StdOut -ShortFormat
		.\TS_MonitorDiagExecution.ps1 -SessionName "PLACollector_$($DataCollectorSetName)" -ScriptBlockToExecute (($Function:CleanDataCollectorSetTrace) -Replace ("ToBeDetermined", $DataCollectorSetName)) 
	}
	elseif ($null -ne $DataCollectorSet)
	{
		"[Warning] DataCollectorSet [$DataCollectorSetName] is null" | WriteTo-StdOut -ShortFormat
	}
	
	if (-not ($DoNotPromptUser.IsPresent))
	{
		$Results = Get-DiagInput -Id "ETLTraceCollectorStopper" -Parameter @{"Title"=$StopTitle; "Description"=$StopDescription}
		$TraceTimeDisplay = (GetAgeDescription(New-TimeSpan $TraceTimeStarted))
	}
	
	Write-DiagProgress -Activity ($EvtTraceStrings.ID_ETLTraceStopping -replace "%Component%", $ComponentName) -Status ($EvtTraceStrings.ID_ETLTraceStoppingDesc -replace "%Component%", $ComponentName)

	if (($StopTrace.IsPresent) -or (($StopTrace.IsPresent -eq $false) -and ($StartTrace.IsPresent -eq $false)))
	{
		$OutputFolder = StopDataCollectorSet $DataCollectorSet
		#end the TS_MonitorDiagExecution
		.\TS_MonitorDiagExecution.ps1 -EndMonitoring -SessionName "PLACollector_$($DataCollectorSetName)"
		Write-DiagProgress -Activity ($EvtTraceStrings.ID_ETLTraceCollecting -replace "%Component%", $ComponentName) -Status ($EvtTraceStrings.ID_ETLTraceCollectingDesc -replace "%Component%", $ComponentName)

		if ($OutputFileName -is [array])
		{
			$X = 0
			ForEach ($OutputFile in $OutputFileName)
			{
				if ($FileDescription -is [Array])
				{
					$FDescription = $FileDescription[$x]
				}
				else
				{
					$FDescription = $FileDescription
				}
				if ($sectionDescription -is [Array])
				{
					$SDescription = $sectionDescription[$x]
				}
				else
				{
					$SDescription = $sectionDescription
				}
				CollectFiles -filesToCollect ([System.IO.Path]::Combine($OutputFolder, $OutputFile)) -fileDescription $FDescription -sectionDescription $SDescription
				$X++
			}
		}
		else
		{
			CollectFiles -filesToCollect ([System.IO.Path]::Combine($OutputFolder, $OutputFileName)) -fileDescription $FileDescription -sectionDescription $sectionDescription
		}
			
		if (-not ($DisableRootCauseDetected.IsPresent))
		{
			if (Test-Path -Path ([System.IO.Path]::Combine($OutputFolder, $OutputFileName))) 
			{

				$XMLFileName = "..\ETLCollected.XML"

				$MSG_Summary = new-object PSObject

				add-member -inputobject $MSG_Summary -membertype noteproperty -name "More Information" -value ("A $TraceTimeDisplay $ComponentName ETL trace was collected for and saved to <a href= `"`#" + $OutputFileName + "`">$OutputFileName</a>.")
				
				($MSG_Summary | ConvertTo-Xml2).Save($XMLFileName)

				Update-DiagRootCause -Id RC_ETLCollected -Detected $true -Parameter @{"XMLFileName"=$XMLFileName; "Verbosity"="Informational"; "SectionTitle"="Additional Information"; "Component"=$ComponentName}
			}
		}
	}
}
else
{
	"An error has occurred when setting Data Collector Set. Aborting" | WriteTo-StdOut -ShortFormat
	if ($null -ne $DataCollectorSet) 
	{
		"DataCollectorSet Type Information: " | WriteTo-StdOut -ShortFormat
		$DataCollectorSet | Get-Member | Out-String | WriteTo-StdOut -ShortFormat
		"DataCollectorSet: " | WriteTo-StdOut -ShortFormat
		$DataCollectorSet | WriteTo-StdOut -ShortFormat
	}
	else
	{
		"DataCollectorSet is Null" | WriteTo-StdOut -ShortFormat
	}
}

if ($null -ne $DataCollectorSet.Status)
{
	return $DataCollectorSet
}


# SIG # Begin signature block
# MIInmAYJKoZIhvcNAQcCoIIniTCCJ4UCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCDfBlLe7wJX6kHt
# /JpP7vWWzqe+ft2k8ZYINLgC6cynGaCCDXYwggX0MIID3KADAgECAhMzAAACy7d1
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
# /Xmfwb1tbWrJUnMTDXpQzTGCGXgwghl0AgEBMIGVMH4xCzAJBgNVBAYTAlVTMRMw
# EQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVN
# aWNyb3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMTH01pY3Jvc29mdCBDb2RlIFNp
# Z25pbmcgUENBIDIwMTECEzMAAALLt3U5+wJxQjYAAAAAAsswDQYJYIZIAWUDBAIB
# BQCggbAwGQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQwHAYKKwYBBAGCNwIBCzEO
# MAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIMloGUdYFE9NwMYejZBkzyGX
# vsVnzsQmaII3rJ+KGTitMEQGCisGAQQBgjcCAQwxNjA0oBSAEgBNAGkAYwByAG8A
# cwBvAGYAdKEcgBpodHRwczovL3d3dy5taWNyb3NvZnQuY29tIDANBgkqhkiG9w0B
# AQEFAASCAQBBXt7E9cuOtvUjQzrRaBeI3oHCQFd0GuURI1QdfVdh+flm32ljlEQD
# g19cr6XWRG7pnnue6A6kx7vbwaF6uM4vcGbMNqZRFQS9IVQlTwFs6V6s5fftWtLE
# jMKFG3q+hP14OzvwMtS/nr0QPS7GZuS1QZljGaT19GgbUlmIqdP5UOUf/oLAdEGh
# Towrbjf9UQXU1cxZAI8Gc0+x3Pp5wDTeBYkOZsbNVtSGcfZhx2OGkoIohfPU3qnj
# rVHZt5yK9An1sbyKqSdNZZcvrvg+DInzS2g0cj1Nlb+hK5E7hT8hGKd1+zTYEjPh
# aXs5Pf8N7iKLW2Dq8sJx/rMO+vl98GcCoYIXADCCFvwGCisGAQQBgjcDAwExghbs
# MIIW6AYJKoZIhvcNAQcCoIIW2TCCFtUCAQMxDzANBglghkgBZQMEAgEFADCCAVEG
# CyqGSIb3DQEJEAEEoIIBQASCATwwggE4AgEBBgorBgEEAYRZCgMBMDEwDQYJYIZI
# AWUDBAIBBQAEIJEWslIYx3qE1W/9vnL4duyTXUmJBWr3EMVlH+O787glAgZi2AXX
# ov4YEzIwMjIwODAxMDgwMTE1Ljg3N1owBIACAfSggdCkgc0wgcoxCzAJBgNVBAYT
# AlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYD
# VQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJTAjBgNVBAsTHE1pY3Jvc29mdCBB
# bWVyaWNhIE9wZXJhdGlvbnMxJjAkBgNVBAsTHVRoYWxlcyBUU1MgRVNOOjhBODIt
# RTM0Ri05RERBMSUwIwYDVQQDExxNaWNyb3NvZnQgVGltZS1TdGFtcCBTZXJ2aWNl
# oIIRVzCCBwwwggT0oAMCAQICEzMAAAGZyI+vrbZ9vosAAQAAAZkwDQYJKoZIhvcN
# AQELBQAwfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNV
# BAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQG
# A1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTAwHhcNMjExMjAyMTkw
# NTE2WhcNMjMwMjI4MTkwNTE2WjCByjELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldh
# c2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBD
# b3Jwb3JhdGlvbjElMCMGA1UECxMcTWljcm9zb2Z0IEFtZXJpY2EgT3BlcmF0aW9u
# czEmMCQGA1UECxMdVGhhbGVzIFRTUyBFU046OEE4Mi1FMzRGLTlEREExJTAjBgNV
# BAMTHE1pY3Jvc29mdCBUaW1lLVN0YW1wIFNlcnZpY2UwggIiMA0GCSqGSIb3DQEB
# AQUAA4ICDwAwggIKAoICAQC4E/lXXKMsy9rVa2a8bRb0Ar/Pj4+bKiAgMgKayvCM
# Fn3ddGof8eWFgJWp5JdKjWjrnmW1r9tHpcP2kFpjXp2Udrj55jt5NYi1MERcoIo+
# E29XuCwFAMJftGdvsWea/OTQPIFsZEWqEteXdRncyVwct5xFzBIC1JWCdmfc7R59
# RMIyvgWjIz8356mweowkOstN1fe53KIJ8flrYILIQWsNRMOT3znAGwIb9kyL54C6
# jZjFxOSusGYmVQ+Gr/qZQELw1ipx9s5jNP1LSpOpfTEBFu+y9KLNBmMBARkSPpTF
# kGEyGSwGGgSdOi6BU6FPK+6urZ830jrRemK4JkIJ9tQhlGcIhAjhcqZStn+38lRj
# VvrfbBI5EpI2NwlVIK2ibGW7sWeTAz/yNPNISUbQhGAJse/OgGj/1qz/Ha9mqfYZ
# 8BHchNxn08nWkqyrjrKicQyxuD8mCatTrVSbOJYfQyZdHR9a4vgyGeZEXBYQNAlI
# uB37QCOAgs/VeDU8M4dc/IlrTyC0uV1SS4Gk8zV+5X5eRu+XORN8FWqzI6k/9y6c
# WwOWMK6aUN1XqLcaF/sm9rX84eKW2lhDc3C31WLjp8UOfOHZfPuyy54xfilnhhCP
# y4QKJ9jggoqqeeEhCEfgDYjy+PByV/e5HDB2xHdtlL93wltAkI3aCxo84kVPBCa0
# OwIDAQABo4IBNjCCATIwHQYDVR0OBBYEFI26Vrg+nGWvrvIh0dQPEonENR0QMB8G
# A1UdIwQYMBaAFJ+nFV0AXmJdg/Tl0mWnG1M1GelyMF8GA1UdHwRYMFYwVKBSoFCG
# Tmh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2lvcHMvY3JsL01pY3Jvc29mdCUy
# MFRpbWUtU3RhbXAlMjBQQ0ElMjAyMDEwKDEpLmNybDBsBggrBgEFBQcBAQRgMF4w
# XAYIKwYBBQUHMAKGUGh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2lvcHMvY2Vy
# dHMvTWljcm9zb2Z0JTIwVGltZS1TdGFtcCUyMFBDQSUyMDIwMTAoMSkuY3J0MAwG
# A1UdEwEB/wQCMAAwEwYDVR0lBAwwCgYIKwYBBQUHAwgwDQYJKoZIhvcNAQELBQAD
# ggIBAHGzWh29ibBNro3ns8E3EOHGsLB1Gzk90SFYUKBilIu4jDbR7qbvXNd8nnl/
# z5D9LKgw3T81jqy5tMiWp+p4jYBBk3PRx1ySqLUfhF5ZMWolRzW+cQZGXV38iSmd
# AUG0CpR5x1rMdPIrTczVUFsOYGqmkoUQ/dRiVL4iAXJLCNTj4x3YwIQcCPt0ijJV
# inPIMAYzA8f99BbeiskyI0BHGAd0kGUX2I2/puYnlyS8toBnANjh21xgvEuaZ2dv
# RqvWk/i1XIlO67au/XCeMTvXhPOIUmq80U32Tifw3SSiBKTyir7moWH1i7H2q5QA
# nrBxuyy//ZsDfARDV/Atmj5jr6ATfRHDdUanQpeoBS+iylNU6RARu8g+TMCu/Znd
# Zmrs9w+8galUIGg+GmlNk07fXJ58Oc+qFqgNAsNkMi+dSzKkWGA4/klJFn0XichX
# L8+t7KOayXKGzQja6CdtCjisnyS8hbv4PKhaeMtf68wJWKKOs0tt2AJfYC5vSbH9
# ck8BGj2e/yQXEZEu88L5/fHK5XUk/IKXx3zaLkxXTSZ43Ea/WKXVBzMasHZ3Pmny
# 0moEekAXx1UhLNNYv4Vum33VirxSB6r/GKQxFSHu7yFfrWQpYyyDH119TmhAedS8
# T1VabqdtO5ZP2E14TK82Vyxy3xEPelOo4dRIlhm7XY6k9B68MIIHcTCCBVmgAwIB
# AgITMwAAABXF52ueAptJmQAAAAAAFTANBgkqhkiG9w0BAQsFADCBiDELMAkGA1UE
# BhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAc
# BgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEyMDAGA1UEAxMpTWljcm9zb2Z0
# IFJvb3QgQ2VydGlmaWNhdGUgQXV0aG9yaXR5IDIwMTAwHhcNMjEwOTMwMTgyMjI1
# WhcNMzAwOTMwMTgzMjI1WjB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGlu
# Z3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBv
# cmF0aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAxMDCC
# AiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAOThpkzntHIhC3miy9ckeb0O
# 1YLT/e6cBwfSqWxOdcjKNVf2AX9sSuDivbk+F2Az/1xPx2b3lVNxWuJ+Slr+uDZn
# hUYjDLWNE893MsAQGOhgfWpSg0S3po5GawcU88V29YZQ3MFEyHFcUTE3oAo4bo3t
# 1w/YJlN8OWECesSq/XJprx2rrPY2vjUmZNqYO7oaezOtgFt+jBAcnVL+tuhiJdxq
# D89d9P6OU8/W7IVWTe/dvI2k45GPsjksUZzpcGkNyjYtcI4xyDUoveO0hyTD4MmP
# frVUj9z6BVWYbWg7mka97aSueik3rMvrg0XnRm7KMtXAhjBcTyziYrLNueKNiOSW
# rAFKu75xqRdbZ2De+JKRHh09/SDPc31BmkZ1zcRfNN0Sidb9pSB9fvzZnkXftnIv
# 231fgLrbqn427DZM9ituqBJR6L8FA6PRc6ZNN3SUHDSCD/AQ8rdHGO2n6Jl8P0zb
# r17C89XYcz1DTsEzOUyOArxCaC4Q6oRRRuLRvWoYWmEBc8pnol7XKHYC4jMYcten
# IPDC+hIK12NvDMk2ZItboKaDIV1fMHSRlJTYuVD5C4lh8zYGNRiER9vcG9H9stQc
# xWv2XFJRXRLbJbqvUAV6bMURHXLvjflSxIUXk8A8FdsaN8cIFRg/eKtFtvUeh17a
# j54WcmnGrnu3tz5q4i6tAgMBAAGjggHdMIIB2TASBgkrBgEEAYI3FQEEBQIDAQAB
# MCMGCSsGAQQBgjcVAgQWBBQqp1L+ZMSavoKRPEY1Kc8Q/y8E7jAdBgNVHQ4EFgQU
# n6cVXQBeYl2D9OXSZacbUzUZ6XIwXAYDVR0gBFUwUzBRBgwrBgEEAYI3TIN9AQEw
# QTA/BggrBgEFBQcCARYzaHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3BraW9wcy9E
# b2NzL1JlcG9zaXRvcnkuaHRtMBMGA1UdJQQMMAoGCCsGAQUFBwMIMBkGCSsGAQQB
# gjcUAgQMHgoAUwB1AGIAQwBBMAsGA1UdDwQEAwIBhjAPBgNVHRMBAf8EBTADAQH/
# MB8GA1UdIwQYMBaAFNX2VsuP6KJcYmjRPZSQW9fOmhjEMFYGA1UdHwRPME0wS6BJ
# oEeGRWh0dHA6Ly9jcmwubWljcm9zb2Z0LmNvbS9wa2kvY3JsL3Byb2R1Y3RzL01p
# Y1Jvb0NlckF1dF8yMDEwLTA2LTIzLmNybDBaBggrBgEFBQcBAQROMEwwSgYIKwYB
# BQUHMAKGPmh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2kvY2VydHMvTWljUm9v
# Q2VyQXV0XzIwMTAtMDYtMjMuY3J0MA0GCSqGSIb3DQEBCwUAA4ICAQCdVX38Kq3h
# LB9nATEkW+Geckv8qW/qXBS2Pk5HZHixBpOXPTEztTnXwnE2P9pkbHzQdTltuw8x
# 5MKP+2zRoZQYIu7pZmc6U03dmLq2HnjYNi6cqYJWAAOwBb6J6Gngugnue99qb74p
# y27YP0h1AdkY3m2CDPVtI1TkeFN1JFe53Z/zjj3G82jfZfakVqr3lbYoVSfQJL1A
# oL8ZthISEV09J+BAljis9/kpicO8F7BUhUKz/AyeixmJ5/ALaoHCgRlCGVJ1ijbC
# HcNhcy4sa3tuPywJeBTpkbKpW99Jo3QMvOyRgNI95ko+ZjtPu4b6MhrZlvSP9pEB
# 9s7GdP32THJvEKt1MMU0sHrYUP4KWN1APMdUbZ1jdEgssU5HLcEUBHG/ZPkkvnNt
# yo4JvbMBV0lUZNlz138eW0QBjloZkWsNn6Qo3GcZKCS6OEuabvshVGtqRRFHqfG3
# rsjoiV5PndLQTHa1V1QJsWkBRH58oWFsc/4Ku+xBZj1p/cvBQUl+fpO+y/g75LcV
# v7TOPqUxUYS8vwLBgqJ7Fx0ViY1w/ue10CgaiQuPNtq6TPmb/wrpNPgkNWcr4A24
# 5oyZ1uEi6vAnQj0llOZ0dFtq0Z4+7X6gMTN9vMvpe784cETRkPHIqzqKOghif9lw
# Y1NNje6CbaUFEMFxBmoQtB1VM1izoXBm8qGCAs4wggI3AgEBMIH4oYHQpIHNMIHK
# MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVk
# bW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSUwIwYDVQQLExxN
# aWNyb3NvZnQgQW1lcmljYSBPcGVyYXRpb25zMSYwJAYDVQQLEx1UaGFsZXMgVFNT
# IEVTTjo4QTgyLUUzNEYtOUREQTElMCMGA1UEAxMcTWljcm9zb2Z0IFRpbWUtU3Rh
# bXAgU2VydmljZaIjCgEBMAcGBSsOAwIaAxUAku/zYujnqapN6BJ9MJ5jtgDrlOug
# gYMwgYCkfjB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4G
# A1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSYw
# JAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAxMDANBgkqhkiG9w0B
# AQUFAAIFAOaRrQowIhgPMjAyMjA4MDEwOTM4MThaGA8yMDIyMDgwMjA5MzgxOFow
# dzA9BgorBgEEAYRZCgQBMS8wLTAKAgUA5pGtCgIBADAKAgEAAgIHcwIB/zAHAgEA
# AgIRsTAKAgUA5pL+igIBADA2BgorBgEEAYRZCgQCMSgwJjAMBgorBgEEAYRZCgMC
# oAowCAIBAAIDB6EgoQowCAIBAAIDAYagMA0GCSqGSIb3DQEBBQUAA4GBAFaD7lFs
# Znrxp9nHX+qbqRngB88DiwwxUQ5Orjh03sSO5cUw1d7MarjEkp8/E+F6lQJqWX09
# QKDAs84/bUPylTn8uk3rydGWQeYWStv3idndx66Qlzym/FsLeU3WKchdqTks2wPD
# fU3hZUP/iDl2dTiGrZ3knpOkphGyqRJ0svrOMYIEDTCCBAkCAQEwgZMwfDELMAkG
# A1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQx
# HjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQGA1UEAxMdTWljcm9z
# b2Z0IFRpbWUtU3RhbXAgUENBIDIwMTACEzMAAAGZyI+vrbZ9vosAAQAAAZkwDQYJ
# YIZIAWUDBAIBBQCgggFKMBoGCSqGSIb3DQEJAzENBgsqhkiG9w0BCRABBDAvBgkq
# hkiG9w0BCQQxIgQgqB6QcYYBna6ecHxTvKiBN3z7/7XtXxWJKSymw4MzplkwgfoG
# CyqGSIb3DQEJEAIvMYHqMIHnMIHkMIG9BCBmfWn58qKN7WWpBTYOrUO1BSCSnKPL
# C/G7wCOIc2JsfjCBmDCBgKR+MHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNo
# aW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29y
# cG9yYXRpb24xJjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEw
# AhMzAAABmciPr622fb6LAAEAAAGZMCIEIDeboswsfoQpLJHcPklawfz4JSyTO9DY
# TKSjMhqRCWPSMA0GCSqGSIb3DQEBCwUABIICACBCL9L1USV31tmW/EKxAIUI5BAC
# LaFXSX9+X+0RFOKs7xxokOYMWfIVZmU0ahHLC4r+XLmIIZeFD5quDSurFmhYgnMb
# 4ZXn8kv8DzVoBZm/jlNfd65qfyLcGJ/qW+xhSTvJOqzEjrSxswEW4rxg8x/DFrgi
# /xUXcTmmgp5zQ4Qx93aWqXMntGgBQ5M2Yl5j30HCvBgdvX6w6/+5vAFPfW9Zc6bK
# sA5vMF2gU4bR9PSvB+QCCZXnNalLT9A7lMtQJFY9jJaawAi/a2QsQ6blKFfqG8vA
# ABkkIWwCNI+9hHhJMMpx4CFU2ae3vAj6ZnSXXKTXEaRhlVSKKhaI4gqmQ1X3vDWm
# m+4zTr/9UbFsjcBC0SvyGf4e+L+UpbjaQ9FqartTkdOq46uiUvrlReSkY0C16gsD
# 57M4AubGSCRfk1ny9b0lDIRAFOZ/ZAA2Qd1H764kUQjYgX+b1OMrYlbiQtSbWNGI
# oqqMUtrypN+Tk8qUEMV5FGyKjRqLOnC3jhqiNWsjghtGTbSZzfVQtvrxjKijA4WO
# pzTT0Rn0Kk4dhUu8P7e/59lF9ERHENoqTXNTricEUDriniEeS3gaWYiYNXuIBhM+
# ac8mR1Xee0SKLiZ5n6/FXIXTAhMDDPZdOpE6poco/ZsQqX6QoX25+KeJ87KJRpRO
# XHmThJ6JEXBXW04K
# SIG # End signature block
