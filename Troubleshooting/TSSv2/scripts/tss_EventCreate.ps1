<# Filename: tss_EventCreate.ps1 [-EventID -EvtLogName] [-Computername]
:: Purpose:  create an Event log entry in [EvtLogName] with [Event ID]
::           the tss.cmd script has a switch to stop data collection upon such event.
:: Example: tss_EventCreate.cmd 999 System
::
::  Copyright ^(C^) Microsoft. All rights reserved.
::  THIS CODE IS PROVIDED *AS IS* WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESS OR IMPLIED, INCLUDING ANY
::  IMPLIED WARRANTIES OF FITNESS FOR A PARTICULAR PURPOSE, MERCHANTABILITY, OR NON-INFRINGEMENT.
::
:: Last-Update by waltere: 2022-10-06

The tss_EventCreate.cmd can only write event ID 0 - 1000 using EVENTCREATE.exe

:: in Powershell 
:: 1.  do this once to register a new Event Source ( not needed for writing events with a known Source: 
   New-EventLog –LogName "System" –Source 'TSS'
:: 2.  Write-EventLog -LogName "System" -Source "TSS" -EventID 15004 -EntryType Information -Message "TSS added this EventID as stop trigger." -Category 1 -RawData 10,20 -ComputerName $Env:Computername
:: in CMD script you would invoke: Powershell "Write-EventLog -LogName 'System' -Source 'TSS' -EventID 999 -EntryType Information -Message 'TSS added this EventID as stop trigger.' -Category 1 -RawData 10,20 -ComputerName $Env:Computername"

:: for testing it is sufficient to specify an exiting "Source", just look up an existing eventlog entry
example:
  Write-EventLog -LogName "System" -Source "Outlook" -EventID 59 -EntryType Information -Message "Test this EventID as stop trigger." -Category 1 -RawData 10,20 -ComputerName $Env:Computername
#>

<#
.SYNOPSIS
	Write any EventID into any Eventlog file, i.e. for testing a TSSv2.ps1 -WaitEvent Evt:<ID> trigger
	see Get-Help Write-EventLog -detailed
	for registering an own source, use: New-EventLog –LogName "System" –Source 'TSS'

.DESCRIPTION  
	Script will write any EventID into any Eventlog file, i.e. for testing a TSSv2.ps1 -WaitEvent Evt:<ID> trigger
	You can also register a new event Source 'TSS', but this source will be bound to the eventlog name. so if you change the eventlog name you need to specify a new source-name, or use Unregister-Event.
	Please look up any existing event in the <eventlog>.evtx file you are interested in and remember the ID and Source

.NOTES

.PARAMETER LogName
 	Specify the name of the Windows Event Log, default = "System"
	Default is current folder
.PARAMETER Source
	The Event Source, which is known to exist in the given EventLog, default = "Outlook"
.PARAMETER EntryType
	The type of Event, default = "Warning"
.PARAMETER Message
	The Event message you want to log, example "Testing this EventID as stop trigger. Event-ID was sent by computer $Env:Computername"
.PARAMETER Computername
	Which computer do you want to write the eventlog, default = $Env:Computername	
.PARAMETER EventID
	default EventID = 999, because TSS listens always to EventID 999 in addition to other IDs specified in trigger Stop:Evt:<ID>
	
.PARAMETER UseExitCode
	 This switch will cause the script to close after the error is logged if an error occurs.
	 It is used to pass the error number back to the task scheduler or CMD script.

.EXAMPLE
	Write-EventLog -LogName "System" -Source "Outlook" -EventID 59 -EntryType Information -Message "Test this EventID as stop trigger." -Category 1 -RawData 10,20 -ComputerName $Env:Computername
	Example 1: will  write the EventID 59 into local or remote computers "System" Eventlog with the given informational message
#>

param(
	[string]$LogName 	= 'System',								# Application","System",""
	[string]$Source 	= "EventLog",							# Source module, which is known to exist in the given EventLog
	[string]$EntryType 	= "Warning",							# "Information","Warning","Error"
	[string]$Computername = "$Env:Computername",				# Remote Computername
	[string]$Username 	= "$Env:USERDOMAIN\$Env:Username",		# (domain) user who has permission to write into the remote computer'S eventlog
	[string]$Message 	= "StopMe Event ID: $EventID test from script $scriptName in order to stop data collection. Event was sent by user $Username on computer $Env:Computername at $SendTimeStamp UTC",
	[int32]$EventID 	= 999,									# Event ID number
	[string]$Folderpath = $global:LogFolder,					# $(Split-Path $MyInvocation.MyCommand.Path -Parent),
	[switch]$UseExitCode = $true								# This will cause the script to bail out after the error is logged if an error occurs.
)


#region: customization section of script, logging configuration ----------------------#
	$LogFileScript 	= $Folderpath +"\"+ $ENV:ComputerName + "__WriteEventLog.txt"
	$ErrorThrown 	= $null
	$ScriptVersion	= 1.00	#2022-10-06
#endregion: customization section of script, logging configuration ------------------#
$scriptName = $MyInvocation.MyCommand.Name
$ScriptBeginTimeStamp = Get-Date
#New-EventLog –LogName "System" –Source 'TSSv2'

#region: Helper Functions -----------------------------------------------------------#
function ExitWithCode ($Ecode) {
	# set ErrorLevel to be picked up by invoking CMD script
	if ( $UseExitCode ) {
		WriteInfo "Return Code $Ecode"
		#error.clear()	# clear script errors
		exit $Ecode
		} #end UseExitCode
}
#endregion: Helper Functions

#region: MAIN
try {
	$SendTimeStamp = (Get-Date).ToUniversalTime().ToString("yyMMdd-HHmmss.fffffff")
	Write-Host "...sending Event ID $EventID Type $EntryType to $LogName eventlog on $Computername, sent by $Username at $SendTimeStamp UTC from $Env:Computername"
	#Write-EventLog -LogName $LogName -EntryType $EntryType -Source $Source -EventID $EventID -Message "This is StopMe Event ID: $EventID from script $scriptName in order to stop data collection. Event was sent by user $Username on computer $Env:Computername at $SendTimeStamp UTC" -Category 1 -ComputerName $Env:Computername
	Write-EventLog -LogName $LogName -EntryType $EntryType -Source "EventLog" -EventId $EventID -Message "This is user initiated StopMe Event ID: $EventID from script $scriptName in order to stop data collection. Event was sent by user $Env:username on computer $Env:Computername at $SendTimeStamp UTC" -Category 1 -ComputerName $Env:Computername
}
catch {
	Write-Host -ForegroundColor Red -BackgroundColor Black "An Error occured"
	Write-Host -ForegroundColor Red -BackgroundColor Black $error[0].Exception.Message
	$ErrorThrown = $true
}
finally {
	$ScriptEndTimeStamp = Get-Date
	$LogLevel = 0
	Write-Host -ForegroundColor Black -BackgroundColor Gray "`nScript $scriptName v$ScriptVersion execution finished. Duration interaction: $(New-TimeSpan -Start $ScriptBeginTimeStamp -End $ScriptEndTimeStamp)"

  if($ErrorThrown) {Throw $error[0].Exception.Message}
}
#endregion: MAIN


# SIG # Begin signature block
# MIInzAYJKoZIhvcNAQcCoIInvTCCJ7kCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCCg5UNChNP0O7Hp
# MoKpAZnBAlStH7ddp0WlL8zA+qA/eKCCDYEwggX/MIID56ADAgECAhMzAAACzI61
# lqa90clOAAAAAALMMA0GCSqGSIb3DQEBCwUAMH4xCzAJBgNVBAYTAlVTMRMwEQYD
# VQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMTH01pY3Jvc29mdCBDb2RlIFNpZ25p
# bmcgUENBIDIwMTEwHhcNMjIwNTEyMjA0NjAxWhcNMjMwNTExMjA0NjAxWjB0MQsw
# CQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9u
# ZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMR4wHAYDVQQDExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIB
# AQCiTbHs68bADvNud97NzcdP0zh0mRr4VpDv68KobjQFybVAuVgiINf9aG2zQtWK
# No6+2X2Ix65KGcBXuZyEi0oBUAAGnIe5O5q/Y0Ij0WwDyMWaVad2Te4r1Eic3HWH
# UfiiNjF0ETHKg3qa7DCyUqwsR9q5SaXuHlYCwM+m59Nl3jKnYnKLLfzhl13wImV9
# DF8N76ANkRyK6BYoc9I6hHF2MCTQYWbQ4fXgzKhgzj4zeabWgfu+ZJCiFLkogvc0
# RVb0x3DtyxMbl/3e45Eu+sn/x6EVwbJZVvtQYcmdGF1yAYht+JnNmWwAxL8MgHMz
# xEcoY1Q1JtstiY3+u3ulGMvhAgMBAAGjggF+MIIBejAfBgNVHSUEGDAWBgorBgEE
# AYI3TAgBBggrBgEFBQcDAzAdBgNVHQ4EFgQUiLhHjTKWzIqVIp+sM2rOHH11rfQw
# UAYDVR0RBEkwR6RFMEMxKTAnBgNVBAsTIE1pY3Jvc29mdCBPcGVyYXRpb25zIFB1
# ZXJ0byBSaWNvMRYwFAYDVQQFEw0yMzAwMTIrNDcwNTI5MB8GA1UdIwQYMBaAFEhu
# ZOVQBdOCqhc3NyK1bajKdQKVMFQGA1UdHwRNMEswSaBHoEWGQ2h0dHA6Ly93d3cu
# bWljcm9zb2Z0LmNvbS9wa2lvcHMvY3JsL01pY0NvZFNpZ1BDQTIwMTFfMjAxMS0w
# Ny0wOC5jcmwwYQYIKwYBBQUHAQEEVTBTMFEGCCsGAQUFBzAChkVodHRwOi8vd3d3
# Lm1pY3Jvc29mdC5jb20vcGtpb3BzL2NlcnRzL01pY0NvZFNpZ1BDQTIwMTFfMjAx
# MS0wNy0wOC5jcnQwDAYDVR0TAQH/BAIwADANBgkqhkiG9w0BAQsFAAOCAgEAeA8D
# sOAHS53MTIHYu8bbXrO6yQtRD6JfyMWeXaLu3Nc8PDnFc1efYq/F3MGx/aiwNbcs
# J2MU7BKNWTP5JQVBA2GNIeR3mScXqnOsv1XqXPvZeISDVWLaBQzceItdIwgo6B13
# vxlkkSYMvB0Dr3Yw7/W9U4Wk5K/RDOnIGvmKqKi3AwyxlV1mpefy729FKaWT7edB
# d3I4+hldMY8sdfDPjWRtJzjMjXZs41OUOwtHccPazjjC7KndzvZHx/0VWL8n0NT/
# 404vftnXKifMZkS4p2sB3oK+6kCcsyWsgS/3eYGw1Fe4MOnin1RhgrW1rHPODJTG
# AUOmW4wc3Q6KKr2zve7sMDZe9tfylonPwhk971rX8qGw6LkrGFv31IJeJSe/aUbG
# dUDPkbrABbVvPElgoj5eP3REqx5jdfkQw7tOdWkhn0jDUh2uQen9Atj3RkJyHuR0
# GUsJVMWFJdkIO/gFwzoOGlHNsmxvpANV86/1qgb1oZXdrURpzJp53MsDaBY/pxOc
# J0Cvg6uWs3kQWgKk5aBzvsX95BzdItHTpVMtVPW4q41XEvbFmUP1n6oL5rdNdrTM
# j/HXMRk1KCksax1Vxo3qv+13cCsZAaQNaIAvt5LvkshZkDZIP//0Hnq7NnWeYR3z
# 4oFiw9N2n3bb9baQWuWPswG0Dq9YT9kb+Cs4qIIwggd6MIIFYqADAgECAgphDpDS
# AAAAAAADMA0GCSqGSIb3DQEBCwUAMIGIMQswCQYDVQQGEwJVUzETMBEGA1UECBMK
# V2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0
# IENvcnBvcmF0aW9uMTIwMAYDVQQDEylNaWNyb3NvZnQgUm9vdCBDZXJ0aWZpY2F0
# ZSBBdXRob3JpdHkgMjAxMTAeFw0xMTA3MDgyMDU5MDlaFw0yNjA3MDgyMTA5MDla
# MH4xCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdS
# ZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMT
# H01pY3Jvc29mdCBDb2RlIFNpZ25pbmcgUENBIDIwMTEwggIiMA0GCSqGSIb3DQEB
# AQUAA4ICDwAwggIKAoICAQCr8PpyEBwurdhuqoIQTTS68rZYIZ9CGypr6VpQqrgG
# OBoESbp/wwwe3TdrxhLYC/A4wpkGsMg51QEUMULTiQ15ZId+lGAkbK+eSZzpaF7S
# 35tTsgosw6/ZqSuuegmv15ZZymAaBelmdugyUiYSL+erCFDPs0S3XdjELgN1q2jz
# y23zOlyhFvRGuuA4ZKxuZDV4pqBjDy3TQJP4494HDdVceaVJKecNvqATd76UPe/7
# 4ytaEB9NViiienLgEjq3SV7Y7e1DkYPZe7J7hhvZPrGMXeiJT4Qa8qEvWeSQOy2u
# M1jFtz7+MtOzAz2xsq+SOH7SnYAs9U5WkSE1JcM5bmR/U7qcD60ZI4TL9LoDho33
# X/DQUr+MlIe8wCF0JV8YKLbMJyg4JZg5SjbPfLGSrhwjp6lm7GEfauEoSZ1fiOIl
# XdMhSz5SxLVXPyQD8NF6Wy/VI+NwXQ9RRnez+ADhvKwCgl/bwBWzvRvUVUvnOaEP
# 6SNJvBi4RHxF5MHDcnrgcuck379GmcXvwhxX24ON7E1JMKerjt/sW5+v/N2wZuLB
# l4F77dbtS+dJKacTKKanfWeA5opieF+yL4TXV5xcv3coKPHtbcMojyyPQDdPweGF
# RInECUzF1KVDL3SV9274eCBYLBNdYJWaPk8zhNqwiBfenk70lrC8RqBsmNLg1oiM
# CwIDAQABo4IB7TCCAekwEAYJKwYBBAGCNxUBBAMCAQAwHQYDVR0OBBYEFEhuZOVQ
# BdOCqhc3NyK1bajKdQKVMBkGCSsGAQQBgjcUAgQMHgoAUwB1AGIAQwBBMAsGA1Ud
# DwQEAwIBhjAPBgNVHRMBAf8EBTADAQH/MB8GA1UdIwQYMBaAFHItOgIxkEO5FAVO
# 4eqnxzHRI4k0MFoGA1UdHwRTMFEwT6BNoEuGSWh0dHA6Ly9jcmwubWljcm9zb2Z0
# LmNvbS9wa2kvY3JsL3Byb2R1Y3RzL01pY1Jvb0NlckF1dDIwMTFfMjAxMV8wM18y
# Mi5jcmwwXgYIKwYBBQUHAQEEUjBQME4GCCsGAQUFBzAChkJodHRwOi8vd3d3Lm1p
# Y3Jvc29mdC5jb20vcGtpL2NlcnRzL01pY1Jvb0NlckF1dDIwMTFfMjAxMV8wM18y
# Mi5jcnQwgZ8GA1UdIASBlzCBlDCBkQYJKwYBBAGCNy4DMIGDMD8GCCsGAQUFBwIB
# FjNodHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpb3BzL2RvY3MvcHJpbWFyeWNw
# cy5odG0wQAYIKwYBBQUHAgIwNB4yIB0ATABlAGcAYQBsAF8AcABvAGwAaQBjAHkA
# XwBzAHQAYQB0AGUAbQBlAG4AdAAuIB0wDQYJKoZIhvcNAQELBQADggIBAGfyhqWY
# 4FR5Gi7T2HRnIpsLlhHhY5KZQpZ90nkMkMFlXy4sPvjDctFtg/6+P+gKyju/R6mj
# 82nbY78iNaWXXWWEkH2LRlBV2AySfNIaSxzzPEKLUtCw/WvjPgcuKZvmPRul1LUd
# d5Q54ulkyUQ9eHoj8xN9ppB0g430yyYCRirCihC7pKkFDJvtaPpoLpWgKj8qa1hJ
# Yx8JaW5amJbkg/TAj/NGK978O9C9Ne9uJa7lryft0N3zDq+ZKJeYTQ49C/IIidYf
# wzIY4vDFLc5bnrRJOQrGCsLGra7lstnbFYhRRVg4MnEnGn+x9Cf43iw6IGmYslmJ
# aG5vp7d0w0AFBqYBKig+gj8TTWYLwLNN9eGPfxxvFX1Fp3blQCplo8NdUmKGwx1j
# NpeG39rz+PIWoZon4c2ll9DuXWNB41sHnIc+BncG0QaxdR8UvmFhtfDcxhsEvt9B
# xw4o7t5lL+yX9qFcltgA1qFGvVnzl6UJS0gQmYAf0AApxbGbpT9Fdx41xtKiop96
# eiL6SJUfq/tHI4D1nvi/a7dLl+LrdXga7Oo3mXkYS//WsyNodeav+vyL6wuA6mk7
# r/ww7QRMjt/fdW1jkT3RnVZOT7+AVyKheBEyIXrvQQqxP/uozKRdwaGIm1dxVk5I
# RcBCyZt2WwqASGv9eZ/BvW1taslScxMNelDNMYIZoTCCGZ0CAQEwgZUwfjELMAkG
# A1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQx
# HjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEoMCYGA1UEAxMfTWljcm9z
# b2Z0IENvZGUgU2lnbmluZyBQQ0EgMjAxMQITMwAAAsyOtZamvdHJTgAAAAACzDAN
# BglghkgBZQMEAgEFAKCBrjAZBgkqhkiG9w0BCQMxDAYKKwYBBAGCNwIBBDAcBgor
# BgEEAYI3AgELMQ4wDAYKKwYBBAGCNwIBFTAvBgkqhkiG9w0BCQQxIgQghlFB7G4e
# D1ZeidoQ0ZL5yXGZTzdCS8nBSaHeW/qmc1AwQgYKKwYBBAGCNwIBDDE0MDKgFIAS
# AE0AaQBjAHIAbwBzAG8AZgB0oRqAGGh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbTAN
# BgkqhkiG9w0BAQEFAASCAQBPCk6+IQwoWhtqRUCV4y9uQA1SXfOlaldHxkMps6ji
# CL9Rx8zDDSi67Vgjq0hPIxDk8h61sTtpQSNTL2F6lzFCh/AOVCPDuiqSxNAmBen6
# kZOcn4vvhI28auy7niNCDgIfVjcOTCSQ6LxPSaZu125w12gI6qqpLxJT408/biU3
# meNWHmKkB43QILtLOJUMfLwBsp8Rmg9x9TM3eSj4CMbo1agWSTdmshS2m41t41Tg
# cZqejmGBh3WEoBg6uUwwZjwuju281XWTYSbTQfWJXP2yk9yyp6oKecb0b13lNXSV
# tysdvtOQHy3RX0O+8IeHsyzqMLK0JpKaaFyEe/Ver1u/oYIXKzCCFycGCisGAQQB
# gjcDAwExghcXMIIXEwYJKoZIhvcNAQcCoIIXBDCCFwACAQMxDzANBglghkgBZQME
# AgEFADCCAVgGCyqGSIb3DQEJEAEEoIIBRwSCAUMwggE/AgEBBgorBgEEAYRZCgMB
# MDEwDQYJYIZIAWUDBAIBBQAEILN3GcDIyrDUrsC55X0CU50n3Srz3/hFuN1/NLP6
# vul3AgZjT/SUR54YEjIwMjIxMDI2MTQzMTM0LjM1WjAEgAIB9KCB2KSB1TCB0jEL
# MAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1v
# bmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEtMCsGA1UECxMkTWlj
# cm9zb2Z0IElyZWxhbmQgT3BlcmF0aW9ucyBMaW1pdGVkMSYwJAYDVQQLEx1UaGFs
# ZXMgVFNTIEVTTjozQkQ0LTRCODAtNjlDMzElMCMGA1UEAxMcTWljcm9zb2Z0IFRp
# bWUtU3RhbXAgU2VydmljZaCCEXswggcnMIIFD6ADAgECAhMzAAABtPuACEQF0i36
# AAEAAAG0MA0GCSqGSIb3DQEBCwUAMHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpX
# YXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQg
# Q29ycG9yYXRpb24xJjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAy
# MDEwMB4XDTIyMDkyMDIwMjIwOVoXDTIzMTIxNDIwMjIwOVowgdIxCzAJBgNVBAYT
# AlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYD
# VQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xLTArBgNVBAsTJE1pY3Jvc29mdCBJ
# cmVsYW5kIE9wZXJhdGlvbnMgTGltaXRlZDEmMCQGA1UECxMdVGhhbGVzIFRTUyBF
# U046M0JENC00QjgwLTY5QzMxJTAjBgNVBAMTHE1pY3Jvc29mdCBUaW1lLVN0YW1w
# IFNlcnZpY2UwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQC0R6aeZQcy
# Qh+86K7bsrzplvBaGSwbBXvYOXW4Z2qvakqb6Z/OhP5ieCSr1osR/5cO0APID7Yo
# hlTSI7xYbv14mPPPb1+VmkEpsqDzGXY/c712uV65DDdOc1803j5AiCMxekTe3E8X
# szshEspkyI63cV+QVZWaJckADsTc4jAmCmGDT22HdO/OnwxPz4c60bdt2tF3/La7
# xWtCxBMtmJXBNnqoNgo1Pw9BmXvEWtJI7dDNdr3UuKlmdg6XeyIYkMJ57UFrtfWL
# Xd1AUfEqXkV/gnMN244Fnzl7ZWunIXLVrdrIZTMGsjDn2OExuMjD1hVxC32RRae3
# IKY2TXlbJsJL6FekQMMtWPVflb2yeahbWq7Tf66emtCNZBpW47sF9y9B01V3IpKo
# B4rLV5PYdxzmfVoBV5cWbqxtUmZnM9ARBHcmvtbxhxOOSoLmFPaqti4hxgY5/c+P
# g6p1ebVCqG7C2yTG+K/vLLdn4/EmnErH7Z7rMZFqhCYiUt+D9rjZc1UdN/pbOvmT
# tDXDu/S4D+wWyDIqYjsfModfTzEMNKYmihcDlu0PoHSXH8uqzpBvgq2GcDs3YgR0
# nmyMwiHIdnAGvt/MOyRT/5KCnZSd+qs3VV1r+Bv6maVsnCLwymG8SVjONPs9krYO
# bh6ityPHtPZBV7cQh6Uu4ZvHPJtuVmhFOQIDAQABo4IBSTCCAUUwHQYDVR0OBBYE
# FMtEheXxlLg6nLsSKLdO3jjMMtl+MB8GA1UdIwQYMBaAFJ+nFV0AXmJdg/Tl0mWn
# G1M1GelyMF8GA1UdHwRYMFYwVKBSoFCGTmh0dHA6Ly93d3cubWljcm9zb2Z0LmNv
# bS9wa2lvcHMvY3JsL01pY3Jvc29mdCUyMFRpbWUtU3RhbXAlMjBQQ0ElMjAyMDEw
# KDEpLmNybDBsBggrBgEFBQcBAQRgMF4wXAYIKwYBBQUHMAKGUGh0dHA6Ly93d3cu
# bWljcm9zb2Z0LmNvbS9wa2lvcHMvY2VydHMvTWljcm9zb2Z0JTIwVGltZS1TdGFt
# cCUyMFBDQSUyMDIwMTAoMSkuY3J0MAwGA1UdEwEB/wQCMAAwFgYDVR0lAQH/BAww
# CgYIKwYBBQUHAwgwDgYDVR0PAQH/BAQDAgeAMA0GCSqGSIb3DQEBCwUAA4ICAQAS
# 0Q8FjCm3gmKhKrSOgbPCphfpKg0fthuqmACt2Wet23q7e6QpESW4oRWpLZdqNfHH
# RSRcZzheL12nZtLGm7JCdOSr4hDCSDunV0qvABra92Zo3PPeatJp5QS7jTIJOEfC
# q5CTB6gbh6pFFl7X061VKYMM0LdlDoiDSrPv2+K9eDLl0VaTienEDkvFIZHjAFpd
# oi5WGgRrTq93/3/ZixD31sKJHtLElG3VetDmQkYdSLQWGDPXnyq9eB+aruo2p+p9
# NKaxBGu1t7hm/9f6o+j+Xpp75KsuRyNF+vQ41XS8VW40rHoJv3QPkuA2lz3HxX+o
# gcSv4ldtZdbqYBFVWo1AKZeVUeNMGOFxfBKZp1HU6i1w3+wqnYQ4z0k9ivzo71j8
# kBkL3O6D2qWMpOuhlN9gDssh1yY+vr27UVIP/qK8vodEdl3+TYQvsW1nDM1xFF0U
# X9WCmQ7Ech+q+NdqZvCgyhP6+0ZO2qCiu6GFKTRszUX+kGmL+c9m1U0sZM1orxa3
# qSxxsL0bp/T2DP/AEEk4Ga9Ms845P/e1oIZKgmgMAFacr4N7mmJ7gpfwHHEpBsm/
# HPu9GxUnlHqYbH4G9q/kCOzG9lnDp5CaQjS89FyTEv1MJUJ9ZLS7IgqbKjpN2iyd
# sE7+iyt7uvSNL0AfyykSpWWEVylA186D8K91LbE1UzCCB3EwggVZoAMCAQICEzMA
# AAAVxedrngKbSZkAAAAAABUwDQYJKoZIhvcNAQELBQAwgYgxCzAJBgNVBAYTAlVT
# MRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQK
# ExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xMjAwBgNVBAMTKU1pY3Jvc29mdCBSb290
# IENlcnRpZmljYXRlIEF1dGhvcml0eSAyMDEwMB4XDTIxMDkzMDE4MjIyNVoXDTMw
# MDkzMDE4MzIyNVowfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24x
# EDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlv
# bjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTAwggIiMA0G
# CSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQDk4aZM57RyIQt5osvXJHm9DtWC0/3u
# nAcH0qlsTnXIyjVX9gF/bErg4r25PhdgM/9cT8dm95VTcVrifkpa/rg2Z4VGIwy1
# jRPPdzLAEBjoYH1qUoNEt6aORmsHFPPFdvWGUNzBRMhxXFExN6AKOG6N7dcP2CZT
# fDlhAnrEqv1yaa8dq6z2Nr41JmTamDu6GnszrYBbfowQHJ1S/rboYiXcag/PXfT+
# jlPP1uyFVk3v3byNpOORj7I5LFGc6XBpDco2LXCOMcg1KL3jtIckw+DJj361VI/c
# +gVVmG1oO5pGve2krnopN6zL64NF50ZuyjLVwIYwXE8s4mKyzbnijYjklqwBSru+
# cakXW2dg3viSkR4dPf0gz3N9QZpGdc3EXzTdEonW/aUgfX782Z5F37ZyL9t9X4C6
# 26p+Nuw2TPYrbqgSUei/BQOj0XOmTTd0lBw0gg/wEPK3Rxjtp+iZfD9M269ewvPV
# 2HM9Q07BMzlMjgK8QmguEOqEUUbi0b1qGFphAXPKZ6Je1yh2AuIzGHLXpyDwwvoS
# CtdjbwzJNmSLW6CmgyFdXzB0kZSU2LlQ+QuJYfM2BjUYhEfb3BvR/bLUHMVr9lxS
# UV0S2yW6r1AFemzFER1y7435UsSFF5PAPBXbGjfHCBUYP3irRbb1Hode2o+eFnJp
# xq57t7c+auIurQIDAQABo4IB3TCCAdkwEgYJKwYBBAGCNxUBBAUCAwEAATAjBgkr
# BgEEAYI3FQIEFgQUKqdS/mTEmr6CkTxGNSnPEP8vBO4wHQYDVR0OBBYEFJ+nFV0A
# XmJdg/Tl0mWnG1M1GelyMFwGA1UdIARVMFMwUQYMKwYBBAGCN0yDfQEBMEEwPwYI
# KwYBBQUHAgEWM2h0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2lvcHMvRG9jcy9S
# ZXBvc2l0b3J5Lmh0bTATBgNVHSUEDDAKBggrBgEFBQcDCDAZBgkrBgEEAYI3FAIE
# DB4KAFMAdQBiAEMAQTALBgNVHQ8EBAMCAYYwDwYDVR0TAQH/BAUwAwEB/zAfBgNV
# HSMEGDAWgBTV9lbLj+iiXGJo0T2UkFvXzpoYxDBWBgNVHR8ETzBNMEugSaBHhkVo
# dHRwOi8vY3JsLm1pY3Jvc29mdC5jb20vcGtpL2NybC9wcm9kdWN0cy9NaWNSb29D
# ZXJBdXRfMjAxMC0wNi0yMy5jcmwwWgYIKwYBBQUHAQEETjBMMEoGCCsGAQUFBzAC
# hj5odHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpL2NlcnRzL01pY1Jvb0NlckF1
# dF8yMDEwLTA2LTIzLmNydDANBgkqhkiG9w0BAQsFAAOCAgEAnVV9/Cqt4SwfZwEx
# JFvhnnJL/Klv6lwUtj5OR2R4sQaTlz0xM7U518JxNj/aZGx80HU5bbsPMeTCj/ts
# 0aGUGCLu6WZnOlNN3Zi6th542DYunKmCVgADsAW+iehp4LoJ7nvfam++Kctu2D9I
# dQHZGN5tggz1bSNU5HhTdSRXud2f8449xvNo32X2pFaq95W2KFUn0CS9QKC/GbYS
# EhFdPSfgQJY4rPf5KYnDvBewVIVCs/wMnosZiefwC2qBwoEZQhlSdYo2wh3DYXMu
# LGt7bj8sCXgU6ZGyqVvfSaN0DLzskYDSPeZKPmY7T7uG+jIa2Zb0j/aRAfbOxnT9
# 9kxybxCrdTDFNLB62FD+CljdQDzHVG2dY3RILLFORy3BFARxv2T5JL5zbcqOCb2z
# AVdJVGTZc9d/HltEAY5aGZFrDZ+kKNxnGSgkujhLmm77IVRrakURR6nxt67I6Ile
# T53S0Ex2tVdUCbFpAUR+fKFhbHP+CrvsQWY9af3LwUFJfn6Tvsv4O+S3Fb+0zj6l
# MVGEvL8CwYKiexcdFYmNcP7ntdAoGokLjzbaukz5m/8K6TT4JDVnK+ANuOaMmdbh
# IurwJ0I9JZTmdHRbatGePu1+oDEzfbzL6Xu/OHBE0ZDxyKs6ijoIYn/ZcGNTTY3u
# gm2lBRDBcQZqELQdVTNYs6FwZvKhggLXMIICQAIBATCCAQChgdikgdUwgdIxCzAJ
# BgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25k
# MR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xLTArBgNVBAsTJE1pY3Jv
# c29mdCBJcmVsYW5kIE9wZXJhdGlvbnMgTGltaXRlZDEmMCQGA1UECxMdVGhhbGVz
# IFRTUyBFU046M0JENC00QjgwLTY5QzMxJTAjBgNVBAMTHE1pY3Jvc29mdCBUaW1l
# LVN0YW1wIFNlcnZpY2WiIwoBATAHBgUrDgMCGgMVAGWc2JDzm5f2c3gpEm3+AeQn
# HgkIoIGDMIGApH4wfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24x
# EDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlv
# bjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTAwDQYJKoZI
# hvcNAQEFBQACBQDnA606MCIYDzIwMjIxMDI2MjA1NzMwWhgPMjAyMjEwMjcyMDU3
# MzBaMHcwPQYKKwYBBAGEWQoEATEvMC0wCgIFAOcDrToCAQAwCgIBAAICDjACAf8w
# BwIBAAICEggwCgIFAOcE/roCAQAwNgYKKwYBBAGEWQoEAjEoMCYwDAYKKwYBBAGE
# WQoDAqAKMAgCAQACAwehIKEKMAgCAQACAwGGoDANBgkqhkiG9w0BAQUFAAOBgQBz
# DO3wcbjEkAysDgs+Rm1cgCHsyRwJwxUBgr6kQh5tvQ7I4COKBJScJhkm+KG1KyUP
# /7aJcCNmuZSgyaQQI84tVu2xJOjwokEvmj9unQdv/B7930Zo+Qj8uhPxbooZN4Eb
# oP7G2OPAGzCOCr4AEFTUMRBz5lwF8d68hCc+b3KL+DGCBA0wggQJAgEBMIGTMHwx
# CzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRt
# b25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJjAkBgNVBAMTHU1p
# Y3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEwAhMzAAABtPuACEQF0i36AAEAAAG0
# MA0GCWCGSAFlAwQCAQUAoIIBSjAaBgkqhkiG9w0BCQMxDQYLKoZIhvcNAQkQAQQw
# LwYJKoZIhvcNAQkEMSIEIC9a4lJRl56TxmaXPbRwDkmjEVfU/b5vNCtTauw4bmMg
# MIH6BgsqhkiG9w0BCRACLzGB6jCB5zCB5DCBvQQg08j3e+ajMHAGUXG9+v+sSWt4
# U9Hi7Hu9crHaeLcB9wYwgZgwgYCkfjB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMK
# V2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0
# IENvcnBvcmF0aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0Eg
# MjAxMAITMwAAAbT7gAhEBdIt+gABAAABtDAiBCCKU/FadRFZHyN0KSGEPNDaVFIC
# S+oc8ISD6wHddKwBrTANBgkqhkiG9w0BAQsFAASCAgAYokhIj+t2Rl5/u61e+YDS
# 6uUIfjftePspq/iagYtwZyuA6+eSzCSsTADK9Vo0cUyLPO+3lo5uN0NGw0y3lA/z
# LU26WUQ5Dwv2dpgylyacJw9wgrKukMcRnDt118pzt1NI7M9J36c21cgpnYLiI4FH
# vqacqguEo+ODIDopTn2OkJEcjntD75k3RyyFboTbpWRWw1sEbG3KESDJ41YMJooU
# jBvt7XkwGiVxNoIsVvifoVM0+umD5obE3eI3wevD0rZ2rlkTZYzqMkFTzCqB3w7z
# qkOdImpg5G8Oyd+Mht6a4s69hkYfmY8Qre4kYsZ8ZMhCbbXHZJA6VjLRmK4R3bPR
# JfXFHA5Y3+G2CZIArPJQvvnh6or38z+R/gNYIfsDayEKR5QOYB3KGXYdjHDXbLLk
# gF6iyDzBEag4SihXdQjHnWAx+k3BhWF4exGxFRxySSXcKiFBjhM3t+fs2CrUl/Vp
# 9JQGtI4OGvUKyd1b5lm3PPwGEwmiXrbDgMLUsqnKoue4XIHVx/6oYPMTE8KwddFK
# CFsTjfpBey+usSe4lGlCFmJn9UfxiZ0LWmamxIPYaBUk3zPnuNaFriiNzslbWmRb
# GcSJn7IUuJotRcE+Vpd/9O0YTsGOw0TuVkst7vky54CYRLSU3b1KmY/aMMLkDJdV
# U7/R72mb9Rc5xhp/lFUYig==
# SIG # End signature block
