﻿#************************************************
# utils_load20072010powershell.ps1
# Version 2.0.1
# Date: 04-12-2013
# Author: Brian Prince - brianpr@microsoft.com
# Description:  Utility functions specific to Exchange 2007 2010
#************************************************

# For backward compatability with scripts that use "Debug", set an alias
Set-Alias -Name Debug -Value Write-DebugLog

# Populate-ExchangeServerLocal function
#---------------------------------
# Description: Populates local Exchange server in the cache
Function Populate-ExchangeServerLocal
{
	#If $ExchangeServerLocal is not null, that means we have already cached the local Exchange server. 
	if ($null -ne $global:exchangeServerLocalCached)	
	{
		return	
	}
	
	if  (IsExchangePSSnapinInstalled)
	{
 		#Get the machine name
		$machineName = $Env:COMPUTERNAME
		
		#Initialize the Output Filename Prefix and Exchange Server Name variables
		$global:rootOutFile = Join-Path $pwd.Path.ToString() $Env:COMPUTERNAME
		$Script:ExchangeServerName = $null

		if($null -eq $Server)
		{
			$Server = $Env:COMPUTERNAME
		}
		else 
		{
			$Server = $Server
		}
		$Error.Clear()
		# Test whether local computername is an Exchange 2007 or Exchange 2010 Server
		$TestServerName = Get-ExchangeServer -Identity $Server -ErrorAction SilentlyContinue
		if ($Error)
		{
			# Attempt to get CMS Name if local computername is not an Exchange 2007 or Exchange 2010 Server
			$Server = (Get-MailboxServer | Where-Object {$_.RedundantMachines -eq $server}).name
			
			if ($null -eq $Server)
			{	
				"Server name not found or server specified does not have Exchange installed." | WriteTo-StdOut
				$isExchServerFound = $false
				
			}
			else
			{	# Local server is a potential owner of Exchange 2007 CMS - use CMS name as Exchange Server name
				$Script:ExchangeServerName = $Server
				$script:rootOutFile = Join-Path $pwd.Path.ToString() ($machinename + "_CMS_" + $Script:ExchangeServerName)
				$isExchServerFound = $true
			}
		}
		else
		{	# Local server is an Exchange 2007 or Exchange 2010 Server
			$Script:ExchangeServerName = $Server
			$script:rootOutFile = Join-Path $pwd.Path.ToString() $Script:ExchangeServerName
			$isExchServerFound = $true
		}
		if ($isExchServerFound = $true){
		
#			if ($ExVersion -eq 8){[bool]$script:Exchange2007 = $true}
#			elseif ($ExVersion -eq 14){[bool]$script:Exchange2010 = $true}
			$global:exchangeServerLocalCached = (Get-ExchangeServer $Script:ExchangeServerName -Status)
			"Exchange Server Name: " + $Script:ExchangeServerName | WriteTo-StdOut
			"Exchange Version: " + $global:exchangeServerLocalCached.AdminDisplayVersion.Major  | WriteTo-StdOut
		}	
		Else
		{
			"Exchange Server Not Installed or Exchange Powershell Snapin Failed to Load or Get-ExchangeServer Failed." | WriteTo-StdOut
			
		}
	}
	# Else check for Exchange 2003 server and Exchange 2003 Cluster
}

# Get-ExchangeServerLocal function
#-------------------------------
# Description: Returns the cached local Exchange Server object
Function Get-ExchangeServerLocalCached
{
	#Populate the cache
	Populate-ExchangeServerLocal
	return $global:exchangeServerLocalCached
}

# Populate-OrganizationConfig function
#---------------------------------
# Description: Populates Exchange OrganizationConifg in the cache
Function Populate-OrganizationConifg
{
	#If $OrganizationConifgCached is not null, that means we have already cached the local Exchange server. 
	if ($null -ne $global:OrganizationConifgCached)	
	{
		return	
	}
	
	if  (IsExchangePSSnapinInstalled)
	{
 		$global:OrganizationConifgCached = (Get-OrganizationConfig)
	}	
	Else
	{
		"Exchange Powershell Snapin Failed to Load or Get-OrganizationConfig Failed." | WriteTo-StdOut
	}
}

# Get-OrganizationConfig function
#-------------------------------
# Description: Returns the cached local Exchange Server object
Function Get-OrganizationConifgCached
{
	#Populate the cache
	Populate-OrganizationConifg
	return $global:OrganizationConifgCached
}

# Populate-TransportServer function
#---------------------------------
# Description: Populates Exchange TransportServer in the cache
Function Populate-TransportServer
{
	#If $TransportServer is not null, that means we have already cached the local Exchange server. 
	if ($null -ne $global:TransportServerCached)	
	{
		return	
	}
	
	if  (IsExchangePSSnapinInstalled)
	{
		If (Get-ExchangeServerLocalCached){
 		$global:TransportServerCached = (Get-TransportServer -Identity $global:exchangeServerLocalCached.Identity )
		}
	}	
	Else
	{
		"Exchange Powershell Snapin Failed to Load or Get-OrganizationConfig Failed." | WriteTo-StdOut
	}
}

# Get-TransportServer function
#-------------------------------
# Description: Returns the cached local Exchange Server object
Function Get-TransportServerCached
{
	#Populate the cache
	Populate-TransportServer
	return $global:TransportServerCached
}



# <summary>
# Connects the Exchange Management Shell through Remote PowerShell
# </summary>
Function Connect-ExchangeManagementShell {
	trap [Exception] {
		Log-Error $_
		continue;
	}
	
	# TODO: Figure out how to properly import our binaries so types can be properly serialized	
	Write-DebugLog "Connecting Remote Powershell"
	
	$global:ExSession = New-PSSession -ConfigurationName Microsoft.Exchange -ConnectionUri "http://$($env:COMPUTERNAME)/PowerShell" -Authentication Kerberos
	if ($null -eq $global:ExSession) {
		return $false
	}
	
	$result = Import-PSSession $global:ExSession
	if ($null -eq $result) {
		return $false
	}
	
	Write-DebugLog "Remote Powershell Connected"
	return $true
}

# IsExchangeExtensionInstalled function
#---------------------------------
# Description:
#	Checks for the existence of the Exchange Server PowerShell Snapin. 
#
# Arguments:
#	None
#
# Returns:
#	Boolean indicating the presence of PowerShell Snapin for Exchange Server 2010 or 2007
#
# Example:
#	$isInstalled = IsExchangePSSnapinInstalled
#				
Function IsExchangePSSnapinInstalled
{
	$Script:ExchPSSnapinAdded = $true
	#======================================
	# Set global variables and load Powershell snapin for version of Exchange installed
	#======================================
	
	if ($global:ExchangeVersion -eq 14){
		If ($null -eq (Get-PSSnapin -Name "Microsoft.Exchange.Management.PowerShell.E2010" -ErrorAction SilentlyContinue)){
			("Add-PSSnapin 'Microsoft.Exchange.Management.PowerShell.E2010'") | WriteTo-StdOut
			Add-PSSnapin -Name "Microsoft.Exchange.Management.PowerShell.E2010" -ErrorAction SilentlyContinue
			If ($null -ne (Get-PSSnapin -Name "Microsoft.Exchange.Management.PowerShell.E2010" -ErrorAction SilentlyContinue)){
				$Script:ExchPSSnapinAdded = $true
			}
		}
		Else{
			$Script:ExchPSSnapinAdded = $true
		}
	}
	ElseIf ($global:ExchangeVersion -eq 8){
		If ($null -eq (Get-PSSnapin -Name "Microsoft.Exchange.Management.PowerShell.Admin" -ErrorAction SilentlyContinue)){
			("Add-PSSnapin 'Microsoft.Exchange.Management.PowerShell.Admin'") | WriteTo-StdOut
			Add-PSSnapin -Name "Microsoft.Exchange.Management.PowerShell.Admin" -ErrorAction SilentlyContinue 
			If ($null -ne (Get-PSSnapin -Name "Microsoft.Exchange.Management.PowerShell.Admin" -ErrorAction SilentlyContinue)){
				$Script:ExchPSSnapinAdded = $true
			}
		}
		Else{
			$Script:ExchPSSnapinAdded = $true
		}
	}
	Else {
		("Installed Exchange version could not be determined.") | WriteTo-StdOut
		$Script:ExchPSSnapinAdded = $false
	}
	return $Script:ExchPSSnapinAdded
}




###########
# Fake Invoke-ExchangeCommand to be able to run a script both for 2010 and 2013
###########
Function Invoke-ExchangeCommand(
	[string]$commandText,
	[switch]$Local = $false,
	$Runspace = $null)
{
	Invoke-Expression $commandText
}

$global:ExSession = $null
$global:exchangeServerLocalCached = $null #This will hold the local Exchange Server object and all properties
$global:OrganizationConfigCached = $null #This will hold the Exchange organization configuration and all properties
$global:TransportServerCached = $null #This will hold the TransportServer configuration and all properties


# SIG # Begin signature block
# MIInmAYJKoZIhvcNAQcCoIIniTCCJ4UCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCDCbd7GM9nuK+8A
# 6nU3qxu1NVeYAh6lW9RpUfXrGgihXaCCDXYwggX0MIID3KADAgECAhMzAAACy7d1
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
# MAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIEeuazPD0K5xLwlbfZRfjLKB
# G3SOAbfftiPBb8swuV6QMEQGCisGAQQBgjcCAQwxNjA0oBSAEgBNAGkAYwByAG8A
# cwBvAGYAdKEcgBpodHRwczovL3d3dy5taWNyb3NvZnQuY29tIDANBgkqhkiG9w0B
# AQEFAASCAQAoHy6zSjZZ3dyWbaG2ZERnMwQ+r+eiSVG4EKxU6HW3STAhHhwB8xci
# wNMf8p88lPYy2vYk6S25K3OrSwVRRvhVZgHXRjdcqCJ/CtRV409WbBdJbXWQPn8S
# iqHE3g5hJ2LXI80N5vDgoNIeCqM9RkYbEwVrI6f34R4V0Waf8/KsLfNN8y6BQ87a
# AzwcV47FtavVS9dkiJ0dNgsiTXYur3J0HGlWc8gu1y7uSJd9rCet14Yu2zXg5GYs
# jW6lNIq0W69gRtEi+v7UMijoQYLpmwTTPYoykJ9m0pZvKcPaXf4hszzXKeSXCAvf
# owe6vdmhHVfLOtOayS42Tijj3NOno/PIoYIXADCCFvwGCisGAQQBgjcDAwExghbs
# MIIW6AYJKoZIhvcNAQcCoIIW2TCCFtUCAQMxDzANBglghkgBZQMEAgEFADCCAVEG
# CyqGSIb3DQEJEAEEoIIBQASCATwwggE4AgEBBgorBgEEAYRZCgMBMDEwDQYJYIZI
# AWUDBAIBBQAEIPpiDrmKLsNR9HrtnfzPyyGJymMFZHfwi5qLz19VmYMmAgZi1VDl
# 27IYEzIwMjIwODAxMDgxNTEzLjEyNFowBIACAfSggdCkgc0wgcoxCzAJBgNVBAYT
# AlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYD
# VQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJTAjBgNVBAsTHE1pY3Jvc29mdCBB
# bWVyaWNhIE9wZXJhdGlvbnMxJjAkBgNVBAsTHVRoYWxlcyBUU1MgRVNOOjdCRjEt
# RTNFQS1CODA4MSUwIwYDVQQDExxNaWNyb3NvZnQgVGltZS1TdGFtcCBTZXJ2aWNl
# oIIRVzCCBwwwggT0oAMCAQICEzMAAAGfK0U1FQguS10AAQAAAZ8wDQYJKoZIhvcN
# AQELBQAwfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNV
# BAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQG
# A1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTAwHhcNMjExMjAyMTkw
# NTIyWhcNMjMwMjI4MTkwNTIyWjCByjELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldh
# c2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBD
# b3Jwb3JhdGlvbjElMCMGA1UECxMcTWljcm9zb2Z0IEFtZXJpY2EgT3BlcmF0aW9u
# czEmMCQGA1UECxMdVGhhbGVzIFRTUyBFU046N0JGMS1FM0VBLUI4MDgxJTAjBgNV
# BAMTHE1pY3Jvc29mdCBUaW1lLVN0YW1wIFNlcnZpY2UwggIiMA0GCSqGSIb3DQEB
# AQUAA4ICDwAwggIKAoICAQCk9Xl8TVGyiZAvzm8tB4fLP0znL883YDIG03js1/Wz
# CaICXDs0kXlJ39OUZweBFa/V8l27mlBjyLZDtTg3W8dQORDunfn7SzZEoFmlXaSY
# cQhyDMV5ghxi6lh8y3NV1TNHGYLzaoQmtBeuFSlEH9wp6rC/sRK7GPrOn17XAGzo
# +/yFy7DfWgIQ43X35ut20TShUeYDrs5GOVpHp7ouqQYRTpu+lAaCHfq8tr+LFqIy
# jpkvxxb3Hcx6Vjte0NPH6GnICT84PxWYK7eoa5AxbsTUqWQyiWtrGoyQyXP4yIKf
# TUYPtsTFCi14iuJNr3yRGjo4U1OHZU2yGmWeCrdccJgkby6k2N5AhRYvKHrePPh5
# oWHY01g8TckxV4h4iloqvaaYGh3HDPWPw4KoKyEy7QHGuZK1qAkheWiKX2qE0eNR
# WummCKPhdcF3dcViVI9aKXhty4zM76tsUjcdCtnG5VII6eU6dzcL6YFp0vMl7JPI
# 3y9Irx9sBEiVmSigM2TDZU4RUIbFItD60DJYzNH0rGu2Dv39P/0Owox37P3ZfvB5
# jAeg6B+SBSD0awi+f61JFrVc/UZ83W+5tgI/0xcLGWHBNdEibSF1NFfrV0KPCKfi
# 9iD2BkQgMYi02CY8E3us+UyYA4NFYcWJpjacBKABeDBdkY1BPfGgzskaKhIGhdox
# 9QIDAQABo4IBNjCCATIwHQYDVR0OBBYEFGI08tUeExYrSA4u6N/ZasfWHchhMB8G
# A1UdIwQYMBaAFJ+nFV0AXmJdg/Tl0mWnG1M1GelyMF8GA1UdHwRYMFYwVKBSoFCG
# Tmh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2lvcHMvY3JsL01pY3Jvc29mdCUy
# MFRpbWUtU3RhbXAlMjBQQ0ElMjAyMDEwKDEpLmNybDBsBggrBgEFBQcBAQRgMF4w
# XAYIKwYBBQUHMAKGUGh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2lvcHMvY2Vy
# dHMvTWljcm9zb2Z0JTIwVGltZS1TdGFtcCUyMFBDQSUyMDIwMTAoMSkuY3J0MAwG
# A1UdEwEB/wQCMAAwEwYDVR0lBAwwCgYIKwYBBQUHAwgwDQYJKoZIhvcNAQELBQAD
# ggIBAB2KKCk8O+kZ8+m9bPXQIAmo+6xbKDaKkMR3/82A8XVAMa9RpItYJkdkta+C
# 6ZIVBsZEARJkKnWpYJiiyGBV3PmPoIMP5zFbr0BYLMolDJZMtH3MifVBD9NknYNK
# g+GbWyaAPs8VZ6UD3CRzjoVZ2PbHRH+UOl2Yc/cm1IR3BlvjlcNwykpzBGUndARe
# fuzjfRSfB+dBzmlFY+dME8+J3OvveMraIcznSrlr46GXMoWGJt0hBJNf4G5JZqyX
# e8n8z2yR5poL2uiMRzqIXX1rwCIXhcLPFgSKN/vJxrxHiF9ByViouf4jCcD8O2mO
# 94toCSqLERuodSe9dQ7qrKVBonDoYWAx+W0XGAX2qaoZmqEun7Qb8hnyNyVrJ2C2
# fZwAY2yiX3ZMgLGUrpDRoJWdP+tc5SS6KZ1fwyhL/KAgjiNPvUBiu7PF4LHx5TRF
# U7HZXvgpZDn5xktkXZidA4S26NZsMSygx0R1nXV3ybY3JdlNfRETt6SIfQdCxRX5
# YUbI5NdvuVMiy5oB3blfhPgNJyo0qdmkHKE2pN4c8iw9SrajnWcM0bUExrDkNqcw
# aq11Dzwc0lDGX14gnjGRbghl6HLsD7jxx0+buzJHKZPzGdTLMFKoSdJeV4pU/t3d
# PbdU21HS60Ex2Ip2TdGfgtS9POzVaTA4UucuklbjZkQihfg2MIIHcTCCBVmgAwIB
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
# IEVTTjo3QkYxLUUzRUEtQjgwODElMCMGA1UEAxMcTWljcm9zb2Z0IFRpbWUtU3Rh
# bXAgU2VydmljZaIjCgEBMAcGBSsOAwIaAxUAdF2umB/yywxFLFTC8rJ9Fv9c9reg
# gYMwgYCkfjB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4G
# A1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSYw
# JAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAxMDANBgkqhkiG9w0B
# AQUFAAIFAOaRmxgwIhgPMjAyMjA4MDEwODIxNDRaGA8yMDIyMDgwMjA4MjE0NFow
# dzA9BgorBgEEAYRZCgQBMS8wLTAKAgUA5pGbGAIBADAKAgEAAgIbQwIB/zAHAgEA
# AgIRqjAKAgUA5pLsmAIBADA2BgorBgEEAYRZCgQCMSgwJjAMBgorBgEEAYRZCgMC
# oAowCAIBAAIDB6EgoQowCAIBAAIDAYagMA0GCSqGSIb3DQEBBQUAA4GBAEg80CEF
# JzLl8HeAJ/hZbnWQNsuIwu49g6NyKJi5qDBmnp/p+lUYWLzptwQ8IZws+2i1BWTq
# rded+t2dg1o3aCvWO7+8zpJUL+MYbToFai4eHsm4gREbd8MJ20XBPG8dyFA9AHGL
# CNzy86mPSsSureH5EZOyVbA1/999a8cmYWEOMYIEDTCCBAkCAQEwgZMwfDELMAkG
# A1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQx
# HjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQGA1UEAxMdTWljcm9z
# b2Z0IFRpbWUtU3RhbXAgUENBIDIwMTACEzMAAAGfK0U1FQguS10AAQAAAZ8wDQYJ
# YIZIAWUDBAIBBQCgggFKMBoGCSqGSIb3DQEJAzENBgsqhkiG9w0BCRABBDAvBgkq
# hkiG9w0BCQQxIgQgr/yFH6ACZl8lrM2wCsbf4qNDxpKNoMWMSVwpAE7Mk4QwgfoG
# CyqGSIb3DQEJEAIvMYHqMIHnMIHkMIG9BCCG8V4poieJnqXnVzwNUejeKgLJfEH7
# P+jspyw3S3xc2jCBmDCBgKR+MHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNo
# aW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29y
# cG9yYXRpb24xJjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEw
# AhMzAAABnytFNRUILktdAAEAAAGfMCIEIOlIiYcAkE7hdl0Wdg0v2Y1xxRsJuCeW
# RwNv6bySR2rrMA0GCSqGSIb3DQEBCwUABIICAFn00HGtjkrcY1GMmXfsrR6Q3rB4
# q1IGAlzdt/7327WALau3UMU9J2g0s95ZhLpzHCLVKy64HVe2mYB9tr/rhQV99y3d
# fwPRevHWc1W2WRMZUFC7RjOwrTY4swwt343PNWEk2pCL2zZeSVyftlDb75AZNRf+
# 8LHEZDLeny3wshqeaGeC25BDMN6qOD1PsG7Q462pcBI7dkpBYFefZ6PLQHAhogJZ
# MyBxVww4FiBVLC20d4AP0JSrCArPm8DbuiYncuPzul++32CcSEkHAIr5NInqJ0Au
# RWwfxQiUNim1DJ8hgxkzh7EWH05RPa0rb2V/+13rYsAZIryZxo+i3I/EzWYrcUNM
# WuO56DUcuMy74+A5ClLPFOdRrMD+9W7Lk+FQhgzwqaDLRLJUQk++UO0m6YVpR3RB
# 7p9oUk5qJ8mKHj1yH6w93He2Q9KvX7awTHlnrfypB7b2Rv+vI6ektInO5QJF239r
# yDuDiFwBGDcZikorucJqeHHc9mkFpcwy4wyu2wiMGYAtGSXofW8ER00cM249IJxN
# zNLpHWfpjhB1BNoZk0S03iuwIhqnbXG3fJp59xRqWOrDk/Kf35JxLY2hsa8tL97n
# LtpO/wcXb0adU5rNRYFy0aoaEVg0E0iEBErNSDk8nLB/ax4VI68WcSBVQWXXxxJs
# paAP+smsPOx1LrXw
# SIG # End signature block
