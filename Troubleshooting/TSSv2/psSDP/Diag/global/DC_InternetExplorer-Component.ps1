#***************************************************
# DC_InternetExplorer-Component.ps1
# Version 1.0: HKCU and HKLM locations
# Version 1.1.06.07.13: Added "HKU\.DEFAULT" and "HKU\S-1-5-18" locations. [suggestion:johnfern]
# Version 1.2.07.30.14: Added the parsed output of Trusted Sites and Local Intranet to the new _InternetExplorer_Zones.TXT [suggestion:waltere]
# Version 1.3.08.23.14: Added Protected Mode detection for IE Zones. [suggestion:edb]  TFS264121
# Version 1.4.09.04.14: Fixed exception. Corrected syntax for reading registry value by adding "-ErrorAction SilentlyContinue"
# Date: 2009-2014
# Author: Boyd Benson (bbenson@microsoft.com)
# Description: Collects information about Internet Explorer (IE)
# Called from: Networking Diagnostics
#****************************************************

Trap [Exception]
	{
	 # Handle exception and throw it to the stdout log file. Then continue with function and script.
		 $Script:ExceptionMessage = $_
		 "[info]: Exception occurred."  | WriteTo-StdOut
		 "[info]: Exception.Message $ExceptionMessage."  | WriteTo-StdOut 
		 $Error.Clear()
		 continue
	}

$sectionDescription = "Internet Explorer"
	
Import-LocalizedData -BindingVariable ScriptVariable
Write-DiagProgress -Activity $ScriptVariable.ID_CTSInternetExplorer -Status $ScriptVariable.ID_CTSInternetExplorerDescription

#----------Registry
$OutputFile= $Computername + "_InternetExplorer_reg_output.TXT"
$CurrentVersionKeys =	"HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings",
						"HKLM\Software\Microsoft\Windows\CurrentVersion\Internet Settings",
						"HKU\.DEFAULT\Software\Microsoft\Windows\CurrentVersion\Internet Settings",
						"HKU\S-1-5-18\Software\Microsoft\Windows\CurrentVersion\Internet Settings"

RegQuery -RegistryKeys $CurrentVersionKeys -Recursive $true -OutputFile $OutputFile -fileDescription "Internet Explorer registry output" -SectionDescription $sectionDescription

$isServerSku = (Get-CimInstance -Class Win32_ComputerSystem).DomainRole -gt 1
$OutputFile= $Computername + "_InternetExplorer_Zones.TXT"

"===================================================="	| Out-File -FilePath $OutputFile -append
"Internet Explorer Zone Information"					| Out-File -FilePath $OutputFile -append
"===================================================="	| Out-File -FilePath $OutputFile -append
"Overview"												| Out-File -FilePath $OutputFile -append
"----------------------------------------------------"	| Out-File -FilePath $OutputFile -append
"   1. IE Enhanced Security Configuration (IE ESC) [Server SKU Only]"		| Out-File -FilePath $OutputFile -append
"   2. IE Protected Mode Configuration for each IE Zone"	| Out-File -FilePath $outputFile -append
"   3. List of Sites in IE Zone2 `"Trusted Sites`""		| Out-File -FilePath $OutputFile -append
"   4. List of Sites in IE Zone1 `"Local Intranet`""	| Out-File -FilePath $OutputFile -append
"===================================================="	| Out-File -FilePath $OutputFile -append
"`n`n`n`n`n"	| Out-File -FilePath $OutputFile -append

"====================================================" 	| Out-File -FilePath $outputFile -append
"IE Enhanced Security Configuration (ESC) [Server SKU Only]" 				| Out-File -FilePath $outputFile -append
"====================================================" 	| Out-File -FilePath $outputFile -append
#detect if IE ESC is enabled/disabled for user/admin
if ($isServerSku -eq $true){
	"`n" | Out-File -FilePath $outputFile -append
	# IE ESC is only used on Server SKUs.
	# Detecting if IE Enhanced Security Configuration is Enabled or Disabled
	#  regkey  : HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A7-37EF-4b3f-8CFC-4F3A74704073}
	#  regvalue: IsInstalled
	$regkey="HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A7-37EF-4b3f-8CFC-4F3A74704073}"
	$adminIEESC = (Get-ItemProperty -path $regkey).IsInstalled
	if ($adminIEESC -eq '0'){
		"IE ESC is DISABLED for Admin users." | Out-File -FilePath $outputFile -append
	}
	else{
		"IE ESC is ENABLED for Admin users." | Out-File -FilePath $outputFile -append
	}
	#user
	#  regkey  : HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A8-37EF-4b3f-8CFC-4F3A74704073}
	#  regvalue: IsInstalled
	$regkey= "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A8-37EF-4b3f-8CFC-4F3A74704073}"
	$userIEESC=(Get-ItemProperty -path $regkey).IsInstalled
	if ($userIEESC -eq '0'){
		"IE ESC is DISABLED for non-Admin users." | Out-File -FilePath $outputFile -append
	}
	else{
		"IE ESC is ENABLED for non-Admin users." | Out-File -FilePath $outputFile -append
	}
	"`n`n`n" | Out-File -FilePath $outputFile -append
}
else{
	"IE ESC is only used on Server SKUs. Not checking status." | Out-File -FilePath $outputFile -append
	"`n`n`n" | Out-File -FilePath $outputFile -append
}



#added this section 08.23.14
"====================================================" 	| Out-File -FilePath $outputFile -append
"IE Protected Mode Configuration for each IE Zone" 		| Out-File -FilePath $outputFile -append
"====================================================" 	| Out-File -FilePath $outputFile -append
$zone0 = "Computer"
$zone1 = "Local intranet"
$zone2 = "Trusted sites"
$zone3 = "Internet"
$zone4 = "Restricted sites"
$regkeyZonesHKCU = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Zones"
$zonesHKCU = Get-ChildItem -path $regkeyZonesHKCU
$regkeyZonesHKLM = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Zones"
$zonesHKLM = Get-ChildItem -path $regkeyZonesHKLM

# Regvalue 2500 exists by default in HKLM in each zone, but may not exist in HKCU.
for($i=0;$i -le 4;$i++)
{
	if ($i -eq 0) {"IE Protected Mode for Zone0 `"$zone0`":" 	| Out-File -FilePath $outputFile -append }
	if ($i -eq 1) {"IE Protected Mode for Zone1 `"$zone1`":" 	| Out-File -FilePath $outputFile -append }
	if ($i -eq 2) {"IE Protected Mode for Zone2 `"$zone2`":" 	| Out-File -FilePath $outputFile -append }
	if ($i -eq 3) {"IE Protected Mode for Zone3 `"$zone3`":" 	| Out-File -FilePath $outputFile -append }
	if ($i -eq 4) {"IE Protected Mode for Zone4 `"$zone4`":" 	| Out-File -FilePath $outputFile -append }
	$regkeyZoneHKCU = join-path $regkeyZonesHKCU $i
	$regkeyZoneHKLM = join-path $regkeyZonesHKLM $i
	$regvalueHKCU2500Enabled = $false
	$regvalueHKLM2500Enabled = $false

	If (test-path $regkeyZoneHKCU)
	{
		#Moved away from this since it exceptions on W7/WS2008R2:   $regvalueHKCU2500 = (Get-ItemProperty -path $regkeyZoneHKCU).2500
		$regvalueHKCU2500 = Get-ItemProperty -path $regkeyZoneHKCU -name "2500" -ErrorAction SilentlyContinue		
		if ($regvalueHKCU2500 -eq 0){
			#"IE Protected Mode is ENABLED in HKCU. (RegValue 2500 is set to 0.)"
			$regvalueHKCU2500Enabled = $true
		}
		if ($regvalueHKCU2500 -eq 3){
			#"IE Protected Mode is DISABLED in HKCU. (RegValue 2500 is set to 3.)"
			$regvalueHKCU2500Enabled = $false
		}
	}
	If (test-path $regkeyZoneHKLM)
	{
		#Moved away from this since it exceptions on W7/WS2008R2:   $regvalueHKCU2500 = (Get-ItemProperty -path $regkeyZoneHKLM).2500
		$regvalueHKLM2500 = Get-ItemProperty -path $regkeyZoneHKLM -name "2500" -ErrorAction SilentlyContinue
		if ($regvalueHKLM2500 -eq 0){
			#"IE Protected Mode is ENABLED in HKCU. (RegValue 2500 is set to 0.)"
			$regvalueHKLM2500Enabled = $true
		}
		if ($regvalueHKLM2500 -eq 3){
			#"IE Protected Mode is DISABLED in HKCU. (RegValue 2500 is set to 3.)"
			$regvalueHKLM2500Enabled = $false
		}
	}

	If (($regvalueHKCU2500Enabled -eq $true) -and ($regvalueHKLM2500Enabled -eq $true)){
		"  ENABLED (HKCU:enabled; HKLM:enabled)" 	| Out-File -FilePath $outputFile -append
		"`n" | Out-File -FilePath $outputFile -append
	}
	elseif (($regvalueHKCU2500Enabled -eq $true) -and ($regvalueHKLM2500Enabled -eq $false)){
		"  DISABLED (HKCU:enabled; HKLM:disabled)" 	| Out-File -FilePath $outputFile -append
		"`n" | Out-File -FilePath $outputFile -append
	}
	elseif (($regvalueHKCU2500Enabled -eq $false) -and ($regvalueHKLM2500Enabled -eq $true)){
		"  ENABLED (HKCU:disabled; HKLM:enabled)" 	| Out-File -FilePath $outputFile -append
		"`n" | Out-File -FilePath $outputFile -append
	}
	elseif (($regvalueHKCU2500Enabled -eq $false) -and ($regvalueHKLM2500Enabled -eq $false)){
		"  DISABLED (HKCU:disabled; HKLM:disabled)" 	| Out-File -FilePath $outputFile -append
		"`n" | Out-File -FilePath $outputFile -append
	}
}
"`n`n`n" | Out-File -FilePath $outputFile -append


#Build an array with all registry subkeys of $regkey 
$regkeyZoneMapDomains = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\Domains"
$regkeyZoneMapEscDomains = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\EscDomains"
$zoneMapDomains = Get-ChildItem -path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\Domains"
$zoneMapDomainsLength = $zoneMapDomains.length

# Creating psobjects
$ieZoneMapDomainsObj = New-Object psobject
$ieZoneMapEscDomainsObj = New-Object psobject
$ieDomainsTrustedSitesObj = New-Object psobject
$ieEscDomainsTrustedSitesObj = New-Object psobject
$ieDomainLocalIntranetObj = New-Object psobject
$ieEscDomainLocalIntranetObj = New-Object psobject

#Loop through each domain and determine what Zone the domain is in using http or https regvalues
$domainCount=0
$trustedSiteCount=0
$localIntranetCount=0
foreach ($domain in $zoneMapDomains)
{
	$domainCount++
	$domainName = $domain.PSChildName
	
	# Add all domains to $ieZoneMapDomainsObj
	Add-Member -InputObject $ieZoneMapDomainsObj -MemberType NoteProperty -Name "Domain$domainCount" -Value $domainName

	$domainRegkey = $regkeyZoneMapDomains + '\' + $domainName
	$domainHttp     = (Get-ItemProperty -path "$domainRegkey").http
	$domainHttps    = (Get-ItemProperty -path "$domainRegkey").https
	$domainSubkeys = Get-ChildItem -path $domainRegkey

	if ($domain.SubKeyCount -ge 1){
		foreach ($subkey in $domainSubkeys){
			$subkeyName = $subkey.PSChildName
			$domainRegkey = $regkeyZoneMapDomains + '\' + $domainName + '\' + $subkeyName
			$fullDomainName = $subkeyName + "." + $domainName
			$domainHttp     = (Get-ItemProperty -path "$domainRegkey").http
			$domainHttps    = (Get-ItemProperty -path "$domainRegkey").https

			if ($domainHttp -eq 2){
				$trustedSiteCount++
				# Add trusted sites to the $ieDomainsTrustedSitesObj
				Add-Member -InputObject $ieDomainsTrustedSitesObj -MemberType NoteProperty -Name "Website$trustedSiteCount`t: HTTP" -Value $fullDomainName
			}			
			if ($domainHttps -eq 2){
				$trustedSiteCount++
				# Add trusted sites to the $ieDomainsTrustedSitesObj
				Add-Member -InputObject $ieDomainsTrustedSitesObj -MemberType NoteProperty -Name "Website$trustedSiteCount`t: HTTPS" -Value $fullDomainName	
			}

			if ($domainHttp -eq 1){
				$localIntranetCount++
				# Add Local Intranet to the $ieDomainLocalIntranetObj
				Add-Member -InputObject $ieDomainLocalIntranetObj -MemberType NoteProperty -Name "Website$localIntranetCount`t: HTTP" -Value $fullDomainName	
			}
			if ($domainHttps -eq 1){
				$localIntranetCount++
				# Add Local Intranet to the $ieDomainLocalIntranetObj
				Add-Member -InputObject $ieDomainLocalIntranetObj -MemberType NoteProperty -Name "Website$localIntranetCount`t: HTTPS" -Value $fullDomainName	
			}
		}
	}
	else
	{
		$fullDomainName = $domainName
		$domainHttp     = (Get-ItemProperty -path "$domainRegkey").http
		$domainHttps    = (Get-ItemProperty -path "$domainRegkey").https
		
		if ($domainHttp -eq 2){
			$trustedSiteCount++
			# Add trusted sites to the $ieDomainsTrustedSitesObj
			Add-Member -InputObject $ieDomainsTrustedSitesObj -MemberType NoteProperty -Name "Website$trustedSiteCount`t: HTTP" -Value $fullDomainName				
		}
		if ($domainHttps -eq 2){
			$trustedSiteCount++
			# Add trusted sites to the $ieDomainsTrustedSitesObj
			Add-Member -InputObject $ieDomainsTrustedSitesObj -MemberType NoteProperty -Name "Website$trustedSiteCount`t: HTTPS" -Value $fullDomainName		
		}

		if ($domainHttp -eq 1){
			$localIntranetCount++
			# Add Local Intranet to the $ieDomainLocalIntranetObj
			Add-Member -InputObject $ieDomainLocalIntranetObj -MemberType NoteProperty -Name "Website$localIntranetCount`t: HTTP" -Value $fullDomainName	
		}
		if ($domainHttps -eq 1){
			$localIntranetCount++
			# Add Local Intranet to the $ieDomainLocalIntranetObj
			Add-Member -InputObject $ieDomainLocalIntranetObj -MemberType NoteProperty -Name "Website$localIntranetCount`t: HTTPS" -Value $fullDomainName	
		}	
	}
}

if ($isServerSku -eq $true)
{
	#Loop through each domain and determine what Zone the domain is in using http or https regvalues
	$zoneMapEscDomains = Get-ChildItem -path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\EscDomains"
	$zoneMapEscDomainsLength = $zoneMapEscDomains.length

	$escDomainCount=0
	$trustedSiteCount=0
	$localIntranetCount=0
	if($null -ne $zoneMapEscDomains){ #_#
		foreach ($domain in $zoneMapEscDomains){
			$escDomainCount++
			$domainName = $domain.PSChildName

			# Add domains to $ieZoneMapEscDomainsObj
			Add-Member -InputObject $ieZoneMapEscDomainsObj -MemberType NoteProperty -Name "EscDomain$escDomainCount" -Value $domainName

			$domainRegkey = $regkeyZoneMapEscDomains + '\' + $domainName
			$domainHttp     = (Get-ItemProperty -path "$domainRegkey").http -ErrorAction Ignore
			$domainHttps    = (Get-ItemProperty -path "$domainRegkey").https -ErrorAction Ignore
			$domainSubkeys = Get-ChildItem -path $domainRegkey -ErrorAction Ignore

			if ($domain.SubKeyCount -ge 1){
				foreach ($subkey in $domainSubkeys){
					$subkeyName = $subkey.PSChildName
					$domainRegkey = $regkeyZoneMapEscDomains + '\' + $domainName + '\' + $subkeyName
					$fullDomainName = $subkeyName + "." + $domainName
					$domainHttp     = (Get-ItemProperty -path "$domainRegkey").http -ErrorAction Ignore
					$domainHttps    = (Get-ItemProperty -path "$domainRegkey").https -ErrorAction Ignore

					if ($domainHttp -eq 2){
						$trustedSiteCount++
						# Add trusted sites to the $ieEscDomainsTrustedSitesObj
						Add-Member -InputObject $ieEscDomainsTrustedSitesObj -MemberType NoteProperty -Name "Website$trustedSiteCount`t: HTTP" -Value $fullDomainName
					}
					if ($domainHttps -eq 2){
						$trustedSiteCount++
						# Add trusted sites to the $ieEscDomainsTrustedSitesObj
						Add-Member -InputObject $ieEscDomainsTrustedSitesObj -MemberType NoteProperty -Name "Website$trustedSiteCount`t: HTTPS" -Value $fullDomainName
					}

					if ($domainHttp -eq 1){
						$localIntranetCount++
						# Add Local Intranet to the $ieEscDomainLocalIntranetObj
						Add-Member -InputObject $ieEscDomainLocalIntranetObj -MemberType NoteProperty -Name "Website$localIntranetCount`t: HTTP" -Value $fullDomainName	
					}
					if ($domainHttps -eq 1){
						$localIntranetCount++
						# Add Local Intranet to the $ieEscDomainLocalIntranetObj
						Add-Member -InputObject $ieEscDomainLocalIntranetObj -MemberType NoteProperty -Name "Website$localIntranetCount`t: HTTPS" -Value $fullDomainName	
					}		
				}
			}
			else
			{
				$fullDomainName = $domainName
				$domainHttp     = (Get-ItemProperty -path "$domainRegkey").http -ErrorAction Ignore
				$domainHttps    = (Get-ItemProperty -path "$domainRegkey").https -ErrorAction Ignore
				
				if ($domainHttp -eq 2){
					$trustedSiteCount++
					# Add trusted sites to the $ieEscDomainsTrustedSitesObj
					Add-Member -InputObject $ieEscDomainsTrustedSitesObj -MemberType NoteProperty -Name "Website$trustedSiteCount`t: HTTP" -Value $fullDomainName	
				}
				if ($domainHttps -eq 2){
					$trustedSiteCount++
					# Add trusted sites to the $ieEscDomainsTrustedSitesObj
					Add-Member -InputObject $ieEscDomainsTrustedSitesObj -MemberType NoteProperty -Name "Website$trustedSiteCount`t: HTTPS" -Value $fullDomainName	
				}

				if ($domainHttp -eq 1){
					$localIntranetCount++
					# Add Local Intranet to the $ieEscDomainLocalIntranetObj
					Add-Member -InputObject $ieEscDomainLocalIntranetObj -MemberType NoteProperty -Name "Website$localIntranetCount`t: HTTP" -Value $fullDomainName	
				}
				if ($domainHttps -eq 1){
					$localIntranetCount++
					# Add Local Intranet to the $ieEscDomainLocalIntranetObj
					Add-Member -InputObject $ieEscDomainLocalIntranetObj -MemberType NoteProperty -Name "Website$localIntranetCount`t: HTTPS" -Value $fullDomainName	
				}		
			}
		}
	}
}



"====================================================" 				| Out-File -FilePath $outputFile -append
"List of Sites in IE Zone2 `"Trusted Sites`""						| Out-File -FilePath $outputFile -append
"====================================================" 				| Out-File -FilePath $outputFile -append
if ($isServerSku -eq $true)
{
	"--------------------" 											| Out-File -FilePath $outputFile -append
	"[ZoneMap\Domains registry location]" 							| Out-File -FilePath $outputFile -append
	  "Used when IE Enhanced Security Configuration is Disabled" 	| Out-File -FilePath $outputFile -append
	"--------------------" 											| Out-File -FilePath $outputFile -append
	$ieDomainsTrustedSitesObj | Format-List							| Out-File -FilePath $outputFile -append
	"`n" 															| Out-File -FilePath $outputFile -append
	"`n" 															| Out-File -FilePath $outputFile -append
	"`n" 															| Out-File -FilePath $outputFile -append
	"--------------------" 											| Out-File -FilePath $outputFile -append
	"[ZoneMap\EscDomains registry location]" 						| Out-File -FilePath $outputFile -append
	"Used when IE Enhanced Security Configuration is Enabled" 		| Out-File -FilePath $outputFile -append
	"--------------------" 											| Out-File -FilePath $outputFile -append
	$ieEscDomainsTrustedSitesObj | Format-List						| Out-File -FilePath $outputFile -append
}
else
{
	"--------------------" 											| Out-File -FilePath $outputFile -append
	"[ZoneMap\Domains registry location]" 							| Out-File -FilePath $outputFile -append
	"--------------------" 											| Out-File -FilePath $outputFile -append
	$ieDomainsTrustedSitesObj | Format-List							| Out-File -FilePath $outputFile -append
}
"`n" | Out-File -FilePath $outputFile -append
"`n" | Out-File -FilePath $outputFile -append
"`n" | Out-File -FilePath $outputFile -append




"====================================================" | Out-File -FilePath $outputFile -append
"List of Sites in IE Zone1 `"Local Intranet`"" | Out-File -FilePath $outputFile -append
"====================================================" | Out-File -FilePath $outputFile -append
if ($isServerSku -eq $true)
{
	"--------------------" 										| Out-File -FilePath $outputFile -append
	"[ZoneMap\Domains registry location]" 						| Out-File -FilePath $outputFile -append
	"Used when IE Enhanced Security Configuration is Disabled" 	| Out-File -FilePath $outputFile -append
	"--------------------" 										| Out-File -FilePath $outputFile -append
	$ieDomainLocalIntranetObj | Format-List						| Out-File -FilePath $outputFile -append
	"`n" 														| Out-File -FilePath $outputFile -append
	"`n" 														| Out-File -FilePath $outputFile -append
	"`n" 														| Out-File -FilePath $outputFile -append
	"--------------------" 										| Out-File -FilePath $outputFile -append
	"[ZoneMap\EscDomains registry location]" 					| Out-File -FilePath $outputFile -append
	"Used when IE Enhanced Security Configuration is Enabled" 	| Out-File -FilePath $outputFile -append
	"--------------------" 										| Out-File -FilePath $outputFile -append
	$ieEscDomainLocalIntranetObj | Format-List					| Out-File -FilePath $outputFile -append
}
else
{
	"--------------------" 										| Out-File -FilePath $outputFile -append
	"[ZoneMap\Domains registry location]" 						| Out-File -FilePath $outputFile -append
	"--------------------" 										| Out-File -FilePath $outputFile -append
	$ieDomainLocalIntranetObj | Format-List						| Out-File -FilePath $outputFile -append
}
"`n" | Out-File -FilePath $outputFile -append
"`n" | Out-File -FilePath $outputFile -append
"`n" | Out-File -FilePath $outputFile -append

CollectFiles -sectionDescription $sectionDescription -fileDescription "IE Zones Information (Trusted Sites and Local Intranet)" -filesToCollect $outputFile


# SIG # Begin signature block
# MIInpAYJKoZIhvcNAQcCoIInlTCCJ5ECAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCADVrwjz9TzVZAH
# v8wT5rv8BdQ81BI5gQTCCTQaMeT1maCCDYUwggYDMIID66ADAgECAhMzAAACzfNk
# v/jUTF1RAAAAAALNMA0GCSqGSIb3DQEBCwUAMH4xCzAJBgNVBAYTAlVTMRMwEQYD
# VQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMTH01pY3Jvc29mdCBDb2RlIFNpZ25p
# bmcgUENBIDIwMTEwHhcNMjIwNTEyMjA0NjAyWhcNMjMwNTExMjA0NjAyWjB0MQsw
# CQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9u
# ZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMR4wHAYDVQQDExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIB
# AQDrIzsY62MmKrzergm7Ucnu+DuSHdgzRZVCIGi9CalFrhwtiK+3FIDzlOYbs/zz
# HwuLC3hir55wVgHoaC4liQwQ60wVyR17EZPa4BQ28C5ARlxqftdp3H8RrXWbVyvQ
# aUnBQVZM73XDyGV1oUPZGHGWtgdqtBUd60VjnFPICSf8pnFiit6hvSxH5IVWI0iO
# nfqdXYoPWUtVUMmVqW1yBX0NtbQlSHIU6hlPvo9/uqKvkjFUFA2LbC9AWQbJmH+1
# uM0l4nDSKfCqccvdI5l3zjEk9yUSUmh1IQhDFn+5SL2JmnCF0jZEZ4f5HE7ykDP+
# oiA3Q+fhKCseg+0aEHi+DRPZAgMBAAGjggGCMIIBfjAfBgNVHSUEGDAWBgorBgEE
# AYI3TAgBBggrBgEFBQcDAzAdBgNVHQ4EFgQU0WymH4CP7s1+yQktEwbcLQuR9Zww
# VAYDVR0RBE0wS6RJMEcxLTArBgNVBAsTJE1pY3Jvc29mdCBJcmVsYW5kIE9wZXJh
# dGlvbnMgTGltaXRlZDEWMBQGA1UEBRMNMjMwMDEyKzQ3MDUzMDAfBgNVHSMEGDAW
# gBRIbmTlUAXTgqoXNzcitW2oynUClTBUBgNVHR8ETTBLMEmgR6BFhkNodHRwOi8v
# d3d3Lm1pY3Jvc29mdC5jb20vcGtpb3BzL2NybC9NaWNDb2RTaWdQQ0EyMDExXzIw
# MTEtMDctMDguY3JsMGEGCCsGAQUFBwEBBFUwUzBRBggrBgEFBQcwAoZFaHR0cDov
# L3d3dy5taWNyb3NvZnQuY29tL3BraW9wcy9jZXJ0cy9NaWNDb2RTaWdQQ0EyMDEx
# XzIwMTEtMDctMDguY3J0MAwGA1UdEwEB/wQCMAAwDQYJKoZIhvcNAQELBQADggIB
# AE7LSuuNObCBWYuttxJAgilXJ92GpyV/fTiyXHZ/9LbzXs/MfKnPwRydlmA2ak0r
# GWLDFh89zAWHFI8t9JLwpd/VRoVE3+WyzTIskdbBnHbf1yjo/+0tpHlnroFJdcDS
# MIsH+T7z3ClY+6WnjSTetpg1Y/pLOLXZpZjYeXQiFwo9G5lzUcSd8YVQNPQAGICl
# 2JRSaCNlzAdIFCF5PNKoXbJtEqDcPZ8oDrM9KdO7TqUE5VqeBe6DggY1sZYnQD+/
# LWlz5D0wCriNgGQ/TWWexMwwnEqlIwfkIcNFxo0QND/6Ya9DTAUykk2SKGSPt0kL
# tHxNEn2GJvcNtfohVY/b0tuyF05eXE3cdtYZbeGoU1xQixPZAlTdtLmeFNly82uB
# VbybAZ4Ut18F//UrugVQ9UUdK1uYmc+2SdRQQCccKwXGOuYgZ1ULW2u5PyfWxzo4
# BR++53OB/tZXQpz4OkgBZeqs9YaYLFfKRlQHVtmQghFHzB5v/WFonxDVlvPxy2go
# a0u9Z+ZlIpvooZRvm6OtXxdAjMBcWBAsnBRr/Oj5s356EDdf2l/sLwLFYE61t+ME
# iNYdy0pXL6gN3DxTVf2qjJxXFkFfjjTisndudHsguEMk8mEtnvwo9fOSKT6oRHhM
# 9sZ4HTg/TTMjUljmN3mBYWAWI5ExdC1inuog0xrKmOWVMIIHejCCBWKgAwIBAgIK
# YQ6Q0gAAAAAAAzANBgkqhkiG9w0BAQsFADCBiDELMAkGA1UEBhMCVVMxEzARBgNV
# BAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jv
# c29mdCBDb3Jwb3JhdGlvbjEyMDAGA1UEAxMpTWljcm9zb2Z0IFJvb3QgQ2VydGlm
# aWNhdGUgQXV0aG9yaXR5IDIwMTEwHhcNMTEwNzA4MjA1OTA5WhcNMjYwNzA4MjEw
# OTA5WjB+MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UE
# BxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSgwJgYD
# VQQDEx9NaWNyb3NvZnQgQ29kZSBTaWduaW5nIFBDQSAyMDExMIICIjANBgkqhkiG
# 9w0BAQEFAAOCAg8AMIICCgKCAgEAq/D6chAcLq3YbqqCEE00uvK2WCGfQhsqa+la
# UKq4BjgaBEm6f8MMHt03a8YS2AvwOMKZBrDIOdUBFDFC04kNeWSHfpRgJGyvnkmc
# 6Whe0t+bU7IKLMOv2akrrnoJr9eWWcpgGgXpZnboMlImEi/nqwhQz7NEt13YxC4D
# dato88tt8zpcoRb0RrrgOGSsbmQ1eKagYw8t00CT+OPeBw3VXHmlSSnnDb6gE3e+
# lD3v++MrWhAfTVYoonpy4BI6t0le2O3tQ5GD2Xuye4Yb2T6xjF3oiU+EGvKhL1nk
# kDstrjNYxbc+/jLTswM9sbKvkjh+0p2ALPVOVpEhNSXDOW5kf1O6nA+tGSOEy/S6
# A4aN91/w0FK/jJSHvMAhdCVfGCi2zCcoOCWYOUo2z3yxkq4cI6epZuxhH2rhKEmd
# X4jiJV3TIUs+UsS1Vz8kA/DRelsv1SPjcF0PUUZ3s/gA4bysAoJf28AVs70b1FVL
# 5zmhD+kjSbwYuER8ReTBw3J64HLnJN+/RpnF78IcV9uDjexNSTCnq47f7Fufr/zd
# sGbiwZeBe+3W7UvnSSmnEyimp31ngOaKYnhfsi+E11ecXL93KCjx7W3DKI8sj0A3
# T8HhhUSJxAlMxdSlQy90lfdu+HggWCwTXWCVmj5PM4TasIgX3p5O9JawvEagbJjS
# 4NaIjAsCAwEAAaOCAe0wggHpMBAGCSsGAQQBgjcVAQQDAgEAMB0GA1UdDgQWBBRI
# bmTlUAXTgqoXNzcitW2oynUClTAZBgkrBgEEAYI3FAIEDB4KAFMAdQBiAEMAQTAL
# BgNVHQ8EBAMCAYYwDwYDVR0TAQH/BAUwAwEB/zAfBgNVHSMEGDAWgBRyLToCMZBD
# uRQFTuHqp8cx0SOJNDBaBgNVHR8EUzBRME+gTaBLhklodHRwOi8vY3JsLm1pY3Jv
# c29mdC5jb20vcGtpL2NybC9wcm9kdWN0cy9NaWNSb29DZXJBdXQyMDExXzIwMTFf
# MDNfMjIuY3JsMF4GCCsGAQUFBwEBBFIwUDBOBggrBgEFBQcwAoZCaHR0cDovL3d3
# dy5taWNyb3NvZnQuY29tL3BraS9jZXJ0cy9NaWNSb29DZXJBdXQyMDExXzIwMTFf
# MDNfMjIuY3J0MIGfBgNVHSAEgZcwgZQwgZEGCSsGAQQBgjcuAzCBgzA/BggrBgEF
# BQcCARYzaHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3BraW9wcy9kb2NzL3ByaW1h
# cnljcHMuaHRtMEAGCCsGAQUFBwICMDQeMiAdAEwAZQBnAGEAbABfAHAAbwBsAGkA
# YwB5AF8AcwB0AGEAdABlAG0AZQBuAHQALiAdMA0GCSqGSIb3DQEBCwUAA4ICAQBn
# 8oalmOBUeRou09h0ZyKbC5YR4WOSmUKWfdJ5DJDBZV8uLD74w3LRbYP+vj/oCso7
# v0epo/Np22O/IjWll11lhJB9i0ZQVdgMknzSGksc8zxCi1LQsP1r4z4HLimb5j0b
# pdS1HXeUOeLpZMlEPXh6I/MTfaaQdION9MsmAkYqwooQu6SpBQyb7Wj6aC6VoCo/
# KmtYSWMfCWluWpiW5IP0wI/zRive/DvQvTXvbiWu5a8n7dDd8w6vmSiXmE0OPQvy
# CInWH8MyGOLwxS3OW560STkKxgrCxq2u5bLZ2xWIUUVYODJxJxp/sfQn+N4sOiBp
# mLJZiWhub6e3dMNABQamASooPoI/E01mC8CzTfXhj38cbxV9Rad25UAqZaPDXVJi
# hsMdYzaXht/a8/jyFqGaJ+HNpZfQ7l1jQeNbB5yHPgZ3BtEGsXUfFL5hYbXw3MYb
# BL7fQccOKO7eZS/sl/ahXJbYANahRr1Z85elCUtIEJmAH9AAKcWxm6U/RXceNcbS
# oqKfenoi+kiVH6v7RyOA9Z74v2u3S5fi63V4GuzqN5l5GEv/1rMjaHXmr/r8i+sL
# gOppO6/8MO0ETI7f33VtY5E90Z1WTk+/gFcioXgRMiF670EKsT/7qMykXcGhiJtX
# cVZOSEXAQsmbdlsKgEhr/Xmfwb1tbWrJUnMTDXpQzTGCGXUwghlxAgEBMIGVMH4x
# CzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRt
# b25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMTH01p
# Y3Jvc29mdCBDb2RlIFNpZ25pbmcgUENBIDIwMTECEzMAAALN82S/+NRMXVEAAAAA
# As0wDQYJYIZIAWUDBAIBBQCggbAwGQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQw
# HAYKKwYBBAGCNwIBCzEOMAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIDjS
# 3GCZsN6TdCLkflTy7aohvO6RKavVJrAlHOIhi7YaMEQGCisGAQQBgjcCAQwxNjA0
# oBSAEgBNAGkAYwByAG8AcwBvAGYAdKEcgBpodHRwczovL3d3dy5taWNyb3NvZnQu
# Y29tIDANBgkqhkiG9w0BAQEFAASCAQCDrXGaIaImNpUvDrZHz0n+6gDe4fI+E3mk
# NfNRDrav025d0N5Fa9zdaNQKiWJhzt9yKwFeuM5DrUAkXAtdyQHzDVpcMWRz+Lpd
# hkiUU4DBOXkRwnif3gF8acNMdfxaPVGKx5bHwFgckZrRqSyJBs85n3SyQtz5N4IW
# PhgwfN+bak6TG/z1eEB+z0SqsjkO4yvchY/1fdIqfbMQ5818/LW5V3B4tVf989m9
# zxXJZG0bTOQbYAdOzIMgU+PqdmOMzTr0rePSMLJIQif1V7BbLBivLUwH1PjraUAJ
# 15CFk8X8j7KEk5eWIIzSgIS7EUfRhR7r0DSrIuJfMLjeOK/WrrI7oYIW/TCCFvkG
# CisGAQQBgjcDAwExghbpMIIW5QYJKoZIhvcNAQcCoIIW1jCCFtICAQMxDzANBglg
# hkgBZQMEAgEFADCCAVEGCyqGSIb3DQEJEAEEoIIBQASCATwwggE4AgEBBgorBgEE
# AYRZCgMBMDEwDQYJYIZIAWUDBAIBBQAEIGeriPSg+VihDIpT3vwsHmfJNHTUDNfZ
# HAFzjlMXDU1aAgZjR/fOTugYEzIwMjIxMDI0MDgxNTE5LjcyMlowBIACAfSggdCk
# gc0wgcoxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQH
# EwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJTAjBgNV
# BAsTHE1pY3Jvc29mdCBBbWVyaWNhIE9wZXJhdGlvbnMxJjAkBgNVBAsTHVRoYWxl
# cyBUU1MgRVNOOjNCQkQtRTMzOC1FOUExMSUwIwYDVQQDExxNaWNyb3NvZnQgVGlt
# ZS1TdGFtcCBTZXJ2aWNloIIRVDCCBwwwggT0oAMCAQICEzMAAAGd/onl+Xu7TMAA
# AQAAAZ0wDQYJKoZIhvcNAQELBQAwfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldh
# c2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBD
# b3Jwb3JhdGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIw
# MTAwHhcNMjExMjAyMTkwNTE5WhcNMjMwMjI4MTkwNTE5WjCByjELMAkGA1UEBhMC
# VVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNV
# BAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjElMCMGA1UECxMcTWljcm9zb2Z0IEFt
# ZXJpY2EgT3BlcmF0aW9uczEmMCQGA1UECxMdVGhhbGVzIFRTUyBFU046M0JCRC1F
# MzM4LUU5QTExJTAjBgNVBAMTHE1pY3Jvc29mdCBUaW1lLVN0YW1wIFNlcnZpY2Uw
# ggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQDgEWh60BxJFuR+mlFuFCtG
# 3mR2XHNCfPMTXcp06YewAtS1bbGzK7hDC1JRMethcmiKM/ebdCcG6v6k4lQyLlSa
# HmHkIUC5pNEtlutzpsVN+jo+Nbdyu9w0BMh4KzfduLdxbda1VztKDSXjE3eEl5Of
# +5hY3pHoJX9Nh/5r4tc4Nvqt9tvVcYeIxpchZ81AK3+UzpA+hcR6HS67XA8+cQUB
# 1fGyRoVh1sCu0+ofdVDcWOG/tcSKtJch+eRAVDe7IRm84fPsPTFz2dIJRJA/PUaZ
# R+3xW4Fd1ZbLNa/wMbq3vaYtKogaSZiiCyUxU7mwoA32iyTcGHC7hH8MgZWVOEBu
# 7CfNvMyrsR8Quvu3m91Dqsc5gZHMxvgeAO9LLiaaU+klYmFWQvLXpilS1iDXb/82
# +TjwGtxEnc8x/EvLkk7Ukj4uKZ6J8ynlgPhPRqejcoKlHsKgxWmD3wzEXW1a09d1
# L2Io004w01i31QAMB/GLhgmmMIE5Z4VI2Jlh9sX2nkyh5QOnYOznECk4za9cIdMK
# P+sde2nhvvcSdrGXQ8fWO/+N1mjT0SIkX41XZjm+QMGR03ta63pfsj3g3E5a1r0o
# 9aHgcuphW0lwrbBA/TGMo5zC8Z5WI+Rwpr0MAiDZGy5h2+uMx/2+/F4ZiyKauKXq
# d7rIl1seAYQYxKQ4SemB0QIDAQABo4IBNjCCATIwHQYDVR0OBBYEFNbfEI3hKujM
# nF4Rgdvay4rZG1XkMB8GA1UdIwQYMBaAFJ+nFV0AXmJdg/Tl0mWnG1M1GelyMF8G
# A1UdHwRYMFYwVKBSoFCGTmh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2lvcHMv
# Y3JsL01pY3Jvc29mdCUyMFRpbWUtU3RhbXAlMjBQQ0ElMjAyMDEwKDEpLmNybDBs
# BggrBgEFBQcBAQRgMF4wXAYIKwYBBQUHMAKGUGh0dHA6Ly93d3cubWljcm9zb2Z0
# LmNvbS9wa2lvcHMvY2VydHMvTWljcm9zb2Z0JTIwVGltZS1TdGFtcCUyMFBDQSUy
# MDIwMTAoMSkuY3J0MAwGA1UdEwEB/wQCMAAwEwYDVR0lBAwwCgYIKwYBBQUHAwgw
# DQYJKoZIhvcNAQELBQADggIBAIbHcpxLt2h0LNJ334iCNZYsta2Eant9JUeipweb
# FIwQMij7SIQ83iJ4Y4OL5YwlppwvF516AhcHevYMScY6NAXSAGhp5xYtkEckeV6g
# Nbcp3C4I3yotWvDd9KQCh7LdIhpiYCde0SF4N5JRZUHXIMczvNhe8+dEuiCnS1sW
# iGPUFzNJfsAcNs1aBkHItaSxM0AVHgZfgK8R2ihVktirxwYG0T9o1h0BkRJ3PfuJ
# F+nOjt1+eFYYgq+bOLQs/SdgY4DbUVfrtLdEg2TbS+siZw4dqzM+tLdye5XGyJlK
# BX7aIs4xf1Hh1ymMX24YJlm8vyX+W4x8yytPmziNHtshxf7lKd1Pm7t+7UUzi8QB
# hby0vYrfrnoW1Kws+z34uoc2+D2VFxrH39xq/8KbeeBpuL5++CipoZQsd5QO5Ni8
# 1nBlwi/71JsZDEomso/k4JioyvVAM2818CgnsNJnMZZSxM5kyeRdYh9IbjGdPddP
# Vcv0kPKrNalPtRO4ih0GVkL/a4BfEBtXDeEUIsM4A00QehD+ESV3I0UbW+b4NTmb
# RcjnVFk5t6nuK/FoFQc5N4XueYAOw2mMDhAoFE+2xtTHk2ewd9xGkbFDl2b6u/Fb
# hsUb5+XoP0PdJ3FTNP6G/7Vr4sIOxar4PpY674aQCiMSywwtIWOoqRS/OP/rSjF9
# E/xfMIIHcTCCBVmgAwIBAgITMwAAABXF52ueAptJmQAAAAAAFTANBgkqhkiG9w0B
# AQsFADCBiDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNV
# BAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEyMDAG
# A1UEAxMpTWljcm9zb2Z0IFJvb3QgQ2VydGlmaWNhdGUgQXV0aG9yaXR5IDIwMTAw
# HhcNMjEwOTMwMTgyMjI1WhcNMzAwOTMwMTgzMjI1WjB8MQswCQYDVQQGEwJVUzET
# MBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMV
# TWljcm9zb2Z0IENvcnBvcmF0aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGltZS1T
# dGFtcCBQQ0EgMjAxMDCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAOTh
# pkzntHIhC3miy9ckeb0O1YLT/e6cBwfSqWxOdcjKNVf2AX9sSuDivbk+F2Az/1xP
# x2b3lVNxWuJ+Slr+uDZnhUYjDLWNE893MsAQGOhgfWpSg0S3po5GawcU88V29YZQ
# 3MFEyHFcUTE3oAo4bo3t1w/YJlN8OWECesSq/XJprx2rrPY2vjUmZNqYO7oaezOt
# gFt+jBAcnVL+tuhiJdxqD89d9P6OU8/W7IVWTe/dvI2k45GPsjksUZzpcGkNyjYt
# cI4xyDUoveO0hyTD4MmPfrVUj9z6BVWYbWg7mka97aSueik3rMvrg0XnRm7KMtXA
# hjBcTyziYrLNueKNiOSWrAFKu75xqRdbZ2De+JKRHh09/SDPc31BmkZ1zcRfNN0S
# idb9pSB9fvzZnkXftnIv231fgLrbqn427DZM9ituqBJR6L8FA6PRc6ZNN3SUHDSC
# D/AQ8rdHGO2n6Jl8P0zbr17C89XYcz1DTsEzOUyOArxCaC4Q6oRRRuLRvWoYWmEB
# c8pnol7XKHYC4jMYctenIPDC+hIK12NvDMk2ZItboKaDIV1fMHSRlJTYuVD5C4lh
# 8zYGNRiER9vcG9H9stQcxWv2XFJRXRLbJbqvUAV6bMURHXLvjflSxIUXk8A8Fdsa
# N8cIFRg/eKtFtvUeh17aj54WcmnGrnu3tz5q4i6tAgMBAAGjggHdMIIB2TASBgkr
# BgEEAYI3FQEEBQIDAQABMCMGCSsGAQQBgjcVAgQWBBQqp1L+ZMSavoKRPEY1Kc8Q
# /y8E7jAdBgNVHQ4EFgQUn6cVXQBeYl2D9OXSZacbUzUZ6XIwXAYDVR0gBFUwUzBR
# BgwrBgEEAYI3TIN9AQEwQTA/BggrBgEFBQcCARYzaHR0cDovL3d3dy5taWNyb3Nv
# ZnQuY29tL3BraW9wcy9Eb2NzL1JlcG9zaXRvcnkuaHRtMBMGA1UdJQQMMAoGCCsG
# AQUFBwMIMBkGCSsGAQQBgjcUAgQMHgoAUwB1AGIAQwBBMAsGA1UdDwQEAwIBhjAP
# BgNVHRMBAf8EBTADAQH/MB8GA1UdIwQYMBaAFNX2VsuP6KJcYmjRPZSQW9fOmhjE
# MFYGA1UdHwRPME0wS6BJoEeGRWh0dHA6Ly9jcmwubWljcm9zb2Z0LmNvbS9wa2kv
# Y3JsL3Byb2R1Y3RzL01pY1Jvb0NlckF1dF8yMDEwLTA2LTIzLmNybDBaBggrBgEF
# BQcBAQROMEwwSgYIKwYBBQUHMAKGPmh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9w
# a2kvY2VydHMvTWljUm9vQ2VyQXV0XzIwMTAtMDYtMjMuY3J0MA0GCSqGSIb3DQEB
# CwUAA4ICAQCdVX38Kq3hLB9nATEkW+Geckv8qW/qXBS2Pk5HZHixBpOXPTEztTnX
# wnE2P9pkbHzQdTltuw8x5MKP+2zRoZQYIu7pZmc6U03dmLq2HnjYNi6cqYJWAAOw
# Bb6J6Gngugnue99qb74py27YP0h1AdkY3m2CDPVtI1TkeFN1JFe53Z/zjj3G82jf
# ZfakVqr3lbYoVSfQJL1AoL8ZthISEV09J+BAljis9/kpicO8F7BUhUKz/AyeixmJ
# 5/ALaoHCgRlCGVJ1ijbCHcNhcy4sa3tuPywJeBTpkbKpW99Jo3QMvOyRgNI95ko+
# ZjtPu4b6MhrZlvSP9pEB9s7GdP32THJvEKt1MMU0sHrYUP4KWN1APMdUbZ1jdEgs
# sU5HLcEUBHG/ZPkkvnNtyo4JvbMBV0lUZNlz138eW0QBjloZkWsNn6Qo3GcZKCS6
# OEuabvshVGtqRRFHqfG3rsjoiV5PndLQTHa1V1QJsWkBRH58oWFsc/4Ku+xBZj1p
# /cvBQUl+fpO+y/g75LcVv7TOPqUxUYS8vwLBgqJ7Fx0ViY1w/ue10CgaiQuPNtq6
# TPmb/wrpNPgkNWcr4A245oyZ1uEi6vAnQj0llOZ0dFtq0Z4+7X6gMTN9vMvpe784
# cETRkPHIqzqKOghif9lwY1NNje6CbaUFEMFxBmoQtB1VM1izoXBm8qGCAsswggI0
# AgEBMIH4oYHQpIHNMIHKMQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3Rv
# bjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0
# aW9uMSUwIwYDVQQLExxNaWNyb3NvZnQgQW1lcmljYSBPcGVyYXRpb25zMSYwJAYD
# VQQLEx1UaGFsZXMgVFNTIEVTTjozQkJELUUzMzgtRTlBMTElMCMGA1UEAxMcTWlj
# cm9zb2Z0IFRpbWUtU3RhbXAgU2VydmljZaIjCgEBMAcGBSsOAwIaAxUAt+lDSRX9
# 2KFyij71Jn20CoSyyuCggYMwgYCkfjB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMK
# V2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0
# IENvcnBvcmF0aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0Eg
# MjAxMDANBgkqhkiG9w0BAQUFAAIFAOcATTgwIhgPMjAyMjEwMjQwNzMxMDRaGA8y
# MDIyMTAyNTA3MzEwNFowdDA6BgorBgEEAYRZCgQBMSwwKjAKAgUA5wBNOAIBADAH
# AgEAAgIVIDAHAgEAAgIRpzAKAgUA5wGeuAIBADA2BgorBgEEAYRZCgQCMSgwJjAM
# BgorBgEEAYRZCgMCoAowCAIBAAIDB6EgoQowCAIBAAIDAYagMA0GCSqGSIb3DQEB
# BQUAA4GBAExf9+oKaUzOjpA/P0e62v3ks2RQTSvPdwVjt1166yj5WUKLJbZUfYjn
# SfLrbGvSuk6HurjcWPUDHWKKvX/mUfJOKAiYT9yulwEZW1ADeaHldFepqDfAGrLD
# 0vYhitZbhHfAdXEq0BuppPDDwUQnuFSgJWCvKxvKEj66wOqH/FdEMYIEDTCCBAkC
# AQEwgZMwfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNV
# BAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQG
# A1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTACEzMAAAGd/onl+Xu7
# TMAAAQAAAZ0wDQYJYIZIAWUDBAIBBQCgggFKMBoGCSqGSIb3DQEJAzENBgsqhkiG
# 9w0BCRABBDAvBgkqhkiG9w0BCQQxIgQgVa++aaGYL5QkdI3n85KAhmQ5LsyRNrYP
# LuOj62yIik0wgfoGCyqGSIb3DQEJEAIvMYHqMIHnMIHkMIG9BCD1HmOt4IqgT4A0
# n4JblX/fzFLyEu4OBDOb+mpMlYdFoTCBmDCBgKR+MHwxCzAJBgNVBAYTAlVTMRMw
# EQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVN
# aWNyb3NvZnQgQ29ycG9yYXRpb24xJjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0
# YW1wIFBDQSAyMDEwAhMzAAABnf6J5fl7u0zAAAEAAAGdMCIEIFBSa0naN2NZijO9
# ADknaMU9hfqJFbk7xmp0nwTPmeNdMA0GCSqGSIb3DQEBCwUABIICANOudwLqYlTp
# zstjMpzT1aLpiysVyAln/0Om6ncv0FBMBpwFP+1x4GJ+oUTT+ZYjO1a2jgbNHMAp
# RqTKfoBvyEwL648VGrfX7I0YrrTJ91JDWbgy6FdYhYebSeaNYzXK/rN2qesYBNzI
# RcK866ip4UAq5jtYgajrBX8rNC4ePYGGpIDXfPVf8KDQZSioMDdVtFKpcqOJF+Fz
# s6ZFGsssNjHCxFSIraZHlHrgkIv0sv6IqljyU60VO3i3ASpEHV42RcPUuZdtInUs
# GhkjyDhFT4X4kAbOSLiPTHaGBLmsSJyQYrJhisyy+bUkoz5aNtUfbMJBhcIDXKfd
# VXwH3mQ9LzSp/vxyjK/i5AHPAZyxjhXnFeYzjTgm0h5ty3BofAqCXGs0tNM6KFI3
# ogHPC4Vu8DLYSE0Foxd+53w3FM0Lumbn+lzc1I476gtev0vTmITeI/CG6MSSNVUD
# ZS1I2x6PPnv4OjSxP6BPEENS/ZBWXJe2bd3GyTTsLDYZhfYjIEYQ3o6HYZ5NAFd/
# OmdZ3KRg6rGhbp8Rx7YrXuctsJjm4LdJ9M3BkVdSmc5PKKRh0nboQElL2TDrYC8G
# W0O3MSvCDrloaiNsB3fi91X6OdZCVv2fnibMdX6bP4oCVOfBAnXUKvPF9YdoHCJN
# Rj+Zj5LwyXumSdxhNpdU9dvyNW/Fau0z
# SIG # End signature block
