# Name tss_GetLockoutEvents.ps1

<# 
.SYNOPSIS
 Script to find Account Lockout: PowerShell script collects Security events from all DCs related with Bad Password attempts

.DESCRIPTION
 PowerShell script sample to assist in troubleshooting account lockout issues. It can be used to collect Security Events from all DCs in a given forest or domain.
 It collects events like 4625, 4771, 4776 with error codes 0x18 and c000006a respectively.
 You do not have to run the script elevated. However you have to run it with *domain admin* privileges.
 It can be run against any domain in the forest you logon to run the script. Running against a different domain may need you to run the script with other domain admin privileges or Enterprise Admin.
 Script can also detect trusted domains and collect events from remote DCs. Make sure that the domain admin running the script has the permission to collect events remotely from trusted domains.

.PARAMETER UserName
 Please enter the UserName (sAMAccountName)
 
.PARAMETER DomainName
 Please enter the NetBIOS or FQDN of any domain in the forest
 
.PARAMETER DataPath
 This switch determines the path for output files
 
.EXAMPLE
 .\tss_GetLockoutEvents.ps1 -UserName "User1" -DomainName "Contoso" -DataPath "C:\MS_DATA" 
 Example 1:  for User1 in domain Contoso
 
.LINK
 https://internal.support.services.microsoft.com/en-us/help/4498703
 https://microsoft.sharepoint.com/teams/HybridIdentityPOD/_layouts/15/Doc.aspx?sourcedoc={5bec59af-bf31-4073-9111-a63486fcdf0c}&action=view&wd=target%28Account%20Lockouts.one%7C9a46c4f5-38af-4648-93f2-8a976a91c463%2FWorkflow%20Account%20Lockout%20Data%20Collection%20-%20Reactive%7Cdc03d719-fff5-4bdf-b46e-15456c2521f1%2F%29
 
 Author: Ahmed Fouad (v-ahfoua@microsoft.com)
#>


# Version 1.4 - 2020.03.25 WalterE

[CmdletBinding()]
PARAM (
    [Parameter(Mandatory=$True,Position=0,HelpMessage='Enter user sAMAccountName')]
	[string]$UserName
	,
	[Parameter(Mandatory=$True,Position=1,HelpMessage='Enter DomainName')]
	[string]$DomainName
	,
	[string]$DataPath = (Split-Path $MyInvocation.MyCommand.Path -Parent)
)

#region helper functions
function CheckDomain
{	# Check domain and user variables
	try 
	{
	  Write-Host "..Checking whether domain $DomainName exists" 
	  if (Get-ADDomain $DomainName) 
	   {
		Write-Host "Domain '$DomainName' exists" -fore Green
	   }

	}
	catch 
	{
		 Write-Host $_.Exception.Message -fore Red
		 break 
	}
}

function CheckUser
{	# Check whether the user exist or not
	try
	{
	   Write-Host "..Checking whether AD user $UserName exists" 
	   if (Get-ADUser -Identity $UserName -Server $DomainName) 
		{
		 Write-Host "AD user '$UserName' exists in '$DomainName' domain" -fore Green
		}
	}
	catch 
	{
		Write-Host  $_.Exception.Message -fore Red
		break 
	}
}

function CheckDomainAdmin
{
	Write-Host "..Checking whether the current user $env:Username has domain admin privilege" 

	if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole("$DomainName\Domain Admins") -and  (-not  ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole("Enterprise Admins") ) ) 
	  {
		Write-Host "Sorry you '$env:Username' don't have domain admin privilege to run this script" -fore Red
		Break
	  }
	Else 
	  {
		Write-Host "User '$UserName' is member of '$DomainName\Domain Admins'" -fore Green 
	  }
}
#endregion helper functions


#region variables

[xml]$xmlfilter = "<QueryList> 
           <Query Id='0'> 
              <Select Path='Security'> 
                 *[EventData[Data[@Name='TargetUserName'] and (Data='$username')]] 
                  and 
                 *[EventData[Data[@Name='status'] and (Data='0x18')]] 
                 and
                 *[System[(EventID='4771' or EventID='4768' or EventID='4769' )]]
              </Select> 
           </Query> 
<Query Id='1'> 
              <Select Path='Security'> 
               *[EventData[Data[@Name='TargetUserName'] and (Data='$username')]] 
               and  
               *[EventData[Data[@Name='substatus'] and (Data='0xc000006a')]] 
                  and
               *[System[(EventID='4625' )]] 
               </Select> 
           </Query> 
<Query Id='2'> 
              <Select Path='Security'> 
               *[EventData[Data[@Name='TargetUserName'] and (Data='$username')]] 
                  and
               *[System[(EventID='4740' or EventID='4767' )]] 
               </Select> 
           </Query> 
<Query Id='3'> 
              <Select Path='Security'> 
               *[EventData[Data[@Name='TargetUserName'] and (Data='$username')]] 
               and  
               *[EventData[Data[@Name='Status'] and (Data='0xc000006a')]] 
                  and
               *[System[(EventID='4776' )]] 
               </Select> 
           </Query> 

</QueryList>"

#_# $DataPath = read-host "Please enter the path of the report (leave it blank to use the default path)"

if ($DataPath)
    {
      $fullpath = $DataPath
      New-Item -ItemType Directory -Path $fullpath\LockoutLogs -ErrorAction SilentlyContinue -InformationAction SilentlyContinue | Out-Null
    }
Else 
    {
     $fullpath = (get-location).path
     New-Item -ItemType Directory -Path $fullpath\LockoutLogs -ErrorAction SilentlyContinue -InformationAction SilentlyContinue | Out-Null
    
    }

$CSVPath = $fullpath + "\LockoutLogs\Report.csv" 


$AllEvents = @()
$SourceMachines = @()
$ExchangeServersIPv4 = @()

foreach ($ExchangeServer in $ExchangeServers ) 
{
   $ExchangeServersIPv4 += (Resolve-DnsName $ExchangeServer.name).IPAddress

}

#endregion variables

function GetEventsFromAllDCs
{
	$Dcs = Get-ADDomainController -Filter * -Server $DomainName
	#get events from all domain controllers
	foreach ($dc in $Dcs)
	{
	$serverName = $dc.HostName
	Write-Host "Checking connectivity to DC:" $serverName 
	$PingStatus = Get-WmiObject win32_pingStatus -Filter "Address = '$serverName'"

	if ($PingStatus.StatusCode -eq 0)
		{  
		  Write-Host $serverName  " is Online" -fore Green
		  Write-Host "Collecting logs from:" $serverName
		  $Events = get-winevent -FilterXml $xmlfilter -ComputerName $serverName -ErrorAction SilentlyContinue  
		  foreach ($event in $events)
		  {
		   $eventxml = [xml]$event.ToXml()

		   if ($event.Id -eq "4771")
			 {
			  $ipv4 = ($eventxml.Event.EventData.Data[6].'#text').Split(":")
			  $myObject = New-Object System.Object
			  $myObject | Add-Member -type NoteProperty -name "Source Machine" -Value $ipv4[($ipv4.length -1 )]
			  $myObject | Add-Member -type NoteProperty -name "Event ID" -Value "4771"
			  $SourceMachines += $myObject
			 } 
		   if ($event.Id -eq "4776")
			 {
			  $ipv4 = Resolve-DnsName ($eventxml.Event.EventData.Data[2].'#text')
			  $myObject = New-Object System.Object
			  $myObject | Add-Member -type NoteProperty -name "Source Machine" -Value $ipv4.IPAddress
			  $myObject | Add-Member -type NoteProperty -name "Event ID" -Value "4776"
			  $SourceMachines += $myObject
			   
			 }
		   if ($event.Id -eq "4625")
			 {
			  $ipv4 = Resolve-DnsName ($eventxml.Event.EventData.Data[2].'#text')
			  $myObject = New-Object System.Object
			  $myObject | Add-Member -type NoteProperty -name "Source Machine" -Value $ipv4.IPAddress
			  $myObject | Add-Member -type NoteProperty -name "Event ID" -Value "4625"
			  $SourceMachines += $myObject
			 }
		  }
		  if ($($Events.count) -eq 0) {
			Write-Host "[Info] Found $($Events.count) Events on $serverName for $UserName" -ForegroundColor Cyan
		  } else { Write-Host "[Warning] Found $($Events.count) Events on $serverName for $UserName" -BackgroundColor Red}
 		  
		  $AllEvents += $Events
		}
	Else 
	   {
		 Write-Host "$serverName is offline" -fore Red
	   }
	}

	# save the report 
	if ($AllEvents -ne 0)
	   { 
		 $AllEvents | Select-Object MachineName,TimeCreated,ProviderName,Id,@{n='Message';e={$_.Message -replace '\s+', " "}} | Export-Csv -Path  $CSVPath -NoTypeInformation
	   }
	if ($($AllEvents.count) -eq 0) {
		Write-Host "[Info] $($AllEvents.count) events found on all domain controllers `n" -ForegroundColor green
	} else { Write-Host "[Warning] $($AllEvents.count) events found on all domain controllers `n" -BackgroundColor Red}
	Write-Verbose "$AllEvents"

	if ($SourceMachines.Count -gt 0 )
	  {
		Write-Host "Summary of source machines for the bad password `n" -BackgroundColor Green -ForegroundColor Red
		$SourceMachines | Group-Object "Source Machine","Event ID"  -NoElement   | Sort-Object -Property Count -Descending
		$ExchangeServersIncluded = Compare-Object -ReferenceObject $SourceMachines."Source Machine"  -DifferenceObject $ExchangeServersIPv4  -IncludeEqual -ExcludeDifferent
		if ($ExchangeServersIncluded.InputObject.Length -gt 0 ) 
		   { 
			 Write-Host "`n Below Exchange Servers included in bad password source machines list `n" -BackgroundColor Green -ForegroundColor Red
			 $ExchangeServersIncluded.InputObject

			 $ExportExchangeLogs = read-host "`nDo you want to export IIS logs from mentioned Exchange servers (Yes/No)" 
			 if ($ExportExchangeLogs = "yes ")
				{
				  foreach ($ip in $ExchangeServersIncluded.InputObject)
					{
					  New-Item -ItemType Directory -Path "$fullpath\Exchange_$ip" -InformationAction SilentlyContinue -ErrorAction SilentlyContinue | Out-Null
					  Copy-Item -Path \\$ip\c$\inetpub\logs\LogFiles -Destination "$fullpath\LockoutLogs\Exchange_$ip" -Recurse -Force
					}
				}
		   }
	  }
} # end GetEventsFromAllDCs

# MAIN 
CheckDomainAdmin
CheckDomain
CheckUser
GetEventsFromAllDCs

# SIG # Begin signature block
# MIInqgYJKoZIhvcNAQcCoIInmzCCJ5cCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCCuyXxhWWTLwUiy
# ufbAHBcPVkt5DxCzOjZF8//7kFu1/6CCDYEwggX/MIID56ADAgECAhMzAAACzI61
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
# RcBCyZt2WwqASGv9eZ/BvW1taslScxMNelDNMYIZfzCCGXsCAQEwgZUwfjELMAkG
# A1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQx
# HjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEoMCYGA1UEAxMfTWljcm9z
# b2Z0IENvZGUgU2lnbmluZyBQQ0EgMjAxMQITMwAAAsyOtZamvdHJTgAAAAACzDAN
# BglghkgBZQMEAgEFAKCBrjAZBgkqhkiG9w0BCQMxDAYKKwYBBAGCNwIBBDAcBgor
# BgEEAYI3AgELMQ4wDAYKKwYBBAGCNwIBFTAvBgkqhkiG9w0BCQQxIgQgmquRGjwR
# Mp9dHMAE3VGAcV3Ak9K98D84lWJK/U0A84owQgYKKwYBBAGCNwIBDDE0MDKgFIAS
# AE0AaQBjAHIAbwBzAG8AZgB0oRqAGGh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbTAN
# BgkqhkiG9w0BAQEFAASCAQATWbEmop8sDyCfOXQx8bgdkNkXWWR21Tfur6IpQytv
# Dt0mG83l8oSvZZJx0pB1rSN4ULsU4AtwQTc8IDiqI6PbY3Bhf9UIKhZcjXXWKcm+
# dtnHVqemMMSZTVD6lY2XnUpjyqa5xJHc2RsBFtr/bGDQu7rXNcYT7b5f1F1ih2pA
# vk2SzJEXPbUkRp9VSRLaBhAGOGvzhv2jRqH9dM/0icGRae3Ks9gVGq7Tej185IC2
# EsXPecwujgsFJnCNtRP78zvm6B6gSd0SIntebPCRmf3EtGjTSR+x7VU2/dldJkQp
# Z/KejmAzuSl5cA0ZMghHtB7Roc0eGZwqgJwGYj0uqElOoYIXCTCCFwUGCisGAQQB
# gjcDAwExghb1MIIW8QYJKoZIhvcNAQcCoIIW4jCCFt4CAQMxDzANBglghkgBZQME
# AgEFADCCAVUGCyqGSIb3DQEJEAEEoIIBRASCAUAwggE8AgEBBgorBgEEAYRZCgMB
# MDEwDQYJYIZIAWUDBAIBBQAEIJ914XToTLMxXvQu/bEesF7cKKkt8HFLV1SU4xY+
# hizQAgZjToPZ0CAYEzIwMjIxMDI2MTQzMTM1LjA1NFowBIACAfSggdSkgdEwgc4x
# CzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRt
# b25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xKTAnBgNVBAsTIE1p
# Y3Jvc29mdCBPcGVyYXRpb25zIFB1ZXJ0byBSaWNvMSYwJAYDVQQLEx1UaGFsZXMg
# VFNTIEVTTjo0NjJGLUUzMTktM0YyMDElMCMGA1UEAxMcTWljcm9zb2Z0IFRpbWUt
# U3RhbXAgU2VydmljZaCCEVwwggcQMIIE+KADAgECAhMzAAABpAfP44+jum/WAAEA
# AAGkMA0GCSqGSIb3DQEBCwUAMHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNo
# aW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29y
# cG9yYXRpb24xJjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEw
# MB4XDTIyMDMwMjE4NTExOFoXDTIzMDUxMTE4NTExOFowgc4xCzAJBgNVBAYTAlVT
# MRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQK
# ExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xKTAnBgNVBAsTIE1pY3Jvc29mdCBPcGVy
# YXRpb25zIFB1ZXJ0byBSaWNvMSYwJAYDVQQLEx1UaGFsZXMgVFNTIEVTTjo0NjJG
# LUUzMTktM0YyMDElMCMGA1UEAxMcTWljcm9zb2Z0IFRpbWUtU3RhbXAgU2Vydmlj
# ZTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAMBHjgD6FPy81PUhcOIV
# Gh4bOSaq634Y+TjW2hNF9BlnWxLJCEuMiV6YF5x6YTM7T1ZLM6NnH0whPypiz3bV
# ZRmwgGyTURKfVyPJ89R3WaZ/HMvcAJZnCMgL+mOpxE94gwQJD/qo8UquOrCKCY/f
# cjchxV8yMkfIqP69HnWfW0ratk+I2GZF2ISFyRtvEuxJvacIFDFkQXj3H+Xy9IHz
# Nqqi+g54iQjOAN6s3s68mi6rqv6+D9DPVPg1ev6worI3FlYzrPLCIunsbtYt3Xw3
# aHKMfA+SH8CV4iqJ/eEZUP1uFJT50MAPNQlIwWERa6cccSVB5mN2YgHf8zDUqQU4
# k2/DWw+14iLkwrgNlfdZ38V3xmxC9mZc9YnwFc32xi0czPzN15C8wiZEIqCddxbw
# imc+0LtPKandRXk2hMfwg0XpZaJxDfLTgvYjVU5PXTgB10mhWAA/YosgbB8KzvAx
# XPnrEnYg3XLWkgBZ+lOrHvqiszlFCGQC9rKPVFPCCsey356VhfcXlvwAJauAk7V0
# nLVTgwi/5ILyHffEuZYDnrx6a+snqDTHL/ZqRsB5HHq0XBo/i7BVuMXnSSXlFCo3
# On8IOl8JOKQ4CrIlri9qWJYMxsSICscotgODoYOO4lmXltKOB0l0IAhEXwSSKID5
# QAa9wTpIagea2hzjI6SUY1W/AgMBAAGjggE2MIIBMjAdBgNVHQ4EFgQU4tATn6z4
# CBL2xZQd0jjN6SnjJMIwHwYDVR0jBBgwFoAUn6cVXQBeYl2D9OXSZacbUzUZ6XIw
# XwYDVR0fBFgwVjBUoFKgUIZOaHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3BraW9w
# cy9jcmwvTWljcm9zb2Z0JTIwVGltZS1TdGFtcCUyMFBDQSUyMDIwMTAoMSkuY3Js
# MGwGCCsGAQUFBwEBBGAwXjBcBggrBgEFBQcwAoZQaHR0cDovL3d3dy5taWNyb3Nv
# ZnQuY29tL3BraW9wcy9jZXJ0cy9NaWNyb3NvZnQlMjBUaW1lLVN0YW1wJTIwUENB
# JTIwMjAxMCgxKS5jcnQwDAYDVR0TAQH/BAIwADATBgNVHSUEDDAKBggrBgEFBQcD
# CDANBgkqhkiG9w0BAQsFAAOCAgEACVYcUNEMlyTuPDBGhiZ1U548ssF6J2g9QElW
# Eb2cZ4dL0+5G8721/giRtTPvgxQhDF5rJCjHGj8nFSqOE8fnYz9vgb2YclYHvkoK
# WUJODxjhWS+S06ZLR/nDS85HeDAD0FGduAA80Q7vGzknKW2jxoNHTb74KQEMWiUK
# 1M2PDN+eISPXPhPudGVGLbIEAk1Goj5VjzbQuLKhm2Tk4a22rkXkeE98gyNojHlB
# hHbb7nex3zGBTBGkVtwt2ud7qN2rcpuJhsJ/vL/0XYLtyOk7eSQZdfye0TT1/qj1
# 8iSXHsIXDhHOuTKqBiiatoo4Unwk7uGyM0lv38Ztr+YpajSP+p0PEMRH9RdfrKRm
# 4bHV5CmOTIzAmc49YZt40hhlVwlClFA4M+zn3cyLmEGwfNqD693hD5W3vcpnhf3x
# hZbVWTVpJH1CPGTmR4y5U9kxwysK8VlfCFRwYUa5640KsgIv1tJhF9LXemWIPEnu
# w9JnzHZ3iSw5dbTSXp9HmdOJIzsO+/tjQwZWBSFqnayaGv3Y8w1KYiQJS8cKJhwn
# hGgBPbyan+E5D9TyY9dKlZ3FikstwM4hKYGEUlg3tqaWEilWwa9SaNetNxjSfgah
# 782qzbjTQhwDgc6Jf07F2ak0YMnNJFHsBb1NPw77dhmo9ki8vrLOB++d6Gm2Z/jD
# pDOSst8wggdxMIIFWaADAgECAhMzAAAAFcXna54Cm0mZAAAAAAAVMA0GCSqGSIb3
# DQEBCwUAMIGIMQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4G
# A1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMTIw
# MAYDVQQDEylNaWNyb3NvZnQgUm9vdCBDZXJ0aWZpY2F0ZSBBdXRob3JpdHkgMjAx
# MDAeFw0yMTA5MzAxODIyMjVaFw0zMDA5MzAxODMyMjVaMHwxCzAJBgNVBAYTAlVT
# MRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQK
# ExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1l
# LVN0YW1wIFBDQSAyMDEwMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA
# 5OGmTOe0ciELeaLL1yR5vQ7VgtP97pwHB9KpbE51yMo1V/YBf2xK4OK9uT4XYDP/
# XE/HZveVU3Fa4n5KWv64NmeFRiMMtY0Tz3cywBAY6GB9alKDRLemjkZrBxTzxXb1
# hlDcwUTIcVxRMTegCjhuje3XD9gmU3w5YQJ6xKr9cmmvHaus9ja+NSZk2pg7uhp7
# M62AW36MEBydUv626GIl3GoPz130/o5Tz9bshVZN7928jaTjkY+yOSxRnOlwaQ3K
# Ni1wjjHINSi947SHJMPgyY9+tVSP3PoFVZhtaDuaRr3tpK56KTesy+uDRedGbsoy
# 1cCGMFxPLOJiss254o2I5JasAUq7vnGpF1tnYN74kpEeHT39IM9zfUGaRnXNxF80
# 3RKJ1v2lIH1+/NmeRd+2ci/bfV+AutuqfjbsNkz2K26oElHovwUDo9Fzpk03dJQc
# NIIP8BDyt0cY7afomXw/TNuvXsLz1dhzPUNOwTM5TI4CvEJoLhDqhFFG4tG9ahha
# YQFzymeiXtcodgLiMxhy16cg8ML6EgrXY28MyTZki1ugpoMhXV8wdJGUlNi5UPkL
# iWHzNgY1GIRH29wb0f2y1BzFa/ZcUlFdEtsluq9QBXpsxREdcu+N+VLEhReTwDwV
# 2xo3xwgVGD94q0W29R6HXtqPnhZyacaue7e3PmriLq0CAwEAAaOCAd0wggHZMBIG
# CSsGAQQBgjcVAQQFAgMBAAEwIwYJKwYBBAGCNxUCBBYEFCqnUv5kxJq+gpE8RjUp
# zxD/LwTuMB0GA1UdDgQWBBSfpxVdAF5iXYP05dJlpxtTNRnpcjBcBgNVHSAEVTBT
# MFEGDCsGAQQBgjdMg30BATBBMD8GCCsGAQUFBwIBFjNodHRwOi8vd3d3Lm1pY3Jv
# c29mdC5jb20vcGtpb3BzL0RvY3MvUmVwb3NpdG9yeS5odG0wEwYDVR0lBAwwCgYI
# KwYBBQUHAwgwGQYJKwYBBAGCNxQCBAweCgBTAHUAYgBDAEEwCwYDVR0PBAQDAgGG
# MA8GA1UdEwEB/wQFMAMBAf8wHwYDVR0jBBgwFoAU1fZWy4/oolxiaNE9lJBb186a
# GMQwVgYDVR0fBE8wTTBLoEmgR4ZFaHR0cDovL2NybC5taWNyb3NvZnQuY29tL3Br
# aS9jcmwvcHJvZHVjdHMvTWljUm9vQ2VyQXV0XzIwMTAtMDYtMjMuY3JsMFoGCCsG
# AQUFBwEBBE4wTDBKBggrBgEFBQcwAoY+aHR0cDovL3d3dy5taWNyb3NvZnQuY29t
# L3BraS9jZXJ0cy9NaWNSb29DZXJBdXRfMjAxMC0wNi0yMy5jcnQwDQYJKoZIhvcN
# AQELBQADggIBAJ1VffwqreEsH2cBMSRb4Z5yS/ypb+pcFLY+TkdkeLEGk5c9MTO1
# OdfCcTY/2mRsfNB1OW27DzHkwo/7bNGhlBgi7ulmZzpTTd2YurYeeNg2LpypglYA
# A7AFvonoaeC6Ce5732pvvinLbtg/SHUB2RjebYIM9W0jVOR4U3UkV7ndn/OOPcbz
# aN9l9qRWqveVtihVJ9AkvUCgvxm2EhIRXT0n4ECWOKz3+SmJw7wXsFSFQrP8DJ6L
# GYnn8AtqgcKBGUIZUnWKNsIdw2FzLixre24/LAl4FOmRsqlb30mjdAy87JGA0j3m
# Sj5mO0+7hvoyGtmW9I/2kQH2zsZ0/fZMcm8Qq3UwxTSwethQ/gpY3UA8x1RtnWN0
# SCyxTkctwRQEcb9k+SS+c23Kjgm9swFXSVRk2XPXfx5bRAGOWhmRaw2fpCjcZxko
# JLo4S5pu+yFUa2pFEUep8beuyOiJXk+d0tBMdrVXVAmxaQFEfnyhYWxz/gq77EFm
# PWn9y8FBSX5+k77L+DvktxW/tM4+pTFRhLy/AsGConsXHRWJjXD+57XQKBqJC482
# 2rpM+Zv/Cuk0+CQ1ZyvgDbjmjJnW4SLq8CdCPSWU5nR0W2rRnj7tfqAxM328y+l7
# vzhwRNGQ8cirOoo6CGJ/2XBjU02N7oJtpQUQwXEGahC0HVUzWLOhcGbyoYICzzCC
# AjgCAQEwgfyhgdSkgdEwgc4xCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5n
# dG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9y
# YXRpb24xKTAnBgNVBAsTIE1pY3Jvc29mdCBPcGVyYXRpb25zIFB1ZXJ0byBSaWNv
# MSYwJAYDVQQLEx1UaGFsZXMgVFNTIEVTTjo0NjJGLUUzMTktM0YyMDElMCMGA1UE
# AxMcTWljcm9zb2Z0IFRpbWUtU3RhbXAgU2VydmljZaIjCgEBMAcGBSsOAwIaAxUA
# NBwo4pNrfEL6DVo+tw96vGJvLp+ggYMwgYCkfjB8MQswCQYDVQQGEwJVUzETMBEG
# A1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWlj
# cm9zb2Z0IENvcnBvcmF0aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFt
# cCBQQ0EgMjAxMDANBgkqhkiG9w0BAQUFAAIFAOcDjfYwIhgPMjAyMjEwMjYxNDQ0
# MDZaGA8yMDIyMTAyNzE0NDQwNlowdDA6BgorBgEEAYRZCgQBMSwwKjAKAgUA5wON
# 9gIBADAHAgEAAgIBOjAHAgEAAgIRFDAKAgUA5wTfdgIBADA2BgorBgEEAYRZCgQC
# MSgwJjAMBgorBgEEAYRZCgMCoAowCAIBAAIDB6EgoQowCAIBAAIDAYagMA0GCSqG
# SIb3DQEBBQUAA4GBADu+Brje1Z3CvO5Qc9z/vM2VWKNPi0s7q0zszI64oNXRClbt
# Uk+KVrGkmxcEqE/GyOaRE+Gw1cheTxXEqNoU+4HHHJkR7Ti9L0f0yV9MhX/8ZLfc
# J2xIJWBcLtvJ29V7fZw9q+zUZWI8Q2ET+4xWAhv46z0h/L+SazSxGh3oc1U4MYIE
# DTCCBAkCAQEwgZMwfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24x
# EDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlv
# bjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTACEzMAAAGk
# B8/jj6O6b9YAAQAAAaQwDQYJYIZIAWUDBAIBBQCgggFKMBoGCSqGSIb3DQEJAzEN
# BgsqhkiG9w0BCRABBDAvBgkqhkiG9w0BCQQxIgQg6h8Fcqe8LfJsr8yfvAWfzlAF
# votqK8P23dSeBp8n8EowgfoGCyqGSIb3DQEJEAIvMYHqMIHnMIHkMIG9BCAF/OCj
# ISZwpMBJ8MJ3WwMCF3qOa5YHFG6J4uHjaup5+DCBmDCBgKR+MHwxCzAJBgNVBAYT
# AlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYD
# VQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJjAkBgNVBAMTHU1pY3Jvc29mdCBU
# aW1lLVN0YW1wIFBDQSAyMDEwAhMzAAABpAfP44+jum/WAAEAAAGkMCIEIIbH3P1n
# HA02LrkoOIdBCEc9mC1Y5jeHcX8GQ6b+HYgVMA0GCSqGSIb3DQEBCwUABIICAD06
# 3yZ19/gjeEX1lIeh8tjeDFXDA4VSv5yx6txNDSf3BGsO5lEBD3RNEjOq18gFQncx
# eJsHn6+7ZDwiA9udnXKe1h7GGd3n3LnD+wkqGlfyCYwl/Oi0ETgOAJvV8qSF+i9J
# 3NAlXmeUd43GeEa2BnM0beFnrUZFGtHx5+ZEsXPLcY3S96GcwSmRW9IDWRaIqtCt
# YkXz7sgZ7EHv2w4CMjGqlqtWpjSc4FdEF55UxTMe6ShPTDtMe/yQdATz060ZdahC
# UZXocJAHfn6OsSRAT1/l8nUSHxqn+BYB095/8Tjp1KIta4JSoGeZjI9b0oZOEYJI
# YR/eYm/OgRPf2rW4QqlQz4Cbhc7OOQr20ADAo6poS+Ds/d+nVjHKk0tXQMOVpvi2
# ie3bbvDR9Q+qYhJTFZLRR+QIYODKXQOWLMxhp2h0qj7/QmKOAvd0JR6Ichwv4RJr
# U8+cEo8Kc3fC2sg9ebEIEILkghNFCnHTdYiYj1ZS5bvtchiZALxVwVHpOKQTGqIB
# xyFIcPHX5TgSPnXk2PIyjCjKdRLruRt8TPbZItz6f3RaVZeO24+0MngDN19b+13j
# Cf2fL6SBR1aixXQXecT4FT1tVpPUGw6HhV4bv3cgN8xGwCjamdGuVonMUoslqY4R
# PgnD8mBRLe6QtZa5U5BBNGr0IiTgKhMtlVRrFCEa
# SIG # End signature block
