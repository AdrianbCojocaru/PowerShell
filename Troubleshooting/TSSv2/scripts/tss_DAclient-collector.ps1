<# Script name: tss_DAclient-collector.ps1
Purpose: - a script you can use to generate the same information that the DCA generates for DirectAccess
 see also DARA: DirectAccess troubleshooting guide https://internal.support.services.microsoft.com/en-US/help/2921221
#>

param(
	[Parameter(Mandatory=$False,Position=0,HelpMessage='Choose a writable output folder location, i.e. C:\Temp\ ')]
	[string]$DataPath = (Split-Path $MyInvocation.MyCommand.Path -Parent)
)

$ScriptVer="1.01"	#Date: 2018-12-19
$logfile = $DataPath+"\_DirectAccessCli_"+$env:COMPUTERNAME+"_"+(Get-Date -Format yyddMMhhmm)+".txt"

Write-Host "v$ScriptVer Starting collection of debug information for DirectAccess Client on this machine ..." -ForegroundColor White -BackgroundColor DarkGreen
Write-Host "... resulting Logfile: $logfile"
$user = whoami
write-output "v$ScriptVer - Direct Access connectivity status for user: $user is" | out-file -Encoding ascii $logfile
$date = Get-date
Write-output "DATE: $date" | Out-File -Encoding ascii -Append $logfile


# Get a List of all available DTEs
$RegDTEs = get-item hklm:\SOFTWARE\Policies\Microsoft\Windows\NetworkConnectivityAssistant\DTEs -EA SilentlyContinue
$DTEs=($RegDTEs).property -split ("PING:")
$DTEs= $DTEs | Where-Object {$_}
# $DTEs

# Get a List of all available Probes
# Separate them into icmp and http probes
$RegProbes = get-item "HKLM:\SOFTWARE\Policies\Microsoft\Windows\NetworkConnectivityAssistant\Probes" -EA SilentlyContinue
$probelist = ($RegProbes).property
$httpprobe = New-Object System.Collections.ArrayList
$ICMPProbe = New-Object System.Collections.ArrayList
foreach($probe in $probelist)
	{
		if($probe -match "http") {	$httpprobe = $httpprobe + $probe}
		else					 {	$ICMPProbe = $ICMPProbe + $probe}
	}
$httpprobe = $httpprobe -csplit "HTTP:"
$httpprobe = $httpprobe | Where-Object {$_}
$icmpprobe = $icmpprobe -csplit "PING:"
$icmpprobe = $icmpprobe | Where-Object {$_}

# $httpprobe
# $icmpprobe

# check if each of the probe URLs are accessible
if($httpprobe -gt 0)
{
Write-output "`n =============HTTP PROBES=============" | Out-File -Encoding ascii -Append $logfile
foreach ($URL in $httpprobe)
	{
		$result = (Invoke-WebRequest -Uri $URL).statusdescription
		Invoke-WebRequest -Uri $url -ErrorAction SilentlyContinue -ErrorVariable test
		if($result = 'OK' -and !$test)
			{    write-output "$url Pass" | Out-File -Encoding ascii -Append $logfile}
		elseif ($test -match "Unable to connect to the remote server" )
			{	write-output "$url (NAME Resolved)" | Out-File -Encoding ascii -Append $logfile}
		else 
			{	write-output "$url Failed" | Out-File -Encoding ascii -Append $logfile}
	}
}
else
{
Write-output "There are no HTTP probes configured" | Out-File -Encoding ascii -Append $logfile
}	

# check if each ICMP probe is accessible
if($icmpprobe -gt 0)
{
Write-output "`n =============ICMP PROBES=============" | Out-File -Encoding ascii -Append $logfile
foreach($ip in $icmpprobe)
	{
		$result = ping $ip -n 1
		if($result -match "Packets: Sent = 1, Received = 1, Lost = 0")
			{	write-output "$ip PASS" | Out-File -Encoding ascii -Append $logfile}
		elseif($result -match "Pinging")
			{	write-output "$ip Name resolved But ping failed" | Out-File -Encoding ascii -Append $logfile}
		else
			{	write-output "$ip Failed to resolve name" | Out-File -Encoding ascii -Append $logfile}
	}
}
else 
{
Write-output "There are no ICMP probes configured" | Out-File -Encoding ascii -Append $logfile
}

# check if DTEs are pingable
Write-output "`n =============DTEs=============" | Out-File -Encoding ascii -Append $logfile
if ($DTEs) {
  foreach($ip in $DTEs)
	{
		$result = ping $ip -n 1
		if($result -match "Packets: Sent = 1, Received = 1, Lost = 0")
			{	write-output "DTE: $ip PASS" | Out-File -Encoding ascii -Append $logfile}
		else
			{	write-output "DTE: $ip Fail" | Out-File -Encoding ascii -Append $logfile}
	}		
  }
  else
			{	write-output "There are no DTE's to test configured in `n HKLM\SOFTWARE\Policies\Microsoft\Windows\NetworkConnectivityAssistant\DTEs " | Out-File -Encoding ascii -Append $logfile}

Write-output "`n _____ IP Configuration (Get-NetIPConfiguration -All -Detailed)" | Out-File -Encoding ascii -Append $logfile
Get-NetIPConfiguration -All -Detailed | Out-File -Encoding ascii -Append $logfile

Write-output "`n _____ System Info (systeminfo)" | Out-File -Encoding ascii -Append $logfile
systeminfo | Out-File -Encoding ascii -Append $logfile

Write-output "`n _____ 6to4 State (Netsh int 6to4 show state)" | Out-File -Encoding ascii -Append $logfile
Netsh int 6to4 show state | Out-File -Encoding ascii -Append $logfile
Write-output "`n _____ teredo State (Netsh int teredo show state)" | Out-File -Encoding ascii -Append $logfile
Netsh int teredo show state | Out-File -Encoding ascii -Append $logfile
Write-output "`n _____ httpstunnel Int (Netsh int httpstunnel show int)" | Out-File -Encoding ascii -Append $logfile
Netsh int httpstunnel show int | Out-File -Encoding ascii -Append $logfile
Write-output "`n _____ dnsclient State (Netsh dnsclient show state)" | Out-File -Encoding ascii -Append $logfile
Netsh dnsclient show state | Out-File -Encoding ascii -Append $logfile

Write-output "`n _____ 6to4 Configuration (Get-Net6to4Configuration)" | Out-File -Encoding ascii -Append $logfile
Get-Net6to4Configuration | Out-File -Encoding ascii -Append $logfile

Write-output "`n _____ Proxy Configuration (netsh winhttp show proxy)" | Out-File -Encoding ascii -Append $logfile
netsh winhttp show proxy | Out-File -Encoding ascii -Append $logfile

Write-output "`n _____ Teredo Configuration (Get-NetTeredoConfiguration)" | Out-File -Encoding ascii -Append $logfile
Get-NetTeredoConfiguration | Out-File -Encoding ascii -Append $logfile

Write-output "`n _____ Teredo State (Get-NetTeredoState)" | Out-File -Encoding ascii -Append $logfile
Get-NetTeredoState | Out-File -Encoding ascii -Append $logfile

Write-output "`n _____ HTTPs Configuration (Get-NetIPHttpsConfiguration)" | Out-File -Encoding ascii -Append $logfile
Get-NetIPHttpsConfiguration | Out-File -Encoding ascii -Append $logfile

Write-output "`n _____ IP-HTTPs State (Get-NetIPHttpsState)" | Out-File -Encoding ascii -Append $logfile
Get-NetIPHttpsState | Out-File -Encoding ascii -Append $logfile

Write-output "`n _____ Certificate Store (root) (certutil -store root)" | Out-File -Encoding ascii -Append $logfile
certutil -store root | Out-File -Encoding ascii -Append $logfile

Write-output "`n _____ NRPT Policy (Get-DnsClientNrptPolicy)" | Out-File -Encoding ascii -Append $logfile
Get-DnsClientNrptPolicy | Out-File -Encoding ascii -Append $logfile
Write-output "`n _____ NCSI Policy (Get-NCSIPolicyConfiguration)" | Out-File -Encoding ascii -Append $logfile
Get-NCSIPolicyConfiguration | Out-File -Encoding ascii -Append $logfile

Write-output "`n _____ Winsock Catalog (netsh winsock show catalog)" | Out-File -Encoding ascii -Append $logfile
netsh winsock show catalog | Out-File -Encoding ascii -Append $logfile

Write-output "`n _____ WFP Netevents (netsh wfp show netevents file=-)" | Out-File -Encoding ascii -Append $logfile
netsh wfp show netevents file=- | Out-File -Encoding ascii -Append $logfile

Write-output "`n _____ IPsec Rules (Show-NetIPsecRule -PolicyStore ActiveStore)" | Out-File -Encoding ascii -Append $logfile
Show-NetIPsecRule -PolicyStore ActiveStore | Out-File -Encoding ascii -Append $logfile

Write-output "`n _____ IPsec Main Mode SA's (Get-NetIPsecMainModeSA)" | Out-File -Encoding ascii -Append $logfile
Get-NetIPsecMainModeSA | Out-File -Encoding ascii -Append $logfile

Write-output "`n _____ IPsec Quick Mode SA's (Get-NetIPsecQuickModeSA)" | Out-File -Encoding ascii -Append $logfile
Get-NetIPsecQuickModeSA | Out-File -Encoding ascii -Append $logfile

Write-output "`n _____ IP Address (Get-NetIPAddress)" | Out-File -Encoding ascii -Append $logfile
Get-NetIPAddress | Out-File -Encoding ascii -Append $logfile

Write-output "`n _____ Route (Get-NetRoute)" | Out-File -Encoding ascii -Append $logfile
Get-NetRoute | Out-File -Encoding ascii -Append $logfile

Write-output "`n _____ DA Multisite (Get-DAEntryPointTableItem)" | Out-File -Encoding ascii -Append $logfile
Get-DAEntryPointTableItem | Out-File -Encoding ascii -Append $logfile

Write-output "`n _____ DA ConnectionStatus (Get-DAConnectionStatus)" | Out-File -Encoding ascii -Append $logfile
$DaStat_Temp = Get-DAConnectionStatus -EA SilentlyContinue
if ($DaStat_Temp) {
		Get-DAConnectionStatus | Out-File -Encoding ascii -Append $logfile}
Write-output "`n _____ DA Settings (Get-DAClientExperienceConfiguration)" | Out-File -Encoding ascii -Append $logfile
Get-DAClientExperienceConfiguration | Out-File -Encoding ascii -Append $logfile

Write-output "`n _____ Prefix Policy Table (Get-NetPrefixPolicy)" | Out-File -Encoding ascii -Append $logfile
Get-NetPrefixPolicy | Out-File -Encoding ascii -Append $logfile

Write-output "`n _____ Certificate Store (my) (certutil -silent -store -user my)" | Out-File -Encoding ascii -Append $logfile
certutil -silent -store -user my | Out-File -Encoding ascii -Append $logfile

Write-output "`n _____ Groups (whoami /all)" | Out-File -Encoding ascii -Append $logfile
whoami /all | Out-File -Encoding ascii -Append $logfile

Write-output "`n _____ === END of DAclient collector ===" | Out-File -Encoding ascii -Append $logfile	

Write-Host "$(Get-Date -Format 'HH:mm:ss') Done - tss_DAclient-collector`n" -ForegroundColor White -BackgroundColor DarkGreen
# SIG # Begin signature block
# MIInqgYJKoZIhvcNAQcCoIInmzCCJ5cCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCACji+T5RwWtKZm
# 2GTHPvB1gORPisnPxsUzvRCMsUapZ6CCDYEwggX/MIID56ADAgECAhMzAAACzI61
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
# BgEEAYI3AgELMQ4wDAYKKwYBBAGCNwIBFTAvBgkqhkiG9w0BCQQxIgQgRd5fZcIM
# VM4cBZTS9n90bDoD7B11e8yRnCOab2HCtx0wQgYKKwYBBAGCNwIBDDE0MDKgFIAS
# AE0AaQBjAHIAbwBzAG8AZgB0oRqAGGh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbTAN
# BgkqhkiG9w0BAQEFAASCAQB6/bE9GCNycpW1qN7lY0ncDPWD412uIJe+pxr/u8nP
# ISchyY8HXymLGxO9HQjtJZ0EcxracvZ0c38LzNeaJXvCwLMQuG3KHqKntlaGtgOE
# Mo/IaBkMEuUETf0m5r/tiiGyefbVuOsTF3CRUpc8OiVNGf6544xsWtAqkD49N5+b
# fvL/stOAEGcn9SVpLr2DtBHGT3kM0cps6jqEPn5KugW0TYsqwIGLWe7QUqWbDEH0
# VOVCGxG9N0akQ2h2G3I733xLwE7T02VafreDwD1DBc2L8E+GZOT1lJYftsZv+qoE
# rRimJENeu7TBfJ9CSsGTDd7eHvncfyrxugagZ658VoY+oYIXCTCCFwUGCisGAQQB
# gjcDAwExghb1MIIW8QYJKoZIhvcNAQcCoIIW4jCCFt4CAQMxDzANBglghkgBZQME
# AgEFADCCAVUGCyqGSIb3DQEJEAEEoIIBRASCAUAwggE8AgEBBgorBgEEAYRZCgMB
# MDEwDQYJYIZIAWUDBAIBBQAEIDsytF7zrtEkGBeTK1poqLBFLtbf1WXm9gJZIGHS
# eY3HAgZjTtWpM2kYEzIwMjIxMDI2MTQzMTM0LjI2OFowBIACAfSggdSkgdEwgc4x
# CzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRt
# b25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xKTAnBgNVBAsTIE1p
# Y3Jvc29mdCBPcGVyYXRpb25zIFB1ZXJ0byBSaWNvMSYwJAYDVQQLEx1UaGFsZXMg
# VFNTIEVTTjo0RDJGLUUzREQtQkVFRjElMCMGA1UEAxMcTWljcm9zb2Z0IFRpbWUt
# U3RhbXAgU2VydmljZaCCEVwwggcQMIIE+KADAgECAhMzAAABsKHjgzLojTvAAAEA
# AAGwMA0GCSqGSIb3DQEBCwUAMHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNo
# aW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29y
# cG9yYXRpb24xJjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEw
# MB4XDTIyMDMwMjE4NTE0MloXDTIzMDUxMTE4NTE0Mlowgc4xCzAJBgNVBAYTAlVT
# MRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQK
# ExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xKTAnBgNVBAsTIE1pY3Jvc29mdCBPcGVy
# YXRpb25zIFB1ZXJ0byBSaWNvMSYwJAYDVQQLEx1UaGFsZXMgVFNTIEVTTjo0RDJG
# LUUzREQtQkVFRjElMCMGA1UEAxMcTWljcm9zb2Z0IFRpbWUtU3RhbXAgU2Vydmlj
# ZTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAJzGbTsM19KCnQc5RC7V
# oglySXMKLut/yWWPQWD6VAlJgBexVKx2n1zgX3o/xA2ZgZ/NFGcgNDRCJ7mJiOeW
# 7xeHnoNXPlg7EjYWulfk3oOAj6a7O15GvckpYsvLcx+o8Se8CrfIb40EJ8W0Qx4T
# IXf0yDwAJ4/qO94dJ/hGabeJYg4Gp0G0uQmhwFovAWTHlD1ci+sp36AxT9wIhHqw
# /70tzMvrnDF7jmQjaVUPnjOgPOyFWZiVr7e6rkSl4anT1tLv23SWhXqMs14wolv4
# ZeQcWP84rV2Frr1KbwkIa0vlHjlv4xG9a6nlTRfo0CYUQDfrZOMXCI5KcAN2BZ6f
# Vb09qtCdsWdNNxB0y4lwMjnuNmx85FNfzPcMZjmwAF9aRUUMLHv626I67t1+dZoV
# PpKqfSNmGtVt9DETWkmDipnGg4+BdTplvgGVq9F3KZPDFHabxbLpSWfXW90MZXOu
# FH8yCMzDJNUzeyAqytFFyLZir3j4T1Gx7lReCOUPw1puVzbWKspV7ModZjtN/IUW
# dVIdk3HPp4QN1wwdVvdXOsYdhG8kgjGyAZID5or7C/75hyKQb5F0Z+Ee04uY9K+s
# DZ3l3z8TQZWAfYurbZCMWWnmJVsu5V4PR5PO+U6D7tAtMvMULNYibT9+sxVZK/WQ
# er2JJ9q3Z7ljFs4lgpmfc6AVAgMBAAGjggE2MIIBMjAdBgNVHQ4EFgQUOt8BJDcB
# Jm4dy6ASZHrXIEfWNj8wHwYDVR0jBBgwFoAUn6cVXQBeYl2D9OXSZacbUzUZ6XIw
# XwYDVR0fBFgwVjBUoFKgUIZOaHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3BraW9w
# cy9jcmwvTWljcm9zb2Z0JTIwVGltZS1TdGFtcCUyMFBDQSUyMDIwMTAoMSkuY3Js
# MGwGCCsGAQUFBwEBBGAwXjBcBggrBgEFBQcwAoZQaHR0cDovL3d3dy5taWNyb3Nv
# ZnQuY29tL3BraW9wcy9jZXJ0cy9NaWNyb3NvZnQlMjBUaW1lLVN0YW1wJTIwUENB
# JTIwMjAxMCgxKS5jcnQwDAYDVR0TAQH/BAIwADATBgNVHSUEDDAKBggrBgEFBQcD
# CDANBgkqhkiG9w0BAQsFAAOCAgEA3XPih5sNtUfAyLnlXq6MZSpCh0TF+uG+nhIJ
# 44//cMcQGEViZ2N263NwvrQjCFOni/+oxf76jcmUhcKWLXk9hhd7vfFBhZZzcF5a
# Ns07Uligs24pveasFuhmJ4y82OYm1G1ORYsFndZdvF//NrYGxaXqUNlRHQlskV/p
# mccqO3Oi6wLHcPB1/WRTLJtYbIiiwE/uTFEFEL45wWD/1mTCPEkFX3hliXEypxXz
# dZ1k6XqGTysGAtLXUB7IC6CH26YygKQuXG8QjcJBAUG/9F3yNZOdbFvn7FinZyNc
# IVLxld7h0bELfQzhIjelj+5sBKhLcaFU0vbjbmf0WENgFmnyJNiMrL7/2FYOLsgi
# QDbJx6Dpy1EfvuRGsdL5f+jVVds5oMaKrhxgV7oEobrA6Z56nnWYN47swwouucHf
# 0ym1DQWHy2DHOFRRN7yv++zes0GSCOjRRYPK7rr1Qc+O3nsd604Ogm5nR9QqhOOc
# 2OQTrvtSgXBStu5vF6W8DPcsns53cQ4gdcR1Y9Ng5IYEwxCZzzYsq9oalxlH+ZH/
# A6J7ZMeSNKNkrXPx6ppFXUxHuC3k4mzVyZNGWP/ZgcUOi2qV03m6Imytvi1kfGe6
# YdCh32POgWeNH9lfKt+d1M+q4IhJLmX0E2ZZICYEb9Q0romeMX8GZ+cbhuNsFimJ
# ga/fjjswggdxMIIFWaADAgECAhMzAAAAFcXna54Cm0mZAAAAAAAVMA0GCSqGSIb3
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
# MSYwJAYDVQQLEx1UaGFsZXMgVFNTIEVTTjo0RDJGLUUzREQtQkVFRjElMCMGA1UE
# AxMcTWljcm9zb2Z0IFRpbWUtU3RhbXAgU2VydmljZaIjCgEBMAcGBSsOAwIaAxUA
# Ap4vkN3fD5FNBVYZklZeS/JFPBiggYMwgYCkfjB8MQswCQYDVQQGEwJVUzETMBEG
# A1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWlj
# cm9zb2Z0IENvcnBvcmF0aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFt
# cCBQQ0EgMjAxMDANBgkqhkiG9w0BAQUFAAIFAOcDNwEwIhgPMjAyMjEwMjYwODMz
# MDVaGA8yMDIyMTAyNzA4MzMwNVowdDA6BgorBgEEAYRZCgQBMSwwKjAKAgUA5wM3
# AQIBADAHAgEAAgIIyzAHAgEAAgIRMzAKAgUA5wSIgQIBADA2BgorBgEEAYRZCgQC
# MSgwJjAMBgorBgEEAYRZCgMCoAowCAIBAAIDB6EgoQowCAIBAAIDAYagMA0GCSqG
# SIb3DQEBBQUAA4GBAIWTnZm9L0gheE7yHI+hsoKPIedjKzLAcTGK5DmTQPm2qOpN
# oLbqFxCFgCoFIa2XTgXjceRn9gQG0KOLAWmCcaeMAkp/4jABmiXekqIhotjRrWg8
# RKHGKVpQSVoX0KJQh4G/9F6Rp2QM6lFUkBS5cxwna/IvECPVnY4pOs6FDQTpMYIE
# DTCCBAkCAQEwgZMwfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24x
# EDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlv
# bjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTACEzMAAAGw
# oeODMuiNO8AAAQAAAbAwDQYJYIZIAWUDBAIBBQCgggFKMBoGCSqGSIb3DQEJAzEN
# BgsqhkiG9w0BCRABBDAvBgkqhkiG9w0BCQQxIgQgDPY///vpLIbTI0QtVPBerVtK
# 1ddF/9oC1mjHPyyioccwgfoGCyqGSIb3DQEJEAIvMYHqMIHnMIHkMIG9BCDNBgtD
# d8uf9KTjGf1G67IfKmcNFJmeWTd6ilAy5xWEoDCBmDCBgKR+MHwxCzAJBgNVBAYT
# AlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYD
# VQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJjAkBgNVBAMTHU1pY3Jvc29mdCBU
# aW1lLVN0YW1wIFBDQSAyMDEwAhMzAAABsKHjgzLojTvAAAEAAAGwMCIEIJnGjdQX
# 0ajuU6uNC5lE1XzNLRPATJne9uPahD1tmpGVMA0GCSqGSIb3DQEBCwUABIICAEuI
# x/SwUT92/YB+xfQAfCcz/R5VHd+dLkuAYt236EQLv3kC0gD2doMbxMjWzEmAN+9j
# IJMzy2KC8C1AmXsrdWz4cZErzVjwhowPXb7C39gMUFO/iG2pxDBBWDJh0G466vDd
# adwDdYniChW8WdXtE2viy1c1QrSJwxIKQXyrjy0PNJ7jlbZzDH4DQhbumBpxJdr7
# 7V+44NV4KubLu+Tzii4jlUiKXvd3XRtGkNbYqhLEwYznPhHZhVUR0FLOfdwcohZb
# yPrlxOMUOqKkM07lFG33ndGwXrzq5ilUjSveq/6PfSTavARO/7q2p/2VH0k0HgZ8
# 397iDSJvnbDd1A836+OCoQV111UmVknpyb89QhGzgMDvVFJ4upy93SdQmjgPep/3
# QMSavQEizySpiniIKzSQ7K2nzA6897XVD97iwaZqZlE8EnXxA2fxavHhJFJXzZN2
# o/ZNpj/s5Zt1dpdGnfUxaPzAkLIDK782YW/OHXD5XvVnlOaBRK/+HJDLN2oOLpRy
# 9y28jGKfVn1W4j+xeCrN98hl/6742maMrZ5apHTcOqRSzc/lCsrDREbbic1O8gBH
# 6ONDXXWTcNpsVMMZR1guPNd0lI/jKX8XdB05OhjDFf3HHtDWh0O/v3oK+cIsrzxp
# 2OR7UIV/hxgU2qLevnw2Yc07Iods1rybzghQihNu
# SIG # End signature block
