﻿#************************************************
# TS_ProcOverview.ps1
# Version 1.0.1
# Date: 2-2-2010
# Author: Andre Teixeira - andret@microsoft.com
# Description: This script executes a series of WMI queries to obtain process statistics - such as top process by handle count/ memory usage and so.
#              Also, it shows statistics for Kernel Pool memory usage using MemSnap tool
#************************************************


trap 
{
	$errorMessage = "Error [{4}]:`r`n Category {0}, Error Type {1}, ID: {2}, Message: {3}" -f  $_.CategoryInfo.Category, $_.Exception.GetType().FullName,  $_.FullyQualifiedErrorID, $_.Exception.Message, $_.InvocationInfo.PositionMessage
	$errorMessage | WriteTo-StdOut
	continue
}

Import-LocalizedData -BindingVariable ProcInfoStrings

Write-DiagProgress -Activity $ProcInfoStrings.ID_ProcInfo -Status $ProcInfoStrings.ID_ProcInfoObtaining

$KernelGraph = "<span xmlns:v=`"urn:schemas-microsoft-com:vml`"><v:group id=`"GraphValue`" class=`"vmlimage`" style=`"width:300px;height:15px;vertical-align:middle`" coordsize=`"{MaxValue},100`" title=`"{ValueDisplay}`"><v:rect class=`"vmlimage`" style=`"top:1;left:1;width:{MaxValue};height:100`" strokecolor=`"#336699`"><v:fill type=`"gradient`" angle=`"0`" color=`"#C4CCC7`" color2=`"white`" /></v:rect><v:rect class=`"vmlimage`" style=`"top:2;left:2;width:{Value};height:99`" strokecolor=`"{GraphColorEnd}`"><v:fill type=`"gradient`" angle=`"270`" color=`"{GraphColorStart}`" color2=`"{GraphColorEnd}`" /></v:rect></v:group></span>"
$ProcGraph   = "<span xmlns:v=`"urn:schemas-microsoft-com:vml`"><v:group id=`"GraphValue`" class=`"vmlimage`" style=`"width:200px;height:15px;vertical-align:middle`" coordsize=`"{MaxValue},100`" title=`"{ValueDisplay}`"><v:rect class=`"vmlimage`" style=`"top:1;left:1;width:{MaxValue};height:100`" strokecolor=`"#336699`"><v:fill type=`"gradient`" angle=`"0`" color=`"#C4CCC7`" color2=`"white`" /></v:rect><v:rect class=`"vmlimage`" style=`"top:2;left:1;width:{Value};height:99`" strokecolor=`"{GraphColorEnd}`"><v:fill type=`"gradient`" angle=`"270`" color=`"{GraphColorStart}`" color2=`"{GraphColorEnd}`" /></v:rect><v:rect style=`"top:-70;left:1;width:{MaxValue};height:50`" filled=`"false`" stroked=`"false`" textboxrect=`"top:19;left:1;width:{MaxValue};height:30`"><v:textbox style=`"color:white;`" inset=`"10px, 10px, 28px, 177px`">{ValueDisplay}</v:textbox></v:rect></v:group></span>"

$sectionDescription = "Processes and Kernel Memory information"
$fileDescription = "Processess/Performance Information"
$OutputFile = $ComputerName + "_ProcessesPerfInfo.htm"
$CommandToExecute = "cscript.exe ProcessesPerfInfo.vbs /generatescripteddiagxmlalerts"

$OutputXMLFileName = ($Computername + "_ProcessesPerfInfo.xml")

if (-not (Test-Path $OutputXMLFileName))
{

	RunCmD -commandToRun $CommandToExecute -sectionDescription $sectionDescription -filesToCollect $OutputFile -fileDescription $fileDescription

	[xml] $ProcOverviewXML = Get-Content $OutputXMLFileName

	$MAXITEMS_TO_DISPLAY = 3

	$PoolMemoryXML = $ProcOverviewXML.SelectSingleNode("//Section[SectionTitle = 'Kernel Memory Information']")

	foreach ($PoolMemorySection in $PoolMemoryXML.SubSection) 
	{
		$Item_Summary = new-object PSObject
		$PoolMemorySectionTitle = $PoolMemorySection.SectionTitle.get_InnerText()
		$MaxValue = $PoolMemorySection.KernelMemory.MaxValue.get_InnerText()
		$Displayed = 0
		foreach ($Tag in $PoolMemorySection.SelectNodes("KernelMemory/PoolMemory"))
		{
			$Displayed++
			if ($Displayed -le $MAXITEMS_TO_DISPLAY) {
				$TagName = $Tag.Tag.get_InnerText()
				$MemoryAllocationDisplay = $Tag.ValueDisplay.get_InnerText()
				$MemoryAllocationValue = $Tag.Value.get_InnerText()
				$GraphColorStart = $Tag.GraphColorStart.get_InnerText()
				$GraphColorEnd = $Tag.GraphColorEnd.get_InnerText()
				
				$Graph = $KernelGraph -replace "{MaxValue}", "$MaxValue" -replace "{ValueDisplay}", "$MemoryAllocationDisplay" -replace "{Value}", "$MemoryAllocationValue" -replace "{GraphColorStart}", "$GraphColorStart" -replace "{GraphColorEnd}", "$GraphColorEnd"
				
				add-member -inputobject $Item_Summary  -membertype noteproperty -name $TagName -value ("<table><tr><td width=`"100px`">$MemoryAllocationDisplay</td><td> $Graph</td></tr></table>")
			}
		}
		$Item_Summary | ConvertTo-Xml2 | update-diagreport -id ("52_$PoolMemorySectionTitle") -name $PoolMemorySectionTitle -verbosity informational
	}

	$ProcXML = $ProcOverviewXML.SelectSingleNode("//Section[SectionTitle = 'Process Statistics']")

	$Item_Summary = new-object PSObject
	foreach ($ProcSection in $ProcXML.SubSection) 
	{
		$ProcSectionTitle = $ProcSection.SectionTitle.get_InnerText()
		$MaxValue = $ProcSection.ProcessCollection.MaxValue.get_InnerText()
		$Displayed = 0
		#$MaxValue = $null
		$Line = ""
		foreach ($Process in $ProcSection.SelectNodes("ProcessCollection/Process"))
		{
			$Displayed++
			if ($Displayed -lt $MAXITEMS_TO_DISPLAY) {
				$ProcessName = $Process.Name.get_InnerText()
				$Display = $Process.ValueDisplay.get_InnerText()
				$Value = $Process.Value.get_InnerText()
				$GraphColorStart = $Process.GraphColorStart.get_InnerText()
				$GraphColorEnd = $Process.GraphColorEnd.get_InnerText()
				
				#if ($MaxValue -eq $null) 
				#{
				#	$MaxValue = ([int] $Value * 1.2)
				#}
				
				$Graph = $ProcGraph -replace "{MaxValue}", "$MaxValue" -replace "{ValueDisplay}", "$Display" -replace "{Value}", "$Value" -replace "{GraphColorStart}", "$GraphColorStart" -replace "{GraphColorEnd}", "$GraphColorEnd"
				$Line += "<table><tr><td width=`"120px`">$ProcessName</td><td> $Graph</td></tr></table>"
			}
		}
		add-member -inputobject $Item_Summary  -membertype noteproperty -name $ProcSectionTitle -value $Line
	}

	add-member -inputobject $Item_Summary -membertype noteproperty -name "More Information" -value ("For more information, please open the file <a href= `"`#" + $OutputFile + "`">" + $OutputFile + "</a>.")

	$Item_Summary | ConvertTo-Xml2 | update-diagreport -id ("50_ProcSummary") -name "Processes Summary" -verbosity informational

	$RootCauseXMLFilename = ($ComputerName + "_ProcessesPerfInfoRootCauses.XML")
	if (Test-Path ($RootCauseXMLFilename))
	{ 
		$RootCauseDetectedHash = @{}
		[xml] $XMLRootCauses = Get-Content -Path $RootCauseXMLFilename
		Foreach ($RootCauseDetected in $XMLRootCauses.SelectNodes("/Root/RootCause"))
		{
			$InformationCollected = @{}
			$ProcessName = $null
			switch ($RootCauseDetected.name)
			{
				"RC_HighHandleCount"
				{
					$InformationCollected = @{"Process Name" = $RootCauseDetected.param1; 
											  "Process ID" = $RootCauseDetected.param2;
											  "Current Handle Count" = $RootCauseDetected.CurrentValue}
					$ProcessName = $RootCauseDetected.param1
					$PublicURL = "http://blogs.technet.com/b/markrussinovich/archive/2009/09/29/3283844.aspx"
				}
				
				"RC_KernelMemoryPerformanceIssue"
				{
					$InformationCollected = @{"Kernel Tag Name" = $RootCauseDetected.param1; 
											  "Pool Memory Type" = $RootCauseDetected.param2;
											  "Current Allocated (MB)" = $RootCauseDetected.CurrentValue;
											  "Current Allocated (%)" = ($RootCauseDetected.ExpectedValue + "%")}
					$PublicURL = "http://blogs.technet.com/b/askperf/archive/2008/04/11/an-introduction-to-pool-tags.aspx"
				}
				"RC_LowSysPTEs"
				{
					$InformationCollected = @{"Current SysPTEs count" = $RootCauseDetected.CurrentValue}; 			
					$PublicURL = "http://blogs.technet.com/b/askperf/archive/2008/05/16/troubleshooting-server-hangs-part-four.aspx"
				}
				
				"RC_LowVirtualMemory"
				{
					$InformationCollected = @{"Committed Bytes In Use (%)" = $RootCauseDetected.CurrentValue};
					$TopProcesses = Get-Process | Sort-Object -Property VM -Descending | Select-Object -First 3
					$X = 1
					foreach ($Process in $TopProcesses)
					{
						$InformationCollected += @{"Top Process [$X] Memory Usage" = ($Process.Name + " (ID " + $Process.Id.ToString() + "): " + (FormatBytes $Process.VirtualMemorySize64))};
						$X++
					}
					$PublicURL = "http://blogs.technet.com/b/askperf/archive/2008/01/25/an-overview-of-troubleshooting-memory-issues.aspx"
				}			
			}
		
			if ($RootCauseDetectedHash.ContainsKey($RootCauseDetected.name) -eq $false) 
			{
				$RootCauseDetectedHash += @{$RootCauseDetected.name = $true}
			}
			
			Write-GenericMessage -RootCauseID $RootCauseDetected.name -Verbosity $RootCauseDetected.Type -InformationCollected $InformationCollected -ProcessName $ProcessName -PublicContentURL $PublicURL -Visibility 4 -MessageVersion 2
		}
		foreach ($RootCause in $RootCauseDetectedHash.get_Keys())
		{
			Update-DiagRootCause -Id $RootCause -Detected $true
		}
	}
}
else
{
	"[ProcessInfo] - Skipped execution as $OutputXMLFileName already exists"  | WriteTo-StdOut
}
# SIG # Begin signature block
# MIIjiAYJKoZIhvcNAQcCoIIjeTCCI3UCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCC/aihql+O+CmWH
# +XJrsVScX+JH98kD7DNLk5DFE6prfqCCDYEwggX/MIID56ADAgECAhMzAAAB32vw
# LpKnSrTQAAAAAAHfMA0GCSqGSIb3DQEBCwUAMH4xCzAJBgNVBAYTAlVTMRMwEQYD
# VQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMTH01pY3Jvc29mdCBDb2RlIFNpZ25p
# bmcgUENBIDIwMTEwHhcNMjAxMjE1MjEzMTQ1WhcNMjExMjAyMjEzMTQ1WjB0MQsw
# CQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9u
# ZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMR4wHAYDVQQDExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIB
# AQC2uxlZEACjqfHkuFyoCwfL25ofI9DZWKt4wEj3JBQ48GPt1UsDv834CcoUUPMn
# s/6CtPoaQ4Thy/kbOOg/zJAnrJeiMQqRe2Lsdb/NSI2gXXX9lad1/yPUDOXo4GNw
# PjXq1JZi+HZV91bUr6ZjzePj1g+bepsqd/HC1XScj0fT3aAxLRykJSzExEBmU9eS
# yuOwUuq+CriudQtWGMdJU650v/KmzfM46Y6lo/MCnnpvz3zEL7PMdUdwqj/nYhGG
# 3UVILxX7tAdMbz7LN+6WOIpT1A41rwaoOVnv+8Ua94HwhjZmu1S73yeV7RZZNxoh
# EegJi9YYssXa7UZUUkCCA+KnAgMBAAGjggF+MIIBejAfBgNVHSUEGDAWBgorBgEE
# AYI3TAgBBggrBgEFBQcDAzAdBgNVHQ4EFgQUOPbML8IdkNGtCfMmVPtvI6VZ8+Mw
# UAYDVR0RBEkwR6RFMEMxKTAnBgNVBAsTIE1pY3Jvc29mdCBPcGVyYXRpb25zIFB1
# ZXJ0byBSaWNvMRYwFAYDVQQFEw0yMzAwMTIrNDYzMDA5MB8GA1UdIwQYMBaAFEhu
# ZOVQBdOCqhc3NyK1bajKdQKVMFQGA1UdHwRNMEswSaBHoEWGQ2h0dHA6Ly93d3cu
# bWljcm9zb2Z0LmNvbS9wa2lvcHMvY3JsL01pY0NvZFNpZ1BDQTIwMTFfMjAxMS0w
# Ny0wOC5jcmwwYQYIKwYBBQUHAQEEVTBTMFEGCCsGAQUFBzAChkVodHRwOi8vd3d3
# Lm1pY3Jvc29mdC5jb20vcGtpb3BzL2NlcnRzL01pY0NvZFNpZ1BDQTIwMTFfMjAx
# MS0wNy0wOC5jcnQwDAYDVR0TAQH/BAIwADANBgkqhkiG9w0BAQsFAAOCAgEAnnqH
# tDyYUFaVAkvAK0eqq6nhoL95SZQu3RnpZ7tdQ89QR3++7A+4hrr7V4xxmkB5BObS
# 0YK+MALE02atjwWgPdpYQ68WdLGroJZHkbZdgERG+7tETFl3aKF4KpoSaGOskZXp
# TPnCaMo2PXoAMVMGpsQEQswimZq3IQ3nRQfBlJ0PoMMcN/+Pks8ZTL1BoPYsJpok
# t6cql59q6CypZYIwgyJ892HpttybHKg1ZtQLUlSXccRMlugPgEcNZJagPEgPYni4
# b11snjRAgf0dyQ0zI9aLXqTxWUU5pCIFiPT0b2wsxzRqCtyGqpkGM8P9GazO8eao
# mVItCYBcJSByBx/pS0cSYwBBHAZxJODUqxSXoSGDvmTfqUJXntnWkL4okok1FiCD
# Z4jpyXOQunb6egIXvkgQ7jb2uO26Ow0m8RwleDvhOMrnHsupiOPbozKroSa6paFt
# VSh89abUSooR8QdZciemmoFhcWkEwFg4spzvYNP4nIs193261WyTaRMZoceGun7G
# CT2Rl653uUj+F+g94c63AhzSq4khdL4HlFIP2ePv29smfUnHtGq6yYFDLnT0q/Y+
# Di3jwloF8EWkkHRtSuXlFUbTmwr/lDDgbpZiKhLS7CBTDj32I0L5i532+uHczw82
# oZDmYmYmIUSMbZOgS65h797rj5JJ6OkeEUJoAVwwggd6MIIFYqADAgECAgphDpDS
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
# RcBCyZt2WwqASGv9eZ/BvW1taslScxMNelDNMYIVXTCCFVkCAQEwgZUwfjELMAkG
# A1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQx
# HjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEoMCYGA1UEAxMfTWljcm9z
# b2Z0IENvZGUgU2lnbmluZyBQQ0EgMjAxMQITMwAAAd9r8C6Sp0q00AAAAAAB3zAN
# BglghkgBZQMEAgEFAKCBpDAZBgkqhkiG9w0BCQMxDAYKKwYBBAGCNwIBBDAcBgor
# BgEEAYI3AgELMQ4wDAYKKwYBBAGCNwIBFTAvBgkqhkiG9w0BCQQxIgQg5YSz9/Xa
# ndokEZvqwRqSCXZi0o/Hh2LNHoYLGlXBKnkwOAYKKwYBBAGCNwIBDDEqMCigCIAG
# AFQAUwBToRyAGmh0dHBzOi8vd3d3Lm1pY3Jvc29mdC5jb20gMA0GCSqGSIb3DQEB
# AQUABIIBAGjit4QXZDtuQvbbxzSllFYXODrmDCqr4jY46TKtMddahYV1DvNcExkm
# agJ/U/+AzI5C7lgiSrON4Vkdzs9lv8C8Z0104Wjzko1Ggw8q2h3cjlMOysAbwk5f
# t2/LZ9t1MtJ9B9USbUr4bhVCiUE4tJvyM+daFOV4zEFdw29CKyM82842wKJqgT2N
# 8j8c03Qc10hIb92bPfou8myAZ9vVqMjktG5EZHTIAo/hhvlsoK5t3g6T39yKEZv4
# DBF9VHa9IWz9g+7LRXxARAOrlxVSESQo+KeoDrnBrLfgsYv3wZ+omlMMLaTygAYi
# RXYzazPS46P/Xf/FaOksryCes979B8ChghLxMIIS7QYKKwYBBAGCNwMDATGCEt0w
# ghLZBgkqhkiG9w0BBwKgghLKMIISxgIBAzEPMA0GCWCGSAFlAwQCAQUAMIIBVQYL
# KoZIhvcNAQkQAQSgggFEBIIBQDCCATwCAQEGCisGAQQBhFkKAwEwMTANBglghkgB
# ZQMEAgEFAAQgUB5MknvdZm2cRoZkT8oo/czu4MYJBTFCe3wUJ3tW/akCBmGB3Gir
# ZhgTMjAyMTExMTExNjUzMzYuMjY1WjAEgAIB9KCB1KSB0TCBzjELMAkGA1UEBhMC
# VVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNV
# BAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEpMCcGA1UECxMgTWljcm9zb2Z0IE9w
# ZXJhdGlvbnMgUHVlcnRvIFJpY28xJjAkBgNVBAsTHVRoYWxlcyBUU1MgRVNOOjYw
# QkMtRTM4My0yNjM1MSUwIwYDVQQDExxNaWNyb3NvZnQgVGltZS1TdGFtcCBTZXJ2
# aWNloIIORDCCBPUwggPdoAMCAQICEzMAAAFaLLluRDTLbygAAAAAAVowDQYJKoZI
# hvcNAQELBQAwfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAO
# BgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEm
# MCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTAwHhcNMjEwMTE0
# MTkwMjE2WhcNMjIwNDExMTkwMjE2WjCBzjELMAkGA1UEBhMCVVMxEzARBgNVBAgT
# Cldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29m
# dCBDb3Jwb3JhdGlvbjEpMCcGA1UECxMgTWljcm9zb2Z0IE9wZXJhdGlvbnMgUHVl
# cnRvIFJpY28xJjAkBgNVBAsTHVRoYWxlcyBUU1MgRVNOOjYwQkMtRTM4My0yNjM1
# MSUwIwYDVQQDExxNaWNyb3NvZnQgVGltZS1TdGFtcCBTZXJ2aWNlMIIBIjANBgkq
# hkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAsL1cHFcNrScIrvQd/4aKHo3FGXWYCHMU
# l2iTxuzfGknztMzbysR4eRkBoT4pv0aL1S9OlDfOsRbJZKkhCTLG/9Z/RwiEDWYk
# 6rK7bRM3eX3pm+DNivM7+tCU+9spbv2gA7j5gWx6RAK2vMz2FChLkFgbA+H1DPro
# G5LEf1DB7LA0FCyORWiKSkHGRL4RdIjOltrZp++dExfsst7Z6vJz4+U9eZNI58fV
# Y3KRzbm73OjplfSAB3iNSkHN0wuccK0TrZsvY87TRyYAmyK2qBqi/7eUWt93Sw8A
# LBMY72LKaUmVvaxq/COpKePlHMbhHEbqtTaLt61udBOjNHvc4cwY5QIDAQABo4IB
# GzCCARcwHQYDVR0OBBYEFGRzJT/1HI+SftAGhdk5NDzA3jFnMB8GA1UdIwQYMBaA
# FNVjOlyKMZDzQ3t8RhvFM2hahW1VMFYGA1UdHwRPME0wS6BJoEeGRWh0dHA6Ly9j
# cmwubWljcm9zb2Z0LmNvbS9wa2kvY3JsL3Byb2R1Y3RzL01pY1RpbVN0YVBDQV8y
# MDEwLTA3LTAxLmNybDBaBggrBgEFBQcBAQROMEwwSgYIKwYBBQUHMAKGPmh0dHA6
# Ly93d3cubWljcm9zb2Z0LmNvbS9wa2kvY2VydHMvTWljVGltU3RhUENBXzIwMTAt
# MDctMDEuY3J0MAwGA1UdEwEB/wQCMAAwEwYDVR0lBAwwCgYIKwYBBQUHAwgwDQYJ
# KoZIhvcNAQELBQADggEBAAAAbex8WBtSLDiBYxXxU7GVsgb8IgxKJyIO0hmc8vzg
# 4w3iUl5Xkt4mv4dgFyjHmu5Zmbj0rb2IGYm/pWJcy0/zWlhnUQUzvfTpj7MsiH+1
# Lnvg95awe88PRA7FDgc4zYY0+8UB1S+jzPmmBX/kT6U+7rW5QIgFMMRKIc743utq
# CpvcwRM+pEo8s0Alwo8NxqUrOeYY+WfNjo/XOin/tr3RVwEdEopD+FO+f/wLxjpv
# 4y+TmRgmHrso1tVVy64FbIVIxlMcZ6cee4dWD2y8fv6Wb9X/AhtlQookk7QdCbKh
# 3JJ4P8ksLs02wNhGkU37b10tG3HR5bJmiwmZPyopsEgwggZxMIIEWaADAgECAgph
# CYEqAAAAAAACMA0GCSqGSIb3DQEBCwUAMIGIMQswCQYDVQQGEwJVUzETMBEGA1UE
# CBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9z
# b2Z0IENvcnBvcmF0aW9uMTIwMAYDVQQDEylNaWNyb3NvZnQgUm9vdCBDZXJ0aWZp
# Y2F0ZSBBdXRob3JpdHkgMjAxMDAeFw0xMDA3MDEyMTM2NTVaFw0yNTA3MDEyMTQ2
# NTVaMHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQH
# EwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJjAkBgNV
# BAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEwMIIBIjANBgkqhkiG9w0B
# AQEFAAOCAQ8AMIIBCgKCAQEAqR0NvHcRijog7PwTl/X6f2mUa3RUENWlCgCChfvt
# fGhLLF/Fw+Vhwna3PmYrW/AVUycEMR9BGxqVHc4JE458YTBZsTBED/FgiIRUQwzX
# Tbg4CLNC3ZOs1nMwVyaCo0UN0Or1R4HNvyRgMlhgRvJYR4YyhB50YWeRX4FUsc+T
# TJLBxKZd0WETbijGGvmGgLvfYfxGwScdJGcSchohiq9LZIlQYrFd/XcfPfBXday9
# ikJNQFHRD5wGPmd/9WbAA5ZEfu/QS/1u5ZrKsajyeioKMfDaTgaRtogINeh4HLDp
# mc085y9Euqf03GS9pAHBIAmTeM38vMDJRF1eFpwBBU8iTQIDAQABo4IB5jCCAeIw
# EAYJKwYBBAGCNxUBBAMCAQAwHQYDVR0OBBYEFNVjOlyKMZDzQ3t8RhvFM2hahW1V
# MBkGCSsGAQQBgjcUAgQMHgoAUwB1AGIAQwBBMAsGA1UdDwQEAwIBhjAPBgNVHRMB
# Af8EBTADAQH/MB8GA1UdIwQYMBaAFNX2VsuP6KJcYmjRPZSQW9fOmhjEMFYGA1Ud
# HwRPME0wS6BJoEeGRWh0dHA6Ly9jcmwubWljcm9zb2Z0LmNvbS9wa2kvY3JsL3By
# b2R1Y3RzL01pY1Jvb0NlckF1dF8yMDEwLTA2LTIzLmNybDBaBggrBgEFBQcBAQRO
# MEwwSgYIKwYBBQUHMAKGPmh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2kvY2Vy
# dHMvTWljUm9vQ2VyQXV0XzIwMTAtMDYtMjMuY3J0MIGgBgNVHSABAf8EgZUwgZIw
# gY8GCSsGAQQBgjcuAzCBgTA9BggrBgEFBQcCARYxaHR0cDovL3d3dy5taWNyb3Nv
# ZnQuY29tL1BLSS9kb2NzL0NQUy9kZWZhdWx0Lmh0bTBABggrBgEFBQcCAjA0HjIg
# HQBMAGUAZwBhAGwAXwBQAG8AbABpAGMAeQBfAFMAdABhAHQAZQBtAGUAbgB0AC4g
# HTANBgkqhkiG9w0BAQsFAAOCAgEAB+aIUQ3ixuCYP4FxAz2do6Ehb7Prpsz1Mb7P
# BeKp/vpXbRkws8LFZslq3/Xn8Hi9x6ieJeP5vO1rVFcIK1GCRBL7uVOMzPRgEop2
# zEBAQZvcXBf/XPleFzWYJFZLdO9CEMivv3/Gf/I3fVo/HPKZeUqRUgCvOA8X9S95
# gWXZqbVr5MfO9sp6AG9LMEQkIjzP7QOllo9ZKby2/QThcJ8ySif9Va8v/rbljjO7
# Yl+a21dA6fHOmWaQjP9qYn/dxUoLkSbiOewZSnFjnXshbcOco6I8+n99lmqQeKZt
# 0uGc+R38ONiU9MalCpaGpL2eGq4EQoO4tYCbIjggtSXlZOz39L9+Y1klD3ouOVd2
# onGqBooPiRa6YacRy5rYDkeagMXQzafQ732D8OE7cQnfXXSYIghh2rBQHm+98eEA
# 3+cxB6STOvdlR3jo+KhIq/fecn5ha293qYHLpwmsObvsxsvYgrRyzR30uIUBHoD7
# G4kqVDmyW9rIDVWZeodzOwjmmC3qjeAzLhIp9cAvVCch98isTtoouLGp25ayp0Ki
# yc8ZQU3ghvkqmqMRZjDTu3QyS99je/WZii8bxyGvWbWu3EQ8l1Bx16HSxVXjad5X
# wdHeMMD9zOZN+w2/XU/pnR4ZOC+8z1gFLu8NoFA12u8JJxzVs341Hgi62jbb01+P
# 3nSISRKhggLSMIICOwIBATCB/KGB1KSB0TCBzjELMAkGA1UEBhMCVVMxEzARBgNV
# BAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jv
# c29mdCBDb3Jwb3JhdGlvbjEpMCcGA1UECxMgTWljcm9zb2Z0IE9wZXJhdGlvbnMg
# UHVlcnRvIFJpY28xJjAkBgNVBAsTHVRoYWxlcyBUU1MgRVNOOjYwQkMtRTM4My0y
# NjM1MSUwIwYDVQQDExxNaWNyb3NvZnQgVGltZS1TdGFtcCBTZXJ2aWNloiMKAQEw
# BwYFKw4DAhoDFQDMgAWYvcYcdZwAliLeFobCWmUaLqCBgzCBgKR+MHwxCzAJBgNV
# BAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4w
# HAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJjAkBgNVBAMTHU1pY3Jvc29m
# dCBUaW1lLVN0YW1wIFBDQSAyMDEwMA0GCSqGSIb3DQEBBQUAAgUA5TePeDAiGA8y
# MDIxMTExMTE2NDc1MloYDzIwMjExMTEyMTY0NzUyWjB3MD0GCisGAQQBhFkKBAEx
# LzAtMAoCBQDlN494AgEAMAoCAQACAiYUAgH/MAcCAQACAhEuMAoCBQDlOOD4AgEA
# MDYGCisGAQQBhFkKBAIxKDAmMAwGCisGAQQBhFkKAwKgCjAIAgEAAgMHoSChCjAI
# AgEAAgMBhqAwDQYJKoZIhvcNAQEFBQADgYEARgjej0SbSLQSMcUwvN12chrEC28n
# cvB5Y3XUAVhEcy1SU+s/DPBT7RaNwTGRnmi6Mq9YdOCw28LOQagQobT23OIXtlQk
# v6/VnsW+JiF8q2A2Zvn08thSlcdfEr1B4nsYLVrR78o0MGag24mYk75Z6ATsfNVT
# HmPR653hJHGQ0OcxggMNMIIDCQIBATCBkzB8MQswCQYDVQQGEwJVUzETMBEGA1UE
# CBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9z
# b2Z0IENvcnBvcmF0aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQ
# Q0EgMjAxMAITMwAAAVosuW5ENMtvKAAAAAABWjANBglghkgBZQMEAgEFAKCCAUow
# GgYJKoZIhvcNAQkDMQ0GCyqGSIb3DQEJEAEEMC8GCSqGSIb3DQEJBDEiBCBIqiiS
# K7BDjZI4JCLa4Or9Usb8yl7yzIyng+Y2IiES9TCB+gYLKoZIhvcNAQkQAi8xgeow
# gecwgeQwgb0EIJP8qCZ0xLLkXTDDghqv1yZ/kizekzSFS4gicvltsX+wMIGYMIGA
# pH4wfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcT
# B1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQGA1UE
# AxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTACEzMAAAFaLLluRDTLbygA
# AAAAAVowIgQgMnaZvhznlep5/TqcHsVpqibeOA9Q6qLRQqPN0sxjsvwwDQYJKoZI
# hvcNAQELBQAEggEAlLLz0ZM8DzRC/ZAAbPFrQGxV0ADsS1T52i/ZRnvAKLFp4e/H
# bor6SxpTeYfWRzQQu+tJsCOibUdZk5ifQQNucDEN73A49vqAs2tPcXbo4VgoQyiA
# o/aTjmu2fdfHzW6bgWrjC2TcJm/8lz635UuAbC57QSieIuDkcCjI5ZSJk85TVKSi
# 3MzdE9UQkaQM1aRf1Ro6pwQeFlB7Znf0NpxPAToGkn499ZXBM1BXuvqmm800DxhQ
# sRwly/e0m53/jEzh5B1ODejLOdGqxi2jV4noKvAEAMikMbTduN0sWWnG/hk4RF6d
# RGSt0BVd5FNikoKGYCNebztn0h2TuKcJyVDa6A==
# SIG # End signature block
