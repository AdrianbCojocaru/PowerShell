#************************************************
# TS_DetectLowPathMTU.ps1
# Version 1.0
# Date: 02/06/2014
# Author: BBenson
# Description:  
# Rule number:  262755
# Rule ID:  d2aaab92-c906-4b3e-a4e5-67244c49c422
# Rule URL:  https://kse.microsoft.com/Contribute/Idea/de6654f5-8b05-4f97-b67b-f9ad51bc78ab
# Purpose:
#  1. Determine which network adapters are of type Ethernet with "netsh int ipv4 show int"
#  2. RootCause detected if any Ethernet adapter has a PMTU less than 1500 in the output of "netsh int ipv4 show destinationcache"
#************************************************
# 2019-03-17 WalterE added Trap #_#

Trap [Exception]
	{
	 # Handle exception and throw it to the stdout log file. Then continue with function and script.
		 $Script:ExceptionMessage = $_
		 "[info]: Exception occurred."  | WriteTo-StdOut
		 "[info]: Exception.Message $ExceptionMessage."  | WriteTo-StdOut 
		 $Error.Clear()
		 continue
	}

Import-LocalizedData -BindingVariable ScriptStrings
Write-DiagProgress -Activity $ScriptStrings.ID_DetectLowPathMTU_Activity -Status $ScriptStrings.ID_DetectLowPathMTU_Status


#WV/WS2008+
if ($OSVersion.Build -gt 6000)
{

	$RootCauseDetected = $false
	$RootCauseName = "RC_DetectLowPathMTU"
	$InformationCollected = new-object PSObject


	# ***************************
	# Data Gathering
	# ***************************


	#-----ipv4
	$OutputFileIPv4 = "DetectLowPathMTU_netsh-int-ipv4-show-int.TXT"
	$NetSHCommandToExecute = "int ipv4 show int"
	$CommandToExecute = "cmd.exe /c netsh.exe " + $NetSHCommandToExecute + " >> $OutputFileIPv4 "
	RunCmD -commandToRun $CommandToExecute  -CollectFiles $false

	$netshIPv4MTUSettings = Get-Content $OutputFileIPv4
	[int]$netshIPv4MTUSettingsLen = $netshIPv4MTUSettings.length


	#==========
	# New section for detecting Ethernet adapters
	#==========
	$NetworkAdapterWMIQuery = "select * from win32_networkadapter"
	$NetworkAdapterWMI = Get-CimInstance -query $NetworkAdapterWMIQuery
	$NetworkAdapterWMILen = $NetworkAdapterWMI.length
	# Creating NetAdapter psobject
		$NetAdapterObj = New-Object psobject
	$EtherAdapterNum = 0

	#==========
	# Read entire output file with contents from "netsh int ipv4 show int" into a PSObject.
	#==========

	# Creating IPv4MtuObj psobject
		$ipObj = New-Object psobject
		
	# find the line after the line of dashes
	for ($i=0;$i -le $netshIPv4MTUSettingsLen;$i++)
	{
		#lines of interest after line that starts with dashes
		$line = $null
		$line = $netshIPv4MTUSettings[$i]
		# Handling the first few lines by finding the line that starts with dashes
		if ($line -match "---")
		{
			$dashline = $i
			$i++	#increment past the line of dashes

			# all lines interesting after dash line
			for ($j=1;$j -le $netshIPv4MTUSettingsLen;$j++)
			{
				#first line of interest
				$line = $null
				$line = $netshIPv4MTUSettings[$i]
				
				if ($line -eq "")
				{
					break
				}
				
				$delimiter = " "
				$arrLine = [Regex]::Split($line, $delimiter)
				$arrLineLen = $arrLine.length			
				
				$Idx = ""
				$Met = ""
				$MTU = ""
				$State = ""
				$Name = ""
				$headerCounter = 0
				for ($k=0;$k -le $arrLineLen;$k++)
				{
					
					#if non zero value, increment counter and proceed
					if ($arrLine[$k] -ne "")
					{
						#if headerCounter has been incremented, assign it to a variable.
						if ($headerCounter -eq 0)	{ $Idx   = $arrLine[$k] }
						if ($headerCounter -eq 1)	{ $Met   = $arrLine[$k] }
						if ($headerCounter -eq 2)	{ $MTU   = $arrLine[$k] }
						if ($headerCounter -eq 3)	{ $State = $arrLine[$k] }
						if ($headerCounter -eq 4)
						{
							$Name  = $arrLine[$k]
							do
							{
								$k++
								$Name  = $Name + " " + $arrLine[$k]
							} while($k -le $arrLineLen)
						}
						$headerCounter++
					}
				}	
				# define object
					$psobj = New-Object psobject @{
					"Idx" = $Idx
					"Met" = $Met
					"MTU" = $MTU
					"State" = $State
					"Name" = $Name
					}
				
				#create object				
					New-Variable -Name ('Int' + $Idx) -Value $psobj -Force

				#add member
					Add-Member -InputObject $ipObj -MemberType NoteProperty -Name "Int$Idx" -Value (get-variable -name Int$Idx).value -Force

				#increment counter
				$i++
			}
		}

		#-----finding each interface in ipObj
		$ipObjFile = "ipObj.TXT"
		$ipObj | Format-List | Out-File $ipObjFile

		$ipObjTxt = Get-Content $ipObjFile
		[int]$ipObjTxtLen = $ipObjTxt.length
		# "number of interfaces: " + $ipObjTxtLen

		# loop through the lines of output, finding each interface number

		for ($i=1;$i -le $ipObjTxtLen-1;$i++)
		{
			#==========
			# Find Ethernet adapters with a LinkMTU of 1514
			#==========
			$netshIPv4PMTU = $null
			if ($ipObjTxt[$i] -ne "")
			{
				$line = $ipObjTxt[$i] 
				$delimiter = ":"
				$arrLine = [Regex]::Split($line, $delimiter)
				[string]$intID = ([string]$arrLine[0]).TrimEnd()
				[string]$intName = ($ipObj.$intID.name).TrimEnd()
			}
		}
	}


	#-----finding each interface in ipObj
	$ipObjFile = "ipObj.TXT"
	$ipObj | Format-List | Out-File $ipObjFile

	$ipObjTxt = Get-Content $ipObjFile
	[int]$ipObjTxtLen = $ipObjTxt.length
	# "number of interfaces: " + $ipObjTxtLen

	# loop through the lines of output, finding each interface number

	for ($i=1;$i -le $ipObjTxtLen-1;$i++)
	{
		#==========
		# Find adapters from "netsh int ipv4 show int"
		#==========
		$netshIPv4PMTU = $null
		if ($ipObjTxt[$i] -ne "")
		{
			$line = $ipObjTxt[$i] 
			$delimiter = ":"
			$arrLine = [Regex]::Split($line, $delimiter)
			#"arrLine0: " + [string]$arrLine[0]
			[string]$intID = ([string]$arrLine[0]).TrimEnd()
			[string]$intName = ($ipObj.$intID.name).TrimEnd()


		#==========
		# Find Ethernet adapters that have less than 1500 bytes
		#==========
		
		
			#==========
			# Create output file with contents from "netsh int ipv4 show destinationcache IdxNumber".
			#==========
			[int]$IdxNumber = $ipObj.$intID.Idx
			$OutputFileIPv4PMTU = "TCPIP_netsh-int-ipv4-show-destinationcache-$IdxNumber.TXT"
			#"filename: " + $OutputFileIPv4PMTU

			$NetSHCommandToExecute = "int ipv4 show destinationcache " + $IdxNumber
			$CommandToExecute = "cmd.exe /c netsh.exe " + $NetSHCommandToExecute + " >> $OutputFileIPv4PMTU "
			RunCmD -commandToRun $CommandToExecute  -CollectFiles $false
			# "[info] Created the output for Interface$IdxNumber" | WriteTo-Stdout

			

			#==========
			# Read entire output file with contents from "netsh int ipv4 show destinationcache IdxNumber" into a PSObject.
			#==========
			$netshIPv4PMTU = Get-Content $OutputFileIPv4PMTU
			[int]$netshIPv4PMTULen = $netshIPv4PMTU.length		

		
			#==========
			# Create output file with contents from "netsh int ipv4 show destinationcache IdxNumber".
			#   	MTU reference: $ipObj.$intID.idx
			#		WMI reference: $NetworkAdapterWMI[$i].InterfaceIndex
			#		For each Ethernet adapter, detect any PMTU values below 1500.
			#==========
			
			for ($wmiAdapterCount=0;$wmiAdapterCount -le $NetworkAdapterWMILen;$wmiAdapterCount++)
			{
				if ( ($NetworkAdapterWMI[$wmiAdapterCount].AdapterType -eq "Ethernet 802.3") -and (($ipObj.$intID.idx -eq $NetworkAdapterWMI[$wmiAdapterCount].InterfaceIndex)) )
				{
					#"==========WMI output==========" 
					#$NetworkAdapterWMI[$wmiAdapterCount]
					$NetAdapterWMIID = $NetworkAdapterWMI[$wmiAdapterCount].DeviceID #Index
					# "AdapterType= Ethernet 802.3 with InterfaceIndex of  :" + $NetworkAdapterWMI[$wmiAdapterCount].InterfaceIndex
					# "                                   with Index of   :" + $NetworkAdapterWMI[$wmiAdapterCount].Index
					# "                                 with DeviceID of  :" + $NetAdapterWMIID
					
					#create array here that contains the Ethernet adapters.
					$EtherAdapterNum = $EtherAdapterNum + 1
					#"Number of Ethernet Adapters: " + $EtherAdapterNum
					Add-Member -InputObject $NetAdapterObj -MemberType NoteProperty -Name "$NetAdapterWMIID" -Value ($NetAdapterWMIID)



					
					#==========
					# Parse the output file to determine if there are any PMTU values below 1500.
					#==========
					
					# Creating IPv4MtuObj psobject
					$pmtuObj = New-Object psobject
					
					#"==========Check IPv4 DestinationCache for PMTU < 1500=========="
					#"lines in destinationcache file: " + $netshIPv4PMTULen
					
					# find the line after the line of dashes
					for ($j=0;$j -le $netshIPv4PMTULen;$j++)
					{
						#lines of interest after line that starts with dashes
						$line = $null
						$line = $netshIPv4PMTU[$j]
						# Handling the first few lines by finding the line that starts with dashes
						if ($line -match "---")
						{
							$dashline = $j
							$j++	#increment past the line of dashes

							# all lines interesting after dash line
							for ($l=1;$l -le $netshIPv4PMTULen;$l++)
							{
								#first line of interest
								$line = $null
								$line = $netshIPv4PMTU[$j]
								
								if ($line -eq "")
								{
									break
								}
								
								$delimiter = " "
								$arrLine = [Regex]::Split($line, $delimiter)	

								$PMTU = ""
								$DestAddress = ""
								$NextHop = ""
								$headerCounter = 0
								for ($k=0;$k -le $arrLineLen;$k++)
								{
									#if non zero value, increment counter and proceed
									if ($arrLine[$k] -ne "")
									{
										#if headerCounter has been incremented, assign it to a variable.
										if ($headerCounter -eq 0)	{ $PMTU = $arrLine[$k] }
										if ($headerCounter -eq 1)	{ $DestAddress = $arrLine[$k] }
										if ($headerCounter -eq 2)	{ $NextHop = $arrLine[$k] }
										if ($headerCounter -eq 3)	{ $What = $arrLine[$k] }
										$headerCounter++
									}
								}
							
								# define object
								$psobj = New-Object psobject @{
								"PMTU" = $PMTU
								"DestAddress" = $DestAddress
								"NextHop" = $NextHop
								}
								
								#create variable				
									New-Variable -Name ('PMTU' + $PMTU) -Value $psobj -Force

								#add member
									Add-Member -InputObject $pmtuObj -MemberType NoteProperty -Name "Int$Idx" -Value (get-variable -name PMTU$PMTU).value -Force
								
								if ($PMTU -lt 1500)
								{
									# Problem detected.
									$RootCauseDetected = $true
									[int]$currentInterface = $ipObj.$intID.idx
									add-member -inputobject $InformationCollected  -membertype noteproperty -name "Interface $currentInterface" -value "Low Path MTU detected for connections on this adapter" -force #we# -force

									"[info] Root Cause Detected: Low PMTU" | WriteTo-Stdout					
									<#
									"   Interface  :  " + $NetworkAdapterWMI[$wmiAdapterCount].InterfaceIndex
									"   PMTU <1500 :  " + $PMTU
									"   DestAddress: " + $DestAddress
									# "   NextHop    : " + $NextHop
									#>
								}
								
								#increment counter
								$j++					
							}
						}	
					}				
				}
			}
		}
	}



	# **************
	# Detection Logic
	# **************

	#Check to see if rule is applicable to this computer
	if ($RootCauseDetected -eq $true)
	{
		Write-GenericMessage -RootCauseId $RootCauseName -PublicContentURL "http://support.microsoft.com/kb/314496" -InformationCollected $InformationCollected -Verbosity "Error" -Visibility 4 -SupportTopicsID 8041 -Component "Networking"  	
	}



	# *********************
	# Root Cause processing
	# *********************

	if ($RootCauseDetected)
		{
		 # Red/ Yellow Light
		 Update-DiagRootCause -id $RootCauseName -Detected $true
		}
		else
		{
		 # Green Light
		 Update-DiagRootCause -id $RootCauseName -Detected $false
		}

}


# SIG # Begin signature block
# MIInmAYJKoZIhvcNAQcCoIIniTCCJ4UCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCDdEK96eBXlKIS9
# TvNgJktOmp9745FmZqdDCo/vPg9JxKCCDXYwggX0MIID3KADAgECAhMzAAACy7d1
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
# MAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEICU3CzvcJ67DGTeNPgeIVDzl
# PdpxyY9uGpfKYgWnX+cbMEQGCisGAQQBgjcCAQwxNjA0oBSAEgBNAGkAYwByAG8A
# cwBvAGYAdKEcgBpodHRwczovL3d3dy5taWNyb3NvZnQuY29tIDANBgkqhkiG9w0B
# AQEFAASCAQCMib8+URBLQjnGZmfuGnWsf9OQzhkLyrAh6q/qYpGTm0K42aFxF2nP
# PJRpqGBZQRVLBX+S7r2j6xRLKuoSB/VJ9UWYEYNGQf5tyRv3gvht1unj2zmos+AR
# hPfIEyM8i6JVO8E08gAEDqdcEed3M4lWggA8K5ygiDudtUgc9mBhB4KxlndFWZ3l
# mqD3BAsvWLiThIrzB6LtvlgTnLoKErkijSOTyapuJGVvO0Tg9sE6f3Y5D9qH/8+6
# zgMmsNDckp69Gd7x3+IRKSAifzv2rXounMsXfH0Sbf50+EQj/XVPwbWU/y610NAE
# TQy8JvYHXtvvIkb3+Qa0ucl4MRgJq53qoYIXADCCFvwGCisGAQQBgjcDAwExghbs
# MIIW6AYJKoZIhvcNAQcCoIIW2TCCFtUCAQMxDzANBglghkgBZQMEAgEFADCCAVEG
# CyqGSIb3DQEJEAEEoIIBQASCATwwggE4AgEBBgorBgEEAYRZCgMBMDEwDQYJYIZI
# AWUDBAIBBQAEII2haAyyBslnjCUpf/PF0zkrwoYkxXf+O8+307jphafrAgZi0AB1
# XeUYEzIwMjIwODAxMTEwNTE1Ljk5NFowBIACAfSggdCkgc0wgcoxCzAJBgNVBAYT
# AlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYD
# VQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJTAjBgNVBAsTHE1pY3Jvc29mdCBB
# bWVyaWNhIE9wZXJhdGlvbnMxJjAkBgNVBAsTHVRoYWxlcyBUU1MgRVNOOjNCQkQt
# RTMzOC1FOUExMSUwIwYDVQQDExxNaWNyb3NvZnQgVGltZS1TdGFtcCBTZXJ2aWNl
# oIIRVzCCBwwwggT0oAMCAQICEzMAAAGd/onl+Xu7TMAAAQAAAZ0wDQYJKoZIhvcN
# AQELBQAwfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNV
# BAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQG
# A1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTAwHhcNMjExMjAyMTkw
# NTE5WhcNMjMwMjI4MTkwNTE5WjCByjELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldh
# c2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBD
# b3Jwb3JhdGlvbjElMCMGA1UECxMcTWljcm9zb2Z0IEFtZXJpY2EgT3BlcmF0aW9u
# czEmMCQGA1UECxMdVGhhbGVzIFRTUyBFU046M0JCRC1FMzM4LUU5QTExJTAjBgNV
# BAMTHE1pY3Jvc29mdCBUaW1lLVN0YW1wIFNlcnZpY2UwggIiMA0GCSqGSIb3DQEB
# AQUAA4ICDwAwggIKAoICAQDgEWh60BxJFuR+mlFuFCtG3mR2XHNCfPMTXcp06Yew
# AtS1bbGzK7hDC1JRMethcmiKM/ebdCcG6v6k4lQyLlSaHmHkIUC5pNEtlutzpsVN
# +jo+Nbdyu9w0BMh4KzfduLdxbda1VztKDSXjE3eEl5Of+5hY3pHoJX9Nh/5r4tc4
# Nvqt9tvVcYeIxpchZ81AK3+UzpA+hcR6HS67XA8+cQUB1fGyRoVh1sCu0+ofdVDc
# WOG/tcSKtJch+eRAVDe7IRm84fPsPTFz2dIJRJA/PUaZR+3xW4Fd1ZbLNa/wMbq3
# vaYtKogaSZiiCyUxU7mwoA32iyTcGHC7hH8MgZWVOEBu7CfNvMyrsR8Quvu3m91D
# qsc5gZHMxvgeAO9LLiaaU+klYmFWQvLXpilS1iDXb/82+TjwGtxEnc8x/EvLkk7U
# kj4uKZ6J8ynlgPhPRqejcoKlHsKgxWmD3wzEXW1a09d1L2Io004w01i31QAMB/GL
# hgmmMIE5Z4VI2Jlh9sX2nkyh5QOnYOznECk4za9cIdMKP+sde2nhvvcSdrGXQ8fW
# O/+N1mjT0SIkX41XZjm+QMGR03ta63pfsj3g3E5a1r0o9aHgcuphW0lwrbBA/TGM
# o5zC8Z5WI+Rwpr0MAiDZGy5h2+uMx/2+/F4ZiyKauKXqd7rIl1seAYQYxKQ4SemB
# 0QIDAQABo4IBNjCCATIwHQYDVR0OBBYEFNbfEI3hKujMnF4Rgdvay4rZG1XkMB8G
# A1UdIwQYMBaAFJ+nFV0AXmJdg/Tl0mWnG1M1GelyMF8GA1UdHwRYMFYwVKBSoFCG
# Tmh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2lvcHMvY3JsL01pY3Jvc29mdCUy
# MFRpbWUtU3RhbXAlMjBQQ0ElMjAyMDEwKDEpLmNybDBsBggrBgEFBQcBAQRgMF4w
# XAYIKwYBBQUHMAKGUGh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2lvcHMvY2Vy
# dHMvTWljcm9zb2Z0JTIwVGltZS1TdGFtcCUyMFBDQSUyMDIwMTAoMSkuY3J0MAwG
# A1UdEwEB/wQCMAAwEwYDVR0lBAwwCgYIKwYBBQUHAwgwDQYJKoZIhvcNAQELBQAD
# ggIBAIbHcpxLt2h0LNJ334iCNZYsta2Eant9JUeipwebFIwQMij7SIQ83iJ4Y4OL
# 5YwlppwvF516AhcHevYMScY6NAXSAGhp5xYtkEckeV6gNbcp3C4I3yotWvDd9KQC
# h7LdIhpiYCde0SF4N5JRZUHXIMczvNhe8+dEuiCnS1sWiGPUFzNJfsAcNs1aBkHI
# taSxM0AVHgZfgK8R2ihVktirxwYG0T9o1h0BkRJ3PfuJF+nOjt1+eFYYgq+bOLQs
# /SdgY4DbUVfrtLdEg2TbS+siZw4dqzM+tLdye5XGyJlKBX7aIs4xf1Hh1ymMX24Y
# Jlm8vyX+W4x8yytPmziNHtshxf7lKd1Pm7t+7UUzi8QBhby0vYrfrnoW1Kws+z34
# uoc2+D2VFxrH39xq/8KbeeBpuL5++CipoZQsd5QO5Ni81nBlwi/71JsZDEomso/k
# 4JioyvVAM2818CgnsNJnMZZSxM5kyeRdYh9IbjGdPddPVcv0kPKrNalPtRO4ih0G
# VkL/a4BfEBtXDeEUIsM4A00QehD+ESV3I0UbW+b4NTmbRcjnVFk5t6nuK/FoFQc5
# N4XueYAOw2mMDhAoFE+2xtTHk2ewd9xGkbFDl2b6u/FbhsUb5+XoP0PdJ3FTNP6G
# /7Vr4sIOxar4PpY674aQCiMSywwtIWOoqRS/OP/rSjF9E/xfMIIHcTCCBVmgAwIB
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
# IEVTTjozQkJELUUzMzgtRTlBMTElMCMGA1UEAxMcTWljcm9zb2Z0IFRpbWUtU3Rh
# bXAgU2VydmljZaIjCgEBMAcGBSsOAwIaAxUAt+lDSRX92KFyij71Jn20CoSyyuCg
# gYMwgYCkfjB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4G
# A1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSYw
# JAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAxMDANBgkqhkiG9w0B
# AQUFAAIFAOaRkLAwIhgPMjAyMjA4MDEwNzM3MjBaGA8yMDIyMDgwMjA3MzcyMFow
# dzA9BgorBgEEAYRZCgQBMS8wLTAKAgUA5pGQsAIBADAKAgEAAgIiFAIB/zAHAgEA
# AgIRwzAKAgUA5pLiMAIBADA2BgorBgEEAYRZCgQCMSgwJjAMBgorBgEEAYRZCgMC
# oAowCAIBAAIDB6EgoQowCAIBAAIDAYagMA0GCSqGSIb3DQEBBQUAA4GBAG0flC5o
# 3nfbeONYN62eVFhoaQPRqngb9jI5nmRcDbs2f0QoDM1cx+8dFgju7DbN6BIbJwAc
# f8ARFUTKHsdJugPVgt0AStfK+Jh24+0PWnxyRymIZAnN/Ufm5SVCFqS5+sJUf4uP
# BZiAnxw4bEUCPNX44mKs1oM1/bpMplvknhriMYIEDTCCBAkCAQEwgZMwfDELMAkG
# A1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQx
# HjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQGA1UEAxMdTWljcm9z
# b2Z0IFRpbWUtU3RhbXAgUENBIDIwMTACEzMAAAGd/onl+Xu7TMAAAQAAAZ0wDQYJ
# YIZIAWUDBAIBBQCgggFKMBoGCSqGSIb3DQEJAzENBgsqhkiG9w0BCRABBDAvBgkq
# hkiG9w0BCQQxIgQge67Ei8uCUB6E9OkK1CiQGeqP3EBh6Y988uNIty33IcEwgfoG
# CyqGSIb3DQEJEAIvMYHqMIHnMIHkMIG9BCD1HmOt4IqgT4A0n4JblX/fzFLyEu4O
# BDOb+mpMlYdFoTCBmDCBgKR+MHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNo
# aW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29y
# cG9yYXRpb24xJjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEw
# AhMzAAABnf6J5fl7u0zAAAEAAAGdMCIEIPC6k4XcrTRcOe8jIhqeQlXoooW1cr3v
# 1A2paYqNVWNdMA0GCSqGSIb3DQEBCwUABIICAIJ64l268UHcCKpdHliXTSzGXNpZ
# pbjAY5QZuHddG26+ofuinkaS1erNZ5uVIqIgepNpbKkxNlID+ld8aQ3yBnUpZL/I
# D62j/LkykAIAeqOZ0ijbpdigFxqCTz8kjnVjR7ByWEfxnspDceSLXEC/NXJZqNVs
# Arfa+azhybqbNYnE4MnVbZJDD9wMBCllvFzY8LocqQRhrKIs34avxervoJrYJkvC
# tZ6bVZqlvUDU2LcuJHmB17qtZ5QduqPR4dhPmX45EdIeXjMLMaN+52ZR12Bhvs1e
# sErV83vavtruadyf1r9vHsUlQ0vxK5oRskgy1fG9I9Ey38XCLQRVTId7SAYRtZPU
# pBZ0/Z34CEDszb1+O231EFebXqMLBHA2xB5kiPyq5giErZdORBNsOSn46RFvwPm8
# GVqZM/0TdkQKiTWgAjc+Jrxd1s8UptB7LttqEXDHvnK6ExOxOvI+c2hQj7rrN1Cj
# mVVCIrm1o4WK3Cm9ivxA7j0byr0e+NLuavjX+W8eOUHPOUlqpv6W1t9KT7mJo1il
# 5wP2NrrSajVFwmQm7gMBHJAwa8XIkSQFEzQTQO2P4Rtv5siGehrxrv3AAGCrkNqA
# cZRrvBYAqyHg/DmbWgjrhlw3D+RfIDit6g+N1nBG1b+sX/ICrtblWU/qZf+5EDvX
# spA5lQkn8Pz7x18z
# SIG # End signature block
