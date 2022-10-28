#************************************************
# DC_ServerManagerInfo.ps1
# Version 1.0.1
# Date: 09-11-2010
# Author: Andre Teixeira - andret@microsoft.com
# Description: This script can be used to 
#************************************************
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

<# trap [Exception] 
{
	WriteTo-ErrorDebugReport -ErrorRecord $_
	continue
} #>

Function Out-MultiLevelObject
{ Param ($items, $startObjects, $path=("Path"), $parent=("Parent"), $label=("Label"), $indent=0, $Attributes="")
					
	Foreach ($startAt in $StartObjects) 
	{
		$children = $items | where-object {$_.$parent -eq $startAt.$path} 
	
		$AttributesText = ""
	
		if ($null -ne $children) {
			if ($null -ne $startAt.$label) {
			("<div style=`"margin-left:" + ($indent * 15) + "`">") + "$($startAt.$label)"  + "</div>" 
			}
			$children | ForEach-Object {Out-MultiLevelObject $items $_ $path $parent $label ($indent + 1)} 
		} else {
			("<div style=`"margin-left:" + ($indent * 15) + "`">" + "$($startAt.$label)" + "</div>")
		}
	}
}

if ($OSVersion.Build -gt 6000)
{
	Import-LocalizedData -BindingVariable ServerManagerStrings
	Write-DiagProgress -Activity $ServerManagerStrings.ID_ServerManagerInfo -Status $ServerManagerStrings.ID_ServerManagerObtaining

	if ((Get-CimInstance -Class Win32_ComputerSystem).DomainRole -gt 1) 
	{ #Server

		if (test-path "$Env:windir\system32\oclist.exe") 
		{
			$OutputFile = $ComputerName + "_OptionalComponents.txt"
			$CommandToExecute = "$Env:windir\system32\cmd.exe /c $Env:windir\system32\oclist.exe > $OutputFile"
			$fileDescription = $ServerManagerStrings.ID_ServerManagerOclist
			RunCmD -commandToRun $CommandToExecute -sectionDescription $sectionDescription -filesToCollect "$OutputFile.*" -fileDescription $fileDescription
		} 
		else 
		{ # dont execute code below in ServerCore or pre-Windows Server 2008
			
			if ($OSVersion.Build -gt 7000)
			{
				Import-Module "ServerManager"
								
				$Features_Summary = new-object PSObject
				
				$AllFeatures = Get-WindowsFeature | Where-Object {($_.installed -eq $true)}
				$Roles = $AllFeatures | Where-Object {($_.FeatureType -eq "Role")}
				$RoleServices = $AllFeatures | Where-Object {($_.FeatureType -ne "Role")}
				$Features = $AllFeatures | Where-Object {($_.FeatureType -eq "Feature") -and ($_.Depth -eq 1)}
				
				Foreach ($Feature in $Roles) 
				{
					$RoleServicesForFeature = ($AllFeatures | Where-Object {($_.Parent -eq $Feature.Name) -and ($_.Installed -eq $true)})
					if ($RoleServicesForFeature)
					{
						$RoleServiceDisplay = Out-MultiLevelObject -items $RoleServices -StartObjects $RoleServicesForFeature -path "Name" -Parent "Parent" -label "DisplayName"
					}
					else
					{
						$RoleServiceDisplay = "<div style=`"margin-left:0`">(There are no role services for " + $Feature.Name + ")</div>"
					}
					add-member -inputobject $Features_Summary -membertype noteproperty -name $Feature.DisplayName -value $RoleServiceDisplay
				}
				
				$Features_Summary | ConvertTo-Xml2 | update-diagreport -ID "06_Roles" -name "Server Roles/ Role Services" -verbosity "Informational"
				
				$Features_Summary = new-object PSObject
				
				Foreach ($Feature in $Features) 
				{
					$RoleServicesForFeature = ($AllFeatures | Where-Object {($_.Parent -eq $Feature.Name)})
					if ($RoleServicesForFeature)
					{
						$RoleServiceDisplay = Out-MultiLevelObject -items $RoleServices -StartObjects $RoleServicesForFeature -path "Name" -Parent "Parent" -label "DisplayName"
					}
					else
					{
						$RoleServiceDisplay =  "<div style=`"margin-left:0`">&#160;</div>"
					}
					add-member -inputobject $Features_Summary -membertype noteproperty -name $Feature.DisplayName -value $RoleServiceDisplay
				}
				
				$Features_Summary | ConvertTo-Xml2 | update-diagreport -ID "06_RolesFeatures" -name "Feature/ Services" -verbosity "Informational"				
			}
			if(($OSVersion.Major -eq 6) -and ($OSVersion.Minor -eq 2))
            {
                $AllRemovedFeatures = Get-WindowsFeature | Where-Object {$_.InstallState -eq "Removed"}    #This need to be confirmed.
                $RemovedRoles = $AllRemovedFeatures | Where-Object {($_.FeatureType -eq "Role")}
                $RemovedRoleServices = $AllRemovedFeatures | Where-Object {($_.FeatureType -ne "Role")}
                $RemovedFeatures = $AllRemovedFeatures | Where-Object {($_.FeatureType -eq "Feature") -and ($_.Depth -eq 1)}
	
                $Roles_Summary = new-object PSObject
				
                Foreach ($Feature in $RemovedRoles) 
                {
                   $RoleServicesForFeature = ($AllRemovedFeatures | Where-Object { $_.Parent -eq $Feature.Name })
                   if ($null -ne $RoleServicesForFeature)
                   {
				      $RoleServiceDisplay = Out-MultiLevelObject -items $RemovedRoleServices -StartObjects $RoleServicesForFeature -path "Name" -Parent "Parent" -label "DisplayName"
		           }
		           else
		           {
			          $RoleServiceDisplay = "<div style=`"margin-left:0`">(There are no role services for " + $Feature.Name + ")</div>"
		           }
		           add-member -inputobject $Roles_Summary -membertype noteproperty -name $Feature.DisplayName -value $RoleServiceDisplay
                }
				
                $Roles_Summary | ConvertTo-Xml2 | update-diagreport -ID "07_RemovedRoles" -name "Removed Server Roles/ Role Services" -verbosity "Informational"
				
                $Features_Summary = new-object PSObject
				
                Foreach ($Feature in $RemovedFeatures) 
                {
		           $RoleServicesForFeature = ($AllRemovedFeatures | Where-Object { $_.Parent -eq $Feature.Name })
		           if ($RoleServicesForFeature)
		           {
		    	       $RoleServiceDisplay = Out-MultiLevelObject -items $RemovedRoleServices -StartObjects $RoleServicesForFeature -path "Name" -Parent "Parent" -label "DisplayName"
	    	       }
    		       else
		           {
			           $RoleServiceDisplay =  "<div style=`"margin-left:0`">&#160;</div>"
    		       }
		           add-member -inputobject $Features_Summary -membertype noteproperty -name $Feature.DisplayName -value $RoleServiceDisplay
                }
				
                $Features_Summary | ConvertTo-Xml2 | update-diagreport -ID "07_RemovedRolesFeatures" -name "Removed Feature/ Services" -verbosity "Informational"
	
            }
		}
	}
}


# SIG # Begin signature block
# MIInlAYJKoZIhvcNAQcCoIInhTCCJ4ECAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCBG7zbaixXayU1E
# UBodUAZ15B2Kp+gyK8ZV4Qgtfbv1ZKCCDXYwggX0MIID3KADAgECAhMzAAACy7d1
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
# /Xmfwb1tbWrJUnMTDXpQzTGCGXQwghlwAgEBMIGVMH4xCzAJBgNVBAYTAlVTMRMw
# EQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVN
# aWNyb3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMTH01pY3Jvc29mdCBDb2RlIFNp
# Z25pbmcgUENBIDIwMTECEzMAAALLt3U5+wJxQjYAAAAAAsswDQYJYIZIAWUDBAIB
# BQCggbAwGQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQwHAYKKwYBBAGCNwIBCzEO
# MAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIJo/x7DocApLtT/Gu/icHNXx
# qFko+s2c6vE/FmOdVpfBMEQGCisGAQQBgjcCAQwxNjA0oBSAEgBNAGkAYwByAG8A
# cwBvAGYAdKEcgBpodHRwczovL3d3dy5taWNyb3NvZnQuY29tIDANBgkqhkiG9w0B
# AQEFAASCAQAcvWMny0fQUQ8cry7vBl58zJTUEL8s8EKNJSM895tgNZiVBoFIKmU5
# 9i5BH3IhZqtnc8mvlrMi1Sa1goUsxzGxD9jl+K3x+0JL+P3Q2uZOwM3nKd9J85oj
# RL3Mv1chhmjIckv43oUW7ohmkDA+PPaBJPZw5gK2JebJ4WmrJ5ofDNhKC/ATsLmq
# X9C7FnLGP1vosN43EHrwC7DZn/io4AyAWd3fhFsj3FfndLEu+LrP3FYRCodI+GVZ
# 0j87sJHjCIwHqIQJiY60/gTlDkXg++1HBCurxh8NTGmAyrN3qDszK0CN+58OnIRq
# PMJOigtkaZoFal5nVP43DJfS9Pk0T4QcoYIW/DCCFvgGCisGAQQBgjcDAwExghbo
# MIIW5AYJKoZIhvcNAQcCoIIW1TCCFtECAQMxDzANBglghkgBZQMEAgEFADCCAVAG
# CyqGSIb3DQEJEAEEoIIBPwSCATswggE3AgEBBgorBgEEAYRZCgMBMDEwDQYJYIZI
# AWUDBAIBBQAEIEMJGOG0uwBIqvJkVxgmq/lA/R1t5roG5OYxuWePfiwjAgZi1+uY
# RYIYEjIwMjIwODAxMDc1MTAyLjY2WjAEgAIB9KCB0KSBzTCByjELMAkGA1UEBhMC
# VVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNV
# BAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjElMCMGA1UECxMcTWljcm9zb2Z0IEFt
# ZXJpY2EgT3BlcmF0aW9uczEmMCQGA1UECxMdVGhhbGVzIFRTUyBFU046NDlCQy1F
# MzdBLTIzM0MxJTAjBgNVBAMTHE1pY3Jvc29mdCBUaW1lLVN0YW1wIFNlcnZpY2Wg
# ghFUMIIHDDCCBPSgAwIBAgITMwAAAZcDz1mca4l4PwABAAABlzANBgkqhkiG9w0B
# AQsFADB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UE
# BxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSYwJAYD
# VQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAxMDAeFw0yMTEyMDIxOTA1
# MTRaFw0yMzAyMjgxOTA1MTRaMIHKMQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2Fz
# aGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENv
# cnBvcmF0aW9uMSUwIwYDVQQLExxNaWNyb3NvZnQgQW1lcmljYSBPcGVyYXRpb25z
# MSYwJAYDVQQLEx1UaGFsZXMgVFNTIEVTTjo0OUJDLUUzN0EtMjMzQzElMCMGA1UE
# AxMcTWljcm9zb2Z0IFRpbWUtU3RhbXAgU2VydmljZTCCAiIwDQYJKoZIhvcNAQEB
# BQADggIPADCCAgoCggIBAO0ASupKQU3z8J79yysdVZy/WJKM1MCs8oQyoo9ROlgl
# fxMFmXzws2unDhsSk+KY74S1yWLlEGhkSJ6j5LNhSdvT6coRZoRiC5uCn4dMVmIP
# zkuV3uaTZeD3UowMTbIx44gfYMelOyfmnQt/QIOV88Tkc7Ck/n++xTE14NYxbrOx
# K4pTr1ovs5zKTfpUzIIqMc0wvrtWZkwkE7ttfW9hVKE69CplSTEKkJHezObEdPT2
# zqeHAt40LPucydTs8SI0ZXFJi75XQROmkWkrtMdwZgAxrdJhmNDEbIM5zsnbSQS5
# 3q3PkCtJHMbjuqxwN89iq/X5qR7HzXDf3kT7WRzi66R+fQJ4q0AO6bs+pGttEwPv
# DIWdfYW/JrK0aPS5oq4xcUmxn7B92TRGy495Ye1XPgxEITB9ivVz4lOSZLef+m8e
# v9vznd2jbwug8d7OTd1LFueJCiNbcFNgkuatR6L+fgEcrmZNPw27EbrOg/e3wdWa
# EJb/+LawXDFUc+zJDqx2vGz+Fqmw9Hmy2LYhMb8eB7hJ4ftKd73jY4d4D9Puw5Il
# cCGHH1XJSIRRRrH50ohXsa7ruuOrlJWvlU1Lht246kuxYSN4Yekx6L//fF3x3Fnj
# Yb8QOSvn4vtQXEi4ECr6vx2I/8PzJH927u9zhEYrDWmnGmjgkf0ydh937NQO5SBx
# AgMBAAGjggE2MIIBMjAdBgNVHQ4EFgQUbc8BzyjrMG6WVQvRsb7dfr0VAGAwHwYD
# VR0jBBgwFoAUn6cVXQBeYl2D9OXSZacbUzUZ6XIwXwYDVR0fBFgwVjBUoFKgUIZO
# aHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3BraW9wcy9jcmwvTWljcm9zb2Z0JTIw
# VGltZS1TdGFtcCUyMFBDQSUyMDIwMTAoMSkuY3JsMGwGCCsGAQUFBwEBBGAwXjBc
# BggrBgEFBQcwAoZQaHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3BraW9wcy9jZXJ0
# cy9NaWNyb3NvZnQlMjBUaW1lLVN0YW1wJTIwUENBJTIwMjAxMCgxKS5jcnQwDAYD
# VR0TAQH/BAIwADATBgNVHSUEDDAKBggrBgEFBQcDCDANBgkqhkiG9w0BAQsFAAOC
# AgEABEjYYdIk7TMeeyFy34eC7h2w9TRvTJSwNcGEB0AZ0fVP64N6rdzcenu/kLhC
# jBISqnS394OUUeEf6GS+bxCVVlHyEh/6Elnc6q0oanJk+Dsc3NggbNFLZ8qKVQ5u
# FtgrpqN6rspGD6QaBnXoq7w3XdedwMLCZCDIJv/LMSSmyAXk/NrZ61J4DZjaPLu5
# dbhNIbDAKtW4r0Ot30CJ6/lamCb2E9Fv9D1u6QN6oeKHDY4l+mfHfZI8fC+7gTyP
# x7MYnwo//JhUb6VQWDsqj+2OXYuWQJ40w0hzGTVBTx7fp4RV1HB41z0URwjKqiYO
# A+t1+m9FdEfO0Pd4qcBiFwTMzjEDSLSTkXpB7R5S4t24Oi56Y7NGgqOf0ZRwozZE
# g4PsVe6mHmt+y/zikzY6ph96TQGtwbz/6w0IhhGL4AG1RxCEM+1jFkmLFnlDxWSN
# +pgo4FGOled/ApELQ8DPAQ4gHMvqrjvHqcpIj9B99sqsA4fOdgXlptXrRfj5MP7f
# Fzt0PnYhbuxoIqo3Xpo+FX6UbJtrUzfR5wHsK629F8GPEBNradIUXTdm9FIksTJg
# eITciil1WgyzhQnYi57H6Q9K4zh/I2xAmTm2lli5/XhLw6/kDUD70uK+Oy/QGvC6
# 9R6+O1cCeRNoAhJ72MCEQ86SYTEYtCoo2DeN8k+l0hkeDfYwggdxMIIFWaADAgEC
# AhMzAAAAFcXna54Cm0mZAAAAAAAVMA0GCSqGSIb3DQEBCwUAMIGIMQswCQYDVQQG
# EwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwG
# A1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMTIwMAYDVQQDEylNaWNyb3NvZnQg
# Um9vdCBDZXJ0aWZpY2F0ZSBBdXRob3JpdHkgMjAxMDAeFw0yMTA5MzAxODIyMjVa
# Fw0zMDA5MzAxODMyMjVaMHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5n
# dG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9y
# YXRpb24xJjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEwMIIC
# IjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA5OGmTOe0ciELeaLL1yR5vQ7V
# gtP97pwHB9KpbE51yMo1V/YBf2xK4OK9uT4XYDP/XE/HZveVU3Fa4n5KWv64NmeF
# RiMMtY0Tz3cywBAY6GB9alKDRLemjkZrBxTzxXb1hlDcwUTIcVxRMTegCjhuje3X
# D9gmU3w5YQJ6xKr9cmmvHaus9ja+NSZk2pg7uhp7M62AW36MEBydUv626GIl3GoP
# z130/o5Tz9bshVZN7928jaTjkY+yOSxRnOlwaQ3KNi1wjjHINSi947SHJMPgyY9+
# tVSP3PoFVZhtaDuaRr3tpK56KTesy+uDRedGbsoy1cCGMFxPLOJiss254o2I5Jas
# AUq7vnGpF1tnYN74kpEeHT39IM9zfUGaRnXNxF803RKJ1v2lIH1+/NmeRd+2ci/b
# fV+AutuqfjbsNkz2K26oElHovwUDo9Fzpk03dJQcNIIP8BDyt0cY7afomXw/TNuv
# XsLz1dhzPUNOwTM5TI4CvEJoLhDqhFFG4tG9ahhaYQFzymeiXtcodgLiMxhy16cg
# 8ML6EgrXY28MyTZki1ugpoMhXV8wdJGUlNi5UPkLiWHzNgY1GIRH29wb0f2y1BzF
# a/ZcUlFdEtsluq9QBXpsxREdcu+N+VLEhReTwDwV2xo3xwgVGD94q0W29R6HXtqP
# nhZyacaue7e3PmriLq0CAwEAAaOCAd0wggHZMBIGCSsGAQQBgjcVAQQFAgMBAAEw
# IwYJKwYBBAGCNxUCBBYEFCqnUv5kxJq+gpE8RjUpzxD/LwTuMB0GA1UdDgQWBBSf
# pxVdAF5iXYP05dJlpxtTNRnpcjBcBgNVHSAEVTBTMFEGDCsGAQQBgjdMg30BATBB
# MD8GCCsGAQUFBwIBFjNodHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpb3BzL0Rv
# Y3MvUmVwb3NpdG9yeS5odG0wEwYDVR0lBAwwCgYIKwYBBQUHAwgwGQYJKwYBBAGC
# NxQCBAweCgBTAHUAYgBDAEEwCwYDVR0PBAQDAgGGMA8GA1UdEwEB/wQFMAMBAf8w
# HwYDVR0jBBgwFoAU1fZWy4/oolxiaNE9lJBb186aGMQwVgYDVR0fBE8wTTBLoEmg
# R4ZFaHR0cDovL2NybC5taWNyb3NvZnQuY29tL3BraS9jcmwvcHJvZHVjdHMvTWlj
# Um9vQ2VyQXV0XzIwMTAtMDYtMjMuY3JsMFoGCCsGAQUFBwEBBE4wTDBKBggrBgEF
# BQcwAoY+aHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3BraS9jZXJ0cy9NaWNSb29D
# ZXJBdXRfMjAxMC0wNi0yMy5jcnQwDQYJKoZIhvcNAQELBQADggIBAJ1VffwqreEs
# H2cBMSRb4Z5yS/ypb+pcFLY+TkdkeLEGk5c9MTO1OdfCcTY/2mRsfNB1OW27DzHk
# wo/7bNGhlBgi7ulmZzpTTd2YurYeeNg2LpypglYAA7AFvonoaeC6Ce5732pvvinL
# btg/SHUB2RjebYIM9W0jVOR4U3UkV7ndn/OOPcbzaN9l9qRWqveVtihVJ9AkvUCg
# vxm2EhIRXT0n4ECWOKz3+SmJw7wXsFSFQrP8DJ6LGYnn8AtqgcKBGUIZUnWKNsId
# w2FzLixre24/LAl4FOmRsqlb30mjdAy87JGA0j3mSj5mO0+7hvoyGtmW9I/2kQH2
# zsZ0/fZMcm8Qq3UwxTSwethQ/gpY3UA8x1RtnWN0SCyxTkctwRQEcb9k+SS+c23K
# jgm9swFXSVRk2XPXfx5bRAGOWhmRaw2fpCjcZxkoJLo4S5pu+yFUa2pFEUep8beu
# yOiJXk+d0tBMdrVXVAmxaQFEfnyhYWxz/gq77EFmPWn9y8FBSX5+k77L+DvktxW/
# tM4+pTFRhLy/AsGConsXHRWJjXD+57XQKBqJC4822rpM+Zv/Cuk0+CQ1ZyvgDbjm
# jJnW4SLq8CdCPSWU5nR0W2rRnj7tfqAxM328y+l7vzhwRNGQ8cirOoo6CGJ/2XBj
# U02N7oJtpQUQwXEGahC0HVUzWLOhcGbyoYICyzCCAjQCAQEwgfihgdCkgc0wgcox
# CzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRt
# b25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJTAjBgNVBAsTHE1p
# Y3Jvc29mdCBBbWVyaWNhIE9wZXJhdGlvbnMxJjAkBgNVBAsTHVRoYWxlcyBUU1Mg
# RVNOOjQ5QkMtRTM3QS0yMzNDMSUwIwYDVQQDExxNaWNyb3NvZnQgVGltZS1TdGFt
# cCBTZXJ2aWNloiMKAQEwBwYFKw4DAhoDFQBhQNKwjZhJNM1Ndg2DRjFNwdZj0aCB
# gzCBgKR+MHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYD
# VQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJjAk
# BgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEwMA0GCSqGSIb3DQEB
# BQUAAgUA5pGTGDAiGA8yMDIyMDgwMTA3NDczNloYDzIwMjIwODAyMDc0NzM2WjB0
# MDoGCisGAQQBhFkKBAExLDAqMAoCBQDmkZMYAgEAMAcCAQACAh6LMAcCAQACAhHD
# MAoCBQDmkuSYAgEAMDYGCisGAQQBhFkKBAIxKDAmMAwGCisGAQQBhFkKAwKgCjAI
# AgEAAgMHoSChCjAIAgEAAgMBhqAwDQYJKoZIhvcNAQEFBQADgYEAXV5C4tYHr2Vx
# GTCUML/9Dy3owqEyXijhD4ZwBh73D8/WEONamwUjdfdD6rrPxC1f9DVzggrlLoYl
# cyXERtwqmJeScKJDyvhSyxlhN7epQh4GyHReiFyRBQkRsTNQxQCp7jvivcht/h2D
# A3mCvL3zzUkyuTCzsjRkdpmYvfoQFW4xggQNMIIECQIBATCBkzB8MQswCQYDVQQG
# EwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwG
# A1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQg
# VGltZS1TdGFtcCBQQ0EgMjAxMAITMwAAAZcDz1mca4l4PwABAAABlzANBglghkgB
# ZQMEAgEFAKCCAUowGgYJKoZIhvcNAQkDMQ0GCyqGSIb3DQEJEAEEMC8GCSqGSIb3
# DQEJBDEiBCDro2KaNlVfCubx9JB+TdCgBjZXD+p0+P2VgMYxKsv8ODCB+gYLKoZI
# hvcNAQkQAi8xgeowgecwgeQwgb0EIFt72hsQlXo4/gQMxUnzMXx0Pm8cZKgsPC5D
# GP0GeKa/MIGYMIGApH4wfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0
# b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3Jh
# dGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTACEzMA
# AAGXA89ZnGuJeD8AAQAAAZcwIgQgndd5Q0gY4a9ceW9Unyyhf6AyADQIfSYttYlH
# jrKSu98wDQYJKoZIhvcNAQELBQAEggIAh4eJgc0EfRLF9WPq6GPBouHxGWWRd1E7
# AUkDO5ujFWye/83bJiqB+Icnv2CEeLk+oZaJlopCvBmM+22amR1OJ1w1vGI+8fF4
# r6pJ+VM/cEHQuZCEIDHgp2CX+c+DpG9BvuYgta+3QAzwrR0vHJBx4ZAMHfB1r2w1
# NndUEqayTZoUJVP13pB1y+h7l6olz84R5l6PAZIdVcJ3P8hHnTa9g1asQ6Mmx9tO
# 8HGVDEyZvLjeX++8sxDaF8Ewomj3MGHlz933DFmHz8IKws3TxSTSdy5PEsywOI1Y
# 06imOA2Hm0YEdT/eHhvnsgWpDrJWYDWQXJfYJ0w8oLz9JA66jqsWAREucKZg4E7r
# iciYJuZ0Yo2GZXZeFZuwCyxzuAIs2O4eZgJWmeSyWkOdI12yZEda1R0kS05yaf7I
# 8yEyxtPvYUPjwdeY/dBD6fbvq4etVZrSLx+uztHfoB0pwmj5zBiTqVeLxIWuFKop
# S6NXYIJXDk0WLtPMYYXiHKWstIDVjfyS6NoeONd2lX/uttdsmUDkg2uqF8Xr8b3s
# ncA4a57TIuAZgbQMjuzcBqx9H/ETprz9lDBBFyejz2p+bLIVBGW7dcAMrz73+9mz
# 8kOwxnfqJem49xnD9tRAuZExkZUXRAHosvACkdtz35jpeTNRz4WV/NwfVVRtUFVM
# Uke8Gm35vPE=
# SIG # End signature block
