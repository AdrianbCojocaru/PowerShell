﻿# Local variables
$Script:TSSv2RegKey		= "HKLM:Software\Microsoft\CESDiagnosticTools\TSSv2"
$Script:TSSv2ParamRegKey = "$TSSv2RegKey\Parameters"
$Script:TSSv2ParamRegKeyArray = @{}
$Script:ETLFileCountByProvider = @{}
$Script:LogFolder = "C:\Windows\temp"
$Script:LogFile = "$Script:LogFolder\$($env:COMPUTERNAME)__Log-PurgeTask.txt"

Function LogMessage{
	param(
		[ValidateNotNullOrEmpty()]
		[Int]$Level,
		[parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[String]$Message,
		[ValidateNotNullOrEmpty()]
		[String]$Color,
		[Switch]$LogMsg=$False
	)

	If($Level -eq $Null){
		$Level = $LogLevel.Normal
	}

	If(($Level -eq $LogLevel.Debug) -and !($DebugMode.IsPresent)){
	   Return # Early return. This is LogMessage $LogLevel.Debug but DebugMode switch is not set.
	}

	Switch($Level){
		'0'{ # Normal
			$MessageColor = 'White'
			$LogConsole = $True
			$LogMessage = $Message
		}
		'1'{ # Info / Normal console message
			$MessageColor = 'Yellow'
			$LogConsole = $True
			$LogMessage = $Message  # Simple message
		}
		'2'{ # Warning
			$Levelstr = 'WARNING'
			$MessageColor = 'Magenta'
			$LogConsole = $True
		}
		'3'{ # Error
			$Levelstr = 'ERROR'
			$MessageColor = 'Red'
			$LogConsole = $True
		}
		'4'{ # Debug
			$Levelstr = 'DEBUG'
			$MessageColor = 'Green'
			If($DebugMode.IsPresent){
				$LogConsole = $True
			}Else{
				$LogConsole = $False
			}
		}
		'5'{ # ErrorLogFileOnly
			$Levelstr = 'ERROR'
			$LogConsole = $False
		}
		'6'{ # WarnLogFileOnly
			$Levelstr = 'WARNING'
			$LogConsole = $False
		}
		'7'{ # InfoLogFileOnly / Normal LogFile message
			$Levelstr = 'INFO'
			$LogMessage = $Message  # Simple message
			$LogConsole = $False
		}
	}

	# If color is specifed, overwrite it.
	If($Color -ne $Null -and $Color.Length -ne 0){
		$MessageColor = $Color
	}

	$Index = 1
	# In case of Warning/Error/Debug, add a function name and a line numberand to message.
	If($Level -eq $LogLevel.Warning -or $Level -eq $LogLevel.Error -or $Level -eq $LogLevel.Debug -or $Level -eq $LogLevel.ErrorLogFileOnly -or $Level -eq $LogLevel.WarnLogFileOnly -or $Level -eq $LogLevel.InfoLogFileOnly){
		$CallStack = Get-PSCallStack
		$CallerInfo = $CallStack[$Index]
		$2ndCallerInfo = $CallStack[$Index+1]
		$3rdCallerInfo = $CallStack[$Index+2]

		# LogMessage() is called from wrapper function like LogInfo() and EnterFun(). In this case, we show caller of the wrapper function.
		If($CallerInfo.FunctionName -notlike "*LogException" -and ($CallerInfo.FunctionName -like "Log*" -or $CallerInfo.FunctionName -like "*EnterFunc" -or $CallerInfo.FunctionName -like "*EndFunc")){
			$CallerInfo = $2ndCallerInfo # Set actual function name calling LogInfo/LogWarn/LogError
			If($CallerInfo.FunctionName -like "*LogException"){
				$CallerInfo = $3rdCallerInfo
			}
		}
		$FuncName = $CallerInfo.FunctionName.Replace("global:","")
		If($FuncName -eq "<ScriptBlock>"){
			$FuncName = "Main"
		}

		# If this is from POD module, add the module name in front of the function name.
		If($CallerInfo.ScriptName -notlike "*$global:ScriptName"){ # ScriptName = 'TSSv2.ps1'
			$FuncName = (((Split-path $CallerInfo.ScriptName -leaf) -replace "TSSv2_","") + ":" + $FuncName)
		}
		$LogMessage = ((Get-Date).ToString("yyyyMMdd HH:mm:ss.fff") + ' [' + $FuncName + '(' + $CallerInfo.ScriptLineNumber + ')]'+ " $Levelstr" + ": " + $Message)
	}Else{
		$LogMessage = (Get-Date).ToString("yyyyMMdd HH:mm:ss.fff") + " " + $Message
	}

	If($LogConsole){
		Write-Host $LogMessage -ForegroundColor $MessageColor
	}

	# In case of error, warning, ErrorLogFileOnly, WarnLogFileOnly and InfoLogFileOnly, we log the message to error log file.
	If(![String]::IsNullOrEmpty($LogFolder) -and $LogMsg){
		$LogMessage | Out-File -Append $Script:LogFile -ErrorAction Stop
	}
}

Function LogInfoFile {
	param(
		[parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[String]$Message
	)
    LogMessage $Loglevel.InfoLogFileOnly $Message -LogMsg
}

Function LogErrorFile {
	param(
		[parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[String]$Message
	)
    LogMessage $Loglevel.ErrorLogFileOnly $Message -LogMsg
}


Function ReadParameterFromTSSv2Reg{
	LogInfoFile "$Script:TSSv2ParamRegKey"
	If(!(Test-Path $Script:TSSv2ParamRegKey)){
		LogInfoFile "There are no parameter settings in TSSv2 registry."
		Return
	}Else{
		LogInfoFile "Reading parameters from TSSv2 registry."
		
		$ParamArray = Get-Item "$Script:TSSv2ParamRegKey" | Select-Object -ExpandProperty Property -ErrorAction Ignore
		$RegValue = Get-ItemProperty -Path  "$Script:TSSv2ParamRegKey" -ErrorAction Ignore
		ForEach($Param in $ParamArray){
			$Data = $RegValue.$Param

			# Convert string boolean to boolean
			If($Data -eq "True"){
				$Data = $True
			}ElseIf($Data -eq "False"){
				$Data = $False
			}

			# Load data as a string array if data has delimiter(,).
			If($Data.gettype().Name -eq 'String'){
				If($Data.contains(',')){
					$Data = $Data -split ','
				}
			}

			LogInfoFile ('  - $' + "$Param($(($Data.gettype()).Name)) = $Data")
			If(!($Script:TSSv2ParamRegKeyArray.ContainsKey($Param))){
				$Script:TSSv2ParamRegKeyArray.Add($Param,$Data)
			}
		}
	}
}

###
### Main
###
LogInfoFile "==================== START ===================="
# Read parameters from TSSv2 registry to get log folder and NrFilesToKeep.
ReadParameterFromTSSv2Reg

# Purge ETL files
# Get ETLNumberToKeep and log folder.
If($Script:TSSv2ParamRegKeyArray.ContainsKey('LogFolder')){
    $TSSv2LogFolder = $Script:TSSv2ParamRegKeyArray['LogFolder']
    If([String]::IsNullOrEmpty($TSSv2LogFolder)){
        LogErrorFile "LogFolder is null."
        LogInfoFile "==================== END ===================="
        Return
    }
}Else{
    If([String]::IsNullOrEmpty($TSSv2LogFolder)){
        LogErrorFile "LogFolder is not set in $($Script:TSSv2ParamRegKey)."
        LogInfoFile "==================== END ===================="
        Return
    }
}

If($Script:TSSv2ParamRegKeyArray.ContainsKey('EtlOptions')){
    $EtlOptions = $Script:TSSv2ParamRegKeyArray['EtlOptions'] -split ':'
    $ETLNumberToKeep = $EtlOptions[2]
    If([String]::IsNullOrEmpty($ETLNumberToKeep)){
        LogErrorFile "Found EtlOptions but ETLNumberToKeep is not set."
        Return
    }
}

LogInfoFile "ETLNumberToKeep = $ETLNumberToKeep"
LogInfoFile "LogFolder = $TSSv2LogFolder"
$ETLFiles = @()
$AllETLFiles = Get-Item "$TSSv2LogFolder\*"

ForEach($ETLFile in $AllETLFiles){
    If(($ETLFile.Name -like "*.etl") -and ($ETLFile.Name -notlike "*WPR*") -and ($ETLFile.Name -notlike "*Netsh*")){
        $ETLFiles += $ETLFile
    }
}

ForEach($ETLFile in $ETLFiles){
    $Token = $ETLFile.Name -Split "_"
    # Get 2nd token from end. That is the trace provider name.
    [Int]$ProviderTokenIndex = $Token.Count - 2
    $Provider = $Token[$ProviderTokenIndex]
    If($ETLFileCountByProvider.ContainsKey($Provider)){
        $ETLFileCountByProvider[$Provider] = $ETLFileCountByProvider[$Provider] + 1
    }Else{
        $ETLFileCountByProvider.Add($Provider,1)
    }
}

LogInfoFile "Number of files by provider: $($ETLFileCountByProvider.Count)"
$CadidateFiles = $Null
ForEach($Key in $ETLFileCountByProvider.Keys){
    $FileCount = $ETLFileCountByProvider[$Key]
    LogInfoFile "  - $Key $FileCount files"
    If($FileCount -gt $ETLNumberToKeep){
        $CadidateFiles = Get-Item "$TSSv2LogFolder\*_$Key*.etl" | Sort-Object -Property LastWriteTime
        $CadidateFiles = $CadidateFiles[0 .. ($CadidateFiles.Count - $ETLNumberToKeep - 1)]
        Remove-Item $CadidateFiles -ErrorAction SilentlyContinue
        LogInfoFile "    Files deleted for $($Key):"
        ForEach($CadidateFile in $CadidateFiles){
            LogInfoFile "    - $($CadidateFile.Name)"
        }
    }
}

# Purge Netsh file
# => To be implemented.
LogInfoFile "==================== END ===================="

# SIG # Begin signature block
# MIInqQYJKoZIhvcNAQcCoIInmjCCJ5YCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCAiCnmGCw5a2GHE
# fnTekEYw4d9YaAJAARLDcPKout9ZnKCCDYEwggX/MIID56ADAgECAhMzAAACzI61
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
# RcBCyZt2WwqASGv9eZ/BvW1taslScxMNelDNMYIZfjCCGXoCAQEwgZUwfjELMAkG
# A1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQx
# HjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEoMCYGA1UEAxMfTWljcm9z
# b2Z0IENvZGUgU2lnbmluZyBQQ0EgMjAxMQITMwAAAsyOtZamvdHJTgAAAAACzDAN
# BglghkgBZQMEAgEFAKCBrjAZBgkqhkiG9w0BCQMxDAYKKwYBBAGCNwIBBDAcBgor
# BgEEAYI3AgELMQ4wDAYKKwYBBAGCNwIBFTAvBgkqhkiG9w0BCQQxIgQgl8E98isd
# 0Dv2KBhxfTsq/ZKmQ2JYbctvEgXqRXtOHVwwQgYKKwYBBAGCNwIBDDE0MDKgFIAS
# AE0AaQBjAHIAbwBzAG8AZgB0oRqAGGh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbTAN
# BgkqhkiG9w0BAQEFAASCAQAhMs/fQQm7wLQMQ/5mb17We9IXtP5ecdtDk6X9yD/d
# ErFems260Mo1RWDaf12qSgWuAUoiBn9SuaOx/Lo8dbL7+ODos8+VC8D/X0lPgTPq
# /E1aJI9H9Ps/nb2rtZJB0ARH+F5DGoTWekkw2vtxeUqs+p+zXgOMG93yChS66kb9
# JUTAmba/RUcYTvWIES4Yhb6NDqk2aKNsZjOxo07HeOkt005MtEm5x47erUWlHeJl
# NSaD3uT43XabJeha7i6lq98haYbCvWge8iQjvAcpTUk5wv+Mp3sGDst6NaTRD7Tb
# i8MCfY7y8g/YZU2OXq4QZUIpIYvr5KD5XfbZDPPA40tYoYIXCDCCFwQGCisGAQQB
# gjcDAwExghb0MIIW8AYJKoZIhvcNAQcCoIIW4TCCFt0CAQMxDzANBglghkgBZQME
# AgEFADCCAVQGCyqGSIb3DQEJEAEEoIIBQwSCAT8wggE7AgEBBgorBgEEAYRZCgMB
# MDEwDQYJYIZIAWUDBAIBBQAEIAQJ6D6NB1Pxz6zb1FS6H1soocqwY/8pImBqk3iu
# JOWUAgZjTo6Xd+EYEjIwMjIxMDI2MTQzMTM3LjYyWjAEgAIB9KCB1KSB0TCBzjEL
# MAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1v
# bmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEpMCcGA1UECxMgTWlj
# cm9zb2Z0IE9wZXJhdGlvbnMgUHVlcnRvIFJpY28xJjAkBgNVBAsTHVRoYWxlcyBU
# U1MgRVNOOkM0QkQtRTM3Ri01RkZDMSUwIwYDVQQDExxNaWNyb3NvZnQgVGltZS1T
# dGFtcCBTZXJ2aWNloIIRXDCCBxAwggT4oAMCAQICEzMAAAGj+5qzjnuGQ08AAQAA
# AaMwDQYJKoZIhvcNAQELBQAwfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hp
# bmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jw
# b3JhdGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTAw
# HhcNMjIwMzAyMTg1MTE2WhcNMjMwNTExMTg1MTE2WjCBzjELMAkGA1UEBhMCVVMx
# EzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoT
# FU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEpMCcGA1UECxMgTWljcm9zb2Z0IE9wZXJh
# dGlvbnMgUHVlcnRvIFJpY28xJjAkBgNVBAsTHVRoYWxlcyBUU1MgRVNOOkM0QkQt
# RTM3Ri01RkZDMSUwIwYDVQQDExxNaWNyb3NvZnQgVGltZS1TdGFtcCBTZXJ2aWNl
# MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA771Nyst7KgpwKots23Ps
# 23Yls/VMTPMyGLziBLpgsjsIXp1VIDkjVsUIdzDpkXZ4XxCJp/SjZdJd/+OnmyCZ
# Ri0xsaLid4C1ZI0rnKG3iLJCEHGfRMhCoX42KyIHFb56ExhYRsUj7txJ1f91bD79
# jz8y726rdcIrk/Yb5mJtXA5Uf3n4iJMaeahzFaB2zSqUGlrWtiDduXxdV7kvapNS
# YkG+dCnHZtSu7vSW3b8ehTlsFssoCEI+nHLieayt05Hca/hRt8Ca2lCe0/vnw1E+
# GDVsAIfToWW9sjI/z+5GzfHbfbd1poaklBhChmkAGDrasUNMnj57Tq237Ft++nwz
# 2WjxrVqB/FlDWkhPVWcl1o73yBYyIxbrl14VSJRH5aeBBV+/aAuy/qjv45ynPLpE
# dkibpYQZn0sG3nvU18KzHnPQiW+vpLM3RBtpYlMshZtfBtRUph5utcRUUzKG5UZA
# d6xkH5XBXfzqFiiczGzSO8zwak5zHTEvLKbjZcD31VKmy6K9MmDijxrUAIltMFUW
# gQDdWsVJjM51Dq/NfGvHDqL9PXfyb5cX7Iq0ASeGn5R4AyGXDuM/30QCWAZSXQqR
# wGNNhPP6MTI+App2tTWh/mgWL+r1gOWtW/0fgmxV7wYcw6Q9M2gHjTbyPzw4R7jb
# oGx9xcuSLSmE+nuKtbQBtF0CAwEAAaOCATYwggEyMB0GA1UdDgQWBBRQUfuzPCYI
# sc9NL0GjaKsucmOLqjAfBgNVHSMEGDAWgBSfpxVdAF5iXYP05dJlpxtTNRnpcjBf
# BgNVHR8EWDBWMFSgUqBQhk5odHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpb3Bz
# L2NybC9NaWNyb3NvZnQlMjBUaW1lLVN0YW1wJTIwUENBJTIwMjAxMCgxKS5jcmww
# bAYIKwYBBQUHAQEEYDBeMFwGCCsGAQUFBzAChlBodHRwOi8vd3d3Lm1pY3Jvc29m
# dC5jb20vcGtpb3BzL2NlcnRzL01pY3Jvc29mdCUyMFRpbWUtU3RhbXAlMjBQQ0El
# MjAyMDEwKDEpLmNydDAMBgNVHRMBAf8EAjAAMBMGA1UdJQQMMAoGCCsGAQUFBwMI
# MA0GCSqGSIb3DQEBCwUAA4ICAQBa8t6naZfDqK4HEa7Q+yy2ZcjmAuaA+RMpCeOB
# mWyh6Kmy1r2iS7QxNXGUdV1x0FsVxUcwtFGRQUiR8qdpyXKXl7KPTfB4Ppv+lR8X
# INkHwBmkZReFNgs1Hw96kzrIPqD7QTWcfQyE4agTpcW5+Rufp4h01Ma5bAF4SvYM
# 2IaEMaXBpQfkQvPeG27IzJYoCBgXbwLiLLKFh2+Ub1U3omcLiZz8Qi3nQEIenxlA
# CTscLdE6W2DWC7k2MZpJV2KxqLk4lZ/p7mxhB0ME1gpcl2Id6LU3sr4vmzW9X4Lp
# 3dOwX34A2mKgEMA4acVJi3g/661bXWLfuIsstv3bqkIvgvL74ZTTCXNh+fufbZHJ
# Ca8PXWjKJkeGZGywMGqwD6e8JW1+cfXzcN/mgEFWyTNlwlNSMLFpqAMrsCoHpADc
# fuX/ZIV56p9f8O12V7gH689XiWrUIKzQDUsH2WbNLS/GhEO6xjzQNCLXQrdJ9krW
# HLJqP1ryltkbQGwGnY3BzjG04MR4FNagDMX2SjhXp3T24UWkmsuhX57xwlT+FPf5
# KVbt2evl21i/OIdOlm65G/gpToXc5DM2kd/twEulYpFdGMZh1WcAZvw3NbrBZONm
# MwI10IUbumQosw4Z2o8MV1+T4RgTlFIb3LFLvpw99epEpW0llJwgXrh6OddsUizl
# uHwrATCCB3EwggVZoAMCAQICEzMAAAAVxedrngKbSZkAAAAAABUwDQYJKoZIhvcN
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
# OHBE0ZDxyKs6ijoIYn/ZcGNTTY3ugm2lBRDBcQZqELQdVTNYs6FwZvKhggLPMIIC
# OAIBATCB/KGB1KSB0TCBzjELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0
# b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3Jh
# dGlvbjEpMCcGA1UECxMgTWljcm9zb2Z0IE9wZXJhdGlvbnMgUHVlcnRvIFJpY28x
# JjAkBgNVBAsTHVRoYWxlcyBUU1MgRVNOOkM0QkQtRTM3Ri01RkZDMSUwIwYDVQQD
# ExxNaWNyb3NvZnQgVGltZS1TdGFtcCBTZXJ2aWNloiMKAQEwBwYFKw4DAhoDFQAe
# X+leQswBs9qkLBr4ZdzdKUMNE6CBgzCBgKR+MHwxCzAJBgNVBAYTAlVTMRMwEQYD
# VQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24xJjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1w
# IFBDQSAyMDEwMA0GCSqGSIb3DQEBBQUAAgUA5wOYrjAiGA8yMDIyMTAyNjE1Mjk1
# MFoYDzIwMjIxMDI3MTUyOTUwWjB0MDoGCisGAQQBhFkKBAExLDAqMAoCBQDnA5iu
# AgEAMAcCAQACAg4sMAcCAQACAhFCMAoCBQDnBOouAgEAMDYGCisGAQQBhFkKBAIx
# KDAmMAwGCisGAQQBhFkKAwKgCjAIAgEAAgMHoSChCjAIAgEAAgMBhqAwDQYJKoZI
# hvcNAQEFBQADgYEAOeQKaTTLk7upkyx/KKUAAnGgsdSlJkPOEV8+TSbriv7FurPi
# qFM/+jcJPX6f+gH2DWy+IIzmLVi3czI+MZme5HPEiJX/05h+De4KNmz032teDi+1
# cicWyF9wYFVfLiB7buMFxkbgoRyIkUdOenf9BcO9o1ysuMq3lLGsYQxvitcxggQN
# MIIECQIBATCBkzB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQ
# MA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9u
# MSYwJAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAxMAITMwAAAaP7
# mrOOe4ZDTwABAAABozANBglghkgBZQMEAgEFAKCCAUowGgYJKoZIhvcNAQkDMQ0G
# CyqGSIb3DQEJEAEEMC8GCSqGSIb3DQEJBDEiBCB9j9YDxQ47Jlfi05XervSHKtv3
# Xt23fAiQn2jnKj7GxjCB+gYLKoZIhvcNAQkQAi8xgeowgecwgeQwgb0EIIz4uLAG
# ccwyg53+yBtpjGnC8QmVERmX+lM+SXPp643+MIGYMIGApH4wfDELMAkGA1UEBhMC
# VVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNV
# BAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRp
# bWUtU3RhbXAgUENBIDIwMTACEzMAAAGj+5qzjnuGQ08AAQAAAaMwIgQgMLScLI/X
# SVdb0M2x/GQaTScu5zrgCsbBTjg1wWX8ufIwDQYJKoZIhvcNAQELBQAEggIA5JuP
# Fbih5BdqzUHAosWJLMIu0ZgNuZMAHHRPpLSmaHUoucKXcazb1wyvil4IOy2IFNHm
# rwFQbGVjXvevAfyz0nkidcS1BKHt+pNWiYaGQyOdMuu42PiFcas8mnJx9fcVXILj
# /uujDji2eZ6LUNvItuuEOaq8eAOocR1QciX/vMNbpTUVe0kGpYGRLIosPCiv8Hlp
# Nz9oo3EkGImHWmnVammD5KOYDHuTgIZt3iD3yQHgNk85hhSO0aVUsu4QbOzP0n1O
# N5/hGv26Nv66fu3jFp/5ShxSO8ljpN6zAhRP9kOAsWHdPhqdU+vz2+Ap8oGt+0RY
# QNPTOLZms6s7qnFIVWYEqKaViKlLgz/8Gcy41LXz55QrVIizfcMXcVw3aPm03w/H
# 0wOGLXo5kqdrxMEIdhbIGKzSEctB+POx/QBcdGftkltnmxsqla4HzLvwmeySMuKC
# JWtCMFK3BDHU5/eMShVU+bMmPgcs6G6Lb3Na/19Ls6EZt//i+MiSdgUfYRWag+9Z
# +SP5JAFZTT68P/WCwVd5MeXvfCks/pN4iBqdVDmNb8DujaAqyTgdYvMY942AJp+x
# L3O9pkVaiRJlmIsdJPDk3FV9CsztxMJzVV52FJS8b/cxdoJFDNVhQIkjiuQujtP5
# LwIx/I52MX4g7GMltYwbddMdY4GUzZ5JPcmFAk8=
# SIG # End signature block
