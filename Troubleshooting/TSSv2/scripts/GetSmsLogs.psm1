# GetSmsLogs.psm1 https://github.com/nedpyle/storagemigrationservicehelper
# https://raw.githubusercontent.com/nedpyle/storagemigrationservicehelper/master/StorageMigrationServiceHelper.psm1
# Date: Jun 15, 2020

# Windows Server Storage Migration Service Helper

# Copyright (c) Microsoft Corporation. All rights reserved.

# MIT License

# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:

# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.

# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.


Function GetSmsLogsFolder($Path, [ref]$SmsLogsFolder)
{
    $suffix = $null
    $folderNamePrefix = "StorageMigrationLog_$targetComputerName"
    
    do
    {
        $p = $Path + "\$folderNamePrefix"
        if ($null -ne $suffix)
        {
            $p += "_$suffix"
            $suffix += 1
        }
        else
        {
            $suffix = 1
        }
    } while (Test-Path $p -erroraction 'silentlycontinue')
    
    $SmsLogsFolder.value = $p
}

Function LogAction($message)
{
    Write-Output "==> $message"
}

Function GetSmsEventLogs($SmsLogsFolder)
{
    $names = @{
        "Microsoft-Windows-StorageMigrationService/Debug" = "$($targetComputerName)_Sms_Debug.log"
        "Microsoft-Windows-StorageMigrationService-Proxy/Debug" ="$($targetComputerName)_Proxy_Debug.log"
    }

    foreach ($key in $names.Keys)
    {
        $outFile = $names[$key]
        LogAction "Collecting traces for $($key) (outFile=$outFile)"
        
        $outFullFile = "$SmsLogsFolder\$outFile"
        
        if (! $computerNameWasProvided)
        {
            get-winevent -logname $key -oldest -ea SilentlyContinue | foreach-object {$_.Message} > "$outFullFile"
        }
        else
        {
            if ($null -eq $Credential)
            {
                Get-WinEvent -ComputerName $targetComputerName -logname $key -oldest -ea SilentlyContinue | foreach-object {$_.Message} > "$outFullFile"
            }
            else
            {
                Get-WinEvent -ComputerName $targetComputerName -Credential $Credential -logname $key -oldest -ea SilentlyContinue | foreach-object {$_.Message} > "$outFullFile"
            }
        }
    }
}

Function GetSmsEventLogs2($SmsLogsFolder)
{
    $names = @{
    "Microsoft-Windows-StorageMigrationService/Admin" = "$($targetComputerName)_Sms_Admin.log"
    "Microsoft-Windows-StorageMigrationService/Operational" = "$($targetComputerName)_Sms_Operational.log"

    "Microsoft-Windows-StorageMigrationService-Proxy/Admin" = "$($targetComputerName)_Proxy_Admin.log"
    "Microsoft-Windows-StorageMigrationService-Proxy/Operational" = "$($targetComputerName)_Proxy_Operational.log"
    }

    foreach ($key in $names.Keys)
    {
        $outFile = $names[$key]
        LogAction "Collecting traces for $($key) (outFile=$outFile)"
        
        $outFullFile = "$SmsLogsFolder\$outFile"
        
        if (! $computerNameWasProvided)
        {
            get-winevent -logname $key -oldest -ea SilentlyContinue | foreach-object { #write "$_.TimeCreated $_.Id $_.LevelDisplayName $_.Message"} > "$outFullFile"
                $id=$_.Id;
                $l = (0, (6 - $id.Length) | Measure-Object -Max).Maximum
                $m = "$($_.TimeCreated) {0,$l} $($_.LevelDisplayName) " -f $id
                $m += $_.Message
                $m
            } > "$outFullFile"

        }
        else
        {
            if ($null -eq $Credential)
            {
                Get-WinEvent -ComputerName $targetComputerName -logname $key -oldest -ea SilentlyContinue | foreach-object {#write "$_.TimeCreated $_.Id $_.LevelDisplayName $_.Message"} > "$outFullFile"
                    $id=$_.Id;
                    $l = (0, (6 - $id.Length) | Measure-Object -Max).Maximum
                    $m = "$($_.TimeCreated) {0,$l} $($_.LevelDisplayName) " -f $id
                    $m += $_.Message
                    $m
                } > "$outFullFile"
            }
            else
            {
                Get-WinEvent -ComputerName $targetComputerName -Credential $Credential -logname $key -oldest -ea SilentlyContinue | foreach-object {#write "$_.TimeCreated $_.Id $_.LevelDisplayName $_.Message"} > "$outFullFile"
                    $id=$_.Id;
                    $l = (0, (6 - $id.Length) | Measure-Object -Max).Maximum
                    $m = "$($_.TimeCreated) {0,$l} $($_.LevelDisplayName) " -f $id
                    $m += $_.Message
                    $m
                } > "$outFullFile"
            }
        }
    }
}


Function GetSystemEventLogs($SmsLogsFolder)
{
    $outFile = "$($targetComputerName)_System.log"
    $outFullFile = "$SmsLogsFolder\$outFile"
    
    if (! $computerNameWasProvided)
    {
        get-winevent -logname System -oldest -ea SilentlyContinue | foreach-object {
            $id=$_.Id;
            $l = (0, (6 - $id.Length) | Measure-Object -Max).Maximum
            $m = "$($_.TimeCreated) {0,$l} $($_.LevelDisplayName) " -f $id
            $m += $_.Message
            $m
        } > "$outFullFile"
    }
    else
    {
        if ($null -eq $Credential)
        {
            get-winevent -ComputerName $targetComputerName -logname System -oldest -ea SilentlyContinue | foreach-object {
                $id=$_.Id;
                $l = (0, (6 - $id.Length) | Measure-Object -Max).Maximum
                $m = "$($_.TimeCreated) {0,$l} $($_.LevelDisplayName) " -f $id
                $m += $_.Message
                $m
            } > "$outFullFile"
        }
        else
        {
            get-winevent -ComputerName $targetComputerName -Credential $Credential -logname System -oldest -ea SilentlyContinue | foreach-object {
                $id=$_.Id;
                $l = (0, (6 - $id.Length) | Measure-Object -Max).Maximum
                $m = "$($_.TimeCreated) {0,$l} $($_.LevelDisplayName) " -f $id
                $m += $_.Message
                $m
            } > "$outFullFile"
        }
    }
}

Function GetSystemInfo($SmsLogsFolder)
{
    if (! $computerNameWasProvided)
    {
        $remoteFeatures = Get-WindowsFeature
        
        $windows = $env:systemroot
	    $orcver = Get-ChildItem $windows\sms\* | Format-List versioninfo
	    $proxyver = Get-ChildItem $windows\smsproxy\* | Format-List versioninfo
        
    }
    else
    {
        if ($null -eq $Credential)
        {
            $remoteFeatures = Get-WindowsFeature -ComputerName $targetComputerName
        }
        else
        {
            $remoteFeatures = Get-WindowsFeature -ComputerName $targetComputerName -Credential $Credential
        }
    }
    
    $remoteFeatures | Format-Table -AutoSize
    
    if ($computerNameWasProvided)
    {
        # We want to find out whether SMS cmdlets are present on the local computer
        $features = Get-WindowsFeature *SMS*
    }
    else
    {
        $features = $remoteFeatures
    }

    $areSmsCmdletsAvailable = $false
    $isSmsInstalled = $false
    Write-Output $orcver
    Write-Output $proxyver
    
    foreach ($feature in $features)
    {
        if ($feature.Name -eq "RSAT-SMS")
        {
            $areSmsCmdletsAvailable = $feature.Installed
            break
        }
    }
    
    foreach ($feature in $remoteFeatures)
    {
        if ($feature.Name -eq "SMS")
        {
            $isSmsInstalled = $feature.Installed
            break
        }
    }
    
    Write-Output "areSmsCmdletsAvailable: $areSmsCmdletsAvailable"
    Write-Output "isSmsInstalled: $isSmsInstalled"

    if ($areSmsCmdletsAvailable -and $isSmsInstalled)
    {
        if (! $computerNameWasProvided)
        {
            $smsStates = Get-SmsState
        }
        else
        {
            if ($null -eq $Credential)
            {
                $smsStates = Get-SmsState -OrchestratorComputerName $targetComputerName
            }
            else
            {
                $smsStates = Get-SmsState -OrchestratorComputerName $targetComputerName -Credential $Credential
            }
        }
        
        Write-Output $smsStates
Write-Output "After ###################"

        foreach ($state in $smsStates)
        {
            $job = $state.Job
            Write-Output "+++"
            Write-Output "Inventory summary for job: $job"
            
            if (! $computerNameWasProvided)
            {
                $inventorySummary = Get-SmsState -Name $job -InventorySummary
            }
            else
            {
                if ($null -eq $Credential)
                {
                    $inventorySummary = Get-SmsState -OrchestratorComputerName $targetComputerName -Name $job -InventorySummary
                }
                else
                {
                    $inventorySummary = Get-SmsState -OrchestratorComputerName $targetComputerName -Credential $Credential -Name $job -InventorySummary
                }
            }
            
            Write-Output $inventorySummary

            foreach ($entry in $inventorySummary)
            {
                $device = $entry.Device
                Write-Output "!!!"
                Write-Output "Inventory config detail for device: $device"

                if (! $computerNameWasProvided)
                {
                    $detail = Get-SmsState -Name $job -ComputerName $device -InventoryConfigDetail
                }
                else
                {
                    if ($null -eq $Credential)
                    {
                        $detail = Get-SmsState -OrchestratorComputerName $targetComputerName -Name $job -ComputerName $device -InventoryConfigDetail
                    }
                    else
                    {
                        $detail = Get-SmsState -OrchestratorComputerName $targetComputerName -Credential $Credential -Name $job -ComputerName $device -InventoryConfigDetail
                    }
                }

                Write-Output $detail

                Write-Output "!!!"
                Write-Output "Inventory SMB detail for device: $device"

                if (! $computerNameWasProvided)
                {
                    $detail = Get-SmsState -Name $job -ComputerName $device -InventorySMBDetail
                }
                else
                {
                    if ($null -eq $Credential)
                    {
                        $detail = Get-SmsState -OrchestratorComputerName $targetComputerName -Name $job -ComputerName $device -InventorySMBDetail
                    }
                    else
                    {
                        $detail = Get-SmsState -OrchestratorComputerName $targetComputerName -Credential $Credential -Name $job -ComputerName $device -InventorySMBDetail
                    }
                }

                Write-Output $detail
            }

            if ($state.LastOperation -ne "Inventory")
            {
                Write-Output "+++"
                Write-Output "Transfer summary for job: $job"

                if (! $computerNameWasProvided)
                {
                    $transferSummary = Get-SmsState -Name $job -TransferSummary
                }
                else
                {
                    if ($null -eq $Credential)
                    {
                        $transferSummary = Get-SmsState -OrchestratorComputerName $targetComputerName -Name $job -TransferSummary
                    }
                    else
                    {
                        $transferSummary = Get-SmsState -OrchestratorComputerName $targetComputerName -Credential $Credential -Name $job -TransferSummary
                    }
                }
                
                Write-Output $transferSummary

                foreach ($entry in $inventorySummary)
                {
                    $device = $entry.Device
                    Write-Output "!!!"
                    Write-Output "Transfer SMB detail for device: $device"

                    if (! $computerNameWasProvided)
                    {
                        $detail = Get-SmsState -Name $job -ComputerName $device -TransferSMBDetail
                    }
                    else
                    {
                        if ($null -eq $Credential)
                        {
                            $detail = Get-SmsState -OrchestratorComputerName $targetComputerName -Name $job -ComputerName -ComputerName $device $device -TransferSMBDetail
                        }
                        else
                        {
                            $detail = Get-SmsState -OrchestratorComputerName $targetComputerName -Credential $Credential -Name $job -ComputerName $device -ComputerName $device -TransferSMBDetail
                        }
                    }

                    Write-Output $detail
                }
                
                Write-Output "+++"
                Write-Output "Cutover summary for job: $job"

                if (! $computerNameWasProvided)
                {
                    $cutoverSummary = Get-SmsState -Name $job -CutoverSummary
                }
                else
                {
                    if ($null -eq $Credential)
                    {
                        $cutoverSummary = Get-SmsState -OrchestratorComputerName $targetComputerName -Name $job -CutoverSummary
                    }
                    else
                    {
                        $cutoverSummary = Get-SmsState -OrchestratorComputerName $targetComputerName -Credential $Credential -Name $job -CutoverSummary
                    }
                }

                Write-Output $cutoverSummary
            }
            Write-Output "==="
        }

    }
}

Function Get-SmsLogs (
    [string] $ComputerName = $null,
    [System.Management.Automation.PSCredential] $Credential = $null,
    [string] $Path = (Get-Item -Path ".\").FullName
)
{
    $error.Clear()
    
    if ($null -eq $ComputerName -or $ComputerName -eq "")
    {
        $computerNameWasProvided = $false
        $targetComputerName = "$env:ComputerName"
    }
    else
    {
        $computerNameWasProvided = $true
        $targetComputerName = $ComputerName
    }

    [string]$smsLogsFolder = ""
    
    GetSmsLogsFolder -Path $path -SmsLogsFolder ([ref]$smsLogsFolder)

    LogAction "Creating directory '$smsLogsFolder'"
    $null = New-Item -Path $smsLogsFolder -Type Directory
    
    Start-Transcript -Path "$smsLogsFolder\$($targetComputerName)_Get-SmsLogs.log" -Confirm:0
    
    $date = Get-Date
    Write-Output "Get-SmsLogs started on $date"
    
    Write-Output "ComputerName: '$ComputerName'"
    Write-Output "TargetComputerName: '$targetComputerName'"
    Write-Output "Path: '$Path'"

    GetSmsEventLogs  -SmsLogsFolder $SmsLogsFolder
    GetSmsEventLogs2 -SmsLogsFolder $SmsLogsFolder
    GetSystemEventLogs -SmsLogsFolder $SmsLogsFolder
    GetSystemInfo -SmsLogsFolder $SmsLogsFolder
    
    $date = Get-Date
    Write-Output "Get-SmsLogs finished on $date"
    
    Stop-Transcript

    Compress-Archive -Path $SmsLogsFolder -DestinationPath $SmsLogsFolder -CompressionLevel Optimal
    
    LogAction "ZIP file containing the logs: '$($SmsLogsFolder).zip'"
}

Export-ModuleMember -Function Get-SmsLogs
# SIG # Begin signature block
# MIInzAYJKoZIhvcNAQcCoIInvTCCJ7kCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCAgAAgg6UHeKdKQ
# FmD/T3zaovgmvApsGFatBo3dSqTRmKCCDYEwggX/MIID56ADAgECAhMzAAACzI61
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
# BgEEAYI3AgELMQ4wDAYKKwYBBAGCNwIBFTAvBgkqhkiG9w0BCQQxIgQgArKl9NHI
# 53eYFgFR5axAsKi51zQV86j5/csSRlzsbCgwQgYKKwYBBAGCNwIBDDE0MDKgFIAS
# AE0AaQBjAHIAbwBzAG8AZgB0oRqAGGh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbTAN
# BgkqhkiG9w0BAQEFAASCAQBqxUwfCNNpRGy5kQV/IMkn+9pXjHKcCdSVegFc5dHs
# NEr31K4lJoLzpMnnr2X8G2SVTww5oCZ9xd01PsZdn1DUgclRQ0EXEFoalVPXcL+k
# MLib25D1q+9DbFcgbsHU7l9xyx+iMzAY0n9R/fu8GF5pFnVcT6FeuzSuseW1wkzX
# QiCbn6Issv0EoPmM8mC0G5LYPOuChZYGKUq5ijMdciwARDHaxXEOyW90cyqbRqER
# l9b3mU9RDfueT+5d6B7y4CL3bSpf8YhRv/cozzaAnMAKse1aRDh4qUmSUj+f6RI4
# aSRXpYSNNdCSsvJnvOuP623Xil+F8h2zrB1l9RA6tF/0oYIXKzCCFycGCisGAQQB
# gjcDAwExghcXMIIXEwYJKoZIhvcNAQcCoIIXBDCCFwACAQMxDzANBglghkgBZQME
# AgEFADCCAVgGCyqGSIb3DQEJEAEEoIIBRwSCAUMwggE/AgEBBgorBgEEAYRZCgMB
# MDEwDQYJYIZIAWUDBAIBBQAEILqK6q+aGSM/ids8rxBbTY0VXEb4lmM1b1SLc8wt
# airuAgZjT+tCwvMYEjIwMjIxMDI2MTQzMTM0LjQ0WjAEgAIB9KCB2KSB1TCB0jEL
# MAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1v
# bmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEtMCsGA1UECxMkTWlj
# cm9zb2Z0IElyZWxhbmQgT3BlcmF0aW9ucyBMaW1pdGVkMSYwJAYDVQQLEx1UaGFs
# ZXMgVFNTIEVTTjo4RDQxLTRCRjctQjNCNzElMCMGA1UEAxMcTWljcm9zb2Z0IFRp
# bWUtU3RhbXAgU2VydmljZaCCEXswggcnMIIFD6ADAgECAhMzAAABs/4lzikbG4oc
# AAEAAAGzMA0GCSqGSIb3DQEBCwUAMHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpX
# YXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQg
# Q29ycG9yYXRpb24xJjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAy
# MDEwMB4XDTIyMDkyMDIwMjIwM1oXDTIzMTIxNDIwMjIwM1owgdIxCzAJBgNVBAYT
# AlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYD
# VQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xLTArBgNVBAsTJE1pY3Jvc29mdCBJ
# cmVsYW5kIE9wZXJhdGlvbnMgTGltaXRlZDEmMCQGA1UECxMdVGhhbGVzIFRTUyBF
# U046OEQ0MS00QkY3LUIzQjcxJTAjBgNVBAMTHE1pY3Jvc29mdCBUaW1lLVN0YW1w
# IFNlcnZpY2UwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQC0fA+65hiA
# riywYIKyvY3t4SUqXPQk8G62v+Cm9nruQ2UeqAoBbQm4oDLjHGN9UJR6/95LloRy
# dOZ+Prd++zx6J3Qw28/3VPqvzX10iq9acFNji8pWNLMOd9VWdbFgHcg9hEAhM03S
# w+CiWwusJgAqJ4iQQKr4Q8l8SdDbr5ZO+K3VRL64m7A2ccwpVhGuL+thDY/x8ogl
# F9zGRp2PwIQ8ms36XIQ1qD+nCYDQkl5h1fV7CYFyeJfgGAIGqgLzfDfhKTftExKw
# oBTn8GVdtXIO74HpzlePIJhvxDH9C70QHoq8T1LvozQdyUhW1tVlPGecbCxKDZXt
# +YnHRE/ht8AzZnEl5UGLOLfeCFkeeNfj7FE5KtJJnT+P9TuBg+eGbCeXlJy2msFz
# scU9X4G1m/VUYNWeGrKVqbi+YBcB2vFDTEcbCn36K+qq11VUNTnSTktSZXr4aWZb
# LEglQ6HTHN9CN31ns58urTTqH6X2j67cCdLpF3Cw9ck/vPbuLkAf66lCuiex6ZDb
# tH0eTOcRrTnIfZ8p3DvWpaK8Q34hHW+s3qrQn3G6OOrvv637LJXBkriRc5cBDZ1P
# r0PiSeoyUVKwfpq+dc1lDIlkyw1ZoS3euv/w2v2AYwNAYtIXGLjv1nLX1pP98fOw
# C27ahwG5OotXCfGtnKInro/vQQEko7l5AQIDAQABo4IBSTCCAUUwHQYDVR0OBBYE
# FNAaXcJRZ1IMGIs4SCH/XgXcn8ONMB8GA1UdIwQYMBaAFJ+nFV0AXmJdg/Tl0mWn
# G1M1GelyMF8GA1UdHwRYMFYwVKBSoFCGTmh0dHA6Ly93d3cubWljcm9zb2Z0LmNv
# bS9wa2lvcHMvY3JsL01pY3Jvc29mdCUyMFRpbWUtU3RhbXAlMjBQQ0ElMjAyMDEw
# KDEpLmNybDBsBggrBgEFBQcBAQRgMF4wXAYIKwYBBQUHMAKGUGh0dHA6Ly93d3cu
# bWljcm9zb2Z0LmNvbS9wa2lvcHMvY2VydHMvTWljcm9zb2Z0JTIwVGltZS1TdGFt
# cCUyMFBDQSUyMDIwMTAoMSkuY3J0MAwGA1UdEwEB/wQCMAAwFgYDVR0lAQH/BAww
# CgYIKwYBBQUHAwgwDgYDVR0PAQH/BAQDAgeAMA0GCSqGSIb3DQEBCwUAA4ICAQBa
# hrs3zrAJuMACXxEZiYFltLTSyz5OlWI+d/oQZlCArKhoI/aFzTWrYAqvox7dNxIk
# 81YcbXilji6EzMd/XAnFCYAzkCB/ho7so2FVXTgmvRcepSOvdPzgWRZc9gw7i6VA
# bqP/793uCp7ONdpjtwOpg0JJ3cXiUrHQUm5CqnHAe0wv5rhToc4N/Zn4oxiAnNZG
# c4iRP+h3SghfKffr7NchlEebs5CKPuvKv5+ZDbd94XWkNt+FRIdMD0hPnQoKSkan
# 8YGLAU/+bV2t3vE18iZVaBvY8Fwayp0kG+PpNfYx1Qd8FVH5Z7gDSUSPWs1sKmBS
# g22VpH0PLaTaBXyihUR21qJnKHT9W1Z+5CllAkwPGBtkZUwbb67NwqmN5gA0yVIo
# OHJDfzBugCK/EPgApigRJuDhaTnGTF9HMWrKKXYMTPWknQbrGiX2dyLZd7wuQt0R
# Pe7lEbFQdqbwvgp4xbbfz5GO9ZfVEx81AjvvjOIUhks5H7vsgYVzBngWai15fXH3
# 4GD3J0RY0E/exm/24OLLCyBbjSTTQCbm/iL8YaJka7VrgeEjfd+aDH7xuXBHme3s
# mKQWeA25LzeOGbxEdBB0WpC9sW9a67I+3PCPmrhKmM7VKQ57qugcaQSFAJRd1Ayd
# EjBucalv/YSzFp2iQryHqxFkxZuuI7YQItAQzMJwsDCCB3EwggVZoAMCAQICEzMA
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
# IFRTUyBFU046OEQ0MS00QkY3LUIzQjcxJTAjBgNVBAMTHE1pY3Jvc29mdCBUaW1l
# LVN0YW1wIFNlcnZpY2WiIwoBATAHBgUrDgMCGgMVAHGLROiW3R4SpcJCXiqAldSS
# JA5hoIGDMIGApH4wfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24x
# EDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlv
# bjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTAwDQYJKoZI
# hvcNAQEFBQACBQDnA6O+MCIYDzIwMjIxMDI2MjAxNzAyWhgPMjAyMjEwMjcyMDE3
# MDJaMHcwPQYKKwYBBAGEWQoEATEvMC0wCgIFAOcDo74CAQAwCgIBAAICGsQCAf8w
# BwIBAAICEVMwCgIFAOcE9T4CAQAwNgYKKwYBBAGEWQoEAjEoMCYwDAYKKwYBBAGE
# WQoDAqAKMAgCAQACAwehIKEKMAgCAQACAwGGoDANBgkqhkiG9w0BAQUFAAOBgQBv
# p6W/1aTiOXGNn5K1ZCCmae6r3QoDryaOAGIJl9ooX+BPpyMxx2Hn7MApe18QgeA6
# TA/BjYu+0ZMzCEx5eGmX9DAOWSACVGPDDBrUklt6IPlKrVgZCAHu2ajPEPnxW0Ls
# zn4hyeLMnI3hQEXOKJKmUCaZibuAlX9Wb8LpMTuYEzGCBA0wggQJAgEBMIGTMHwx
# CzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRt
# b25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJjAkBgNVBAMTHU1p
# Y3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEwAhMzAAABs/4lzikbG4ocAAEAAAGz
# MA0GCWCGSAFlAwQCAQUAoIIBSjAaBgkqhkiG9w0BCQMxDQYLKoZIhvcNAQkQAQQw
# LwYJKoZIhvcNAQkEMSIEIDZpPyEQ/dEln20SrUkx8jQNNkESydsXG6M3VAidOxE6
# MIH6BgsqhkiG9w0BCRACLzGB6jCB5zCB5DCBvQQghqEz1SoQ0ge2RtMyUGVDNo5P
# 5ZdcyRoeijoZ++pPv0IwgZgwgYCkfjB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMK
# V2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0
# IENvcnBvcmF0aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0Eg
# MjAxMAITMwAAAbP+Jc4pGxuKHAABAAABszAiBCAOJovhPOIH2oWJWe1vQOjJj481
# 5YZKgpXoVXBjlkwlpzANBgkqhkiG9w0BAQsFAASCAgAiZbCaB402zeOZL3spiSUc
# XBqPCzKb8cBx5OhZpfzQZ5STsA5KNpK1QU9hV+VolW34VvwLSmzm39sx2r0IFlQ+
# 5lXvisIE4c0Ax5hILJgXBPAJDItqjSh3bk177fE5SJ0lIFdJQsoPIyDL/Q0y30w/
# aPhzxWIUnnQzpcT+0MXP6EDfUDA/+RR5SmndvOUEzCxBS/zDBEccxSD+LZbeuBed
# Znxst36hXvdrdyBU4Mj7Zm4kKrXK68BSUZvXWbkpKwB6/PunOM2qcTP1IryOVZRY
# swRn8o9SSMTxl6YCL8lcDOdLPRpJpOwDOMZCOfwHbpajdehwR2qOnQT/CD+cAxhI
# kU+nm6qRoRMQmhfUCJJr5fDPUnHdPsFx5JKnduhWjxURotJyeaf4MDD0+pGLH2LQ
# yxViOIzetF9wENpk/BYsoyogdA3yVJ8OkTnnyFYl3FGbQv4854Ls863Vw/bGCCe5
# +vULpcX6Os+LnQkVlOQBK9mLFrPgD1SATDbKA+6lObn4MkW+Jdq0ro9G76A5hXRn
# lO5ZkHJIiBIYv4SUDEJuSgdZm/mYOuqhwGzObpjIQ5ldbyfuRioWzfd+TohCU6Aa
# Z0YIJVyoxkACIJ2UlicMZql9KmIwbKmPmh5wPnh9/rWYYT7Og+cGTDoMNZLT2PXF
# 17ae+G+UdEcAtkowrjT6wQ==
# SIG # End signature block
