
#Region ===============================[Metadata]==============================

<#PSScriptInfo

.VERSION 1.0

.GUID 917fd640-9878-4235-8360-d9c07849c5b8

.Date 04-Dec-2022

.AUTHOR adrianbcojocaru@gmail.com

#>

<#

.DESCRIPTION
  Gets the error codes from the Microsoft-Windows-WindowsUpdateClient Event Log, counts them, and writes the result in the registry.
  ErrorCode | FoundCounter

.SYNOPSIS
  Gets the error codes from the Microsoft-Windows-WindowsUpdateClient Event Log, counts them, and writes the result in the registry.

.EXAMPLE
  ### destination group already exists:
  Get-WindowsUpdateError.ps1

#>

#EndRegion ============================[Metadata]==============================

#Region ===============================[Functions]==============================

[string]$RegKey = "HKLM:SOFTWARE\Adrian\WindowsUpdateInfo"
[version]$ScriptVersion = '1.0.0.0'
[string]$SystemDrive = $env:SystemDrive
Function Set-RegistryKey {
    <#
 .Synopsis
  Used to create registry keys and/or write/update registry values.
 .Example
  ### 
  Set-RegistryKey -Key "HKLM:SOFTWARE\OrclOASIS" -Name "EstimatedRunTime" -Value "8" -Type "String"
 .Example
  ### If you are certain that the registry key already exists.
 Set-RegistryKey -Key "HKLM:SOFTWARE\OrclOASIS" -Name "EstimatedRunTime" -Value "8" -Type "String" -CreateNoKey
 .Example
  ### Set the (Default) value.
 Set-RegistryKey -Key "HKLM:SOFTWARE\OrclOASIS" -Value "8"
#>

    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullorEmpty()]
        # Mandatory. The registry key without a trailing \.
        [string]$Key,
        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        # Optional. Registry name.
        [string]$Name,
        [Parameter(Mandatory = $false)]
        # Optional. Registry value.
        $Value,
        [Parameter(Mandatory = $false)]
        [ValidateSet('Binary', 'DWord', 'ExpandString', 'MultiString', 'None', 'QWord', 'String', 'Unknown')]
        # Optional. Registry type. Accepted: Binary, DWord, ExpandString, MultiString, None, QWord, String, Unknown.
        [Microsoft.Win32.RegistryValueKind]$Type = 'String',
        [Parameter(Mandatory = $false)]
        # Optional. Does not attempt to create the registry key if it doesn't exists.
        [switch]$CreateNoKey
    )
    Begin {
        [string]${CmdletName} = $PSCmdlet.MyInvocation.MyCommand.Name
    }
    Process {
        if (!($CreateNoKey)) {
            if (!(Test-Path -Path $key -ErrorAction 'Stop')) {
                Try {

                    $null = New-Item -Path $Key -Force -ErrorAction 'Stop'
                }
                Catch {

                }           
            }
        }
        Try {
            if ($PSBoundParameters.ContainsKey('Name')) {
                If (-not (Get-ItemProperty -LiteralPath $key -Name $Name -ErrorAction 'SilentlyContinue')) {
                    #$error.Remove($error[$error.Count-1])

                    $null = New-ItemProperty -LiteralPath $key -Name $name -Value $Value -PropertyType $Type -ErrorAction 'Stop'
                }
                Else {

                    $null = Set-ItemProperty -LiteralPath $key -Name $name -Value $Value -ErrorAction 'Stop'
                }
            }
            Else {
                $Name = '(Default)'

            }
        }
        catch {
        }
    }      
    end {}
}
Function Get-WinEvent2 {
    <#
 .Synopsis
  Gets the event log from a certain provider
 .Example
  ### 
  Get-WinEvent2 -Id 20 -ProviderName 'Microsoft-Windows-WindowsUpdateClient'
#>

    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $false)]
        [ValidateNotNullorEmpty()]
        # Optional. The event Id. If not provided, it will return all the events in ProviderName param
        [Int32]$Id,
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        # Optional. Registry name.
        [string]$ProviderName
    )
    Begin {
        [string]${CmdletName} = $PSCmdlet.MyInvocation.MyCommand.Name
    }
    Process {
        Try {
            $hash = @{ProviderName = $ProviderName }
            if ($Id) { $hash["ID"] = $Id }
            $Events = Get-WinEvent -FilterHashtable $hash
        }
        catch {
        }
    }      
    end {
        Write-Output $Events
    }
}
Function Get-FreeDiskSpace {
    <#
    .SYNOPSIS
        Retrieves the free disk space in MB on a particular drive (defaults to system drive)
    .DESCRIPTION
        Retrieves the free disk space in MB on a particular drive (defaults to system drive)
    .PARAMETER Drive
        Drive to check free disk space on
    .PARAMETER ContinueOnError
        Continue if an error is encountered. Default is: $true.
    .EXAMPLE
        Get-FreeDiskSpace -Drive 'C:'
    #>
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $false)]
        [ValidateNotNullorEmpty()]
        [string]$Drive = $envSystemDrive,
        [Parameter(Mandatory = $false)]
        [ValidateNotNullorEmpty()]
        [boolean]$ContinueOnError = $true
    )
    
    Begin {
        [string]${CmdletName} = $PSCmdlet.MyInvocation.MyCommand.Name
    }
    End {
        Try {
            $disk = Get-CimInstance -Class 'Win32_LogicalDisk' -Filter "DeviceID='$Drive'" -ErrorAction 'Stop'
            [double]$freeDiskSpace = [math]::Round($disk.FreeSpace / 1MB)
            Write-Output $freeDiskSpace
        }
        Catch {
        }
    }
}

#EndRegion ============================[Functions]==============================

Set-RegistryKey -Key $RegKey -Name 'ScriptVersionDetection' -Value $ScriptVersion
$LastHotfix = ((Get-HotFix | Sort-Object -Property InstalledOn)[-1])
if ($LastHotfix -eq $null) {
    Set-RegistryKey -Key $RegKey -Name 'HotFixDate' -Value 'NoHotfixFound'
    Exit 101
}

# $CurrDate = Get-Date
# if ($LastHotfix.InstalledOn.AddDays(30) -gt $CurrDate) {
#     Set-RegistryKey -Key $RegKey -Name 'HotFixDate' -Value 'LessThan30Days'
#     Exit 102
# }
$FreeDiskSpace = Get-FreeDiskSpace -Drive $SystemDrive
Set-RegistryKey -Key $RegKey -Name 'FreeDiskSpaceMB' -Value $FreeDiskSpace
Set-RegistryKey -Key $RegKey -Name 'HotFixDate' -Value $LastHotfix.InstalledOn.ToString("dd-MMM-yyyy")

$WinUpdateEvents = Get-WinEvent2 -Id 20 -ProviderName 'Microsoft-Windows-WindowsUpdateClient'
# create counter for error codes
$ErrorCodeCounter = @{}
$WinUpdateEvents | ForEach-Object {
    # extract the error code and put it into the counter
    if ($_.message -match '0[xX][0-9a-fA-F]+') {
        $ErrorCodeCounter["$($Matches.Values)"] = $ErrorCodeCounter."$($Matches.Values)" + 1
    }
}
# write the hash into the registry
$ErrorCodeCounter.Keys | ForEach-Object {
    Set-RegistryKey -Key "$RegKey\Errors" -Name $_ -Value $($ErrorCodeCounter[$_])
}

Exit 0