<#PSScriptInfo

.VERSION 1.0

.GUID 111ed545-ddec-4d2f-bcc1-ce11b1eb8fde

.AUTHOR adrianbcojocaru@gmail.com

#>

#Requires -Modules AzureAD
#Requires -Modules ImportExcel

<#
  .SYNOPSIS
  Adds Windows devices from on or moure AAD user groups to a single AAD device group.

  .DESCRIPTION
  Gets the users from each User group ID defined in $AADUserGroupIDs
  Gets the Windows devices for each of those users and adds them to the group defined in the $DestinationGroupId

  .EXAMPLE
  .\Add-UserDevicesToGroup.ps1

#>
$TimeStamp = Get-Date -Format yyyyMMddTHHmmss
$LogPath = "$PSScriptRoot\$TimeStamp.log"

Function Write-Log {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $true, Position = 0, ValueFromPipeline = $true)]
        [ValidateNotNull()]
        [AllowEmptyString()]
        # Mandatory. Specifies the message string.
        [string]$Message,
        [Parameter(Mandatory = $false, Position = 1)]
        # Optional. Specifies the message color in the powershell console White(default) Green Blue Yellow DarkYellow Red
        [string]$Color = 'White',
        [Parameter(Mandatory = $false, Position = 2)]
        # Optional. Specifies the message color in the powershell console White(default) Green Blue Yellow DarkYellow Red
        [string]$BackgroundColor = '',
        [Parameter(Mandatory = $false, Position = 3)]
        [ValidateNotNull()]
        # Optional. Specifies the name of the message writter. Function, command or custom name. Defaults to FunctioName or unknown
        [string]$Caller = 'Unknown'
    )
    Begin {
        [string]$LogDate = (Get-Date -Format 'MM-dd-yyyy').ToString()
        [string]$LogTime = (Get-Date -Format 'HH\:mm\:ss.fff').ToString()
        [string]${CmdletName} = $PSCmdlet.MyInvocation.MyCommand.Name
        #if ([string]::IsNullOrEmpty($Message)) { return }
    }
    Process {
        #if ([string]::IsNullOrEmpty($Message)) { return }
        ForEach ($Msg in $Message) {
            If ($Msg) {
                [string]$CompleteMsg = "[$LogDate $LogTime] [${Caller}] :: $Msg"
                #Try {
                if ($BackgroundColor -eq '') {
                    $CompleteMsg | Write-Host -ForegroundColor $Color
                }
                else {
                    $CompleteMsg | Write-Host -ForegroundColor $Color -BackgroundColor $BackgroundColor 
                }
                $CompleteMsg | Out-File -FilePath $LogPath -Append -NoClobber -Force -Encoding 'UTF8' -ErrorAction 'Stop' 
            }
        }
    }
    End {}
}
function Write-Error2 {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $false, Position = 0)]
        [AllowEmptyCollection()]
        # Optional. The errorr collection.
        [array]$ErrorRecord,
        [Parameter(Mandatory = $false, Position = 1)]
        [AllowEmptyCollection()]
        # Optional.
        [switch]$Pause
    )
    Begin {
        [string]${CmdletName} = $PSCmdlet.MyInvocation.MyCommand.Name
        If (-not $ErrorRecord) {
            If ($global:Error.Count -eq 0) {
                Return
            }
            Else {
                [array]$ErrorRecord = $global:Error[0]
            }
        }
    }
    Process {
        $ErrorRecord | ForEach-Object {
            $errNumber = $ErrorRecord.count - $( $ErrorRecord.IndexOf($_))
            $_.CategoryInfo | Write-Log -Caller "${CmdletName} Nr. $errNumber"  -Color Red
            $_ | Write-Log -Caller "${CmdletName} Nr. $errNumber" -Color Red
            $_.InvocationInfo.PositionMessage | Write-Log -Caller "${CmdletName} Nr. $errNumber" -Color Red
            if ($Pause) {
                Write-Log "Please review before continuing!" -BackgroundColor DarkMagenta -Color Yellow -Caller $CmdletName
                Pause
            }
        }
    }
    End {}
}

Connect-AzureAD

$Devices_Windows = [System.Collections.ArrayList]@()
$Devices_Other = [System.Collections.ArrayList]@()
$Users = [System.Collections.ArrayList]@()
$NonUsers = [System.Collections.ArrayList]@()

# Source user groups
$AADUserGroupIDs = @(
    '83b57739-30de-4000-9474-352a7f4455c3' #
    '1aa7e09d-b46b-4e51-b360-41952106c1ab' #
    '23b77af6-d89f-4ed2-bbc1-6fc686d08a59' #
)

# Destination device group. It will contain all devices associated with the users in the Sourse user groups defined above
$DestinationGroupId = '06d6fc34-8cc0-4acf-9dd3-186f794a46ff' # 
$AADUserGroupIDs | Foreach-Object {
    # Get users from each group
    Get-AzureADGroupMember -ObjectId $_ -All $true | ForEach-Object {
        if ($_.ObjectType -ne 'User') {
            Write-Log "$($_.ObjectId) | $($_.ObjectType) " -Caller 'Skip-Object'
            $NonUsers.Add($_) | Out-Null
        } else {
            if ($Users -contains $_) {
                Write-Log "$($_.ObjectId) | $($_.DisplayName) | $($_.UserPrincipalName)" -Caller 'Skip-User'
            } else {
                # If the current user was not already processed in one of the previous groups,
                # Get the list of user's devices
                Write-Log "$($_.ObjectId) | $($_.DisplayName) | $($_.UserPrincipalName)" -Caller 'Add-User'
                $Users.Add($_) | Out-Null
                Get-AzureADUserRegisteredDevice -ObjectId $_.ObjectId | ForEach-Object {  
                    if ($_.DeviceOSType -eq 'Windows') {
                        # Add the device to AAD group
                        Write-Log "$($_.DeviceId) | $($_.DisplayName) | $($_.DeviceOSType) | $($_.DeviceOSVersion)" -Caller 'Add-Device'
                        $Devices_Windows.Add($_) | Out-Null
                        Add-AzureADGroupMember -ObjectId $DestinationGroupId -RefObjectId $_.ObjectId
                    } else {
                        $Devices_Other.Add($_) | Out-Null
                        Write-Log "$($_.DeviceId) | $($_.DisplayName) | $($_.DeviceOSType) | $($_.DeviceOSVersion)" -Caller 'Skip-Device'
                    }
                }
            }
        }
    }
}

$Devices_Windows | Export-Excel "$PSScriptRoot\Devices_Windows_$TimeStamp.xlsx"
$Devices_Other | Export-Excel "$PSScriptRoot\Devices_Other_$TimeStamp.xlsx"
$Users | Export-Excel "$PSScriptRoot\Users_$TimeStamp.xlsx"
$NonUsers | Export-Excel "$PSScriptRoot\NonUsers_$TimeStamp.xlsx"