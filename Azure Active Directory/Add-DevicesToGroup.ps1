<#PSScriptInfo

.VERSION 1.0

.GUID 876e34d6-4b94-4204-9f32-730d8b6871a1

.AUTHOR adrianbcojocaru@gmail.com

#>

#Requires -Modules AzureAD

<#
  .SYNOPSIS
  Adds a list of devices to an AAAD security group.

  .DESCRIPTION

  .EXAMPLE
  .\Add-DevicesToGroup.ps1

#>


$FilePath = "$PSScriptRoot\MyList.txt"
$TimeStamp = get-date -Format yyyyMMddTHHmmss
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

# Install-Module AzureAD
Connect-AzureAD
$destinationGroup = Get-AzureADGroup -SearchString 'AAD Global CP Intune CloudAuth Cert QA Devices'

Get-Content $FilePath | ForEach-Object {
    try {
        $ToBeAdded = Get-AzureADDevice -SearchString $_
        Write-Log "Adding $($ToBeAdded.DisplayName) | $($ToBeAdded.DeviceId) | $($ToBeAdded.ObjectId)"
        Add-AzureADGroupMember -ObjectId $destinationGroup.ObjectId -RefObjectId $ToBeAdded.ObjectId
    } catch {
        Write-Error2
    }
}
