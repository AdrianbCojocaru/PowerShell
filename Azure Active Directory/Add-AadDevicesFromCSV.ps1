<#
  .SYNOPSIS
  Add devices to a new or existing AzureAD group.
  .DESCRIPTION
  Uses AzureAD module to add devices froma *.csv file to a new or existing AzureAD group.
  If the AadGroupObjectId parameter is provided it implies assumed thet the AzureAD group exists
  If the AadGroupName parameter is provided a new AzureAD group will be created even if a group with the same name already exists.
  Either ColumnName_AzureADDeviceId or ColumnName_DeviceName must be provided. It defines the source of devices from the csv file, either the AzureAD name or AzureAD Object ID.
  .PARAMETER CSVPath
  Specifies the path to the CSV input file.
  .PARAMETER AadGroupObjectId
  The Object ID of an existing AzureAD group. All the devices in the CSV file will be added to this group.
  .PARAMETER AadGroupName
  The Name of an a new AzureAD group. All the devices in the CSV file will be added to this group.
  .PARAMETER ColumnName_AzureADDeviceId
  The name of the column containing the AzureAD Device ID iin the CSV file
  If this parameter is provided the devices will be added using the AzureAD Device ID.
  You can use this or ColumnName_DeviceName but ColumnName_AzureADDeviceId is recommended.
  .PARAMETER ColumnName_DeviceName
  The name of the column containing the AzureAD Device Name iin the CSV file
  If this parameter is provided the devices will be added using the AzureAD Device Name.
  Often times there will be multiple entries with the same device name. If such an entry is encountered, all the devices that have the same name will be added to the group.
  You can use this or ColumnName_AzureADDeviceId but ColumnName_AzureADDeviceId is recommended.
  .OUTPUTS
  A log file will be created under the Logs-ScriptName folder next to the script.
  A CSV file containg the operation result will be generated under the Output folder next to the script.
  .EXAMPLE
  .\Add-AadDevicesFromCSV.ps1 -CSVPath .\wufb_merged_report_test.csv -AadGroupObjectId '29d21dfe-0e45-46b8-8b93-e5d592b1c88c' -ColumnName_AzureADDeviceId 'AzureADDeviceId'
  Add devices by AzureAD Group Object ID & AzureAD Device ID. [RECOMMENDED]
  .EXAMPLE
  .\Add-AadDevicesFromCSV.ps1 -CSVPath .\wufb_merged_report_test.csv -AadGroupObjectId '713382bb-aeee-4176-958c-134e72f7ac3c' -ColumnName_DeviceName 'DeviceNameX'
  Add devices by AzureAD Group Object ID & AzureAD Device Name.
  .EXAMPLE
  .\Add-AadDevicesFromCSV.ps1 -CSVPath .\wufb_merged_report_test.csv -AadGroupName '[Test] Adrian Cojocaru CSV' -ColumnName_AzureADDeviceId 'AzureADDeviceId'
  Add devices by AzureAD Group Object ID & AzureAD Device ID. The AzureAD group will be created even if a group with the same name already exists.
  If you wish to add devices to an existing AzureAD group, use -AadGroupObjectId instead.
  .EXAMPLE
  .\Add-AadDevicesFromCSV.ps1 -CSVPath .\wufb_merged_report_test.csv -AadGroupName '[Test] Adrian Cojocaru CSV' -ColumnName_DeviceName 'DeviceNameX'
  Add devices by AzureAD Group Name & AzureAD Device Name. The AzureAD group will be created even if a group with the same name already exists.
  If you wish to add devices to an existing AzureAD group, use -AadGroupObjectId instead.
#>

[CmdletBinding()]
Param (
    # Mandatory
    [Parameter(Mandatory = $false)]
    #[string]$CSVPath = "C:\Git\AzureAD\wufb_merged_report - Copy.csv",
    [string]$CSVPath = '',
    [Parameter(Mandatory = $false)]
    # The destination AzureAD group ID of an existing group.
    # (the group must exist)
    #[string]$AadGroupObjectId = '713382bb-aeee-4176-958c-134e72f7ac3c',
    [string]$AadGroupObjectId = '',
    [Parameter(Mandatory = $false)]
    # If you choose to provide this instead of AadGroupObjectId, the group will be created even if already exists.
    [string]$AadGroupName = '',
    [Parameter(Mandatory = $false)]
    # The name of the column containing the AzureAD Device ID in the CSV file
    # Provide either this or ColumnName_DeviceName
    #[string]$ColumnName_AzureADDeviceId = 'AzureADDeviceId',
    [string]$ColumnName_AzureADDeviceId = '',
    [Parameter(Mandatory = $false)]
    # The name of the column containing the AzureAD Device Name in the CSV file
    # Provide either this or ColumnName_AzureADDeviceId
    #[string]$ColumnName_DeviceName = 'DeviceNameX'
    [string]$ColumnName_DeviceName = ''
)

#Region ===============================[Variables]=============================
#$csvPath = "C:\Users\acojoca4\Downloads\New query(1).csv"
# $csvPath = "C:\Git\AzureAD\wufb_merged_report - Copy.csv"
# $AadGroupName = ''
#$AadGroupObjectId = ''
$TimeStamp = get-date -Format yyyyMMddTHHmmss
#$LogPath = "$PSScriptRoot\$ScriptName-$TimeStamp.log"
$ScriptName = (Get-Item $PSCommandPath).Basename
$LogName = (Get-Item $CSVPath).Basename
$LogFolder = "$PSScriptRoot\Logs-$ScriptName"
$OutputFolder = "$PSScriptRoot\Output-$ScriptName"
$LogPath = "$LogFolder\$LogName-$TimeStamp.log"

#$ColumnName_DeviceName = 'DeviceNameX'
#$MainColumn = $ColumnName_AzureADDeviceId
#EndRegion ============================[Variables]=============================

#Region ===============================[Functions]============================
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

function Add-AzureAadDeviceByDeviceId {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $true, Position = 0, ValueFromPipeline = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$AadDevcieId,
        [Parameter(Mandatory = $true, Position = 1)]
        [ValidateNotNullOrEmpty()]
        [string]$AadGroupId
    )
    Begin {
        [string]${CmdletName} = $PSCmdlet.MyInvocation.MyCommand.Name
        $PSBoundParameters.GetEnumerator() | Sort-Object -Property Name | ForEach-Object { "$($_.Key) = $($_.Value)" | Write-Log -Caller $CmdletName }
        $AlreadyAdded = [System.Collections.ArrayList]::new()
        $AllGroupMembers = Get-AzureADGroupMember -ObjectId $AadGroupObjectId -All $true
    }
    Process {
        try {
            if ($AlreadyAdded -contains $AadDevcieId) {
                Write-Log "$AadDevcieId was already processed." -Caller $CmdletName -Color DarkYellow
            } else {
                Write-Log "Adding AzureAD DevcieId '$AadDevcieId' to AzureAD GroupId '$AadGroupId'" -Caller $CmdletName
                if ($AllGroupMembers.DeviceId -notcontains $AadDevcieId) {
                    # https://github.com/Azure/azure-docs-powershell-azuread/issues/216
                    $ToBeAdded = Get-AzureADDevice -Filter "DeviceId eq guid'$AadDevcieId'"
                    if ($ToBeAdded.count -eq 0) {
                        Write-Log "No device found for ID '$AadDevcieId'" -Color DarkMagenta -Caller $CmdletName
                    } else {
                        Add-AzureADGroupMember -ObjectId $AadGroupId -RefObjectId $ToBeAdded.ObjectId
                        $AlreadyAdded.Add($AadDevcieId) | Out-Null
                    }
                } else {
                    Write-Log "AzureAD DevcieId '$AadDevcieId' is already part of AzureAD GroupId '$AadGroupId'." -Caller $CmdletName -Color DarkYellow
                }
            }
        }
        catch {
            Write-Error2
        }
    }
    End {
        $AlreadyAdded | Out-File "$OutputFolder\$CmdletName-$TimeStamp.csv"
    }
}
function Add-AzureAadDeviceByDeviceName {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $true, Position = 0, ValueFromPipeline = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$AadDevcieName,
        [Parameter(Mandatory = $true, Position = 1)]
        [ValidateNotNullOrEmpty()]
        [string]$AadGroupId
    )
    Begin {
        [string]${CmdletName} = $PSCmdlet.MyInvocation.MyCommand.Name
        $PSBoundParameters.GetEnumerator() | Sort-Object -Property Name | ForEach-Object { "$($_.Key) = $($_.Value)" | Write-Log -Caller $CmdletName }
        $AlreadyAdded = [System.Collections.ArrayList]::new()
        $AllGroupMembers = Get-AzureADGroupMember -ObjectId $AadGroupObjectId -All $true
    }
    Process {
        try {
            if ($AlreadyAdded -contains $AadDevcieName) {
                Write-Log "$AadDevcieName was already processed." -Caller $CmdletName -Color DarkYellow
            } else {
                Write-Log "Adding AzureAD DevcieName '$AadDevcieName' to AzureAD GroupId '$AadGroupId'" -Caller $CmdletName
                # remove .pmintl.net from the devices's name
                if ($AadDevcieName -like "*.pmintl.net*") {$AadDevcieName = $AadDevcieName.Split('.')[0]}
                if ($AllGroupMembers.DisplayName -notcontains $AadDevcieName) {
                    # https://github.com/Azure/azure-docs-powershell-azuread/issues/216
                    $ToBeAdded = Get-AzureADDevice -SearchString $AadDevcieName
                    if ($ToBeAdded.count -eq 0) {
                        Write-Log "No device found for Azure AD DeviceName '$AadDevcieName'" -Color DarkMagenta -Caller $CmdletName
                    } else {
                        $ToBeAdded | ForEach-Object {
                            Write-Log "[$($ToBeAdded.count)] ObjectId=$($_.ObjectId) ApproximateLastLogonTimeStamp=$($_.ApproximateLastLogonTimeStamp) ProfileType=$($_.ProfileType) DeviceTrustType=$($_.DeviceTrustType) LastDirSyncTime=$($_.LastDirSyncTime) DeviceOSVersion=$($_.DeviceOSVersion)" -Caller $CmdletName
                            Add-AzureADGroupMember -ObjectId $AadGroupId -RefObjectId $_.ObjectId
                            $AlreadyAdded.Add($AadDevcieName) | Out-Null
                        }
                    }
                } else {
                    Write-Log "AzureAD DevcieName '$AadDevcieName' already part of AzureAD GroupId '$AadGroupId'." -Caller $CmdletName -Color DarkYellow
                }
            }
        }
        catch {
            Write-Error2
        }
    }
    End {
        $AlreadyAdded | Out-File "$OutputFolder\$CmdletName-$TimeStamp.csv"
    }
}
#EndRegion ============================[Functions]=============================

if (-not (Test-Path $LogFolder)) {New-Item -ItemType Directory $LogFolder | Out-Null}
if (-not (Test-Path $OutputFolder)) {New-Item -ItemType Directory $OutputFolder | Out-Null}
$PSBoundParameters.GetEnumerator() | Sort-Object -Property Name | ForEach-Object { "$($_.Key) = $($_.Value)" | Write-Log -Caller 'Info-Start' }
# Install-Module AzureAD
# Connect-AzureAD
if ($AADGroupName) {
    try {
        Write-Log -Message "AAD group to look for: '$AADGroupName'" -Caller 'Get-AzureADGroup' -Color DarkYellow
        $DestinationGroup = Get-AzureADGroup -SearchString $AADGroupName
        Write-Log "$($DestinationGroup.Count) destination group(s) found." -Caller 'Get-AzureADMultiGroup'
        $DestinationGroup = New-AzureADGroup -DisplayName $AADGroupName -SecurityEnabled $true -MailEnabled $false -MailNickName "NotSet"
        "New AAD group created: $($DestinationGroup.DisplayName) | $($DestinationGroup.ObjectID)" | Write-Log -Caller 'Get-AzureADMultiGroup' -Color DarkYellow
        $AadGroupObjectId = $DestinationGroup.ObjectId
        <#
        if ($DestinationGroup.Count -eq 0) {
            # Create the AAD group
            $DestinationGroup = New-AzureADGroup -DisplayName $AADGroupName -SecurityEnabled $true -MailEnabled $false -MailNickName "NotSet"
            "New AAD group created: $($DestinationGroup.DisplayName) | $($DestinationGroup.ObjectID)" | Write-Log -Caller 'Get-AzureADMultiGroup' -Color DarkYellow
            $AadGroupObjectId = $DestinationGroup.ObjectId
        } elseif ($DestinationGroup.Count -gt 1) {
            # Exit if the provided name matches multiple AAD groups
            $DestinationGroup | ForEach-Object {"Existing AAD groups found: $($_.DisplayName) | $($_.ObjectID)" | Write-Log -Caller 'Get-AzureADMultiGroup' -Color DarkYellow}
            Exit 1
        }
        #>
    }
    catch {
        Write-Error2
        Exit 1
    }
} else {
    try {
        $DestinationGroup = Get-AzureADGroup -ObjectId $AADGroupObjectId
    }
    catch {
        Write-Log -Message "Invalid AzureAD Group ObjectId ?" -Caller 'Get-AzureADGroup' -Color DarkYellow
        Write-Error2
        Exit 1
    }
}

Write-Log -Message "AAD group that will be used: $($DestinationGroup.DisplayName) | $($DestinationGroup.ObjectID)" -Caller 'Get-AzureADGroup'

if ($ColumnName_AzureADDeviceId) {
    (Import-Csv $csvPath).$ColumnName_AzureADDeviceId | Add-AzureAadDeviceByDeviceId -AadGroupId $AadGroupObjectId
} else {
    (Import-Csv $csvPath).$ColumnName_DeviceName | Add-AzureAadDeviceByDeviceName -AadGroupId $AadGroupObjectId
}
