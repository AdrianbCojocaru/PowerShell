<#
  .SYNOPSIS
  Used to update the members of an AzureAD based on a Microsoft365 Defender advanced hunting query
  .DESCRIPTION
  A json file contains the AAD group id + the defender query
  The scrip reads this file and updates the AzureAD group membership with the results from the query
  Safeguards to be put in place
  .PARAMETER ConfigFile
  Design to be executed in a runbook. Params are subject to change
  
  .OUTPUTS
  A log file will be created under the Logs-ScriptName folder next to the script.
  .EXAMPLE
  .\Add-AadDevicesFromCSV.ps1 -CSVPath "C:\Git\Proactive remediations\Git_AdvancedHuntingResults-SoftwareEidence_plus_AAD_DeviceId.csv" -AadGroupObjectId 'aa0116f4-d2d9-4191-8348-686ea15d085b' -ColumnName_AzureADDeviceId 'AadDeviceId'

#>
#Region----------------------------------------------------- [Script Parameters] -------------------------------------------------------
[CmdletBinding()]
Param (
    # Mandatory
    [Parameter(Mandatory = $false)]
    [string]$ConfigFile = ''
)
#EndRegion------------------------------------------------------ [Script Parameters] -------------------------------------------------------

#Region----------------------------------------------------- [Script Variables] ----------------------------------------------
[int32]$Global:ExitCode = 0
$GLOBAL:VerbosePreference="Continue"
[string]$TimeStamp = get-date -Format yyyyMMddTHHmmss
#[string]$ScriptName = (Get-Item $PSCommandPath).Basename
#[string]$ScriptName = 'TestName'
#[string]$LogName = $ScriptName
#[string]$LogFolder = "$PSScriptRoot\Logs-$ScriptName"
#[string]$OutputFolder = "$PSScriptRoot\Output-$ScriptName"
#[string]$LogPath = "$LogFolder\$LogName-$TimeStamp.log"
#EndRegion ----------------------------------------------------- [Script Variables] ----------------------------------------------

##Region ----------------------------------------------------- [AzureAD Variables] ----------------------------------------------
[string]$tenantId = ''
[string]$clientId = ''
[string]$appSecret = ''
#EndRegion ----------------------------------------------------- [AzureAD Variables] ----------------------------------------------

#region----------------------------------------------------- [Classes] ----------------------------------------------
class CustomException : Exception {
    [string] $additionalData

    CustomException($Message, $additionalData) : base($Message) {
        $this.additionalData = $additionalData
    }
}
#endregion----------------------------------------------------- [Classes] ----------------------------------------------

#Region -------------------------------------------------------- [Functions] ----------------------------------------------
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
                    $CompleteMsg | Write-Verbose
                }
                else {
                    $CompleteMsg | Write-Verbose
                }
               # $CompleteMsg | Out-File -FilePath $LogPath -Append -NoClobber -Force -Encoding 'UTF8' -ErrorAction 'Stop' 
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

function Get-ThreatProtectionToken {
    Begin {
        [string]${CmdletName} = $PSCmdlet.MyInvocation.MyCommand.Name
        $PSBoundParameters.GetEnumerator() | Sort-Object -Property Name | ForEach-Object { "$($_.Key) = $($_.Value)" | Write-Log -Caller $CmdletName }
    }
    End {
        try {
            $SecurityAppIdUri = 'https://api.security.microsoft.com'
            $oAuthUri = "https://login.windows.net/$tenantId/oauth2/token"
            $authBody = [Ordered] @{
                resource      = $SecurityAppIdUri
                client_id     = $clientId
                client_secret = $appSecret
                grant_type    = 'client_credentials'
            }
            $authResponse = Invoke-RestMethod -Method Post -Uri $oAuthUri -Body $authBody -ErrorAction Stop
            $authResponse.access_token
        }
        catch {
            Write-Error2
            throw [CustomException]::new( $CmdletName, "Error calling $SecurityAppIdUri")
        }
    }
}
function  Get-GraphToken {
    Begin {
        [string]${CmdletName} = $PSCmdlet.MyInvocation.MyCommand.Name
        $PSBoundParameters.GetEnumerator() | Sort-Object -Property Name | ForEach-Object { "$($_.Key) = $($_.Value)" | Write-Log -Caller $CmdletName }
    }
    End {
        try {
            $GraphUrl = "https://login.microsoftonline.com/$tenantid/oauth2/v2.0/token"
            $body = @{
                Grant_Type    = "client_credentials"
                Scope         = "https://graph.microsoft.com/.default"
                Client_Id     = $clientId
                Client_Secret = $appSecret
            }
              
            $connection = Invoke-RestMethod -Method Post -Uri $GraphUrl -Body $body -ErrorAction Stop
            $connection.access_token
        }
        catch {
            Write-Error2
            throw [CustomException]::new( $CmdletName, "Error calling $GraphUrl")
        }
    }
    
}
function Get-JsonContent {
    param (
        [Parameter(Mandatory = $false, Position = 0, ValueFromPipeline = $true)]
        [ValidateNotNull()]
        [AllowEmptyString()]
        # Mandatory. Specifies the message string.
        [string]$JsonPath,
        [Parameter(Mandatory = $false, Position = 1)]
        [ValidateNotNull()]
        [AllowEmptyString()]
        # Mandatory. Specifies the message string.
        [switch]$Web
    )
    Begin {
        [string]${CmdletName} = $PSCmdlet.MyInvocation.MyCommand.Name
        $PSBoundParameters.GetEnumerator() | Sort-Object -Property Name | ForEach-Object { "$($_.Key) = $($_.Value)" | Write-Log -Caller $CmdletName }
    }
    End {
        try {
            if ($Web) {
                Invoke-RestMethod 'https://.blob.core.windows.net/xxxxx/AdvancedHuntingTestQueries.json'
            } else {
                if (Test-Path $JsonPath) {
                    Get-Content $JsonPath -Raw | ConvertFrom-Json 
                }
                else { throw "File not found: $JsonPath" }
            }
        }
        catch {
            Write-Error2
        }
    }
    
}

function Get-DefenderDevices {
    param (
        [Parameter(Mandatory = $true, Position = 0, ValueFromPipeline = $true)]
        [ValidateNotNull()]
        [AllowEmptyString()]
        # Mandatory. Specifies the query string.
        [string]$Query
    )
    #$query = 'DeviceTvmSoftwareEvidenceBeta | where SoftwareName contains "chrome"  | join  DeviceInfo on DeviceId | summarize any(DeviceId, DeviceName, LoggedOnUsers) by AadDeviceId' # Paste your own query here
    Begin {
        [string]${CmdletName} = $PSCmdlet.MyInvocation.MyCommand.Name
        $PSBoundParameters.GetEnumerator() | Sort-Object -Property Name | ForEach-Object { "$($_.Key) = $($_.Value)" | Write-Log -Caller $CmdletName }
    }
    End {
        try {
            $AdvancedHuntingRunUrl = "https://api.security.microsoft.com/api/advancedhunting/run"
            $headers = @{ 
                'Content-Type' = 'application/json'
                Accept         = 'application/json'
                Authorization  = "Bearer $Token_TP" 
            }
            $body = ConvertTo-Json -InputObject @{ 'Query' = $query }
            $webResponse = Invoke-WebRequest -Method Post -Uri $AdvancedHuntingRunUrl -Headers $headers -Body $body -ErrorAction Stop
            $response = $webResponse | ConvertFrom-Json
            # $results = $response.Results
            # check if the AadDeviceId property is returned
            $response
        }
        catch {
            Write-Error2
            throw [CustomException]::new( $CmdletName, "Error calling $AdvancedHuntingRunUrl")
        }
    }
}

function  Format-DeviceList {
    <#
  .DESCRIPTION
  Returns an ArrayList

 .Example
   "AzureADDeviceId1","AzureADDeviceId2","AzureADDeviceId3" | Get-AADDeviceInfo
#>
    param (
        [Parameter(Mandatory = $true, Position = 0, ValueFromPipeline = $true)]
        [ValidateNotNull()]
        [AllowEmptyString()]
        # Mandatory. Specifies the message string.
        [string]$JsonPath
    )
    Begin {
        [string]${CmdletName} = $PSCmdlet.MyInvocation.MyCommand.Name
        $PSBoundParameters.GetEnumerator() | Sort-Object -Property Name | ForEach-Object { "$($_.Key) = $($_.Value)" | Write-Log -Caller $CmdletName }
    }
    End {
        try {
            if (Test-Path $JsonPath) {
                Get-Content $JsonPath -Raw | ConvertFrom-Json 
            }
            else { throw "File not found: $JsonPath" }
        }
        catch {
            Write-Error2
        }
    }
    
}
function  Get-AllAADGroupMembers {
    param (
        [Parameter(Mandatory = $true, Position = 0, ValueFromPipeline = $true)]
        [ValidateNotNull()]
        [AllowEmptyString()]
        # Mandatory. Specifies the message string.
        [string]$GroupId
    )
    Begin {
        [string]${CmdletName} = $PSCmdlet.MyInvocation.MyCommand.Name
        $PSBoundParameters.GetEnumerator() | Sort-Object -Property Name | ForEach-Object { "$($_.Key) = $($_.Value)" | Write-Log -Caller $CmdletName }
    }
    End {
        try {
            $headers = @{ 'Authorization' = "Bearer $Token_Graph" }
            $url = "https://graph.microsoft.com/v1.0/groups/$GroupId/members"
            $response = Invoke-WebRequest -Uri $url -Headers $headers -Method Get -ErrorAction Stop
            $response.Content | ConvertFrom-Json
            #check this when the group will have a few members..
            ($response.Content | ConvertFrom-Json).value | Select-Object -Property '@odata.type', 'id', 'deviceId', 'displayName' | Out-String | Write-Log -Caller $CmdletName
        }
        catch {
            Write-Error2
            throw [CustomException]::new( $CmdletName, "$($response.StatusCode) StatusCode calling $url")
        }
    }
    
}

function  Get-AADDeviceInfo {
    <#
  .DESCRIPTION
  Returns the Azure Object ID & Display Name for a given DeviceId

 .Example
   "AzureADDeviceId1","AzureADDeviceId2","AzureADDeviceId3" | Get-AADDeviceInfo
#>
    param (
        [Parameter(Mandatory = $true, Position = 0, ValueFromPipeline = $true)]
        [ValidateNotNull()]
        [AllowEmptyString()]
        # Mandatory. Specifies the message string.
        [string]$DeviceId
    )
    Begin {
        [string]${CmdletName} = $PSCmdlet.MyInvocation.MyCommand.Name
        $PSBoundParameters.GetEnumerator() | Sort-Object -Property Name | ForEach-Object { "$($_.Key) = $($_.Value)" | Write-Log -Caller $CmdletName }
        $AlreadyAddedList = [System.Collections.ArrayList]::new()
        $AADDeviceInfoList = [System.Collections.ArrayList]::new()
    }
    Process {
        try {
            if (-not ([string]::IsNullOrEmpty(($DeviceId)))) {
                if ($AlreadyAddedList.DeviceId -contains $DeviceId) {
                    Write-Log "$DeviceId was already processed." -Caller $CmdletName -Color DarkYellow
                }
                else {
                    $headers = @{
                        Authorization  = "Bearer $Token_Graph"
                        "Content-type" = "application/json"
                    }
                    $urlListDevices = "https://graph.microsoft.com/v1.0/devices(deviceId='{$DeviceId}')?`$select=id,displayName"
                    $response = Invoke-RestMethod -Headers $headers -Uri $urlListDevices -Method Get -ErrorAction Stop
                    $AADDeviceInfoList.Add($response)
                    $AlreadyAddedList.Add($DeviceId)
                }
            }
            else {
                Write-Log "Empty DeviceId" -Caller $CmdletName
            }
        }
        catch {
            Write-Error2
            throw [CustomException]::new( $CmdletName, "$($response.StatusCode) StatusCode calling $urlListDevices ")
        }
    }
    End {
        $AADDeviceInfoList
        Write-Log "Ended" -Caller $CmdletName
    }
}
function  Add-AADGroupMembers {
    param (
        [Parameter(Mandatory = $true, Position = 0, ValueFromPipeline = $false)]
        [ValidateNotNull()]
        [AllowEmptyString()]
        # Mandatory. Specifies the message string.
        [string]$GroupId,
        [Parameter(Mandatory = $true, Position = 1, ValueFromPipeline = $true)]
        [ValidateNotNull()]
        [AllowEmptyString()]
        # Mandatory. Specifies the message string.
        $AllObjectIds
    )
    Begin {
        [string]${CmdletName} = $PSCmdlet.MyInvocation.MyCommand.Name
        $PSBoundParameters.GetEnumerator() | Sort-Object -Property Name | ForEach-Object { "$($_.Key) = $($_.Value)" | Write-Log -Caller $CmdletName }
        #$urlref = "https://graph.microsoft.com/v1.0/groups/$GroupId/members/`$ref"
        $urlMultiObj = "https://graph.microsoft.com/v1.0/groups/$GroupId"
        $headers = @{
            Authorization  = "Bearer $Token_Graph"
            "Content-type" = "application/json"
        }
    }
    Process {
        #Write-Log "Next batch of ObjectIds:" -Caller $CmdletName # comment this later on
        #$ObjectIds | Out-String | Write-Log -Caller $CmdletName # comment this later on
    }
    End {
        try {
            #Note that up to 20 members can be added in a single request
            # https://learn.microsoft.com/en-us/graph/api/group-post-members?view=graph-rest-1.0&tabs=http
            $CurrentCount = 0
            $ObjIdsToBeAdded = New-Object System.Collections.Generic.List[System.Object]
            $AllObjectIds | ForEach-Object { $ObjIdsToBeAdded.Add("https://graph.microsoft.com/v1.0/directoryObjects/$_") }
            while ($CurrentCount -lt $AllObjectIds.count) {
                $body = @{}
                $NewCount = $CurrentCount + 19
                Write-Log "Batch of objects to be added:" -Caller $CmdletName
                $ObjIdsToBeAdded[$CurrentCount..$NewCount] | Out-String | Write-Log -Caller $CmdletName   
                $body.Add("members@odata.bind", $ObjIdsToBeAdded[$CurrentCount..$NewCount])
                $bodyJSON = $body | ConvertTo-Json
                $response = Invoke-RestMethod -Headers $headers -Uri $urlMultiObj -Method Patch -Body $bodyJSON -ErrorAction Stop
                Write-Log "Objects added. StatusCode = $($response.StatusCode)" -Caller $CmdletName
                $CurrentCount = $NewCount + 1
            }
        }
        catch {
            Write-Error2
            throw [CustomException]::new( $CmdletName, "$($response.StatusCode) StatusCode calling $url")
        }
        Write-Log "Ended" -Caller $CmdletName
    }
}
function  Remove-AADGroupMember {
    param (
        [Parameter(Mandatory = $true, Position = 0, ValueFromPipeline = $false)]
        [ValidateNotNull()]
        [AllowEmptyString()]
        # Mandatory. Specifies the message string.
        [string]$GroupId,
        [Parameter(Mandatory = $true, Position = 1, ValueFromPipeline = $true)]
        [ValidateNotNull()]
        [AllowEmptyString()]
        # Mandatory. Specifies the message string.
        [string]$ObjectId
    )
    Begin {
        [string]${CmdletName} = $PSCmdlet.MyInvocation.MyCommand.Name
        $PSBoundParameters.GetEnumerator() | Sort-Object -Property Name | ForEach-Object { "$($_.Key) = $($_.Value)" | Write-Log -Caller $CmdletName }
        #$urlref = "https://graph.microsoft.com/v1.0/groups/$GroupId/members/`$ref"
        $headers = @{
            Authorization  = "Bearer $Token_Graph"
            "Content-type" = "application/json"
        }
    }
    Process {
        try {
            $url = "https://graph.microsoft.com/v1.0/groups/$GroupId/members/$ObjectId/`$ref"
            Write-Log "Removing $url" -Caller $CmdletName
            $response = Invoke-RestMethod -Headers $headers -Uri $url -Method Delete -ErrorAction Stop
        }
        catch {
            Write-Error2
            throw [CustomException]::new( $CmdletName, "$($response.StatusCode) StatusCode calling $url")
        }
        #Write-Log "Next batch of ObjectIds:" -Caller $CmdletName # comment this later on
        #$ObjectIds | Out-String | Write-Log -Caller $CmdletName # comment this later on
    }
    End {
    }
}
#Region -------------------------------------------------------- [Functions] ----------------------------------------------

$Token_TP = Get-ThreatProtectionToken
$Token_Graph = Get-GraphToken
$JsonObjects = Get-JsonContent -Web #-JsonPath "C:\Git\APIs\AdvancedHuntingTestQueries.json"
if ($JsonObjects.count -eq 0) { throw 'Json is null' }
# For each Json object get the devices from defender and update the AAD group membership
$JsonObjects | ForEach-Object {
    $DefenderDevices = Get-DefenderDevices -Query $_.AdvancedHuntingQuery
    # $DefenderDevices.Results | Where-Object { $_.AadDeviceId -ne '' } | Select-Object DeviceId, AadDeviceId, DeviceName, OSPlatform, OSBuild | Out-String | Write-Log -Caller 'Get-DevicesCurrentQuery'
    if ([string]::IsNullOrEmpty(( $DefenderDevices.Results))) {
        throw [CustomException]::new( 'Get-CurrentJsonQueryResults', 'The current query did not returned any results.')
    }
    if ($DefenderDevices.Schema.Name -notcontains 'AadDeviceId') {
        throw [CustomException]::new( 'Get-CurrentJsonQueryAadDeviceId', 'The return objects(s) do not contain an AadDeviceId property. Check the query. AadDeviceId is required.')
    }
    # Get unique devices only
    $DefenderQueyAadDeviceIds = ($DefenderDevices.Results | Group-Object -Property 'AadDeviceId' | Where-Object { $_.Name }).Name
    $DefenderQueyAadDeviceIds | Out-String | Write-Log -Caller 'Get-DefenderQueryUniqueAadDeviceIds'
    $UniqueDeviceList = New-Object System.Collections.Generic.List[System.Object]
    $UniqueDeviceList = ($DefenderQueyAadDeviceIds | Get-AADDeviceInfo).Id
    # Get all existing group members (devices only) to compare them later on
    #$CurrentMembers = Get-MgGroupMember -GroupId $_.AzureADGroupId -All | Where-Object {$_.AdditionalProperties.'@odata.type' -eq '#microsoft.graph.device'}
    $GroupData = Get-AllAADGroupMembers -GroupId $_.AzureADGroupId
    # if the group is empty, just add whatever the query returns.
    #if ([string]::IsNullOrEmpty(($GroupData.Content | ConvertFrom-Json).value)) {
    if ([string]::IsNullOrEmpty(($GroupData.value))) {
        Add-AADGroupMembers -AllObjectIds $UniqueDeviceList -GroupId $_.AzureADGroupId
    }
    else {
        # difference between two groups, to remove/add elements
        $Differences = Compare-Object -ReferenceObject $GroupData.value.id -DifferenceObject $UniqueDeviceList
        $ObjToBeAdded = ($Differences | Where-Object { $_.SideIndicator -eq '=>' }).InputObject
        $ObjToBeRemoved = ($Differences | Where-Object { $_.SideIndicator -eq '<=' }).InputObject
        if ($ObjToBeAdded) {
            Add-AADGroupMembers -AllObjectIds $ObjToBeAdded -GroupId $_.AzureADGroupId 
        }
        else {
            Write-Log 'No Objects to be added' -Caller 'Get-ObjectsToBeAdded'
        }
        if ($ObjToBeRemoved) {
            $ObjToBeRemoved | Remove-AADGroupMember -GroupId $_.AzureADGroupId 
        }
        else {
            Write-Log 'No Objects to be removed' -Caller 'Get-ObjectsToBeRemoved'
        }
    }
}

#New-MgGroup -BodyParameter $params
#poate scoti access tokens din parametrii ca sa nu apara in log si folosesti variablila globala
#check if group name matches the group id to avoid mistakes