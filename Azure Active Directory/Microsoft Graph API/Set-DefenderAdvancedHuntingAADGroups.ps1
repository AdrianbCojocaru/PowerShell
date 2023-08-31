<#PSScriptInfo

.VERSION 1.0

.DATE 02-Jul-2023

.AUTHOR adrian.cojocaru

#>

<#
  .SYNOPSIS
  Updates AzureAD group membership based on Defender advanced hunting queries.
  .DESCRIPTION
  The scrip is meant to run in a Runbook.
  An external *.json file stored on blob storage contains the AzureAD group Id & Name to be updated and also the Advanced Hunting query for Microsoft 365 Defender.
  This script reads the Json file and for each section it will update the AzureAD group membershipp with devices returned from the query.
  The advanced hunting query MUST return the AadDeviceId of each device.
  App registration permissions:
  Microsoft Graph (2)	
    Device.Read.All
    GroupMember.ReadWrite.All
  Microsoft Threat Protection (1)	
    AdvancedHunting.Read.All
  .PARAMETER JsonPath
  HTTPS path to the json file. "AdvancedHunting-AADGroups.json" can be used as an example
  .PARAMETER tenantId
  AzureAD tenant Id
  .PARAMETER clientId
  Application (client) Id
  .PARAMETER appSecret
  Application (client) secret
  
  .EXAMPLE
  .\AdvancedHunting-AADGroups.ps1
#>
#Region ----------------------------------------------------- [AzureAD Variables] ----------------------------------------------
[string]$tenantId = if ($env:AZUREPS_HOST_ENVIRONMENT) { Get-AutomationVariable -Name "TenantId" } else { $env:TenantId }
[string]$clientId = if ($env:AZUREPS_HOST_ENVIRONMENT) { Get-AutomationVariable -Name "DefenderAppClientId" } else { $env:DefenderAppClientId }
[string]$appSecret = if ($env:AZUREPS_HOST_ENVIRONMENT) { Get-AutomationVariable -Name "DefenderAppSecret" } else { $env:DefenderAppSecret }
[string]$JsonPath = 'https://dwmemautomation.blob.core.windows.net/testXMA%3D'
#EndRegion ----------------------------------------------------- [AzureAD Variables] ----------------------------------------------
#Region ----------------------------------------------------- [Script Variables] ----------------------------------------------
[version]$ScriptVersion = [version]'1.0.0'
$Global:ExitCode = 0
$VerbosePreference = "SilentlyContinue"
#EndRegion ----------------------------------------------------- [Script Variables] ----------------------------------------------
#Region ----------------------------------------------------- [Classes] ----------------------------------------------
class CustomException : Exception {
    <#

    .DESCRIPTION
    Used to throw exceptions.
    .EXAMPLE
    throw [CustomException]::new( "Get-ErrorOne", "This will cause the script to end with ExitCode 101")

#>
    [string] $additionalData

    CustomException($Message, $additionalData) : base($Message) {
        $this.additionalData = $additionalData
    }
}
class CustomQueryException : Exception {
    [string] $additionalData

    CustomQueryException($Message, $additionalData) : base($Message) {
        $this.additionalData = $additionalData
    }
}
#EndRegion ----------------------------------------------------- [Classes] ----------------------------------------------
#Region -------------------------------------------------------- [Functions] ----------------------------------------------
Function Write-LogRunbook {
    <#

    .DESCRIPTION
    Write messages to a log file defined by $LogPath and also display them in the console.
    Message format: [Date & Time] [CallerInfo] :: Message Text

#>
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $true, Position = 0, ValueFromPipeline = $true)]
        [ValidateNotNull()]
        [AllowEmptyString()]
        # Mandatory. Specifies the message string.
        [string]$Message,
        [Parameter(Mandatory = $false, Position = 1)]
        [ValidateNotNull()]
        # Optional. Specifies the name of the message writter. Function, command or custom name. Defaults to FunctioName or unknown
        [string]$Caller = 'Unknown'
    )
    Begin {
        [string]$LogDate = (Get-Date -Format 'MM-dd-yyyy').ToString()
        [string]$LogTime = (Get-Date -Format 'HH\:mm\:ss.fff').ToString()
    }
    Process {
        "[$LogDate $LogTime] [${Caller}] :: $Message" | Write-Verbose -Verbose  
    }
    End {}
}

function Write-ErrorRunbook {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $false, Position = 0)]
        [AllowEmptyCollection()]
        # Optional. The errorr collection.
        [array]$ErrorRecord
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
            $ErrorText = "[${CmdletName} Nr. $errNumber] :: $($($_.Exception).Message)`n" + `
                ">>> Line: $($($_.InvocationInfo).ScriptLineNumber) Char: $($($_.InvocationInfo).OffsetInLine) <<<`n" + `
                "$($($_.InvocationInfo).Line)" 
            $ErrorText | Write-Error
        }
    }
    End {}
}
function Get-ThreatProtectionToken {
    Begin {
        [string]${CmdletName} = $PSCmdlet.MyInvocation.MyCommand.Name
        $PSBoundParameters.GetEnumerator() | Sort-Object -Property Name | ForEach-Object { "$($_.Key) = $($_.Value)" | Write-LogRunbook -Caller $CmdletName }
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
            Write-ErrorRunbook
            throw [CustomException]::new( $CmdletName, "Error calling $SecurityAppIdUri")
        }
    }
}
function  Get-GraphToken {
    Begin {
        [string]${CmdletName} = $PSCmdlet.MyInvocation.MyCommand.Name
        $PSBoundParameters.GetEnumerator() | Sort-Object -Property Name | ForEach-Object { "$($_.Key) = $($_.Value)" | Write-LogRunbook -Caller $CmdletName }
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
            Write-ErrorRunbook
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
        [string]$JsonFilePath,
        [Parameter(Mandatory = $false, Position = 1)]
        [ValidateNotNull()]
        [AllowEmptyString()]
        # Mandatory. Specifies the message string.
        [switch]$Web
    )
    Begin {
        [string]${CmdletName} = $PSCmdlet.MyInvocation.MyCommand.Name
        $PSBoundParameters.GetEnumerator() | Sort-Object -Property Name | ForEach-Object { "$($_.Key) = $($_.Value)" | Write-LogRunbook -Caller $CmdletName }
    }
    End {
        try {
            if ($Web) {
                #Invoke-RestMethod 'https://stfnemeamemtransfer.blob.core.windows.net/testac/AdvancedHuntingTestQueries.json?sp=r&st=2023-08-06T19:49:39Z&se=2024-08-07T03:49:39Z&spr=https&sv=2022-11-02&sr=b&sig=3RlsQZ6vTbur%2F6T4YPDK7izF525uobv4zCJbZypjp4M%3D' -ErrorAction Stop
                Invoke-RestMethod $JsonFilePath -ErrorAction Stop
            }
            else {
                if (Test-Path $JsonPath) {
                    Get-Content $JsonPath -Raw | ConvertFrom-Json 
                }
                else { throw "File not found: $JsonPath" }
            }
        }
        catch {
            Write-ErrorRunbook
            throw [CustomException]::new( $CmdletName, "Error calling json url")
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
        $PSBoundParameters.GetEnumerator() | Sort-Object -Property Name | ForEach-Object { "$($_.Key) = $($_.Value)" | Write-LogRunbook -Caller $CmdletName }
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
            $webResponse = Invoke-WebRequest -Method Post -Uri $AdvancedHuntingRunUrl -Headers $headers -Body $body -UseBasicParsing -ErrorAction Stop
            $response = $webResponse | ConvertFrom-Json
            # $results = $response.Results
            # check if the AadDeviceId property is returned
            $response
        }
        catch {
            Write-ErrorRunbook
            throw [CustomException]::new( $CmdletName, "Error calling $AdvancedHuntingRunUrl")
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
        $PSBoundParameters.GetEnumerator() | Sort-Object -Property Name | ForEach-Object { "$($_.Key) = $($_.Value)" | Write-LogRunbook -Caller $CmdletName }
    }
    End {
        try {
            $headers = @{ 'Authorization' = "Bearer $Token_Graph" }
            $url = "https://graph.microsoft.com/v1.0/groups/$GroupId/members"
            $response = Invoke-WebRequest -Uri $url -Headers $headers -Method Get -UseBasicParsing -ErrorAction Stop
            $response.Content | ConvertFrom-Json
            #check this when the group will have a few members..
            ($response.Content | ConvertFrom-Json).value | Select-Object -Property '@odata.type', 'id', 'deviceId', 'displayName' | Out-String | Write-LogRunbook -Caller $CmdletName
        }
        catch {
            Write-ErrorRunbook
            throw [CustomException]::new( $CmdletName, "$($response.StatusCode) StatusCode calling $url")
        }
    } 
}
function  Test-AADGroup {
    <#
  .DESCRIPTION
  Check if the AzureAD group exists and the Id matches the name.
  This is a safeguard in case of mistakes in the config file
 .Example
   Test-AADGroup -GroupId '0ed6c216-dde9-4a06-83fe-923f1e42c86a' -GroupName 'TestAADGroup1'
#>
    param (
        [Parameter(Mandatory = $true, Position = 0, ValueFromPipeline = $true)]
        [ValidateNotNull()]
        [AllowEmptyString()]
        # Mandatory. Specifies the message string.
        [string]$GroupId,
        [Parameter(Mandatory = $true, Position = 0, ValueFromPipeline = $true)]
        [ValidateNotNull()]
        [AllowEmptyString()]
        # Mandatory. Specifies the message string.
        [string]$GroupName
    )
    Begin {
        [string]${CmdletName} = $PSCmdlet.MyInvocation.MyCommand.Name
        $PSBoundParameters.GetEnumerator() | Sort-Object -Property Name | ForEach-Object { "$($_.Key) = $($_.Value)" | Write-LogRunbook -Caller $CmdletName }
    }
    End {
        try {
            $headers = @{ 'Authorization' = "Bearer $Token_Graph" }
            $url = "https://graph.microsoft.com/v1.0/groups/$GroupId"
            $response = Invoke-WebRequest -Uri $url -Headers $headers -Method Get -UseBasicParsing -ErrorAction Stop
            $GroupInfo = $response.Content | ConvertFrom-Json
            #check this when the group will have a few members..
            if ($GroupInfo.displayName -eq $GroupName) {
                Write-LogRunbook 'Group Name & Id match.' -Caller $CmdletName
                return $true
            }
            else {
                Write-LogRunbook "The provided Group name: '$GroupName' doesn't match the actual Group display name: '$($GroupInfo.displayName)' for GroupId: '$GroupId'." -Caller $CmdletName
                return $false
            }
        }
        catch {
            Write-LogRunbook $_ -Caller $CmdletName
            return $false
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
        $PSBoundParameters.GetEnumerator() | Sort-Object -Property Name | ForEach-Object { "$($_.Key) = $($_.Value)" | Write-LogRunbook -Caller $CmdletName }
        $AlreadyAddedList = [System.Collections.ArrayList]::new()
        $AADDeviceInfoList = [System.Collections.ArrayList]::new()
    }
    Process {
        try {
            if (-not ([string]::IsNullOrEmpty(($DeviceId)))) {
                if ($AlreadyAddedList.DeviceId -contains $DeviceId) {
                    Write-LogRunbook "$DeviceId was already processed." -Caller $CmdletName -Color DarkYellow
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
                Write-LogRunbook "Empty DeviceId" -Caller $CmdletName
            }
        }
        catch {
            Write-ErrorRunbook
            throw [CustomException]::new( $CmdletName, "$($response.StatusCode) StatusCode calling $urlListDevices ")
        }
    }
    End {
        $AADDeviceInfoList
        Write-LogRunbook "Ended" -Caller $CmdletName
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
        $PSBoundParameters.GetEnumerator() | Sort-Object -Property Name | ForEach-Object { "$($_.Key) = $($_.Value)" | Write-LogRunbook -Caller $CmdletName }
        #$urlref = "https://graph.microsoft.com/v1.0/groups/$GroupId/members/`$ref"
        $urlMultiObj = "https://graph.microsoft.com/v1.0/groups/$GroupId"
        $headers = @{
            Authorization  = "Bearer $Token_Graph"
            "Content-type" = "application/json"
        }
    }
    Process {
        #Write-LogRunbook "Next batch of ObjectIds:" -Caller $CmdletName # comment this later on
        #$ObjectIds | Out-String | Write-LogRunbook -Caller $CmdletName # comment this later on
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
                Write-LogRunbook "Batch of objects to be added:" -Caller $CmdletName
                $ObjIdsToBeAdded[$CurrentCount..$NewCount] | Out-String | Write-LogRunbook -Caller $CmdletName   
                $body.Add("members@odata.bind", $ObjIdsToBeAdded[$CurrentCount..$NewCount])
                $bodyJSON = $body | ConvertTo-Json
                $response = Invoke-RestMethod -Headers $headers -Uri $urlMultiObj -Method Patch -Body $bodyJSON -ErrorAction Stop
                Write-LogRunbook "Objects added. StatusCode = $($response.StatusCode)" -Caller $CmdletName
                $CurrentCount = $NewCount + 1
            }
        }
        catch {
            Write-ErrorRunbook
            throw [CustomException]::new( $CmdletName, "$($response.StatusCode) StatusCode calling $url")
        }
        Write-LogRunbook "Ended" -Caller $CmdletName
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
        $PSBoundParameters.GetEnumerator() | Sort-Object -Property Name | ForEach-Object { "$($_.Key) = $($_.Value)" | Write-LogRunbook -Caller $CmdletName }
        #$urlref = "https://graph.microsoft.com/v1.0/groups/$GroupId/members/`$ref"
        $headers = @{
            Authorization  = "Bearer $Token_Graph"
            "Content-type" = "application/json"
        }
    }
    Process {
        try {
            $url = "https://graph.microsoft.com/v1.0/groups/$GroupId/members/$ObjectId/`$ref"
            Write-LogRunbook "Removing $url" -Caller $CmdletName
            $response = Invoke-RestMethod -Headers $headers -Uri $url -Method Delete -ErrorAction Stop
        }
        catch {
            Write-ErrorRunbook
            throw [CustomException]::new( $CmdletName, "$($response.StatusCode) StatusCode calling $url")
        }
        #Write-LogRunbook "Next batch of ObjectIds:" -Caller $CmdletName # comment this later on
        #$ObjectIds | Out-String | Write-LogRunbook -Caller $CmdletName # comment this later on
    }
    End {
    }
}
#EndRegion -------------------------------------------------------- [Functions] ----------------------------------------------

try {
    Write-LogRunbook "---------------------------- $ScriptVersion -----------------------" -Caller "ScriptVersion"
    $CurrentJsonObject = 1
    $JsonObjects = Get-JsonContent -JsonFilePath $JsonPath -Web
    $Token_TP = Get-ThreatProtectionToken
    $Token_Graph = Get-GraphToken
    $JsonObjects | ForEach-Object {
        Write-LogRunbook "--------------------------------------------------------------------------------" -Caller "JsonEntry $CurrentJsonObject"
        #        Write-LogRunbook "Processing AzureAD Group: '$($_.AzureADGroupName)' Id: '$($_.AzureADGroupId)'" -Caller "JsonEntry $CurrentJsonObject"
        if (Test-AADGroup -GroupId $_.AzureADGroupId -GroupName $_.AzureADGroupName) {
            try {
                $DefenderDevices = Get-DefenderDevices -Query $_.AdvancedHuntingQuery
                # $DefenderDevices.Results | Where-Object { $_.AadDeviceId -ne '' } | Select-Object DeviceId, AadDeviceId, DeviceName, OSPlatform, OSBuild | Out-String | Write-LogRunbook -Caller 'Get-DevicesCurrentQuery'
                if ([string]::IsNullOrEmpty(( $DefenderDevices.Results))) {
                    Write-LogRunbook 'The current query did not returned any results.' -Caller 'Get-CurrentJsonQueryResults'
                    throw [CustomQueryException]::new( 'Get-CurrentJsonQueryResults', 'The current query did not returned any results.')
                }
                if ($DefenderDevices.Schema.Name -notcontains 'AadDeviceId') {
                    Write-LogRunbook 'The return objects(s) do not contain an AadDeviceId property. Check the query. AadDeviceId is required.' -Caller 'Get-CurrentJsonQueryAadDeviceId'
                    throw [CustomQueryException]::new( 'Get-CurrentJsonQueryAadDeviceId', 'The return objects(s) do not contain an AadDeviceId property. Check the query. AadDeviceId is required.')
                }
                # Get unique devices only
                $DefenderQueyAadDeviceIds = ($DefenderDevices.Results | Group-Object -Property 'AadDeviceId' | Where-Object { $_.Name }).Name
                $DefenderQueyAadDeviceIds | Out-String | Write-LogRunbook -Caller 'Get-DefenderQueryUniqueAadDeviceIds'
                $UniqueDeviceList = New-Object System.Collections.Generic.List[System.Object]
                $UniqueDeviceList = ($DefenderQueyAadDeviceIds | Get-AADDeviceInfo).Id
                # Get all existing group members (devices only) to compare them later on
                #$CurrentMembers = Get-MgGroupMember -GroupId $_.AzureADGroupId -All | Where-Object {$_.AdditionalProperties.'@odata.type' -eq '#microsoft.graph.device'}
                $GroupData = Get-AllAADGroupMembers -GroupId $_.AzureADGroupId
                # if the group is empty, just add whatever the query returns.
                #if ([string]::IsNullOrEmpty(($GroupData.Content | ConvertFrom-Json).value)) {
                if ($GroupData.value.Count -eq 0) {
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
                    Write-LogRunbook "Added $($ObjToBeAdded.count) objects." -Caller 'Get-ObjectsToBeAdded'

                    if ($ObjToBeRemoved) {
                        $ObjToBeRemoved | Remove-AADGroupMember -GroupId $_.AzureADGroupId 
                    }
                    Write-LogRunbook "Removed $($ObjToBeRemoved.count) objects." -Caller 'Get-ObjectsToBeRemoved'

                }
            }
            catch [CustomQueryException] {
                Write-LogRunbook "Query results unusable. Skipped."  -Caller 'Invalid-Results'
            }
        } 
        $CurrentJsonObject += 1
    }
}
catch {
    switch ($_.Exception.Message) {
        'Get-ThreatProtectionToken' { $Global:ExitCode = 101 }
        'Get-GraphToken' { $Global:ExitCode = 102 }
        'Get-JsonContent' { $Global:ExitCode = 103 }
        'Get-DefenderDevices' { $Global:ExitCode = 104 }
        'Get-AllAADGroupMembers' { $Global:ExitCode = 105 }
        'Get-AADDeviceInfo' { $Global:ExitCode = 106 }
        'Add-AADGroupMembers' { $Global:ExitCode = 107 }
        'Remove-AADGroupMember' { $Global:ExitCode = 108 }
        Default { $Global:ExitCode = 300 }
    }
    Write-ErrorRunbook
    Write-LogRunbook "Execution completed with exit code: $Global:ExitCode" -Caller 'Info-End'
}
finally {
    if ($Global:ExitCode -ne 0) { throw $_ }
    Write-LogRunbook "Execution completed with exit code: $Global:ExitCode" -Caller 'Info-End'
}