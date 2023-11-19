<#PSScriptInfo

.VERSION 1.0

.DATE 02-Jul-2023

.AUTHOR adrian.cojocaru

#>

<#
  .SYNOPSIS
  Updates AzureAD group membership based on Microsoft 365 Defender advanced hunting queries.
  .DESCRIPTION
  The scrip is meant to run in a Runbook.
  An external *.json file stored on blob storage contains the AzureAD group Id & Name to be updated and also the Advanced Hunting query for Microsoft 365 Defender.
  This script reads the Json file and for each section it will update the AzureAD group membershipp with devices returned from the query.
  The advanced hunting query MUST return the AadDeviceId of each device.
  See the attached pdf for more info.
  App registration permissions:
  Microsoft Graph (2)	
    Device.Read.All
    GroupMember.ReadWrite.All
  Microsoft Threat Protection (1)	
    AdvancedHunting.Read.All
  
  .EXAMPLE
  .\AdvancedHunting-AADGroups.ps1
#>
#Region ----------------------------------------------------- [AzureAD Variables] ----------------------------------------------
[string]$ApplicationId = if ($env:AZUREPS_HOST_ENVIRONMENT -or $PSPrivateMetadata.JobId) { Get-AutomationVariable -Name "DWC-EUD-Automation_AppId" }else { $env:STFNmemDefenderAppClientId }
#[string]$ApplicationSecret = if ($env:AZUREPS_HOST_ENVIRONMENT -or $PSPrivateMetadata.JobId) { Get-AutomationVariable -Name "DWC-EUD-Automation_AppSecret" } else { $env:STFNmemDefenderAppSecret }
[string]$Thumbprint = if ($env:AZUREPS_HOST_ENVIRONMENT -or $PSPrivateMetadata.JobId) { Get-AutomationVariable -Name "DWC-EUD-Automation_CertThumbprint" } else { $env:STFNmemDefenderAppCertThumbprint }
[string]$TenantId = if ($env:AZUREPS_HOST_ENVIRONMENT -or $PSPrivateMetadata.JobId) { Get-AutomationVariable -Name "TenantId" }else { $env:STFNmemTenantId }
[string]$JsonPath = 'https://dwmemautomation.blob.core.windows.net/testXMA%3D'
#EndRegion ----------------------------------------------------- [AzureAD Variables] ----------------------------------------------
#Region ----------------------------------------------------- [Script Variables] ----------------------------------------------
[version]$ScriptVersion = [version]'1.0.0'
$Global:GraphTokenRefreshLimit = 24
$Global:GraphTokenRefreshCount = 0
$Global:GatewayTimeoutCountLimit = 24
$Global:GatewayTimeoutCount = 0
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
function Get-Token {
    <#
  .DESCRIPTION
  Get Authentication token from Microsoft Graph (default) or Threat Protection.
  Authentication can be done with a Certificate  Thumbprint (default) or ApplicationId Id & ApplicationSecret.
  $Thumbprint variable needs to be initialized before calling the function
  For ApplicationId & ApplicationSecret the $ApplicationId & $ApplicationSecret variables need to be initialized before calling the function.
 .Example
   Get a token for Graph using certificate thumbprint (default behaviour)
   Get-Token
 .Example
   Get a token for Defender's ThreatProtection using certificate thumbprint
   Get-Token -ThreatProtection
 .Example
   Get a token for Defender's ThreatProtection using ApplicationId & ApplicationSecret
   For ApplicationId & ApplicationSecret the variables need to be defined before calling the function: $ApplicationId & $ApplicationSecret
   Get-Token -ThreatProtection -AppIdSecret
#>
    param (
        [Parameter(Mandatory = $false, Position = 0)]
        [switch]$ThreatProtection,
        [Parameter(Mandatory = $false, Position = 1)]
        [switch]$AppIdSecret
    )
    Begin {
        [string]${CmdletName} = $PSCmdlet.MyInvocation.MyCommand.Name
        $PSBoundParameters.GetEnumerator() | Sort-Object -Property Name | ForEach-Object { "$($_.Key) = $($_.Value)" | Write-LogRunbook -Caller $CmdletName }
    }
    End {
        try {
            $url = if ($ThreatProtection) { 'https://api.security.microsoft.com' } else { 'https://graph.microsoft.com' }
            Write-LogRunbook "url = $url" -Caller $CmdletName
            if ($AppIdSecret) {
                $body = [Ordered] @{
                    grant_type    = 'client_credentials'
                    client_id     = $ApplicationId
                    client_secret = $ApplicationSecret  
                }
                if ($ThreatProtection) {
                    $oAuthUrl = "https://login.windows.net/$TenantId/oauth2/token"
                    $body.Add('resource', $url)
                }
                else {
                    $oAuthUrl = "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token" 
                    $body.Add('scope', $url + '/.default')
                }
                Write-LogRunbook "oAuthUrl = $oAuthUrl" -Caller $CmdletName
                [string]$Token = (Invoke-RestMethod -Method Post -Uri $oAuthUrl -Body $body -ErrorAction Stop).access_token
            }
            else {
                # certificate auth
                if (-not (Get-AzContext)) {
                    Write-LogRunbook "No AzContext. Running Connect-AzAccount" -Caller $CmdletName
                    Connect-AzAccount -CertificateThumbprint $Thumbprint -ApplicationId $ApplicationId -Tenant $TenantId -ServicePrincipal
                }
                [string]$Token = (Get-AzAccessToken -ResourceUrl $url).Token
            }
            $Token
        }
        catch {
            Write-ErrorRunbook
            throw [CustomException]::new( $CmdletName, "Error calling https://api.security.microsoft.com")
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
            switch ($_.Exception.Response.StatusCode) {
                'Unauthorized' {
                    if ($Global:GraphTokenRefreshCount -lt $Global:GraphTokenRefreshLimit) {
                        Write-LogRunbook "Token expired. Getting a new one. GraphTokenRefreshCount: '$Global:GraphTokenRefreshCount'" -Caller $CmdletName
                        $global:Token_TP = Get-Token -ThreatProtection
                        $Global:GraphTokenRefreshCount++
                        Get-DefenderDevices @PSBoundParameters
                    }
                    else {
                        Write-ErrorRunbook
                        throw [CustomException]::new( $CmdletName, "GraphTokenRefreshLimit '$Global:GraphTokenRefreshCount' reached! ")
                    }
                }
                Default {
                    Write-ErrorRunbook
                    throw [CustomException]::new( $CmdletName, "$($response.StatusCode) StatusCode calling '$url'")
                }
            }
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
        $GroupMembersList = @()
        $count = 0
    }
    End {
        try {
            $headers = @{ 'Authorization' = "Bearer $Token_Graph" }
            $url = "https://graph.microsoft.com/v1.0/groups/$GroupId/members"
            $response = Invoke-RestMethod -Uri $url -Headers $headers -Method Get -UseBasicParsing -ErrorAction Stop
            #$response.Content | ConvertFrom-Json
            #check this when the group will have a few members..
            $response.value | Select-Object -Property '@odata.type', 'id', 'deviceId', 'displayName' | Out-String | Write-LogRunbook -Caller $CmdletName
            if ($response.value) { $GroupMembersList += $response.value }
            while ($response.'@odata.nextLink') {
                $count++
                Write-LogRunbook "Current @odata.nextLink: $count" -Caller $CmdletName
                #Start-Sleep -Seconds 1
                $response = Invoke-RestMethod -Headers $headers -Uri $response.'@odata.nextLink' -Method Get -ErrorAction Stop
                if ($response.value) { 
                    $response.value | Select-Object -Property '@odata.type', 'id', 'deviceId', 'displayName' | Out-String | Write-LogRunbook -Caller $CmdletName
                    $GroupMembersList += $response.value 
                }
            }
            $GroupMembersList
        }
        catch {
            switch ($_.Exception.Response.StatusCode) {
                'Unauthorized' {
                    if ($Global:GraphTokenRefreshCount -lt $Global:GraphTokenRefreshLimit) {
                        Write-LogRunbook "Token expired. Getting a new one. GraphTokenRefreshCount: '$Global:GraphTokenRefreshCount'" -Caller $CmdletName
                        $global:Token_Graph = Get-Token
                        $Global:GraphTokenRefreshCount++
                        Get-AllAADGroupMembers @PSBoundParameters
                    }
                    else {
                        Write-ErrorRunbook
                        throw [CustomException]::new( $CmdletName, "GraphTokenRefreshLimit '$Global:GraphTokenRefreshCount' reached! ")
                    }
                }
                'NotFound' { 
                    Write-LogRunbook "AzureAD object not found." -Caller $CmdletName
                }
                Default {
                    Write-ErrorRunbook
                    throw [CustomException]::new( $CmdletName, "$($response.StatusCode) StatusCode calling '$url'")
                }
            }
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
            switch ($_.Exception.Response.StatusCode) {
                'Unauthorized' {
                    if ($Global:GraphTokenRefreshCount -lt $Global:GraphTokenRefreshLimit) {
                        Write-LogRunbook "Token expired. Getting a new one. GraphTokenRefreshCount: '$Global:GraphTokenRefreshCount'" -Caller $CmdletName
                        $global:Token_Graph = Get-Token
                        $Global:GraphTokenRefreshCount++
                        Test-AADGroup @PSBoundParameters
                    }
                    else {
                        Write-ErrorRunbook
                        throw [CustomException]::new( $CmdletName, "GraphTokenRefreshLimit '$Global:GraphTokenRefreshCount' reached! ")
                    }
                }
                'NotFound' { 
                    Write-LogRunbook "AzureAD object not found." -Caller $CmdletName
                }
                Default {
                    Write-ErrorRunbook
                    throw [CustomException]::new( $CmdletName, "$($response.StatusCode) StatusCode calling '$url'")
                }
            }
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
            switch ($_.Exception.Response.StatusCode) {
                'Unauthorized' {
                    if ($Global:GraphTokenRefreshCount -lt $Global:GraphTokenRefreshLimit) {
                        Write-LogRunbook "Token expired. Getting a new one. GraphTokenRefreshCount: '$Global:GraphTokenRefreshCount'" -Caller $CmdletName
                        $global:Token_Graph = Get-Token
                        $Global:GraphTokenRefreshCount++
                        Get-AADDeviceInfo @PSBoundParameters
                    }
                    else {
                        Write-ErrorRunbook
                        throw [CustomException]::new( $CmdletName, "GraphTokenRefreshLimit '$Global:GraphTokenRefreshCount' reached! ")
                    }
                }
                'NotFound' { 
                    Write-LogRunbook "DeviceId $DeviceId not found." -Caller $CmdletName
                }
                Default {
                    Write-ErrorRunbook
                    throw [CustomException]::new( $CmdletName, "$($response.StatusCode) StatusCode calling '$url'")
                }
            }
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
                # A maximum of 20 objects can be added in a single request
                $NewCount = $CurrentCount + 19
                Write-LogRunbook "Batch of objects to be added in current request:" -Caller $CmdletName
                $ObjIdsToBeAdded[$CurrentCount..$NewCount] | Out-String | Write-LogRunbook -Caller $CmdletName   
                $body.Add("members@odata.bind", $ObjIdsToBeAdded[$CurrentCount..$NewCount])
                $bodyJSON = $body | ConvertTo-Json
                $response = Invoke-RestMethod -Headers $headers -Uri $urlMultiObj -Method Patch -Body $bodyJSON -ErrorAction Stop
                Write-LogRunbook "Objects added." -Caller $CmdletName
                $CurrentCount = $NewCount + 1
            }
        }
        catch {
            switch ($_.Exception.Response.StatusCode) {
                'Unauthorized' {
                    if ($Global:GraphTokenRefreshCount -lt $Global:GraphTokenRefreshLimit) {
                        Write-LogRunbook "Token expired. Getting a new one. GraphTokenRefreshCount: '$Global:GraphTokenRefreshCount'" -Caller $CmdletName
                        $global:Token_Graph = Get-Token
                        $Global:GraphTokenRefreshCount++
                        Add-AADGroupMembers @PSBoundParameters
                    }
                    else {
                        Write-ErrorRunbook
                        throw [CustomException]::new( $CmdletName, "GraphTokenRefreshLimit '$Global:GraphTokenRefreshCount' reached! ")
                    }
                }
                'NotFound' { 
                    Write-LogRunbook "AzureAD object not found." -Caller $CmdletName
                }
                Default {
                    Write-ErrorRunbook
                    throw [CustomException]::new( $CmdletName, "$($response.StatusCode) StatusCode calling '$url'")
                }
            }
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
            switch ($_.Exception.Response.StatusCode) {
                'Unauthorized' {
                    if ($Global:GraphTokenRefreshCount -lt $Global:GraphTokenRefreshLimit) {
                        Write-LogRunbook "Token expired. Getting a new one. GraphTokenRefreshCount: '$Global:GraphTokenRefreshCount'" -Caller $CmdletName
                        $global:Token_Graph = Get-Token
                        $Global:GraphTokenRefreshCount++
                        Remove-AADGroupMember @PSBoundParameters
                    }
                    else {
                        Write-ErrorRunbook
                        throw [CustomException]::new( $CmdletName, "GraphTokenRefreshLimit '$Global:GraphTokenRefreshCount' reached! ")
                    }
                }
                'NotFound' { 
                    Write-LogRunbook "AzureAD object not found." -Caller $CmdletName
                }
                Default {
                    Write-ErrorRunbook
                    throw [CustomException]::new( $CmdletName, "$($response.StatusCode) StatusCode calling '$url'")
                }
            }
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
    $Token_Graph = Get-Token
    #$Token_Graph = ''
    $Token_TP = Get-Token -ThreatProtection
    #$Token_TP = ''
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
                Write-Output "$($_.AdvancedHuntingQuery) returned $($($($DefenderDevices).Results).Count) devices."
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
                    [int]$CurrentMemberCount = $GroupData.Count
                if ($CurrentMemberCount -eq 0) {
                    Add-AADGroupMembers -AllObjectIds $UniqueDeviceList -GroupId $_.AzureADGroupId
                }
                else {
                    # difference between two groups, to remove/add elements
                    $Differences = Compare-Object -ReferenceObject $GroupData.id -DifferenceObject $UniqueDeviceList
                    $ObjToBeAdded = ($Differences | Where-Object { $_.SideIndicator -eq '=>' }).InputObject
                    $ObjToBeRemoved = ($Differences | Where-Object { $_.SideIndicator -eq '<=' }).InputObject
                    
                    if ($ObjToBeRemoved) {
                        # Protection against removing all members
                        if ($CurrentMemberCount * 0.99 -ge $ObjToBeRemoved.Count) {
                            $ObjToBeRemoved | Remove-AADGroupMember -GroupId $_.AzureADGroupId 
                        }
                        else {
                            Write-LogRunbook "An attempt was made to remove more than 99% of the members for the group: '$($_.AzureADGroupName)' Id: $($_.AzureADGroupId). Double check this is correct." -Caller 'Remove-AllGroupMembers'
                            throw [CustomException]::new( 'Remove-AllGroupMembers', "An attampt was made to remove more than 99% of the members for the group: '$($_.AzureADGroupName)' Id: $($_.AzureADGroupId). Double check this is correct.")
                        }
                    }
                    Write-LogRunbook "Removed $($ObjToBeRemoved.count) objects." -Caller 'Get-ObjectsToBeRemoved'
                    if ($ObjToBeAdded) {
                        Add-AADGroupMembers -AllObjectIds $ObjToBeAdded -GroupId $_.AzureADGroupId 
                    }
                    Write-LogRunbook "Added $($ObjToBeAdded.count) objects." -Caller 'Get-ObjectsToBeAdded'
                    # try-catch jump to here if required to avoid err
                }
                Write-Output "Group: '$($_.AzureADGroupName)' Id: $($_.AzureADGroupId) Member count before: $CurrentMemberCount Devices added: $($ObjToBeAdded.count) Devices removed: $($ObjToBeRemoved.count)"
            }
            catch [CustomQueryException] {
                Write-LogRunbook "Query results unusable. Skipped."  -Caller 'Invalid-Results'
            }
        }
        else { Write-Output "Group: '$($_.AzureADGroupName)' Id: $($_.AzureADGroupId) skipped." }
        $CurrentJsonObject += 1
    }
}
catch {
    switch ($_.Exception.Message) {
        'Get-Token' { $Global:ExitCode = 102 }
        'Get-JsonContent' { $Global:ExitCode = 103 }
        'Get-DefenderDevices' { $Global:ExitCode = 104 }
        'Get-AllAADGroupMembers' { $Global:ExitCode = 105 }
        'Get-AADDeviceInfo' { $Global:ExitCode = 106 }
        'Add-AADGroupMembers' { $Global:ExitCode = 107 }
        'Remove-AADGroupMember' { $Global:ExitCode = 108 }
        'Remove-AllGroupMembers'  { $Global:ExitCode = 109 }
        Default { $Global:ExitCode = 300 }
    }
    Write-ErrorRunbook
    Write-LogRunbook "Execution completed with exit code: $Global:ExitCode" -Caller 'Info-End'
}
finally {
    if ($Global:ExitCode -ne 0) { throw $_ }
    Write-LogRunbook "Execution completed with exit code: $Global:ExitCode" -Caller 'Info-End'
}