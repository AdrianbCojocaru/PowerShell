
#----------------------------------------------------- [Functions] ----------------------------------------------
Function Write-Log {
    <#
 .Synopsis
  Used to write to the log file.

 .Example
   ### Call Write-Log with -Caller (optional parameter).
   Write-Log -Message "Your message goes here" -Caller "Caller Name goes here"

 .Example
   ### Call Write-Log.
   Write-Log -Message "Your message goes here"
#>

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
                #}
                #Catch {
                # Write-Error2 -Message  "[$LogDate $LogTime] [${CmdletName}] :: Failed to write message [$Msg] to the log file [$LogPath]" -Category WriteError
                #}
            }
        }
    }
    End {}
}
function Write-Error2 {
    <#
     .Synopsis
      Used to dump errors to the log file. Parameters needed only for a collection.
     .Example
     ###
     Write-Error2
    #>
    
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
            #$_.InvocationInfo.Line | Write-Log -Caller "Error Nr. $errNumber"
            #"$($($Error[2].InvocationInfo).ScriptName): $($($Error[2].InvocationInfo).ScriptLineNumber) char:$($($Error[2].InvocationInfo).OffsetInLine)"
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
Function Get-OGinfo {
    <#
 .Synopsis
  Receives the OG group ID [string]
  Returns the Organization Group info [PSCustomObject]
  The API also supports multiple OGs/all OGs

 .Example
   Get-OGinfo -OGID "GroupID"
#>
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $true, Position = 0, ValueFromPipeline = $true)]
        [string]$GroupID

    )
    Begin {
        [string]${CmdletName} = $PSCmdlet.MyInvocation.MyCommand.Name
    }
    Process {
        Write-Log "Getting info for GroupID = $GroupID" -Caller $CmdletName

        $params = @{             
            ContentType = "application/json;version=2"
            Headers     = @{
                "aw-tenant-code" = $awtenantcode
                "Authorization"  = $Authorization
                "Accept"         = 'application/json;version=2'
            }
            Method      = 'Get'
            #InFile = $Deploy.Source
            #OutFile     = "$DirPath\$RepoName.zip"
            Uri         = "https://as884.awmdm.com/API/system/groups/search?groupid=$GroupID"
            Verbose     = $false
        }
        try {       
            Write-Log "Sending request to $($params.Uri)" -Caller $CmdletName
            $OGinfo = Invoke-RestMethod @params -ErrorAction Stop
            Write-Log "Request returned $($OGinfo.TotalResults) result(s)." -Caller $CmdletName -Color Green
            $OGinfo | Out-String -Stream | Write-Log -Caller $CmdletName
            $RegInfo = "OK;$($OGinfo.TotalResults)"
        }
        catch {
            $RegInfo = "Error"
            $OGinfo = $null
            Write-Error2
            # pause
        }
        finally {
            Set-RegistryKey -Key "HKLM:SOFTWARE\Oracle\WSONE" -Name $CmdletName -Value $RegInfo -Type "String"
            if ($RegInfo -eq "Error") { Exit 1001 }
        }
    }
    End {
        $OGinfo
    }
}
Function Get-UserEmail {
    <#
 .Synopsis
  Returns the user's email address that is using the device [string]

 .Example
   Get-UserEmail
#>
    [CmdletBinding()]
    Param ( )
    Begin {
        [string]${CmdletName} = $PSCmdlet.MyInvocation.MyCommand.Name
    }
    Process {
        Write-Log "Searching for the email address" -Caller $CmdletName
        # escape @ from the email address
        try {       
            $Email = if (Test-Path -Path "HKLM:\SOFTWARE\OrclOBI") {
                Write-Log "Reading 'EMAILID' from HKLM:\SOFTWARE\OrclOBI" -Caller $CmdletName
                Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\OrclOBI" -Name "EMAILID" -ErrorAction Stop
            }
            else {
                Write-Log "Reading 'EmailId' from HKLM:\SOFTWARE\OrclOASIS" -Caller $CmdletName
                Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\OrclOASIS" -Name "EmailId" -ErrorAction Stop
            }
            $RegInfo = "OK;$Email"
        }
        catch {
            $RegInfo = "Error"
            $Email = $null
            Write-Error2
            # pause
        }
        finally {
            $email += if (($Email) -and ($Email -notcontains '@oracle.com')) { '@oracle.com' }
            Set-RegistryKey -Key "HKLM:SOFTWARE\Oracle\WSONE" -Name $CmdletName -Value $RegInfo -Type "String"
            Write-Log "Email = $Email" -Caller $CmdletName
        }
    }
    End {
        $Email
    }
}
Function Get-EnrollmentUserInfo {
    <#
 .Synopsis
  Receives the email address of the user [string]
  Returns the User info [PSCustomObject]

 .Example
   Get-EnrollmentUserInfo -Email "adrian.c.cojocaru@oracle.com"
#>
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $true, Position = 0, ValueFromPipeline = $true)]
        [ValidateNotNullorEmpty()]
        [string]$Email

    )
    Begin {
        [string]${CmdletName} = $PSCmdlet.MyInvocation.MyCommand.Name
    }
    Process {
        Write-Log "Getting info for user = $Email" -Caller $CmdletName
        # escape @ from the email address
        $Email = [uri]::EscapeDataString($Email)
        $Uri = "https://as884.awmdm.com/API/system/users/search?email=$Email"
        $Headers = @{
            "aw-tenant-code" = $awtenantcode
            "Authorization"  = $Authorization
            "Accept"         = 'application/json;version=2'
            ContentType      = "application/json;version=2"
            Verbose          = $false
        }
        try {       
            Write-Log "Sending request to $Uri" -Caller $CmdletName
            $EnrollmentUserInfo = Invoke-RestMethod -Uri $Uri -Method 'Get' -Headers $Headers -ErrorAction Stop
            Write-Log "Request returned $($EnrollmentUserInfo.Total) result(s)." -Caller $CmdletName -Color Green
            $EnrollmentUserInfo | Out-String -Stream | Write-Log -Caller $CmdletName
            $RegInfo = "OK;$($EnrollmentUserInfo.Total)"
        }
        catch {
            $RegInfo = "Error"
            $EnrollmentUserInfo = $null
            Write-Error2
            # pause
        }
        finally {
            Set-RegistryKey -Key "HKLM:SOFTWARE\Oracle\WSONE" -Name $CmdletName -Value $RegInfo -Type "String"
            if ($RegInfo -eq "Error") { Exit 1002 }
        }
    }
    End {
        $EnrollmentUserInfo
    }
}
Function Get-EnrollmentUserAttributes {
    <#
 .Synopsis
  Receives the user's uuid [string]
  Returns Enrollment User Attributes [PSCustomObject]
  .DESCRIPTION
  Read an enrollment user attributes including uuid, externalId, domain, userName, firstName, lastName, displayName, fullName, userPrincipalName,
  emailAddress, phoneNumber, mobileNumber, emailUserName, messageType, messageTemplateUuid, enrollmentRoleUuid, status, securityType, 
  deviceStagingType, enrolledDeviceCount, organizationGroupUuid, enrollmentOrganizationGroupUuid, aadMappingAttribute, department, employeeIdentifier, costCenter,
  customAttribute1, customAttribute2, customAttribute3, customAttribute4 and customAttribute5

 .Example
   Get-EnrollmentUserAttributes -uuid "5c20eba0-2328-4e23-abb3-aff91462b804"
#>
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $true, Position = 0, ValueFromPipeline = $true)]
        [ValidateNotNullorEmpty()]
        [string]$uuid
    )
    Begin {
        [string]${CmdletName} = $PSCmdlet.MyInvocation.MyCommand.Name
    }
    Process {
        Write-Log "Getting info for user = $Email" -Caller $CmdletName
        # escape @ from the email address
        $Email = [uri]::EscapeDataString($Email)
        $Uri = "https://as884.awmdm.com/API/system/users/$uuid"
        $Headers = @{
            "aw-tenant-code" = $awtenantcode
            "Authorization"  = $Authorization
            "Accept"         = 'application/json;version=2'
            ContentType      = "application/json;version=2"
            Verbose          = $false
        }
        try {       
            Write-Log "Sending request to $Uri" -Caller $CmdletName
            $EnrollmentUserAttributes = Invoke-RestMethod -Uri $Uri -Method 'Get' -Headers $Headers -ErrorAction Stop
            Write-Log "Request returned $($($EnrollmentUserAttributes.uuid).count) result(s)." -Caller $CmdletName -Color Green
            $EnrollmentUserAttributes | Out-String -Stream | Write-Log -Caller $CmdletName
            $RegInfo = "OK;$($($EnrollmentUserAttributes.uuid).Count)"
        }
        catch {
            $RegInfo = "Error"
            $EnrollmentUserAttributes = $null
            Write-Error2
            # pause
        }
        finally {
            Set-RegistryKey -Key "HKLM:SOFTWARE\Oracle\WSONE" -Name $CmdletName -Value $RegInfo -Type "String"
            if ($RegInfo -eq "Error") { Exit 1006 }
        }
    }
    End {
        $EnrollmentUserAttributes
    }
}
Function Set-EnrollmentUserOG {
    <#
 .Synopsis
  Updates user's Enrollment Organization Group
  Updates user's CustomAttribute3 with user's old Organization Group uuid
  Returns TRUE for success FALSE for failure
.PARAMETER UserUUID
   Required. [psobject]. User that will change the Enrollment Organization Group. Returned by Get-EnrollmentUserAttributes
.PARAMETER OGUUID
   Required. [string]. The new Enrollment Organization Group uuid
 .Example
   Set-EnrollmentUserOG -User #UserObj - OGUUID "9635d24f-e51a-4bc8-9cde-75c53497183a"
#>
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $true, Position = 0, ValueFromPipeline = $true)]
        [ValidateNotNullorEmpty()]
        [psobject]$User,
        [Parameter(Mandatory = $true, Position = 0, ValueFromPipeline = $true)]
        [ValidateNotNullorEmpty()]
        [string]$OGUUID

    )
    Begin {
        [string]${CmdletName} = $PSCmdlet.MyInvocation.MyCommand.Name
    }
    Process {
        Write-Log "User's uuid: $($User.UUID); User's email: $($User.emailAddress)" -Caller $CmdletName
        Write-Log "Current user's enrollment OG UUID: $($User.enrollmentOrganizationGroupUuid); New enrollment OG UUID: $OGUUID" -Caller $CmdletName
        # escape @ from the email address
        $Uri = "https://as884.awmdm.com/API/system/users/$($User.UUID)"
        $headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
        $headers.Add("Authorization", $Authorization)
        $headers.Add("aw-tenant-code", $awtenantcode)
        $headers.Add("Accept", "application/json;version=2")
        $headers.Add("Content-Type", "application/json")

        $body = "{
              `"enrollmentOrganizationGroupUuid`": `"$OGUUID`"
            }"
        
        try {       
            Write-Log "Sending request to $Uri" -Caller $CmdletName
            Invoke-RestMethod -Uri $Uri -Method 'PUT' -Headers $Headers -Body $Body -ErrorAction Stop
            $Success = $true
            $RegInfo = "OK;$Success"
            Write-Log "Request returned: User's OG changed successfully." -Caller $CmdletName  -Color Green
        }
        catch {
            $Success = $false
            $RegInfo = "Error;$Success"
            Write-Error2
        }
        finally {
            Set-RegistryKey -Key "HKLM:SOFTWARE\Oracle\WSONE" -Name $CmdletName -Value $RegInfo -Type "String"
            if ($RegInfo -eq "Error") { Exit 1007 }
        }
    }
    End {
        return $Success
    }
}
Function Get-EnrollmentToken {
    <#
 .Synopsis
  Receives  User uuid [string] [mandatory]
            OG uuid [string] [mandatory]
            Device friendly name [string] [mandatory]
            Device serial number [string] 
            Device tag [string]
  Returns the enrollment token for a Windows device [string]
  .DESCRIPTION
    #### Platform ID #####
    # 0 Any
    # 5 Android
    # 2 Apple iOS
    # 10 Apple macOS
    # 12 Windows Desktop

    ### Mode ID ###
    # 83 Windows

    ### message_type ###
    # 0 = email
    # 1 = SMS
    # 2 = QR Code
    # -1 = None (?)

    ## "message_template_id": 79 - this varies in stage / prod !
 .Example
   Get-EnrollmentToken -UserUUID "5c20eba0-2328-4e23-abb3-aff91462b804"-OGUUID "7b331346-b9ae-41bb-8f37-0f4e6a03a170" -DeviceFriendlyName "OASIS9" -DeviceTag "TagName"
#>
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $true, Position = 0, ValueFromPipeline = $true)]
        [ValidateNotNullorEmpty()]
        [string]$UserUUID,
        [Parameter(Mandatory = $true, Position = 1, ValueFromPipeline = $true)]
        [ValidateNotNullorEmpty()]
        [string]$OGUUID,
        [Parameter(Mandatory = $true, Position = 2, ValueFromPipeline = $true)]
        [ValidateNotNullorEmpty()]
        [string]$DeviceFriendlyName,
        [Parameter(Mandatory = $false, Position = 3, ValueFromPipeline = $true)]
        [ValidateNotNullorEmpty()]
        [string]$DeviceSerialNumber,
        [Parameter(Mandatory = $false, Position = 4, ValueFromPipeline = $true)]
        [ValidateNotNullorEmpty()]
        [string]$DeviceTag
    )
    Begin {
        [string]${CmdletName} = $PSCmdlet.MyInvocation.MyCommand.Name
    }
    Process {
        "UserUUID = $UserUUID", "DeviceFriendlyName = $DeviceFriendlyName", "DeviceSerialNumber = $DeviceSerialNumber", `
            "DeviceTag = $DeviceTag" | Write-Log -Caller $CmdletName
        $Uri = "https://as884.awmdm.com/API/mdm/groups/$OGUUID/enrollment-tokens"
        $headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
        $headers.Add("Authorization", $Authorization)
        $headers.Add("aw-tenant-code", $awtenantcode)
        $headers.Add("Accept", "application/json;version=2")
        $headers.Add("Content-Type", "application/json")
        <#
        $Body = @{
            "registration_type"         = "REGISTER_DEVICE"
            $device_registration_record = @{
                "user_uuid"           = $UserUUID
                "friendly_name"       = $DeviceFriendlyName
                "ownership_type"      = "CORPORATE_DEDICATED"
                "platform_id"         = 12
                "model_id"            = 83
                "serial_number"       = $DeviceSerialNumber
                "message_template_id" = 79
                "message_type"        = -1
                #"tags"                = "[ {
                #    "name": "OFSS"
                #} ]"
            }
        }
        #>
        $Body = "{
                `"registration_type`": `"REGISTER_DEVICE`",
                `"device_registration_record`": {
                  `"user_uuid`": `"$UserUUID`",
                  `"friendly_name`": `"$DeviceFriendlyName`",
                  `"ownership_type`": `"CORPORATE_DEDICATED`",
                  `"platform_id`": 12,
                  `"model_id`": 0,
                  `"message_template_id`": 79,
                  `"to_email_address`": `"adrian.c.cojocaru@oracle.com`",
                  `"message_type`": 0,
                  `"tags`": [
                    {
                      `"name`": `"$DeviceTag`"
                    }
                  ]
                }
              }"
        try {       
            Write-Log "Sending request to $Uri" -Caller $CmdletName
            $EnrollmentToken = Invoke-RestMethod -Uri $Uri -Method 'POST' -Headers $Headers -Body $Body -ErrorAction Stop
            Write-Log "Request returned $($EnrollmentToken.token.Count) result(s)." -Caller $CmdletName -Color Green
            # sometimes the api does not return anything even if the token is generated... depending on the OG
            if ($($EnrollmentToken.token.Count) -eq 0) {
                Write-Log "Request returned no error but also $($EnrollmentToken.token.Count) tokens. Stopping" -Caller $CmdletName -Color Green
                throw "Request returned no token."
            }
            $EnrollmentToken | Out-String -Stream | Write-Log -Caller $CmdletName
            $RegInfo = "OK;$($EnrollmentToken.token.Count)"
        }
        catch {
            $RegInfo = "Error"
            $EnrollmentToken = $null
            Write-Error2
            # pause
        }
        finally {
            Set-RegistryKey -Key "HKLM:SOFTWARE\Oracle\WSONE" -Name $CmdletName -Value $RegInfo -Type "String"
            if ($RegInfo -eq "Error") { Exit 1003 }
        }
    }
    End {
        $EnrollmentToken
    }
}

Function Get-InstalledApplication {
    <#
.SYNOPSIS
	Returns information about 32-bit installed applications. [PSCustomObject]
.PARAMETER Name
	Required. The name of the application to search for. Wildcards Allowed
.PARAMETER MSI
	Optional. It will only return the installed MSI Apps
 .Example
   Get-InstalledApplication -Name "*Intelligent Hub*" -MSI
 .Example
   Get-InstalledApplication -Name "*Intelligent Hub*"
#>
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $true, Position = 0)]
        [ValidateNotNullorEmpty()]
        [string[]]$Name,
        [Parameter(Mandatory = $false, Position = 1)]
        [ValidateNotNullorEmpty()]
        [switch]$MSI = $false
    )

    Begin {
        [string]${CmdletName} = $PSCmdlet.MyInvocation.MyCommand.Name
    }
    Process {
        ## Search app by "DisplayName" under the 32-bit Uninstall key
        "Name = $Name", "MSI = $MSI" | Write-Log -Caller $CmdletName
        [string[]]$regKeyApplications = 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall'
        [psobject[]]$regKeyApplication = @()
        ForEach ($regKey in $regKeyApplications) {
            If (Test-Path -LiteralPath $regKey -ErrorAction 'SilentlyContinue' -ErrorVariable '+ErrorUninstallKeyPath') {
                [psobject[]]$UninstallKeyApps = Get-ChildItem -LiteralPath $regKey -ErrorAction 'SilentlyContinue' -ErrorVariable '+ErrorUninstallKeyPath'
                ForEach ($UninstallKeyApp in $UninstallKeyApps) {
                    Try {
                        [psobject]$regKeyApplicationProps = Get-ItemProperty -LiteralPath $UninstallKeyApp.PSPath -ErrorAction 'Stop'
                        If ($regKeyApplicationProps.DisplayName) { [psobject[]]$regKeyApplication += $regKeyApplicationProps }
                    }
                    Catch {
                        Write-Log -Message "Unable to read values from key [$($UninstallKeyApp.PSPath)]." -Caller ${CmdletName}
                        Continue
                    }
                }
            }
        }
        If ($ErrorUninstallKeyPath) {
            Write-Error2 -ErrorRecord $ErrorUninstallKeyPath
        }

        $UpdatesSkippedCounter = 0
        [psobject[]]$installedApplication = @()
        ForEach ($regKeyApp in $regKeyApplication) {
            Try {
                [string]$appDisplayName = ''
                [string]$appDisplayVersion = ''
                [string]$appPublisher = ''

                ## don't search in updates or hotfixes keys
                if ($MSI) {
                    If (($regKeyApp.DisplayName -match '(?i)kb\d+') -or ($regKeyApp.DisplayName -match 'Cumulative Update')`
                            -or ($regKeyApp.DisplayName -match 'Security Update') -or ($regKeyApp.DisplayName -match 'Hotfix')`
                            -or ($regKeyApp.UninstallString -notmatch 'msiexec.exe')) {
                        $UpdatesSkippedCounter += 1
                        Continue
                    }
                }
                else {
                    If (($regKeyApp.DisplayName -match '(?i)kb\d+') -or ($regKeyApp.DisplayName -match 'Cumulative Update')`
                            -or ($regKeyApp.DisplayName -match 'Security Update') -or ($regKeyApp.DisplayName -match 'Hotfix')) {
                        $UpdatesSkippedCounter += 1
                        Continue
                    }
                }

                ## remove special characters
                $appDisplayName = $regKeyApp.DisplayName -replace '[^\u001F-\u007F]', ''
                $appDisplayVersion = $regKeyApp.DisplayVersion -replace '[^\u001F-\u007F]', ''
                $appPublisher = $regKeyApp.Publisher -replace '[^\u001F-\u007F]', ''

                ForEach ($application in $Name) {
                    $applicationMatched = $false                          
                    If (($regKeyApp.DisplayName -like $application) -and ($regKeyApp.PSChildName -ne $UninstallKeyName)) {
                        $applicationMatched = $true
                        Write-Log -Message "App found $($regKeyApp.PSChildName) name [$appDisplayName] version [$appDisplayVersion]." -Caller ${CmdletName}
                    }
                }
                If ($applicationMatched -and ($($regKeyApp.PSChildName) -ne $UninstallKeyName)) {
                    $installedApplication += New-Object -TypeName 'PSObject' -Property @{
                        UninstallSubkey = $regKeyApp.PSChildName
                        ProductCode     = If ($regKeyApp.PSChildName -match $MSIProductCodeRegExPattern) { $regKeyApp.PSChildName } Else { [string]::Empty }
                        DisplayName     = $appDisplayName
                        DisplayVersion  = $appDisplayVersion
                        UninstallString = $regKeyApp.UninstallString
                        InstallSource   = $regKeyApp.InstallSource
                        InstallLocation = $regKeyApp.InstallLocation
                        InstallDate     = $regKeyApp.InstallDate
                        SystemComponent = $regKeyApp.SystemComponent
                        ModifyPath      = $regKeyApp.ModifyPath
                        EstimatedSize   = $regKeyApp.EstimatedSize
                        Publisher       = $appPublisher
                    }
                }
            }
            Catch {
                Write-Log -Message "Failed to get app info for [$appDisplayName]." -Caller ${CmdletName}
                Continue
            }
        }
        #if ($UpdatesSkippedCounter -ne 0) {Write-Log -Message "Skipped $UpdatesSkippedCounter entries. [updates/patches]." -Caller ${CmdletName}}
        If (-not $installedApplication) {
            Write-Log -Message "No results for $Name." -Caller ${CmdletName}
        }
    }
    End {
        $installedApplication | Out-String -Stream | Write-Log -Caller $CmdletName
        Write-Output -InputObject $installedApplication
    }
}
Function Get-SerialNumber {
    <#
    .SYNOPSIS
        Returns the serial number of the current device [string].
    #>
    [CmdletBinding()]
    Param (  )
    
    Begin {
        ## Get the name of this function and write header
        [string]${CmdletName} = $PSCmdlet.MyInvocation.MyCommand.Name
    }
    Process {
        try {
            Write-Log -Message "Get the serial number via WMI." -Caller ${CmdletName}
            $SerialNumber = Get-CimInstance -ClassName win32_bios -ErrorAction Stop | Select-Object -ExpandProperty SerialNumber
            $RegInfo = "OK;$SerialNumber"
        }
        catch {
            Write-Error2
            Write-Log -Message "WMI call failed. Trying registry " -Caller ${CmdletName}
            try {
                $SerialNumber = if (Test-Path -Path "HKLM:\SOFTWARE\OrclOASIS\Hardware") {
                    Write-Log "Reading 'Hardware_ChassisSerial' from HKLM:\SOFTWARE\OrclOASIS\Hardware" -Caller $CmdletName
                    Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\OrclOASIS\Hardware" -Name "Hardware_ChassisSerial" -ErrorAction Stop
                    $RegInfo = "OK;$SerialNumber"
                }
                else {
                    # no registry with the serial number in OBI?!
                    $RegInfo = "Error"
                    Write-Log "Reading 'EmailId' from HKLM:\SOFTWARE\OrclOASIS" -Caller $CmdletName
                }
            }
            catch {
                $RegInfo = "Error"
                Write-Error2
            }
        }
        finally {
            Set-RegistryKey -Key "HKLM:SOFTWARE\Oracle\WSONE" -Name $CmdletName -Value $RegInfo -Type "String"
            Write-Log "SerialNumber = $SerialNumber" -Caller $CmdletName
        }
    }
    End {
        $SerialNumber
    }
}
Function Get-MDMEvents {
    <#
.SYNOPSIS
    Returns a  collection for th enrollment or unenrollment events.
.PARAMETER Type
   Required. EventType 'Enrollments', 'Unenrollments'
.Example
    Get-MDMEvents -Type Enrollments
.Example
    Get-MDMEvents -Type Unenrollments
#>
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $false, Position = 0)]
        [ValidateNotNullorEmpty()]
        [ValidateSet('Enrollments', 'Unenrollments')]
        [String]$Type
    )
    
    Begin {
        ## Get the name of this function and write header
        [string]${CmdletName} = $PSCmdlet.MyInvocation.MyCommand.Name
        $EventID = if ($Type -eq 'Enrollments') { 72 } else { 74 }
    }
    Process {
        ## Skip balloon if in silent mode, disabled in the config or presentation is detected
        Write-Log -Message "Searching for MDM $Type." -Caller ${CmdletName}
        try {
            [hashtable]$WinEvtFilter = @{ ProviderName = 'Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider'; ID = $EventID }
            [array]$JoinEvent = Get-WinEvent -FilterHashtable $WinEvtFilter | Sort-Object -Property 'TimeCreated'
            $AlreadyJoined = $JoinEvent.Count -gt 0
            Write-Log -Message "Microsoft-Windows-User Device Registration - Nr of successful MDM $Type found: $($JoinEvent.Count)." -Caller ${CmdletName}
            if ($AlreadyJoined) { $JoinEvent | Sort-Object -Property 'TimeCreated' | Select-Object -Property TimeCreated, id, message | Write-Log -Caller ${CmdletName} }
            $RegInfo = $($JoinEvent.Count)
        }
        finally {
            Set-RegistryKey -Key "HKLM:SOFTWARE\Oracle\WSONE" -Name "$CmdletName$Type" -Value $RegInfo -Type "String"
        }
    }
    End {
        return $AlreadyJoined
    }
}
Function Get-EnrollmentStatus {
    <#
.SYNOPSIS
    Keeps checking for the 'Status' registry under "HKLM:\SOFTWARE\AIRWATCH\EnrollmentStatus" for xx seconds [int] or until the value changes to 'Completed'
    Returns TRUE if Status is Completed, FALSE otherwise.
    Logs values for thee following registries: Status, CurrentStep, LastError
.PARAMETER Seconds
   Required. Number of secons to check for registry Status = Completed under HKLM:\SOFTWARE\AIRWATCH\EnrollmentStatus
   Default = 120
.Example
    Get-EnrollmentStatus -Seconds 180s
#>
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $false, Position = 0)]
        [ValidateNotNullorEmpty()]
        [Int32]$Seconds = '120'
    )
    
    Begin {
        ## Get the name of this function and write header
        [string]${CmdletName} = $PSCmdlet.MyInvocation.MyCommand.Name
        [bool]$EnrollmentCompleted = $false
    }
    End {
        ## Skip balloon if in silent mode, disabled in the config or presentation is detected
        Write-Log -Message "Checking HKLM:\SOFTWARE\AIRWATCH\EnrollmentStatus for $Seconds seconds." -Caller ${CmdletName}
        try {
            foreach ($fiveseconds in (1..$Seconds)) {
                Start-Sleep -Seconds 5
                if (Test-Path -Path "HKLM:\SOFTWARE\AIRWATCH\EnrollmentStatus") {
                    $Regs = (Get-Itemproperty -Path 'HKLM:\SOFTWARE\AIRWATCH\EnrollmentStatus' -ErrorAction Ignore)
                    Write-Log "HKLM:\SOFTWARE\AIRWATCH\EnrollmentStatus | Status = $($Regs.Status) | CurrentStep = $($Regs.CurrentStep)" -Caller $CmdletName
                    if ($Regs.Status -eq 'Completed') {
                        $EnrollmentCompleted = $true
                        $StatusRegValue = 'OK'
                        Write-Log "Request retruned EnrollmentStatus = Completed. Exiting the loop." -Caller $CmdletName  -Color Green
                        break
                    }
                    elseif ($Regs.Status -eq 'Failed') {
                        Write-Log "HKLM:\SOFTWARE\AIRWATCH\EnrollmentStatus | LastError = $($Regs.LastError)" -Caller $CmdletName
                    }
                }
                else {
                    Write-Log "HKLM:\SOFTWARE\AIRWATCH\EnrollmentStatus does not exist" -Caller $CmdletName
                }
            }
        }
        finally {
            Write-Log "Returns $EnrollmentCompleted" -Caller $CmdletName
            $RegInfo = if ($EnrollmentCompleted) { "OK;$StatusRegValue" } else { "$($Regs.Status);$($Regs.CurrentStep);$($Regs.LastError)" }
            Set-RegistryKey -Key "HKLM:SOFTWARE\Oracle\WSONE" -Name "$CmdletName$Type" -Value $RegInfo -Type "String"
        }
        return $EnrollmentCompleted
    }
}
function Start-SilentEnrollment {
    <#
  .SYNOPSIS
    Starts the installation of the MSIFilePath [string] using the EnrollmentToken [string].
    .Example
   Start-SilentEnrollment -MSIFilePath "C:\Work\AirwatchAgent.msi" -EnrollmentToken "ZZZ"
  #>
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $true, Position = 0, ValueFromPipeline = $true)]
        [ValidateNotNullorEmpty()]
        [psobject]$MSIFilePath,
        [Parameter(Mandatory = $true, Position = 1, ValueFromPipeline = $true)]
        [ValidateNotNullorEmpty()]
        [psobject]$EnrollmentToken
    )
    Begin {
        [string]${CmdletName} = $PSCmdlet.MyInvocation.MyCommand.Name
        $MSIFilePath | Write-Log -Caller $CmdletName
    }
    End {
        if (-not(Test-Path $LogDir)) { New-Item -Path $LogDir -ItemType "directory" }
        $MSIName = $MSIFilePath | Split-Path -Leaf
        $DataStamp = get-date -Format yyyyMMddTHHmmss
        $MSIInstallArguments = @(
            "/i"
            "`"$MSIFilePath`""
            "/qn"
            "ENROLL=Y"
            "IMAGE=N"
            "SERVER=`"$EnrollmentServer`""
            "LGName=`"$EnrollmentToken`""
            "/norestart"
            "/l*v"
            "`"$LogDir\$MSIName-$DataStamp-install.log`""
        )
        Write-Log "Executing msiexec.exe $MSIInstallArguments" -Caller $CmdletName
        $ExitCode = (Start-Process "msiexec.exe" -ArgumentList $MSIInstallArguments -Wait -Passthru).ExitCode
        Write-Log "$MSIName installation return code: $ExitCode" -Caller $CmdletName
        if ($ExitCode -eq 1603) {
            Set-RegistryKey -Key "HKLM:SOFTWARE\Oracle\WSONE" -Name $CmdletName -Value 'Error' -Type "String"
            Exit 1005
        }
        else {
            Set-RegistryKey -Key "HKLM:SOFTWARE\Oracle\WSONE" -Name $CmdletName -Value "OK;$ExitCode" -Type "String"
            Write-Log "Request returned: MSI installed successfully." -Caller $CmdletName  -Color Green
            return $true
        }
    }
}
function Remove-InstalledApplication {
    <#
  .SYNOPSIS
    Removes the specified installed application [PSCustomObject].
    .Example
   Remove-InstalledApplication -App $AppObject
  #>
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $true, Position = 0, ValueFromPipeline = $true)]
        [ValidateNotNullorEmpty()]
        [psobject]$App
    )
    Begin {
        [string]${CmdletName} = $PSCmdlet.MyInvocation.MyCommand.Name
    }
    End {
        "DisplayName = $($App.DisplayName)", "DisplayVersion = $($App.DisplayVersion)", "ProductCode = $($App.ProductCode)" | Write-Log -Caller $CmdletName
        if (-not(Test-Path $LogDir)) { New-Item -Path $LogDir -ItemType "directory" }
        $DataStamp = get-date -Format yyyyMMddTHHmmss
        $MSIUninstallArguments = @(
            "/x"
            $App.ProductCode
            "/qn"
            "/norestart"
            "/l*v"
            "`"$LogDir\IntelligentHub-$DataStamp-uninstall.log`""
        )
        Write-Log "Executing msiexec.exe $MSIUninstallArguments" -Caller $CmdletName
        $ExitCode = (Start-Process "msiexec.exe" -ArgumentList $MSIUninstallArguments -Wait -Passthru).ExitCode
        Write-Log "Uninstallation return code: $ExitCode" -Caller $CmdletName
        Start-Sleep -Seconds 10
        if ($ExitCode -eq 1603) {
            Set-RegistryKey -Key "HKLM:SOFTWARE\Oracle\WSONE" -Name $CmdletName -Value 'Error' -Type "String"
            Exit 1004
        }
        else {
            Set-RegistryKey -Key "HKLM:SOFTWARE\Oracle\WSONE" -Name $CmdletName -Value "OK;$ExitCode" -Type "String"
            Write-Log "Request returned: MSI uninstalled successfully." -Caller $CmdletName  -Color Green
            return $true
        }
    }
}
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
                    Write-Log -Message "Create reg key: [$key]." -Caller ${CmdletName}
                    $null = New-Item -Path $Key -Force -ErrorAction 'Stop'
                }
                Catch {
                    Write-Log -Message "<< Error >>  creating reg key: [$key]"  -Caller ${CmdletName}
                    Write-Error2
                }           
            }
        }
        Try {
            if ($PSBoundParameters.ContainsKey('Name')) {
                If (-not (Get-ItemProperty -LiteralPath $key -Name $Name -ErrorAction 'SilentlyContinue')) {
                    #$error.Remove($error[$error.Count-1])
                    Write-Log -Message "Create reg value: [$key] [$name = $Value]." -Caller ${CmdletName}
                    $null = New-ItemProperty -LiteralPath $key -Name $name -Value $Value -PropertyType $Type -ErrorAction 'Stop'
                }
                Else {
                    Write-Log -Message "Update reg value: [$key] [$name = $Value]." -Caller ${CmdletName}
                    $null = Set-ItemProperty -LiteralPath $key -Name $name -Value $Value -ErrorAction 'Stop'
                }
            }
            Else {
                $Name = '(Default)'
                Write-Log -Message "Update reg value: [$key] [$Name = $Value]." -Caller ${CmdletName}

            }
        }
        catch {
            Write-Log -Message "<< Error >>  writting [$key] [$Name = $Value]. See the -CreateKey parameter." -Caller ${CmdletName}
            Write-Error2
        }
    }      
    end {}
}

#----------------------------------------------------- [ End Functions] ----------------------------------------------