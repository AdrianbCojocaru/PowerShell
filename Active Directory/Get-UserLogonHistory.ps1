<#PSScriptInfo

.VERSION 1.0

.GUID 40d7e958-968d-4ba1-8e67-dd8afeb6954b

.AUTHOR adrianbcojocaru@gmail.com

#>

#Requires -RunAsAdministrator

<#
  .SYNOPSIS
  Creates a report with the login history for all users.

  .DESCRIPTION
  Creates a report with the login history for all users.
  By default the CSV report will be created in the 'Output' folder next to this script.
  By default one CSV report is generated for each ComputerName.
  CSV report format: ComputerName | Username | GivenName | Surname | StartTime | StopTime | 'Session Active (Days)' | 'Session Active (Min)' | Groups | OrganizationalUnits 
  CSV report name = ScriptName + ComputerName + DateTime

  .PARAMETER ComputerName
  [string[]] Name of the Computer(s) to read the EventLog from.

  .PARAMETER CSVDestinationPath
  [string] Path to a single CSV report containg the result.
  Specifying this parameter will override the defaults...

  .PARAMETER RSAT
  [switch] Used to install the Remote Server Administration Tools

  .INPUTS
  This script supports pipeline input as an array of ComputerNames.
  If not ComputerName is provided then teh reportt is taken from the local machine

  .OUTPUTS
  A log file will be created under the Logs folder next to the script.
  By default the CSV report will be created in the 'Output' folder next to this script.
  By default one CSV report is generated for each ComputerName.
  CSV report format: ComputerName | Username | GivenName | Surname | StartTime | StopTime | 'Session Active (Days)' | 'Session Active (Min)' | Groups | OrganizationalUnits 
  CSV report name = ScriptName + ComputerName + DateTime

  .EXAMPLE
  .\Get-UserLogonHistory.ps1

  .EXAMPLE
  'HostName1','HostName2','HostName3' | .\Get-UserLogonHistory.ps1

  .EXAMPLE
  'HostName1','HostName2','HostName3' | .\Get-UserLogonHistory.ps1 -CSVDestinationPath .\LoginHistory.csv
  
  .EXAMPLE
  .\Get-UserLogonHistory.ps1 -ComputerName 'HostName1','HostName2'

  .EXAMPLE 
  .\Get-UserLogonHistory.ps1 -ComputerName 'HostName1','HostName2' -CSVDestinationPath .\LoginHistory.csv

#>

[CmdletBinding()]
Param (
    [Parameter(Mandatory = $false, Position = 0, ValueFromPipeline = $true)]
    [string[]]$ComputerName = $Env:COMPUTERNAME,
    [Parameter(Mandatory = $false)]
    [string]$CSVDestinationPath = '',
    [Parameter(Mandatory = $false)]
    [switch]$RSAT
)
begin {
    #Region ===============================[Variables]=============================

    # Change the global Error action to stop, so that any error will stop the script
    $ErrorActionPreference = [System.Management.Automation.ActionPreference]::Stop
    # Force script culture. This helps avoid issues with date/time.
    # To use an invariant culture, replace 'en-US' with [System.Globalization.CultureInfo]::InvariantCulture
    [System.Threading.Thread]::CurrentThread.CurrentUICulture = 'en-US'
    [System.Threading.Thread]::CurrentThread.CurrentCulture = 'en-US'
    # Get script name (without extension).
    [string]$ScriptName = (Get-Item $MyInvocation.MyCommand.Definition).BaseName
    # Generate a timestamp variable to be used for filenames.
    [string]$FileNameTimestamp = Get-Date -UFormat "%Y%m%d%H%M%S"
    # Define the log file name.
    [string]$LogFileName = $ScriptName
    # Log folder.
    [string]$LogFolder = "$PSScriptRoot\Logs"
    # Full log file path.
    [string]$LogPath = "$LogFolder\$LogFileName-$FileNameTimestamp.log"
    # Output folder.
    [string]$OutputFolder = "$PSScriptRoot\Output"
    # Define an array of external module names that need to be loaded for this script.
    [string]$RequiredModule = 'ActiveDirectory'

    #EndRegion ============================[Variables]=============================

    #Region ===============================[Functions]=============================
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
            [string]$Caller = 'Unknown',
            [Parameter(Mandatory = $false, Position = 4)]
            # Optional. Specifies the name of the message writter. Function, command or custom name. Defaults to FunctioName or unknown
            [switch]$NoConsoleOutput = $false
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
                    if (-not ($NoConsoleOutput)) {
                        if ($BackgroundColor -eq '') {
                            $CompleteMsg | Write-Host -ForegroundColor $Color
                        }
                        else {
                            $CompleteMsg | Write-Host -ForegroundColor $Color -BackgroundColor $BackgroundColor 
                        }
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
    function Set-ADPrerequisites {
        <#
     .Synopsis
      Used to check & install RSAT and the Active Directoryy module.
     .Example
     ###
     Set-ADPrerequisites
    #>
    
        [CmdletBinding()]
        Param ( )
        Begin {
            [string]${CmdletName} = $PSCmdlet.MyInvocation.MyCommand.Name
        }
        Process {
            # Script needs to run on any machine. Check for RSAT
            Write-Log "Checking RSAT" -Caller $CmdletName
            if ((Get-WindowsCapability -Name Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0 -Online -ErrorAction SilentlyContinue).state -eq 'NotPresent') {
                Write-Log "RSAT not present. Installing.." -Caller $CmdletName
                if ($RSAT) {
                    try {
                        Add-WindowsCapability -online -Name Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0 -ErrorAction 'Stop'
                        Write-Log "Successfully installed Remote Server Administration Tools." -Caller $CmdletName
                    }
                    catch {
                        $Global:ExitCode = 108
                        Write-Error2
                        throw "Error installing RSAT."
                    }
                }
                else {
                    $Global:ExitCode = 109
                    Write-Log "Remote Server Administration Tools (RSAT) is not present." -Color 'Yellow' -Caller $CmdletName
                    Write-Log "Install RSAT yourself or restart this script with ADMIN privileges and the '-RSAT' parameter to install RSAT automatically." -Color 'Yellow' -Caller $CmdletName
                    throw "RSAT is missing. Use -RSAT with ADMIN privileges."
                }
            }
            # Import ActiveDirectory module
            try {
                if (Get-Module $RequiredModule) {
                    Write-Log "'$RequiredModule' module is already available." -Caller $CmdletName
                }
                else {
                    Write-Log "Importing module '$RequiredModule'...." -Caller $CmdletName
                    Import-Module -Name $RequiredModule -Force -ErrorAction 'Stop' | Out-Null
                    Write-Log "Module '$RequiredModule' successfully imported." -Caller $CmdletName
                }
            }
            catch {
                Write-Log "Installing module '$RequiredModule'." -Caller $CmdletName
                Install-Module -Name $RequiredModule -Scope 'CurrentUser' -Force | Out-Null
                Write-Log "Importing module '$RequiredModule'." -Caller $CmdletName
                Import-Module -Name $RequiredModule -Force | Out-Null
            }
        } End {
            if (-not (Get-Module $RequiredModule)) {
                Write-Log "'$RequiredModule' still not present." -Color 'Red' -Caller 'Get-Module'
                Exit 1
            }
        }
    }
    function Get-UserActivity {
        <#
 .Synopsis
  Used to get user log-on, log-off & session active time by reading the EventLog.

 .INPUTS
  Accepts an array as pipeline input containing the computernames names.

 .OUTPUTS
  Returns an ArrayList of containg user's session info.

 .Example
   [string[]]$DeviceName | Get-UserActivity

#>
        Param (
            [Parameter(Mandatory = $false, Position = 0, ValueFromPipeline = $true)]
            [ValidateNotNull()]
            [string[]]$DeviceName = $ComputerName
        )
    
        begin {
            [string]${CmdletName} = $PSCmdlet.MyInvocation.MyCommand.Name
            # Holds SecurityGroups that were created
            #[System.Collections.ArrayList]$ResourceList = New-Object System.Collections.ArrayList($null)
            $ResourceList = [System.Collections.Generic.List[object]]::new()
            # Define all of the events to indicate session start or stop
            $sessionEvents = @(
                @{ 'Label' = 'Logon'; 'EventType' = 'SessionStart'; 'LogName' = 'Security'; 'ID' = 4624 } ## Advanced Audit Policy --> Audit Logon
                @{ 'Label' = 'Logoff'; 'EventType' = 'SessionStop'; 'LogName' = 'Security'; 'ID' = 4647 } ## Advanced Audit Policy --> Audit Logoff
                @{ 'Label' = 'Startup'; 'EventType' = 'SessionStop'; 'LogName' = 'System'; 'ID' = 6005 }
                @{ 'Label' = 'RdpSessionReconnect'; 'EventType' = 'SessionStart'; 'LogName' = 'Security'; 'ID' = 4778 } ## Advanced Audit Policy --> Audit Other Logon/Logoff Events
                @{ 'Label' = 'RdpSessionDisconnect'; 'EventType' = 'SessionStop'; 'LogName' = 'Security'; 'ID' = 4779 } ## Advanced Audit Policy --> Audit Other Logon/Logoff Events
                @{ 'Label' = 'Locked'; 'EventType' = 'SessionStop'; 'LogName' = 'Security'; 'ID' = 4800 } ## Advanced Audit Policy --> Audit Other Logon/Logoff Events
                @{ 'Label' = 'Unlocked'; 'EventType' = 'SessionStart'; 'LogName' = 'Security'; 'ID' = 4801 } ## Advanced Audit Policy --> Audit Other Logon/Logoff Events
            )
                    
            # All of the IDs that designate when user activity starts
            $sessionStartIds = ($sessionEvents | Where-Object { $_.EventType -eq 'SessionStart' }).ID
            # All of the IDs that designate when user activity stops
            $sessionStopIds = ($sessionEvents | Where-Object { $_.EventType -eq 'SessionStop' }).ID
                    
            # All of the log names we'll be querying
            $logNames = ($sessionEvents.LogName | Select-Object -Unique)
            ## All of the interesting IDs we'll be looking for
            $ids = $sessionEvents.Id
                        
            #  XPath query for the security event log to exclude System activity
            $logonXPath = "Event[System[EventID=4624]] and Event[EventData[Data[@Name='TargetDomainName'] != 'Window Manager']] and Event[EventData[Data[@Name='TargetDomainName'] != 'Font Driver Host']] and Event[EventData[Data[@Name='TargetDomainName'] != 'NT AUTHORITY']] and (Event[EventData[Data[@Name='LogonType'] = '2']] or Event[EventData[Data[@Name='LogonType'] = '10']]  or Event[EventData[Data[@Name='LogonType'] = '11']])"
            $otherXpath = 'Event[System[({0})]]' -f "EventID=$(($ids.where({ $_ -ne '4624' })) -join ' or EventID=')"
            $xPath = '({0}) or ({1})' -f $logonXPath, $otherXpath
        
        }
        process {
            # Construct OUs & SecurityGroups parameters
            Write-Log "DeviceName = '$_'" -Caller $CmdletName
            try {
                ## Query computer's event logs using the Xpath filter
                $events = Get-WinEvent -ComputerName $_ -LogName $logNames -FilterXPath $xPath
                Write-Log -Message "Found [$($events.Count)] events to look through" -Caller $CmdletName
        
                ## Set up the output object
                $output = [ordered]@{
                    'ComputerName'          = $_
                    'Username'              = $null
                    'StartTime'             = $null
                    'StartAction'           = $null
                    'StopTime'              = $null
                    'StopAction'            = $null
                    'Session Active (Days)' = $null
                    'Session Active (Min)'  = $null
                }
                
                ## Need current users because if no stop time, they're still probably logged in
                $getGimInstanceParams = @{
                    ClassName = 'Win32_ComputerSystem'
                }
                if ($_ -ne $Env:COMPUTERNAME) {
                    $getGimInstanceParams.ComputerName = $_
                    Write-Log "Querying remote device $_." -Caller $CmdletName   
                }
                $loggedInUsers = Get-CimInstance @getGimInstanceParams | Select-Object -ExpandProperty UserName |`
                    ForEach-Object { 
                    if ($_) {
                        $_.split('\')[1] 
                        Write-Log "User '$_' is logged in." -Caller $CmdletName
                    }
                    else { Write-Log 'No user is logged in.' -Caller $CmdletName }
                }
                $MostRecent = $true        
                ## Find all user start activity events and begin parsing
                $events.where({ $_.Id -in $sessionStartIds }).foreach({
                        try {
                            $logonEvtId = $_.Id
                            $output.StartAction = $sessionEvents.where({ $_.ID -eq $logonEvtId }).Label
                            $xEvt = [xml]$_.ToXml()
        
                            ## Figure out the login session ID
                            $output.Username = ($xEvt.Event.EventData.Data | Where-Object { $_.Name -eq 'TargetUserName' }).'#text'
                            $logonId = ($xEvt.Event.EventData.Data | Where-Object { $_.Name -eq 'TargetLogonId' }).'#text'
                            if (-not $logonId) {
                                $logonId = ($xEvt.Event.EventData.Data | Where-Object { $_.Name -eq 'LogonId' }).'#text'
                            }
                            $output.StartTime = $_.TimeCreated
                
                            Write-Log -Message "New session start event found: event ID [$($logonEvtId)] username [$($output.Username)] logonID [$($logonId)] time [$($output.StartTime)]" -NoConsoleOutput -Caller $CmdletName
                            ## Try to match up the user activity end event with the start event we're processing
                            ## If a user activity end event could not be found
                            if (-not ($sessionEndEvent = $Events.where({
                                            $_.TimeCreated -gt $output.StartTime -and
                                            $_.ID -in $sessionStopIds -and
                                            (([xml]$_.ToXml()).Event.EventData.Data | Where-Object { $_.Name -eq 'TargetLogonId' }).'#text' -eq $logonId
                                        })) | Select-Object -last 1) {
                                if ($output.UserName -in $loggedInUsers) {
                                    ## And the user is still logged-in And it is his most recent Start activity -> Then this is his currently active session
                                    $output.StopTime = if ($MostRecent) { Get-Date } else { $output.StartTime }
                                    $output.StopAction = if ($MostRecent) { 'StillLoggdeIn' } else { 'Unknown' }
                                }
                                else {
                                    throw "JumpToCatchBlock"
                                }
                            }
                            else {
                                ## Capture the user activity end time
                                $output.StopTime = $sessionEndEvent.TimeCreated | Select-Object -Last 1 
                                Write-Log -Message "Session stop ID is [$($sessionEndEvent.Id)]" -NoConsoleOutput -Caller $CmdletName
                                $output.StopAction = $sessionEvents.where({ $_.ID -eq $sessionEndEvent.Id }).Label
                            }
                        
                            $sessionTimespan = New-TimeSpan -Start $output.StartTime -End $output.StopTime
                            if ($sessionTimespan -eq 0) {
                                $output.StopTime = 'NotFound'
                                $output.'Session Active (Days)' = $output.'Session Active (Min)' = 'N/A' 
                            } 
                            else {
                                $output.'Session Active (Days)' = [math]::Round($sessionTimespan.TotalDays, 2) 
                                $output.'Session Active (Min)' = [math]::Round($sessionTimespan.TotalMinutes, 2)
                            }
                         
                            $output.GetEnumerator() | Sort-Object -Property Name | ForEach-Object { "$($_.Key) = $($_.Value)" | Write-Log -Caller $CmdletName }
                            $Resource = [pscustomobject]$output
                            $ResourceList.Add($Resource) | Out-Null
                            $MostRecent = $false
                        }
                        catch {
                            if ($_.Exception.Message -eq 'JumpToCatchBlock') {
                                Write-Log "Could not find a session end event for logon ID [$($logonId)]." -NoConsoleOutput -Caller $CmdletName
                            }
                            else {
                                $Global:ExitCode = 101
                                Write-Error2
                            }
                        }
                    })
            }
            catch [Microsoft.ActiveDirectory.Management.ADException] {
                $Global:ExitCode = 102
                Write-Log "Error creating $Type. ${LoggingName}$($SecurityGroupParameters.Name)" -Color 'Red' -Caller $CmdletName
                Write-Error2
                Exit $Global:ExitCode
            }    
        }
        end {
            return $ResourceList
        }
    }
    function Get-UserInfo {
        <#
     .Synopsis
      Used to retrievve the OU and SecurityGroups naames that the user belongs to.
    
     .INPUTS
      Accepts an array as pipeline input containing the User object to look for.
    
     .OUTPUTS
      Returns the input array of with the OU or SecurityGroup properties added.
    
     .Example
       $UserObj | Get-ADUserInfo
    
    #>
        Param (
            [Parameter(Mandatory = $true, Position = 0, ValueFromPipeline = $true)]
            [ValidateNotNull()]
            [System.Collections.ArrayList]$UserList
        )
        
        begin {
            [string]${CmdletName} = $PSCmdlet.MyInvocation.MyCommand.Name
            # Holds SecurityGroups that were created
            [System.Collections.ArrayList]$ResourceList = New-Object System.Collections.ArrayList($null)
        }
        process {
            # initialzie variables
            [string]$GivenName = 'N/A'
            [string]$Surname = 'N/A'
            [string]$UserOU = 'N/A'
            [string]$JoinedUserGroups = 'N/A'
            [PSCustomObject ]$CurrUser = $_
            # Log the current user object
            $_.psobject.properties | ForEach-Object { "$($_.Name) = $($_.Value)" | Write-Log -Caller $CmdletName }
            if (($_.Username) -and ($_.Username -ne '')) {
                # First check our list if we already looked this user up. Then OU & Groups properties already exits.
                try {
                    $ResourceList | ForEach-Object {
                        if ($_.Username -eq $CurrUser.Username) {
                            if (Get-Member -inputobject $_ -name "OrganizationalUnits" -Membertype Properties) {
                                # OrganizationalUnits (and Groups) property exists in the memory list
                                # No need to check for Groups, just copy the values taht we already have
                                $Surname = $_.Surname
                                $GivenName = $_.GivenName
                                $UserOU = $_.OrganizationalUnits
                                $JoinedUserGroups = $_.Groups
                                throw "JumpToCatchBlock"
                            }
                        } }
                    Write-Log "Looking for user '$($_.Username)'"  -Caller $CmdletName
                    try {
                        # get the User object for reporting
                        $UserObj = Get-ADUser -Identity $_.Username
                        Write-Log "GivenName '$($UserObj.GivenName)'." -Caller $CmdletName
                        Write-Log "Surname '$($UserObj.Surname)'." -Caller $CmdletName
                        $Surname = if ($UserObj.Surname) { $UserObj.Surname } else { 'N/A' }
                        $GivenName = if ($UserObj.GivenName) { $UserObj.GivenName } else { 'N/A' }
                        # Get user SecurrityGroup
                        $UserGroups = (Get-ADPrincipalGroupMembership -Identity $_.Username -ErrorAction Stop).name
                        Write-Log "User '$($_.Username)' group(s) $UserGroups." -Caller $CmdletName
                        $JoinedUserGroups = '"' + ($UserGroups -join '";"' ) + '"'
                        Write-Log "User '$($_.Username)' group(s) str $JoinedUserGroups." -Caller $CmdletName
                        # Get user Organizational Unit
                        $UserOUPath = ($UserObj | Select-Object @{n = 'OU'; e = { $_.DistinguishedName -replace '^.*?,(?=[A-Z]{2}=)' } }).OU
                        Write-Log "User '$($_.Username)' OU(s) $UserOUPath." -Caller $CmdletName
                        $UserOUPath = $UserOUPath -replace ',', ';'
                        if ($UserOUPath -like "*OU*") { $UserOU = $UserOUPath }                    
                    }
                    catch [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException] {
                        Write-Log "User '$($_.Username)' was not found." -Color 'Yellow' -Caller $CmdletName
                    }
                    catch [Microsoft.ActiveDirectory.Management.ADServerDownException] {
                        $Global:ExitCode = 700
                        Write-Error2
                        Exit  $Global:ExitCode
                    }
                }
                catch {
                    if ($_.Exception.Message -eq 'JumpToCatchBlock') {
                        Write-Log "User '$($CurrUser.Username)' already in the list.Skipping." -NoConsoleOutput -Caller $CmdletName
                    }
                    else {
                        $Global:ExitCode = 103
                        Write-Error2
                    }
                }
                finally {
                    $_ | Add-Member -MemberType NoteProperty -Name 'GivenName' -Value $GivenName
                    $_ | Add-Member -MemberType NoteProperty -Name 'Surname' -Value $Surname
                    $_ | Add-Member -MemberType NoteProperty -Name 'Groups' -Value $JoinedUserGroups
                    $_ | Add-Member -MemberType NoteProperty -Name 'OrganizationalUnits' -Value $UserOU
                    $ResourceList.Add($_) | Out-Null
                }
            }
            else {
                Write-Log "The Username property is empty" -Color 'Yellow' -Caller $CmdletName
                $_ | Add-Member -MemberType NoteProperty -Name 'GivenName' -Value $GivenName
                $_ | Add-Member -MemberType NoteProperty -Name 'Surname' -Value $Surname
                $_ | Add-Member -MemberType NoteProperty -Name 'Groups' -Value $JoinedUserGroups
                $_ | Add-Member -MemberType NoteProperty -Name 'OrganizationalUnits' -Value $UserOU
                $ResourceList.Add($_) | Out-Null
            }
        }
        end {
            return $ResourceList
        }
    }

    #EndRegion ============================[Functions]=============================

    # create Log folder
    If (-not (Test-Path -Path $LogFolder)) { New-Item -ItemType Directory -Path $LogFolder -Force | Out-Null }
    Write-Log "CSVDestinationPath = $CSVDestinationPath" -Caller 'Parameters'
    # Check Active Directory module
    if (Get-Module $RequiredModule) {
        Write-Log "'$RequiredModule' already present." -Caller 'Get-Module'
    }
    else {
        Set-ADPrerequisites
    }
    # Create the Output folder
    $Path = If ($CSVDestinationPath) { Split-Path $CSVDestinationPath -Parent } else { $OutputFolder }
    If (-not (Test-Path -Path $Path)) { New-Item -ItemType Directory -Path $Path -Force | Out-Null }

} process {
    $ComputerName | ForEach-Object {
        try {
            # Define the global exit code for troubleshooting.
            [int32]$Global:ExitCode = 0
            # In case of multiple computernames, append the computer name to the csv report naming
            Write-Log "ComputerName = $_" -Caller 'Parameters'
            $NewCSVDestinationPath = If ($CSVDestinationPath) { $CSVDestinationPath } else { "$OutputFolder\$LogFileName-$_-$FileNameTimestamp.csv" }
            Write-Log "New CSVDestinationPath = $NewCSVDestinationPath" -Caller 'New-CSVDestinationPath'
            $_ | Get-UserActivity | Get-UserInfo |`
                Select-Object -Property ComputerName, Username, StartTime, StartAction, StopTime, StopAction, 'Session Active (Days)', 'Session Active (Min)' |`
                Export-Csv $NewCSVDestinationPath -NoTypeInformation -Append
        }
        catch {
            $Global:ExitCode = 999
            Write-Error2
        }
        finally {
            Write-Log -Message "============ [Processing $_ ended. Exit code: $Global:ExitCode] ============" -Caller 'ComputerBlockEnd'
        }
    }
} end {
    Write-Log -Message "============ [Script ended.] ============" -Caller 'Finally'
}
