<#PSScriptInfo

.VERSION 1.0

.GUID e0b23673-e266-4f42-9a93-c056f092232d

.AUTHOR adrianbcojocaru@gmail.com

#>

#Requires -RunAsAdministrator

<#
  .SYNOPSIS
  Moves Active Directory users to an OU & group.

  .DESCRIPTION
  Moves all Active Directory users defined by [GivenName] & [Surname] inside the input CSV file to an OU & Security Group specified by the [Role] column.
  The OUs and Security Groups will be created if they don't exist.

  .PARAMETER CSVPath
  [string] Specifies the path to the CSV input file.

  .PARAMETER RSAT
  [switch] Used to install the Remote Server Administration Tools

  .PARAMETER OUPath
  [string] Path for the Organizational Unit

  .PARAMETER GroupPath
  [string] Path to the Security Group

  .OUTPUTS
  A log file will be created under the Logs folder next to the script.
  A CSV file containg the operation result will be generated under the Output folder next to the script.

  .EXAMPLE
  .\Move-ADUsers.ps1 -CSVPath .\users.csv
  Default: Creates the OU at the top domain level & the Security Group under 'Users' container.
  They will be named according to the 'Role' column values.

  .EXAMPLE
  .\Move-ADUsers.ps1 -CSVPath .\users.csv -OUPath 'OU=Test,DC=CORP,DC=CONTOSO,DC=COM' -GroupPath 'OU=Test,DC=CORP,DC=CONTOSO,DC=COM'
  The Organizational Unit and Security Group are created under the paths specified by the '-OUPath' & '-GroupPath' parameters.
  (the Path, excluding the Name)
  They will be named according to the 'Role' column values.

#>

[CmdletBinding()]
Param (
    [Parameter(Mandatory = $false)]
    [string]$CSVPath = '',
    [Parameter(Mandatory = $false)]
    [switch]$RSAT,
    [Parameter(Mandatory = $false)]
    [string]$OUPath,
    [Parameter(Mandatory = $false)]
    [string]$GroupPath
)

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
# Define the global exit code for troubleshooting.
[int32]$Global:ExitCode = 0
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
        if ((Get-WindowsCapability -Name Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0 -Online).state -eq 'NotPresent') {
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
function New-ADResource {
    <#
 .Synopsis
  Used to create OUs or SecurityGroups if they don't already exist.

 .INPUTS
  Accepts an array as pipeline input containing the OU/Group names.
  OUs and SecurityGroups will be created under $ResourcePath
  OUs and SecurityGroups will have the same name as the current element of the array.

 .OUTPUTS
  Returns an array of created & existing OUs or SecurityGroups.

 .Example
   [string[]]$names | New-ADResource -Type 'OU' -ResourcePath $OUPath 
   [string[]]$names | New-ADResource -Type 'SecurityGroup' -ResourcePath $SecurityGroupPath

#>
    Param (
        [Parameter(Mandatory = $true, Position = 0, ValueFromPipeline = $true)]
        [ValidateNotNull()]
        [string[]]$Names,
        [Parameter(Mandatory = $true, Position = 1)]
        [ValidateSet('OU', 'SecurityGroup')]
        [string]$Type,
        [Parameter(Mandatory = $false, Position = 2)]
        [string]$ResourcePath
    )
    
    begin {
        [string]${CmdletName} = $PSCmdlet.MyInvocation.MyCommand.Name
        # Holds SecurityGroups that were created
        [System.Collections.ArrayList]$ResourceList = New-Object System.Collections.ArrayList($null)
    }
    process {
        # Construct OUs & SecurityGroups parameters
        Write-Log "ResourcePath = '$ResourcePath' Name = '$_' Type '$Type'" -Caller $CmdletName
        if ($Type -eq 'SecurityGroup') {
            $Parameters = @{
                Name           = $_
                SamAccountName = $_
                GroupCategory  = 'Security'
                DisplayName    = $_
                GroupScope     = 'Global'
                Path           = if ($ResourcePath) { $ResourcePath } else { 'CN=Users,DC=' + $env:userdnsdomain.Replace('.', ',DC=') }
                ErrorAction    = 'Stop'
            }
            $LoggingName = "CN="
        }
        else {
            # OU
            $Parameters = @{
                Name                            = $_
                Path                            = if ($ResourcePath) { $ResourcePath } else { 'DC=' + $env:userdnsdomain.Replace('.', ',DC=') }
                ProtectedFromAccidentalDeletion = $false
                ErrorAction                     = 'Stop'
            }
            $LoggingName = "OU="
            
        }
        # Try creating the resource & handle already exists exception types
        try {
            $Parameters.GetEnumerator() | Sort-Object -Property Name | ForEach-Object { "$($_.Key) = $($_.Value)" | Write-Log -Caller $CmdletName }
            if ($Type -eq 'OU') { New-ADOrganizationalUnit @Parameters } else { New-ADGroup @Parameters }
            Write-Log "${LoggingName}$($Parameters.Name),$($Parameters.Path) successfully created." -Color 'Green' -Caller $CmdletName
        }
        catch [Microsoft.ActiveDirectory.Management.ADException] {
            Switch ($_.Exception.Message) {
                # Check if Security Group/OU already exists
                "The specified group already exists" {
                    Write-Log "${LoggingName}$($Parameters.Name),$($Parameters.Path) group already exists." -Color 'Yellow' -Caller $CmdletName
                }
                "An attempt was made to add an object to the directory with a name that is already in use" {
                    Write-Log "${LoggingName}$($Parameters.Name),$($Parameters.Path) An attempt was made to add an object to the directory with a name that is already in use." -Color 'Yellow' -Caller $CmdletName
                }
                default {
                    $Global:ExitCode = 102
                    Write-Log "Error creating $Type. ${LoggingName}$($SecurityGroupParameters.Name)" -Color 'Red' -Caller $CmdletName
                    Write-Error2
                    Exit $Global:ExitCode
                }
            }
        }
        finally {
            $ResourceList.Add($Parameters.Name) | Out-Null
            #$ResourceList.Add("${LoggingName}$($Parameters.Name),$($Parameters.Path)") | Out-Null
        }
    }
    end {
        return $ResourceList
    }
}
function Confirm-CSV {
    <#
     .Synopsis
      Used to validate a CSV file.
     .Example
     ###
     Confirm-CSV -Path users.csv
    #>
    
    [CmdletBinding()]
    Param ([Parameter(Mandatory = $true, Position = 0)]
        [ValidateNotNull()]
        [string]$Path
    )
    Begin {
        [string]${CmdletName} = $PSCmdlet.MyInvocation.MyCommand.Name
    }
    End {
        # Script needs to run on any machine. Check for RSAT
        Write-Log "Checking $Path" -Caller $CmdletName
        try {
            $csv = Import-Csv -Path $Path -ErrorAction Stop
            # Check headers
            if (($csv | Get-Member -Name GivenName) -and ($csv | Get-Member -Name Surname) -and ($csv | Get-Member -Name Role)) {
                $csv | Foreach-Object {
                    #$_.psobject.Properties.Value
                    if (-not(($_ | Where-Object -Property GivenName) -and ($_ | Where-Object -Property Surname))) {
                        throw "Invalid CSV file. GivenName & Surname must not be empty.'$($_.GivenName)','$($_.Surname)'"
                    }   
                }
            }
            else {
                throw 'Invalid CSV file. One or more of the required headers are not present.'
            }
        
            Write-Log "The CSV file is valid $Path" -Color 'Green' -Caller $CmdletName
        }
        catch {
            $Global:ExitCode = 800
            Write-Log $_.Exception.Message -Color 'Red' -Caller $CmdletName
            Exit $Global:ExitCode
        }
        return $csv
    }
}
function Set-ADUser {
    <#
 .Synopsis
  Used to move a user to an OU or add it to a group if not already there.

 .INPUTS
  Accepts an array of objects as pipeline input containing User GivenName & Surname properties.
  DestinationOUPath - string
  DestinationGroupName - string

 .OUTPUTS
  Returns the input array + existing OU & Groups properties.

 .Example
   [string[]]$names | Set-ADUser -DestinationOUPath "OUToBeMovedIn" -DestinationGroupName "GroupToBeMovedIn"
   [string[]]$names | Set-ADUser -DestinationGroupName "GroupToBeMovedIn"

#>
    Param (
        [Parameter(Mandatory = $true, Position = 0, ValueFromPipeline = $true)]
        [ValidateNotNull()]
        [string[]]$Names,
        [Parameter(Mandatory = $false, Position = 1)]
        [ValidateNotNull()]
        [string]$DestinationGroupName,
        [Parameter(Mandatory = $false, Position = 2)]
        [ValidateNotNull()]
        [string]$DestinationOUName,
        [Parameter(Mandatory = $false, Position = 3)]
        [string]$DestinationOUPath
    )
    
    begin {
        [string]${CmdletName} = $PSCmdlet.MyInvocation.MyCommand.Name
        # Holds reporting that were created
        [System.Collections.ArrayList]$ResourceList = New-Object System.Collections.ArrayList($null)
    }
    process {
        # Construct OUs & SecurityGroups parameters
        if (-not ($DestinationGroupName)) { $DGN = $_.Role }
        if (-not ($DestinationOUName)) { $DOUN = $_.Role }
        Write-Log "GivenName = '$($_.GivenName)' Surname = '$($_.Surname)' Role = '$($_.Role)' DestinationGroupName = '$DGN'"  -Caller $CmdletName
        Write-Log "DestinationOUPath = '$DestinationOUPath' DestinationOUName = '$DOUN'" -Caller $CmdletName
        # Add data for reporting - Group & OU columns
        try {
            # Get user info
            #$CurrentUser = Get-ADUser -Filter "Surname -eq '$($_.Surname)'"
            $CurrentUser = Get-ADUser -Filter "GivenName -eq '$($_.GivenName)' -and Surname -eq '$($_.Surname)'"
            # Go ahead only if we find exactly 1 user
            if ($CurrentUser) {
                $UserCount = $CurrentUser.count
                if ($UserCount -ne 1) {
                    Write-Log "$UserCount users found that match the criteria" -Color 'DarkMagenta' -BackgroundColor 'Yellow' -Caller $CmdletName
                    $CurrentUser.DistinguishedName | Write-Log -Color 'DarkMagenta' -BackgroundColor 'Yellow' -Caller $CmdletName
                    $_ | Add-Member -MemberType NoteProperty -Name 'OrganizationalUnit' -Value 'MultiUserFound'
                    $_ | Add-Member -MemberType NoteProperty -Name 'SecurityGroup' -Value 'MultiUserFound'
                }
                else {
                    # Get destination group info
                    $Group = Get-ADGroup -Identity $DGN
                    # Add user to group
                    Add-ADGroupMember -Identity $Group -Members $CurrentUser
                    Write-Log "Added user '$($CurrentUser.DistinguishedName)' to Group '$($Group.DistinguishedName)'." -Color 'Green' -Caller $CmdletName
                    $_ | Add-Member -MemberType NoteProperty -Name 'OrganizationalUnit' -Value $DGN
                    # Add user to OU
                    # Multiple OUs can have the same name - make sure we get the correct one
                    if (-not($DestinationOUPath)) { $DestinationOUPath = 'DC=' + $env:userdnsdomain.Replace('.', ',DC=') }
                    Write-Log "Target OU 'OU=$DOUN,$DestinationOUPath'." -Caller $CmdletName
                    # move user to OU
                    Move-ADObject -Identity $CurrentUser -TargetPath "OU=$DOUN,$DestinationOUPath"
                    Write-Log "Moved user '$($CurrentUser.DistinguishedName)' to Organizational Unit 'OU=$DOUN,$DestinationOUPath'." -Color 'Green' -Caller $CmdletName
                    $_ | Add-Member -MemberType NoteProperty -Name 'SecurityGroup' -Value $DOUN
                }
            }
            else {
                $_ | Add-Member -MemberType NoteProperty -Name 'OrganizationalUnit' -Value 'NoUserFound'
                $_ | Add-Member -MemberType NoteProperty -Name 'SecurityGroup' -Value 'NoUserFound'
                Write-Log "No user found that matches the above criteria" -Color 'Yellow' -Caller $CmdletName
            }
        }
        catch {
            $_ | Add-Member -MemberType NoteProperty -Name 'OrganizationalUnit' -Value 'Error'
            $_ | Add-Member -MemberType NoteProperty -Name 'SecurityGroup' -Value 'Error'
            Write-Log "Error setting user '$($CurrentUser.DistinguishedName)'" -Color 'Red' -Caller $CmdletName
            Write-Error2
        }
        finally {
            $ResourceList.Add($_) | Out-Null
        }
    }
    end {
        return $ResourceList
    }
}

#EndRegion ============================[Functions]=============================

try {
    # Create Log & Output folders
    If (-not (Test-Path -Path $LogFolder)) { New-Item -ItemType Directory -Path $LogFolder -Force | Out-Null }
    If (-not (Test-Path -Path $OutputFolder)) { New-Item -ItemType Directory -Path $OutputFolder -Force | Out-Null }
    Write-Log "CSVPath = $CSVPath | RSAT = $RSAT" -Caller 'Parameters'
    Write-Log "OUPath = $OUPath | GroupPath = $GroupPath" -Caller 'Parameters'
    # OU Path and Group Path cannot be the same
    if (($OUPath) -and ($OUPath -eq $GroupPath)) { throw 'JumpToCatchBlock' }

    # Check Active Directory module
    if (Get-Module $RequiredModule) {
        Write-Log "'$RequiredModule' already present." -Caller 'Get-Module'
    }
    else {
        Set-ADPrerequisites
    }

    # Validate CSV
    $CSVUsers = Confirm-CSV -Path $CSVPath
    #$CSVName = (Get-Item $CSVPath).BaseName
    # Get OU/SecurityGroup names
    $Containers = $CSVUsers | Select-Object -Property 'Role' -Unique
    # Create OUs & Security Groups
    ($Containers).Role | New-ADResource -Type 'OU' -ResourcePath $OUPath | New-ADResource -Type 'SecurityGroup' -ResourcePath $GroupPath
    
    # Move Users to the OU & Security Group defined by the Role header and export the reults
    #$CSVUsers | Move-ADUser | Export-Csv "$OutputFolder\$CSVName-results-$FileNameTimestamp.csv" -NoTypeInformation
    #  if (-not($OUPath)) { $Path = 'DC=' + $env:userdnsdomain.Replace('.', ',DC=') } else {}
    $CSVUsers | Set-ADUser -DestinationOUPath $OUPath | Export-Csv "$OutputFolder\$ScriptName-results-$FileNameTimestamp.csv" -NoTypeInformation
}
catch {
    if ($_.Exception.Message -eq 'JumpToCatchBlock') {
        Write-Log 'OU Path and Group Path cannot be the same!' -Color 'Red' -Caller 'Pre-Check'
        $Global:ExitCode = 200 
    }
    else {
        Write-Error2
        $Global:ExitCode = 101
    }
}
finally {
    Write-Log -Message "============ [Script ended. Exit code: $Global:ExitCode] ============" -Caller 'Finally'
}


# function check-csv; header, null givenname/surname - handle null role in script?
# $csvContent = Import-Csv -Path "$CSVPath" -Header @("Date","HostName", "InfoType","IPAddress","Subnet")
# https://stackoverflow.com/questions/53231838/check-csv-for-blank-fields-and-write-output-if-exist-blank
# https://stackoverflow.com/questions/37996293/finding-duplicate-lines-in-a-csv-file
