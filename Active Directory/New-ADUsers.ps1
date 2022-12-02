<#PSScriptInfo

.VERSION 1.0

.GUID 31abe8bd-bf88-4723-981d-57075585332d

.Date 03-Dec-2022

.AUTHOR adrianbcojocaru@gmail.com

#>

#Requires -RunAsAdministrator

<#
  .SYNOPSIS
  Creates Active Directory users based on a CSV file.

  .DESCRIPTION
  CSV Header format: GivenName | Surname | Role
  'GivenName' and 'Surname' columns cannot have empty values.
  If a user already exists, it will be skipped.

  .PARAMETER CSVPath
  [string] Specifies the path to the CSV input file.

  .PARAMETER Password
  [string] User's Password. Default value: AtosP@ssw0rd

  .PARAMETER RSAT
  [switch] Used to install the Remote Server Administration Tools. Internet connection required.

  .OUTPUTS
  A log file will be created under the Logs folder next to the script.
  A CSV file containg the users creation status will be generated under the Output folder next to the script.

  .EXAMPLE
  .\New-ADUsers.ps1 -CSVPath ".\users.csv"

#>
[CmdletBinding()]
Param (
    [Parameter(Mandatory = $true)]
    [string]$CSVPath = '',
    [Parameter(Mandatory = $false)]
    [switch]$RSAT
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

function Add-ADUser {
    <#

 .Synopsis
  Used to Create a new Active Directory user if it doesn't already exists.

 .INPUTS
  Accepts a [ArrayList] as pipeline input.
  Each [PSCustomObject] needs to have GivenName and Surname properties representing the user.

 .OUTPUTS
  Returns the same [ArrayList] plus the 'Result' property.
  Result = Added - the user was created in AD
  Result = Skipped - the user already exists in AD

 .Example
   [ArrayList]$Users | Add-ADUser

#>
    Param (
        [Parameter(Mandatory = $true, Position = 0, ValueFromPipeline = $true)]
        [ValidateNotNull()]
        # Mandatory. Specifies the message string.
        [PSCustomObject[]]$Users
    )
    
    begin {
        [string]${CmdletName} = $PSCmdlet.MyInvocation.MyCommand.Name
        # Define the list that holds the New-ADUser operation status <Added> <AlreadyExists> <IncompleteData>
        [System.Collections.ArrayList]$Users_status = New-Object System.Collections.ArrayList($null)
        # Define function result for each input object
        [string]$Result = 'N/A'
    }
    process {
        Write-Log "GivenName = '$($_.GivenName)' Surname = '$($_.Surname)'" -Caller $CmdletName
        # check for empty values
        if (($_.GivenName) -and ($_.Surname)) {
            # parameters for New-ADUser
            $NewADUserParameters = @{
                Name                  = "$($_.GivenName).$($_.Surname)"
                GivenName             = $_.GivenName
                Surname               = $_.Surname
                #AccountPassword       = ConvertTo-SecureString $Password -AsPlainText -Force
                AccountPassword       = $Password
                Enabled               = $true
                ChangePasswordAtLogon = $True
            }
            try {
                $NewADUserParameters.GetEnumerator() | Sort-Object -Property Name | ForEach-Object { "$($_.Key) = $($_.Value)" | Write-Log -Caller $CmdletName }
                New-ADUser @NewADUserParameters
                Write-Log "User '$($NewADUserParameters.Name)' successfully created." -Color 'Green' -Caller $CmdletName
                $Result = 'Added'
            }
            # AD server not found terminating error
            catch [Microsoft.ActiveDirectory.Management.ADServerDownException] {
                $Global:ExitCode = 101
                $Result = 'ADServerDown'
                Write-Error2
                Exit  $Global:ExitCode
            }
            # Password Complexity terminating error
            catch [Microsoft.ActiveDirectory.Management.ADPasswordComplexityException] {
                Switch ($_.Exception.Message) {
                    "The password does not meet the length, complexity, or history requirement of the domain." {
                        $Global:ExitCode = 102
                        Write-Error2
                        $Result = 'PasswordRequirements'
                        Exit $Global:ExitCode
                    }
                    "The specified account already exists" {
                        Write-Log "User '$($NewADUserParameters.Name)' already exists.." -Color "Yellow" -Caller $CmdletName
                        $Result = 'AlreadyExists.'
                    }
                    default {
                        $Global:ExitCode = 103
                        Write-Log 'Other' -Caller $CmdletName
                        Write-Log $_.Exception.Message -Color 'Red' -Caller $CmdletName
                    }
                }
            }
            # Account already exists warning
            catch [Microsoft.ActiveDirectory.Management.ADIdentityAlreadyExistsException] {
                Write-Log "User '$($NewADUserParameters.Name)' already exists." -Color "Yellow" -Caller $CmdletName
                $Result = 'AlreadyExists'
            }
            # Other non-terminating errors
            catch [Microsoft.ActiveDirectory.Management.ADException] {
                $Global:ExitCode = 300
                Write-Log "Error creating user $($NewADUserParameters.Name):" -Color 'Red' -Caller $CmdletName
                $Result = 'OtherError'
                Write-Error2
            }
            finally {
                $_ | Add-Member -MemberType NoteProperty -Name 'Result' -Value $Result
                $Users_status.Add($_) | Out-Null
            }
        }
        else {
            Write-Log "$($_.GivenName).$($_.Surname) user data incomplete." -Color "DarkGray" -Caller $CmdletName
            $_ | Add-Member -MemberType NoteProperty -Name 'Result' -Value 'IncompleteData'
            $Users_status.Add($_) | Out-Null
        }
    }
    end {
        return $Users_status
    }
}
#EndRegion ============================[Functions]=============================

try {
    # Create Log & Output folders
    If (-not (Test-Path -Path $LogFolder)) { New-Item -ItemType Directory -Path $LogFolder -Force | Out-Null }
    If (-not (Test-Path -Path $OutputFolder)) { New-Item -ItemType Directory -Path $OutputFolder -Force | Out-Null }
    Write-Log "=====================================================" -Color 'Yellow' -Caller 'PasswordPrompt'
    Write-Log "Please provide a password for the newly created users" -Color 'Yellow' -Caller 'PasswordPrompt'
    Write-Log "=====================================================" -Color 'Yellow' -Caller 'PasswordPrompt'
    $Password = Read-Host -AsSecureString "AccountPassword"
    Write-Log "CSVPath = $CSVPath | RSAT = $RSAT" -Caller 'Parameters'

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

    # Pipe the object collection to Add-ADUser and export the output (Result 'Added' or 'Skipped') to -results- csv
    $CSVUsers | Add-ADUser | Export-Csv "$OutputFolder\$ScriptName-results-$FileNameTimestamp.csv" -NoTypeInformation
}
catch {
    Write-Error2
}
finally {
    Write-Log -Message "============ [Script ended. Exit code: $Global:ExitCode] ============" -Caller 'Finally'
}