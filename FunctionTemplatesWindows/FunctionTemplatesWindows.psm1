# FunctionTemplatesWindows
# Version: $version$
# Changeset: $sha$

Function Write-Log {
    <#
 .Synopsis
  Used to write a message to the log file and/or the console.

 .Example
   ### Call Write-Log with -Caller (optional parameter).
   Write-Log -Message "Your message goes here" -Caller "Caller Name goes here"

 .Example
   ### Call Write-Log
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

function Write-Header {
    <#
 .Synopsis
  Used to write the log file header. No Parameters.
 .Example
 ###
   Write-Header
#>

    [CmdletBinding()]
    Param ()
    Begin {
        if ($DisableLogging) { return }
        [string]$LogDate = (Get-Date -Format 'MM-dd-yyyy').ToString()
        [string]$LogTime = (Get-Date -Format 'HH\:mm\:ss.fff').ToString()
        [string]${CmdletName} = $PSCmdlet.MyInvocation.MyCommand.Name
        If (-not (Test-Path -LiteralPath $LogDir -PathType 'Container')) {
            Try {
                $null = New-Item -Path $LogDir -Type 'Directory' -Force -ErrorAction 'Stop'
            }
            Catch {
                Write-Error -Message  "[$LogDate $LogTime] [${CmdletName}] :: Failed to create the log directory [$LogDir]" -Category WriteError
            }
        }
        Write-Log -Message "###################### $($(Get-PSCallStack).ScriptName) | Version: $ScriptVersion ######################" -Caller $CmdletName
    }
    Process {
        if ($DisableLogging) { return }
        [psobject]$UserInfo = [Security.Principal.WindowsIdentity]::GetCurrent()
        [psobject]$AllOSInfo = Get-WmiObject -Class 'Win32_OperatingSystem' -ErrorAction 'SilentlyContinue'
        [psobject]$OSInfo = $AllOSInfo | Select-Object -Property *
        [psobject]$PSInfo = $($PSVersionTable.PSVersion)
        $PSBitness = if ([Environment]::Is64BitProcess) { "64-bit" } else { "32-bit" }
        Write-Log -Message "$($OSInfo.Caption) | $($OSInfo.Version) | $($OSInfo.OSArchitecture) " -Caller $CmdletName
        Write-Log -Message "Input Locale = $($OSInfo.Locale); OSLanguage = $($OSInfo.OSLanguage); OSType = $($OSInfo.OSType); OSProductSuite = $($OSInfo.OSProductSuite)" -Caller $CmdletName
        Write-Log -Message "Powershell Runs as: $($UserInfo.Name)" -Caller $CmdletName
        Write-Log -Message "Powershell Version: $PSInfo; $PSBitness" -Caller $CmdletName
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
Function Set-RegistryKey {
    <#
 .Synopsis
  Used to create registry keys and/or write/update registry values.
 .Example
  ### 
  Set-RegistryKey -Key "HKLM:SOFTWARE\MilkyWay" -Name "EstimatedRunTime" -Value "8" -Type "String"
 .Example
  ### If you are certain that the registry key already exists.
 Set-RegistryKey -Key "HKLM:SOFTWARE\MilkyWay" -Name "EstimatedRunTime" -Value "8" -Type "String" -CreateNoKey
 .Example
  ### Set the (Default) value.
 Set-RegistryKey -Key "HKLM:SOFTWARE\MilkyWay" -Value "8"
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
                    Write-Error
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
                $null = Set-Item -LiteralPath $key -Value $Value -ErrorAction 'Stop'
            }
        }
        catch {
            Write-Log -Message "<< Error >>  writting [$key] [$Name = $Value]. See the -CreateKey parameter." -Caller ${CmdletName}
            Write-Error
        }
    }      
    end {}
}

Function Get-RegistryKey {
    <#
 .Synopsis
  If the specified Key is empty ==> returns the key path [string]
  If the specified Key not found ==> returns $false [bool]
  If the Name parameter is specified ==> Returns the value of the registry specified by -Name. [string]
                                     ==>> Returns ValueNotFound if the registry does not exist. [string]
  If no Name parameter is specified ==> Returns all the <Name - Value> pair under -Key.[PSCustomObject]
 .Example
  ### Get the value for a registry named "EstimatedChargeRemaining" under "HKLM:SOFTWARE\MilkyWay" as [string]
  Get-RegistryKey -Key "HKLM:SOFTWARE\MilkyWay" -Name "EstimatedChargeRemaining"
 .Example
  ### Get the <Name - Value> pair under Key "HKLM:SOFTWARE\MilkyWay" as a [PSCustomObject].
  Get-RegistryKey -Key "HKLM:SOFTWARE\MilkyWay"
 .Example
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
        [string]$Name
    )
    Begin {
        [string]${CmdletName} = $PSCmdlet.MyInvocation.MyCommand.Name
    }
    Process {
        Try {
            # Key does not exist ?
            If (Test-Path -LiteralPath $key -ErrorAction 'Stop') {
                [PSCustomObject]$regKeyValue = Get-ItemProperty $Key -ErrorAction 'Stop'
                [int32]$regKeyValuePropertyCount = ($regKeyValue | Measure-Object).Count

                # Is key empty ?
                If ($regKeyValuePropertyCount -eq 0) {
                    $regKeyValue = $Key
                    Write-Log -Message "Registry key [$key] is empty" -Caller ${CmdletName}
                    # Do we return a single value ?
                }
                elseif ($PSBoundParameters.ContainsKey('Name')) {
                    $regKeyValue = if ([bool]($regKeyValue.PSobject.Properties.name -match $Name)) { $regKeyValue.$Name } else { "ValueNotFound" }
                    Write-Log -Message "Get registry key [$key] value [$Name] = [$regKeyValue]." -Caller ${CmdletName}
                    # No reg name ==>> Return all values in the current key - exclude child keys
                }
                else {
                    Write-Log -Message "Get all values from key [$key]." -Caller ${CmdletName}
                    $regKeyValue.PSObject.Properties | ForEach-Object {
                        "$($_.Name) = $($_.Value)" | Write-Log -Caller ${CmdletName}
                    }
                    $regKeyValue | Add-Member -NotePropertyName Key -NotePropertyValue $key
                }
            }
            else { [bool]$regKeyValue = $false; Write-Log -Message "<< Error >> Registry key not found: [$key]" -Caller ${CmdletName} }
        }
        Catch [System.Management.Automation.ItemNotFoundException] {
            Write-Log -Message "<< Error >> Registry key still missing: [$key]" -Caller ${CmdletName} 
            Write-Error
        }
        Catch {
            Write-Log -Message "<< Error >> Registry key [$key] value [$Name]" -Caller ${CmdletName} 
            Write-Error
        }
        Write-Output -InputObject ($regKeyValue)
    }
}

Function Copy-Files {
    <#
 .Synopsis
  Used to copy one or more files.
 .Example
  ### 
  Copy-Files -Path "C:\MilkyWay\Source\*" -Destination "C:\MilkyWay\Destination\" -StopOnError
  Copy-Files -Path "C:\MilkyWay\Source\TestFolder\" -Destination "C:\MilkyWay\Destination\"
 .Example
   ### 
  Copy-Files -Path "C:\MilkyWay\SourceFile.txt" -Destination "C:\MilkyWay\Destination\"
  Copy-Files -Path "C:\MilkyWay\SourceFile.txt" -Destination "C:\MilkyWay\Destination\DestinationFile.txt" -StopOnError
#>
	[CmdletBinding()]
	Param (
		[Parameter(Mandatory = $true)]
		[ValidateNotNullorEmpty()]
        # Mandatory. Source path.
		[string[]]$Path,
		[Parameter(Mandatory = $true)]
		[ValidateNotNullorEmpty()]
        # Mandatory. Destination path.
		[string]$Destination,
        [Parameter(Mandatory=$false)]
		[ValidateNotNullOrEmpty()]
        # Optional. If specified teh fucntion will stop when the first error is encountered.
		[switch]$StopOnError
	)
	Begin {
		[string]${CmdletName} = $PSCmdlet.MyInvocation.MyCommand.Name
		Write-Log -Message "$Path $Destination" -Caller $CmdletName
	}
	Process {
		Try {
			If ((!([IO.Path]::HasExtension($Destination))) -and (!(Test-Path -Path $Destination -PathType 'Container'))) {
				Write-Log -Message "Destination folder does not exist, creating destination folder $Destination." -Caller ${CmdletName}
				New-Item -Path $Destination -Type 'Directory' -Force -ErrorAction 'Stop'
			}
            If ($StopOnError) {
                $null = Copy-Item -Path $Path -Destination $Destination -Force -Recurse -ErrorAction 'Stop'
            }
            Else {
                $null = Copy-Item -Path $Path -Destination $Destination -Force -Recurse -ErrorAction 'SilentlyContinue' -ErrorVariable '+ErrorCopyFiles'
            }
			Write-Log -Message "Copy file(s) recursively in path [$Path] to destination [$Destination]." -Caller ${CmdletName}
            if ($ErrorCopyFiles) {
                Write-Log -Message "ErrorRecordNumber = $($ErrorCopyFiles.Count)" -Caller $CmdletName
                Write-Log -Message "The following errors were encontered while copy file(s) from [$Path] to [$Destination]"
                Write-Error -ErrorRecord $ErrorCopyFiles
            }
			Copy-Item -Path $Path -Destination $Destination -Force -Recurse -ErrorAction 'Stop'
		}
		Catch {
			Write-Log -Message "Failed to copy file(s) in path [$Path] to destination $Destination." -Caller ${CmdletName}
            Write-Error
            Throw "Failed to copy file [$path]: $($_.Exception.Message)"
		}
	}
    End {
        # Write-Log "End" -Caller $CmdletName -Color Green
    }
}
Function Remove-Folder {
    <#
 .Synopsis
  Used to delete a folder.
 .Example
  ### 
  Remove-Folder -Path "C:\MilkyWay\Source"
#>
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $true, Position = 0)]
        [ValidateNotNullorEmpty()]
        # Mandatory. Folder to be deleted.
        [string[]]$Path
    )
    Begin {
        [string]${CmdletName} = $PSCmdlet.MyInvocation.MyCommand.Name
        Write-Log -Message "$Path" -Caller $CmdletName
    }
    Process {
        Try {
            If (-not (Test-Path -Path $Path -PathType 'Container')) {
                Write-Log -Message "Folder $Path does not exist." -Caller ${CmdletName}
            }
            else {
                Write-Log -Message "Removing $Path." -Caller ${CmdletName}
                Remove-Item -Path $Path -Force -Recurse -ErrorAction 'SilentlyContinue' -ErrorVariable '+ErrorRemoveFolder'
            }
            if ($ErrorRemoveFolder) {
                Write-Log -Message "ErrorRecordNumber = $($ErrorRemoveFolder.Count)" -Caller $CmdletName
                Write-Log -Message "The following errors were encontered while removing folder [$Path]"
                Write-Error -ErrorRecord $ErrorRemoveFolder
            }
        }
        Catch {
            Write-Log -Message "Failed to remove folder $Path." -Caller ${CmdletName}
            Write-Error
        }
    }
    End {}
}
Function Remove-File {
    <#
 .Synopsis
  Used to delete one or more files.
 .Example
  ### 
  Remove-File -Path "C:\MilkyWay\Source\FileToBeDeleted.txt"
  Get-ChildItem -Path "c:\MilkyWay\Source" -File | Remove-File
  Get-ChildItem -Path "c:\MilkyWay\Source" -File | Remove-File -StopOnError
#>
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $true, Position = 0, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [ValidateNotNullorEmpty()]
        [Alias('FullName')]
        # Mandatory. File to be deleted.
        [string[]]$Path,
        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        # Optional. If specified, the fucntion will stop when the first error is encountered.
        [switch]$StopOnError
    )
    Begin {
        [string]${CmdletName} = $PSCmdlet.MyInvocation.MyCommand.Name
    }
    Process {
        Try {
            If (-not (Test-Path -Path $Path -PathType 'Leaf')) {
                Write-Log -Message "$Path file does not exist." -Caller ${CmdletName}
            }
            Write-Log -Message "Removing $Path." -Caller ${CmdletName}
            If ($StopOnError) {
                $null = Remove-Item -Path $Path -Force -ErrorAction 'Stop'
            }
            Else {
                $null = Remove-Item -Path $Path -Force -ErrorAction 'SilentlyContinue' -ErrorVariable '+ErrorRemoveFiles'
            }
            if ($ErrorRemoveFiles) {
                Write-Log -Message "ErrorRecordNumber = $($ErrorRemoveFolder.Count)" -Caller $CmdletName
                Write-Log -Message "The following errors were encontered while removing folder [$Path]"
                Write-Error -ErrorRecord $ErrorRemoveFiles
            }
        }
        Catch {
            Write-Log -Message "Failed to remove file $Path." -Caller ${CmdletName}
            Write-Error
            Throw "Failed to delete file [$path]: $($_.Exception.Message)"
        }
    }
    End {}
}

function Get-EasterEastern {
    <#
 .Example
  Get-EasterEastern 2090
#>
    Param (
        [Parameter(Mandatory = $true)]
        [int]$Year
    )
    $a = $Year % 4
    $b = $Year % 7
    $c = $Year % 19
    $d = ((19 * $c) + 15) % 30
    $e1 = - $d
    $e = ((2 * $a) + (4 * $b) + $e1 + 34) % 7
    $month = [Math]::Floor(($d + $e + 114) / 31)
    $day = (($d + $e + 114) % 31) + 1
    $cal = New-Object -TypeName System.Globalization.JulianCalendar
    New-Object -TypeName System.DateTime -ArgumentList $Year, $month, $day, $cal
}

Export-ModuleMember -Function Write-Log
Export-ModuleMember -Function Write-Header
Export-ModuleMember -Function Set-RegistryKey
Export-ModuleMember -Function Get-RegistryKey
Export-ModuleMember -Function Copy-Files
Export-ModuleMember -Function Remove-Folder
Export-ModuleMember -Function Remove-File
Export-ModuleMember -Function Write-Error2
Export-ModuleMember -Function Get-EasterEastern
