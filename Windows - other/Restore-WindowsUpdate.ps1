#requires -version 3
<#PSScriptInfo

.VERSION 1.0

.GUID 2925334f-e35c-4872-93d9-e4515620fa44

.Date 05-Dec-2022

.AUTHOR adrianbcojocaru@gmail.com

#>
<#

.SYNOPSIS
  Attempts to repair most common Windows Updates errors

.DESCRIPTION
  Restart services: Windows Update, BITS, Application Identity, Cryptographic Services
  Reset security descriptors to default for Windows Update & BITS
  Re-register Windows Update-related COMs
  Clears Windows Update cache
  Performs online image restore health
  Reset WSUS client cookie

.NOTES
  https://learn.microsoft.com/en-us/troubleshoot/windows-client/deployment/additional-resources-for-windows-update
  https://learn.microsoft.com/en-us/troubleshoot/windows-client/deployment/common-windows-update-errors?toc=%2Fwindows%2Fdeployment%2Ftoc.json&bc=%2Fwindows%2Fdeployment%2Fbreadcrumb%2Ftoc.json
  https://learn.microsoft.com/en-us/windows/deployment/update/windows-update-error-reference

#>


[string]$LogDir = "$env:ProgramData\Adrian\Baseimage\Logs\Adrian\WindowsUpdate"
[string]$LogPath = "$LogDir\WindowsUpdateRepair.log"
[string]$RegKey = "HKLM:SOFTWARE\Adrian\WindowsUpdateInfo"
[version]$ScriptVersion = '1.0.0.1'
[string]$SystemDrive = $env:SystemDrive
[int32]$Global:ExitCode = 0
[version]$TargetVer = New-Object -TypeName System.Version -ArgumentList '10.0.19044.0'

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
Function Get-WinEvent2 {
    <#
 .Synopsis
  Gets the event log from a certain provider
 .Example
  ### 
  Get-WinEvent2 -Id 20 -ProviderName 'Microsoft-Windows-WindowsUpdateClient'
#>

    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $false)]
        [ValidateNotNullorEmpty()]
        # Optional. The event Id. If not provided, it will return all the events in ProviderName param
        [Int32]$Id,
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        # Optional. Registry name.
        [string]$ProviderName
    )
    Begin {
        [string]${CmdletName} = $PSCmdlet.MyInvocation.MyCommand.Name
    }
    Process {
        Try {
            Write-Log "ProviderName = $ProviderName | ID = $Id" -Caller $CmdletName
            $hash = @{ProviderName = $ProviderName }
            if ($Id) { $hash["ID"] = $Id }
            $Events = Get-WinEvent -FilterHashtable $hash
        }
        catch {
            Write-Log -Message "<< Error >> getting events." -Caller $CmdletName
            Write-Error2
        }
    }      
    end {
        Write-Output $Events
    }
}
Function Get-FreeDiskSpace {
    <#
    .SYNOPSIS
        Retrieves the free disk space in MB on a particular drive (defaults to system drive)
    .DESCRIPTION
        Retrieves the free disk space in MB on a particular drive (defaults to system drive)
    .PARAMETER Drive
        Drive to check free disk space on
    .PARAMETER ContinueOnError
        Continue if an error is encountered. Default is: $true.
    .EXAMPLE
        Get-FreeDiskSpace -Drive 'C:'
    #>
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $false)]
        [ValidateNotNullorEmpty()]
        [string]$Drive = $envSystemDrive,
        [Parameter(Mandatory = $false)]
        [ValidateNotNullorEmpty()]
        [boolean]$ContinueOnError = $true
    )
    
    Begin {
        [string]${CmdletName} = $PSCmdlet.MyInvocation.MyCommand.Name
    }
    End {
        Try {
            Write-Log -Message "Retrieve free disk space for drive [$Drive]." -Caller $CmdletName
            $disk = Get-WmiObject -Class 'Win32_LogicalDisk' -Filter "DeviceID='$Drive'" -ErrorAction 'Stop'
            [double]$freeDiskSpace = [math]::Round($disk.FreeSpace / 1MB)
    
            Write-Log -Message "Free disk space for drive [$Drive]: [$freeDiskSpace MB]." -Caller $CmdletName
            Write-Output -InputObject $freeDiskSpace
        }
        Catch {
            Write-Log -Message "Failed to retrieve free disk space for drive [$Drive]." -Caller $CmdletName
            Write-Error2
            If (-not $ContinueOnError) {
                Throw "Failed to retrieve free disk space for drive [$Drive]: $($_.Exception.Message)"
            }
        }
    }
}
Function New-ProgressBar {
 
    [void][System.Reflection.Assembly]::LoadWithPartialName('presentationframework') 
    $syncHash = [hashtable]::Synchronized(@{})
    $newRunspace = [runspacefactory]::CreateRunspace()
    $syncHash.Runspace = $newRunspace
    $syncHash.Activity = ''
    $syncHash.PercentComplete = 0
    $newRunspace.ApartmentState = "STA" 
    $newRunspace.ThreadOptions = "ReuseThread"           
    $data = $newRunspace.Open() | Out-Null
    $newRunspace.SessionStateProxy.SetVariable("syncHash", $syncHash)           
    $PowerShellCommand = [PowerShell]::Create().AddScript({    
            [xml]$xaml = @" 
        <Window 
            xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation" 
            xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml" 
            Name="Window" Title="Progress..." WindowStartupLocation = "CenterScreen" Topmost="True"
            Width = "300" Height = "60" ShowInTaskbar = "True" ResizeMode="Noresize"> 
            <StackPanel Margin="2" x:Name="sp1">
                <TextBlock Text="Please wait..." HorizontalAlignment="Center" VerticalAlignment="Center" FontSize="18"/>
               <ProgressBar Name="ProgressBar" Height="30" IsIndeterminate="True"/>
            </StackPanel> 
        </Window> 
"@ 
            #<TextBlock Text="{Binding ElementName=ProgressBar, Path=Value, StringFormat={}{0:0}%}" HorizontalAlignment="Center" VerticalAlignment="Center" />
            $reader = (New-Object System.Xml.XmlNodeReader $xaml) 
            $syncHash.Window = [Windows.Markup.XamlReader]::Load( $reader ) 
            #===========================================================================
            # Store Form Objects In PowerShell
            #===========================================================================
            $xaml.SelectNodes("//*[@Name]") | ForEach-Object { $SyncHash."$($_.Name)" = $SyncHash.Window.FindName($_.Name) }
            $syncHash.Window.ShowInTaskbar = $false
            $syncHash.Window.WindowStyle = "None"
            $syncHash.Window.Add_MouseLeftButtonDown({
                    $syncHash.Window.DragMove()
                })
            $syncHash.Window.ShowDialog() | Out-Null 
            $syncHash.Error = $Error 

        }) 
    $PowerShellCommand.Runspace = $newRunspace 
    $data = $PowerShellCommand.BeginInvoke() 
    
    Register-ObjectEvent -InputObject $SyncHash.Runspace `
        -EventName 'AvailabilityChanged' `
        -Action { 

        if ($Sender.RunspaceAvailability -eq "Available") {
            $Sender.Closeasync()
            $Sender.Dispose()
        } 
                
    } | Out-Null

    return $syncHash

}
Function Update-ProgressBar {   
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $false)]
        [ValidateNotNullorEmpty()]
        $Hash,
        [Parameter(Mandatory = $false)]
        [ValidateNotNullorEmpty()]
        [string]$Text = ''
    )
    [string]${CmdletName} = $PSCmdlet.MyInvocation.MyCommand.Name

    Write-Log -Message "New text: $Text" -Caller $CmdletName
    try {
        $Hash.Window.Dispatcher.invoke([action] {
                $sp = $Hash.Window.FindName('sp1')
                $sp.Children[0].Text = $Text
            },
            "Normal")
    }
    catch {}
}

# .Net methods for hiding/showing the console in the background
Add-Type -Name Window -Namespace Console -MemberDefinition '
[DllImport("Kernel32.dll")]
public static extern IntPtr GetConsoleWindow();

[DllImport("user32.dll")]
public static extern bool ShowWindow(IntPtr hWnd, Int32 nCmdShow);
'
$consolePtr = [Console.Window]::GetConsoleWindow()
#0 hide
[Console.Window]::ShowWindow($consolePtr, 0)
# show UI
$Global:ProgressBar = New-ProgressBar
try {
    Write-Log -Message $env:COMPUTERNAME -Caller 'ComputerName'
    Add-Type -AssemblyName PresentationCore, PresentationFramework
    Set-RegistryKey -Key $RegKey -Name 'Step' -Value "Get-SystemData"
    Update-ProgressBar -Hash $ProgressBar -Text "Please do not restart your device`nProcess-EventLogs..."
    # create log dir
    If (-not (Test-Path -Path $LogPath)) { New-Item -ItemType Directory -Path $LogDir -Force }
    # write script version
    Set-RegistryKey -Key $RegKey -Name 'ScriptVersionRepair' -Value $ScriptVersion
    # os version
    $OSVersion = [Environment]::OSVersion.Version.ToString()
    Set-RegistryKey -Key $RegKey -Name 'OSVersion' -Value $OSVersion
    $FreeDiskSpace = Get-FreeDiskSpace -Drive $SystemDrive
    Set-RegistryKey -Key $RegKey -Name 'FreeDiskSpaceMB' -Value $FreeDiskSpace
    if ($OSVersion -ge $TargetVer) {
        Write-Log "System already on $OSVersion." -Caller 'WindowsVersion'
        $Global:ProgressBar.Window.Dispatcher.Invoke([action] { $Global:ProgressBar.Window.close() }, "Normal")
        [System.Windows.MessageBox]::Show("System already on $OSVersion.", 'OS Version up-to-date', 'OK', 'Info')
        Exit 0
    }
    # Check the last hotfix installation date
    Set-RegistryKey -Key $RegKey -Name 'Step' -Value "Get-HotFix"
    $Hotfixes = Get-HotFix
    $Hotfixes | Select-Object -Property HotFixID, InstalledBy, InstalledOn | Write-Log -Caller 'Hotfixes'
    $LastHotfix = (( $Hotfixes | Sort-Object -Property InstalledOn)[-1])
    Set-RegistryKey -Key $RegKey -Name 'HotFixDate' -Value $LastHotfix.InstalledOn.ToString("dd-MMM-yyyy")
    <#
    $CurrDate = Get-Date
    if ($LastHotfix.InstalledOn.AddDays(30) -gt $CurrDate) {
        Write-Log "System got updated recently. Exit." -Caller 'LastHotfix'
        [System.Windows.MessageBox]::Show("System updates installed less than 30 days ago.", 'OS had recent updates', 'OK', 'Info')
        #$Global:ProgressBar.Window.Dispatcher.Invoke([action] { $Global:ProgressBar.Window.close() }, "Normal")
        Exit 0
    }
    #>
    # get free disk space on C:
    Set-RegistryKey -Key $RegKey -Name 'Step' -Value "Get-WinUpdateEvent"
    $WinUpdateEvents = Get-WinEvent2 -Id 20 -ProviderName 'Microsoft-Windows-WindowsUpdateClient'
    # create counter for error codes
    $ErrorCodeCounter = @{}
    $WinUpdateEvents | ForEach-Object {
        # extract the error code and put it into the counter
        if ($_.message -match '0[xX][0-9a-fA-F]+') {
            $ErrorCodeCounter["$($Matches.Values)"] = $ErrorCodeCounter."$($Matches.Values)" + 1
        }
        Write-Log "$($_.TimeCreated) | $($_.message)" -Caller "EventLogMessage"
    }
    # write the hash into the registry
    $ErrorCodeCounter.Keys | ForEach-Object {
        Set-RegistryKey -Key "$RegKey\Errors" -Name $_ -Value $($ErrorCodeCounter[$_])
    }
    #
    Set-RegistryKey -Key $RegKey -Name 'Step' -Value "Get-WinUpdateLog"
    Get-WindowsUpdateLog -LogPath "$LogDir\WindowsUpdateLog_etl.log"
    # Run the Windows built-in update troubleshooting pack, if it exists.
    Set-RegistryKey -Key $RegKey -Name 'Step' -Value "Invoke-TroubleshootingPack"
    Update-ProgressBar -Hash $ProgressBar -Text "Please do not restart your device`nInvoke-TroubleshootingPack..."
    if (Get-Command 'Get-TroubleshootingPack' -EA SilentlyContinue) {
        Write-Log -Message "Invoking the built-in update troubleshooting pack." -Caller 'Invoke-TroubleshootingPack'
        Get-TroubleshootingPack -Path "$env:SystemRoot\diagnostics\system\WindowsUpdate" | Invoke-TroubleshootingPack -Unattended -Result "$LogDir\TroubleshootingPackResult"
    }
    ## Stop relevant services
    Set-RegistryKey -Key $RegKey -Name 'Step' -Value "Stop-Services"
    Update-ProgressBar -Hash $ProgressBar -Text "Please do not restart your device`nStop-Services..."
    Write-Log -Message "Stopping Windows Update related services." -Caller 'Stop-Services'
    'wuauserv', 'bits', 'appidsvc', 'cryptsvc' | Get-Service | Select-Object -Property DisplayName, name, status | Write-Log -Caller 'ServiceStatus'
    #if a sercive is disabled > enable it
    'wuauserv', 'bits', 'appidsvc', 'cryptsvc' | Get-Service | Stop-Service -Force | Write-Log -Caller 'StoppingServcie'
    Start-Sleep -Seconds 5
    # Remove all BITS jobs.
    Set-RegistryKey -Key $RegKey -Name 'Step' -Value "Remove-BITSJobs"
    Update-ProgressBar -Hash $ProgressBar -Text "Please do not restart your device`nRemove-BITSJobs..."
    Write-Log -Message "Removing BITS jobs." -Caller 'Remove-BITSJobs'
    $CmdOutput = (Get-BitsTransfer -Verbose | Remove-BitsTransfer -Verbose) *>&1
    if ($CmdOutput.Length -gt 0) { Write-Log -Message "$CmdOutput" -Caller 'Remove-BITSJobs' }
    Start-Sleep -Seconds 5
    # clearing the Windows Update cache
    Set-RegistryKey -Key $RegKey -Name 'Step' -Value "Clear-UpdateCache"
    Update-ProgressBar -Hash $ProgressBar -Text "Please do not restart your device`nClear-UpdateCache..."
    Write-Log -Message "Removing $env:ALLUSERSPROFILE\Application Data\Microsoft\Network\Downloader\qmgr*.dat files" -Caller 'Clear-UpdateCache'
    Remove-Item -Path "$env:ALLUSERSPROFILE\Application Data\Microsoft\Network\Downloader\qmgr*.dat" -Force -Recurse -ErrorAction SilentlyContinue
    # Backing up Windows Update cache folders
    Write-Log -Message 'Backing up Windows Update cache folders…' -Caller 'Clear-UpdateCache'
    Remove-Item -Path "$env:SYSTEMROOT\SoftwareDistribution\DataStore.bak" -Force -Recurse -ErrorAction SilentlyContinue
    Rename-Item -Path "$env:SYSTEMROOT\SoftwareDistribution\DataStore" -NewName 'DataStore.bak' -ErrorAction SilentlyContinue
    Remove-Item -Path "$env:SYSTEMROOT\SoftwareDistribution\Download.bak" -Force -Recurse -ErrorAction SilentlyContinue
    Rename-Item -Path "$env:SYSTEMROOT\SoftwareDistribution\Download" -NewName 'Download.bak' -ErrorAction SilentlyContinue
    Remove-Item -Path "$env:SYSTEMROOT\System32\catroot2.bak" -Force -Recurse -ErrorAction SilentlyContinue
    Rename-Item -Path "$env:SYSTEMROOT\System32\catroot2" -NewName 'catroot2.bak' -ErrorAction SilentlyContinue
    # Resetting the Windows Update Services to defualt settings..."
    Write-Log 'Resetting BITS and Windows Update services security descriptors…' -Caller 'BITS wuauserv'
    Set-RegistryKey -Key $RegKey -Name 'Step' -Value "Reset-UpdateSettigs"
    Update-ProgressBar -Hash $ProgressBar -Text "Please do not restart your device`nReset-UpdateSettigs..."
    $null = Start-Process -FilePath 'sc.exe' -ArgumentList 'sdset bits D:(A;CI;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCSWLOCRRC;;;IU)(A;;CCLCSWLOCRRC;;;SU)'
    $null = Start-Process -FilePath 'sc.exe' -ArgumentList 'sdset wuauserv D:(A;;CCLCSWRPLORC;;;AU)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;SY)'
    # get serice security descriptors
    Write-Log  -Message 'Re-registering all requisite DLLs…' -Caller "Reregister-COMs"
    Set-RegistryKey -Key $RegKey -Name 'Step' -Value "Reregister-COMs"
    Update-ProgressBar -Hash $ProgressBar -Text "Please do not restart your device`nReregister-COMs..."
    $dlls = @(
        'atl.dll'
        'urlmon.dll'
        'mshtml.dll'
        'shdocvw.dll'
        'browseui.dll'
        'jscript.dll'
        'vbscript.dll'
        'scrrun.dll'
        'msxml.dll'
        'msxml3.dll'
        'msxml6.dll'
        'actxprxy.dll'
        'softpub.dll'
        'wintrust.dll'
        'dssenh.dll'
        'rsaenh.dll'
        'gpkcsp.dll'
        'sccbase.dll'
        'slbcsp.dll'
        'cryptdlg.dll'
        'oleaut32.dll'
        'ole32.dll'
        'shell32.dll'
        'initpki.dll'
        'wuapi.dll'
        'wuaueng.dll'
        'wuaueng1.dll'
        'wucltui.dll'
        'wups.dll'
        'wups2.dll'
        'wuweb.dll'
        'qmgr.dll'
        'qmgrprxy.dll'
        'wucltux.dll'
        'muweb.dll'
        'wuwebv.dll'
    )
    foreach ($dll in $dlls) {
        Write-Log -Message "$env:SYSTEMROOT\System32\$dll" -Caller "Reregister-COMs"
        regsvr32.exe "$env:SYSTEMROOT\System32\$dll" /s
    }
    <##>
    # WSUS
    Write-Log 'Removing WSUS registry values…' -Caller 'WSUS'
    @('AccountDomainSid', 'PingID', 'SusClientId', 'SusClientIDValidation') | ForEach-Object {
        Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate" -Name $_ -ErrorAction Ignore
    }

    ## Restart relevant services
    Write-Log -Message "Restart Windows Update related services." -Caller 'Start-Services'
    Set-RegistryKey -Key $RegKey -Name 'Step' -Value "Start-Services"
    Update-ProgressBar -Hash $ProgressBar -Text "Please do not restart your device`nStart-Services..."
    'wuauserv', 'bits', 'appidsvc', 'cryptsvc' | Get-Service | Start-Service | Write-Log -Caller 'Start-Services'
    'wuauserv', 'bits', 'appidsvc', 'cryptsvc' | Get-Service | Select-Object -Property DisplayName, name, status | Write-Log -Caller 'ServiceStatus'

    # set network settings to default
    #Write-Log 'et network settings to default'
    #$null = netsh winsock reset
    #$null = netsh winhttp reset proxy

    Write-Log "Starting component cleanup.." -Caller 'Start-ComponentCleanup'
    Set-RegistryKey -Key $RegKey -Name 'Step' -Value "Start-ComponentCleanup"
    Update-ProgressBar -Hash $ProgressBar -Text "Please do not restart your device`nStart-ComponentCleanup..."
    $startcomponentcleanup = Start-Job -ScriptBlock { Start-Process 'dism.exe' -WindowStyle Hidden -ArgumentList "/online /cleanup-image /startcomponentcleanup /LogPath:$using:LogDir\DISM_ComponentCleanup.log" | Wait-Process } | Wait-Job -Timeout 1200
    if ($startcomponentcleanup.State -ne 'Completed') { $Global:ExitCode = 104; Throw 'startcomponentcleanup job still running. Exiting.' }

    Write-Log "Starting restore health.." -Caller 'Restore-Health'
    Set-RegistryKey -Key $RegKey -Name 'Step' -Value 'Restore-Health'
    Update-ProgressBar -Hash $ProgressBar -Text "Please do not restart your device`nStart-RestoreHealth..."
    $Restorehealth = Start-Job -ScriptBlock { Start-Process 'dism.exe' -WindowStyle Hidden -ArgumentList "/online /cleanup-image /Restorehealth /LogPath:$using:LogDir\DISM_RestoreHealth.log" | Wait-Process } | Wait-Job -Timeout 1200
    if ($Restorehealth.State -ne 'Completed') { $Global:ExitCode = 103; Throw 'RestoreHealth job still running. Exiting.' }
    # $SFCOutput = (&"$env:SystemRoot\system32\sfc.exe" /scannow) *>&1
    Copy-Item -Path "$env:SystemRoot\Logs\CBS\CBS.log" -Destination "$LogDir\"
    #give dism a second chance
    [int]$dismCount = 0
    Set-RegistryKey -Key $RegKey -Name 'Step' -Value 'Wait-Dism'
    while ((Get-Process 'dism' -ErrorAction SilentlyContinue) -and ($dismCount -lt 720)) { $dismCount += 1; Start-Sleep -Seconds 10 }
    # Reset computer group membership
    Write-Log 'Resetting WSUS client cookie..' -Caller 'Reset-WUSCokkie'
    Set-RegistryKey -Key $RegKey -Name 'Step' -Value "Reset-WUSCokkie"
    Update-ProgressBar -Hash $ProgressBar -Text "Please do not restart your device`nReset-WUSCokkie..."
    $USOClient = Start-Job -ScriptBlock { Start-Process 'USOClient.exe' -ArgumentList 'RefreshSettings' -PassThru | Wait-Process } | Wait-Job -Timeout 600
    if ($USOClient.State -ne 'Completed') { $Global:ExitCode = 102; Write-Log 'USOClient.exe job still running. Exiting.' }
    $wuauclt = Start-Job -ScriptBlock { Start-Process 'wuauclt.exe' -ArgumentList '/resetauthorization' | Wait-Process } | Wait-Job -Timeout 600
    if ($wuauclt.State -ne 'Completed') { $Global:ExitCode = 101; Throw 'wuauclt.exe job still running. Exiting.' }
    Set-RegistryKey -Key $RegKey -Name 'Step' -Value "CompletedSuccessfully"
    Start-Sleep =seconds 10
    Write-Log 'Done. Displaying the restart pop-up.' -Caller 'Done'
    $Global:ProgressBar.Window.Dispatcher.Invoke([action] { $Global:ProgressBar.Window.close() }, "Normal")
    [System.Windows.MessageBox]::Show("Please restart your device.", 'Please restart', 'OK', 'Info')
    # Write-Log 'Initiating update cycle…'
    # (New-Object -ComObject Microsoft.Update.AutoUpdate).DetectNow()
}
catch {
    Write-Error2
    $ProgressBar.Window.Dispatcher.invoke([action] { $ProgressBar.Window.Close() })
}
finally {
    Set-RegistryKey -Key "$RegKey" -Name 'ExitCode' -Value $Global:ExitCode
    Write-Log "Script exit code: [$Global:ExitCode]"
    Write-Log "=====================[CONSOLE Script Ended]====================="
    #$ProgressBar.Window.Dispatcher.invoke([action] { $ProgressBar.Window.Close() })
    Exit 0
}
#>s