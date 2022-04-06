# Force script culture. This helps avoid issues with date/time.
# To use an invariant culture, replace 'en-US' with [System.Globalization.CultureInfo]::InvariantCulture
Add-Type -AssemblyName PresentationFramework
[System.Threading.Thread]::CurrentThread.CurrentUICulture = 'en-US'
[System.Threading.Thread]::CurrentThread.CurrentCulture = 'en-US'
# Get script name (without extension).
[string]$ScriptName = (Get-Item $MyInvocation.MyCommand.Definition).BaseName
# Generate a timestamp variable to be used for filenames.
[string]$FileNameTimestamp = Get-Date -UFormat "%Y%m%d%H%M%S"
# Define the log file name.
[string]$LogFileName = $ScriptName
# Log folder.
[string]$LogFolder = "$PSScriptRoot\Logs\$ScriptName"
# Full log file path.
[string]$LogFile = "$LogFolder\$FileNameTimestamp-$LogFileName.log"
# How many log files to keep? Anything over this number will be deleted, starting with the oldest files.
[int32]$LogsFilesToKeep = 30
# Output file name.
[string]$OutputFileName = $ScriptName
# Output folder.
[string]$OutputFolder = "$PSScriptRoot\Output\$ScriptName"
# Full output file path.
[string]$OutputFile = "$OutputFolder\$FileNameTimestamp-$OutputFileName.xlsx"
# How many log files to keep?
[int32]$OutputFilesToKeep = 30
# Data folder.
[string]$DataFolder = "$PSScriptRoot\Data"
# Define the global exit code.
[int32]$Global:ExitCode = 0
# Define the GlobalOutput variable. To be used when output needs to be controlled.
# Add any output data to this variable. It will be written to the output in the 'finally' block.
[array]$Global:Output = @()
# Define an array of external module names that need to be loaded for this script.
# Leave it empty if no external modules are required.
[array]$RequiredModules = @(
)
#EndRegion === Template generic variables ===

# =================================
# === Script specific variables ===
# =================================
$ErrorActionPreference = [System.Management.Automation.ActionPreference]::Stop
$TextNewLine = [System.Environment]::NewLine
[string]$SCCMPrimary = 'xxxxxxxxxxxxx'
[string]$TextBoxLog = "$LogFolder\$FileNameTimestamp-$LogFileName-OutputText.log"

#$IsVPNon = $false
#EndRegion ============================[Variables]=============================

#Region ===============================[Functions]=============================
function Write-Log {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true, Position = 0, ValueFromPipeline = $true)]
        [string]
        $Message,
        [Parameter(Mandatory = $False, Position = 1)]
        [int32]
        $Severity = 1,
        [Parameter(Mandatory = $False, Position = 2)]
        [boolean]
        $WriteHost = $true
    )
    switch ($Severity) {
        1 { $Level = 'Info:' }
        2 { $Level = 'Warning:' }
        3 { $Level = 'Error:' }
        Default { $Level = '-----' }
    }
    $TimeStamp = (Get-Date).ToString("yyyy-MM-dd HH:mm K")
    if ($null -eq $LogFile) {
        [string]$ScriptName = [io.path]::GetFileNameWithoutExtension($MyInvocation.ScriptName)
        $LogFilePath = "$PSScriptRoot\$ScriptName.log"
    }
    else {
        $LogFilePath = $LogFile
    }
    $Entry = "$TimeStamp $Level $Message"
    if ($LogFilePath) {
        try {
            Add-Content $LogFilePath -Value $Entry -EA 'Stop'
        }
        catch {
            Write-Warning "Unable to access log file [$LogFilePath]"
        }
    }
    else {
        Write-Warning "Log file is missing."
    }
    # If the "$WriteHost" variable is set, output the log data to console also.
    if ($WriteHost) {
        # Only output using color options if running in a host which supports colors.
        If ($Host.UI.RawUI.ForegroundColor) {
            Switch ($Severity) {
                3 { Write-Host -Object $Entry -ForegroundColor 'Red' -BackgroundColor 'Black' }
                2 { Write-Host -Object $Entry -ForegroundColor 'Yellow' -BackgroundColor 'Black' }
                Default { Write-Host -Object $Entry }
            }
        }
        # If executing "powershell.exe -File <filename>.ps1 > log.txt",
        # then all the Write-Host calls are converted to Write-Output calls so that they are included in the text log.
        Else {
            Write-Output -InputObject $Entry
        }
    }
}
function Initialize-Script {
    # If log folder doesn't exist, create it.
    # Else, remove all but the newest "$LogsFilesToKeep" log files.
    If (!(Test-Path -Path $LogFolder)) {
        New-Item -Path $LogFolder -ItemType Directory -Force | Out-Null
    }
    else {
        Get-ChildItem -Path $LogFolder |
        Where-Object { !$_.PsIsContainer } |
        Sort-Object -Property 'CreationTime' -Descending |
        Select-Object -Skip $LogsFilesToKeep |
        Remove-Item -Force -EA 'SilentlyContinue'
    }
    # If Output folder doesn't exist, create it.
    # Else, remove all but the newest "$OutputFilesToKeep" output files.
    If (! (Test-Path -Path $OutputFolder)) {
        New-Item -Path $OutputFolder -ItemType Directory -Force | Out-Null
    }
    else {
        Get-ChildItem -Path $OutputFolder |
        Where-Object { !$_.PsIsContainer } |
        Sort-Object -Property 'CreationTime' -Descending |
        Select-Object -Skip $OutputFilesToKeep |
        Remove-Item -Force -EA 'SilentlyContinue'
    }
    # Make sure the data folder exists.
    if (!(Test-Path -Path $DataFolder)) {
        New-Item -Path $DataFolder -ItemType 'Directory' -Force | Out-Null
    }
}
function Initialize-ExternalModules {
    if ($IM -and ($RequiredModules.Count -gt 0)) {
        # Make sure the network connection uses TLS1.2. Required by PSGallery connection.
        Write-Log "Settings HTTPS security protocol to TLS 1.2."
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        Write-Log "Installing / Upgrading NuGet."
        $null = Install-PackageProvider -Name 'NuGet' -Scope 'AllUsers' -Force
        Write-Log "Setting PSGallery as a trusted repository."
        $null = Set-PSRepository -Name 'PSGallery' -InstallationPolicy 'Trusted'
        Write-Log "Setting execution policy to 'Bypass' to be able to import modules."
        $null = Set-ExecutionPolicy -ExecutionPolicy 'Bypass' -Scope 'CurrentUser' -Force -Confirm:$false
        # Go through the list of required modules and try to install them if missing.
        foreach ($ModuleName in $RequiredModules) {
            try {
                Import-Module -Name $ModuleName -Force -EA 'Stop'
            }
            catch {
                Write-Log "Installing module '$ModuleName'."
                $null = Install-Module -Name $ModuleName -Scope 'AllUsers' -Force
                Write-Log "Importing module '$ModuleName'."
                $null = Import-Module -Name $ModuleName -Force
            }
        }
    }
    else {
        # Try to import each module to check if all is OK.
        foreach ($ModuleName in $RequiredModules) {
            try {
                Write-Log "Importing module '$ModuleName'."
                Import-Module -Name $ModuleName -Force -ErrorAction Stop
            }
            catch {
                Write-Log "Module '$ModuleName' is missing." 2
                Write-Log "Please restart this script with ADMIN privileges and the '-IM' parameter to install the missing module." 2
                exit 1
            }
        }
    }
}
function Update-CheckBox {
    <#
.SYNOPSIS
   Update CheckBox - Text Color & IsChecked properties

.PARAMETER Box
   Name of the Box
   Mandatory - [String]

.PARAMETER  DataSource
   Status - Check Pass or Fail
   Mandatory - [string]

.EXAMPLE
   Update-Box -Box "Box1" -DataSource "Item 1"
   #>
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory = $true, Position = 0)]$Name,
        [Parameter(Mandatory = $true, Position = 1)]
        [ValidateSet('Pass', 'Fail', 'InProgress', 'N')]
        [string]$Status
    )
    #$Name.Items.Clear()
    try {
        if ($Status -eq 'Pass') {
            $Name.Foreground = 'Green'
        }
        elseif ($Status -eq 'Fail' ) {
            $Name.Foreground = 'Red'
        }
        elseif ($Status -eq 'InProgress' ) {
            $Name.Foreground = 'Orange'
        }
        else {
            $Name.Foreground = 'Black'
        }
        Write-Log "$Name = $Status"
    }
    catch {
        Write-Log "Error updating CheckName $Name with Status $Status" -Severity 3
    }
}

function Add-Text {
    <#
.SYNOPSIS
   Write string into a TextBox

.PARAMETER Text
   Text to be written
   Mandatory - [String]
   #>
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory = $false, Position = 0)] [string]$Text,
        [Parameter(Mandatory = $false, Position = 1)] [switch]$Clear,
        [Parameter(Mandatory = $false, Position = 2)] [switch]$NoBullet,
        [Parameter(Mandatory = $false, Position = 3)] [switch]$RemoveLastLine
    )
    try {

        if ($Clear) {
            Write-Log "TextBox.Clear()"
            $TextResults.Clear()
        }
        if (-not ($RemoveLastLine)) { Write-Log "TextBox.Add $Text" }
        if ($NoBullet) {
            $TextResults.Text = $TextResults.Text + $TextNewLine + "$Text" 
        }
        elseif ($RemoveLastLine) {
            $TextResults.Text = $TextResults.Text.Remove($TextResults.Text.LastIndexOf([System.Environment]::Newline))
            Write-Log "Removing last line in the TextBox"
        }
        else {
            $TextResults.Text = $TextResults.Text + $TextNewLine + "-- $Text"
        }
        
    }
    catch {
        Write-Log "Error updating TextBox $Text" -Severity 3
    }
}

function Update-Gui {
    # Basically WinForms Application.DoEvents()
    $Window.Dispatcher.Invoke([Windows.Threading.DispatcherPriority]::Background, [action] {})
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
            Name="Window" Title="Progress..." WindowStartupLocation = "CenterScreen" 
            Width = "300" Height = "40" ShowInTaskbar = "True" ResizeMode="Noresize"> 
            <StackPanel Margin="2">
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
#EndRegion ============================[Functions]=============================

#Region ===============================[EXEC]==================================

try {


    # Clear the terminal.
    Clear-Host
    # Prepare the output folders.
    Initialize-Script
    # Call the 'Manage external modules" script block.
    Initialize-ExternalModules
    # Write Log header.
    Write-Log "================================================================" 0
    Write-Log "Starting Script [$ScriptName]."
    Write-Log "Hostname: $env:COMPUTERNAME"
    Write-Log "Powershell version: $($PSVersionTable.PSVersion -join ('.'))"
    Write-Log "Running as user: $([System.Security.Principal.WindowsIdentity]::GetCurrent().Name)"
    Write-Log "================================================================" 0

    #! === MAIN CODE START ===
    [ xml]$xaml = @"
    <Window
    xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
    xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
    x:Name="Window"
    FontSize="18" Title="SCCM checks"
    Height="650" Width="700" ShowInTaskbar = "True">
    <Grid>
        <Grid.ColumnDefinitions>
            <ColumnDefinition Width="20"/>
            <ColumnDefinition Width="*"/>
            <ColumnDefinition Width="20"/>
            <ColumnDefinition Width="*"/>
            <ColumnDefinition Width="20"/>
            <ColumnDefinition Width="*"/>
            <ColumnDefinition Width="20"/>
        </Grid.ColumnDefinitions>
        <Grid.RowDefinitions>
            <RowDefinition Height="20"/>
            <RowDefinition Height="auto"/>
            <RowDefinition Height="auto"/>
            <RowDefinition Height="auto"/>
            <RowDefinition Height="auto"/>
            <RowDefinition Height="auto"/>
            <RowDefinition Height="auto"/>
            <RowDefinition Height="auto"/>
            <RowDefinition Height="auto"/>
            <RowDefinition Height="20"/>
            <RowDefinition Height="auto"/>
            <RowDefinition Height="20"/>
            <RowDefinition Height="*"/>
            <RowDefinition Height="20"/>
        </Grid.RowDefinitions>

        <CheckBox Grid.Column="1" Grid.Row="1"
                   Content="company VPN" Margin="0,0,0,5" HorizontalAlignment="Left"
                   x:Name="CheckVPN" IsChecked="True" IsEnabled="False"/>
        <CheckBox Grid.Column="1" Grid.Row="2"
                  Content="Access to Primary" Margin="0,0,0,5" HorizontalAlignment="Left"
                 x:Name="CheckPrimary"  IsChecked="True" IsEnabled="False"/>
        <CheckBox Grid.Column="1" Grid.Row="3"
                   Content="Access to PDC" Margin="0,0,0,5" HorizontalAlignment="Left"
                  x:Name="CheckPDC" IsChecked="True" IsEnabled="False"/>
        <CheckBox Grid.Column="1" Grid.Row="4"
                  Content="SCCM client status" Margin="0,0,0,5" HorizontalAlignment="Left"
                 x:Name="CheckSCCMClient" IsChecked="True" IsEnabled="False"/>
        <CheckBox Grid.Column="1" Grid.Row="5"
                   Content="Client Script Status" Margin="0,0,0,5" HorizontalAlignment="Left"
                  x:Name="CheckScript"  IsChecked="True" IsEnabled="False"/>
        <CheckBox Grid.Column="1" Grid.Row="6"
                 Content="Management Point" Margin="0,0,0,5" HorizontalAlignment="Left"
                x:Name="CheckMP"  IsChecked="True" IsEnabled="False"/>
        <CheckBox Grid.Column="1" Grid.Row="7"
                Content="Start Gpupdate" Margin="0,0,0,5" HorizontalAlignment="Left"
               x:Name="CheckGPUpdate"  IsChecked="True" IsEnabled="False"/>
        <Button Grid.Column="1" Grid.Row="10"  Grid.ColumnSpan="1"
                x:Name="ButtonP1" Content="Start Phase One" Margin="0,0,0,5"/>
        <TextBox Grid.Column="1" Grid.Row="12"  Grid.ColumnSpan="5" FontFamily="Consolas" FontSize="18"
                 HorizontalAlignment="Stretch" VerticalAlignment="Stretch"
                 TextWrapping="Wrap" Text=""
                 AcceptsReturn="True" VerticalScrollBarVisibility="Visible"
                 x:Name="TextResults"/>
                
        <CheckBox Grid.Column="3" Grid.Row="1"
                 Content="Internet access" Margin="0,0,0,5" HorizontalAlignment="Left"
                 x:Name="CheckInternetP2" IsChecked="True" IsEnabled="False"/>
        <CheckBox Grid.Column="3" Grid.Row="2"
                Content="IBCM access" Margin="0,0,0,5" HorizontalAlignment="Left"
                x:Name="CheckIBCMP2"  IsChecked="True" IsEnabled="False"/>
        <Button Grid.Column="3" Grid.Row="10"  Grid.ColumnSpan="1" IsEnabled="True"
               x:Name="ButtonP2" Content="Start Phase Two" Margin="0,0,0,5"/>

        <CheckBox Grid.Column="5" Grid.Row="1"
                Content="Internet access" Margin="0,0,0,5" HorizontalAlignment="Left"
                x:Name="CheckInternetP3" IsChecked="True" IsEnabled="False"/>
        <CheckBox Grid.Column="5" Grid.Row="2"
                Content="IBCM access" Margin="0,0,0,5" HorizontalAlignment="Left"
                x:Name="CheckIBCMP3"  IsChecked="True" IsEnabled="False"/>
        <Button Grid.Column="5" Grid.Row="10"  Grid.ColumnSpan="1" IsEnabled="True"
                x:Name="ButtonP3" Content="Start Phase Three" Margin="0,0,0,5"/>
    </Grid>
</Window>
"@

    # Reading WPF Content
    #Read XAML
    #  try {
    #      $Window = [Windows.Markup.XamlReader]::Load($reader)
    #  }
    #  catch {
    #      Write-Log -Message "Unable to load Windows.Markup.XamlReader. Double-check syntax and ensure .net is installed." -Severity 3
    #      Throw "Unable to load Windows.Markup.XamlReader. Double-check syntax and ensure .net is installed."
    #  }
    #--- Load Window Objects
    $reader = (New-Object System.Xml.XmlNodeReader $xaml)
    $Window = [Windows.Markup.XamlReader]::Load( $reader )
    $CheckVPN = $Window.FindName('CheckVPN')
    $CheckSCCMClient = $Window.FindName('CheckSCCMClient')
    $CheckPDC = $Window.FindName('CheckPDC')
    $CheckPrimary = $Window.FindName('CheckPrimary')
    $CheckGPUpdate = $Window.FindName('CheckGPUpdate')
    $CheckScript = $Window.FindName('CheckScript')
    $CheckMP = $Window.FindName('CheckMP')
    $ButtonP1 = $Window.FindName('ButtonP1')

    $CheckInternetP2 = $Window.FindName('CheckInternetP2')
    $CheckIBCMP2 = $Window.FindName('CheckIBCMP2')
    $ButtonP2 = $Window.FindName('ButtonP2')

    $CheckInternetP3 = $Window.FindName('CheckInternetP3')
    $CheckIBCMP3 = $Window.FindName('CheckIBCMP3')
    $ButtonP3 = $Window.FindName('ButtonP3')


    $Window.WindowStartupLocation = "CenterScreen"
    $TextResults = $Window.FindName('TextResults')
    function Get-SCCMLogInfo {
        [CmdletBinding()]
        Param (
            [Parameter(Mandatory = $true, Position = 0)]
            [string]$StringToSearch,
            [Parameter(Mandatory = $true, Position = 1)]
            [string]$LogPath
        )
        # Check the function name to be used in the log report.
        [string]$functionName = $MyInvocation.MyCommand
        # Log the function startup.
        Write-Log -Severity 1 -Message "=== function [$functionName] started ==="
        $LogName = Split-Path $LogPath -Leaf
        Write-Log -Message "Scanning $LogName for status messages."
        # Default the LogMsgTime variable to the start of the Unix Epoch.
        $LogMsgTime = get-date "1970.01.01"
        # Scan the update log and search for issues.
        #[string]$LogPath = $env:SystemRoot + '\CCM\Logs\CcmEval.log'
        #[string]$StringToSearch = 'company.com and is accessible'
        $ReturnObject = New-Object PSObject
        $ReturnObject | Add-Member -NotePropertyName  MatchingLogLine -NotePropertyValue 0
        $ReturnObject | Add-Member -NotePropertyName  LogMsgTime -NotePropertyValue 0
        if (Test-Path -Path $LogPath) {
            [string]$MatchingLogLine = (Select-String -Path $LogPath -Pattern $StringToSearch -SimpleMatch | Select-Object -Last 1).Line
            if (!([string]::IsNullOrWhiteSpace($MatchingLogLine))) {
                $LogRegex = '\<\!\[LOG\[(?<Message>.*)?\]LOG\]\!\>\<time=\"(?<Time>.+)(?<TZAdjust>[+|-])' +
                '(?<TZOffset>\d{2,3})\"\s+date=\"(?<Date>.+)?\"\s+component=\"(?<Component>.+)?\"\s+context="(?<Context>.*)' +
                '?\"\s+type=\"(?<Type>\d)?\"\s+thread=\"(?<TID>\d+)?\"\s+file=\"(?<Reference>.+)?\"\>'
                $MatchingLogLine -match $LogRegex | Out-Null
                Write-Log -Message "Matching log line was:`n$MatchingLogLine"
                $ReturnObject | Add-Member -NotePropertyName MatchingLogLine -NotePropertyValue $MatchingLogLine -Force
                # $MsgIndexStart = $MatchingLogLine.IndexOf('LOG[') + 4
                # $MsgIndexEnd = $MatchingLogLine.IndexOf(']LOG') - 7
                try {
                    $LogMsgTime = [DateTime]::ParseExact($("$($matches.date) $($matches.time)"), "MM-dd-yyyy HH:mm:ss.fff", $null)
                    Write-Log -Severity 1 -Message "The last successful operation timestamp: [$LogMsgTime]"
                    $ReturnObject | Add-Member -NotePropertyName LogMsgTime -NotePropertyValue $LogMsgTime -Force
                }
                catch {
                    Write-Log -Severity 2 -Message "Cannot get date and time from the log entry."
                    Write-Log -Severity 1 -Message "Error was: $($_.exception.Message)"
                }
                # $TextToDispaly = "[$LogMsgTime] " + $MatchingLogLine.Substring($MsgIndexStart, $MsgIndexEnd)
            }
            else {
                # $TextToDispaly = "No MP found!"
                Write-Log -Severity 2 -Message "No '$StringToSearch' message found in the log file [$LogPath]."
            }

            # Add-Text -Text $TextToDispaly
        }
        # Write the result to log and to output
        Write-Log -Severity 1 -Message "=== function [$functionName] ended ==="
        Write-Log -Severity 0 -Message "----------------------------------------------------------------"
        return $ReturnObject
    }

    function Test-ServerConnection {
        param (
            [Parameter(Mandatory = $true)]
            [string]$Server,
            [Parameter(Mandatory = $false)]
            [int32]$Port 
        )    
        #
        $ServerAddress = switch ($Server) {
            'xxxx.com' { "1.1.1.1" }
            'google.com' { "8.8.8.8" }
            $SCCMPrimary { "0.0.0.0" }
            Default { $Server }
        }
        Write-Log "Trying WMI first."
        Write-Log "Testing connection to [$Server] actual address [$ServerAddress] on port: [$Port]"
        $ConnectionETA = (Get-Date).AddMinutes(1).ToShortTimeString()
        Add-Text -Text "Checking $Server. ETA: $ConnectionETA"
        Update-Gui
        if ((Get-CimInstance -Class Win32_PingStatus -Filter ("Address='$ServerAddress' and Timeout=20000")).StatusCode -eq 0) {
            Add-Text -RemoveLastLine
            Add-Text -Text "$Server is reachable."
            return $true
        }       
        else {
            Write-Log "WMI method unsuccessful. Trying Test-NetConnection."
            $ProgressPreference = 'SilentlyContinue'
            if ($Port -ne 0) {
                Write-Log "Testing connection to [$Server] actual address [$ServerAddress] on [$Port]"
                [scriptblock]$SB = {
                    Param ([string]$ServerAddress, [int32]$Port)               
                    $Output = (Test-NetConnection -ComputerName "$ServerAddress" -Port $Port -WarningAction:SilentlyContinue).TcpTestSucceeded
                    Write-Output $Output
                }
            }
            else {
                Write-Log -Message "Testing connection to [$Server] actual address [$ServerAddress]."
                [scriptblock]$SB = {
                    Param ([string]$ServerAddress, [int32]$Port)               
                    $Output = (Test-NetConnection -ComputerName "$ServerAddress" -WarningAction:SilentlyContinue).TcpTestSucceeded
                    Write-Output $Output
                }
            }
            $job = Start-Job -Name 'AJob' -ScriptBlock $SB -ArgumentList ($ServerAddress, $Port) | Get-Job | Wait-Job -Timeout 20
            if ($job.count -ne 0) { Receive-Job $job -OutVariable JobRes | Out-Null }
            if ($JobRes) {
                Add-Text -Text "$Server is reachable."
                return $true
            }
            else {
                Add-Text -Text "$Server is not reachable."
                return $false
            }
        }
    }

    function Get-companyVPNConfig {
        $companyNetCfg = Get-NetIPConfiguration | Where-Object { $_.IPv4Address.IPAddress -like "1.1*" }
        if ($companyNetCfg.count -eq 0) {
            $companyVPN = $false
            Write-Log "company VPN is off."
        }
        else {
            $companyVPN = $true
            Write-Log "company VPN is on."
        }
        return $companyVPN
    }

    function Start-PhaseOne {
        [CmdletBinding()]
        Param
        (
            [Parameter(Mandatory = $false, Position = 0)] [switch]$SkipVPN
        )
        # company VPN
        if (!($SkipVPN)) {
            if (Get-companyVPNConfig) {
                Add-Text "company VPN connected. Starting Phase 1." -Clear -NoBullet
                Update-CheckBox $CheckVPN -Status 'Pass'
            }
            else {
                Add-Text "company VPN seems to be disconnected.`n" -Clear -NoBullet
                Add-Text "Please connect to company VPN and Start Phase One."
                Update-CheckBox $CheckVPN -Status 'Fail'
                $TextResults.Text | out-file $TextBoxLog -Append
                return
            }
        }
        Update-Gui
        # Access to SCCM primary
        Update-CheckBox -Name $CheckPrimary -Status 'InProgress'
        Update-Gui
        if (Test-ServerConnection $SCCMPrimary) { Update-CheckBox $CheckPrimary -Status 'Pass' } else { Update-CheckBox $CheckPrimary -Status 'Fail' }
        Update-Gui
        # Access to PDC
        $PDCconnection = $false
        Update-CheckBox -Name $CheckPDC -Status 'InProgress'
        Update-Gui
        try {
            $logonserver = $env:logonserver -replace '\\', ''
            $logonserver, $env:COMPUTERNAME | Write-Log
            if ($logonserver -ne $env:COMPUTERNAME) {
                if (Test-ServerConnection $logonserver) { Update-CheckBox $CheckPDC -Status 'Pass'; $PDCconnection = $true } else { Update-CheckBox $CheckPDC -Status 'Fail' }
            }
            else {
                Update-CheckBox -Name $CheckPDC -Status 'Fail'
                Add-Text -Text "Not connected to any Domain Controller."
            }
            #[System.Collections.ArrayList]$DomainInfo = Get-CimInstance Win32_NTDomain | Select-Object -Property DnsForestName, DomainControllerAddress, DomainControllerName
            #$DomainInfo | Write-Log
        }
        catch {
            Add-Text -Text "Failed to retrieve domain info."
        }
        Update-Gui
        # SCCM client status
        Update-CheckBox -Name $CheckSCCMClient -Status 'InProgress'
        Update-Gui
        try {
            Write-Log "Checking servcice: CcmExec"
            $ServiceStatus = (Get-Service -ServiceName 'ccmexec').Status.ToString().ToLower()
            if ($ServiceStatus -eq 'running') {
                Update-CheckBox -Name $CheckSCCMClient -Status 'Pass'
            }
            else {
                Update-CheckBox -Name $CheckSCCMClient -Status 'Fail'
            }
            Add-Text -Text "The SCCM service is $ServiceStatus."
        }
        catch {
            Update-CheckBox -Name $CheckSCCMClient -Status 'Fail'
            Add-Text -Text "The SCCM service not found."
        }
        Update-Gui
        # Client Check script status
        Update-CheckBox -Name $CheckScript -Status 'InProgress'
        Update-Gui
        if (Test-Path "$env:windir\Logs\ClientCheck\ClientCheck.log") {
            [datetime]$LastWriteTime = (Get-Item "$env:windir\Logs\ClientCheck\ClientCheck.log").LastWriteTime
            [string]$strLastWriteTime = $LastWriteTime.ToString()
            [datetime]$ApproxDate = (Get-Date).AddDays(-2)
            if ($LastWriteTime.Date -ge $ApproxDate.Date) {
                Update-CheckBox -Name $CheckScript -Status Pass
            }
            else {
                Update-CheckBox -Name $CheckScript -Status Fail
            }
            Add-Text -Text "Client Check script ran on $strLastWriteTime."
        }
        else {
            Add-Text -Text "$env:windir\Logs\ClientCheck\ClientCheck.log not found"
            Update-CheckBox -Name $CheckScript -Status 'Fail'
        }
        Update-Gui
        # get CcmEval.log info
        Update-CheckBox -Name $CheckMP -Status 'InProgress'
        Update-Gui
        $CcmEvalMPAccess = Get-SCCMLogInfo -StringToSearch 'company.com and is accessible' -LogPath "$env:SystemRoot\CCM\Logs\CcmEval.log"
        $CcmEvalMPHealth = Get-SCCMLogInfo -StringToSearch 'Updating MDM_ConfigSetting.ClientHealthStatus with value 7' -LogPath "$env:SystemRoot\CCM\Logs\CcmEval.log"
        $CurrDate = Get-Date
        if ($CcmEvalMPAccess.MatchingLogLine -ne 0) {
            if ($CcmEvalMPAccess.LogMsgTime -ne 0) {
                [datetime]$LogDT = $CcmEvalMPAccess.LogMsgTime
                if ($LogDT.AddDays(3) -ge $CurrDate) {
                    Add-Text "Management Point check was successful."
                    Update-CheckBox -Name $CheckMP -Status 'Pass' 
                }
                else {
                    Add-Text "Last MP successful check: $LogDT."
                    Update-CheckBox -Name $CheckMP -Status 'Fail' 
                }
            }
            else {
                Add-Text "Successful MP check date not found" 
                Update-CheckBox -Name $CheckMP -Status 'Fail'
            }
            if (($CcmEvalMPHealth.MatchingLogLine -ne 0) -and ($CcmEvalMPHealth.LogMsgTime -ne 0)) {
                $MPHealthDate = $CcmEvalMPHealth.LogMsgTime.ToString()
                Add-Text "Last successful Health Status: $MPHealthDate"
            }
        }
        else { Add-Text "No successful MP connection found." }
        Update-Gui
        # gpupdate
        Update-CheckBox -Name $CheckGPUpdate -Status 'InProgress'
        Update-Gui
        if ($PDCconnection) {
            $eta = $CurrDate.AddMinutes(10).ToShortTimeString()
            Add-Text -Text "`n" -NoBullet
            Add-Text -Text "Group Policy update started. Please wait..."
            Add-Text -Text "Estimated Completion Time: $eta"
            Update-Gui
            #$GPResults = Start-Job { (Start-Process -FilePath 'gpupdate' -ArgumentList '/force' -RedirectStandardOutput "$LogFolder\$FileNameTimestamp-$LogFileName-gpupdate.log" -NoNewWindow -PassThru -Wait).ExitCode } | Wait-Job | receive-job
            $GPResults = (Start-Process -FilePath 'gpupdate' -ArgumentList '/force' -RedirectStandardOutput "$LogFolder\$FileNameTimestamp-$LogFileName-gpupdate.log" -NoNewWindow -PassThru -Wait).ExitCode
            #$GPResults = (Start-Process -FilePath 'notepad' -NoNewWindow -PassThru -Wait).ExitCode
            if ($GPResults -eq 0) {
                Update-CheckBox -Name $CheckGPUpdate -Status 'Pass'
                Add-Text -RemoveLastLine
                Add-Text -RemoveLastLine
                Add-Text -RemoveLastLine
                Add-Text -Text "Group Policy successfully applied."
            }
            else {
                Update-CheckBox -Name $CheckGPUpdate -Status 'Fail'
                Add-Text -RemoveLastLine
                Add-Text -RemoveLastLine
                Add-Text -RemoveLastLine
                Add-Text -Text "Applying Group Policy failed. Exit Code: $GPResults"
            }
        }
        
        Add-Text "Phase One finished.`n`n"
        Add-Text "------ Please disconnect the VPN and Start Phase Two! ------" -NoBullet
        $ButtonP2.IsEnabled = "True"
        $TextResults.Text | out-file $TextBoxLog -Append
    }
    
    function Start-PhaseTwo {
        Update-CheckBox $CheckInternetP2 -Status 'N'
        Update-CheckBox $CheckIBCMP2 -Status 'N'
        # company VPN
        Add-Text "Starting Phase Two.`n" -Clear -NoBullet
        Update-Gui
        if (Get-companyVPNConfig) {
            Add-Text "company VPN seems to still be connected."
            Add-Text "Please disconnect the VPN and Start Phase Two."
            return
        }
        else {
            # check internet access
            #if (Test-ServerConnection 'google.com' -Port 443) {
            Update-CheckBox -Name $CheckInternetP2 -Status 'InProgress'
            Update-Gui
            if (Test-ServerConnection 'google.com' -Port 443) {
                Update-CheckBox $CheckInternetP2 -Status 'Pass'
                Add-Text "Internet access: True" 
            }
            else {
                Update-CheckBox $CheckInternetP2 -Status 'Fail'
                Add-Text "The machine has no internet access." 
                Add-Text "This might happen because a VPN is still connected." 
                Add-Text "Please make sure you have an internet connection and start Phase Two again."
                return
            }
            Update-Gui
            # check IBCM access
            Update-CheckBox -Name $CheckIBCMP2 -Status 'InProgress'
            Update-Gui
            if (Test-ServerConnection 'ibcm.company.com' -Port 443) {
                Update-CheckBox $CheckIBCMP2 -Status 'Pass'
            }
            else {
                Update-CheckBox $CheckIBCMP2 -Status 'Fail'
            }
            
            # check logs for IBCM
            $CcmEvalMPAccess = Get-SCCMLogInfo -StringToSearch 'ibcm.company.com and is accessible' -LogPath "$env:SystemRoot\CCM\Logs\CcmEval.log"
            if ($CcmEvalMPAccess.MatchingLogLine -ne 0) {
                if ($CcmEvalMPAccess.LogMsgTime -ne 0) {
                    [datetime]$LogDT = $CcmEvalMPAccess.LogMsgTime
                    Add-Text "Last ibcm.company.com access: $LogDT."
                }
                else {
                    Add-Text "Last ibcm.company.com access has no date."
                }
            }
            else { Add-Text "No ibcm.company.com access found in CcmEval.log." }

            Add-Text "Phase Two finished.`n`n"
            Add-Text "--- Please connect the client's VPN and Start Phase Three! ---" -NoBullet
            $ButtonP3.IsEnabled = "True"
            $TextResults.Text | out-file $TextBoxLog -Append
        }
    }
    function Start-PhaseThree {
        # company VPN
        Update-CheckBox $CheckInternetP3 -Status 'N'
        Update-CheckBox $CheckIBCMP3 -Status 'N'
        Add-Text "Starting Phase Three.`n" -Clear -NoBullet
        Update-Gui
        if (Get-companyVPNConfig) {
            Add-Text "company VPN seems to be connected."
            Add-Text "Please connect the client's VPN instead and Start Phase Three."
            return
        }
        else {
            # check internet access
            #if (Test-ServerConnection 'google.com' -Port 443) {
            Update-CheckBox -Name $CheckInternetP3 -Status 'InProgress'
            Update-Gui
            if (Test-ServerConnection 'google.com') {
                Update-CheckBox $CheckInternetP3 -Status 'Pass'
                Add-Text "Internet access: True" 
            }
            else {
                Update-CheckBox $CheckInternetP3 -Status 'Fail'
                Add-Text "The machine has no internet access." 
                Add-Text "This might happen because a VPN is still connected." 
                Add-Text "Please make sure you have an internet connection and start Phase Two again."
                return
            }
            # check IBCM access
            Update-CheckBox -Name $CheckIBCMP3 -Status 'InProgress'
            Update-Gui
            if (Test-ServerConnection 'ibcm.company.com' -Port 443) {
            
                Update-CheckBox $CheckIBCMP3 -Status 'Pass'
            }
            else {
                Update-CheckBox $CheckIBCMP3 -Status 'Fail'
            }
            Update-Gui
            # check logs for IBCM
            $CcmEvalMPAccess = Get-SCCMLogInfo -StringToSearch 'ibcm.company.com and is accessible' -LogPath "$env:SystemRoot\CCM\Logs\CcmEval.log"
            if ($CcmEvalMPAccess.MatchingLogLine -ne 0) {
                if ($CcmEvalMPAccess.LogMsgTime -ne 0) {
                    [datetime]$LogDT = $CcmEvalMPAccess.LogMsgTime
                    Add-Text "Last ibcm.company.com access: $LogDT."
                }
                else {
                    Add-Text "Last ibcm.company.com access has no date."
                }
            }
            else { Add-Text "No ibcm.company.com access found in CcmEval.log." }

            Add-Text "Phase Three finished.`n`n"
            Add-Text "------ Thank you for completing this test! ------" -NoBullet
            $TextResults.Text | out-file $TextBoxLog -Append
        }
    }
    if (!(Get-companyVPNConfig)) {
        Add-Text "company VPN seems to be disconnected.`n" -Clear -NoBullet
        Add-Text "Please connect to company VPN and start Phase One."
        Update-CheckBox $CheckVPN -Status 'Fail'
    }
    else {
        Add-Text "company VPN connected. Please start Phase One." -Clear -NoBullet
        Update-CheckBox $CheckVPN -Status 'Pass'
    }
    #$script:AsyncResult = $Powershell.BeginInvoke()
    $ButtonP1.Add_Click( {
            $Global:ProgressBar = New-ProgressBar
            Start-PhaseOne
            $Global:ProgressBar.Window.Dispatcher.Invoke([action] { $Global:ProgressBar.Window.close() }, "Normal")
        })
    $ButtonP2.Add_Click( {

            $Global:ProgressBar = New-ProgressBar
            Start-PhaseTwo
            $Global:ProgressBar.Window.Dispatcher.Invoke([action] { $Global:ProgressBar.Window.close() }, "Normal")
        })
    $ButtonP3.Add_Click( {
            $Global:ProgressBar = New-ProgressBar
            Start-PhaseThree
            $Global:ProgressBar.Window.Dispatcher.Invoke([action] { $Global:ProgressBar.Window.close() }, "Normal")
        })
    
    #! === MAIN CODE END ===
    $Window.ShowDialog() | Out-Null
    #Start-PhaseOne
}

catch {
    if ($Global:ExitCode -eq 0) {
        $Global:ExitCode = 99999
        $ErrorMessage = [string]$_.Exception.Message
        $ErrorPosition = [string]$_.InvocationInfo.PositionMessage
        Write-Log -Message "$ErrorMessage | $ErrorPosition" -Severity 3 -WriteHost $true
    }
}
finally {
    $Window.close()
    # $Global:ProgressBar.Window.Dispatcher.Invoke([action] { $Global:ProgressBar.Window.close() }, "Normal")
    # Call the .NET garbage collector.
    [System.GC]::Collect()
    if ($Global:Output) {
        $OutputString = ($Global:Output | Format-List -Property * | Out-String).Trim()
        Write-Log "Script output:`n$OutputString"
        Write-Output $Global:Output
    }
    Write-Log "Global exit code: $Global:ExitCode"
    Write-Log "Script [$ScriptName] finished."
    Write-Log "================================================================" 0
    Exit $Global:ExitCode
}

#EndRegion ============================[EXEC]==================================
