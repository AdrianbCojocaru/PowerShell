Function New-ProgressBar {
    <#
 .Synopsis
  WPF Running-Bar in the center of the screen.

 .Example
   ###
#>
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

$Global:ProgressBar = New-ProgressBar
Start-Sleep -Seconds 5
$Global:ProgressBar.Window.Dispatcher.Invoke([action] { $Global:ProgressBar.Window.close() }, "Normal")
