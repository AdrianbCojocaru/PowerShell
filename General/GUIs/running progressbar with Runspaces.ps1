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
            Width = "600" Height = "100" ShowInTaskbar = "True" ResizeMode="Noresize"> 
            <StackPanel Margin="2"  x:Name="sp1">
                <TextBlock Text="Please wait..." HorizontalAlignment="Center" VerticalAlignment="Center" FontSize="18"/>
                <Rectangle Name="PART_Track"  HorizontalAlignment="Left"
                           Height="20" Width="200" Fill="Red" />
                <ProgressBar Name="ProgressBar" Height="10" IsIndeterminate="True"/>
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
            $syncHash.Window.WindowStyle = "ThreeDBorderWindow"

#            $uri = new-object system.uri("C:\Users\adria\Documents\hub_icon.png")
#$imagesource = new-object System.Windows.Media.Imaging.BitmapImage $uri
#$imagebrush = new-object System.Windows.Media.ImageBrush $imagesource
#$syncHash.Window.Background = $imagebrush

            $syncHash.Window.icon = "icon.png"
            $syncHash.Window.Foreground = 'Black'
          #  $syncHash.Window.Background = '#FC5115'
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
        [string]$Text = '',
        [Parameter(Mandatory = $false)]
        [ValidateNotNullorEmpty()]
        [int32]$Value
    )
    [string]${CmdletName} = $PSCmdlet.MyInvocation.MyCommand.Name

    Write-Log -Message "New text: $Text" -Caller $CmdletName
    try {
        $Hash.Window.Dispatcher.invoke([action] {
                $sp = $Hash.Window.FindName('sp1')
                $sp.Children[0].Text = $text
                $p.PART_Track.Width += $Value
                  
            },
            "Normal")
    }
    catch {}
}
$p = New-ProgressBar