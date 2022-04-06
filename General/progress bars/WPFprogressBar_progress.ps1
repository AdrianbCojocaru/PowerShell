Function New-ProgressBar {
    <#
 .Synopsis
  WPF Progress-Bar in the center of the screen.

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
            Width = "300" Height = "150" ShowInTaskbar = "True"> 
            <StackPanel Margin="50">
               <ProgressBar Name="ProgressBar" Height="30" />
               <TextBlock Text="{Binding ElementName=ProgressBar, Path=Value, StringFormat={}{0:0}%}" HorizontalAlignment="Center" VerticalAlignment="Center" />
            </StackPanel> 
        </Window> 
"@ 
  
            $reader = (New-Object System.Xml.XmlNodeReader $xaml) 
            $syncHash.Window = [Windows.Markup.XamlReader]::Load( $reader ) 
            #===========================================================================
            # Store Form Objects In PowerShell
            #===========================================================================
            $xaml.SelectNodes("//*[@Name]") | % { $SyncHash."$($_.Name)" = $SyncHash.Window.FindName($_.Name) }

            $updateBlock = {            
            
                $SyncHash.Window.Title = $SyncHash.Activity
                $SyncHash.ProgressBar.Value = $SyncHash.PercentComplete
                       
            }

            ############### New Blog ##############
            $syncHash.Window.Add_SourceInitialized( {            
                    ## Before the window's even displayed ...            
                    ## We'll create a timer            
                    $timer = new-object System.Windows.Threading.DispatcherTimer            
                    ## Which will fire 4 times every second            
                    $timer.Interval = [TimeSpan]"0:0:0.01"            
                    ## And will invoke the $updateBlock            
                    $timer.Add_Tick( $updateBlock )            
                    ## Now start the timer running            
                    $timer.Start()            
                    if ( $timer.IsEnabled ) {            
                        Write-Host "Clock is running. Don't forget: RIGHT-CLICK to close it."            
                    }
                    else {            
                        $clock.Close()            
                        Write-Error "Timer didn't start"            
                    }            
                } )

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
 

function Write-ProgressBar {

    Param (
        [Parameter(Mandatory = $true)]
        $ProgressBar,
        [Parameter(Mandatory = $true)]
        [String]$Activity,
        [int]$PercentComplete
    ) 
   
    $ProgressBar.Activity = $Activity

    if ($PercentComplete) {
      
        $ProgressBar.PercentComplete = $PercentComplete

    }

}

function Close-ProgressBar {

    Param (
        [Parameter(Mandatory = $true)]
        [System.Object[]]$ProgressBar
    )

    $ProgressBar.Window.Dispatcher.Invoke([action] { $ProgressBar.Window.close() }, "Normal")
 
}

#Put a Start-Sleep back in if you actually want to see the progress bar up.
$ProgressBar = New-ProgressBar
Measure-Command -Expression {
    1..100 | foreach { start-sleep -s 1; Write-ProgressBar -ProgressBar $ProgressBar -Activity "Counting $_ out of 100" -PercentComplete $_ }
}
Close-ProgressBar $ProgressBar
