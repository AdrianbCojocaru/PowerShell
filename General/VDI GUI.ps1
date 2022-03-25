<#

.SYNOPSIS
  GUI for verifying the VM template: Domain-Join | SCCM service | Lates Updates | SCCM Actions trigger

.NOTES
  Author:         Adrian
  Purpose/Change: Initial script development

.EXAMPLE
  Run the script. No params needed.

#>

#-------------------------------------------------------------#
#----Initial Declarations-------------------------------------#
#-------------------------------------------------------------#

Add-Type -AssemblyName PresentationCore, PresentationFramework

$Xaml = @"
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation" Width="1024" Height="768">
<Grid Margin="12,0,-149,-94">
	<Button Content="Check Updates" HorizontalAlignment="Left" VerticalAlignment="Top" Width="105" Margin="10,20,0,0" Height="41" Name="ButtonCheckUpdates"/>
	<Button Content="ConfigMgr Service" HorizontalAlignment="Left" VerticalAlignment="Top" Width="105" Margin="130,20,0,0" Height="41" Name="ConfigMgrService"/>
	<Button Content="ConfigMgr Actions" HorizontalAlignment="Left" VerticalAlignment="Top" Width="105" Margin="250,20,0,0" Height="41" Name="ConfigMgrActions"/>
    <Button Content="Check Domain-Joined" HorizontalAlignment="Left" VerticalAlignment="Top" Width="125" Margin="370,20,0,0" Height="41" Name="Domainjoined"/>
    <Button Content="Button" HorizontalAlignment="Left" VerticalAlignment="Top" Width="105" Margin="510,20,0,0" Height="41"/>
<TextBox HorizontalAlignment="Left" VerticalAlignment="Top" Height="582" Width="970" TextWrapping="Wrap" Margin="10,116,0,0" Name="TextBox" FontFamily="Consolas" FontSize="13" VerticalScrollBarVisibility="Auto"/>
<TextBlock HorizontalAlignment="Left" VerticalAlignment="Top" TextWrapping="Wrap" Text="Join Computer to domain:" Margin="718,15,0,0" Width="200" Height="23" FontFamily="Consolas" FontSize="13"/>
<TextBox HorizontalAlignment="Left" VerticalAlignment="Top" Height="21" Width="180" TextWrapping="Wrap" Margin="718,38,0,0" Name="JoinComputerTextBox"/>
<Button Content="Join" HorizontalAlignment="Left" VerticalAlignment="Top" Width="176" Margin="718,76,0,0" Height="25" Name="JointoDomain"/>
</Grid>
</Window>
"@

#-------------------------------------------------------------#
#----Control Event Handlers-----------------------------------#
#-------------------------------------------------------------#

#-------------------------------------------------------------#
#----Script Execution-----------------------------------------#
#-------------------------------------------------------------#

$Window = [Windows.Markup.XamlReader]::Parse($Xaml)

[xml]$xml = $Xaml

$xml.SelectNodes("//*[@Name]") | ForEach-Object { Set-Variable -Name $_.Name -Value $Window.FindName($_.Name) }

$a = @{Expression = { $_.PSComputerName }; Label = "Computer Name"; Width = 25 }, 
@{Expression = { $_.Description }; Label = "Category"; Width = 25 }, 
@{Expression = { $_.HotFixID }; Label = "HotFix ID"; Width = 25 }, 
@{Expression = { $_.InstalledBy }; Label = "Installed By"; Width = 25 }, 
@{Expression = { $_.InstalledOn }; Label = "Installed On"; Width = 25 }

[hashtable]$hash = [ordered]@{
    HardwareInventoryCycle                    = '{00000000-0000-0000-0000-000000000001}'
    SoftwareInventoryCycle                    = '{00000000-0000-0000-0000-000000000002}'
    DiscoveryDataCollectionCycle              = '{00000000-0000-0000-0000-000000000003}'
    MachinePolicyRetrievalCycle               = '{00000000-0000-0000-0000-000000000021}'
    MachinePolicyEvaluationCycle              = '{00000000-0000-0000-0000-000000000022}'
    UserPolicyRetrievalCycle                  = '{00000000-0000-0000-0000-000000000026}'
    UserPolicyEvaluationCycle                 = '{00000000-0000-0000-0000-000000000027}'
    SoftwareMeteringGeneratingUsageReport     = '{00000000-0000-0000-0000-000000000031}'
    WindowsInstallersSourceListUpdateCycle    = '{00000000-0000-0000-0000-000000000032}'
    SoftwareUpdatesAssignmentsEvaluationCycle = '{00000000-0000-0000-0000-000000000108}'
    SendUnsentStateMessage                    = '{00000000-0000-0000-0000-000000000111}'
    SoftwareUpdateScanCycle                   = '{00000000-0000-0000-0000-000000000113}'
    ApplicationDeploymentEvaluationCylce      = '{00000000-0000-0000-0000-000000000121}'    
}

$ButtonCheckUpdates.Add_Click( {
        $NrOfDays = 90
        $WinUpdates = Get-HotFix
        $WinUpdatesStr = $WinUpdates | Sort-Object -Property InstalledOn -Descending | Format-Table -Property $a | Out-String
        $NrOfLatestUpd = ($WinUpdates | Where-Object { $_.InstalledOn -gt ((Get-Date).Adddays(-$NrOfDays)) }).count
        $TextBox.Text = ("`n${WinUpdatesStr}${NrOfLatestUpd} Updates installed in the last $NrOfDays days.")
        $TextBox.ScrollToEnd()
    })

$ConfigMgrService.Add_Click( {
        $smstsmgr = Get-Service -name CcmExec
        $TextBox.AddText("`n`n`n$($smstsmgr.DisplayName) Service: $($smstsmgr.Status), $($smstsmgr.StartType)")
        if ($smstsmgr.Status -ne "Running") {
            $TextBox.AddText("`nStarting service....")
            $smstsmgr | Start-Service
            $TextBox.AddText("$($smstsmgr.DisplayName) is now $($smstsmgr.Status)")
        }
        $TextBox.ScrollToEnd()
    })

$ConfigMgrActions.Add_Click( {
        $TextBox.AddText("`n")
        $hash.GetEnumerator() | ForEach-Object {
            $TextBox.AddText("`nRunning $($_.Name)")
            Invoke-CimMethod -Namespace 'root\CCM' -ClassName SMS_Client -MethodName TriggerSchedule -Arguments @{ sScheduleID = "$($_.Value)" } -ErrorAction SilentlyContinue
        }
        $TextBox.ScrollToEnd()
    })

$Domainjoined.Add_Click( {
        try {
            $AD = [System.DirectoryServices.ActiveDirectory.Domain]::GetComputerDomain()
            $TextBox.AddText("`n`nThis computer is joined to $($AD.Name)")
        }
        catch {
            $TextBox.AddText("`n`nThis Computer is not domain-joined !")
        }
        $TextBox.ScrollToEnd()        
    })

$JointoDomain.Add_Click( {
        Add-Computer -DomainName $($JoinComputerTextBox.Text)
    })
$Window.ShowDialog()
