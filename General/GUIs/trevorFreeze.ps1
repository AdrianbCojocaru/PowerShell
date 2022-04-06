# https://smsagent.blog/2015/09/07/powershell-tip-utilizing-runspaces-for-responsive-wpf-gui-applications/
Add-Type –assemblyName PresentationFramework
$ErrorActionPreference = [System.Management.Automation.ActionPreference]::Continue
#Build the GUI
[xml]$xaml = @"
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation" xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml" Title="PowerShell Runspace Demo" Height="283" Width="782" WindowStartupLocation = "CenterScreen">
    <Grid Margin="0,0,0,-1">
        <Button x:Name="Ping1" Content="Ping" HorizontalAlignment="Left" Margin="119,146,0,0" VerticalAlignment="Top" Width="93" Height="31"/>
        <Button x:Name="Ping2" Content="Ping" HorizontalAlignment="Left" Margin="255,146,0,0" VerticalAlignment="Top" Width="93" Height="31"/>
        <Button x:Name="Ping3" Content="Ping" HorizontalAlignment="Left" Margin="387,146,0,0" VerticalAlignment="Top" Width="93" Height="31"/>
        <Button x:Name="Ping4" Content="Ping" HorizontalAlignment="Left" Margin="524,146,0,0" VerticalAlignment="Top" Width="93" Height="31"/>
        <Button x:Name="Ping5" Content="Ping" HorizontalAlignment="Left" Margin="656,146,0,0" VerticalAlignment="Top" Width="93" Height="31"/>
        <TextBox x:Name="ComputerName1" HorizontalAlignment="Left" Height="23" Margin="105,79,0,0" TextWrapping="Wrap" Text="localhost" VerticalAlignment="Top" Width="120"/>
        <TextBox x:Name="ComputerName2" HorizontalAlignment="Left" Height="23" Margin="243,79,0,0" TextWrapping="Wrap" Text="localhost" VerticalAlignment="Top" Width="120"/>
        <TextBox x:Name="ComputerName3" HorizontalAlignment="Left" Height="23" Margin="374,79,0,0" TextWrapping="Wrap" Text="localhost" VerticalAlignment="Top" Width="120"/>
        <TextBox x:Name="ComputerName4" HorizontalAlignment="Left" Height="23" Margin="509,79,0,0" TextWrapping="Wrap" Text="localhost" VerticalAlignment="Top" Width="120"/>
        <TextBox x:Name="ComputerName5" HorizontalAlignment="Left" Height="23" Margin="640,79,0,0" TextWrapping="Wrap" Text="localhost" VerticalAlignment="Top" Width="120"/>
        <ComboBox x:Name="Count1" HorizontalAlignment="Left" Margin="137,107,0,0" VerticalAlignment="Top" Width="56" Height="34">
            <ComboBoxItem Content="1"/>
            <ComboBoxItem Content="2"/>
            <ComboBoxItem Content="3"/>
            <ComboBoxItem Content="4"/>
            <ComboBoxItem Content="5"/>
            <ComboBoxItem Content="6"/>
            <ComboBoxItem Content="7"/>
            <ComboBoxItem Content="8"/>
        </ComboBox>
        <ComboBox x:Name="Count2" HorizontalAlignment="Left" Margin="274,107,0,0" VerticalAlignment="Top" Width="56" Height="34">
            <ComboBoxItem Content="1"/>
            <ComboBoxItem Content="2"/>
            <ComboBoxItem Content="3"/>
            <ComboBoxItem Content="4"/>
            <ComboBoxItem Content="5"/>
            <ComboBoxItem Content="6"/>
            <ComboBoxItem Content="7"/>
            <ComboBoxItem Content="8"/>
        </ComboBox>
        <ComboBox x:Name="Count3" HorizontalAlignment="Left" Margin="403,107,0,0" VerticalAlignment="Top" Width="56" Height="34">
            <ComboBoxItem Content="1"/>
            <ComboBoxItem Content="2"/>
            <ComboBoxItem Content="3"/>
            <ComboBoxItem Content="4"/>
            <ComboBoxItem Content="5"/>
            <ComboBoxItem Content="6"/>
            <ComboBoxItem Content="7"/>
            <ComboBoxItem Content="8"/>
        </ComboBox>
        <ComboBox x:Name="Count4" HorizontalAlignment="Left" Margin="540,107,0,0" VerticalAlignment="Top" Width="56" Height="34">
            <ComboBoxItem Content="1"/>
            <ComboBoxItem Content="2"/>
            <ComboBoxItem Content="3"/>
            <ComboBoxItem Content="4"/>
            <ComboBoxItem Content="5"/>
            <ComboBoxItem Content="6"/>
            <ComboBoxItem Content="7"/>
            <ComboBoxItem Content="8"/>
        </ComboBox>
        <ComboBox x:Name="Count5" HorizontalAlignment="Left" Margin="669,107,0,0" VerticalAlignment="Top" Width="56" Height="34">
            <ComboBoxItem Content="1"/>
            <ComboBoxItem Content="2"/>
            <ComboBoxItem Content="3"/>
            <ComboBoxItem Content="4"/>
            <ComboBoxItem Content="5"/>
            <ComboBoxItem Content="6"/>
            <ComboBoxItem Content="7"/>
            <ComboBoxItem Content="8"/>
        </ComboBox>
        <TextBox x:Name="Result1" HorizontalAlignment="Left" Height="56" Margin="128,182,0,0" TextWrapping="Wrap" VerticalAlignment="Top" Width="75" FontSize="18"/>
        <TextBox x:Name="Result2" HorizontalAlignment="Left" Height="56" Margin="264,182,0,0" TextWrapping="Wrap" VerticalAlignment="Top" Width="75" FontSize="18"/>
        <TextBox x:Name="Result3" HorizontalAlignment="Left" Height="56" Margin="397,182,0,0" TextWrapping="Wrap" VerticalAlignment="Top" Width="75" FontSize="18"/>
        <TextBox x:Name="Result4" HorizontalAlignment="Left" Height="56" Margin="535,182,0,0" TextWrapping="Wrap" VerticalAlignment="Top" Width="75" FontSize="18"/>
        <TextBox x:Name="Result5" HorizontalAlignment="Left" Height="56" Margin="669,182,0,0" TextWrapping="Wrap" VerticalAlignment="Top" Width="75" FontSize="18"/>
        <Label Content="ComputerName:" HorizontalAlignment="Left" Margin="3,75,0,0" VerticalAlignment="Top" Height="26" Width="97"/>
        <Label Content="Count:" HorizontalAlignment="Left" Margin="3,107,0,0" VerticalAlignment="Top" Height="26" Width="94"/>
        <Label Content="Avg Latency (ms):" HorizontalAlignment="Left" Margin="0,182,0,0" VerticalAlignment="Top" Height="26" Width="111"/>
        <Label Content="Runspace Demo: Test-Connection" HorizontalAlignment="Left" Margin="10,10,0,0" VerticalAlignment="Top" Width="338" FontSize="20" FontWeight="Bold"/>
        <Button x:Name="Pingall" Content="Ping all" HorizontalAlignment="Left" Margin="656,14,0,0" VerticalAlignment="Top" Width="89" Height="37" FontWeight="Bold"/>
    </Grid>
</Window>
"@

$reader = (New-Object System.Xml.XmlNodeReader $xaml)
$Window = [Windows.Markup.XamlReader]::Load( $reader )

function Ping {
    param($result, $count, $ComputerName)
    $result.Clear()
    if ($count.SelectedItem.Content -eq $null)
    { NullCount; break }
    $Con = Test-Connection -ComputerName $($ComputerName.Text) -Count $count.SelectedItem.Content
    $avg = [math]::Round(($con.ResponseTime | measure -Average).Average)
    $result.AddText($avg)
}
function NullCount {
    [System.Reflection.Assembly]::LoadWithPartialName('Microsoft.VisualBasic') | Out-Null
    [Microsoft.VisualBasic.Interaction]::MsgBox("Please select a ping count first", 'OKOnly,Information', "Ping")
}



# XAML objects
# ComputerNames
$ComputerName1 = $Window.FindName("ComputerName1")
$ComputerName2 = $Window.FindName("ComputerName2")
$ComputerName3 = $Window.FindName("ComputerName3")
$ComputerName4 = $Window.FindName("ComputerName4")
$ComputerName5 = $Window.FindName("ComputerName5")
# Count
$Count1 = $Window.FindName("Count1")
$Count2 = $Window.FindName("Count2")
$Count3 = $Window.FindName("Count3")
$Count4 = $Window.FindName("Count4")
$Count5 = $Window.FindName("Count5")
# Ping buttons
$Ping1 = $Window.FindName("Ping1")
$Ping2 = $Window.FindName("Ping2")
$Ping3 = $Window.FindName("Ping3")
$Ping4 = $Window.FindName("Ping4")
$Ping5 = $Window.FindName("Ping5")
$Pingall = $Window.FindName("Pingall")
# Result boxes
$Result1 = $Window.FindName("Result1")
$Result2 = $Window.FindName("Result2")
$Result3 = $Window.FindName("Result3")
$Result4 = $Window.FindName("Result4")
$Result5 = $Window.FindName("Result5")

# Click Actions
$Ping1.Add_Click(
    {
        Ping -result $Result1 -count $Count1 -ComputerName $ComputerName1
    })

$Ping2.Add_Click(
    {
        Ping -result $Result2 -count $Count2 -ComputerName $ComputerName2
    })

$Ping3.Add_Click(
    {
        Ping -result $Result3 -count $Count3 -ComputerName $ComputerName3
    })

$Ping4.Add_Click(
    {
        Ping -result $Result4 -count $Count4 -ComputerName $ComputerName4
    })

$Ping5.Add_Click(
    {
        Ping -result $Result5 -count $Count5 -ComputerName $ComputerName5
    })

$Pingall.Add_Click(
    {
        if ($count1.SelectedItem.Content -eq $null -or $count2.SelectedItem.Content -eq $null -or $count3.SelectedItem.Content -eq $null -or $count4.SelectedItem.Content -eq $null -or $count5.SelectedItem.Content -eq $null)
        { NullCount; break }
        Ping -result $Result1 -count $Count1 -ComputerName $ComputerName1
        Ping -result $Result2 -count $Count2 -ComputerName $ComputerName2
        Ping -result $Result3 -count $Count3 -ComputerName $ComputerName3
        Ping -result $Result4 -count $Count4 -ComputerName $ComputerName4
        Ping -result $Result5 -count $Count5 -ComputerName $ComputerName5
    })

$Window.ShowDialog() | Out-Null
