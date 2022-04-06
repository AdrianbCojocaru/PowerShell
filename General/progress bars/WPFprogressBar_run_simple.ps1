Add-Type -AssemblyName PresentationFramework
[System.Threading.Thread]::CurrentThread.CurrentUICulture = 'en-US'
[System.Threading.Thread]::CurrentThread.CurrentCulture = 'en-US'
[xml]$xaml_S = @"
<Window
xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
x:Name="Window"
FontSize="18" Title="Please wait..."
Height="100" Width="320" ShowInTaskbar = "True"
ResizeMode="Noresize">
<Grid Margin="20">
<ProgressBar Minimum="0" Maximum="100" Name="pbStatus" IsIndeterminate="True" />
</Grid>
</Window>
"@
#--- Load Window Objects
$reader_S = (New-Object System.Xml.XmlNodeReader $xaml_S)
$Window_S = [Windows.Markup.XamlReader]::Load( $reader_S )

$Window_S.ShowDialog() | Out-Null
