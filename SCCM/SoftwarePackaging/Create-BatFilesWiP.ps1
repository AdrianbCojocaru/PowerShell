function Get-MSIProductCode {
    param(
        [parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [System.IO.FileInfo]$Path
    )
    Process {
        try {
            # Read property from MSI database
            $WindowsInstaller = New-Object -ComObject WindowsInstaller.Installer
            $MSIDatabase = $WindowsInstaller.GetType().InvokeMember("OpenDatabase", "InvokeMethod", $null, $WindowsInstaller, @($Path.FullName, 0))
            $Query = "SELECT Value FROM Property WHERE Property = 'ProductCode'"
            $View = $MSIDatabase.GetType().InvokeMember("OpenView", "InvokeMethod", $null, $MSIDatabase, ($Query))
            $View.GetType().InvokeMember("Execute", "InvokeMethod", $null, $View, $null)
            $Record = $View.GetType().InvokeMember("Fetch", "InvokeMethod", $null, $View, $null)
            $Value = $Record.GetType().InvokeMember("StringData", "GetProperty", $null, $Record, 1)
 
            # Commit database and close view
            $MSIDatabase.GetType().InvokeMember("Commit", "InvokeMethod", $null, $MSIDatabase, $null)
            $View.GetType().InvokeMember("Close", "InvokeMethod", $null, $View, $null)           
            $MSIDatabase = $null
            $View = $null
 
            # Return the value
            return $Value
        } 
        catch {
            Write-Error -Message $_.Exception.Message
            Read-Host -Prompt "Something went wrong! press Enter to exit"
            break
        }
    }
    End {
        # Run garbage collection and release ComObject
        [System.Runtime.Interopservices.Marshal]::ReleaseComObject($WindowsInstaller) | Out-Null
        [System.GC]::Collect()
    }
}
<#
$location = Get-Location
Get-ChildItem $location | ForEach-Object {
    if ($_.Extension -eq ".msi") {
        $msiName = $_.Name
        $msiBaseName = $_.BaseName
        $msiPath = $_.FullName
    }
    elseif ($_.Extension -eq ".mst") {
        $mstName = $_.Name
        $mstBaseName = $_.BaseName
        $mstPath = $_.FullName
    }
}
#>
$msi = [System.IO.FileInfo]"$($args[0])"
$msiName = $msi.Name
$msiBaseName = $msi.BaseName
$msiPath = $msi.FullName
$msiDir = $msi.Directory.FullName

$msiDir = Split-Path -Path $msiPath -Parent
[string]$msiProductCode = Get-MSIProductCode "$msiPath"
$msiProductCode = $msiProductCode.Trim()

Get-ChildItem $msiDir | ForEach-Object {
    if ($_.Extension -eq ".mst") {
        $mstName = $_.Name
        $mstBaseName = $_.BaseName
        $mstPath = $_.FullName
    }
}
if (!$mstPath) {
    $installCommandLine = "msiexec /i `"$msiName`" /l*v `"%windir%\Logs\SoftwarePackagingRO\${msiBaseName}_install.log`" /qn"
    $uninstallCommandLine = "msiexec /x $msiProductCode /l*v `"%windir%\Logs\SoftwarePackagingRO\${msiBaseName}_uninstall.log`" /qn"
}
else {
    $installCommandLine = "msiexec /i `"$msiName`" TRANSFORMS=`"$mstName`" /l*v `"%windir%\Logs\SoftwarePackagingRO\${mstBaseName}_install.log`" /qn"
    $uninstallCommandLine = "msiexec /x $msiProductCode /l*v `"%windir%\Logs\SoftwarePackagingRO\${mstBaseName}_uninstall.log`" /qn"
}

$installText = @"
@ECHO OFF
cd %~dp0
mkdir "%windir%\Logs\SoftwarePackagingRO"
cls
echo.
echo Installing
echo.
echo ...do not close this window...
echo. 
set SEE_MASK_NOZONECHECKS=1

$installCommandLine 
"@
$uninstallText = @"
@ECHO OFF
cd %~dp0
mkdir "%windir%\Logs\SoftwarePackagingRO"
cls
echo.
echo Uninstalling
echo.
echo ...do not close this window...
echo. 
set SEE_MASK_NOZONECHECKS=1

$uninstallCommandLine 
"@
if (Test-Path "$msiDir\install.bat") {Remove-Item "$msiDir\install.bat"}
if (Test-Path "$msiDir\uninstall.bat") {Remove-Item "$msiDir\uninstall.bat"}
$installText    | Out-File -FilePath "$msiDir\install.bat" -Encoding ASCII
$uninstallText  | Out-File -FilePath "$msiDir\uninstall.bat" -Encoding ASCII
Start-Process notepad++ "$msiDir\install.bat"
Start-Process notepad++ "$msiDir\uninstall.bat"