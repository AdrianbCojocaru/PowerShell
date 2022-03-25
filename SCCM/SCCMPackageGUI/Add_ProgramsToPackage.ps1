Function Add-SCCMPrograms {
    [CmdletBinding()]
    Param (
        [Parameter(ValueFromPipeline = $true)]
        [ValidateNotNullorEmpty()]
        [PSCustomObject]$SCCMPackage
    )
    $OutputBox.AppendText("Add SCCMPrograms..")
    [int]$PackSize = $DiskSpace.Text
    [int]$Duration = $Duration.Text
    [int]$DiskSpaceInstall = $PackSize * 2
    [string]$DiskUnit = "MB"
    [string]$InstallProgramComment = $InstallProgramCommentBox.Text
    [string]$UnInstallProgramComment = $UnInstallProgramCommentBox.Text  
    if (($PackagePath.Text.Length -gt 7)) {
        $PathForPackType = Get-CorrectPath -ServerName $SCCMServer -Path $SCCMPackage.PkgSourcePath
        $PackageType = Get-PSFileType -Path $PathForPackType
        switch ($PackageType) {
            "DeployApplication" {
                $isPowershellPackage.Checked = $true
                $installCommand = "powershell.exe -ExecutionPolicy Bypass -NoLogo -NonInteractive -NoProfile -WindowStyle Hidden -File Deploy-Application.ps1 -DeploymentType `"Install`" -DeployMode `"Silent`""
                $uninstallCommand = "powershell.exe -ExecutionPolicy Bypass -NoLogo -NonInteractive -NoProfile -WindowStyle Hidden -File Deploy-Application.ps1 -DeploymentType `"Uninstall`" -DeployMode `"Silent`""
                break
            }
            "ChromeExtension" {
                $isExtensionPackage.Checked = $true
                $InstallProgramComment = "Google Chrome has to be installed."
                $InstallProgramCommentBox.Text = $InstallProgramComment
                $installCommand = "powershell.exe -ExecutionPolicy Bypass -NoLogo -NonInteractive -NoProfile -WindowStyle Hidden -File install.ps1"
                $uninstallCommand = "powershell.exe -ExecutionPolicy Bypass -NoLogo -NonInteractive -NoProfile -WindowStyle Hidden -File uninstall.ps1"
                break
            }
            default {
                $isBatchPackage.Checked = $true
                $installCommand = "install.bat"
                $uninstallCommand = "uninstall.bat"
            }
        }
    }
    New-CMProgram -PackageId "$($SCCMPackage.PackageID)" -StandardProgramName 'install' -CommandLine $installCommand -DiskSpaceRequirement $DiskSpaceInstall -DiskSpaceUnit $DiskUnit -Duration $Duration `
        -RunType Hidden -ProgramRunType WhetherOrNotUserIsLoggedOn -RunMode RunWithAdministrativeRights -UserInteraction $False
    Set-CMProgram -PackageId "$($SCCMPackage.PackageID)" -StandardProgramName 'install' -StandardProgram -EnableTaskSequence $true -Category "Standard Applications"  -Comment $InstallProgramComment
    $OutputBox.AppendText("..")
    #    New-CMProgram -PackageId "$($SCCMPackage.PackageID)" -StandardProgramName 'uninstall' -CommandLine $uninstallCommand -DiskSpaceRequirement $PackSize -DiskSpaceUnit $DiskUnit -Duration $Duration `
    #        -RunType Hidden -ProgramRunType WhetherOrNotUserIsLoggedOn -RunMode RunWithAdministrativeRights -UserInteraction $False
    #    Set-CMProgram -PackageId "$($SCCMPackage.PackageID)" -StandardProgramName 'uninstall' -StandardProgram -EnableTaskSequence $true -Category "Uninstall Applications"  -Comment $UnInstallProgramComment
    #    $OutputBox.AppendText("..Ok`n")
    return $SCCMPackage
}

If ( ! (Get-Module ConfigurationManager)) {
    Import-Module 'C:\Program Files (x86)\Microsoft Configuration Manager\AdminConsole\bin\ConfigurationManager.psd1' -ErrorAction Stop
}
Set-Location 'CSP:' -ErrorAction Stop

$SCCMPackID = 'CSP04874'
$ProgramName = 'Install ServerManager'
$installCommand = 'powershell.exe -ExecutionPolicy Bypass -NoLogo -NonInteractive -NoProfile -WindowStyle Hidden -File Install-RSAT.ps1 -ServerManager'
$InstallProgramComment = 'Rsat.ServerManager'
#Get-CMPackage -Id $SCCMPackID -Fast | Add-SCCMProgram -Name "" -CmdLine "" -Comment 

New-CMProgram -PackageId  $SCCMPackID -StandardProgramName $ProgramName -CommandLine $installCommand -DiskSpaceRequirement '50' -DiskSpaceUnit 'MB' -Duration '40'`
    -RunType Hidden -ProgramRunType WhetherOrNotUserIsLoggedOn -RunMode RunWithAdministrativeRights -UserInteraction $False |`
    Set-CMProgram -StandardProgram -EnableTaskSequence $true -Category "Standard Applications"  -Comment $InstallProgramComment


$SCCMPackID = 'CSP04874'
$ProgramName = 'Uninstall'
$installCommand = 'powershell.exe -ExecutionPolicy Bypass -NoLogo -NonInteractive -NoProfile -WindowStyle Hidden -File Install-RSAT.ps1 -Uninstall'
$InstallProgramComment = ''
#Get-CMPackage -Id $SCCMPackID -Fast | Add-SCCMProgram -Name "" -CmdLine "" -Comment 

New-CMProgram -PackageId  $SCCMPackID -StandardProgramName $ProgramName -CommandLine $installCommand -DiskSpaceRequirement '50' -DiskSpaceUnit 'MB' -Duration '40'`
    -RunType Hidden -ProgramRunType WhetherOrNotUserIsLoggedOn -RunMode RunWithAdministrativeRights -UserInteraction $False |`
    Set-CMProgram -StandardProgram -EnableTaskSequence $true -Category "Standard Applications"  -Comment $InstallProgramComment