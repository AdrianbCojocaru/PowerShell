<#

.SYNOPSIS
  User GUI that reads software packaging ticket data and creates an SCCM Package

.INPUTS
  None

.OUTPUTS
  One XLSX file will be created in the Output folder

.NOTES
  Author:         Adrian
  Purpose/Change: Initial script development

.EXAMPLE
  Run the script. No params needed.

#>
$SCCMServer = "XXXXX"
$PackServer = "XXXXXX.net"
$PortalLink = "http://xx.xx.xx.xx/packageworkflow"
$TodayDate = Get-Date -format dd.MM.yyyy_HH.mm.ss
$PackSize = 0
$error.Clear()

Function Get-FolderSize {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullorEmpty()]
        [string]$Path
    )
    if (Test-Path $Path) {
        [Long]$ActualSize = 0
        foreach ($Item in (Get-ChildItem $Path -recurse | Where-Object { -not $_.PSIsContainer } | ForEach-Object { $_.FullName })) {
            $ActualSize += (Get-Item $Item).length
        }
        $Size = [math]::ceiling(($ActualSize * 1.10) / 1MB)
    }
    else {
        $OutputBox.AppendText("Get-FolderSize: Unable to resolve Package Path`n")
        $OutputBox.AppendText("Get-FolderSize: Manually fill-in the Package Size`n")
        $Size = 0 
    }
    return $Size
}
Function Get-PSFileType {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullorEmpty()]
        [string]$Path
    )
    if (Test-Path $Path) {     
        :enumFiles foreach ($FileName in (Get-ChildItem -Path $Path).Name) {
            $PackageType = switch ($FileName) {
                "Deploy-Application.ps1" { 'DeployApplication'; break enumFiles }
                "install.ps1" { 'ChromeExtension'; break enumFiles }
                default { 'Batch' }
            }
        }
    }
    return $PackageType
}
Function Get-CorrectPath {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullorEmpty()]
        [string]$ServerName,
        [Parameter(Mandatory = $true)]
        [ValidateNotNullorEmpty()]
        [string]$Path
    )

    if (!(Test-Path $Path)) {
        $DL = Get-PSDrive -PSProvider FileSystem | Where-Object { $_.DisplayRoot -match $ServerName }
        if (!$DL) {
            Switch ($ServerName) {
                $SCCMServer { New-PSDrive -name R -PSProvider FileSystem -Root \\$ServerName.asf.madm.net\APPLICATIONS }
                $PackServer { New-PSDrive -name S -PSProvider FileSystem -Root \\$ServerName\dabteil8 }
            }
            $DL = Get-PSDrive -PSProvider FileSystem | Where-Object { $_.Root -match $ServerName }
            $Path = $Path -replace [Regex]::Escape("$($DL.Root)"), "$($DL.name):"

        }
        else { $Path = $Path -replace [Regex]::Escape("$($DL.DisplayRoot)"), "$($DL.name):" }        
    }
    return $Path
}

Function Read-PortalData {
    [CmdletBinding()]
    Param (
        [Parameter(ValueFromPipeline = $true)]
        [ValidateNotNullorEmpty()]
        [int]$WorkflowID
    )
    $OutputBox.AppendText("Get PortalData...")
    try {
        $PackagingPackages = Invoke-RestMethod -Uri "$PortalLink/ApplicationData.svc/BY_PKG()?`$expand=PackageOrder&`$top=45" `
            -Headers @{"MaxDataServiceVersion" = "3.0";
            "Accept-Encoding"                  = "gzip, deflate";
            "MinDataServiceVersion"            = "3.0";
            "Accept-Language"                  = "en-US,en;q=0.9";
            "User-Agent"                       = "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/65.0.3325.181 Safari/537.36";
            "Accept"                           = "application/json;q=0.8, application/json;odata=fullmetadata;q=0.7, application/atomsvc+xml;q=0.5, */*;q=0.1";
            "Referer"                          = "$PortalLink/HTMLClient/default.htm";
            "Cookie"                           = "msls-client-parameters=preferredLanguage=en-US; ASP.NET_SessionId=45l1bmwamievy0owsvkky55x"
        }  -UseDefaultCredentials -ErrorAction Stop
    }
    catch {
        $PackagingPackages = ''
        $error | out-file "$env:temp\SCCM_Workflow_${TodayDate}.log"
        $OutputBox.ForeColor = "#d0021b"
        $OutputBox.AppendText("`nError: PackageWorkflow data could not be retrieved !`n")
        throw
    }
    $OutputBox.AppendText(".")
    $Package = $PackagingPackages.value | ForEach-Object { $_.PackageOrder } | Where-Object { $_.id -eq $WorkflowID }
    $OutputBox.AppendText(".")
    $PackagePKGField = $PackagingPackages.value | Where-Object { $_.id -eq $WorkflowID }
    $Package | Add-Member -NotePropertyName WorkflowID -NotePropertyValue $WorkflowID
    $Package | Add-Member -NotePropertyName POA_Complexity -NotePropertyValue $PackagePKGField.POA_Complexity
    $OutputBox.AppendText("...Ok`n")
    return $Package
}

Function Add-SCCMPackageName {
    [CmdletBinding()]
    Param (
        [Parameter(ValueFromPipeline = $true)]
        [ValidateNotNullorEmpty()]
        $WebPackage
    )
    $OutputBox.AppendText("Add SCCMPackageName..")
    $Manufacturer = $WebPackage.Manufacturer
    $SoftwareName = $WebPackage.SoftwareName
    $Version = $WebPackage.Version
    Write-Host $Version
    If ($SoftwareName -match $Manufacturer) { $SoftwareName = ($SoftwareName -replace "$Manufacturer ", "").Trim() }
    If ($SoftwareName -match $Version) { $SoftwareName = ($SoftwareName -replace " $Version", "").Trim() }
    [string]$SCCMPackageName = "$Manufacturer $SoftwareName $Version"
    $SCCMPackageName = $SCCMPackageName -replace '^[a-zA-Z ][0-9][0-9,\.]', ' '
    $WebPackage | Add-Member -NotePropertyName SCCMPackageName -NotePropertyValue $SCCMPackageName
    $OutputBox.AppendText(".Ok`n")
    return $WebPackage
}
function Add-SCCMPackagePath {
    Param (
        [Parameter(ValueFromPipeline = $true)]
        [ValidateNotNullorEmpty()]
        [PSCustomObject]$WebPackage
    )
    $OutputBox.AppendText("Add SCCMPackagePath..")
    if ($PackagePath.Text -match '^[a-zA-Z]:\\') {
        $drive = Get-PSDrive -PSProvider FileSystem | Where-Object { $_.Name -match $PackagePath.Text[0] }
        $Path = $drive.DisplayRoot + $PackagePath.Text.Substring(2)
    }
    else { $Path = $PackagePath.Text }
    $WebPackage | Add-Member -NotePropertyName Path -NotePropertyValue $Path
    $OutputBox.AppendText(".Ok`n")
    return $WebPackage
}
Function New-SCCMPackage {
    [CmdletBinding()]
    Param (
        [Parameter(ValueFromPipeline = $true)]
        [ValidateNotNullorEmpty()]
        [PSCustomObject]$WebPackage
    )
    $OutputBox.AppendText("New SCCMPackage...")
    try {
        If ( ! (Get-Module ConfigurationManager)) {
            Import-Module 'C:\Program Files (x86)\Microsoft Configuration Manager\AdminConsole\bin\ConfigurationManager.psd1' -ErrorAction Stop
        }
        Set-Location 'CSP:' -ErrorAction Stop
    }
    catch {
        $error | out-file "$env:temp\SCCM_Workflow_${TodayDate}.log"
        $OutputBox.ForeColor = "#d0021b"
        $OutputBox.AppendText("`nError: Something went wrong, please check the %temp% log file!`n")
        throw
    }
    $OutputBox.AppendText("..")
    try {
        $SCCMPack = New-CMPackage -Name $WebPackage.SCCMPackageName -Version $WebPackage.Version -Manufacturer $WebPackage.Manufacturer`
            -Description $WebPackage.Description -Language $WebPackage.Language -Path $WebPackage.Path -ErrorAction Stop
    }
    catch {
        $error | out-file "$env:temp\SCCM_Workflow_${TodayDate}.log"
        $OutputBox.ForeColor = "#d0021b"
        $OutputBox.AppendText("`nError: Something went wrong, please check the %temp% log file!`n")
        throw
    }
    Set-CMPackage -Id "$($SCCMPack.PackageID)" -EnableBinaryDeltaReplication $true -PrestageBehavior ManualCopy
    Get-CMPackage -Id "$($SCCMPack.PackageID)" | Move-CMObject -FolderPath "CSP:\package\RYNT_PKG\TEST PACKAGES"
    $cDate = Get-Date -Format "dd-MMM-yyyy"
    $SCCMPack | Add-Member -NotePropertyName WorkflowID -NotePropertyValue $WebPackage.WorkflowID
    $SCCMPack | Add-Member -NotePropertyName Complexity -NotePropertyValue $WebPackage.POA_Complexity
    #$SCCMPack | Add-Member -NotePropertyName StartDate -NotePropertyValue $WebPackage.Modified
    $SCCMPack | Add-Member -NotePropertyName EndDate -NotePropertyValue $cDate
    $SCCMPack | Add-Member -NotePropertyName UserName -NotePropertyValue $env:UserName
    $OutputBox.AppendText("..Ok`n")
    return $SCCMPack
}
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
    New-CMProgram -PackageId "$($SCCMPackage.PackageID)" -StandardProgramName 'uninstall' -CommandLine $uninstallCommand -DiskSpaceRequirement $PackSize -DiskSpaceUnit $DiskUnit -Duration $Duration `
        -RunType Hidden -ProgramRunType WhetherOrNotUserIsLoggedOn -RunMode RunWithAdministrativeRights -UserInteraction $False
    Set-CMProgram -PackageId "$($SCCMPackage.PackageID)" -StandardProgramName 'uninstall' -StandardProgram -EnableTaskSequence $true -Category "Uninstall Applications"  -Comment $UnInstallProgramComment
    $OutputBox.AppendText("..Ok`n")
    return $SCCMPackage
}

Function Add-Xls {
    [CmdletBinding()]
    Param (
        [Parameter(ValueFromPipeline = $true)]
        [ValidateNotNullorEmpty()]
        [PSCustomObject]$SCCMPackage
    )
    $OutputBox.AppendText("Add Xlsx..........")
    try {
        If ( ! (Get-Module -ListAvailable ImportExcel)) {
            Install-Module ImportExcel -ErrorAction Stop
            #Write-Host "Imported module"
        }
    }
    catch {
        $error | out-file "$env:temp\SCCM_Workflow_${TodayDate}.log"
        #$OutputBox.ForeColor = "#d0021b"
        #$OutputBox.AppendText("`nError: Failed to install the Excel module, please check the %temp% log file!`n")
        throw
    }
    $OutputBox.AppendText("..")
    #$SCCMPackage = Get-CMPackage -Id "CSP03ABA"
    $MyDocs = [Environment]::GetFolderPath("MyDocuments")
    $SCCMPackage | Select-Object -Property PackageID, WorkflowID, Name, Complexity, SatrtDate, EndDate, Duration, UserName | Export-Excel "$MyDocs\PackageWorkflow.xlsx" -Append # -Show -IncludePivotTable -PivotRows status -PivotData @{status = 'count' }
    $OutputBox.AppendText("..Ok`n")
    return $SCCMPackage
}


Add-Type -AssemblyName System.Windows.Forms
[System.Windows.Forms.Application]::EnableVisualStyles()

# GUI Start { 

$Form = New-Object system.Windows.Forms.Form
$Form.ClientSize = '470,660'
$Form.text = "SCCM Workflow Package Creator"
$Form.TopMost = $false
$Form.Icon = [system.drawing.icon]::ExtractAssociatedIcon($PSHOME + "\powershell.exe")

$InstallProgramCommentBoxText = New-Object system.Windows.Forms.Label
$InstallProgramCommentBoxText.text = "Install Program Comment:"
$InstallProgramCommentBoxText.AutoSize = $true
$InstallProgramCommentBoxText.width = 25
$InstallProgramCommentBoxText.height = 10
$InstallProgramCommentBoxText.location = New-Object System.Drawing.Point(15, 137)
$InstallProgramCommentBoxText.Font = 'Microsoft Sans Serif,10'

$InstallProgramCommentBox = New-Object system.Windows.Forms.TextBox
$InstallProgramCommentBox.multiline = $false
$InstallProgramCommentBox.width = 435
$InstallProgramCommentBox.height = 20
$InstallProgramCommentBox.location = New-Object System.Drawing.Point(15, 162)
$InstallProgramCommentBox.Font = 'Microsoft Sans Serif,10'

$BrowseButton = New-Object system.Windows.Forms.Button
$BrowseButton.text = "Browse..."
$BrowseButton.width = 85
$BrowseButton.height = 39
$BrowseButton.location = New-Object System.Drawing.Point(366, 30)
$BrowseButton.Font = 'Microsoft Sans Serif,10'
$BrowseButton.Add_Click( {
        [System.Reflection.Assembly]::LoadWithPartialName("System.windows.forms") | Out-Null
        $FolderBrowserDialog = New-Object System.Windows.Forms.FolderBrowserDialog
        $FolderBrowserDialog.Description = "Select a folder"
        $FolderBrowserDialog.RootFolder = "MyComputer"
        $FolderBrowserDialog.ShowDialog()
        $PackagePath.Text = $FolderBrowserDialog.SelectedPath
        $PackSize = (Get-FolderSize $FolderBrowserDialog.SelectedPath) * 2
        $DiskSpace.Text = $PackSize
    })

$WorkflowIDText = New-Object system.Windows.Forms.Label
$WorkflowIDText.text = "Workflow ID: *"
$WorkflowIDText.AutoSize = $true
$WorkflowIDText.width = 25
$WorkflowIDText.height = 10
$WorkflowIDText.location = New-Object System.Drawing.Point(15, 72)
$WorkflowIDText.Font = 'Microsoft Sans Serif,10'

$WorkflowID = New-Object system.Windows.Forms.TextBox
$WorkflowID.multiline = $false
$WorkflowID.width = 435
$WorkflowID.height = 20
$WorkflowID.location = New-Object System.Drawing.Point(15, 97)
$WorkflowID.Font = 'Microsoft Sans Serif,10'
$WorkflowID.se

$UnInstallProgramCommentBox = New-Object system.Windows.Forms.TextBox
$UnInstallProgramCommentBox.multiline = $false
$UnInstallProgramCommentBox.width = 435
$UnInstallProgramCommentBox.height = 20
$UnInstallProgramCommentBox.location = New-Object System.Drawing.Point(15, 220)
$UnInstallProgramCommentBox.Font = 'Microsoft Sans Serif,10'

$UnInstallProgramCommentBoxText = New-Object system.Windows.Forms.Label
$UnInstallProgramCommentBoxText.text = "Uninstall Program Comment:"
$UnInstallProgramCommentBoxText.AutoSize = $true
$UnInstallProgramCommentBoxText.width = 25
$UnInstallProgramCommentBoxText.height = 10
$UnInstallProgramCommentBoxText.location = New-Object System.Drawing.Point(15, 197)
$UnInstallProgramCommentBoxText.Font = 'Microsoft Sans Serif,10'

$isPowershellPackage = New-Object system.Windows.Forms.CheckBox
$isPowershellPackage.text = "Powershell Package"
$isPowershellPackage.AutoSize = $false
$isPowershellPackage.width = 120
$isPowershellPackage.height = 20
$isPowershellPackage.location = New-Object System.Drawing.Point(51, 358)
$isPowershellPackage.Font = 'Microsoft Sans Serif,10'

$isBatchPackage = New-Object system.Windows.Forms.CheckBox
$isBatchPackage.text = "Batch"
$isBatchPackage.AutoSize = $false
$isBatchPackage.width = 69
$isBatchPackage.height = 20
$isBatchPackage.location = New-Object System.Drawing.Point(173, 358)
$isBatchPackage.Font = 'Microsoft Sans Serif,10'

$isExtensionPackage = New-Object system.Windows.Forms.CheckBox
$isExtensionPackage.text = "Chrome Extension"
$isExtensionPackage.AutoSize = $false
$isExtensionPackage.width = 188
$isExtensionPackage.height = 20
$isExtensionPackage.location = New-Object System.Drawing.Point(257, 358)
$isExtensionPackage.Font = 'Microsoft Sans Serif,10'

$DurationText = New-Object system.Windows.Forms.Label
$DurationText.text = "Duration (minutes):"
$DurationText.AutoSize = $true
$DurationText.width = 25
$DurationText.height = 10
$DurationText.location = New-Object System.Drawing.Point(15, 267)
$DurationText.Font = 'Microsoft Sans Serif,10'

$Duration = New-Object system.Windows.Forms.TextBox
$Duration.multiline = $false
$Duration.text = "40"
$Duration.width = 62
$Duration.height = 20
$Duration.location = New-Object System.Drawing.Point(144, 265)
$Duration.Font = 'Microsoft Sans Serif,10'

$DiskSpaceText = New-Object system.Windows.Forms.Label
$DiskSpaceText.text = "Package Size (MB):"
$DiskSpaceText.AutoSize = $true
$DiskSpaceText.width = 25
$DiskSpaceText.height = 10
$DiskSpaceText.location = New-Object System.Drawing.Point(252, 267)
$DiskSpaceText.Font = 'Microsoft Sans Serif,10'

$DiskSpace = New-Object system.Windows.Forms.TextBox
$DiskSpace.multiline = $false
$DiskSpace.width = 62
$DiskSpace.height = 20
$DiskSpace.enabled = $true
$DiskSpace.location = New-Object System.Drawing.Point(384, 265)
$DiskSpace.Font = 'Microsoft Sans Serif,10'

$MandatoryFields = New-Object system.Windows.Forms.Label
$MandatoryFields.text = "* Mandatory Fields"
$MandatoryFields.AutoSize = $true
$MandatoryFields.width = 25
$MandatoryFields.height = 10
$MandatoryFields.location = New-Object System.Drawing.Point(21, 640)
$MandatoryFields.Font = 'Microsoft Sans Serif,10'

$OutputBox = New-Object system.Windows.Forms.TextBox
$OutputBox.multiline = $true
$OutputBox.width = 438
$OutputBox.height = 243
$OutputBox.location = New-Object System.Drawing.Point(15, 394)
$OutputBox.Font = 'Consolas, 10pt'

$PackagePathText = New-Object system.Windows.Forms.Label
$PackagePathText.text = "Package Path: *"
$PackagePathText.AutoSize = $true
$PackagePathText.width = 25
$PackagePathText.height = 10
$PackagePathText.location = New-Object System.Drawing.Point(15, 10)
$PackagePathText.Font = 'Microsoft Sans Serif,10'

$PackagePath = New-Object system.Windows.Forms.TextBox
$PackagePath.multiline = $false
$PackagePath.width = 339
$PackagePath.height = 20
$PackagePath.location = New-Object System.Drawing.Point(15, 39)
$PackagePath.Font = 'Microsoft Sans Serif,10'
$PackagePath.Add_Leave( {
        $Path = $PackagePath.Text    
        if (($Path.Length -gt 7) -and ($DiskSpace.Text.Length -eq 0)) {
            $Path = Get-CorrectPath -ServerName $SCCMServer -Path $Path
            $PackSize = Get-FolderSize $Path
            $DiskSpace.Text = $PackSize
        }
    })

$OkButton = New-Object system.Windows.Forms.Button
$OkButton.text = "Ok"
$OkButton.width = 94
$OkButton.height = 30
$OkButton.location = New-Object System.Drawing.Point(129, 313)
$OkButton.Font = 'Microsoft Sans Serif,10'
$OKButton.Add_Click( {
        $StartTime = Get-Date   
        $OutputBox.Clear()
        $OutputBox.ResetForeColor()
        $SCCMPackFull = $WorkflowID.Text | Read-PortalData | Add-SCCMPackageName | Add-SCCMPackagePath | New-SCCMPackage | Add-SCCMPrograms | Add-Xls
        #$OutputBox.AppendText("`n")
        $OutputBox.AppendText("`n`nID = $($SCCMPackFull.PackageID)`n")
        $OutputBox.AppendText("Name = $($SCCMPackFull.Name)`n")
        $OutputBox.AppendText("Date = $($SCCMPackFull.SourceDate)`n")
        $OutputBox.AppendText("Sedo = $($SCCMPackFull.SedoObjectVersion)`n")
        $OutputBox.AppendText("Path = $($SCCMPackFull.PkgSourcePath)`n")
        $OutputBox.AppendText("Priority = $($SCCMPackFull.Priority)`n")
        $EndTime = Get-Date
        [string]$duration = [string]$EndTime.Subtract($StartTime).Minutes + "m " + [string]$EndTime.Subtract($StartTime).Seconds + "s"
        $OutputBox.AppendText("Duration: $duration `nDone.")
        if ($PackSize.Length -eq 0) { $OutputBox.ForeColor = "#f5a623"; $OutputBox.AppendText("`nWarning: Package Size could not be calculated !`n") }
    })

$CancelButton = New-Object system.Windows.Forms.Button
$CancelButton.text = "Cancel"
$CancelButton.width = 94
$CancelButton.height = 30
$CancelButton.location = New-Object System.Drawing.Point(234, 313)
$CancelButton.Font = 'Microsoft Sans Serif,10'
$CancelButton.Add_Click( { $Form.Close() })

$Form.controls.AddRange(@($PackagePath, $PackagePathText, $InstallProgramCommentBoxText, $InstallProgramCommentBox, $BrowseButton, $WorkflowIDText, $WorkflowID, $UnInstallProgramCommentBox, $UnInstallProgramCommentBoxText, $isPowershellPackage, $isBatchPackage, $isExtensionPackage, $DurationText, $Duration, $DiskSpaceText, $DiskSpace, $MandatoryFields, $OutputBox, $OkButton, $CancelButton))

$BrowseButton.TabIndex = 1
$WorkflowID.TabIndex = 2
$InstallProgramCommentBox.TabIndex = 3
$UnInstallProgramCommentBox.TabIndex = 4
$Duration.TabIndex = 5
$DiskSpace.TabIndex = 6
$OkButton.TabIndex = 7
$CancelButton.TabIndex = 8

# GUI end }

[void]$Form.ShowDialog()
