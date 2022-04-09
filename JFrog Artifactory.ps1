#requires -version 7
<#PSScriptInfo

.VERSION 1.6.0.0

.GUID 8e7b1029-c15f-46bf-bf19-d026b778c274

#>

<#

.SYNOPSIS
  Upload/Download files to/from JFrog

.DESCRIPTION
  JFrog Artifactory is a universal DevOps solution providing end-to-end automation and management of binaries and artifacts.
  
  -Action 'Upload' will seprate those bianry files in a Git repository, archive, password-protect and upload them on JFrog
  -Action 'Download' will download the JFroog binary and merge them with the existing files for a given Git repository.

  All actions are logged in the console for user review and: <RepositoryFolderPath>\RepositoryName.log
  The *.zip [that goes in Artifactory containing all the binary fiels] is created under $DirPath - the parrent dir of the repository
  file.exe - https://github.com/julian-r/file-windows/releases is needed for detecting binary files > 1 MB
  ICSharpCode.SharpZipLib.dll - https://github.com/icsharpcode/SharpZipLib compression library is laveraged for password-protected archives

.NOTES
          	 
.EXAMPLE
  "C:\Program Files\PowerShell\7\pwsh.exe"  -executionpolicy bypass -File "Artifactory.ps1" -Action Download -RepoPath %V
  "C:\Program Files\PowerShell\7\pwsh.exe"  -executionpolicy bypass -File "Artifactory.ps1" -Action Upload -RepoPath %V

#>

#------------------------------------------------------ [Script Parameters] -------------------------------------------------------
[CmdletBinding()]
param (
    [Parameter(Mandatory = $false)]
    [string]$RepoPath = "C:\GitLab\RepoName",
    [Parameter(Mandatory = $true)]
    [ValidateSet('Download', 'Upload')]
    [string]$Action = 'Download'
)

#----------------------------------------------------- [Script Variables] ----------------------------------------------
$DirPath = (Get-Item $RepoPath).Parent.FullName
$RepoName = (Get-Item $RepoPath).Name

$CurrDate = Get-Date -Format "yyyy-MM-dd_HHmmss"
[string]$LogPath = "$DirPath\$RepoName\$RepoName.log"
$NonBinaryExtensions = @(".html", ".ps1", ".vbs", ".au3", ".txt", ".md5", ".md", ".bat", ".wsf", ".bak",
    ".pem", ".properties", ".ini", ".xml", ".hta", ".yml", ".miaf", ".htm", ".rtf",
    ".mia", ".bok", ".brk", ".fld", ".mpr", ".css", ".cfg", ".js", ".h", ".m4",
    ".in", ".guess", ".sub", ".ac", ".sh", ".am", ".cmake", ".src", ".c", ".dist",
    ".supp", ".def", ".git", ".reg", ".sif", ".log", ".ps1xml", ".psd1", ".psm1",
    ".ion", ".manifest", ".json", ".crt", ".list", ".aff", ".dic", ".licenses",
    ".version", ".fingerprint", ".lng", ".map", ".sln", ".cpp", ".vcxproj", ".filters",
    ".user", ".tlog", ".lastbuildstate", ".drawio", ".cmd", ".csv", ".py", ".cs",
    ".config", ".url", ".wse", ".admx", ".adml", ".cmtx", ".inf", ".adm",
    ".PolicyRules", ".shtml", ".rdf", ".xul", ".emie", ".gitignore", ".app", ".coffee", ".flow", 
    ".flowconfig", ".editorconfig", ".emie", ".eslintignore", ".eslintrc", ".php", ".ts", ".str")
$GitLabAcceptedExtensions = @(".bmp", ".doc", ".docx", ".dxf", ".emf", ".eps", ".gif", ".jfif", ".jif", ".jpeg", ".jpg",
    ".met", ".midi", ".mov", ".mp2", ".mp3", ".mpg", ".mpeg", ".odf", ".odg", ".odm", ".odp",
    ".ods", ".otg", ".otp", ".ots", ".pbm", ".pcd", ".pct", ".pcx", ".pdf", ".pgm", ".png",
    ".pot", ".ppm", ".ppt", ".pptx", ".ps", ".psd", ".ras", ".rtf", ".sdc", ".sdd", ".sdp",
    ".sgf", ".sgv", ".smf", ".sta", ".stc", ".std", ".sti", ".svm", ".sxc", ".sxd", ".sxg",
    ".sxi", ".sxm", ".tga", ".tif", ".tiff", ".vor", ".vsd", ".wav", ".wmf", ".xbm", ".xlc",
    ".xlm", ".xls", ".xlsx", ".xlt", ".xlw", ".xpm", ".rpd")

#----------------------------------------------------- [Functions] ----------------------------------------------
Function Write-Log {
    <#
 .Synopsis
  Used to write to the log file.

 .Example
   ### Call Write-Log with -Caller (optional parameter).
   Write-Log -Message "Your message goes here" -Caller "Caller Name goes here"

 .Example
   ### Call Write-Log.
   Write-Log -Message "Your message goes here"
#>

    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $true, Position = 0, ValueFromPipeline = $true)]
        [ValidateNotNull()]
        [AllowEmptyString()]
        # Mandatory. Specifies the message string.
        [string]$Message,
        [Parameter(Mandatory = $false, Position = 1)]
        # Optional. Specifies the message color in the powershell console White(default) Green Blue Yellow DarkYellow Red
        [string]$Color = 'White',
        [Parameter(Mandatory = $false, Position = 2)]
        # Optional. Specifies the message color in the powershell console White(default) Green Blue Yellow DarkYellow Red
        [string]$BackgroundColor = '',
        [Parameter(Mandatory = $false, Position = 3)]
        [ValidateNotNull()]
        # Optional. Specifies the name of the message writter. Function, command or custom name. Defaults to FunctioName or unknown
        [string]$Caller = 'Unknown'
    )
    Begin {
        [string]$LogDate = (Get-Date -Format 'MM-dd-yyyy').ToString()
        [string]$LogTime = (Get-Date -Format 'HH\:mm\:ss.fff').ToString()
        [string]${CmdletName} = $PSCmdlet.MyInvocation.MyCommand.Name
        #if ([string]::IsNullOrEmpty($Message)) { return }
    }
    Process {
        #if ([string]::IsNullOrEmpty($Message)) { return }
        ForEach ($Msg in $Message) {
            If ($Msg) {
                [string]$CompleteMsg = "[$LogDate $LogTime] [${Caller}] :: $Msg"
                #Try {
                if ($BackgroundColor -eq '') {
                    $CompleteMsg | Write-Host -ForegroundColor $Color
                }
                else {
                    $CompleteMsg | Write-Host -ForegroundColor $Color -BackgroundColor $BackgroundColor 
                }
                $CompleteMsg | Out-File -FilePath $LogPath -Append -NoClobber -Force -Encoding 'UTF8' -ErrorAction 'Stop' 
                #}
                #Catch {
                # Write-Error2 -Message  "[$LogDate $LogTime] [${CmdletName}] :: Failed to write message [$Msg] to the log file [$LogPath]" -Category WriteError
                #}
            }
        }
    }
    End {}
}

function Write-Error2 {
    <#
     .Synopsis
      Used to dump errors to the log file. Parameters needed only for a collection.
     .Example
     ###
     Write-Error2
    #>
    
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $false, Position = 0)]
        [AllowEmptyCollection()]
        # Optional. The errorr collection.
        [array]$ErrorRecord,
        [Parameter(Mandatory = $false, Position = 1)]
        [AllowEmptyCollection()]
        # Optional.
        [switch]$Pause
    )
    Begin {
        [string]${CmdletName} = $PSCmdlet.MyInvocation.MyCommand.Name
        If (-not $ErrorRecord) {
            If ($global:Error.Count -eq 0) {
                Return
            }
            Else {
                [array]$ErrorRecord = $global:Error[0]
            }
        }
    }
    Process {
        $ErrorRecord | ForEach-Object {
            $errNumber = $ErrorRecord.count - $( $ErrorRecord.IndexOf($_))
            $_.CategoryInfo | Write-Log -Caller "${CmdletName} Nr. $errNumber"  -Color Red
            #$_.InvocationInfo.Line | Write-Log -Caller "Error Nr. $errNumber"
            #"$($($Error[2].InvocationInfo).ScriptName): $($($Error[2].InvocationInfo).ScriptLineNumber) char:$($($Error[2].InvocationInfo).OffsetInLine)"
            $_ | Write-Log -Caller "${CmdletName} Nr. $errNumber" -Color Red
            $_.InvocationInfo.PositionMessage | Write-Log -Caller "${CmdletName} Nr. $errNumber" -Color Red
            if ($Pause) {
                Write-Log "Please review before continuing!" -BackgroundColor DarkMagenta -Color Yellow -Caller $CmdletName
                Pause
            }
        }
    }
    End {}
}
Function Copy-Files {
    <#
     .Synopsis
      Used to copy one or more files.
     .Example
      ### 
      Copy-Files -Path "C:\OrclOASIS\Source\*" -Destination "C:\OrclOASIS\Destination\" -StopOnError
      Copy-Files -Path "C:\OrclOASIS\Source\TestFolder\" -Destination "C:\OrclOASIS\Destination\"
     .Example
       ### 
      Copy-Files -Path "C:\OrclOASIS\SourceFile.txt" -Destination "C:\OrclOASIS\Destination\"
      Copy-Files -Path "C:\OrclOASIS\SourceFile.txt" -Destination "C:\OrclOASIS\Destination\DestinationFile.txt" -StopOnError
    #>
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $true, Position = 0, ValueFromPipeline = $true)]
        [ValidateNotNullorEmpty()]
        # Mandatory. Source path.
        [System.Collections.ArrayList]$Source,
        [Parameter(Mandatory = $true)]
        [ValidateNotNullorEmpty()]
        # Mandatory. Destination path.
        [string]$DestinationDir,
        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        # Optional. If specified teh fucntion will stop when the first error is encountered.
        [switch]$StopOnError
    )
    Begin {
        [string]${CmdletName} = $PSCmdlet.MyInvocation.MyCommand.Name
        Write-Log -Message "Destination: $DestinationDir\$RepoName" -Caller $CmdletName
    }
    Process {
        Try {
            $Path = $_.FullName
            $ChildStructure = $_.DirectoryName -replace ([regex]::Escape($RepoPath)), ''
            $Destination = "$DestinationDir\$RepoName$ChildStructure"
  
            If ((!([IO.Path]::HasExtension("$Destination\"))) -and (!(Test-Path -Path $Destination -PathType 'Container'))) {
                Write-Log -Message "Destination folder does not exist, creating $Destination." -Caller ${CmdletName}
                New-Item -Path $Destination -Type 'Directory' -Force -ErrorAction 'Stop' | Out-Null
            }
            If ($StopOnError) {
                $null = Copy-Item -Path $Path -Destination $Destination -Force -Recurse -ErrorAction 'Stop'
            }
            Else {
                $null = Copy-Item -Path $Path -Destination $Destination -Force -Recurse -ErrorAction 'SilentlyContinue' -ErrorVariable '+ErrorCopyFiles'
            }
            Write-Log -Message "[$Path] copied to [$Destination]." -Caller ${CmdletName}
            if ($ErrorCopyFiles) {
                Write-Log -Message "ErrorRecordNumber = $($ErrorCopyFiles.Count)" -Caller $CmdletName
                Write-Log -Message "The following errors were encontered while copy file(s) from [$Path] to [$Destination]"
                Write-Error2 -ErrorRecord $ErrorCopyFiles
            }
            Copy-Item -Path $Path -Destination $Destination -Force -Recurse -ErrorAction 'Stop'
        }
        Catch {
            Write-Log -Message "Failed to copy [$Path] to destination $Destination." -Caller ${CmdletName}
            Write-Error2 -Pause
            Throw "Failed to copy file [$path]: $($_.Exception.Message)"
        }
    }
    End {
        Write-Log "OK" -Caller $CmdletName -Color Green
    }
}
Function Remove-Folder {
    <#
     .Synopsis
      Used to delete a folder.
     .Example
      ### 
      Remove-Folder -Path "C:\OrclOASIS\Source"
    #>
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $true, Position = 0)]
        [ValidateNotNullorEmpty()]
        # Mandatory. Folder to be deleted.
        [string[]]$Path
    )
    Begin {
        [string]${CmdletName} = $PSCmdlet.MyInvocation.MyCommand.Name
        Write-Log -Message "$Path" -Caller $CmdletName
    }
    Process {
        Try {
            If (-not (Test-Path -Path $Path -PathType 'Container')) {
                Write-Log -Message "Folder $Path does not exist." -Caller ${CmdletName}
            }
            else {
                Write-Log -Message "Removing $Path." -Caller ${CmdletName}
                Remove-Item -Path $Path -Force -Recurse -ErrorAction 'SilentlyContinue' -ErrorVariable '+ErrorRemoveFolder'
            }
            if ($ErrorRemoveFolder) {
                Write-Log -Message "ErrorRecordNumber = $($ErrorRemoveFolder.Count)" -Caller $CmdletName
                Write-Log -Message "The following errors were encontered while removing folder [$Path]" -Caller $CmdletName -Color Yellow
                Write-Error -ErrorRecord $ErrorRemoveFolder
            }
        }
        Catch {
            Write-Log -Message "Failed to remove folder $Path." -Caller ${CmdletName} -Color Yellow
            Write-Error
        }
    }
    End {
        Write-Log "OK" -Caller $CmdletName -Color Green
    }
}

Function Write-Gitignore {
    <#
 .Synopsis
  Used to write to the .gitignore file.

 .Example
   ### $BinaryFiles | Write-Gitignore
#>
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $true, Position = 0, ValueFromPipeline = $true)]
        [ValidateNotNullorEmpty()]
        # Mandatory. Source path.
        [System.Collections.ArrayList]$Files
    )
    Begin {
        [string]${CmdletName} = $PSCmdlet.MyInvocation.MyCommand.Name
        $GitIgnoreContent = [System.Collections.ArrayList]::new()
        # Write-Log -Message "Start" -Caller $CmdletName
        If (-not (Test-Path -LiteralPath "$DirPath\$RepoName\.gitignore" -PathType 'Leaf')) {
            #[System.Collections.ArrayList]$GitIgnoreContent = @()
            [void]$GitIgnoreContent.Add('#')
            Try {
                $null = New-Item -Path "$DirPath\$RepoName\.gitignore" -ItemType 'File' -Force -ErrorAction 'Stop'
            }
            Catch {
                Write-Error2 -Pause
                # Write-Log
                #Write-Error -Message  "[$LogDate $LogTime] [${CmdletName}] :: Failed to create .gitignore" -Category WriteError
            }
        }
        else {
            [System.Collections.ArrayList]$GitIgnoreContent = @(Get-Content "$DirPath\$RepoName\.gitignore")
        }
        if ($GitIgnoreContent -eq $null  ) { 
            $GitIgnoreContent = [System.Collections.ArrayList]::new()
            [void]$GitIgnoreContent.Add('#')
        }
    }
    Process {
        $FilePathGitFormat = $_.FullName -replace [Regex]::Escape("$DirPath\$RepoName"), ''
        $FilePathGitFormat = $FilePathGitFormat -replace '\\', '/'
        $GitIgnoreContentC = $GitIgnoreContent | ForEach-Object { $_.replace('"', '') }
        if ($GitIgnoreContentC -notcontains $FilePathGitFormat) {
            Write-Log -Message "Adding $FilePathGitFormat to $DirPath\$RepoName\.gitignore" -Caller $CmdletName
            $GitIgnoreContent.Add($FilePathGitFormat) | Out-Null
            $GotNewContent = $true
        }
        else { Write-Log -Message "$FilePathGitFormat already in $DirPath\$RepoName\.gitignore" -Caller $CmdletName }
    }
    End {
        try {
            if ($GotNewContent) { Set-Content -Path "$DirPath\$RepoName\.gitignore" -Value $GitIgnoreContent }
        }
        catch {
            Write-Error2
        }
        Write-Log "OK" -Caller $CmdletName -Color Green
    }
}

Function Invoke-Artifactory {
    <#
 .Synopsis
  Used to write to the log file.

 .Example
   ### Invoke-Artifactory -Upload -ZipToUpload  "<PathTo>\RepoName.zip"
 .Example
   ### Invoke-Artifactory -Download
#>
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $false, Position = 0)]
        [switch]$Download,
        [Parameter(Mandatory = $false, Position = 1)]
        [switch]$Upload,
        [Parameter(Mandatory = $false, Position = 2)]
        [string]$ZipToUpload

    )
    [string]${CmdletName} = $PSCmdlet.MyInvocation.MyCommand.Name
    $Url = 'https://artifacthub-iad.oci.MyCompanycorp.com'
    $ArfifactoryFolder = "oit-ees-windows-sources"
    Write-Log "Download = $Download; Upload = $Upload" -Caller $CmdletName
    if ($Download) {
        #            $JFrogURL = "$Url/artifactory/oit-ees-windows-builds/$RepoName/${RepoName}-latest.zip"
        $params = @{             
            ContentType = "application/zip"
            Headers     = @{"X-JFrog-Art-Api" = $APIKey }
            Method      = 'Get'
            #InFile = $Deploy.Source
            OutFile     = "$DirPath\$RepoName.zip"
            Uri         = "$Url/artifactory/$ArfifactoryFolder/$RepoName/$RepoName-latest.zip"
            Verbose     = $false
        }
        #Invoke-RestMethod -Uri $JFrogURL_dl -Method Get -ContentType "application/zip" -Header $JFrogHeader -OutFile 'c:\temp\ab.zip'
    }
    elseif ($Upload) {
        # check if file exists
        $params_FileInfo = @{
            ContentType = "application/zip"
            Headers     = @{"X-JFrog-Art-Api" = $APIKey }
            Method      = 'Get'
            Uri         = "$Url/api/storage/$ArfifactoryFolder/$RepoName/$RepoName-latest.zip"
            Verbose     = $false
        }
        # rename (move) the file
        $params_rename = @{
            ContentType = "application/zip"
            Headers     = @{"X-JFrog-Art-Api" = $APIKey }
            Method      = 'Post'
            Uri         = "$Url/api/move/$ArfifactoryFolder/$RepoName/$RepoName-latest.zip?to=$ArfifactoryFolder/$RepoName/$($RepoName)_$CurrDate.zip"
            Verbose     = $false
        }
        # upload the file
        $params = @{              
            ContentType = "application/zip"
            Headers     = @{"X-JFrog-Art-Api" = $APIKey }
            Method      = 'Put'
            InFile      = $ZipToUpload
            Uri         = "$Url/artifactory/$ArfifactoryFolder/$RepoName/$RepoName-latest.zip"
            Verbose     = $false
        }
    }
    else {

    }
    try {
        #Invoke-RestMethod @params -ErrorAction Stop
        if ($params_rename.Count -ne 0) {
            # comment this if block for error Failed to move .... Could not find item ....RepoName-latest.zip
            # or if Action = Upload...
            # first check if file exists...... params_FileInfo but not done yet... then rename (move) the file [To Do list]
            Write-Log "Rename request for $($params.Uri)" -Caller $CmdletName
            $params_rename.GetEnumerator() | Sort-Object -Property Name | ForEach-Object { "$($_.Key) = $($_.Value)" | Write-Log -Caller $CmdletName }
            $RenameResult = Invoke-RestMethod @params_rename -ErrorAction Stop
            $RenameResult.messages.level, $RenameResult.messages.message | Write-Log -Caller $CmdletName
            Write-Log "Rename OK" -Caller $CmdletName -Color Green
        }
        # This will either be the download or the update call
        if ($Download) { Write-Log "Download request for $($params.Uri)" -Caller $CmdletName } else { Write-Log "Upload request for $($params.Uri)" -Caller $CmdletName }
        $params.GetEnumerator() | Sort-Object -Property Name | ForEach-Object { "$($_.Key) = $($_.Value)" | Write-Log -Caller $CmdletName }
        if ($Download -and (Test-Path $params.OutFile)) {
            Write-Log "$($params.OutFile) already exists." -BackgroundColor Black -Color Yellow -Caller $CmdletName
            Write-Log "This file will be overwritten if you choosse to continue." -BackgroundColor DarkMagenta -Color Yellow -Caller $CmdletName
            pause
        }
        #[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        if ($Upload) {
            [int]$FileSize = (Get-Item  "$DirPath\$RepoName.zip").Length / 1mb
            Write-Log "Uploading $FileSize MB. Please wait...." -Caller $CmdletName
        }
        $DlUpResult = Invoke-RestMethod @params -ErrorAction Stop
        $DlUpResult | Write-Log -Caller $CmdletName
        if ($Download) { Write-Log "Download OK" -Caller $CmdletName -Color Green } else { Write-Log "Upload OK" -Caller $CmdletName -Color Green }

    }
    catch {
        Write-Error2
        $result = $_.Exception.Response.GetResponseStream()
        $reader = New-Object System.IO.StreamReader($result)
        $reader.BaseStream.Position = 0
        $reader.DiscardBufferedData()
        $ResultInfo = $reader.ReadToEnd();
        $ResultInfo | Write-Log -Caller $CmdletName
        pause
    }
}
Function Set-Zip {
    <#
 .Example
   ### Set-Zip -Source "C:\FolderToBeZipped" -Destination "C:\Destination.zip" -Compress
   ### Set-Zip -Source "C:\ZippedFile.zip" -Destination "C:\DestinationFolder" -Expand
#>
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $true, Position = 0)]
        [string]$Source,
        [Parameter(Mandatory = $true, Position = 1)]
        [string]$Destination,
        [Parameter(Mandatory = $false, Position = 2)]
        [switch]$Compress,
        [Parameter(Mandatory = $false, Position = 3)]
        [switch]$Expand
    )
    Begin {
        [string]${CmdletName} = $PSCmdlet.MyInvocation.MyCommand.Name
        try { 
            $SharpZip = Get-ItemPropertyValue 'HKLM:\SOFTWARE\MyCompany\Artifactory' -Name SharpZip -ErrorAction Stop
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            "Key HKLM:\SOFTWARE\MyCompany\Artifactory not found", "The script will now exit!" | Write-Log -Color Red -Caller $CmdletName
            Pause; Exit
        }
        catch [System.Management.Automation.PSArgumentException] {
            "Registry SharpZip does not exist under HKLM:\SOFTWARE\MyCompany\Artifactory\", "The script will now exit!" | Write-Log -Color Red -Caller $CmdletName
            Pause; Exit
        }
        [void][System.Reflection.Assembly]::LoadFrom($SharpZip)
        $ObjZip = New-Object ICSharpCode.SharpZipLib.Zip.FastZip
        $ObjZip.Password = $ZipPass
        "Compress = $Compress Expand = $Expand", "Source = $Source", "Destination = $Destination" | Write-Log -Caller $CmdletName
    }
    Process { }
    End {
        try {
            if ($Compress) {
                "Compressing $($BinaryFiles.count) files. Please wait..." | Write-Log -Caller $CmdletName
                $ObjZip.CreateZip($Destination, $Source, $true, "")
            }
            else {
                [int]$ZipSize = (Get-Item $Source).Length / 1mb
                Write-Log "Extracting $ZipSize MB. Please wait..." -Caller $CmdletName
                $ObjZip.ExtractZip($Source, $Destination, "")
            }
        }
        catch {
            Write-Error2
        }
        Write-Log "OK" -Caller $CmdletName -Color Green
    }
}
#----------------------------------------------------- [ End Functions] ----------------------------------------------

# ---------------------------------------------------- [ Prerequisite-Check ] -------------------------------------------------
"==================================================================================" | Write-Log -Caller 'Start'
# RepoPath is a Directory with the .git Child Directory
if ((Get-Item $RepoPath) -isnot [System.IO.DirectoryInfo]) {
    "`"$RepoPath`" has to be a directory!", "The script will now exit!" | Write-Log -Color Red -Caller 'Prerequisite-Check'
    Pause; Exit
}
if ((Get-ChildItem $RepoPath -Directory -Hidden).Name -ne '.git') {
    "`"$RepoPath`" doesn't seem to be a GIT repository.", "The .git folder is missing!", "The script will now exit!" | Write-Log -Color Red -Caller 'Prerequisite-Check'
    Pause; Exit
}
# File.exe is present. Used for Binary check fallback
try { 
    $ToolPath = Get-ItemPropertyValue 'HKLM:\SOFTWARE\MyCompany\Artifactory' -Name FileDotExe -ErrorAction Stop
    "ToolPath=$ToolPath" | Write-Log -Caller 'Prerequisite-Check'
}
catch [System.Management.Automation.ItemNotFoundException] {
    "Key HKLM:\SOFTWARE\MyCompany\Artifactory not found", "The script will now exit!" | Write-Log -Color Red -Caller 'Prerequisite-Check'
    Pause; Exit
}
catch [System.Management.Automation.PSArgumentException] {
    "Registry FileDotExe does not exist under HKLM:\SOFTWARE\MyCompany\Artifactory\", "The script will now exit!" | Write-Log -Color Red -Caller 'Prerequisite-Check'
    Pause; Exit
}
# API Key is present
try { 
    $APIKey = Get-ItemPropertyValue 'HKLM:\SOFTWARE\MyCompany\Artifactory' -Name APIKey -ErrorAction Stop
}
catch [System.Management.Automation.ItemNotFoundException] {
    "Key HKLM:\SOFTWARE\MyCompany\Artifactory not found", "The script will now exit!" | Write-Log -Color Red -Caller 'Prerequisite-Check'
    Pause; Exit
}
catch [System.Management.Automation.PSArgumentException] {
    "Registry APIKey does not exist under HKLM:\SOFTWARE\MyCompany\Artifactory\", "The script will now exit!" | Write-Log -Color Red -Caller 'Prerequisite-Check'
    Pause; Exit
}
# Password is present
try { 
    $ZipPass = Get-ItemPropertyValue 'HKLM:\SOFTWARE\MyCompany\Artifactory' -Name ZipPass -ErrorAction Stop
}
catch [System.Management.Automation.ItemNotFoundException] {
    "Key HKLM:\SOFTWARE\MyCompany\Artifactory not found", "The script will now exit!" | Write-Log -Color Red -Caller 'Prerequisite-Check'
    Pause; Exit
}
catch [System.Management.Automation.PSArgumentException] {
    "Registry ZipPass does not exist under HKLM:\SOFTWARE\MyCompany\Artifactory\", "The script will now exit!" | Write-Log -Color Red -Caller 'Prerequisite-Check'
    Pause; Exit
}



# ---------------------------------------------------- [ EXECUTION ] -------------------------------------------------

if ($Action -eq 'Upload') {
    "$env:USERNAME | Repository: $RepoPath | $Action $([char]0x25B2) $([char]0x25B2) $([char]0x25B2)" | Write-Log -Caller 'Execution' -Color Cyan
    pause
    # Create file array lists
    $TextFiles = [System.Collections.ArrayList]@()              # GitLab
    $TextFilesFileDotExe = [System.Collections.ArrayList]@()    # GitLab
    $GitLabAcceptedFiles = [System.Collections.ArrayList]@()    # GitLab
    $UnknownFiles1MBOrLess = [System.Collections.ArrayList]@()  # GitLab
    $BinaryFiles = [System.Collections.ArrayList]@()            # JFrog
    #<#
    # Check each file & put it in the coresponding list
    Get-ChildItem "$DirPath\$RepoName" -File -Recurse | ForEach-Object { 
        if ($NonBinaryExtensions -contains $_.Extension) {
            $TextFiles.Add($_)
        }
        elseif (($GitLabAcceptedExtensions -contains $_.Extension) -and ($_.Length / 1mb -lt 30)) {
            $GitLabAcceptedFiles.Add($_)
        }
        elseif (($_.Length / 1mb -lt 0.94)) {
            $UnknownFiles1MBOrLess.Add($_)
        }
        else {
            $CheckExeOutput = (&$ToolPath $_.FullName) | Out-String
            $OutputArr = $CheckExeOutput -split ':'
            if ($OutputArr[1] -match 'text') {
                $TextFilesFileDotExe.Add($_)  
            }
            else { $BinaryFiles.Add($_) }
        }
    }
    # write the results for user to review
    $TextFiles.FullName | Write-Log -Caller 'Non-Binary by extension ==> GitLab'
    $GitLabAcceptedFiles.FullName | Write-Log -Color 'Green' -Caller 'Accepted Binary < 30 MB ==> GitLab'
    $TextFilesFileDotExe.FullName | Write-Log -Color 'Yellow' -Caller 'Non-Binary by TOOL ==> GitLab'
    $UnknownFiles1MBOrLess.FullName | Write-Log -Color 'DarkGreen' -Caller 'Unknown file type 1 MB or less ==> GitLab'
    $BinaryFiles.FullName | Write-Log -Color 'Cyan' -Caller 'Binary by TOOL ==> Artifactory'
    Read-Host "Press Enter to continue."
    # if ok then archive the binary files
    if ($BinaryFiles.Count -ne 0) {
        #$BinaryFiles | Copy-Files -Destination $env:TEMP
        #Write-Log "Creating archive: $DirPath\$RepoName.zip" -Caller "Compress-Archive"
        $BinaryFiles | Copy-Files -Destination "$env:TEMP\$RepoName"
        try {
            #if (Test-Path "$env:TEMP\$RepoName") {"$env:TEMP\$RepoName" | Compress-Archive -DestinationPath "$DirPath\$RepoName.zip" -Force -ErrorAction Stop}
            #Write-Log "OK" -Caller "Compress-Archive" -Color Green
            if (Test-Path "$env:TEMP\$RepoName") { Set-Zip -Source "$env:TEMP\$RepoName" -Destination "$DirPath\$RepoName.zip" -Compress -ErrorAction Stop }
        }
        catch {
            Write-Error2 -Pause
        }
        Remove-Folder "$env:TEMP\$RepoName"
        #   Read-Host "Press Enter to continue."
        # JFrog upload & write .gitignore
        Invoke-Artifactory -Upload -ZipToUpload  "$DirPath\$RepoName.zip"
        $BinaryFiles | Write-Gitignore
    }
    else {
        Write-Log "No binary files found. Nothing to upload." -Caller "Info" -Color Green
    }
}
else { 
    # Action = Download
    "$env:USERNAME | Repository: $RepoPath | $([char]0x25BC) $([char]0x25BC) $([char]0x25BC) $Action" | Write-Log -Caller 'Execution' -Color Yellow
    Pause
    Invoke-Artifactory -Download
    if (Test-Path -Path "$DirPath\$RepoName.zip") {
        if (Test-Path -Path $DirPath\$RepoName -PathType 'Container') {
            Write-Log "All the binary files under $DirPath\$RepoName\ will be overwritten if you choosse to continue." -BackgroundColor DarkMagenta -Color Yellow -Caller "Expand-Archive"
            Pause
        }
        try {
            #Write-Log "Expanding archive: $DirPath\$RepoName.zip" -Caller "Expand-Archive"
            #Expand-Archive -Path "$DirPath\$RepoName.zip" -Force -DestinationPath "$DirPath\" -ErrorAction Stop
            #Write-Log "OK" -Caller "Expand-Archive" -Color Green
            Set-Zip -Source "$DirPath\$RepoName.zip" -Destination $DirPath -Expand -ErrorAction Stop
        }
        catch {
            Write-Error2 -Pause
        }
    }
    else {
        "No *.zip was downloaded.", "Most likely there is nothing on JFrog but please check. [on the To Do list]" | Write-Log -Caller "Info" -Color Yellow
    }

}
Read-Host "[======= The End =======] Press Enter to exit."
#>
