$FolertPath = 'c:\$windows.~bt\sources\panther'
$OutputData = New-Object System.Collections.ArrayList
$ExitCode = 0
if (Test-Path "$FolertPath\CompatData*xml") {
    try {
        $LatestXml = (Get-ChildItem -Path "$FolertPath\CompatData*xml" | Sort-Object LastWriteTime)[0]
        [XML]$LogContent = Get-Content -LiteralPath $LatestXml -Encoding UTF8
        # ============ Get the blocking issues by category. ============
        # === HARDWARE BLOCKERS ===
        [array]$HardwareBlockers = $LogContent.CompatReport.Hardware.HardwareItem |
        Where-Object { $_.InnerXml -match 'BlockingType="Hard"' }
        if ($HardwareBlockers.Count -gt 0) {
            foreach ($Item in $HardwareBlockers) {
                $OutputData += [PsCustomObject]@{
                    Device    = $($env:ComputerName)
                    Category  = 'Issue'
                    Type      = 'Hardware'
                    Details   = '#N/A'
                    HWTitle   = ($Item.CompatibilityInfo.Title | Out-String).Trim()
                    HWMessage = ($Item.CompatibilityInfo.Message | Out-String).Trim()
                    PrgName   = '#N/A'
                    PrgAction = '#N/A'
                }
            }
        }
        # === SOFTWARE BLOCKERS ===
        [array]$ProgramBlockers = $LogContent.CompatReport.Programs |
        Where-Object { $_.InnerXml -match 'BlockingType="Hard"' }
        if ($ProgramBlockers.Count -gt 0) {
            foreach ($Item in $ProgramBlockers) {
                $OutputData += [PsCustomObject]@{
                    Device    = $($env:ComputerName)
                    Category  = 'Issue'
                    Type      = 'Program'
                    Details   = '#N/A'
                    HWTitle   = '#N/A'
                    HWMessage = '#N/A'
                    PrgName   = ($Item.Program.Name | Out-String).Trim()
                    PrgAction = ($Item.Program.Action.Name | Out-String).Trim()
                }
            }
        }
    }
    catch {
        $OutputData += [PsCustomObject]@{
            Device    = $($env:ComputerName)
            Category  = 'Message' # Message, Issue
            Type      = 'Error' # Info, Warning or Error
            Details   = ($_.exception -replace '[^\p{L}\p{Nd}]', '')
            HWTitle   = '#N/A'
            HWMessage = '#N/A'
            PrgName   = '#N/A'
            PrgAction = '#N/A'
        }
        $ExitCode = 20
    }
}
if ($OutputData.count -ne 0) {
    Write-Output $OutputData
}
Exit $ExitCode
