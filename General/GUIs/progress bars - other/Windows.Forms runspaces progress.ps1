Function Start-Worker {
    $SyncHash = [hashtable]::Synchronized(@{TextBox = $TextBox })
    $Runspace = [runspacefactory]::CreateRunspace()
    $Runspace.ThreadOptions = "UseNewThread"                    # Also Consider: ReuseThread  
    $Runspace.Open()
    $Runspace.SessionStateProxy.SetVariable("SyncHash", $SyncHash)          
    $Worker = [PowerShell]::Create().AddScript({
            $ThreadID = [appdomain]::GetCurrentThreadId()
            $SyncHash.TextBox.Text = "Thread $ThreadID has started"
            for ($Progress = 0; $Progress -le 100; $Progress += 10) {
                $SyncHash.TextBox.Text = "Thread $ThreadID at $Progress%"
                Start-Sleep 1                                       # Some background work
            }
            $SyncHash.TextBox.Text = "Thread $ThreadID has finnished"
        })
    $Worker.Runspace = $Runspace
    $Worker.BeginInvoke()
}

[Void][System.Reflection.Assembly]::LoadWithPartialName("System.Windows.Forms")
$Form = New-Object Windows.Forms.Form
$TextBox = New-Object Windows.Forms.TextBox
$TextBox.Visible = $False
$TextBox.Add_TextChanged({ Write-Host $TextBox.Text })
$Form.Controls.Add($TextBox)
$Button = New-Object System.Windows.Forms.Button
$Button.Text = "Start worker"
$Button.Add_Click({ Start-Worker })
$Form.Controls.Add($Button)
$Form.ShowDialog()
