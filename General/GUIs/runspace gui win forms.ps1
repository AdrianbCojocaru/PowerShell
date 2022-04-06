Add-Type -AssemblyName System.Windows.Forms

$buttonStart = New-Object 'System.Windows.Forms.Button'
$buttonStop = New-Object 'System.Windows.Forms.Button'
$timer = New-Object 'System.Windows.Forms.Timer'

$BGScriptBlock = { 
    param($pcc)
    for ($i = 0; $i -lt 5; $i++) {
        $tc = (Test-Connection -ComputerName 8.8.8.8 -Verbose -Count 1)
        $reply = "#$pcc" + $i + "`tAddress: " + $tc.Address + "`tSize: " + $tc.ReplySize + "`tTime: " + $tc.ResponseTime + "ms`r`n"
        $synchash.form.Controls[2].Text = $reply + $synchash.form.Controls[2].Text
        
        start-sleep -Seconds 1
    }
    return "OK"
}

$Global:synchash = [Hashtable]::Synchronized(@{  })
$script:Powershell = [PowerShell]::Create().AddScript($BGScriptBlock).AddArgument('MyPc')
$sessionstate = [system.management.automation.runspaces.initialsessionstate]::CreateDefault()
$runspace = [RunspaceFactory]::CreateRunspace($sessionstate)
$runspace.ApartmentState = "STA"
$runspace.ThreadOptions = "ReuseThread"
$runspace.Open()
$runspace.SessionStateProxy.SetVariable("synchash", $synchash)
$Powershell.Runspace = $runspace

$buttonStart_Click = {
    $script:AsyncResult = $Powershell.BeginInvoke()
    $timer.Enabled = $true; $timer.Start(); $script:tick = 0
}

$buttonStop_Click = {
    $Powershell.Stop()
    $Form.Text = 'Stopped'
    $timer.Stop()
    $timer.Enabled = $false
    
}

$TimerTick = {
    $script:tick++;
    $script:Powershell.InvocationStateInfo.State
}


$Form = New-Object System.Windows.Forms.Form    
$Form.Size = New-Object System.Drawing.Size(600, 400)  
$Form.StartPosition = "CenterScreen"
$Form.Text = 'Form'
$Form.Topmost = $true

$timer.Interval = 1000
$timer.add_Tick($TimerTick)
$synchash.form = $Form

$Button = New-Object System.Windows.Forms.Button 
$Button.Location = New-Object System.Drawing.Size(20, 30) 
$Button.Size = New-Object System.Drawing.Size(110, 80) 
$Button.Text = "START" 
$Button.BackColor = "LightGreen"
$Button.Cursor = [System.Windows.Forms.Cursors]::Hand
$Button.Font = New-Object System.Drawing.Font("Calibri", 11, [System.drawing.FontStyle]::Bold) 
$Button.Add_Click($buttonStart_Click) 
$Form.Controls.Add($Button) 

$StopButton = New-Object System.Windows.Forms.Button 
$StopButton.Location = New-Object System.Drawing.Size(140, 30) 
$StopButton.Size = New-Object System.Drawing.Size(110, 80) 
$StopButton.Text = "STOP" 
$StopButton.BackColor = "Red"
$StopButton.Cursor = [System.Windows.Forms.Cursors]::Hand
$StopButton.Font = New-Object System.Drawing.Font("Calibri", 11, [System.drawing.FontStyle]::Bold) 
$StopButton.Add_Click($buttonStop_Click)
$Form.Controls.Add($StopButton)

$outputBox = New-Object System.Windows.Forms.TextBox 
$outputBox.Location = New-Object System.Drawing.Size(10, 180) 
$outputBox.Size = New-Object System.Drawing.Size(565, 100) 
$outputBox.MultiLine = $True 
$outputBox.SelectionStart = $outputBox.Text.Length;
$outputBox.ScrollToCaret() = $true
$outputBox.ScrollBars = "Vertical"
$outputBox.Text = ""
$Form.Controls.Add($outputBox) 

$Form.ShowDialog()
$Form.add_FormClosing({
        $Powershell.Dispose()
        $runspace.Close()
    })
