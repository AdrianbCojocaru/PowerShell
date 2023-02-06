Add-Type -AssemblyName System.Windows.Forms

# control creation
$form = New-Object System.Windows.Forms.Form
$progressBar1 = New-Object System.Windows.Forms.ProgressBar
$form.Controls.Add($progressBar1)
$progressBar1.Location = '10,10'
$progressBar1.Size = '250,30'

$buttonRun = New-Object System.Windows.Forms.Button
$form.Controls.Add($buttonRun)
$buttonRun.Location = '10,70'
$buttonRun.add_Click({
        $progressBar1.Value = 0
        1..10 | % {
            Start-Sleep -Seconds 2
            $progressBar1.PerformStep()
        }
    })

# form settings
$form.StartPosition = 'CenterScreen'
$form.Text = 'Basic Form Demo'

# buttonOK settings
$buttonRun.Text = 'Run'

$form.ShowDialog()
