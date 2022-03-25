<#

.SYNOPSIS
  Helpdesk GUI that Creates a new User and adds it to specific AD groups

.INPUTS
  None

.OUTPUTS
  None

.NOTES
  Author:         Adrian
  Purpose/Change: Initial script development

.EXAMPLE
  Run the script. No params needed.

#>

# Init PowerShell Gui
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
Add-Type -Name Window -Namespace Console -MemberDefinition '
[DllImport("Kernel32.dll")]
public static extern IntPtr GetConsoleWindow();
[DllImport("user32.dll")]
public static extern bool ShowWindow(IntPtr hWnd, Int32 nCmdShow);
'
$consolePtr = [Console.Window]::GetConsoleWindow()
[Console.Window]::ShowWindow($consolePtr, 0)

# Set Global Variables
$global:path = $null
$global:Location = $null
$UserCredential = Get-Credential
$global:DistGroup = $null


###################################################################################################
##################################### Functions ###################################################
###################################################################################################

# Connect to remote DC and import modules
function DC-Connect {
    $RemoteDCSession = New-PSSession -ComputerName Domain-Controler01
    Import-Module ActiveDirectory -PSSession $RemoteDCSession
    Import-Module ADSync -PSSession $RemoteDCSession
}


# Connect to Server where the exchange management console is located, import Exchange modules
function Web-Connect {
    $RemoteWebSession = New-PSSession -ConfigurationName Microsoft.Exchange -ConnectionUri http://WEB-Server01.reddit.co.uk/PowerShell/ -Authentication Kerberos -Credential $UserCredential
    Import-PSSession $RemoteWebSession -DisableNameChecking
}

function CopyADGroups {

    $CopyUserFrom = $GroFro_TB.Text.Replace(' ', '.')
    $CopyUserTo = $GroTo_TB.Text.Replace(' ', '.')

    Get-ADUser -Identity $CopyUserFrom -Properties memberof |
    Select-Object -ExpandProperty memberof |
    Add-ADGroupMember -Members $CopyUserTo ; LogGroups
}


# Add a new AD user, check if they exist
function NewADUser {
    $Manager = $Manager_TB.Text.Replace(' ', '.')
    $DisplayName = $FirstName_TB.Text + ' ' + $Surname_TB.Text
    $User = $FirstName_TB.Text + '.' + $Surname_TB.Text
    $UserExists = Get-ADUser -Filter "SamAccountName -eq '$User'"
    
    if ($null -eq $UserExists) {

        New-ADUser -SamAccountName $User -Name $DisplayName -GivenName $FirstName_TB.Text -Surname $Surname_TB.Text -DisplayName $DisplayName -Path $global:path -EmailAddress "$User@reddit.co.uk" -UserPrincipalName "$User@reddit.co.uk" `
            -Manager $Manager -State $global:Location -Office $global:Location -Title $JobTitle_TB.Text  -Company "Reddit" ; $UserDN = Get-ADUser $User ; Sync-ADObject -Object $UserDN.DistinguishedName -DC01 -DC02 ;
        Enable-RemoteMailbox $user -RemoteRoutingAddress "$user@Reddit.onmicrosoft.com" ; Start-ADSyncSyncCycle -PolicyType Delta ; LogAdd
    }

    else
    {
        [system.windows.forms.messagebox]::show("This user already exsits!")
        ; LogAddError
    }
}

# Add to log if succesful, clear User fields
function LogAdd {
    $AddLog = 'A user account has been created for ' + $FirstName_TB.Text + ' ' + $Surname_TB.Text
    $LogView.AppendText("$AddLog `r`n`n")
    $FirstName_TB.Text = ""
    $Surname_TB.Text = ""
    $Manager_TB.Text = ""
    $JobTitle_TB.Text = ""
    $RdBtn_Aber.Checked = $false
    $RdBtn_Bov.Checked = $false
    $RdBtn_Col.Checked = $false
    $RdBtn_Edi.Checked = $false
    $RdBtn_Gla.Checked = $false
    $RdBtn_Inv.Checked = $false
    $RdBtn_Leu.Checked = $false
    $RdBtn_Los.Checked = $false
    $RdBtn_Str.Checked = $false
    $Eng_CB.Checked = $false
}
    

function LogGroups {
    $AddLog = 'User groups have been copied from ' + $GroFro_TB.Text + ' to ' + $GroTo_TB.Text
    $LogView.AppendText("$AddLog `r`n`n")
    $GroFro_TB.text = ""
    $GroTo_TB.text = ""
}

# Add to log if there is an error, Clear user fields
function LogAddError {
    $AddLog = 'The user account for ' + $FirstName_TB.Text + ' ' + $Surname_TB.Text + ' was not created.'
    $LogView.AppendText("$AddLog `r`n`n")
    $FirstName_TB.Text = ""
    $Surname_TB.Text = ""
    $DisplayName_TB.Text = ""
    $Manager_TB.Text = ""
    $JobTitle_TB.Text = ""
    $RdBtn_Aber.Checked = $false
    $RdBtn_Bov.Checked = $false
    $RdBtn_Col.Checked = $false
    $RdBtn_Edi.Checked = $false
    $RdBtn_Gla.Checked = $false
    $RdBtn_Inv.Checked = $false
    $RdBtn_Leu.Checked = $false
    $RdBtn_Los.Checked = $false
    $RdBtn_Str.Checked = $false
    $Eng_CB.Checked = $false
}

###################################################################################################
##################################### Form begins #################################################
###################################################################################################

$HelpDeskTool = New-Object system.Windows.Forms.Form
$HelpDeskTool.ClientSize = '575,891'
$HelpDeskTool.text = "AD User Menu"
$HelpDeskTool.TopMost = $false

$FirstName_TB = New-Object system.Windows.Forms.TextBox
$FirstName_TB.multiline = $false
$FirstName_TB.width = 200
$FirstName_TB.height = 20
$FirstName_TB.location = New-Object System.Drawing.Point(165, 60)
$FirstName_TB.Font = 'Microsoft Sans Serif,10'

$FirstName_LB = New-Object system.Windows.Forms.Label
$FirstName_LB.text = "First Name"
$FirstName_LB.AutoSize = $true
$FirstName_LB.width = 25
$FirstName_LB.height = 10
$FirstName_LB.location = New-Object System.Drawing.Point(35, 65)
$FirstName_LB.Font = 'Microsoft Sans Serif,10'

$GenLabel = New-Object system.Windows.Forms.Label
$GenLabel.text = "User Details"
$GenLabel.AutoSize = $true
$GenLabel.width = 25
$GenLabel.height = 10
$GenLabel.location = New-Object System.Drawing.Point(13, 40)
$GenLabel.Font = 'Microsoft Sans Serif,10,style=Bold'

$Surname_LB = New-Object system.Windows.Forms.Label
$Surname_LB.text = "Surname"
$Surname_LB.AutoSize = $true
$Surname_LB.visible = $true
$Surname_LB.width = 25
$Surname_LB.height = 10
$Surname_LB.location = New-Object System.Drawing.Point(35, 95)
$Surname_LB.Font = 'Microsoft Sans Serif,10'

$Surname_TB = New-Object system.Windows.Forms.TextBox
$Surname_TB.multiline = $false
$Surname_TB.width = 200
$Surname_TB.height = 20
$Surname_TB.visible = $true
$Surname_TB.location = New-Object System.Drawing.Point(165, 90)
$Surname_TB.Font = 'Microsoft Sans Serif,10'

$Manager_LB = New-Object system.Windows.Forms.Label
$Manager_LB.text = "Manager"
$Manager_LB.AutoSize = $true
$Manager_LB.visible = $true
$Manager_LB.width = 25
$Manager_LB.height = 10
$Manager_LB.location = New-Object System.Drawing.Point(36, 125)
$Manager_LB.Font = 'Microsoft Sans Serif,10'

$Manager_TB = New-Object system.Windows.Forms.TextBox
$Manager_TB.multiline = $false
$Manager_TB.width = 200
$Manager_TB.height = 20
$Manager_TB.visible = $true
$Manager_TB.location = New-Object System.Drawing.Point(165, 120)
$Manager_TB.Font = 'Microsoft Sans Serif,10'

$WinForm1 = New-Object system.Windows.Forms.Form
$WinForm1.ClientSize = '418,720'
$WinForm1.text = "Form"
$WinForm1.TopMost = $false

$JobTitle_LB = New-Object system.Windows.Forms.Label
$JobTitle_LB.text = "Job Title"
$JobTitle_LB.AutoSize = $true
$JobTitle_LB.visible = $true
$JobTitle_LB.width = 25
$JobTitle_LB.height = 10
$JobTitle_LB.location = New-Object System.Drawing.Point(35, 155)
$JobTitle_LB.Font = 'Microsoft Sans Serif,10'

$JobTitle_TB = New-Object system.Windows.Forms.TextBox
$JobTitle_TB.multiline = $false
$JobTitle_TB.width = 200
$JobTitle_TB.height = 20
$JobTitle_TB.visible = $true
$JobTitle_TB.location = New-Object System.Drawing.Point(165, 150)
$JobTitle_TB.Font = 'Microsoft Sans Serif,10'

$AddUser_Btn = New-Object system.Windows.Forms.Button
$AddUser_Btn.text = "Add User"
$AddUser_Btn.width = 60
$AddUser_Btn.height = 36
$AddUser_Btn.location = New-Object System.Drawing.Point(433, 95)
$AddUser_Btn.Font = 'Microsoft Sans Serif,10'

$RdBtn_Aber = New-Object system.Windows.Forms.RadioButton
$RdBtn_Aber.text = "Aberdeen"
$RdBtn_Aber.AutoSize = $true
$RdBtn_Aber.width = 104
$RdBtn_Aber.height = 20
$RdBtn_Aber.location = New-Object System.Drawing.Point(37, 200)
$RdBtn_Aber.Font = 'Microsoft Sans Serif,10'

$RdBtn_Bov = New-Object system.Windows.Forms.RadioButton
$RdBtn_Bov.text = "Bovington"
$RdBtn_Bov.AutoSize = $true
$RdBtn_Bov.width = 104
$RdBtn_Bov.height = 20
$RdBtn_Bov.location = New-Object System.Drawing.Point(125, 200)
$RdBtn_Bov.Font = 'Microsoft Sans Serif,10'

$RdBtn_Col = New-Object system.Windows.Forms.RadioButton
$RdBtn_Col.text = "Colingwood"
$RdBtn_Col.AutoSize = $true
$RdBtn_Col.width = 104
$RdBtn_Col.height = 20
$RdBtn_Col.location = New-Object System.Drawing.Point(214, 200)
$RdBtn_Col.Font = 'Microsoft Sans Serif,10'

$RdBtn_Edi = New-Object system.Windows.Forms.RadioButton
$RdBtn_Edi.text = "Edinburgh"
$RdBtn_Edi.AutoSize = $true
$RdBtn_Edi.width = 104
$RdBtn_Edi.height = 20
$RdBtn_Edi.location = New-Object System.Drawing.Point(313, 200)
$RdBtn_Edi.Font = 'Microsoft Sans Serif,10'

$RdBtn_Gla = New-Object system.Windows.Forms.RadioButton
$RdBtn_Gla.text = "Glasgow"
$RdBtn_Gla.AutoSize = $true
$RdBtn_Gla.width = 104
$RdBtn_Gla.height = 20
$RdBtn_Gla.location = New-Object System.Drawing.Point(37, 240)
$RdBtn_Gla.Font = 'Microsoft Sans Serif,10'

$RdBtn_Inv = New-Object system.Windows.Forms.RadioButton
$RdBtn_Inv.text = "Inverness"
$RdBtn_Inv.AutoSize = $true
$RdBtn_Inv.width = 104
$RdBtn_Inv.height = 20
$RdBtn_Inv.location = New-Object System.Drawing.Point(125, 240)
$RdBtn_Inv.Font = 'Microsoft Sans Serif,10'

$RdBtn_Leu = New-Object system.Windows.Forms.RadioButton
$RdBtn_Leu.text = "Leuchars"
$RdBtn_Leu.AutoSize = $true
$RdBtn_Leu.width = 104
$RdBtn_Leu.height = 20
$RdBtn_Leu.location = New-Object System.Drawing.Point(214, 240)
$RdBtn_Leu.Font = 'Microsoft Sans Serif,10'

$RdBtn_Los = New-Object system.Windows.Forms.RadioButton
$RdBtn_Los.text = "Lossiemouth"
$RdBtn_Los.AutoSize = $true
$RdBtn_Los.width = 104
$RdBtn_Los.height = 20
$RdBtn_Los.location = New-Object System.Drawing.Point(313, 240)
$RdBtn_Los.Font = 'Microsoft Sans Serif,10'

$RdBtn_Str = New-Object system.Windows.Forms.RadioButton
$RdBtn_Str.text = "Stirling"
$RdBtn_Str.AutoSize = $true
$RdBtn_Str.width = 104
$RdBtn_Str.height = 20
$RdBtn_Str.location = New-Object System.Drawing.Point(419, 200)
$RdBtn_Str.Font = 'Microsoft Sans Serif,10'

$Eng_CB = New-Object system.Windows.Forms.CheckBox
$Eng_CB.text = "User is Eng"
$Eng_CB.AutoSize = $false
$Eng_CB.width = 95
$Eng_CB.height = 20
$Eng_CB.location = New-Object System.Drawing.Point(419, 240)
$Eng_CB.Font = 'Microsoft Sans Serif,10'

$Loc_GB = New-Object system.Windows.Forms.Groupbox
$Loc_GB.height = 81
$Loc_GB.width = 560
$Loc_GB.text = "Location"
$Loc_GB.location = New-Object System.Drawing.Point(9, 185)

$AD_GB = New-Object system.Windows.Forms.Groupbox
$AD_GB.height = 276
$AD_GB.width = 568
$AD_GB.text = "New User Section"
$AD_GB.location = New-Object System.Drawing.Point(3, 16)

$Groupbox1 = New-Object system.Windows.Forms.Groupbox
$Groupbox1.height = 160
$Groupbox1.width = 190
$Groupbox1.text = "Copy AD Group permissions"
$Groupbox1.location = New-Object System.Drawing.Point(10, 322)

$GroFro_TB = New-Object system.Windows.Forms.TextBox
$GroFro_TB.multiline = $false
$GroFro_TB.width = 100
$GroFro_TB.height = 20
$GroFro_TB.location = New-Object System.Drawing.Point(12, 47)
$GroFro_TB.Font = 'Microsoft Sans Serif,10'

$GroTo_TB = New-Object system.Windows.Forms.TextBox
$GroTo_TB.multiline = $false
$GroTo_TB.width = 100
$GroTo_TB.height = 20
$GroTo_TB.location = New-Object System.Drawing.Point(12, 102)
$GroTo_TB.Font = 'Microsoft Sans Serif,10'

$GroFro_LB = New-Object system.Windows.Forms.Label
$GroFro_LB.text = "Groups From"
$GroFro_LB.AutoSize = $true
$GroFro_LB.width = 25
$GroFro_LB.height = 10
$GroFro_LB.location = New-Object System.Drawing.Point(17, 28)
$GroFro_LB.Font = 'Microsoft Sans Serif,10'

$GroTo_LB = New-Object system.Windows.Forms.Label
$GroTo_LB.text = "Groups To"
$GroTo_LB.AutoSize = $true
$GroTo_LB.width = 25
$GroTo_LB.height = 10
$GroTo_LB.location = New-Object System.Drawing.Point(17, 81)
$GroTo_LB.Font = 'Microsoft Sans Serif,10'

$AdGroupCopy_Btn = New-Object system.Windows.Forms.Button
$AdGroupCopy_Btn.text = "Copy"
$AdGroupCopy_Btn.width = 60
$AdGroupCopy_Btn.height = 30
$AdGroupCopy_Btn.location = New-Object System.Drawing.Point(30, 126)
$AdGroupCopy_Btn.Font = 'Microsoft Sans Serif,10'

# Section for log's
$LogView = New-Object system.Windows.Forms.TextBox
$LogView.multiline = $true
$LogView.text = $null
$LogView.width = 555
$LogView.height = 140
$LogView.location = New-Object System.Drawing.Point(10, 720)
$LogView.Font = 'Microsoft Sans Serif,10'

# Set OU path location by radio button
$Event = {
    IF ($Eng_CB.checked) {
        IF ($RdBtn_Aber.Checked) {
            $global:path = "OU=Engineers,OU=Users,OU=Site ABERDEEN,DC=reddit,DC=co,DC=uk" ; $global:Location = "Aberdeen" #; $global:DistGroup = Get-ADGroup -Filter {name -like "All - Aberdeen Engineers"}
        }
        ELSEIF ($RdBtn_Bov.checked -and $Eng_CB.checked) {
            $global:path = "OU=Engineers,OU=Users,OU=Site BOVINGTON,DC=reddit,DC=co,DC=uk"; $global:Location = "Bovington"
        } 
        ELSEIF ($RdBtn_Col.checked -and $Eng_CB.checked) {
            $global:path = "OU=Engineers,OU=Users,OU=Site COLLINGWOOD,DC=reddit,DC=co,DC=uk"; $global:Location = "Collingwood"
        } 
        ELSEIF ($RdBtn_Gla.checked -and $Eng_CB.checked) {
            $global:path = "OU=Engineers,OU=Users,OU=Site GLASGOW,DC=reddit,DC=co,DC=uk"; $global:Location = "Glasgow" #; $global:DistGroup = Get-ADGroup -Filter {name -like "All - Glasgow Engineers"}
        }
        ELSEIF ($RdBtn_Inv.checked -and $Eng_CB.checked) {
            $global:path = "OU=Engineers,OU=Users,OU=Site INVERNESS,DC=reddit,DC=co,DC=uk"; $global:Location = "Inverness" #; $global:DistGroup = Get-ADGroup -Filter {name -like "All - Inverness Engineers"}
        }
        ELSEIF ($RdBtn_Edi.checked -and $Eng_CB.checked) {
            $global:path = "OU=Engineers,OU=Users,OU=Site LOANHEAD,DC=reddit,DC=co,DC=uk"; $global:Location = "Edinburgh" #; $global:DistGroup = Get-ADGroup -Filter {name -like "All - Edinbrugh Engineers"}
        }
        ELSEIF ($RdBtn_Los.checked -and $Eng_CB.checked) {
            $global:path = "OU=Engineers,OU=Users,OU=Site LOSSIEMOUTH,DC=reddit,DC=co,DC=uk"; $global:Location = "Lossiemouth"
        }
        ELSEIF ($RdBtn_Str.checked -and $Eng_CB.checked) {
            $global:path = "OU=Engineers,OU=Users,OU=Site STIRLING,DC=reddit,DC=co,DC=uk"; $global:Location = "Stirling"
        }
        ELSEIF ($RdBtn_Leu.checked -and $Eng_CB.checked) {
            $global:path = "OU=Engineers,OU=Office,OU=Users,OU=Site LEUCHARS,DC=reddit,DC=co,DC=uk"; $global:Location = "Leuchars"
        }
    }
    ELSEIF ($RdBtn_Aber.Checked) {
        $global:path = "OU=Folder Redirection,OU=Office,OU=Users,OU=Site ABERDEEN,DC=reddit,DC=co,DC=uk"; $global:Location = "Aberdeen" #; $global:DistGroup = Get-ADGroup -Filter {name -like "All - Aberdeen Office"}
    }
    ELSEIF ($RdBtn_Bov.checked) {
        $global:path = "OU=Folder Redirection,OU=Office,OU=Users,OU=Site BOVINGTON,DC=reddit,DC=co,DC=uk"; $global:Location = "Bovington"
    } 
    ELSEIF ($RdBtn_Col.checked) {
        $global:path = "OU=Folder Redirection,OU=Office,OU=Users,OU=Site COLLINGWOOD,DC=reddit,DC=co,DC=uk"; $global:Location = "Collingwood"
    } 
    ELSEIF ($RdBtn_Gla.checked) {
        $global:path = "OU=Folder Redirection,OU=Office,OU=Users,OU=Site GLASGOW,DC=reddit,DC=co,DC=uk"; $global:Location = "Glasgow" #; $global:DistGroup = Get-ADGroup -Filter {name -like "All - Glasgow Office"}
    }
    ELSEIF ($RdBtn_Inv.checked) {
        $global:path = "OU=Folder Redirection,OU=Office,OU=Users,OU=Site INVERNESS,DC=reddit,DC=co,DC=uk"; $global:Location = "Inverness"# ; $global:DistGroup = Get-ADGroup -Filter {name -like "All - Inverness Office"}
    }
    ELSEIF ($RdBtn_Edi.checked) {
        $global:path = "OU=Folder Redirection,OU=Office,OU=Users,OU=Site LOANHEAD,DC=reddit,DC=co,DC=uk"; $global:Location = "Edinburgh" #; $global:DistGroup = Get-ADGroup -Filter {name -like "All - Edinburgh Office"}
    }
    ELSEIF ($RdBtn_Los.checked) {
        $global:path = "OU=Folder Redirection,OU=Office,OU=Users,OU=Site LOSSIEMOUTH,DC=reddit,DC=co,DC=uk"; $global:Location = "Lossiemouth"
    }
    ELSEIF ($RdBtn_Str.checked) {
        $global:path = "OU=Folder Redirection,OU=Office,OU=Users,OU=Site STIRLING,DC=reddit,DC=co,DC=uk"; $global:Location = "Stirling"# ; $global:DistGroup = Get-ADGroup -Filter {name -like "All - Stirling Office"}
    }
    ELSEIF ($RdBtn_Leu.checked) {
        $global:path = "OU=Folder Redirection,OU=Office,OU=Users,OU=Site LEUCHARS,DC=reddit,DC=co,DC=uk"; $global:Location = "Leuchars"
    }
    ELSE {
        $global:path = "CN=Users,DC=reddit,DC=co,DC=uk"
    }
}


$RdBtn_Aber.Add_Click($Event)
$RdBtn_Bov.Add_Click($Event)
$RdBtn_Col.Add_Click($Event)
$RdBtn_Gla.Add_Click($Event)
$RdBtn_Inv.Add_Click($Event)
$RdBtn_Edi.Add_Click($Event)
$RdBtn_Los.Add_Click($Event)
$RdBtn_Str.Add_Click($Event)
$RdBtn_Leu.Add_Click($Event)
$Eng_CB.Add_Click($Event)

$HelpDeskTool.controls.AddRange(@($FirstName_TB, $FirstName_LB, $GenLabel, $Surname_LB, $Surname_TB, $Manager_LB, $Manager_TB, $JobTitle_LB, $JobTitle_TB, $Label1, $AddUser_Btn, $RdBtn_Aber, $RdBtn_Bov, $RdBtn_Col, $RdBtn_Edi, $RdBtn_Gla, $RdBtn_Inv, $RdBtn_Leu, $RdBtn_Los, $RdBtn_Str, $Eng_CB, $Loc_GB, $AD_GB, $Groupbox1, $LogView))
$Groupbox1.controls.AddRange(@($GroFro_TB, $GroTo_TB, $GroFro_LB, $GroTo_LB, $AdGroupCopy_Btn))


$AddUser_Btn.Add_Click({ NewADUser })
$AdGroupCopy_Btn.Add_Click({ CopyADGroups })

DC-Connect
Web-Connect


$HelpDeskTool.Add_Shown({ $HelpDeskTool.Activate() })
[void]$HelpDeskTool.ShowDialog()
